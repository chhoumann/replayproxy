use std::{cmp::Reverse, convert::Infallible, net::SocketAddr, sync::Arc};

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::{
    Request, Response, StatusCode, Uri,
    body::Incoming,
    header::{self, HeaderName, HeaderValue},
    service::service_fn,
};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as ConnectionBuilder,
};
use regex::Regex;
use tokio::{net::TcpListener, sync::oneshot};

use crate::{
    config::{CacheMissPolicy, Config, QueryMatchMode, RouteMatchConfig, RouteMode},
    matching,
    storage::{Recording, Storage},
};

type HttpClient = Client<HttpConnector, Full<Bytes>>;

#[derive(Debug)]
pub struct ProxyHandle {
    pub listen_addr: SocketAddr,
    shutdown_tx: oneshot::Sender<()>,
    join: tokio::task::JoinHandle<()>,
}

impl ProxyHandle {
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
        let _ = self.join.await;
    }
}

pub async fn serve(config: &Config) -> anyhow::Result<ProxyHandle> {
    let listener = TcpListener::bind(config.proxy.listen)
        .await
        .map_err(|err| anyhow::anyhow!("bind {}: {err}", config.proxy.listen))?;
    let listen_addr = listener
        .local_addr()
        .map_err(|err| anyhow::anyhow!("get local_addr: {err}"))?;

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: HttpClient = Client::builder(TokioExecutor::new()).build(connector);

    let state = Arc::new(ProxyState::new(config, client)?);

    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let join = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accept = listener.accept() => {
                    let Ok((stream, _peer)) = accept else { continue };
                    let io = TokioIo::new(stream);
                    let state = Arc::clone(&state);
                    tokio::spawn(async move {
                        let service = service_fn(move |req| proxy_handler(req, Arc::clone(&state)));
                        let builder = ConnectionBuilder::new(TokioExecutor::new());
                        if let Err(err) = builder.serve_connection(io, service).await {
                            tracing::debug!("connection error: {err}");
                        }
                    });
                }
            }
        }
    });

    Ok(ProxyHandle {
        listen_addr,
        shutdown_tx,
        join,
    })
}

#[derive(Debug)]
struct ProxyRoute {
    path_prefix: Option<String>,
    path_exact: Option<String>,
    path_regex: Option<Regex>,
    upstream: Option<Uri>,
    mode: RouteMode,
    cache_miss: CacheMissPolicy,
    match_config: Option<RouteMatchConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PathMatchKind {
    Regex,
    Prefix,
    Exact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct PathMatchScore {
    kind: PathMatchKind,
    specificity: usize,
}

#[derive(Debug)]
struct ProxyState {
    routes: Vec<ProxyRoute>,
    client: HttpClient,
    storage: Option<Storage>,
}

impl ProxyState {
    fn new(config: &Config, client: HttpClient) -> anyhow::Result<Self> {
        let mut parsed_routes = Vec::with_capacity(config.routes.len());
        for route in &config.routes {
            let path_regex =
                match route.path_regex.as_deref() {
                    Some(pattern) => Some(Regex::new(pattern).map_err(|err| {
                        anyhow::anyhow!("parse route.path_regex {pattern}: {err}")
                    })?),
                    None => None,
                };
            let upstream =
                match route.upstream.as_deref() {
                    Some(upstream) => Some(upstream.parse().map_err(|err| {
                        anyhow::anyhow!("parse route.upstream {upstream}: {err}")
                    })?),
                    None => None,
                };

            let mode = route
                .mode
                .or(config.proxy.mode)
                .unwrap_or(RouteMode::PassthroughCache);
            let cache_miss = route.cache_miss.unwrap_or(match mode {
                RouteMode::Replay => CacheMissPolicy::Error,
                RouteMode::Record | RouteMode::PassthroughCache => CacheMissPolicy::Forward,
            });
            parsed_routes.push(ProxyRoute {
                path_prefix: route.path_prefix.clone(),
                path_exact: route.path_exact.clone(),
                path_regex,
                upstream,
                mode,
                cache_miss,
                match_config: route.match_.clone(),
            });
        }

        Ok(Self {
            routes: parsed_routes,
            client,
            storage: Storage::from_config(config)?,
        })
    }

    fn route_for(&self, path: &str) -> Option<&ProxyRoute> {
        select_route(&self.routes, path)
    }
}

impl ProxyRoute {
    fn match_score(&self, path: &str) -> Option<PathMatchScore> {
        if let Some(exact) = self.path_exact.as_deref()
            && path == exact
        {
            return Some(PathMatchScore {
                kind: PathMatchKind::Exact,
                specificity: exact.len(),
            });
        }
        if let Some(prefix) = self.path_prefix.as_deref()
            && path.starts_with(prefix)
        {
            return Some(PathMatchScore {
                kind: PathMatchKind::Prefix,
                specificity: prefix.len(),
            });
        }
        if let Some(regex) = self.path_regex.as_ref()
            && regex.is_match(path)
        {
            return Some(PathMatchScore {
                kind: PathMatchKind::Regex,
                specificity: 0,
            });
        }
        None
    }
}

fn select_route<'a>(routes: &'a [ProxyRoute], path: &str) -> Option<&'a ProxyRoute> {
    routes
        .iter()
        .enumerate()
        .filter_map(|(idx, route)| {
            route
                .match_score(path)
                .map(|score| (score, Reverse(idx), route))
        })
        .max_by(|(left_score, left_idx, _), (right_score, right_idx, _)| {
            left_score
                .cmp(right_score)
                .then_with(|| left_idx.cmp(right_idx))
        })
        .map(|(_, _, route)| route)
}

async fn proxy_handler(
    req: Request<Incoming>,
    state: Arc<ProxyState>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let Some(route) = state.route_for(req.uri().path()) else {
        return Ok(simple_response(StatusCode::NOT_FOUND, "no matching route"));
    };

    let Some(upstream_base) = route.upstream.as_ref() else {
        return Ok(simple_response(
            StatusCode::NOT_IMPLEMENTED,
            "route has no upstream",
        ));
    };

    let upstream_uri = match build_upstream_uri(upstream_base, req.uri()) {
        Ok(uri) => uri,
        Err(err) => {
            tracing::debug!("failed to build upstream uri: {err}");
            return Ok(simple_response(
                StatusCode::BAD_GATEWAY,
                "failed to build upstream request",
            ));
        }
    };

    let (mut parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            tracing::debug!("failed to read request body: {err}");
            return Ok(simple_response(
                StatusCode::BAD_REQUEST,
                "failed to read request body",
            ));
        }
    };

    strip_hop_by_hop_headers(&mut parts.headers);
    let match_key = state.storage.as_ref().map(|_| {
        matching::compute_match_key(
            route.match_config.as_ref(),
            &parts.method,
            &parts.uri,
            &parts.headers,
            body_bytes.as_ref(),
        )
    });

    let mut should_record = false;
    match route.mode {
        RouteMode::Record => {
            should_record = state.storage.is_some();
        }
        RouteMode::Replay => {
            let Some(storage) = state.storage.as_ref() else {
                return Ok(simple_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "storage not configured",
                ));
            };
            let match_key = match_key.as_deref().unwrap_or_default();
            match lookup_recording_for_request(
                storage,
                route.match_config.as_ref(),
                &parts.uri,
                match_key,
            )
            .await
            {
                Ok(Some(recording)) => return Ok(response_from_recording(recording)),
                Ok(None) => {
                    if route.cache_miss == CacheMissPolicy::Error {
                        return Ok(simple_response(
                            StatusCode::BAD_GATEWAY,
                            "Gateway Not Recorded",
                        ));
                    }
                }
                Err(err) => {
                    tracing::debug!("failed to lookup recording: {err}");
                    return Ok(simple_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "failed to lookup recording",
                    ));
                }
            }
        }
        RouteMode::PassthroughCache => {
            if let (Some(storage), Some(match_key)) = (state.storage.as_ref(), match_key.as_deref())
            {
                match lookup_recording_for_request(
                    storage,
                    route.match_config.as_ref(),
                    &parts.uri,
                    match_key,
                )
                .await
                {
                    Ok(Some(recording)) => return Ok(response_from_recording(recording)),
                    Ok(None) => should_record = true,
                    Err(err) => {
                        tracing::debug!("failed to lookup recording: {err}");
                        should_record = true;
                    }
                }
            }
        }
    }

    let record_request_headers = should_record.then(|| header_map_to_vec(&parts.headers));
    let record_request_uri = should_record.then(|| request_uri_for_recording(&parts.uri));
    let record_request_method = should_record.then(|| parts.method.to_string());
    let record_match_key = should_record.then(|| match_key.unwrap_or_default());
    let record_request_body = should_record.then(|| body_bytes.to_vec());

    parts.uri = upstream_uri.clone();
    set_host_header(&mut parts.headers, &upstream_uri);

    let upstream_req = Request::from_parts(parts, Full::new(body_bytes));

    let upstream_res = match state.client.request(upstream_req).await {
        Ok(res) => res,
        Err(err) => {
            tracing::debug!("upstream request failed: {err}");
            return Ok(simple_response(
                StatusCode::BAD_GATEWAY,
                "upstream request failed",
            ));
        }
    };

    let (mut parts, body) = upstream_res.into_parts();
    strip_hop_by_hop_headers(&mut parts.headers);
    let record_response_status = should_record.then(|| parts.status.as_u16());
    let record_response_headers = should_record.then(|| header_map_to_vec(&parts.headers));
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            tracing::debug!("failed to read upstream body: {err}");
            return Ok(simple_response(
                StatusCode::BAD_GATEWAY,
                "failed to read upstream response body",
            ));
        }
    };

    if let (
        true,
        Some(storage),
        Some(match_key),
        Some(request_method),
        Some(request_uri),
        Some(request_headers),
        Some(request_body),
        Some(response_status),
        Some(response_headers),
    ) = (
        should_record,
        state.storage.as_ref(),
        record_match_key,
        record_request_method,
        record_request_uri,
        record_request_headers,
        record_request_body,
        record_response_status,
        record_response_headers,
    ) {
        let created_at_unix_ms = match Recording::now_unix_ms() {
            Ok(ts) => ts,
            Err(err) => {
                tracing::debug!("failed to compute recording timestamp: {err}");
                return Ok(simple_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to persist recording",
                ));
            }
        };

        let recording = Recording {
            match_key,
            request_method,
            request_uri,
            request_headers,
            request_body,
            response_status,
            response_headers,
            response_body: body_bytes.to_vec(),
            created_at_unix_ms,
        };

        if let Err(err) = storage.insert_recording(recording).await {
            tracing::debug!("failed to persist recording: {err}");
        }
    }

    Ok(Response::from_parts(parts, Full::new(body_bytes)))
}

fn response_from_recording(recording: Recording) -> Response<Full<Bytes>> {
    let body = Full::new(Bytes::from(recording.response_body));
    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::from_u16(recording.response_status)
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    for (name, value) in recording.response_headers {
        let Ok(header_name) = HeaderName::from_bytes(name.as_bytes()) else {
            tracing::debug!("invalid header name in recording");
            continue;
        };
        let Ok(header_value) = HeaderValue::from_bytes(&value) else {
            tracing::debug!(
                "invalid header value in recording for {}",
                header_name.as_str()
            );
            continue;
        };
        response.headers_mut().append(header_name, header_value);
    }
    strip_hop_by_hop_headers(response.headers_mut());

    response
}

async fn lookup_recording_for_request(
    storage: &Storage,
    route_match: Option<&RouteMatchConfig>,
    request_uri: &Uri,
    match_key: &str,
) -> anyhow::Result<Option<Recording>> {
    let query_mode = route_match
        .map(|route_match| route_match.query)
        .unwrap_or(QueryMatchMode::Exact);

    if query_mode != QueryMatchMode::Subset {
        return storage.get_recording_by_match_key(match_key).await;
    }

    let request_query = request_uri.query();
    let recordings = storage.get_recordings_by_match_key(match_key).await?;
    Ok(recordings.into_iter().find(|recording| {
        matching::query_params_match(
            QueryMatchMode::Subset,
            recording_query_from_uri(&recording.request_uri),
            request_query,
        )
    }))
}

fn recording_query_from_uri(uri: &str) -> Option<&str> {
    uri.split_once('?').map(|(_, query)| query)
}

fn build_upstream_uri(upstream_base: &Uri, original: &Uri) -> anyhow::Result<Uri> {
    let mut parts = original.clone().into_parts();
    parts.scheme = upstream_base.scheme().cloned();
    parts.authority = upstream_base.authority().cloned();
    Uri::from_parts(parts).map_err(|err| anyhow::anyhow!("construct upstream uri: {err}"))
}

fn set_host_header(headers: &mut hyper::HeaderMap, uri: &Uri) {
    let Some(authority) = uri.authority() else {
        return;
    };
    if let Ok(value) = HeaderValue::from_str(authority.as_str()) {
        headers.insert(header::HOST, value);
    }
}

fn strip_hop_by_hop_headers(headers: &mut hyper::HeaderMap) {
    let mut to_remove = Vec::new();
    for value in headers.get_all(header::CONNECTION).iter() {
        let Ok(value) = value.to_str() else { continue };
        for name in value.split(',') {
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            let Ok(header_name) = HeaderName::from_bytes(name.as_bytes()) else {
                continue;
            };
            to_remove.push(header_name);
        }
    }

    for header_name in to_remove {
        headers.remove(header_name);
    }

    const STANDARD: &[&str] = &[
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ];
    for header_name in STANDARD {
        headers.remove(*header_name);
    }
    headers.remove("proxy-connection");
}

fn simple_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    let body = Full::new(Bytes::from(message.to_owned()));
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
}

fn request_uri_for_recording(uri: &Uri) -> String {
    uri.path_and_query()
        .map(|value| value.as_str().to_owned())
        .unwrap_or_else(|| uri.path().to_owned())
}

fn header_map_to_vec(headers: &hyper::HeaderMap) -> Vec<(String, Vec<u8>)> {
    headers
        .iter()
        .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{ProxyRoute, ProxyState, select_route};
    use crate::config::{CacheMissPolicy, Config, RouteMode};

    fn test_route(
        path_exact: Option<&str>,
        path_prefix: Option<&str>,
        path_regex: Option<&str>,
    ) -> ProxyRoute {
        ProxyRoute {
            path_prefix: path_prefix.map(str::to_owned),
            path_exact: path_exact.map(str::to_owned),
            path_regex: path_regex.map(|pattern| regex::Regex::new(pattern).unwrap()),
            upstream: None,
            mode: RouteMode::Record,
            cache_miss: CacheMissPolicy::Forward,
            match_config: None,
        }
    }

    fn test_client() -> super::HttpClient {
        let mut connector = hyper_util::client::legacy::connect::HttpConnector::new();
        connector.enforce_http(false);
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(connector)
    }

    #[test]
    fn route_selection_prefers_exact_over_prefix() {
        let routes = vec![
            test_route(None, Some("/api"), None),
            test_route(Some("/api/users"), None, None),
        ];

        let selected = select_route(&routes, "/api/users").expect("expected route");
        assert_eq!(selected.path_exact.as_deref(), Some("/api/users"));
    }

    #[test]
    fn route_selection_prefers_longest_prefix() {
        let routes = vec![
            test_route(None, Some("/api"), None),
            test_route(None, Some("/api/v1"), None),
        ];

        let selected = select_route(&routes, "/api/v1/chat").expect("expected route");
        assert_eq!(selected.path_prefix.as_deref(), Some("/api/v1"));
    }

    #[test]
    fn route_selection_prefers_prefix_over_regex() {
        let routes = vec![
            test_route(None, None, Some(r"^/api/.*$")),
            test_route(None, Some("/api/v1"), None),
        ];

        let selected = select_route(&routes, "/api/v1/chat").expect("expected route");
        assert_eq!(selected.path_prefix.as_deref(), Some("/api/v1"));
    }

    #[test]
    fn route_selection_falls_back_to_regex_match() {
        let routes = vec![test_route(None, None, Some(r"^/v\d+/chat$"))];

        let selected = select_route(&routes, "/v1/chat").expect("expected route");
        assert!(selected.path_regex.is_some());
    }

    #[test]
    fn route_selection_uses_first_defined_route_on_tie() {
        let routes = vec![
            test_route(None, None, Some(r"^/api/.*$")),
            test_route(None, None, Some(r"^/api/.*$")),
        ];

        let selected = select_route(&routes, "/api/users").expect("expected route");
        assert!(std::ptr::eq(selected, &routes[0]));
    }

    #[test]
    fn proxy_state_new_rejects_invalid_path_regex() {
        let config = Config::from_toml_str(
            r#"
[proxy]
listen = "127.0.0.1:0"

[[routes]]
path_regex = "("
upstream = "http://127.0.0.1:1"
"#,
        )
        .unwrap();

        let err = ProxyState::new(&config, test_client()).unwrap_err();
        assert!(err.to_string().contains("parse route.path_regex"));
    }
}
