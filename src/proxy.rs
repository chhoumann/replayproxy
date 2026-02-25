use std::{convert::Infallible, net::SocketAddr, sync::Arc};

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
use tokio::{net::TcpListener, sync::oneshot};

use crate::config::{Config, RouteConfig};

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
    let listen_addr: SocketAddr = config
        .proxy
        .listen
        .parse()
        .map_err(|err| anyhow::anyhow!("parse proxy.listen {}: {err}", config.proxy.listen))?;

    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|err| anyhow::anyhow!("bind {}: {err}", listen_addr))?;
    let listen_addr = listener
        .local_addr()
        .map_err(|err| anyhow::anyhow!("get local_addr: {err}"))?;

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: HttpClient = Client::builder(TokioExecutor::new()).build(connector);

    let state = Arc::new(ProxyState::new(config.routes.clone(), client)?);

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
    path_prefix: String,
    upstream: Uri,
}

#[derive(Debug)]
struct ProxyState {
    routes: Vec<ProxyRoute>,
    client: HttpClient,
}

impl ProxyState {
    fn new(routes: Vec<RouteConfig>, client: HttpClient) -> anyhow::Result<Self> {
        let mut parsed_routes = Vec::with_capacity(routes.len());
        for route in routes {
            let upstream: Uri = route
                .upstream
                .parse()
                .map_err(|err| anyhow::anyhow!("parse route.upstream {}: {err}", route.upstream))?;
            parsed_routes.push(ProxyRoute {
                path_prefix: route.path_prefix,
                upstream,
            });
        }

        Ok(Self {
            routes: parsed_routes,
            client,
        })
    }

    fn route_for(&self, path: &str) -> Option<&ProxyRoute> {
        self.routes
            .iter()
            .find(|route| path.starts_with(&route.path_prefix))
    }
}

async fn proxy_handler(
    req: Request<Incoming>,
    state: Arc<ProxyState>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let Some(route) = state.route_for(req.uri().path()) else {
        return Ok(simple_response(StatusCode::NOT_FOUND, "no matching route"));
    };

    let upstream_uri = match build_upstream_uri(&route.upstream, req.uri()) {
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

    parts.uri = upstream_uri.clone();
    strip_hop_by_hop_headers(&mut parts.headers);
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

    Ok(Response::from_parts(parts, Full::new(body_bytes)))
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
