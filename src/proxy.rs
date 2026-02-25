use std::{
    cmp::Reverse,
    convert::Infallible,
    error::Error as StdError,
    net::SocketAddr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, combinators::BoxBody};
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
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, sync::oneshot};

use crate::{
    config::{
        BodyOversizePolicy, CacheMissPolicy, Config, QueryMatchMode, RedactConfig,
        RouteMatchConfig, RouteMode,
    },
    matching,
    storage::{Recording, SessionManager, SessionManagerError, Storage},
};

type ProxyBody = BoxBody<Bytes, Box<dyn StdError + Send + Sync>>;
type HttpClient = Client<HttpConnector, ProxyBody>;
const REDACTION_PLACEHOLDER: &str = "[REDACTED]";
const REDACTION_PLACEHOLDER_BYTES: &[u8] = b"[REDACTED]";

#[derive(Debug)]
pub struct ProxyHandle {
    pub listen_addr: SocketAddr,
    pub admin_listen_addr: Option<SocketAddr>,
    shutdown_tx: oneshot::Sender<()>,
    join: tokio::task::JoinHandle<()>,
    admin_shutdown_tx: Option<oneshot::Sender<()>>,
    admin_join: Option<tokio::task::JoinHandle<()>>,
}

impl ProxyHandle {
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
        if let Some(admin_shutdown_tx) = self.admin_shutdown_tx {
            let _ = admin_shutdown_tx.send(());
        }
        let _ = self.join.await;
        if let Some(admin_join) = self.admin_join {
            let _ = admin_join.await;
        }
    }
}

pub async fn serve(config: &Config) -> anyhow::Result<ProxyHandle> {
    let listener = TcpListener::bind(config.proxy.listen)
        .await
        .map_err(|err| anyhow::anyhow!("bind {}: {err}", config.proxy.listen))?;
    let listen_addr = listener
        .local_addr()
        .map_err(|err| anyhow::anyhow!("get local_addr: {err}"))?;
    let admin_listener = if let Some(admin_port) = config.proxy.admin_port {
        let admin_bind_addr = SocketAddr::new(config.proxy.listen.ip(), admin_port);
        Some(
            TcpListener::bind(admin_bind_addr)
                .await
                .map_err(|err| anyhow::anyhow!("bind admin {admin_bind_addr}: {err}"))?,
        )
    } else {
        None
    };
    let admin_listen_addr = match admin_listener.as_ref() {
        Some(admin_listener) => Some(
            admin_listener
                .local_addr()
                .map_err(|err| anyhow::anyhow!("get admin local_addr: {err}"))?,
        ),
        None => None,
    };
    let session_runtime = Arc::new(RwLock::new(ActiveSessionRuntime::from_config(config)?));
    let runtime_status = Arc::new(RuntimeStatus::new(
        config,
        listen_addr,
        admin_listen_addr,
        Arc::clone(&session_runtime),
    ));
    let session_manager = SessionManager::from_config(config)?;

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: HttpClient = Client::builder(TokioExecutor::new()).build(connector);

    let state = Arc::new(ProxyState::new(
        config,
        client,
        Arc::clone(&runtime_status),
        Arc::clone(&session_runtime),
    )?);

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

    let (admin_shutdown_tx, admin_join) = if let Some(admin_listener) = admin_listener {
        let (admin_shutdown_tx, mut admin_shutdown_rx) = oneshot::channel::<()>();
        let admin_state = Arc::new(AdminState {
            status: Arc::clone(&runtime_status),
            session_manager,
            session_runtime,
        });
        let admin_join = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut admin_shutdown_rx => break,
                    accept = admin_listener.accept() => {
                        let Ok((stream, _peer)) = accept else { continue };
                        let io = TokioIo::new(stream);
                        let admin_state = Arc::clone(&admin_state);
                        tokio::spawn(async move {
                            let service = service_fn(move |req| {
                                admin_handler(req, Arc::clone(&admin_state))
                            });
                            let builder = ConnectionBuilder::new(TokioExecutor::new());
                            if let Err(err) = builder.serve_connection(io, service).await {
                                tracing::debug!("admin connection error: {err}");
                            }
                        });
                    }
                }
            }
        });
        (Some(admin_shutdown_tx), Some(admin_join))
    } else {
        (None, None)
    };

    Ok(ProxyHandle {
        listen_addr,
        admin_listen_addr,
        shutdown_tx,
        join,
        admin_shutdown_tx,
        admin_join,
    })
}

#[derive(Debug)]
struct ProxyRoute {
    route_ref: String,
    path_prefix: Option<String>,
    path_exact: Option<String>,
    path_regex: Option<Regex>,
    upstream: Option<Uri>,
    mode: RouteMode,
    cache_miss: CacheMissPolicy,
    body_oversize: BodyOversizePolicy,
    match_config: Option<RouteMatchConfig>,
    // Consumed by upcoming redaction storage steps.
    #[allow(dead_code)]
    redact: Option<RedactConfig>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CacheLogOutcome {
    Hit,
    Miss,
    Bypass,
}

impl CacheLogOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::Miss => "miss",
            Self::Bypass => "bypass",
        }
    }
}

#[derive(Debug, Clone)]
struct ActiveSessionRuntime {
    active_session: String,
    storage: Option<Storage>,
}

impl ActiveSessionRuntime {
    fn from_config(config: &Config) -> anyhow::Result<Self> {
        Ok(Self {
            active_session: config
                .storage
                .as_ref()
                .and_then(|storage| storage.active_session.as_deref())
                .unwrap_or("default")
                .to_owned(),
            storage: Storage::from_config(config)?,
        })
    }
}

#[derive(Debug)]
struct RuntimeStatus {
    started_at: Instant,
    session_runtime: Arc<RwLock<ActiveSessionRuntime>>,
    routes_configured: usize,
    proxy_listen_addr: String,
    admin_listen_addr: Option<String>,
    proxy_requests_total: AtomicU64,
    admin_requests_total: AtomicU64,
    cache_hits_total: AtomicU64,
    cache_misses_total: AtomicU64,
    upstream_requests_total: AtomicU64,
}

#[derive(Debug)]
struct AdminState {
    status: Arc<RuntimeStatus>,
    session_manager: Option<SessionManager>,
    session_runtime: Arc<RwLock<ActiveSessionRuntime>>,
}

#[derive(Debug, Serialize)]
struct AdminStatusResponse {
    uptime_ms: u64,
    active_session: String,
    proxy_listen_addr: String,
    admin_listen_addr: Option<String>,
    routes_configured: usize,
    stats: AdminStatusStats,
}

#[derive(Debug, Serialize)]
struct AdminStatusStats {
    proxy_requests_total: u64,
    admin_requests_total: u64,
    cache_hits_total: u64,
    cache_misses_total: u64,
    upstream_requests_total: u64,
}

#[derive(Debug, Serialize)]
struct AdminSessionsResponse {
    active_session: String,
    sessions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CreateSessionRequest {
    name: String,
}

#[derive(Debug, Serialize)]
struct SessionResponse {
    name: String,
}

#[derive(Debug, Serialize)]
struct AdminErrorResponse {
    error: String,
}

#[derive(Debug, Serialize)]
struct ReplayMissResponse {
    error: &'static str,
    route: String,
    session: String,
    match_key: String,
}

impl RuntimeStatus {
    fn new(
        config: &Config,
        proxy_listen_addr: SocketAddr,
        admin_listen_addr: Option<SocketAddr>,
        session_runtime: Arc<RwLock<ActiveSessionRuntime>>,
    ) -> Self {
        Self {
            started_at: Instant::now(),
            session_runtime,
            routes_configured: config.routes.len(),
            proxy_listen_addr: proxy_listen_addr.to_string(),
            admin_listen_addr: admin_listen_addr.map(|addr| addr.to_string()),
            proxy_requests_total: AtomicU64::new(0),
            admin_requests_total: AtomicU64::new(0),
            cache_hits_total: AtomicU64::new(0),
            cache_misses_total: AtomicU64::new(0),
            upstream_requests_total: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> AdminStatusResponse {
        let uptime_ms = u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        let session_runtime = self
            .session_runtime
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        AdminStatusResponse {
            uptime_ms,
            active_session: session_runtime.active_session.clone(),
            proxy_listen_addr: self.proxy_listen_addr.clone(),
            admin_listen_addr: self.admin_listen_addr.clone(),
            routes_configured: self.routes_configured,
            stats: AdminStatusStats {
                proxy_requests_total: self.proxy_requests_total.load(Ordering::Relaxed),
                admin_requests_total: self.admin_requests_total.load(Ordering::Relaxed),
                cache_hits_total: self.cache_hits_total.load(Ordering::Relaxed),
                cache_misses_total: self.cache_misses_total.load(Ordering::Relaxed),
                upstream_requests_total: self.upstream_requests_total.load(Ordering::Relaxed),
            },
        }
    }

    fn active_session(&self) -> String {
        self.session_runtime
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .active_session
            .clone()
    }
}

#[derive(Debug)]
struct ProxyState {
    routes: Vec<ProxyRoute>,
    client: HttpClient,
    session_runtime: Arc<RwLock<ActiveSessionRuntime>>,
    status: Arc<RuntimeStatus>,
    max_body_bytes: usize,
}

impl ProxyState {
    fn new(
        config: &Config,
        client: HttpClient,
        status: Arc<RuntimeStatus>,
        session_runtime: Arc<RwLock<ActiveSessionRuntime>>,
    ) -> anyhow::Result<Self> {
        let mut parsed_routes = Vec::with_capacity(config.routes.len());
        for (idx, route) in config.routes.iter().enumerate() {
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
                route_ref: format_route_ref(route, idx),
                path_prefix: route.path_prefix.clone(),
                path_exact: route.path_exact.clone(),
                path_regex,
                upstream,
                mode,
                cache_miss,
                body_oversize: route.body_oversize.unwrap_or(BodyOversizePolicy::Error),
                match_config: route.match_.clone(),
                redact: route.redact.clone(),
            });
        }

        Ok(Self {
            routes: parsed_routes,
            client,
            session_runtime,
            status,
            max_body_bytes: config.proxy.max_body_bytes,
        })
    }

    fn route_for(&self, path: &str) -> Option<&ProxyRoute> {
        select_route(&self.routes, path)
    }

    fn active_session_snapshot(&self) -> ActiveSessionRuntime {
        self.session_runtime
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
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

#[derive(Debug)]
enum BodyReadError {
    TooLarge { limit_bytes: usize },
    Read(hyper::Error),
}

async fn collect_body_with_limit(
    mut body: Incoming,
    max_body_bytes: usize,
) -> Result<Bytes, BodyReadError> {
    let mut buffered = Vec::new();
    while let Some(frame_result) = body.frame().await {
        let frame = frame_result.map_err(BodyReadError::Read)?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if buffered
            .len()
            .saturating_add(data.len())
            .gt(&max_body_bytes)
        {
            return Err(BodyReadError::TooLarge {
                limit_bytes: max_body_bytes,
            });
        }
        buffered.extend_from_slice(&data);
    }
    Ok(Bytes::from(buffered))
}

fn parse_content_length(headers: &hyper::HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
}

fn bytes_limit_u64(limit_bytes: usize) -> u64 {
    u64::try_from(limit_bytes).unwrap_or(u64::MAX)
}

fn boxed_full(body: impl Into<Bytes>) -> ProxyBody {
    Full::new(body.into())
        .map_err(|never| -> Box<dyn StdError + Send + Sync> { match never {} })
        .boxed()
}

fn boxed_incoming(body: Incoming) -> ProxyBody {
    body.map_err(|err| -> Box<dyn StdError + Send + Sync> { Box::new(err) })
        .boxed()
}

async fn proxy_handler(
    req: Request<Incoming>,
    state: Arc<ProxyState>,
) -> Result<Response<ProxyBody>, Infallible> {
    state
        .status
        .proxy_requests_total
        .fetch_add(1, Ordering::Relaxed);

    let request_method = req.method().to_string();
    let request_url = req.uri().to_string();
    let request_span = tracing::info_span!(
        "proxy.request",
        method = %request_method,
        url = %request_url,
    );
    let _request_span_guard = request_span.enter();

    let mut route_ref: Option<&str> = None;
    let mut mode: Option<RouteMode> = None;
    let mut cache_outcome = CacheLogOutcome::Bypass;

    macro_rules! respond {
        ($upstream_latency:expr, $response:expr) => {{
            return Ok(response_with_request_log(
                &request_method,
                &request_url,
                route_ref,
                mode,
                cache_outcome,
                $upstream_latency,
                $response,
            ));
        }};
    }

    let Some(route) = state.route_for(req.uri().path()) else {
        respond!(
            None,
            proxy_simple_response(StatusCode::NOT_FOUND, "no matching route")
        );
    };
    route_ref = Some(route.route_ref.as_str());
    mode = Some(route.mode);

    let Some(upstream_base) = route.upstream.as_ref() else {
        respond!(
            None,
            proxy_simple_response(StatusCode::NOT_IMPLEMENTED, "route has no upstream",)
        );
    };

    let upstream_uri = match build_upstream_uri(upstream_base, req.uri()) {
        Ok(uri) => uri,
        Err(err) => {
            tracing::debug!("failed to build upstream uri: {err}");
            respond!(
                None,
                proxy_simple_response(StatusCode::BAD_GATEWAY, "failed to build upstream request",)
            );
        }
    };

    let request_content_length = parse_content_length(req.headers());
    let request_known_oversize = request_content_length
        .map(|len| len > bytes_limit_u64(state.max_body_bytes))
        .unwrap_or(false);
    let bypass_request_buffering = request_known_oversize
        && route.body_oversize == BodyOversizePolicy::BypassCache
        && route.mode != RouteMode::Replay;
    if request_known_oversize && !bypass_request_buffering {
        respond!(
            None,
            proxy_simple_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body exceeds configured proxy.max_body_bytes",
            )
        );
    }

    let (mut parts, body) = req.into_parts();
    strip_hop_by_hop_headers(&mut parts.headers);

    if bypass_request_buffering {
        tracing::debug!(
            limit_bytes = state.max_body_bytes,
            content_length = request_content_length.unwrap_or_default(),
            "bypassing cache for oversized request body"
        );

        parts.uri = upstream_uri.clone();
        set_host_header(&mut parts.headers, &upstream_uri);
        let upstream_req = Request::from_parts(parts, boxed_incoming(body));

        state
            .status
            .upstream_requests_total
            .fetch_add(1, Ordering::Relaxed);
        let upstream_started_at = Instant::now();
        let upstream_res = match state.client.request(upstream_req).await {
            Ok(res) => res,
            Err(err) => {
                let upstream_latency = upstream_started_at.elapsed();
                tracing::debug!("upstream request failed: {err}");
                respond!(
                    Some(upstream_latency),
                    proxy_simple_response(StatusCode::BAD_GATEWAY, "upstream request failed",)
                );
            }
        };
        let upstream_latency = upstream_started_at.elapsed();

        let (mut upstream_parts, upstream_body) = upstream_res.into_parts();
        strip_hop_by_hop_headers(&mut upstream_parts.headers);
        respond!(
            Some(upstream_latency),
            Response::from_parts(upstream_parts, boxed_incoming(upstream_body))
        );
    }

    let body_bytes = match collect_body_with_limit(body, state.max_body_bytes).await {
        Ok(bytes) => bytes,
        Err(BodyReadError::TooLarge { limit_bytes }) => {
            tracing::debug!("request body exceeded configured limit of {limit_bytes} bytes");
            respond!(
                None,
                proxy_simple_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body exceeds configured proxy.max_body_bytes",
                )
            );
        }
        Err(BodyReadError::Read(err)) => {
            tracing::debug!("failed to read request body: {err}");
            respond!(
                None,
                proxy_simple_response(StatusCode::BAD_REQUEST, "failed to read request body",)
            );
        }
    };

    let ActiveSessionRuntime {
        active_session: active_session_name,
        storage: active_storage,
    } = state.active_session_snapshot();

    let match_key = if active_storage.is_some() {
        match matching::compute_match_key(
            route.match_config.as_ref(),
            &parts.method,
            &parts.uri,
            &parts.headers,
            body_bytes.as_ref(),
        ) {
            Ok(match_key) => Some(match_key),
            Err(err) => {
                tracing::debug!("failed to compute match key: {err}");
                let (status, message) = match err {
                    matching::MatchKeyError::InvalidJsonBody(_) => (
                        StatusCode::BAD_REQUEST,
                        "invalid JSON request body for matching",
                    ),
                    matching::MatchKeyError::InvalidJsonPath { .. }
                    | matching::MatchKeyError::SerializeJsonNode { .. } => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "invalid route JSONPath matching configuration",
                    ),
                };
                respond!(None, proxy_simple_response(status, message));
            }
        }
    } else {
        None
    };

    let mut should_record = false;
    match route.mode {
        RouteMode::Record => {
            should_record = active_storage.is_some();
        }
        RouteMode::Replay => {
            let Some(storage) = active_storage.as_ref() else {
                respond!(
                    None,
                    proxy_simple_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "storage not configured",
                    )
                );
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
                Ok(Some(recording)) => {
                    cache_outcome = CacheLogOutcome::Hit;
                    state
                        .status
                        .cache_hits_total
                        .fetch_add(1, Ordering::Relaxed);
                    respond!(None, response_from_recording(recording));
                }
                Ok(None) => {
                    cache_outcome = CacheLogOutcome::Miss;
                    state
                        .status
                        .cache_misses_total
                        .fetch_add(1, Ordering::Relaxed);
                    if route.cache_miss == CacheMissPolicy::Error {
                        respond!(
                            None,
                            replay_miss_response(route, &active_session_name, match_key,)
                        );
                    }
                }
                Err(err) => {
                    tracing::debug!("failed to lookup recording: {err}");
                    respond!(
                        None,
                        proxy_simple_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "failed to lookup recording",
                        )
                    );
                }
            }
        }
        RouteMode::PassthroughCache => {
            if let (Some(storage), Some(match_key)) =
                (active_storage.as_ref(), match_key.as_deref())
            {
                match lookup_recording_for_request(
                    storage,
                    route.match_config.as_ref(),
                    &parts.uri,
                    match_key,
                )
                .await
                {
                    Ok(Some(recording)) => {
                        cache_outcome = CacheLogOutcome::Hit;
                        state
                            .status
                            .cache_hits_total
                            .fetch_add(1, Ordering::Relaxed);
                        respond!(None, response_from_recording(recording));
                    }
                    Ok(None) => {
                        cache_outcome = CacheLogOutcome::Miss;
                        state
                            .status
                            .cache_misses_total
                            .fetch_add(1, Ordering::Relaxed);
                        should_record = true;
                    }
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

    let upstream_req = Request::from_parts(parts, boxed_full(body_bytes));

    state
        .status
        .upstream_requests_total
        .fetch_add(1, Ordering::Relaxed);
    let upstream_started_at = Instant::now();
    let upstream_res = match state.client.request(upstream_req).await {
        Ok(res) => res,
        Err(err) => {
            let upstream_latency = upstream_started_at.elapsed();
            tracing::debug!("upstream request failed: {err}");
            respond!(
                Some(upstream_latency),
                proxy_simple_response(StatusCode::BAD_GATEWAY, "upstream request failed",)
            );
        }
    };
    let upstream_latency = upstream_started_at.elapsed();

    let (mut parts, body) = upstream_res.into_parts();
    strip_hop_by_hop_headers(&mut parts.headers);
    let record_response_status = should_record.then(|| parts.status.as_u16());
    let record_response_headers = should_record.then(|| header_map_to_vec(&parts.headers));
    if !should_record {
        respond!(
            Some(upstream_latency),
            Response::from_parts(parts, boxed_incoming(body))
        );
    }

    let response_known_oversize = parse_content_length(&parts.headers)
        .map(|len| len > bytes_limit_u64(state.max_body_bytes))
        .unwrap_or(false);
    if response_known_oversize {
        if route.body_oversize == BodyOversizePolicy::BypassCache {
            tracing::debug!(
                limit_bytes = state.max_body_bytes,
                "bypassing cache for oversized upstream response body"
            );
            respond!(
                Some(upstream_latency),
                Response::from_parts(parts, boxed_incoming(body))
            );
        }
        respond!(
            Some(upstream_latency),
            proxy_simple_response(
                StatusCode::BAD_GATEWAY,
                "upstream response body exceeds configured proxy.max_body_bytes",
            )
        );
    }

    let body_bytes = match collect_body_with_limit(body, state.max_body_bytes).await {
        Ok(bytes) => bytes,
        Err(BodyReadError::TooLarge { limit_bytes }) => {
            tracing::debug!(
                "upstream response body exceeded configured limit of {limit_bytes} bytes"
            );
            respond!(
                Some(upstream_latency),
                proxy_simple_response(
                    StatusCode::BAD_GATEWAY,
                    "upstream response body exceeds configured proxy.max_body_bytes",
                )
            );
        }
        Err(BodyReadError::Read(err)) => {
            tracing::debug!("failed to read upstream body: {err}");
            respond!(
                Some(upstream_latency),
                proxy_simple_response(
                    StatusCode::BAD_GATEWAY,
                    "failed to read upstream response body",
                )
            );
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
        active_storage.as_ref(),
        record_match_key,
        record_request_method,
        record_request_uri,
        record_request_headers,
        record_request_body,
        record_response_status,
        record_response_headers,
    ) {
        let request_headers = redact_recording_headers(request_headers, route.redact.as_ref());
        let response_headers = redact_recording_headers(response_headers, route.redact.as_ref());
        let created_at_unix_ms = match Recording::now_unix_ms() {
            Ok(ts) => ts,
            Err(err) => {
                tracing::debug!("failed to compute recording timestamp: {err}");
                respond!(
                    Some(upstream_latency),
                    proxy_simple_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "failed to persist recording",
                    )
                );
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

    respond!(
        Some(upstream_latency),
        Response::from_parts(parts, boxed_full(body_bytes))
    );
}

fn response_with_request_log<B>(
    method: &str,
    url: &str,
    route_ref: Option<&str>,
    mode: Option<RouteMode>,
    cache_outcome: CacheLogOutcome,
    upstream_latency: Option<Duration>,
    response: Response<B>,
) -> Response<B> {
    let status = response.status();
    emit_proxy_request_log(
        method,
        url,
        route_ref,
        mode,
        cache_outcome,
        upstream_latency,
        status,
    );
    response
}

fn emit_proxy_request_log(
    method: &str,
    url: &str,
    route_ref: Option<&str>,
    mode: Option<RouteMode>,
    cache_outcome: CacheLogOutcome,
    upstream_latency: Option<Duration>,
    status: StatusCode,
) {
    let upstream_latency_ms = upstream_latency
        .map(|latency| u64::try_from(latency.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);

    tracing::info!(
        method = method,
        url = url,
        route = route_ref.unwrap_or("unmatched"),
        mode = mode_log_label(mode),
        cache = cache_outcome.as_str(),
        upstream_latency_ms,
        status = status.as_u16(),
        "proxy request completed",
    );
}

fn mode_log_label(mode: Option<RouteMode>) -> &'static str {
    match mode {
        Some(RouteMode::Record) => "record",
        Some(RouteMode::Replay) => "replay",
        Some(RouteMode::PassthroughCache) => "passthrough-cache",
        None => "none",
    }
}

fn response_from_recording(recording: Recording) -> Response<ProxyBody> {
    let body = boxed_full(Bytes::from(recording.response_body));
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

    let subset_query_normalizations =
        matching::subset_query_candidate_normalizations(request_uri.query());
    storage
        .get_latest_recording_by_match_key_and_query_subset(match_key, subset_query_normalizations)
        .await
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

fn proxy_simple_response(status: StatusCode, message: &str) -> Response<ProxyBody> {
    let mut response = Response::new(boxed_full(Bytes::from(message.to_owned())));
    *response.status_mut() = status;
    response
}

fn replay_miss_response(
    route: &ProxyRoute,
    active_session: &str,
    match_key: &str,
) -> Response<ProxyBody> {
    let payload = ReplayMissResponse {
        error: "Gateway Not Recorded",
        route: route.route_ref.clone(),
        session: active_session.to_owned(),
        match_key: sanitize_match_key(match_key),
    };

    match serde_json::to_vec(&payload) {
        Ok(body) => {
            let mut response = Response::new(boxed_full(Bytes::from(body)));
            *response.status_mut() = StatusCode::BAD_GATEWAY;
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            response
        }
        Err(err) => {
            tracing::debug!("failed to serialize replay miss response: {err}");
            proxy_simple_response(StatusCode::BAD_GATEWAY, "Gateway Not Recorded")
        }
    }
}

fn sanitize_match_key(match_key: &str) -> String {
    if match_key.len() == 64 && match_key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return match_key.to_owned();
    }
    REDACTION_PLACEHOLDER.to_owned()
}

fn format_route_ref(route: &crate::config::RouteConfig, idx: usize) -> String {
    if let Some(name) = route.name.as_deref() {
        return format!("routes[{idx}] ({name})");
    }
    if let Some(path_exact) = route.path_exact.as_deref() {
        return format!("routes[{idx}] path_exact={path_exact}");
    }
    if let Some(path_prefix) = route.path_prefix.as_deref() {
        return format!("routes[{idx}] path_prefix={path_prefix}");
    }
    if let Some(path_regex) = route.path_regex.as_deref() {
        return format!("routes[{idx}] path_regex={path_regex}");
    }
    format!("routes[{idx}]")
}

fn admin_status_response(status: &RuntimeStatus) -> Response<Full<Bytes>> {
    match serde_json::to_vec(&status.snapshot()) {
        Ok(body) => {
            let mut response = Response::new(Full::new(Bytes::from(body)));
            *response.status_mut() = StatusCode::OK;
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            response
        }
        Err(err) => {
            tracing::debug!("failed to serialize admin status response: {err}");
            simple_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to serialize admin status",
            )
        }
    }
}

fn admin_error_response(status: StatusCode, message: impl Into<String>) -> Response<Full<Bytes>> {
    let payload = AdminErrorResponse {
        error: message.into(),
    };
    match serde_json::to_vec(&payload) {
        Ok(body) => {
            let mut response = Response::new(Full::new(Bytes::from(body)));
            *response.status_mut() = status;
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            response
        }
        Err(err) => {
            tracing::debug!("failed to serialize admin error response: {err}");
            simple_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to serialize admin error response",
            )
        }
    }
}

fn admin_json_response<T: Serialize>(status: StatusCode, payload: &T) -> Response<Full<Bytes>> {
    match serde_json::to_vec(payload) {
        Ok(body) => {
            let mut response = Response::new(Full::new(Bytes::from(body)));
            *response.status_mut() = status;
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            response
        }
        Err(err) => {
            tracing::debug!("failed to serialize admin JSON response: {err}");
            admin_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to serialize admin response",
            )
        }
    }
}

fn status_for_session_error(err: &SessionManagerError) -> StatusCode {
    match err {
        SessionManagerError::InvalidName(_) => StatusCode::BAD_REQUEST,
        SessionManagerError::AlreadyExists(_) => StatusCode::CONFLICT,
        SessionManagerError::NotFound(_) => StatusCode::NOT_FOUND,
        SessionManagerError::Io(_) | SessionManagerError::Internal(_) => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn admin_handler(
    req: Request<Incoming>,
    state: Arc<AdminState>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    state
        .status
        .admin_requests_total
        .fetch_add(1, Ordering::Relaxed);
    let method = req.method().clone();
    let path = req.uri().path().to_owned();

    if path == "/_admin/status" {
        if method != hyper::Method::GET {
            return Ok(simple_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed",
            ));
        }
        return Ok(admin_status_response(&state.status));
    }

    if path == "/_admin/sessions" {
        let Some(session_manager) = state.session_manager.as_ref() else {
            return Ok(admin_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage not configured; session management is unavailable",
            ));
        };

        return match method {
            hyper::Method::GET => match session_manager.list_sessions().await {
                Ok(sessions) => {
                    let response = AdminSessionsResponse {
                        active_session: state.status.active_session(),
                        sessions,
                    };
                    Ok(admin_json_response(StatusCode::OK, &response))
                }
                Err(err) => Ok(admin_error_response(
                    status_for_session_error(&err),
                    err.to_string(),
                )),
            },
            hyper::Method::POST => {
                let body_bytes = match req.into_body().collect().await {
                    Ok(body) => body.to_bytes(),
                    Err(err) => {
                        return Ok(admin_error_response(
                            StatusCode::BAD_REQUEST,
                            format!("failed to read request body: {err}"),
                        ));
                    }
                };

                let create_request: CreateSessionRequest = match serde_json::from_slice(&body_bytes)
                {
                    Ok(create_request) => create_request,
                    Err(err) => {
                        return Ok(admin_error_response(
                            StatusCode::BAD_REQUEST,
                            format!("invalid JSON body: {err}"),
                        ));
                    }
                };

                match session_manager.create_session(&create_request.name).await {
                    Ok(()) => {
                        let response = SessionResponse {
                            name: create_request.name,
                        };
                        Ok(admin_json_response(StatusCode::CREATED, &response))
                    }
                    Err(err) => Ok(admin_error_response(
                        status_for_session_error(&err),
                        err.to_string(),
                    )),
                }
            }
            _ => Ok(admin_error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed",
            )),
        };
    }

    if let Some(session_name) = path
        .strip_prefix("/_admin/sessions/")
        .and_then(|path| path.strip_suffix("/activate"))
    {
        if session_name.is_empty() || session_name.contains('/') {
            return Ok(admin_error_response(StatusCode::NOT_FOUND, "not found"));
        }

        if method != hyper::Method::POST {
            return Ok(admin_error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed",
            ));
        }

        let Some(session_manager) = state.session_manager.as_ref() else {
            return Ok(admin_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage not configured; session management is unavailable",
            ));
        };

        return match session_manager.open_session_storage(session_name).await {
            Ok(storage) => {
                let mut session_runtime = state
                    .session_runtime
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                session_runtime.active_session = session_name.to_owned();
                session_runtime.storage = Some(storage);
                let response = SessionResponse {
                    name: session_name.to_owned(),
                };
                Ok(admin_json_response(StatusCode::OK, &response))
            }
            Err(err) => Ok(admin_error_response(
                status_for_session_error(&err),
                err.to_string(),
            )),
        };
    }

    if let Some(session_name) = path.strip_prefix("/_admin/sessions/") {
        if session_name.is_empty() || session_name.contains('/') {
            return Ok(admin_error_response(StatusCode::NOT_FOUND, "not found"));
        }

        if method != hyper::Method::DELETE {
            return Ok(admin_error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed",
            ));
        }

        let Some(session_manager) = state.session_manager.as_ref() else {
            return Ok(admin_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage not configured; session management is unavailable",
            ));
        };

        let active_session = state.status.active_session();
        if session_name == active_session {
            return Ok(admin_error_response(
                StatusCode::CONFLICT,
                format!("cannot delete active session `{session_name}`"),
            ));
        }

        return match session_manager.delete_session(session_name).await {
            Ok(()) => {
                let mut response = Response::new(Full::new(Bytes::new()));
                *response.status_mut() = StatusCode::NO_CONTENT;
                Ok(response)
            }
            Err(err) => Ok(admin_error_response(
                status_for_session_error(&err),
                err.to_string(),
            )),
        };
    }

    Ok(simple_response(StatusCode::NOT_FOUND, "not found"))
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

fn redact_recording_headers(
    headers: Vec<(String, Vec<u8>)>,
    redact: Option<&RedactConfig>,
) -> Vec<(String, Vec<u8>)> {
    let Some(redact) = redact else {
        return headers;
    };

    if redact.headers.is_empty() {
        return headers;
    }

    headers
        .into_iter()
        .map(|(name, value)| {
            if redact
                .headers
                .iter()
                .any(|configured| configured.eq_ignore_ascii_case(name.as_str()))
            {
                (name, REDACTION_PLACEHOLDER_BYTES.to_vec())
            } else {
                (name, value)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

    use super::{
        CacheLogOutcome, ProxyRoute, emit_proxy_request_log, format_route_ref, mode_log_label,
        redact_recording_headers, sanitize_match_key, select_route,
    };
    use crate::config::{
        BodyOversizePolicy, CacheMissPolicy, Config, RedactConfig, RouteConfig, RouteMode,
    };
    use serde_json::Value;
    use tracing_subscriber::{filter::LevelFilter, fmt::MakeWriter};

    fn test_route(
        path_exact: Option<&str>,
        path_prefix: Option<&str>,
        path_regex: Option<&str>,
    ) -> ProxyRoute {
        ProxyRoute {
            route_ref: "test-route".to_owned(),
            path_prefix: path_prefix.map(str::to_owned),
            path_exact: path_exact.map(str::to_owned),
            path_regex: path_regex.map(|pattern| regex::Regex::new(pattern).unwrap()),
            upstream: None,
            mode: RouteMode::Record,
            cache_miss: CacheMissPolicy::Forward,
            body_oversize: BodyOversizePolicy::Error,
            match_config: None,
            redact: None,
        }
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
    fn config_rejects_invalid_path_regex() {
        let err = Config::from_toml_str(
            r#"
[proxy]
listen = "127.0.0.1:0"

[[routes]]
path_regex = "("
upstream = "http://127.0.0.1:1"
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("invalid `path_regex` expression"));
    }

    #[test]
    fn sanitize_match_key_redacts_unexpected_values() {
        assert_eq!(sanitize_match_key("abc"), "[REDACTED]");
        assert_eq!(
            sanitize_match_key("6a9f16398d64f3fcf57ecf7855da29232ef52f01579f0f74defad5c6af53f3e0"),
            "6a9f16398d64f3fcf57ecf7855da29232ef52f01579f0f74defad5c6af53f3e0"
        );
    }

    #[test]
    fn redact_recording_headers_masks_configured_names_case_insensitively() {
        let headers = vec![
            ("Authorization".to_owned(), b"Bearer topsecret".to_vec()),
            ("x-api-key".to_owned(), b"secret-key".to_vec()),
            ("x-trace-id".to_owned(), b"trace-1".to_vec()),
        ];
        let redact = RedactConfig {
            headers: vec!["authorization".to_owned(), "X-API-KEY".to_owned()],
            body_json: Vec::new(),
        };

        let redacted = redact_recording_headers(headers, Some(&redact));
        let authorization = redacted
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.as_slice());
        let api_key = redacted
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("x-api-key"))
            .map(|(_, value)| value.as_slice());
        let trace_id = redacted
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("x-trace-id"))
            .map(|(_, value)| value.as_slice());

        assert_eq!(authorization, Some(b"[REDACTED]".as_slice()));
        assert_eq!(api_key, Some(b"[REDACTED]".as_slice()));
        assert_eq!(trace_id, Some(b"trace-1".as_slice()));
    }

    #[test]
    fn cache_log_outcome_labels_are_stable() {
        assert_eq!(CacheLogOutcome::Hit.as_str(), "hit");
        assert_eq!(CacheLogOutcome::Miss.as_str(), "miss");
        assert_eq!(CacheLogOutcome::Bypass.as_str(), "bypass");
    }

    #[test]
    fn mode_log_label_covers_all_modes() {
        assert_eq!(mode_log_label(Some(RouteMode::Record)), "record");
        assert_eq!(mode_log_label(Some(RouteMode::Replay)), "replay");
        assert_eq!(
            mode_log_label(Some(RouteMode::PassthroughCache)),
            "passthrough-cache"
        );
        assert_eq!(mode_log_label(None), "none");
    }

    #[test]
    fn emit_proxy_request_log_includes_required_fields_and_no_headers() {
        let writer = SharedWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(LevelFilter::INFO)
            .with_target(true)
            .json()
            .with_writer(writer.clone())
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!(
                "proxy.request",
                method = "GET",
                url = "http://proxy.local/api/hello?x=1"
            );
            let _span_guard = span.enter();
            emit_proxy_request_log(
                "GET",
                "http://proxy.local/api/hello?x=1",
                Some("routes[0] (hello)"),
                Some(RouteMode::PassthroughCache),
                CacheLogOutcome::Miss,
                Some(Duration::from_millis(17)),
                hyper::StatusCode::OK,
            );
        });

        let output = writer.as_string();
        let line = output.lines().next().expect("expected one log line");
        let log: Value = serde_json::from_str(line).expect("log line should be valid JSON");

        assert_eq!(
            log.pointer("/fields/method").and_then(Value::as_str),
            Some("GET"),
            "log: {log}"
        );
        assert_eq!(
            log.pointer("/fields/url").and_then(Value::as_str),
            Some("http://proxy.local/api/hello?x=1"),
            "log: {log}"
        );
        assert_eq!(
            log.pointer("/fields/route").and_then(Value::as_str),
            Some("routes[0] (hello)"),
            "log: {log}"
        );
        assert_eq!(
            log.pointer("/fields/mode").and_then(Value::as_str),
            Some("passthrough-cache"),
            "log: {log}"
        );
        assert_eq!(
            log.pointer("/fields/cache").and_then(Value::as_str),
            Some("miss"),
            "log: {log}"
        );
        assert_eq!(
            log.pointer("/fields/upstream_latency_ms")
                .and_then(Value::as_u64),
            Some(17),
            "log: {log}"
        );
        assert_eq!(
            log.pointer("/fields/status").and_then(Value::as_u64),
            Some(200),
            "log: {log}"
        );
        assert!(
            log.pointer("/fields/headers").is_none(),
            "request headers should not be logged: {log}"
        );
        assert!(
            log.pointer("/fields/authorization").is_none(),
            "sensitive headers should not be logged: {log}"
        );
    }

    #[test]
    fn format_route_ref_prefers_name_then_matcher() {
        let route = RouteConfig {
            name: Some("payments".to_owned()),
            path_prefix: Some("/api".to_owned()),
            path_exact: None,
            path_regex: None,
            upstream: None,
            mode: None,
            body_oversize: None,
            cache_miss: None,
            match_: None,
            redact: None,
            streaming: None,
            websocket: None,
            grpc: None,
            rate_limit: None,
            transform: None,
        };
        assert_eq!(format_route_ref(&route, 3), "routes[3] (payments)");

        let unnamed = RouteConfig {
            name: None,
            path_prefix: Some("/api".to_owned()),
            path_exact: None,
            path_regex: None,
            upstream: None,
            mode: None,
            body_oversize: None,
            cache_miss: None,
            match_: None,
            redact: None,
            streaming: None,
            websocket: None,
            grpc: None,
            rate_limit: None,
            transform: None,
        };
        assert_eq!(format_route_ref(&unnamed, 4), "routes[4] path_prefix=/api");
    }

    #[derive(Clone, Default)]
    struct SharedWriter {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl SharedWriter {
        fn as_string(&self) -> String {
            let bytes = self.buffer.lock().expect("buffer lock poisoned").clone();
            String::from_utf8(bytes).expect("log output should be UTF-8")
        }
    }

    struct LockedWriter {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl<'a> MakeWriter<'a> for SharedWriter {
        type Writer = LockedWriter;

        fn make_writer(&'a self) -> Self::Writer {
            LockedWriter {
                buffer: self.buffer.clone(),
            }
        }
    }

    impl std::io::Write for LockedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.buffer
                .lock()
                .expect("buffer lock poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
