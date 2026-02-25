use std::{
    cmp::Reverse,
    collections::{BTreeMap, VecDeque},
    convert::Infallible,
    error::Error as StdError,
    fmt::Write as _,
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, combinators::BoxBody};
use hyper::{
    Request, Response, StatusCode, Uri,
    body::{Frame, Incoming},
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
use serde_json::Value;
use serde_json_path::JsonPath;
use tokio::{
    net::TcpListener,
    sync::{Mutex as AsyncMutex, oneshot},
};

use crate::{
    config::{
        BodyOversizePolicy, CacheMissPolicy, Config, QueryMatchMode, RedactConfig,
        RouteMatchConfig, RouteMode,
    },
    matching,
    session_export::{self, SessionExportError, SessionExportFormat, SessionExportRequest},
    session_import::{self, SessionImportError, SessionImportRequest},
    storage::{
        Recording, RecordingSearch, RecordingSummary, SessionManager, SessionManagerError, Storage,
    },
};

type ProxyBody = BoxBody<Bytes, Box<dyn StdError + Send + Sync>>;
type HttpClient = Client<HttpConnector, ProxyBody>;
const REDACTION_PLACEHOLDER: &str = "[REDACTED]";
const SUBSET_QUERY_CANDIDATE_LIMIT: usize = 4096;
const ADMIN_RECORDINGS_DEFAULT_LIMIT: usize = 100;
const ADMIN_API_TOKEN_HEADER: &str = "x-replayproxy-admin-token";
const DURATION_HISTOGRAM_BUCKETS: [(&str, u64); 12] = [
    ("0.001", 1_000),
    ("0.005", 5_000),
    ("0.01", 10_000),
    ("0.025", 25_000),
    ("0.05", 50_000),
    ("0.1", 100_000),
    ("0.25", 250_000),
    ("0.5", 500_000),
    ("1", 1_000_000),
    ("2.5", 2_500_000),
    ("5", 5_000_000),
    ("10", 10_000_000),
];

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
        let admin_bind_ip = config
            .proxy
            .admin_bind_ip()
            .expect("admin bind IP should exist when admin_port is configured");
        let admin_bind_addr = SocketAddr::new(admin_bind_ip, admin_port);
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
    let runtime_config = Arc::new(RwLock::new(ProxyRuntimeConfig::from_config(config)?));
    let session_runtime = Arc::new(RwLock::new(ActiveSessionRuntime::from_config(config)?));
    let initial_recordings_total = active_session_recordings_total(&session_runtime).await;
    let runtime_status = Arc::new(RuntimeStatus::new(
        config,
        listen_addr,
        admin_listen_addr,
        Arc::clone(&session_runtime),
        initial_recordings_total,
    ));
    let metrics_enabled = config
        .metrics
        .as_ref()
        .is_some_and(|metrics| metrics.enabled);
    let session_manager = SessionManager::from_config(config)?;

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: HttpClient = Client::builder(TokioExecutor::new()).build(connector);

    let state = Arc::new(ProxyState::new(
        Arc::clone(&runtime_config),
        client,
        Arc::clone(&runtime_status),
        Arc::clone(&session_runtime),
    ));
    let config_reloader = config.source_path().map(|source_path| {
        Arc::new(ConfigReloader {
            source_path: source_path.to_path_buf(),
            runtime_config: Arc::clone(&runtime_config),
            status: Arc::clone(&runtime_status),
            reload_lock: AsyncMutex::new(()),
        })
    });

    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let join = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accept = listener.accept() => {
                    let Ok((stream, _peer)) = accept else { continue };
                    let io = TokioIo::new(stream);
                    let state = Arc::clone(&state);
                    let status = Arc::clone(&state.status);
                    tokio::spawn(async move {
                        let _connection_guard = ActiveConnectionGuard::new(status);
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
            metrics_enabled,
            config_reloader,
            admin_api_token: config.proxy.admin_api_token.clone(),
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

async fn active_session_recordings_total(
    session_runtime: &Arc<RwLock<ActiveSessionRuntime>>,
) -> u64 {
    let active_storage = {
        session_runtime
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .storage
            .clone()
    };
    let Some(storage) = active_storage else {
        return 0;
    };

    match storage.count_recordings().await {
        Ok(total) => total,
        Err(err) => {
            tracing::debug!("failed to count recordings for active session: {err}");
            0
        }
    }
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
struct ProxyRuntimeConfig {
    routes: Vec<ProxyRoute>,
    max_body_bytes: usize,
}

impl ProxyRuntimeConfig {
    fn from_config(config: &Config) -> anyhow::Result<Self> {
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
            max_body_bytes: config.proxy.max_body_bytes,
        })
    }
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
    routes_configured: AtomicUsize,
    proxy_listen_addr: String,
    admin_listen_addr: Option<String>,
    proxy_requests_total: AtomicU64,
    admin_requests_total: AtomicU64,
    cache_hits_total: AtomicU64,
    cache_misses_total: AtomicU64,
    upstream_requests_total: AtomicU64,
    active_connections: AtomicU64,
    active_session_recordings_total: AtomicU64,
    metrics_state: Mutex<RuntimeMetricsState>,
}

#[derive(Debug)]
struct AdminState {
    status: Arc<RuntimeStatus>,
    session_manager: Option<SessionManager>,
    session_runtime: Arc<RwLock<ActiveSessionRuntime>>,
    metrics_enabled: bool,
    config_reloader: Option<Arc<ConfigReloader>>,
    admin_api_token: Option<String>,
}

#[derive(Debug)]
struct ConfigReloader {
    source_path: PathBuf,
    runtime_config: Arc<RwLock<ProxyRuntimeConfig>>,
    status: Arc<RuntimeStatus>,
    reload_lock: AsyncMutex<()>,
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
    active_connections: u64,
    active_session_recordings_total: u64,
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

#[derive(Debug, Deserialize, Default)]
struct AdminSessionExportRequest {
    #[serde(default)]
    out_dir: Option<PathBuf>,
    #[serde(default)]
    format: Option<SessionExportFormat>,
}

#[derive(Debug, Deserialize)]
struct AdminSessionImportRequest {
    in_dir: PathBuf,
}

#[derive(Debug, Serialize)]
struct AdminRecordingsResponse {
    session: String,
    offset: usize,
    limit: usize,
    recordings: Vec<AdminRecordingSummary>,
}

#[derive(Debug, Serialize)]
struct AdminRecordingSummary {
    id: i64,
    match_key: String,
    request_method: String,
    request_uri: String,
    response_status: u16,
    created_at_unix_ms: i64,
}

#[derive(Debug, Serialize)]
struct AdminRecordingResponse {
    id: i64,
    match_key: String,
    created_at_unix_ms: i64,
    request: AdminRequestDetails,
    response: AdminResponseDetails,
}

#[derive(Debug, Serialize)]
struct AdminRequestDetails {
    method: String,
    uri: String,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

#[derive(Debug, Serialize)]
struct AdminResponseDetails {
    status: u16,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AdminRecordingsQuery {
    offset: usize,
    limit: usize,
    method: Option<String>,
    url_contains: Option<String>,
    body_contains: Option<String>,
}

impl Default for AdminRecordingsQuery {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: ADMIN_RECORDINGS_DEFAULT_LIMIT,
            method: None,
            url_contains: None,
            body_contains: None,
        }
    }
}

impl From<RecordingSummary> for AdminRecordingSummary {
    fn from(summary: RecordingSummary) -> Self {
        Self {
            id: summary.id,
            match_key: summary.match_key,
            request_method: summary.request_method,
            request_uri: summary.request_uri,
            response_status: summary.response_status,
            created_at_unix_ms: summary.created_at_unix_ms,
        }
    }
}

impl AdminRecordingResponse {
    fn from_recording(id: i64, recording: Recording) -> Self {
        Self {
            id,
            match_key: recording.match_key,
            created_at_unix_ms: recording.created_at_unix_ms,
            request: AdminRequestDetails {
                method: recording.request_method,
                uri: recording.request_uri,
                headers: recording.request_headers,
                body: recording.request_body,
            },
            response: AdminResponseDetails {
                status: recording.response_status,
                headers: recording.response_headers,
                body: recording.response_body,
            },
        }
    }
}

#[derive(Debug, Serialize)]
struct AdminErrorResponse {
    error: String,
}

#[derive(Debug, Serialize)]
struct AdminConfigReloadResponse {
    source: String,
    routes_before: usize,
    routes_after: usize,
    max_body_bytes_before: usize,
    max_body_bytes_after: usize,
    changed: bool,
}

#[derive(Debug, Serialize)]
struct ReplayMissResponse {
    error: &'static str,
    route: String,
    session: String,
    match_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RequestCounterLabels {
    mode: String,
    method: String,
    status: u16,
}

#[derive(Debug, Clone)]
struct DurationHistogramSnapshot {
    bucket_counts: Vec<u64>,
    observations_total: u64,
    sum_seconds: f64,
}

#[derive(Debug, Clone)]
struct RuntimeMetricsSnapshot {
    requests_total: Vec<(RequestCounterLabels, u64)>,
    upstream_duration: DurationHistogramSnapshot,
    replay_duration: DurationHistogramSnapshot,
}

#[derive(Debug)]
struct DurationHistogram {
    bucket_counts: Vec<u64>,
    observations_total: u64,
    sum_micros: u64,
}

impl DurationHistogram {
    fn new() -> Self {
        Self {
            bucket_counts: vec![0; DURATION_HISTOGRAM_BUCKETS.len()],
            observations_total: 0,
            sum_micros: 0,
        }
    }

    fn observe(&mut self, latency: Duration) {
        let latency_micros = duration_to_micros(latency);
        self.observations_total = self.observations_total.saturating_add(1);
        self.sum_micros = self.sum_micros.saturating_add(latency_micros);

        for (idx, (_, upper_bound_micros)) in DURATION_HISTOGRAM_BUCKETS.iter().enumerate() {
            if latency_micros <= *upper_bound_micros {
                self.bucket_counts[idx] = self.bucket_counts[idx].saturating_add(1);
            }
        }
    }

    fn snapshot(&self) -> DurationHistogramSnapshot {
        DurationHistogramSnapshot {
            bucket_counts: self.bucket_counts.clone(),
            observations_total: self.observations_total,
            sum_seconds: self.sum_micros as f64 / 1_000_000.0,
        }
    }
}

#[derive(Debug)]
struct RuntimeMetricsState {
    requests_total: BTreeMap<RequestCounterLabels, u64>,
    upstream_duration: DurationHistogram,
    replay_duration: DurationHistogram,
}

impl RuntimeMetricsState {
    fn new() -> Self {
        Self {
            requests_total: BTreeMap::new(),
            upstream_duration: DurationHistogram::new(),
            replay_duration: DurationHistogram::new(),
        }
    }

    fn observe_request(&mut self, labels: RequestCounterLabels) {
        let counter = self.requests_total.entry(labels).or_insert(0);
        *counter = counter.saturating_add(1);
    }

    fn observe_upstream_duration(&mut self, latency: Duration) {
        self.upstream_duration.observe(latency);
    }

    fn observe_replay_duration(&mut self, latency: Duration) {
        self.replay_duration.observe(latency);
    }

    fn snapshot(&self) -> RuntimeMetricsSnapshot {
        RuntimeMetricsSnapshot {
            requests_total: self
                .requests_total
                .iter()
                .map(|(labels, count)| (labels.clone(), *count))
                .collect(),
            upstream_duration: self.upstream_duration.snapshot(),
            replay_duration: self.replay_duration.snapshot(),
        }
    }
}

#[derive(Debug)]
struct ActiveConnectionGuard {
    status: Arc<RuntimeStatus>,
}

impl ActiveConnectionGuard {
    fn new(status: Arc<RuntimeStatus>) -> Self {
        status.increment_active_connections();
        Self { status }
    }
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.status.decrement_active_connections();
    }
}

impl RuntimeStatus {
    fn new(
        config: &Config,
        proxy_listen_addr: SocketAddr,
        admin_listen_addr: Option<SocketAddr>,
        session_runtime: Arc<RwLock<ActiveSessionRuntime>>,
        initial_recordings_total: u64,
    ) -> Self {
        Self {
            started_at: Instant::now(),
            session_runtime,
            routes_configured: AtomicUsize::new(config.routes.len()),
            proxy_listen_addr: proxy_listen_addr.to_string(),
            admin_listen_addr: admin_listen_addr.map(|addr| addr.to_string()),
            proxy_requests_total: AtomicU64::new(0),
            admin_requests_total: AtomicU64::new(0),
            cache_hits_total: AtomicU64::new(0),
            cache_misses_total: AtomicU64::new(0),
            upstream_requests_total: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            active_session_recordings_total: AtomicU64::new(initial_recordings_total),
            metrics_state: Mutex::new(RuntimeMetricsState::new()),
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
            routes_configured: self.routes_configured.load(Ordering::Relaxed),
            stats: AdminStatusStats {
                proxy_requests_total: self.proxy_requests_total.load(Ordering::Relaxed),
                admin_requests_total: self.admin_requests_total.load(Ordering::Relaxed),
                cache_hits_total: self.cache_hits_total.load(Ordering::Relaxed),
                cache_misses_total: self.cache_misses_total.load(Ordering::Relaxed),
                upstream_requests_total: self.upstream_requests_total.load(Ordering::Relaxed),
                active_connections: self.active_connections.load(Ordering::Relaxed),
                active_session_recordings_total: self
                    .active_session_recordings_total
                    .load(Ordering::Relaxed),
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

    fn increment_active_connections(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    fn decrement_active_connections(&self) {
        let _ =
            self.active_connections
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_sub(1)
                });
    }

    fn set_active_session_recordings_total(&self, total: u64) {
        self.active_session_recordings_total
            .store(total, Ordering::Relaxed);
    }

    fn increment_active_session_recordings_total(&self) {
        self.active_session_recordings_total
            .fetch_add(1, Ordering::Relaxed);
    }

    fn set_routes_configured(&self, count: usize) {
        self.routes_configured.store(count, Ordering::Relaxed);
    }

    fn decrement_active_session_recordings_total(&self) {
        let _ = self.active_session_recordings_total.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |value| value.checked_sub(1),
        );
    }

    fn active_session_recordings_total(&self) -> u64 {
        self.active_session_recordings_total.load(Ordering::Relaxed)
    }

    fn observe_proxy_request(&self, mode: Option<RouteMode>, method: &str, status: StatusCode) {
        let mut metrics_state = self
            .metrics_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        metrics_state.observe_request(RequestCounterLabels {
            mode: mode_log_label(mode).to_owned(),
            method: method.to_owned(),
            status: status.as_u16(),
        });
    }

    fn observe_upstream_duration(&self, latency: Duration) {
        let mut metrics_state = self
            .metrics_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        metrics_state.observe_upstream_duration(latency);
    }

    fn observe_replay_duration(&self, latency: Duration) {
        let mut metrics_state = self
            .metrics_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        metrics_state.observe_replay_duration(latency);
    }

    fn metrics_snapshot(&self) -> RuntimeMetricsSnapshot {
        self.metrics_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .snapshot()
    }
}

impl ConfigReloader {
    async fn reload(&self) -> anyhow::Result<AdminConfigReloadResponse> {
        let _reload_guard = self.reload_lock.lock().await;
        let config = Config::from_path(&self.source_path).map_err(|err| {
            anyhow::anyhow!("reload config from {}: {err}", self.source_path.display())
        })?;
        let next_runtime = ProxyRuntimeConfig::from_config(&config)?;

        let (routes_before, max_body_bytes_before, routes_after, max_body_bytes_after) = {
            let mut runtime_config = self
                .runtime_config
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let routes_before = runtime_config.routes.len();
            let max_body_bytes_before = runtime_config.max_body_bytes;
            let routes_after = next_runtime.routes.len();
            let max_body_bytes_after = next_runtime.max_body_bytes;
            *runtime_config = next_runtime;
            (
                routes_before,
                max_body_bytes_before,
                routes_after,
                max_body_bytes_after,
            )
        };

        self.status.set_routes_configured(routes_after);

        Ok(AdminConfigReloadResponse {
            source: self.source_path.display().to_string(),
            routes_before,
            routes_after,
            max_body_bytes_before,
            max_body_bytes_after,
            changed: routes_before != routes_after || max_body_bytes_before != max_body_bytes_after,
        })
    }
}

#[derive(Debug)]
struct ProxyState {
    runtime_config: Arc<RwLock<ProxyRuntimeConfig>>,
    client: HttpClient,
    session_runtime: Arc<RwLock<ActiveSessionRuntime>>,
    status: Arc<RuntimeStatus>,
}

impl ProxyState {
    fn new(
        runtime_config: Arc<RwLock<ProxyRuntimeConfig>>,
        client: HttpClient,
        status: Arc<RuntimeStatus>,
        session_runtime: Arc<RwLock<ActiveSessionRuntime>>,
    ) -> Self {
        Self {
            runtime_config,
            client,
            session_runtime,
            status,
        }
    }

    fn route_for(&self, path: &str) -> Option<ProxyRoute> {
        let runtime_config = self
            .runtime_config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        select_route(&runtime_config.routes, path).cloned()
    }

    fn max_body_bytes(&self) -> usize {
        self.runtime_config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .max_body_bytes
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
    Read(hyper::Error),
}

#[derive(Debug)]
enum BodyReadOutcome {
    Buffered(Bytes),
    TooLarge {
        limit_bytes: usize,
        prefetched: Vec<Bytes>,
        remaining: Incoming,
    },
}

async fn read_body_with_limit(
    mut body: Incoming,
    max_body_bytes: usize,
) -> Result<BodyReadOutcome, BodyReadError> {
    let mut buffered = Vec::new();
    let mut buffered_len = 0usize;
    while let Some(frame_result) = body.frame().await {
        let frame = frame_result.map_err(BodyReadError::Read)?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        buffered_len = buffered_len.saturating_add(data.len());
        buffered.push(data);
        if buffered_len > max_body_bytes {
            return Ok(BodyReadOutcome::TooLarge {
                limit_bytes: max_body_bytes,
                prefetched: buffered,
                remaining: body,
            });
        }
    }

    if buffered.is_empty() {
        return Ok(BodyReadOutcome::Buffered(Bytes::new()));
    }
    if buffered.len() == 1 {
        return Ok(BodyReadOutcome::Buffered(
            buffered.pop().expect("buffered contains exactly one chunk"),
        ));
    }

    let mut flattened = Vec::with_capacity(buffered_len);
    for chunk in buffered {
        flattened.extend_from_slice(&chunk);
    }
    Ok(BodyReadOutcome::Buffered(Bytes::from(flattened)))
}

struct PrefixedIncomingBody {
    prefetched: VecDeque<Bytes>,
    remaining: Incoming,
}

impl PrefixedIncomingBody {
    fn new(prefetched: Vec<Bytes>, remaining: Incoming) -> Self {
        Self {
            prefetched: prefetched.into(),
            remaining,
        }
    }
}

impl hyper::body::Body for PrefixedIncomingBody {
    type Data = Bytes;
    type Error = Box<dyn StdError + Send + Sync>;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(chunk) = this.prefetched.pop_front() {
            return Poll::Ready(Some(Ok(Frame::data(chunk))));
        }
        match Pin::new(&mut this.remaining).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(Box::new(err)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
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

fn boxed_prefetched_incoming(prefetched: Vec<Bytes>, body: Incoming) -> ProxyBody {
    PrefixedIncomingBody::new(prefetched, body).boxed()
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
    let mut replay_latency: Option<Duration> = None;
    let max_body_bytes = state.max_body_bytes();

    macro_rules! respond {
        ($upstream_latency:expr, $response:expr) => {{
            let observation = RequestObservation {
                method: &request_method,
                url: &request_url,
                route_ref,
                mode,
                cache_outcome,
                replay_latency,
                upstream_latency: $upstream_latency,
            };
            return Ok(response_with_observability(
                state.status.as_ref(),
                observation,
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
        .map(|len| len > bytes_limit_u64(max_body_bytes))
        .unwrap_or(false);
    let allow_oversize_bypass_cache =
        route.body_oversize == BodyOversizePolicy::BypassCache && route.mode != RouteMode::Replay;
    let bypass_request_buffering = request_known_oversize && allow_oversize_bypass_cache;
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
            limit_bytes = max_body_bytes,
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

    let body_bytes = match read_body_with_limit(body, max_body_bytes).await {
        Ok(BodyReadOutcome::Buffered(bytes)) => bytes,
        Ok(BodyReadOutcome::TooLarge {
            limit_bytes,
            prefetched,
            remaining,
        }) => {
            if allow_oversize_bypass_cache {
                tracing::debug!(
                    limit_bytes = max_body_bytes,
                    "bypassing cache after request body exceeded configured limit mid-stream"
                );

                parts.uri = upstream_uri.clone();
                set_host_header(&mut parts.headers, &upstream_uri);
                let upstream_req =
                    Request::from_parts(parts, boxed_prefetched_incoming(prefetched, remaining));

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
                            proxy_simple_response(
                                StatusCode::BAD_GATEWAY,
                                "upstream request failed",
                            )
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
                tracing::debug!(error_kind = err.kind(), "failed to compute match key");
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
            let replay_started_at = Instant::now();
            let lookup_result = lookup_recording_for_request(
                storage,
                route.match_config.as_ref(),
                &parts.uri,
                match_key,
            )
            .await;
            replay_latency = Some(replay_started_at.elapsed());
            match lookup_result {
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
                            replay_miss_response(&route, &active_session_name, match_key,)
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
                let replay_started_at = Instant::now();
                let lookup_result = lookup_recording_for_request(
                    storage,
                    route.match_config.as_ref(),
                    &parts.uri,
                    match_key,
                )
                .await;
                replay_latency = Some(replay_started_at.elapsed());
                match lookup_result {
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
        .map(|len| len > bytes_limit_u64(max_body_bytes))
        .unwrap_or(false);
    if response_known_oversize {
        if route.body_oversize == BodyOversizePolicy::BypassCache {
            tracing::debug!(
                limit_bytes = max_body_bytes,
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

    let body_bytes = match read_body_with_limit(body, max_body_bytes).await {
        Ok(BodyReadOutcome::Buffered(bytes)) => bytes,
        Ok(BodyReadOutcome::TooLarge {
            limit_bytes,
            prefetched,
            remaining,
        }) => {
            if route.body_oversize == BodyOversizePolicy::BypassCache {
                tracing::debug!(
                    limit_bytes = max_body_bytes,
                    "bypassing cache after upstream response body exceeded configured limit mid-stream"
                );
                respond!(
                    Some(upstream_latency),
                    Response::from_parts(parts, boxed_prefetched_incoming(prefetched, remaining))
                );
            }
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
        let request_body =
            redact_recording_body_json(request_body.as_slice(), route.redact.as_ref());
        let response_body = redact_recording_body_json(body_bytes.as_ref(), route.redact.as_ref());
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
            response_body,
            created_at_unix_ms,
        };

        match storage.insert_recording(recording).await {
            Ok(_) => state.status.increment_active_session_recordings_total(),
            Err(err) => tracing::debug!("failed to persist recording: {err}"),
        }
    }

    respond!(
        Some(upstream_latency),
        Response::from_parts(parts, boxed_full(body_bytes))
    );
}

#[derive(Debug, Clone, Copy)]
struct RequestObservation<'a> {
    method: &'a str,
    url: &'a str,
    route_ref: Option<&'a str>,
    mode: Option<RouteMode>,
    cache_outcome: CacheLogOutcome,
    replay_latency: Option<Duration>,
    upstream_latency: Option<Duration>,
}

fn response_with_observability<B>(
    status: &RuntimeStatus,
    observation: RequestObservation<'_>,
    response: Response<B>,
) -> Response<B> {
    let response_status = response.status();
    status.observe_proxy_request(observation.mode, observation.method, response_status);
    if let Some(latency) = observation.replay_latency {
        status.observe_replay_duration(latency);
    }
    if let Some(latency) = observation.upstream_latency {
        status.observe_upstream_duration(latency);
    }
    emit_proxy_request_log(
        observation.method,
        observation.url,
        observation.route_ref,
        observation.mode,
        observation.cache_outcome,
        observation.upstream_latency,
        response_status,
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
    lookup_recording_for_request_with_subset_limit(
        storage,
        route_match,
        request_uri,
        match_key,
        SUBSET_QUERY_CANDIDATE_LIMIT,
    )
    .await
}

async fn lookup_recording_for_request_with_subset_limit(
    storage: &Storage,
    route_match: Option<&RouteMatchConfig>,
    request_uri: &Uri,
    match_key: &str,
    subset_candidate_limit: usize,
) -> anyhow::Result<Option<Recording>> {
    let query_mode = route_match
        .map(|route_match| route_match.query)
        .unwrap_or(QueryMatchMode::Exact);

    if query_mode != QueryMatchMode::Subset {
        return storage.get_recording_by_match_key(match_key).await;
    }

    let request_query = request_uri.query();
    if let Some(subset_query_normalizations) =
        matching::subset_query_candidate_normalizations_with_limit(
            request_query,
            subset_candidate_limit,
        )
    {
        return storage
            .get_latest_recording_by_match_key_and_query_subset(
                match_key,
                subset_query_normalizations,
            )
            .await;
    }

    let request_query_param_count = request_query
        .map(|query| {
            query
                .split('&')
                .filter(|segment| !segment.is_empty())
                .count()
        })
        .unwrap_or(0);
    tracing::debug!(
        match_key = %sanitize_match_key(match_key),
        subset_candidate_limit,
        request_query_param_count,
        "subset candidate combinations exceeded limit; falling back to recording scan"
    );

    let matched = storage
        .get_latest_recording_by_match_key_and_query_subset_scan(match_key, request_query)
        .await?;
    tracing::debug!(
        match_key = %sanitize_match_key(match_key),
        subset_candidate_limit,
        request_query_param_count,
        matched = matched.is_some(),
        "completed subset lookup fallback recording scan"
    );
    Ok(matched)
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

fn duration_to_micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn prometheus_escape_label_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn append_prometheus_histogram(
    body: &mut String,
    metric_name: &str,
    help: &str,
    snapshot: &DurationHistogramSnapshot,
) {
    let _ = writeln!(body, "# HELP {metric_name} {help}");
    let _ = writeln!(body, "# TYPE {metric_name} histogram");
    for ((bound_label, _), count) in DURATION_HISTOGRAM_BUCKETS
        .iter()
        .zip(&snapshot.bucket_counts)
    {
        let _ = writeln!(body, "{metric_name}_bucket{{le=\"{bound_label}\"}} {count}");
    }
    let _ = writeln!(
        body,
        "{metric_name}_bucket{{le=\"+Inf\"}} {}",
        snapshot.observations_total
    );
    let _ = writeln!(body, "{metric_name}_sum {:.6}", snapshot.sum_seconds);
    let _ = writeln!(body, "{metric_name}_count {}", snapshot.observations_total);
}

async fn recordings_totals_by_session(
    session_manager: Option<&SessionManager>,
    status: &RuntimeStatus,
) -> Vec<(String, u64)> {
    let fallback = || {
        vec![(
            status.active_session(),
            status.active_session_recordings_total(),
        )]
    };
    let Some(session_manager) = session_manager else {
        return fallback();
    };

    let mut sessions = match session_manager.list_sessions().await {
        Ok(sessions) => sessions,
        Err(err) => {
            tracing::debug!("failed to list sessions for metrics output: {err}");
            return fallback();
        }
    };
    sessions.sort_unstable();

    let mut totals = Vec::with_capacity(sessions.len());
    for session_name in sessions {
        let total = match session_manager.open_session_storage(&session_name).await {
            Ok(storage) => match storage.count_recordings().await {
                Ok(total) => total,
                Err(err) => {
                    tracing::debug!(
                        "failed to count recordings for session `{session_name}`: {err}"
                    );
                    0
                }
            },
            Err(err) => {
                tracing::debug!("failed to open session `{session_name}` for metrics: {err}");
                0
            }
        };
        totals.push((session_name, total));
    }
    if totals.is_empty() {
        fallback()
    } else {
        totals
    }
}

fn admin_metrics_response(
    status: &RuntimeStatus,
    recordings_totals: &[(String, u64)],
) -> Response<Full<Bytes>> {
    let snapshot = status.snapshot();
    let metrics_snapshot = status.metrics_snapshot();
    let mut body = String::new();
    let _ = writeln!(
        body,
        "# HELP replayproxy_uptime_seconds Proxy uptime in seconds."
    );
    let _ = writeln!(body, "# TYPE replayproxy_uptime_seconds gauge");
    let _ = writeln!(
        body,
        "replayproxy_uptime_seconds {:.3}",
        snapshot.uptime_ms as f64 / 1_000.0
    );
    let _ = writeln!(
        body,
        "# HELP replayproxy_routes_configured Number of configured routes."
    );
    let _ = writeln!(body, "# TYPE replayproxy_routes_configured gauge");
    let _ = writeln!(
        body,
        "replayproxy_routes_configured {}",
        snapshot.routes_configured
    );

    let _ = writeln!(
        body,
        "# HELP replayproxy_proxy_requests_total Total requests handled by the proxy listener."
    );
    let _ = writeln!(body, "# TYPE replayproxy_proxy_requests_total counter");
    let _ = writeln!(
        body,
        "replayproxy_proxy_requests_total {}",
        snapshot.stats.proxy_requests_total
    );
    let _ = writeln!(
        body,
        "# HELP replayproxy_admin_requests_total Total requests handled by the admin listener."
    );
    let _ = writeln!(body, "# TYPE replayproxy_admin_requests_total counter");
    let _ = writeln!(
        body,
        "replayproxy_admin_requests_total {}",
        snapshot.stats.admin_requests_total
    );
    let _ = writeln!(
        body,
        "# HELP replayproxy_requests_total Total requests handled by the proxy grouped by mode/method/status."
    );
    let _ = writeln!(body, "# TYPE replayproxy_requests_total counter");
    for (labels, count) in &metrics_snapshot.requests_total {
        let _ = writeln!(
            body,
            "replayproxy_requests_total{{mode=\"{}\",method=\"{}\",status=\"{}\"}} {}",
            prometheus_escape_label_value(&labels.mode),
            prometheus_escape_label_value(&labels.method),
            labels.status,
            count
        );
    }

    let _ = writeln!(
        body,
        "# HELP replayproxy_cache_hits_total Total cache hits served from recordings."
    );
    let _ = writeln!(body, "# TYPE replayproxy_cache_hits_total counter");
    let _ = writeln!(
        body,
        "replayproxy_cache_hits_total {}",
        snapshot.stats.cache_hits_total
    );
    let _ = writeln!(
        body,
        "# HELP replayproxy_cache_misses_total Total cache misses that required fallback handling."
    );
    let _ = writeln!(body, "# TYPE replayproxy_cache_misses_total counter");
    let _ = writeln!(
        body,
        "replayproxy_cache_misses_total {}",
        snapshot.stats.cache_misses_total
    );
    let _ = writeln!(
        body,
        "# HELP replayproxy_upstream_requests_total Total requests forwarded upstream."
    );
    let _ = writeln!(body, "# TYPE replayproxy_upstream_requests_total counter");
    let _ = writeln!(
        body,
        "replayproxy_upstream_requests_total {}",
        snapshot.stats.upstream_requests_total
    );
    append_prometheus_histogram(
        &mut body,
        "replayproxy_upstream_duration_seconds",
        "Histogram of upstream response times.",
        &metrics_snapshot.upstream_duration,
    );
    append_prometheus_histogram(
        &mut body,
        "replayproxy_replay_duration_seconds",
        "Histogram of replay lookup response times.",
        &metrics_snapshot.replay_duration,
    );
    let _ = writeln!(
        body,
        "# HELP replayproxy_active_connections Current number of active client connections."
    );
    let _ = writeln!(body, "# TYPE replayproxy_active_connections gauge");
    let _ = writeln!(
        body,
        "replayproxy_active_connections {}",
        snapshot.stats.active_connections
    );
    let _ = writeln!(
        body,
        "# HELP replayproxy_recordings_total Number of stored recordings for a session."
    );
    let _ = writeln!(body, "# TYPE replayproxy_recordings_total gauge");
    for (session_name, total) in recordings_totals {
        let _ = writeln!(
            body,
            "replayproxy_recordings_total{{session=\"{}\"}} {}",
            prometheus_escape_label_value(session_name),
            total
        );
    }

    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    response
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

fn status_for_session_export_error(err: &SessionExportError) -> StatusCode {
    match err {
        SessionExportError::InvalidRequest(_) => StatusCode::BAD_REQUEST,
        SessionExportError::Session(err) => status_for_session_error(err),
        SessionExportError::Io(_) | SessionExportError::Internal(_) => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

fn status_for_session_import_error(err: &SessionImportError) -> StatusCode {
    match err {
        SessionImportError::InvalidRequest(_) => StatusCode::BAD_REQUEST,
        SessionImportError::Session(err) => status_for_session_error(err),
        SessionImportError::Io(_) | SessionImportError::Internal(_) => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

fn status_for_config_reload_error(message: &str) -> StatusCode {
    if message.contains("parse config ")
        || message.contains("parse route.path_regex")
        || message.contains("parse route.upstream")
    {
        return StatusCode::BAD_REQUEST;
    }

    StatusCode::INTERNAL_SERVER_ERROR
}

fn parse_admin_session_export_path(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/_admin/sessions/")?;
    let (session_name, export_suffix) = rest.split_once("/export")?;
    if session_name.is_empty() || session_name.contains('/') {
        return None;
    }
    if export_suffix.is_empty() || export_suffix == "/" {
        return Some(session_name);
    }
    None
}

fn parse_admin_session_import_path(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/_admin/sessions/")?;
    let (session_name, import_suffix) = rest.split_once("/import")?;
    if session_name.is_empty() || session_name.contains('/') {
        return None;
    }
    if import_suffix.is_empty() || import_suffix == "/" {
        return Some(session_name);
    }
    None
}

fn parse_admin_recordings_collection_path(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/_admin/sessions/")?;
    let (session_name, recordings_suffix) = rest.split_once("/recordings")?;
    if session_name.is_empty() || session_name.contains('/') {
        return None;
    }
    if recordings_suffix.is_empty() || recordings_suffix == "/" {
        return Some(session_name);
    }
    None
}

fn parse_admin_recording_item_path(path: &str) -> Option<(&str, i64)> {
    let rest = path.strip_prefix("/_admin/sessions/")?;
    let (session_name, recording_id) = rest.split_once("/recordings/")?;
    if session_name.is_empty()
        || session_name.contains('/')
        || recording_id.is_empty()
        || recording_id.contains('/')
    {
        return None;
    }
    let recording_id = recording_id.parse::<i64>().ok()?;
    Some((session_name, recording_id))
}

fn parse_admin_recordings_query(uri: &Uri) -> Result<AdminRecordingsQuery, String> {
    let mut query = AdminRecordingsQuery::default();
    let Some(raw_query) = uri.query() else {
        return Ok(query);
    };

    for pair in raw_query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match key {
            "offset" => {
                query.offset = parse_admin_recordings_pagination(value, "offset")?;
            }
            "limit" => {
                query.limit = parse_admin_recordings_pagination(value, "limit")?;
            }
            "method" => {
                let value = value.trim();
                query.method = (!value.is_empty()).then_some(value.to_owned());
            }
            "url_contains" => {
                let value = value.trim();
                query.url_contains = (!value.is_empty()).then_some(value.to_owned());
            }
            "body_contains" => {
                let value = value.trim();
                query.body_contains = (!value.is_empty()).then_some(value.to_owned());
            }
            _ => {}
        }
    }

    Ok(query)
}

fn parse_admin_recordings_pagination(value: &str, field_name: &str) -> Result<usize, String> {
    if value.is_empty() {
        return Err(format!("query parameter `{field_name}` must not be empty"));
    }
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("query parameter `{field_name}` must be a non-negative integer"))?;
    if i64::try_from(parsed).is_err() {
        return Err(format!(
            "query parameter `{field_name}` exceeds supported sqlite range"
        ));
    }
    Ok(parsed)
}

fn admin_request_authorized(req: &Request<Incoming>, expected_token: Option<&str>) -> bool {
    let Some(expected_token) = expected_token else {
        return true;
    };

    req.headers()
        .get(ADMIN_API_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|provided_token| provided_token == expected_token)
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
    if !admin_request_authorized(&req, state.admin_api_token.as_deref()) {
        return Ok(admin_error_response(
            StatusCode::UNAUTHORIZED,
            format!("missing or invalid `{ADMIN_API_TOKEN_HEADER}` header for admin API access"),
        ));
    }

    if path == "/metrics" {
        if !state.metrics_enabled {
            return Ok(simple_response(StatusCode::NOT_FOUND, "not found"));
        }
        if method != hyper::Method::GET {
            return Ok(simple_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed",
            ));
        }
        let recordings_totals =
            recordings_totals_by_session(state.session_manager.as_ref(), &state.status).await;
        return Ok(admin_metrics_response(&state.status, &recordings_totals));
    }

    if path == "/_admin/status" {
        if method != hyper::Method::GET {
            return Ok(simple_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed",
            ));
        }
        return Ok(admin_status_response(&state.status));
    }

    if path == "/_admin/config/reload" {
        if method != hyper::Method::POST {
            return Ok(admin_error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed",
            ));
        }
        let Some(config_reloader) = state.config_reloader.as_ref() else {
            return Ok(admin_error_response(
                StatusCode::CONFLICT,
                "config reload unavailable; start proxy from a config file path",
            ));
        };

        return match config_reloader.reload().await {
            Ok(summary) => Ok(admin_json_response(StatusCode::OK, &summary)),
            Err(err) => {
                let message = err.to_string();
                tracing::debug!("failed to reload config: {message}");
                Ok(admin_error_response(
                    status_for_config_reload_error(&message),
                    message,
                ))
            }
        };
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

    if let Some((session_name, recording_id)) = parse_admin_recording_item_path(&path) {
        let Some(session_manager) = state.session_manager.as_ref() else {
            return Ok(admin_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage not configured; session management is unavailable",
            ));
        };

        let storage = match session_manager.open_session_storage(session_name).await {
            Ok(storage) => storage,
            Err(err) => {
                return Ok(admin_error_response(
                    status_for_session_error(&err),
                    err.to_string(),
                ));
            }
        };

        return match method {
            hyper::Method::GET => match storage.get_recording_by_id(recording_id).await {
                Ok(Some(recording)) => Ok(admin_json_response(
                    StatusCode::OK,
                    &AdminRecordingResponse::from_recording(recording_id, recording),
                )),
                Ok(None) => Ok(admin_error_response(
                    StatusCode::NOT_FOUND,
                    format!("recording `{recording_id}` was not found"),
                )),
                Err(err) => {
                    tracing::debug!(
                        "failed to fetch recording `{recording_id}` from session `{session_name}`: {err}"
                    );
                    Ok(admin_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "failed to fetch recording",
                    ))
                }
            },
            hyper::Method::DELETE => match storage.delete_recording(recording_id).await {
                Ok(true) => {
                    if state.status.active_session() == session_name {
                        state.status.decrement_active_session_recordings_total();
                    }
                    let mut response = Response::new(Full::new(Bytes::new()));
                    *response.status_mut() = StatusCode::NO_CONTENT;
                    Ok(response)
                }
                Ok(false) => Ok(admin_error_response(
                    StatusCode::NOT_FOUND,
                    format!("recording `{recording_id}` was not found"),
                )),
                Err(err) => {
                    tracing::debug!(
                        "failed to delete recording `{recording_id}` from session `{session_name}`: {err}"
                    );
                    Ok(admin_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "failed to delete recording",
                    ))
                }
            },
            _ => Ok(admin_error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed",
            )),
        };
    }

    if let Some(session_name) = parse_admin_recordings_collection_path(&path) {
        if method != hyper::Method::GET {
            return Ok(admin_error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed",
            ));
        }

        let query = match parse_admin_recordings_query(req.uri()) {
            Ok(query) => query,
            Err(message) => return Ok(admin_error_response(StatusCode::BAD_REQUEST, message)),
        };

        let Some(session_manager) = state.session_manager.as_ref() else {
            return Ok(admin_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage not configured; session management is unavailable",
            ));
        };

        let storage = match session_manager.open_session_storage(session_name).await {
            Ok(storage) => storage,
            Err(err) => {
                return Ok(admin_error_response(
                    status_for_session_error(&err),
                    err.to_string(),
                ));
            }
        };

        let recordings_result = if query.method.is_some()
            || query.url_contains.is_some()
            || query.body_contains.is_some()
        {
            storage
                .search_recordings(
                    RecordingSearch {
                        method: query.method.clone(),
                        url_contains: query.url_contains.clone(),
                        body_contains: query.body_contains.clone(),
                    },
                    query.offset,
                    query.limit,
                )
                .await
        } else {
            storage.list_recordings(query.offset, query.limit).await
        };

        return match recordings_result {
            Ok(recordings) => {
                let response = AdminRecordingsResponse {
                    session: session_name.to_owned(),
                    offset: query.offset,
                    limit: query.limit,
                    recordings: recordings
                        .into_iter()
                        .map(AdminRecordingSummary::from)
                        .collect(),
                };
                Ok(admin_json_response(StatusCode::OK, &response))
            }
            Err(err) => {
                tracing::debug!(
                    "failed to list recordings for session `{session_name}` with query {:?}: {err}",
                    query
                );
                Ok(admin_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to list recordings",
                ))
            }
        };
    }

    if let Some(session_name) = parse_admin_session_export_path(&path) {
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

        let body_bytes = match req.into_body().collect().await {
            Ok(body) => body.to_bytes(),
            Err(err) => {
                return Ok(admin_error_response(
                    StatusCode::BAD_REQUEST,
                    format!("failed to read request body: {err}"),
                ));
            }
        };
        let export_request = if body_bytes.is_empty() {
            AdminSessionExportRequest::default()
        } else {
            match serde_json::from_slice::<AdminSessionExportRequest>(&body_bytes) {
                Ok(request) => request,
                Err(err) => {
                    return Ok(admin_error_response(
                        StatusCode::BAD_REQUEST,
                        format!("invalid JSON body: {err}"),
                    ));
                }
            }
        };

        return match session_export::export_session(
            session_manager,
            SessionExportRequest {
                session_name: session_name.to_owned(),
                out_dir: export_request.out_dir,
                format: export_request.format.unwrap_or_default(),
            },
        )
        .await
        {
            Ok(result) => Ok(admin_json_response(StatusCode::OK, &result)),
            Err(err) => Ok(admin_error_response(
                status_for_session_export_error(&err),
                err.to_string(),
            )),
        };
    }

    if let Some(session_name) = parse_admin_session_import_path(&path) {
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

        let body_bytes = match req.into_body().collect().await {
            Ok(body) => body.to_bytes(),
            Err(err) => {
                return Ok(admin_error_response(
                    StatusCode::BAD_REQUEST,
                    format!("failed to read request body: {err}"),
                ));
            }
        };
        if body_bytes.is_empty() {
            return Ok(admin_error_response(
                StatusCode::BAD_REQUEST,
                "invalid JSON body: missing `in_dir`",
            ));
        }
        let import_request = match serde_json::from_slice::<AdminSessionImportRequest>(&body_bytes)
        {
            Ok(request) => request,
            Err(err) => {
                return Ok(admin_error_response(
                    StatusCode::BAD_REQUEST,
                    format!("invalid JSON body: {err}"),
                ));
            }
        };

        return match session_import::import_session(
            session_manager,
            SessionImportRequest {
                session_name: session_name.to_owned(),
                in_dir: import_request.in_dir,
            },
        )
        .await
        {
            Ok(result) => {
                if state.status.active_session() == session_name {
                    let active_storage = {
                        let session_runtime = state
                            .session_runtime
                            .read()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        session_runtime.storage.clone()
                    };
                    if let Some(active_storage) = active_storage {
                        match active_storage.count_recordings().await {
                            Ok(total) => state.status.set_active_session_recordings_total(total),
                            Err(err) => {
                                tracing::debug!(
                                    "failed to refresh active session recording count after import for `{session_name}`: {err}"
                                );
                            }
                        }
                    }
                }
                Ok(admin_json_response(StatusCode::OK, &result))
            }
            Err(err) => Ok(admin_error_response(
                status_for_session_import_error(&err),
                err.to_string(),
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
                let recordings_total = match storage.count_recordings().await {
                    Ok(total) => total,
                    Err(err) => {
                        tracing::debug!(
                            "failed to count recordings while activating session `{session_name}`: {err}"
                        );
                        0
                    }
                };
                let mut session_runtime = state
                    .session_runtime
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                session_runtime.active_session = session_name.to_owned();
                session_runtime.storage = Some(storage);
                state
                    .status
                    .set_active_session_recordings_total(recordings_total);
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
    let placeholder = redaction_placeholder(redact).as_bytes();

    headers
        .into_iter()
        .map(|(name, value)| {
            if redact
                .headers
                .iter()
                .any(|configured| configured.eq_ignore_ascii_case(name.as_str()))
            {
                (name, placeholder.to_vec())
            } else {
                (name, value)
            }
        })
        .collect()
}

fn redact_recording_body_json(body: &[u8], redact: Option<&RedactConfig>) -> Vec<u8> {
    let Some(redact) = redact else {
        return body.to_vec();
    };

    if redact.body_json.is_empty() {
        return body.to_vec();
    }

    let mut json: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => {
            tracing::debug!(
                body_len = body.len(),
                "recording body is not valid JSON; skipping body redaction"
            );
            return body.to_vec();
        }
    };

    let mut pointers = Vec::new();
    for (expression_idx, expression) in redact.body_json.iter().enumerate() {
        let path = match JsonPath::parse(expression) {
            Ok(path) => path,
            Err(_) => {
                tracing::debug!(
                    expression_index = expression_idx,
                    "failed to parse redaction JSONPath expression at runtime; skipping expression"
                );
                continue;
            }
        };
        pointers.extend(
            path.query_located(&json)
                .locations()
                .map(|location| location.to_json_pointer()),
        );
    }

    if pointers.is_empty() {
        return body.to_vec();
    }

    pointers.sort_unstable();
    pointers.dedup();

    let placeholder = Value::String(redaction_placeholder(redact).to_owned());
    for pointer in pointers {
        if let Some(node) = json.pointer_mut(pointer.as_str()) {
            *node = placeholder.clone();
        }
    }

    match serde_json::to_vec(&json) {
        Ok(body) => body,
        Err(_) => {
            tracing::debug!("failed to serialize redacted recording body; returning original body");
            body.to_vec()
        }
    }
}

fn redaction_placeholder(redact: &RedactConfig) -> &str {
    redact
        .placeholder
        .as_deref()
        .unwrap_or(REDACTION_PLACEHOLDER)
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

    use super::{
        CacheLogOutcome, ProxyRoute, REDACTION_PLACEHOLDER, emit_proxy_request_log,
        format_route_ref, lookup_recording_for_request_with_subset_limit, mode_log_label,
        redact_recording_body_json, redact_recording_headers, sanitize_match_key, select_route,
    };
    use crate::config::{
        BodyOversizePolicy, CacheMissPolicy, Config, RedactConfig, RouteConfig, RouteMatchConfig,
        RouteMode,
    };
    use crate::storage::{Recording, Storage};
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

    #[tokio::test]
    async fn subset_lookup_fallback_scan_returns_newest_matching_recording() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp_dir.path().join("recordings.db")).unwrap();

        let mut base = Recording {
            match_key: "same-key".to_owned(),
            request_method: "GET".to_owned(),
            request_uri: "/api?a=1".to_owned(),
            request_headers: Vec::new(),
            request_body: Vec::new(),
            response_status: 200,
            response_headers: Vec::new(),
            response_body: b"older-matching".to_vec(),
            created_at_unix_ms: Recording::now_unix_ms().unwrap(),
        };
        storage.insert_recording(base.clone()).await.unwrap();

        base.request_uri = "/api?a=1&b=2".to_owned();
        base.response_body = b"newer-matching".to_vec();
        base.created_at_unix_ms += 1;
        storage.insert_recording(base.clone()).await.unwrap();

        base.request_uri = "/api?x=9".to_owned();
        base.response_body = b"newest-nonmatching".to_vec();
        base.created_at_unix_ms += 1;
        storage.insert_recording(base).await.unwrap();

        let route_match: RouteMatchConfig = toml::from_str("query = \"subset\"\n").unwrap();
        let request_uri: hyper::Uri = "http://example.com/api?a=1&b=2&c=3".parse().unwrap();
        let fetched = lookup_recording_for_request_with_subset_limit(
            &storage,
            Some(&route_match),
            &request_uri,
            "same-key",
            2,
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(fetched.request_uri, "/api?a=1&b=2");
        assert_eq!(fetched.response_body, b"newer-matching");
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
            placeholder: None,
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
    fn redact_recording_uses_custom_placeholder_when_configured() {
        let headers = vec![("Authorization".to_owned(), b"Bearer topsecret".to_vec())];
        let redact = RedactConfig {
            headers: vec!["authorization".to_owned()],
            body_json: vec!["$.secret".to_owned()],
            placeholder: Some("<MASKED>".to_owned()),
        };

        let redacted_headers = redact_recording_headers(headers, Some(&redact));
        let authorization = redacted_headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.as_slice());
        assert_eq!(authorization, Some(b"<MASKED>".as_slice()));

        let body = br#"{"secret":"super-secret","safe":"ok"}"#;
        let redacted_body = redact_recording_body_json(body, Some(&redact));
        let parsed: Value = serde_json::from_slice(&redacted_body).unwrap();
        assert_eq!(
            parsed.pointer("/secret").and_then(Value::as_str),
            Some("<MASKED>")
        );
        assert_eq!(parsed.pointer("/safe").and_then(Value::as_str), Some("ok"));
    }

    #[test]
    fn redact_recording_body_json_masks_nested_object_and_array_fields() {
        let redact = RedactConfig {
            headers: Vec::new(),
            body_json: vec![
                "$.auth.token".to_owned(),
                "$.messages[*].content".to_owned(),
            ],
            placeholder: None,
        };
        let body = br#"{"auth":{"token":"super-secret","keep":"ok"},"messages":[{"content":"first"},{"content":"second"}]}"#;

        let redacted = redact_recording_body_json(body, Some(&redact));
        let parsed: Value = serde_json::from_slice(&redacted).unwrap();

        assert_eq!(
            parsed.pointer("/auth/token").and_then(Value::as_str),
            Some(REDACTION_PLACEHOLDER)
        );
        assert_eq!(
            parsed.pointer("/auth/keep").and_then(Value::as_str),
            Some("ok")
        );
        assert_eq!(
            parsed
                .pointer("/messages/0/content")
                .and_then(Value::as_str),
            Some(REDACTION_PLACEHOLDER)
        );
        assert_eq!(
            parsed
                .pointer("/messages/1/content")
                .and_then(Value::as_str),
            Some(REDACTION_PLACEHOLDER)
        );
    }

    #[test]
    fn redact_recording_body_json_leaves_non_json_payload_unchanged() {
        let redact = RedactConfig {
            headers: Vec::new(),
            body_json: vec!["$.secret".to_owned()],
            placeholder: None,
        };
        let body = b"plain-text-body";

        let redacted = redact_recording_body_json(body, Some(&redact));

        assert_eq!(redacted, body);
    }

    #[test]
    fn redact_recording_body_json_logs_do_not_leak_invalid_json_body_values() {
        let redact = RedactConfig {
            headers: Vec::new(),
            body_json: vec!["$.secret".to_owned()],
            placeholder: None,
        };
        let secret = "sk-live-super-secret";
        let body = format!(r#"{{"secret":"{secret}""#);

        let output = capture_debug_logs(|| {
            let _ = redact_recording_body_json(body.as_bytes(), Some(&redact));
        });

        assert!(
            output.contains("recording body is not valid JSON; skipping body redaction"),
            "log output: {output}"
        );
        assert!(
            !output.contains(secret),
            "log output leaked sensitive body value: {output}"
        );
    }

    #[test]
    fn redact_recording_body_json_logs_do_not_leak_invalid_expression_values() {
        let secret = "sk-live-super-secret";
        let expression = format!("$['{secret}'");
        let redact = RedactConfig {
            headers: Vec::new(),
            body_json: vec![expression.clone()],
            placeholder: None,
        };
        let body = format!(r#"{{"secret":"{secret}"}}"#);

        let output = capture_debug_logs(|| {
            let _ = redact_recording_body_json(body.as_bytes(), Some(&redact));
        });

        assert!(
            output.contains(
                "failed to parse redaction JSONPath expression at runtime; skipping expression"
            ),
            "log output: {output}"
        );
        assert!(
            !output.contains(secret),
            "log output leaked sensitive value: {output}"
        );
        assert!(
            !output.contains(&expression),
            "log output leaked raw expression: {output}"
        );
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

    fn capture_debug_logs(f: impl FnOnce()) -> String {
        let writer = SharedWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(LevelFilter::DEBUG)
            .with_target(false)
            .with_ansi(false)
            .without_time()
            .with_writer(writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        writer.as_string()
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
