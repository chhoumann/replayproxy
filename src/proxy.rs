use std::{
    cmp::Reverse,
    collections::{BTreeMap, VecDeque},
    convert::Infallible,
    env,
    error::Error as StdError,
    ffi::OsStr,
    fmt::Write as _,
    future::Future,
    net::SocketAddr,
    path::Component,
    path::{Path, PathBuf},
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
    Method, Request, Response, StatusCode, Uri,
    body::{Frame, Incoming},
    header::{self, HeaderName, HeaderValue},
    http::uri::Authority,
    service::service_fn,
};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{Client, Error as LegacyClientError, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as ConnectionBuilder,
};
use regex::Regex;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json_path::JsonPath;
#[cfg(feature = "watch")]
use tokio::sync::mpsc;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex as AsyncMutex, oneshot},
    time::{Instant as TokioInstant, Sleep},
};
use tokio_rustls::TlsAcceptor;

#[cfg(feature = "scripting")]
use crate::scripting::{
    ScriptRecording, ScriptRequest, ScriptResponse, run_on_record_script, run_on_replay_script,
    run_on_request_script, run_on_response_script,
};
use crate::{
    ca,
    config::{
        BodyOversizePolicy, CacheMissPolicy, Config, QueryMatchMode, RateLimitConfig, RedactConfig,
        RouteMatchConfig, RouteMode, StreamingConfig, TransformConfig, WebSocketConfig,
    },
    matching,
    session_export::{self, SessionExportError, SessionExportFormat, SessionExportRequest},
    session_import::{self, SessionImportError, SessionImportRequest},
    storage::{
        Recording, RecordingSearch, RecordingSummary, ResponseChunk, SessionManager,
        SessionManagerError, Storage, StoredRecording,
    },
};

type ProxyBody = BoxBody<Bytes, Box<dyn StdError + Send + Sync>>;
type ProxyHttpsConnector = HttpsConnector<HttpConnector>;
type HttpClient = Client<ProxyHttpsConnector, ProxyBody>;
const REDACTION_PLACEHOLDER: &str = "[REDACTED]";
const SUBSET_QUERY_CANDIDATE_LIMIT: usize = 4096;
const ADMIN_RECORDINGS_DEFAULT_LIMIT: usize = 100;
const ADMIN_API_TOKEN_HEADER: &str = "x-replayproxy-admin-token";
const CONFIG_WATCH_DEBOUNCE_WINDOW: Duration = Duration::from_millis(250);
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
    config_watcher_shutdown_tx: Option<oneshot::Sender<()>>,
    config_watcher_join: Option<tokio::task::JoinHandle<()>>,
}

impl ProxyHandle {
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
        if let Some(admin_shutdown_tx) = self.admin_shutdown_tx {
            let _ = admin_shutdown_tx.send(());
        }
        if let Some(config_watcher_shutdown_tx) = self.config_watcher_shutdown_tx {
            let _ = config_watcher_shutdown_tx.send(());
        }
        let _ = self.join.await;
        if let Some(admin_join) = self.admin_join {
            let _ = admin_join.await;
        }
        if let Some(config_watcher_join) = self.config_watcher_join {
            let _ = config_watcher_join.await;
        }
    }
}

pub async fn serve(config: &Config) -> anyhow::Result<ProxyHandle> {
    ensure_rustls_crypto_provider()?;
    validate_tls_ca_material(config)?;

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

    let client = build_http_client()?;
    let h2_upstream_client = build_http2_only_client()?;
    let mitm_tls = build_mitm_tls_state(config)?;
    let runtime_mode_override = Arc::new(RwLock::new(None));
    let record_rate_limiters = Arc::new(RecordRateLimiterRegistry::default());

    let state = Arc::new(ProxyState::new(
        Arc::clone(&runtime_config),
        client,
        h2_upstream_client,
        Arc::clone(&runtime_status),
        Arc::clone(&session_runtime),
        Arc::clone(&runtime_mode_override),
        mitm_tls,
        Arc::clone(&record_rate_limiters),
    ));
    let config_reloader = config.source_path().map(|source_path| {
        Arc::new(ConfigReloader {
            source_path: source_path.to_path_buf(),
            runtime_config: Arc::clone(&runtime_config),
            status: Arc::clone(&runtime_status),
            reload_lock: AsyncMutex::new(()),
        })
    });
    #[cfg(feature = "watch")]
    let (config_watcher_shutdown_tx, config_watcher_join) =
        if let Some(config_reloader) = config_reloader.as_ref() {
            let (shutdown_tx, join) = spawn_config_watcher(Arc::clone(config_reloader))?;
            (Some(shutdown_tx), Some(join))
        } else {
            (None, None)
        };
    #[cfg(not(feature = "watch"))]
    let (config_watcher_shutdown_tx, config_watcher_join) = (None, None);

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
                        if let Err(err) = builder
                            .serve_connection_with_upgrades(io, service)
                            .await
                        {
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
            runtime_config: Arc::clone(&runtime_config),
            session_manager,
            session_runtime,
            metrics_enabled,
            config_reloader,
            admin_api_token: config.proxy.admin_api_token.clone(),
            config_default_mode: config.proxy.mode.unwrap_or(RouteMode::PassthroughCache),
            runtime_mode_override: Arc::clone(&runtime_mode_override),
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
        config_watcher_shutdown_tx,
        config_watcher_join,
    })
}

fn ensure_rustls_crypto_provider() -> anyhow::Result<()> {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return Ok(());
    }

    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
        && rustls::crypto::CryptoProvider::get_default().is_none()
    {
        return Err(anyhow::anyhow!("install rustls ring crypto provider"));
    }
    Ok(())
}

fn build_proxy_https_connector() -> anyhow::Result<ProxyHttpsConnector> {
    let connector = HttpsConnectorBuilder::new()
        .with_native_roots()
        .map_err(|err| anyhow::anyhow!("load native TLS root certificates: {err}"))?
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    Ok(connector)
}

fn build_http_client() -> anyhow::Result<HttpClient> {
    let connector = build_proxy_https_connector()?;
    Ok(Client::builder(TokioExecutor::new()).build(connector))
}

fn build_http2_only_client() -> anyhow::Result<HttpClient> {
    let connector = build_proxy_https_connector()?;
    let mut builder = Client::builder(TokioExecutor::new());
    builder.http2_only(true);
    Ok(builder.build(connector))
}

fn build_mitm_tls_state(config: &Config) -> anyhow::Result<Option<Arc<MitmTlsState>>> {
    let Some(tls) = config.proxy.tls.as_ref() else {
        return Ok(None);
    };
    if !tls.enabled {
        return Ok(None);
    }

    let cert_path = tls.ca_cert.as_deref().ok_or_else(|| {
        anyhow::anyhow!("`proxy.tls.ca_cert` is required when `proxy.tls.enabled = true`")
    })?;
    let key_path = tls.ca_key.as_deref().ok_or_else(|| {
        anyhow::anyhow!("`proxy.tls.ca_key` is required when `proxy.tls.enabled = true`")
    })?;
    let leaf_generator =
        ca::LeafCertGenerator::from_ca_files(cert_path, key_path).map_err(|err| {
            anyhow::anyhow!("initialize CONNECT MITM leaf certificate generator: {err}")
        })?;
    Ok(Some(Arc::new(MitmTlsState { leaf_generator })))
}

fn validate_tls_ca_material(config: &Config) -> anyhow::Result<()> {
    let Some(tls) = config.proxy.tls.as_ref() else {
        return Ok(());
    };

    if !tls.enabled {
        return Ok(());
    }

    let cert_path = tls.ca_cert.as_deref().ok_or_else(|| {
        anyhow::anyhow!("`proxy.tls.ca_cert` is required when `proxy.tls.enabled = true`")
    })?;
    let key_path = tls.ca_key.as_deref().ok_or_else(|| {
        anyhow::anyhow!("`proxy.tls.ca_key` is required when `proxy.tls.enabled = true`")
    })?;

    maybe_autogenerate_tls_ca_material(cert_path, key_path)?;

    ca::validate_ca_material(cert_path, key_path)
        .map_err(|err| anyhow::anyhow!("invalid `proxy.tls` CA material: {err}"))
}

fn maybe_autogenerate_tls_ca_material(cert_path: &Path, key_path: &Path) -> anyhow::Result<()> {
    if cert_path.exists() && key_path.exists() {
        return Ok(());
    }

    if cert_path.exists() || key_path.exists() {
        anyhow::bail!(
            "incomplete `proxy.tls` CA material: expected both {} and {} to exist",
            cert_path.display(),
            key_path.display()
        );
    }

    let cert_file_name = cert_path.file_name().and_then(|name| name.to_str());
    let key_file_name = key_path.file_name().and_then(|name| name.to_str());
    let cert_parent = cert_path.parent();
    let key_parent = key_path.parent();
    if cert_file_name == Some(ca::CA_CERT_FILE_NAME)
        && key_file_name == Some(ca::CA_KEY_FILE_NAME)
        && cert_parent == key_parent
    {
        let Some(ca_dir) = cert_parent else {
            anyhow::bail!(
                "missing `proxy.tls` CA parent directory for {} and {}",
                cert_path.display(),
                key_path.display()
            );
        };
        let generated = ca::generate_ca(ca_dir, false)
            .map_err(|err| anyhow::anyhow!("auto-generate TLS CA material: {err}"))?;
        tracing::info!(
            cert_path = %generated.cert_path.display(),
            key_path = %generated.key_path.display(),
            "generated local CA material for proxy TLS startup"
        );
        return Ok(());
    }

    anyhow::bail!(
        "missing `proxy.tls` CA material at {} and {}; run `replayproxy ca generate --ca-dir <dir>` and point both paths to `<dir>/{}` and `<dir>/{}`",
        cert_path.display(),
        key_path.display(),
        ca::CA_CERT_FILE_NAME,
        ca::CA_KEY_FILE_NAME
    )
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
    streaming: Option<StreamingConfig>,
    websocket: Option<WebSocketConfig>,
    rate_limit: Option<RouteRateLimit>,
    // Consumed by upcoming redaction storage steps.
    #[allow(dead_code)]
    redact: Option<RedactConfig>,
    transform: RouteTransformScripts,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteRateLimit {
    requests_per_second: u64,
    burst: u64,
    queue_depth: Option<usize>,
    timeout: Option<Duration>,
}

impl RouteRateLimit {
    fn from_config(config: &RateLimitConfig) -> Self {
        Self {
            requests_per_second: config.requests_per_second,
            burst: config.burst.unwrap_or(config.requests_per_second),
            queue_depth: config.queue_depth,
            timeout: config.timeout_ms.map(Duration::from_millis),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct RouteTransformScripts {
    on_request: Option<LoadedScript>,
    on_response: Option<LoadedScript>,
    on_record: Option<LoadedScript>,
    on_replay: Option<LoadedScript>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LoadedScript {
    path: PathBuf,
    source: Arc<str>,
}

#[derive(Debug, Clone)]
struct ProxyRuntimeConfig {
    routes: Vec<ProxyRoute>,
    max_body_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum RateLimitScopeMode {
    Record,
    Replay,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RecordRateLimitKey {
    route_ref: String,
    upstream_authority: String,
    mode: RateLimitScopeMode,
}

#[derive(Debug)]
struct RecordRateLimiterEntry {
    limiter: Arc<RecordTokenBucket>,
    config: RouteRateLimit,
}

#[derive(Debug, Default)]
struct RecordRateLimiterRegistry {
    entries: Mutex<BTreeMap<RecordRateLimitKey, RecordRateLimiterEntry>>,
}

impl RecordRateLimiterRegistry {
    fn limiter(&self, key: RecordRateLimitKey, config: &RouteRateLimit) -> Arc<RecordTokenBucket> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if let Some(entry) = entries.get(&key)
            && entry.config == *config
        {
            return Arc::clone(&entry.limiter);
        }

        let limiter = Arc::new(RecordTokenBucket::new(config));
        entries.insert(
            key,
            RecordRateLimiterEntry {
                limiter: Arc::clone(&limiter),
                config: config.clone(),
            },
        );
        limiter
    }
}

#[derive(Debug)]
struct RecordTokenBucket {
    state: AsyncMutex<RecordTokenBucketState>,
    tokens_per_second: f64,
    burst_tokens: f64,
    queue_depth: Option<usize>,
    timeout: Option<Duration>,
}

impl RecordTokenBucket {
    fn new(config: &RouteRateLimit) -> Self {
        let burst_tokens = config.burst as f64;
        Self {
            state: AsyncMutex::new(RecordTokenBucketState {
                available_tokens: burst_tokens,
                last_refill: Instant::now(),
            }),
            tokens_per_second: config.requests_per_second as f64,
            burst_tokens,
            queue_depth: config.queue_depth,
            timeout: config.timeout,
        }
    }

    async fn reserve_delay(&self) -> Result<Duration, RecordRateLimitRejection> {
        let mut state = self.state.lock().await;
        reserve_delay_for_bucket_with_limits(
            &mut state,
            Instant::now(),
            self.tokens_per_second,
            self.burst_tokens,
            self.queue_depth,
            self.timeout,
        )
    }

    async fn reserve_replay_request(&self) -> Result<(), Duration> {
        let mut state = self.state.lock().await;
        match reserve_delay_for_bucket_with_limits(
            &mut state,
            Instant::now(),
            self.tokens_per_second,
            self.burst_tokens,
            None,
            Some(Duration::ZERO),
        ) {
            Ok(delay) => {
                debug_assert!(delay.is_zero());
                Ok(())
            }
            Err(RecordRateLimitRejection::QueueTimeoutExceeded { required_delay, .. }) => {
                Err(required_delay)
            }
            Err(RecordRateLimitRejection::QueueDepthExceeded { .. }) => {
                unreachable!("queue depth is disabled for replay reservation")
            }
        }
    }
}

#[derive(Debug)]
struct RecordTokenBucketState {
    available_tokens: f64,
    last_refill: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordRateLimitRejection {
    QueueDepthExceeded {
        queue_depth: usize,
    },
    QueueTimeoutExceeded {
        timeout: Duration,
        required_delay: Duration,
    },
}

fn reserve_delay_for_bucket_with_limits(
    state: &mut RecordTokenBucketState,
    now: Instant,
    tokens_per_second: f64,
    burst_tokens: f64,
    queue_depth: Option<usize>,
    timeout: Option<Duration>,
) -> Result<Duration, RecordRateLimitRejection> {
    if !(tokens_per_second.is_finite() && tokens_per_second > 0.0) {
        return Ok(Duration::ZERO);
    }

    let elapsed = now.saturating_duration_since(state.last_refill);
    state.last_refill = now;

    let replenished = elapsed.as_secs_f64() * tokens_per_second;
    state.available_tokens = (state.available_tokens + replenished).min(burst_tokens);
    let available_tokens_before_reservation = state.available_tokens;
    state.available_tokens -= 1.0;
    if state.available_tokens >= 0.0 {
        return Ok(Duration::ZERO);
    }

    let delay = Duration::from_secs_f64(-state.available_tokens / tokens_per_second);
    if let Some(queue_depth) = queue_depth {
        let queued = queued_requests_from_available_tokens(state.available_tokens);
        if queued > queue_depth {
            state.available_tokens = available_tokens_before_reservation;
            return Err(RecordRateLimitRejection::QueueDepthExceeded { queue_depth });
        }
    }
    if let Some(timeout) = timeout
        && delay > timeout
    {
        state.available_tokens = available_tokens_before_reservation;
        return Err(RecordRateLimitRejection::QueueTimeoutExceeded {
            timeout,
            required_delay: delay,
        });
    }

    Ok(delay)
}

fn queued_requests_from_available_tokens(available_tokens: f64) -> usize {
    if available_tokens >= 0.0 {
        return 0;
    }

    (-available_tokens).ceil() as usize
}

impl ProxyRuntimeConfig {
    fn from_config(config: &Config) -> anyhow::Result<Self> {
        let mut parsed_routes = Vec::with_capacity(config.routes.len());
        for (idx, route) in config.routes.iter().enumerate() {
            let route_ref = format_route_ref(route, idx);
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
                route_ref: route_ref.clone(),
                path_prefix: route.path_prefix.clone(),
                path_exact: route.path_exact.clone(),
                path_regex,
                upstream,
                mode,
                cache_miss,
                body_oversize: route.body_oversize.unwrap_or(BodyOversizePolicy::Error),
                match_config: route.match_.clone(),
                streaming: route.streaming.clone(),
                websocket: route.websocket.clone(),
                rate_limit: route.rate_limit.as_ref().map(RouteRateLimit::from_config),
                redact: route.redact.clone(),
                transform: load_route_transform_scripts(
                    &route_ref,
                    route.transform.as_ref(),
                    config.source_path(),
                )?,
            });
        }

        Ok(Self {
            routes: parsed_routes,
            max_body_bytes: config.proxy.max_body_bytes,
        })
    }
}

fn load_route_transform_scripts(
    route_ref: &str,
    transform: Option<&TransformConfig>,
    config_source_path: Option<&Path>,
) -> anyhow::Result<RouteTransformScripts> {
    let Some(transform) = transform else {
        return Ok(RouteTransformScripts::default());
    };

    Ok(RouteTransformScripts {
        on_request: load_transform_script_for_hook(
            route_ref,
            "on_request",
            transform.on_request.as_deref(),
            config_source_path,
        )?,
        on_response: load_transform_script_for_hook(
            route_ref,
            "on_response",
            transform.on_response.as_deref(),
            config_source_path,
        )?,
        on_record: load_transform_script_for_hook(
            route_ref,
            "on_record",
            transform.on_record.as_deref(),
            config_source_path,
        )?,
        on_replay: load_transform_script_for_hook(
            route_ref,
            "on_replay",
            transform.on_replay.as_deref(),
            config_source_path,
        )?,
    })
}

fn load_transform_script_for_hook(
    route_ref: &str,
    hook_name: &str,
    script_path: Option<&str>,
    config_source_path: Option<&Path>,
) -> anyhow::Result<Option<LoadedScript>> {
    let Some(script_path) = script_path else {
        return Ok(None);
    };

    let script_path = script_path.trim();
    if script_path.is_empty() {
        anyhow::bail!("{route_ref}: `routes.transform.{hook_name}` must not be empty");
    }

    let resolved_path = resolve_transform_script_path(script_path, config_source_path)?;
    let source = std::fs::read_to_string(&resolved_path).map_err(|err| {
        anyhow::anyhow!(
            "{route_ref}: load `routes.transform.{hook_name}` script {}: {err}",
            resolved_path.display()
        )
    })?;

    Ok(Some(LoadedScript {
        path: resolved_path,
        source: Arc::from(source),
    }))
}

fn resolve_transform_script_path(
    script_path: &str,
    config_source_path: Option<&Path>,
) -> anyhow::Result<PathBuf> {
    let expanded = expand_tilde_path(Path::new(script_path))?;
    if expanded.is_absolute() {
        return Ok(expanded);
    }

    if let Some(config_source_path) = config_source_path
        && let Some(config_dir) = config_source_path.parent()
    {
        return Ok(config_dir.join(expanded));
    }

    Ok(expanded)
}

fn expand_tilde_path(path: &Path) -> anyhow::Result<PathBuf> {
    let mut components = path.components();
    match components.next() {
        Some(Component::Normal(component)) if component == OsStr::new("~") => {
            let home = env::var_os("HOME").ok_or_else(|| {
                anyhow::anyhow!("cannot expand `~` in {}: HOME is not set", path.display())
            })?;
            let mut expanded = PathBuf::from(home);
            for component in components {
                expanded.push(component.as_os_str());
            }
            Ok(expanded)
        }
        _ => Ok(path.to_path_buf()),
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
    runtime_config: Arc<RwLock<ProxyRuntimeConfig>>,
    session_manager: Option<SessionManager>,
    session_runtime: Arc<RwLock<ActiveSessionRuntime>>,
    metrics_enabled: bool,
    config_reloader: Option<Arc<ConfigReloader>>,
    admin_api_token: Option<String>,
    config_default_mode: RouteMode,
    runtime_mode_override: Arc<RwLock<Option<RouteMode>>>,
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

#[derive(Debug, Serialize)]
struct AdminModeResponse {
    runtime_override_mode: Option<RouteMode>,
    default_mode: RouteMode,
}

#[derive(Debug, Deserialize)]
struct AdminSetModeRequest {
    mode: RouteMode,
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
    routes_added: usize,
    routes_removed: usize,
    routes_changed: usize,
    max_body_bytes_before: usize,
    max_body_bytes_after: usize,
    changed: bool,
}

#[derive(Debug, Clone, Default)]
struct RouteDiffSummary {
    added: Vec<usize>,
    removed: Vec<usize>,
    changed: Vec<usize>,
}

impl RouteDiffSummary {
    fn has_changes(&self) -> bool {
        !(self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty())
    }
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

fn summarize_route_diff(
    current: &ProxyRuntimeConfig,
    next: &ProxyRuntimeConfig,
) -> RouteDiffSummary {
    let mut summary = RouteDiffSummary::default();
    let overlap_count = current.routes.len().min(next.routes.len());
    let mut matched_current = vec![false; current.routes.len()];
    let mut matched_next = vec![false; next.routes.len()];

    for idx in 0..overlap_count {
        if proxy_route_configs_equal(&current.routes[idx], &next.routes[idx]) {
            matched_current[idx] = true;
            matched_next[idx] = true;
        }
    }

    // Match equal routes that moved position so we can classify movement as remove+add.
    for (current_idx, current_route) in current.routes.iter().enumerate() {
        if matched_current[current_idx] {
            continue;
        }

        if let Some(next_idx) =
            find_unmatched_matching_route_index(current_route, &next.routes, &matched_next)
        {
            matched_current[current_idx] = true;
            matched_next[next_idx] = true;
            summary.removed.push(current_idx);
            summary.added.push(next_idx);
        }
    }

    for idx in 0..overlap_count {
        if !matched_current[idx] && !matched_next[idx] {
            matched_current[idx] = true;
            matched_next[idx] = true;
            summary.changed.push(idx);
        }
    }

    for (idx, matched) in matched_current.iter().enumerate() {
        if !matched {
            summary.removed.push(idx);
        }
    }
    for (idx, matched) in matched_next.iter().enumerate() {
        if !matched {
            summary.added.push(idx);
        }
    }

    summary.added.sort_unstable();
    summary.removed.sort_unstable();
    summary.changed.sort_unstable();

    summary
}

fn find_unmatched_matching_route_index(
    route: &ProxyRoute,
    routes: &[ProxyRoute],
    matched: &[bool],
) -> Option<usize> {
    routes
        .iter()
        .enumerate()
        .find(|(idx, candidate)| !matched[*idx] && proxy_route_configs_equal(route, candidate))
        .map(|(idx, _)| idx)
}

fn proxy_route_configs_equal(current: &ProxyRoute, next: &ProxyRoute) -> bool {
    current.route_ref == next.route_ref
        && current.path_prefix == next.path_prefix
        && current.path_exact == next.path_exact
        && current.path_regex.as_ref().map(Regex::as_str)
            == next.path_regex.as_ref().map(Regex::as_str)
        && current.upstream.as_ref().map(Uri::to_string)
            == next.upstream.as_ref().map(Uri::to_string)
        && current.mode == next.mode
        && current.cache_miss == next.cache_miss
        && current.body_oversize == next.body_oversize
        && route_match_configs_equal(current.match_config.as_ref(), next.match_config.as_ref())
        && streaming_configs_equal(current.streaming.as_ref(), next.streaming.as_ref())
        && rate_limit_configs_equal(current.rate_limit.as_ref(), next.rate_limit.as_ref())
        && redact_configs_equal(current.redact.as_ref(), next.redact.as_ref())
        && current.transform == next.transform
}

fn route_match_configs_equal(
    current: Option<&RouteMatchConfig>,
    next: Option<&RouteMatchConfig>,
) -> bool {
    match (current, next) {
        (None, None) => true,
        (Some(current), Some(next)) => {
            current.method == next.method
                && current.path == next.path
                && current.query == next.query
                && current.headers == next.headers
                && current.headers_ignore == next.headers_ignore
                && current.body_json == next.body_json
        }
        _ => false,
    }
}

fn redact_configs_equal(current: Option<&RedactConfig>, next: Option<&RedactConfig>) -> bool {
    match (current, next) {
        (None, None) => true,
        (Some(current), Some(next)) => {
            current.headers == next.headers
                && current.body_json == next.body_json
                && current.placeholder == next.placeholder
        }
        _ => false,
    }
}

fn streaming_configs_equal(
    current: Option<&StreamingConfig>,
    next: Option<&StreamingConfig>,
) -> bool {
    match (current, next) {
        (None, None) => true,
        (Some(current), Some(next)) => current.preserve_timing == next.preserve_timing,
        _ => false,
    }
}

fn rate_limit_configs_equal(
    current: Option<&RouteRateLimit>,
    next: Option<&RouteRateLimit>,
) -> bool {
    match (current, next) {
        (None, None) => true,
        (Some(current), Some(next)) => current == next,
        _ => false,
    }
}

fn format_route_indices(route_indices: &[usize]) -> String {
    if route_indices.is_empty() {
        return "none".to_owned();
    }

    route_indices
        .iter()
        .map(|idx| format!("routes[{idx}]"))
        .collect::<Vec<_>>()
        .join(",")
}

impl ConfigReloader {
    async fn reload(&self) -> anyhow::Result<AdminConfigReloadResponse> {
        let _reload_guard = self.reload_lock.lock().await;
        let config = Config::from_path(&self.source_path).map_err(|err| {
            anyhow::anyhow!("reload config from {}: {err}", self.source_path.display())
        })?;
        let next_runtime = ProxyRuntimeConfig::from_config(&config)?;

        let (route_diff, routes_before, max_body_bytes_before, routes_after, max_body_bytes_after) = {
            let mut runtime_config = self
                .runtime_config
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let route_diff = summarize_route_diff(&runtime_config, &next_runtime);
            let routes_before = runtime_config.routes.len();
            let max_body_bytes_before = runtime_config.max_body_bytes;
            let routes_after = next_runtime.routes.len();
            let max_body_bytes_after = next_runtime.max_body_bytes;
            *runtime_config = next_runtime;
            (
                route_diff,
                routes_before,
                max_body_bytes_before,
                routes_after,
                max_body_bytes_after,
            )
        };

        let changed = route_diff.has_changes() || max_body_bytes_before != max_body_bytes_after;
        self.status.set_routes_configured(routes_after);
        tracing::info!(
            source = %self.source_path.display(),
            changed,
            routes_added = route_diff.added.len(),
            routes_removed = route_diff.removed.len(),
            routes_changed = route_diff.changed.len(),
            route_ids_added = %format_route_indices(&route_diff.added),
            route_ids_removed = %format_route_indices(&route_diff.removed),
            route_ids_changed = %format_route_indices(&route_diff.changed),
            max_body_bytes_before,
            max_body_bytes_after,
            "applied config reload diff"
        );

        Ok(AdminConfigReloadResponse {
            source: self.source_path.display().to_string(),
            routes_before,
            routes_after,
            routes_added: route_diff.added.len(),
            routes_removed: route_diff.removed.len(),
            routes_changed: route_diff.changed.len(),
            max_body_bytes_before,
            max_body_bytes_after,
            changed,
        })
    }
}

#[cfg(feature = "watch")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigWatchEventAction {
    Continue,
    ScheduleReload,
    Stop,
}

#[cfg(feature = "watch")]
fn spawn_config_watcher(
    config_reloader: Arc<ConfigReloader>,
) -> anyhow::Result<(oneshot::Sender<()>, tokio::task::JoinHandle<()>)> {
    use notify::{RecursiveMode, Watcher};

    let source_path = config_reloader.source_path.clone();
    let watch_root = source_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_path_buf();
    let watched_source_path = absolute_watch_path(&source_path);
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<notify::Result<notify::Event>>();
    let mut watcher = notify::recommended_watcher(move |event| {
        let _ = event_tx.send(event);
    })
    .map_err(|err| anyhow::anyhow!("create config watcher for {}: {err}", source_path.display()))?;
    watcher
        .watch(&watch_root, RecursiveMode::NonRecursive)
        .map_err(|err| {
            anyhow::anyhow!(
                "watch config directory {} for {}: {err}",
                watch_root.display(),
                source_path.display()
            )
        })?;

    tracing::info!(
        source = %source_path.display(),
        watch_root = %watch_root.display(),
        debounce_ms = CONFIG_WATCH_DEBOUNCE_WINDOW.as_millis(),
        "config file watcher started"
    );

    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let join = tokio::spawn(async move {
        let _watcher = watcher;
        let mut debounce_deadline: Option<tokio::time::Instant> = None;

        loop {
            match debounce_deadline {
                Some(deadline) => {
                    tokio::select! {
                        _ = &mut shutdown_rx => break,
                        _ = tokio::time::sleep_until(deadline) => {
                            debounce_deadline = None;
                            match config_reloader.reload().await {
                                Ok(_) => {}
                                Err(err) => {
                                    tracing::warn!(
                                        source = %config_reloader.source_path.display(),
                                        "failed to reload config after filesystem change: {err}"
                                    );
                                }
                            }
                        }
                        maybe_event = event_rx.recv() => {
                            match classify_config_watch_event(maybe_event, &watched_source_path) {
                                ConfigWatchEventAction::Continue => {}
                                ConfigWatchEventAction::ScheduleReload => {
                                    debounce_deadline = Some(
                                        tokio::time::Instant::now() + CONFIG_WATCH_DEBOUNCE_WINDOW,
                                    );
                                }
                                ConfigWatchEventAction::Stop => break,
                            }
                        }
                    }
                }
                None => {
                    tokio::select! {
                        _ = &mut shutdown_rx => break,
                        maybe_event = event_rx.recv() => {
                            match classify_config_watch_event(maybe_event, &watched_source_path) {
                                ConfigWatchEventAction::Continue => {}
                                ConfigWatchEventAction::ScheduleReload => {
                                    debounce_deadline = Some(
                                        tokio::time::Instant::now() + CONFIG_WATCH_DEBOUNCE_WINDOW,
                                    );
                                }
                                ConfigWatchEventAction::Stop => break,
                            }
                        }
                    }
                }
            }
        }

        tracing::debug!(
            source = %config_reloader.source_path.display(),
            "config file watcher stopped"
        );
    });

    Ok((shutdown_tx, join))
}

#[cfg(feature = "watch")]
fn classify_config_watch_event(
    maybe_event: Option<notify::Result<notify::Event>>,
    watched_source_path: &std::path::Path,
) -> ConfigWatchEventAction {
    let Some(event_result) = maybe_event else {
        return ConfigWatchEventAction::Stop;
    };
    let event = match event_result {
        Ok(event) => event,
        Err(err) => {
            tracing::warn!(
                source = %watched_source_path.display(),
                "config watcher reported an error: {err}"
            );
            return ConfigWatchEventAction::Continue;
        }
    };

    if !config_watch_event_kind_triggers_reload(&event.kind)
        || !watch_event_targets_source_path(&event, watched_source_path)
    {
        return ConfigWatchEventAction::Continue;
    }

    tracing::debug!(
        source = %watched_source_path.display(),
        kind = ?event.kind,
        paths = ?event.paths,
        "detected relevant config filesystem change"
    );

    ConfigWatchEventAction::ScheduleReload
}

#[cfg(feature = "watch")]
fn config_watch_event_kind_triggers_reload(kind: &notify::EventKind) -> bool {
    matches!(
        kind,
        notify::EventKind::Any
            | notify::EventKind::Create(_)
            | notify::EventKind::Modify(_)
            | notify::EventKind::Remove(_)
            | notify::EventKind::Other
    )
}

#[cfg(feature = "watch")]
fn watch_event_targets_source_path(
    event: &notify::Event,
    watched_source_path: &std::path::Path,
) -> bool {
    event
        .paths
        .iter()
        .any(|path| absolute_watch_path(path) == watched_source_path)
}

#[cfg(feature = "watch")]
fn absolute_watch_path(path: &std::path::Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }

    std::env::current_dir()
        .map(|cwd| cwd.join(path))
        .unwrap_or_else(|_| path.to_path_buf())
}

#[derive(Debug)]
struct ProxyState {
    runtime_config: Arc<RwLock<ProxyRuntimeConfig>>,
    client: HttpClient,
    h2_upstream_client: HttpClient,
    session_runtime: Arc<RwLock<ActiveSessionRuntime>>,
    status: Arc<RuntimeStatus>,
    runtime_mode_override: Arc<RwLock<Option<RouteMode>>>,
    mitm_tls: Option<Arc<MitmTlsState>>,
    record_rate_limiters: Arc<RecordRateLimiterRegistry>,
}

#[derive(Debug)]
struct MitmTlsState {
    leaf_generator: ca::LeafCertGenerator,
}

impl ProxyState {
    #[allow(clippy::too_many_arguments)]
    fn new(
        runtime_config: Arc<RwLock<ProxyRuntimeConfig>>,
        client: HttpClient,
        h2_upstream_client: HttpClient,
        status: Arc<RuntimeStatus>,
        session_runtime: Arc<RwLock<ActiveSessionRuntime>>,
        runtime_mode_override: Arc<RwLock<Option<RouteMode>>>,
        mitm_tls: Option<Arc<MitmTlsState>>,
        record_rate_limiters: Arc<RecordRateLimiterRegistry>,
    ) -> Self {
        Self {
            runtime_config,
            client,
            h2_upstream_client,
            session_runtime,
            status,
            runtime_mode_override,
            mitm_tls,
            record_rate_limiters,
        }
    }

    fn request_runtime_config(&self, path: &str) -> RequestRuntimeConfig {
        let runtime_config = self
            .runtime_config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut request_config = request_runtime_config_for_path(&runtime_config, path);
        let runtime_mode_override = *self
            .runtime_mode_override
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let (Some(mode), Some(route)) = (runtime_mode_override, request_config.route.as_mut()) {
            route.mode = mode;
            route.cache_miss = match mode {
                RouteMode::Replay => CacheMissPolicy::Error,
                RouteMode::Record | RouteMode::PassthroughCache => CacheMissPolicy::Forward,
            };
        }
        request_config
    }

    fn active_session_snapshot(&self) -> ActiveSessionRuntime {
        self.session_runtime
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

#[derive(Debug, Clone)]
struct RequestRuntimeConfig {
    route: Option<ProxyRoute>,
    max_body_bytes: usize,
}

fn request_runtime_config_for_path(
    runtime_config: &ProxyRuntimeConfig,
    path: &str,
) -> RequestRuntimeConfig {
    RequestRuntimeConfig {
        route: select_route(&runtime_config.routes, path).cloned(),
        max_body_bytes: runtime_config.max_body_bytes,
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

#[derive(Debug)]
struct RecordedResponseBody {
    body_bytes: Bytes,
    chunks: Vec<ResponseChunk>,
}

#[derive(Debug)]
enum ResponseBodyReadOutcome {
    Buffered(RecordedResponseBody),
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

    Ok(BodyReadOutcome::Buffered(flatten_chunks(
        buffered,
        buffered_len,
    )))
}

async fn read_response_body_with_chunks_with_limit(
    mut body: Incoming,
    max_body_bytes: usize,
) -> Result<ResponseBodyReadOutcome, BodyReadError> {
    let started_at = Instant::now();
    let mut buffered = Vec::new();
    let mut buffered_len = 0usize;
    let mut chunks = Vec::new();
    while let Some(frame_result) = body.frame().await {
        let frame = frame_result.map_err(BodyReadError::Read)?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        let chunk_index = u32::try_from(chunks.len()).unwrap_or(u32::MAX);
        let offset_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        buffered_len = buffered_len.saturating_add(data.len());
        chunks.push(ResponseChunk {
            chunk_index,
            offset_ms,
            chunk_body: data.to_vec(),
        });
        buffered.push(data);
        if buffered_len > max_body_bytes {
            return Ok(ResponseBodyReadOutcome::TooLarge {
                limit_bytes: max_body_bytes,
                prefetched: buffered,
                remaining: body,
            });
        }
    }

    Ok(ResponseBodyReadOutcome::Buffered(RecordedResponseBody {
        body_bytes: flatten_chunks(buffered, buffered_len),
        chunks,
    }))
}

fn flatten_chunks(mut buffered: Vec<Bytes>, buffered_len: usize) -> Bytes {
    if buffered.is_empty() {
        return Bytes::new();
    }
    if buffered.len() == 1 {
        return buffered.pop().expect("buffered contains exactly one chunk");
    }

    let mut flattened = Vec::with_capacity(buffered_len);
    for chunk in buffered {
        flattened.extend_from_slice(&chunk);
    }
    Bytes::from(flattened)
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

struct ReplayChunkBody {
    chunks: VecDeque<ResponseChunk>,
    preserve_timing: bool,
    started_at: TokioInstant,
    pending_chunk: Option<ResponseChunk>,
    delay: Option<Pin<Box<Sleep>>>,
}

impl ReplayChunkBody {
    fn new(chunks: Vec<ResponseChunk>, preserve_timing: bool) -> Self {
        Self {
            chunks: chunks.into(),
            preserve_timing,
            started_at: TokioInstant::now(),
            pending_chunk: None,
            delay: None,
        }
    }
}

impl hyper::body::Body for ReplayChunkBody {
    type Data = Bytes;
    type Error = Box<dyn StdError + Send + Sync>;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.pending_chunk.is_none() {
            this.pending_chunk = this.chunks.pop_front();
        }

        let Some(chunk) = this.pending_chunk.as_ref() else {
            return Poll::Ready(None);
        };

        if this.preserve_timing {
            let deadline = this.started_at + Duration::from_millis(chunk.offset_ms);
            if TokioInstant::now() < deadline {
                if this.delay.is_none() {
                    this.delay = Some(Box::pin(tokio::time::sleep_until(deadline)));
                }
                if let Some(delay) = this.delay.as_mut() {
                    match delay.as_mut().poll(cx) {
                        Poll::Ready(()) => {
                            this.delay = None;
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
            } else {
                this.delay = None;
            }
        }

        let chunk = this
            .pending_chunk
            .take()
            .expect("pending chunk must exist after readiness checks");
        Poll::Ready(Some(Ok(Frame::data(Bytes::from(chunk.chunk_body)))))
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

fn boxed_replay_chunks(chunks: Vec<ResponseChunk>, preserve_timing: bool) -> ProxyBody {
    ReplayChunkBody::new(chunks, preserve_timing).boxed()
}

async fn proxy_handler(
    mut req: Request<Incoming>,
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
    let route_lookup_path = if req.method() == Method::CONNECT && req.uri().path().is_empty() {
        "/"
    } else {
        req.uri().path()
    };
    let request_runtime_config = state.request_runtime_config(route_lookup_path);
    let max_body_bytes = request_runtime_config.max_body_bytes;

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

    let Some(route) = request_runtime_config.route else {
        respond!(
            None,
            proxy_simple_response(StatusCode::NOT_FOUND, "no matching route")
        );
    };
    route_ref = Some(route.route_ref.as_str());
    mode = Some(route.mode);

    if req.method() == Method::CONNECT {
        let Some(connect_authority) = req.uri().authority().cloned() else {
            respond!(
                None,
                proxy_simple_response(
                    StatusCode::BAD_REQUEST,
                    "CONNECT request target must include authority",
                )
            );
        };
        if let Some(mitm_tls) = state.mitm_tls.as_ref() {
            let on_upgrade = hyper::upgrade::on(&mut req);
            let mitm_tls = Arc::clone(mitm_tls);
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                if let Err(err) =
                    mitm_upgraded_connection(on_upgrade, connect_authority, state, mitm_tls).await
                {
                    tracing::debug!("CONNECT MITM session finished: {err}");
                }
            });

            let mut response = Response::new(boxed_full(Bytes::new()));
            *response.status_mut() = StatusCode::OK;
            respond!(None, response);
        } else {
            let tunnel_target = connect_tunnel_target(&connect_authority);

            state
                .status
                .upstream_requests_total
                .fetch_add(1, Ordering::Relaxed);
            let upstream_started_at = Instant::now();
            let upstream_stream = match TcpStream::connect(tunnel_target.as_str()).await {
                Ok(stream) => stream,
                Err(err) => {
                    let upstream_latency = upstream_started_at.elapsed();
                    tracing::debug!(target = %tunnel_target, "CONNECT upstream dial failed: {err}");
                    respond!(
                        Some(upstream_latency),
                        proxy_simple_response(
                            StatusCode::BAD_GATEWAY,
                            "CONNECT upstream dial failed",
                        )
                    );
                }
            };
            let upstream_latency = upstream_started_at.elapsed();

            let on_upgrade = hyper::upgrade::on(&mut req);
            tokio::spawn(async move {
                if let Err(err) = tunnel_upgraded_connection(on_upgrade, upstream_stream).await {
                    tracing::debug!(target = %tunnel_target, "CONNECT tunnel finished: {err}");
                }
            });

            let mut response = Response::new(boxed_full(Bytes::new()));
            *response.status_mut() = StatusCode::OK;
            respond!(Some(upstream_latency), response);
        }
    }

    if route.websocket.is_some() && is_websocket_upgrade_request(&req) {
        if route.mode == RouteMode::Replay {
            respond!(
                None,
                proxy_simple_response(
                    StatusCode::NOT_IMPLEMENTED,
                    "websocket replay mode is not implemented",
                )
            );
        }

        let upstream_uri = match resolve_upstream_uri_for_request(&route, req.uri()) {
            Ok(Some(uri)) => uri,
            Ok(None) => {
                respond!(
                    None,
                    proxy_simple_response(StatusCode::NOT_IMPLEMENTED, "route has no upstream",)
                );
            }
            Err(err) => {
                tracing::debug!("failed to build websocket upstream uri: {err}");
                respond!(
                    None,
                    proxy_simple_response(
                        StatusCode::BAD_GATEWAY,
                        "failed to build upstream request",
                    )
                );
            }
        };
        if let Err(err) =
            maybe_wait_for_record_rate_limit(state.as_ref(), &route, &upstream_uri).await
        {
            tracing::debug!(
                route = %route.route_ref,
                upstream = %upstream_uri,
                error = ?err,
                "record mode rate limiter rejected upstream request"
            );
            respond!(None, record_rate_limit_rejection_response(err));
        }

        let client_on_upgrade = hyper::upgrade::on(&mut req);
        let (mut parts, body) = req.into_parts();
        parts.uri = upstream_uri.clone();
        set_host_header(&mut parts.headers, &upstream_uri);
        parts.headers.remove("proxy-connection");
        let upstream_req = Request::from_parts(parts, boxed_incoming(body));

        state
            .status
            .upstream_requests_total
            .fetch_add(1, Ordering::Relaxed);
        let upstream_started_at = Instant::now();
        let mut upstream_res = match send_upstream_request(state.as_ref(), upstream_req).await {
            Ok(res) => res,
            Err(err) => {
                let upstream_latency = upstream_started_at.elapsed();
                tracing::debug!("websocket upstream request failed: {err}");
                respond!(
                    Some(upstream_latency),
                    proxy_simple_response(StatusCode::BAD_GATEWAY, "upstream request failed",)
                );
            }
        };
        let upstream_latency = upstream_started_at.elapsed();

        if upstream_res.status() == StatusCode::SWITCHING_PROTOCOLS {
            let upstream_on_upgrade = hyper::upgrade::on(&mut upstream_res);
            let websocket_route_ref = route.route_ref.clone();
            tokio::spawn(async move {
                if let Err(err) =
                    tunnel_websocket_upgraded_connections(client_on_upgrade, upstream_on_upgrade)
                        .await
                {
                    tracing::debug!(
                        route = %websocket_route_ref,
                        "websocket upgraded tunnel finished: {err}"
                    );
                }
            });

            let (mut upstream_parts, _upstream_body) = upstream_res.into_parts();
            upstream_parts.headers.remove("proxy-connection");
            respond!(
                Some(upstream_latency),
                Response::from_parts(upstream_parts, boxed_full(Bytes::new()))
            );
        }

        let (mut upstream_parts, upstream_body) = upstream_res.into_parts();
        strip_hop_by_hop_headers(&mut upstream_parts.headers);
        respond!(
            Some(upstream_latency),
            Response::from_parts(upstream_parts, boxed_incoming(upstream_body))
        );
    }

    let has_on_request_transform = route.transform.on_request.is_some();
    let request_content_length = parse_content_length(req.headers());
    let request_known_oversize = request_content_length
        .map(|len| len > bytes_limit_u64(max_body_bytes))
        .unwrap_or(false);
    // on_request transforms require a fully buffered body, so oversized requests cannot
    // use bypass-cache streaming when this hook is configured.
    let allow_oversize_bypass_cache = route.body_oversize == BodyOversizePolicy::BypassCache
        && route.mode != RouteMode::Replay
        && !has_on_request_transform;
    let bypass_request_buffering = request_known_oversize && allow_oversize_bypass_cache;
    if request_known_oversize && !bypass_request_buffering {
        if has_on_request_transform && route.body_oversize == BodyOversizePolicy::BypassCache {
            tracing::debug!(
                route = %route.route_ref,
                limit_bytes = max_body_bytes,
                "rejecting oversized request body because on_request transform requires buffering"
            );
        }
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

        let upstream_uri = match resolve_upstream_uri_for_request(&route, &parts.uri) {
            Ok(Some(uri)) => uri,
            Ok(None) => {
                respond!(
                    None,
                    proxy_simple_response(StatusCode::NOT_IMPLEMENTED, "route has no upstream",)
                );
            }
            Err(err) => {
                tracing::debug!("failed to build upstream uri: {err}");
                respond!(
                    None,
                    proxy_simple_response(
                        StatusCode::BAD_GATEWAY,
                        "failed to build upstream request",
                    )
                );
            }
        };
        if let Err(err) =
            maybe_wait_for_record_rate_limit(state.as_ref(), &route, &upstream_uri).await
        {
            tracing::debug!(
                route = %route.route_ref,
                upstream = %upstream_uri,
                error = ?err,
                "record mode rate limiter rejected upstream request"
            );
            respond!(None, record_rate_limit_rejection_response(err));
        }
        parts.uri = upstream_uri.clone();
        set_host_header(&mut parts.headers, &upstream_uri);
        let upstream_req = Request::from_parts(parts, boxed_incoming(body));

        state
            .status
            .upstream_requests_total
            .fetch_add(1, Ordering::Relaxed);
        let upstream_started_at = Instant::now();
        let upstream_res = match send_upstream_request(state.as_ref(), upstream_req).await {
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

                let upstream_uri = match resolve_upstream_uri_for_request(&route, &parts.uri) {
                    Ok(Some(uri)) => uri,
                    Ok(None) => {
                        respond!(
                            None,
                            proxy_simple_response(
                                StatusCode::NOT_IMPLEMENTED,
                                "route has no upstream",
                            )
                        );
                    }
                    Err(err) => {
                        tracing::debug!("failed to build upstream uri: {err}");
                        respond!(
                            None,
                            proxy_simple_response(
                                StatusCode::BAD_GATEWAY,
                                "failed to build upstream request",
                            )
                        );
                    }
                };
                if let Err(err) =
                    maybe_wait_for_record_rate_limit(state.as_ref(), &route, &upstream_uri).await
                {
                    tracing::debug!(
                        route = %route.route_ref,
                        upstream = %upstream_uri,
                        error = ?err,
                        "record mode rate limiter rejected upstream request"
                    );
                    respond!(None, record_rate_limit_rejection_response(err));
                }
                parts.uri = upstream_uri.clone();
                set_host_header(&mut parts.headers, &upstream_uri);
                let upstream_req =
                    Request::from_parts(parts, boxed_prefetched_incoming(prefetched, remaining));

                state
                    .status
                    .upstream_requests_total
                    .fetch_add(1, Ordering::Relaxed);
                let upstream_started_at = Instant::now();
                let upstream_res = match send_upstream_request(state.as_ref(), upstream_req).await {
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
            if has_on_request_transform && route.body_oversize == BodyOversizePolicy::BypassCache {
                tracing::debug!(
                    route = %route.route_ref,
                    limit_bytes,
                    "rejecting oversized request body because on_request transform requires buffering"
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
    #[cfg(feature = "scripting")]
    let mut body_bytes = body_bytes;

    #[cfg(feature = "scripting")]
    if let Some(script) = route.transform.on_request.as_ref()
        && let Err(err) =
            apply_on_request_script(&route.route_ref, script, &mut parts, &mut body_bytes)
    {
        tracing::debug!("failed to run on_request script: {err}");
        respond!(
            None,
            proxy_simple_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "on_request script failed"
            )
        );
    }

    #[cfg(not(feature = "scripting"))]
    if route.transform.on_request.is_some() {
        tracing::debug!(
            route = %route.route_ref,
            "on_request script is configured but scripting support is disabled"
        );
        respond!(
            None,
            proxy_simple_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "on_request script configured but this replayproxy build does not include scripting support",
            )
        );
    }

    let upstream_uri = match resolve_upstream_uri_for_request(&route, &parts.uri) {
        Ok(Some(uri)) => uri,
        Ok(None) => {
            respond!(
                None,
                proxy_simple_response(StatusCode::NOT_IMPLEMENTED, "route has no upstream",)
            );
        }
        Err(err) => {
            tracing::debug!("failed to build upstream uri: {err}");
            respond!(
                None,
                proxy_simple_response(StatusCode::BAD_GATEWAY, "failed to build upstream request",)
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
            if let Some(required_delay) =
                maybe_reject_for_replay_rate_limit(state.as_ref(), &route, &upstream_uri).await
            {
                respond!(None, replay_rate_limit_rejection_response(required_delay));
            }

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
                    let replay_response =
                        response_from_stored_recording(storage, &route, recording).await;
                    respond!(None, replay_response);
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
                        let replay_response =
                            response_from_stored_recording(storage, &route, recording).await;
                        respond!(None, replay_response);
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

    if let Err(err) = maybe_wait_for_record_rate_limit(state.as_ref(), &route, &upstream_uri).await
    {
        tracing::debug!(
            route = %route.route_ref,
            upstream = %upstream_uri,
            error = ?err,
            "record mode rate limiter rejected upstream request"
        );
        respond!(None, record_rate_limit_rejection_response(err));
    }
    parts.uri = upstream_uri.clone();
    set_host_header(&mut parts.headers, &upstream_uri);

    let upstream_req = Request::from_parts(parts, boxed_full(body_bytes));

    state
        .status
        .upstream_requests_total
        .fetch_add(1, Ordering::Relaxed);
    let upstream_started_at = Instant::now();
    let upstream_res = match send_upstream_request(state.as_ref(), upstream_req).await {
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
    let has_on_response_transform = route.transform.on_response.is_some();
    let should_buffer_response = should_record || has_on_response_transform;
    let allow_response_oversize_bypass_cache =
        route.body_oversize == BodyOversizePolicy::BypassCache && !has_on_response_transform;

    #[cfg(not(feature = "scripting"))]
    if route.transform.on_response.is_some() {
        tracing::debug!(
            route = %route.route_ref,
            "on_response script is configured but scripting support is disabled"
        );
        respond!(
            Some(upstream_latency),
            proxy_simple_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "on_response script configured but this replayproxy build does not include scripting support",
            )
        );
    }

    if !should_buffer_response {
        respond!(
            Some(upstream_latency),
            Response::from_parts(parts, boxed_incoming(body))
        );
    }

    let response_known_oversize = parse_content_length(&parts.headers)
        .map(|len| len > bytes_limit_u64(max_body_bytes))
        .unwrap_or(false);
    if response_known_oversize {
        if allow_response_oversize_bypass_cache {
            tracing::debug!(
                limit_bytes = max_body_bytes,
                "bypassing cache for oversized upstream response body"
            );
            respond!(
                Some(upstream_latency),
                Response::from_parts(parts, boxed_incoming(body))
            );
        }
        if has_on_response_transform && route.body_oversize == BodyOversizePolicy::BypassCache {
            tracing::debug!(
                route = %route.route_ref,
                limit_bytes = max_body_bytes,
                "rejecting oversized upstream response body because on_response transform requires buffering"
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

    let (body_bytes, response_chunks) = match read_response_body_with_chunks_with_limit(
        body,
        max_body_bytes,
    )
    .await
    {
        Ok(ResponseBodyReadOutcome::Buffered(recorded)) => (recorded.body_bytes, recorded.chunks),
        Ok(ResponseBodyReadOutcome::TooLarge {
            limit_bytes,
            prefetched,
            remaining,
        }) => {
            if allow_response_oversize_bypass_cache {
                tracing::debug!(
                    limit_bytes = max_body_bytes,
                    "bypassing cache after upstream response body exceeded configured limit mid-stream"
                );
                respond!(
                    Some(upstream_latency),
                    Response::from_parts(parts, boxed_prefetched_incoming(prefetched, remaining))
                );
            }
            if has_on_response_transform && route.body_oversize == BodyOversizePolicy::BypassCache {
                tracing::debug!(
                    route = %route.route_ref,
                    limit_bytes,
                    "rejecting oversized upstream response body because on_response transform requires buffering"
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

    #[cfg(feature = "scripting")]
    let mut body_bytes = body_bytes;

    #[cfg(feature = "scripting")]
    if let Some(script) = route.transform.on_response.as_ref()
        && let Err(err) =
            apply_on_response_script(&route.route_ref, script, &mut parts, &mut body_bytes)
    {
        tracing::debug!("failed to run on_response script: {err}");
        respond!(
            Some(upstream_latency),
            proxy_simple_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "on_response script failed"
            )
        );
    }

    let record_response_status = should_record.then(|| parts.status.as_u16());
    let record_response_headers = should_record.then(|| header_map_to_vec(&parts.headers));

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

        let mut recording = Recording {
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

        #[cfg(not(feature = "scripting"))]
        if route.transform.on_record.is_some() {
            tracing::debug!(
                route = %route.route_ref,
                "on_record script is configured but scripting support is disabled"
            );
            respond!(
                Some(upstream_latency),
                proxy_simple_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "on_record script configured but this replayproxy build does not include scripting support",
                )
            );
        }

        #[cfg(feature = "scripting")]
        if let Some(script) = route.transform.on_record.as_ref()
            && let Err(err) = apply_on_record_script(&route.route_ref, script, &mut recording)
        {
            tracing::debug!("failed to run on_record script: {err}");
            respond!(
                Some(upstream_latency),
                proxy_simple_response(StatusCode::INTERNAL_SERVER_ERROR, "on_record script failed")
            );
        }

        let pre_redaction_response_body = recording.response_body.clone();
        recording.request_headers =
            redact_recording_headers(recording.request_headers, route.redact.as_ref());
        recording.response_headers =
            redact_recording_headers(recording.response_headers, route.redact.as_ref());
        recording.request_body =
            redact_recording_body_json(recording.request_body.as_slice(), route.redact.as_ref());
        recording.response_body =
            redact_recording_body_json(recording.response_body.as_slice(), route.redact.as_ref());
        let response_chunks = response_chunks_for_storage(
            pre_redaction_response_body.as_slice(),
            recording.response_body.as_slice(),
            response_chunks,
        );

        match storage.insert_recording(recording).await {
            Ok(recording_id) => {
                state.status.increment_active_session_recordings_total();
                if let Err(err) = storage
                    .insert_response_chunks(recording_id, response_chunks)
                    .await
                {
                    tracing::debug!("failed to persist response chunks: {err}");
                }
            }
            Err(err) => tracing::debug!("failed to persist recording: {err}"),
        }
    }

    respond!(
        Some(upstream_latency),
        Response::from_parts(parts, boxed_full(body_bytes))
    );
}

fn response_chunks_for_storage(
    original_body: &[u8],
    stored_body: &[u8],
    chunks: Vec<ResponseChunk>,
) -> Vec<ResponseChunk> {
    if chunks.is_empty() {
        return Vec::new();
    }

    if original_body == stored_body {
        return chunks;
    }

    rechunk_stored_body_preserving_metadata(stored_body, chunks)
}

fn rechunk_stored_body_preserving_metadata(
    stored_body: &[u8],
    chunks: Vec<ResponseChunk>,
) -> Vec<ResponseChunk> {
    if chunks.is_empty() {
        return Vec::new();
    }

    let chunk_count = chunks.len();
    let total_original_len = chunks
        .iter()
        .map(|chunk| chunk.chunk_body.len() as u128)
        .sum::<u128>();
    let stored_len = stored_body.len();
    let stored_len_u128 = stored_len as u128;

    // If the original stream body was empty, keep chunk metadata and place the stored body
    // in the last chunk so replay still emits the original number of chunks in order.
    if total_original_len == 0 {
        return chunks
            .into_iter()
            .enumerate()
            .map(|(idx, mut chunk)| {
                chunk.chunk_body = if idx + 1 == chunk_count {
                    stored_body.to_vec()
                } else {
                    Vec::new()
                };
                chunk
            })
            .collect();
    }

    let mut consumed_original_len = 0u128;
    let mut rechunked = Vec::with_capacity(chunk_count);
    for (idx, mut chunk) in chunks.into_iter().enumerate() {
        let chunk_original_len = chunk.chunk_body.len() as u128;
        let next_consumed_original_len = consumed_original_len.saturating_add(chunk_original_len);
        let start = ((consumed_original_len * stored_len_u128) / total_original_len) as usize;
        let end = if idx + 1 == chunk_count {
            stored_len
        } else {
            ((next_consumed_original_len * stored_len_u128) / total_original_len) as usize
        };

        chunk.chunk_body = stored_body[start..end].to_vec();
        rechunked.push(chunk);
        consumed_original_len = next_consumed_original_len;
    }

    rechunked
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

async fn response_from_stored_recording(
    storage: &Storage,
    route: &ProxyRoute,
    stored_recording: StoredRecording,
) -> Response<ProxyBody> {
    let preserve_timing = route
        .streaming
        .as_ref()
        .map(|streaming| streaming.preserve_timing)
        .unwrap_or(false);
    #[cfg_attr(not(feature = "scripting"), allow(unused_mut))]
    let mut response_chunks = if route.streaming.is_some() {
        match storage.get_response_chunks(stored_recording.id).await {
            Ok(chunks) => Some(chunks).filter(|chunks| !chunks.is_empty()),
            Err(err) => {
                tracing::debug!(
                    route = %route.route_ref,
                    recording_id = stored_recording.id,
                    "failed to read replay response chunks: {err}"
                );
                None
            }
        }
    } else {
        None
    };
    #[cfg_attr(not(feature = "scripting"), allow(unused_mut))]
    let mut recording = stored_recording.recording;

    #[cfg(not(feature = "scripting"))]
    if route.transform.on_replay.is_some() {
        tracing::debug!(
            route = %route.route_ref,
            "on_replay script is configured but scripting support is disabled"
        );
        return proxy_simple_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "on_replay script configured but this replayproxy build does not include scripting support",
        );
    }

    #[cfg(feature = "scripting")]
    if let Some(script) = route.transform.on_replay.as_ref()
        && let Err(err) = apply_on_replay_script(
            &route.route_ref,
            script,
            &mut recording,
            &mut response_chunks,
        )
    {
        tracing::debug!("failed to run on_replay script: {err}");
        return proxy_simple_response(StatusCode::INTERNAL_SERVER_ERROR, "on_replay script failed");
    }

    response_from_recording(recording, response_chunks, preserve_timing)
}

fn response_from_recording(
    recording: Recording,
    response_chunks: Option<Vec<ResponseChunk>>,
    preserve_timing: bool,
) -> Response<ProxyBody> {
    let Recording {
        response_status,
        response_headers,
        response_body,
        ..
    } = recording;
    let body_len = response_body.len();
    let use_chunk_stream = response_chunks
        .as_ref()
        .map(|chunks| !chunks.is_empty())
        .unwrap_or(false);
    let body = match response_chunks {
        Some(chunks) if !chunks.is_empty() => boxed_replay_chunks(chunks, preserve_timing),
        _ => boxed_full(Bytes::from(response_body)),
    };
    let mut response = Response::new(body);
    *response.status_mut() =
        StatusCode::from_u16(response_status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    for (name, value) in response_headers {
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
    if use_chunk_stream {
        response.headers_mut().remove(header::CONTENT_LENGTH);
    } else if let Ok(content_length) = HeaderValue::from_str(&body_len.to_string()) {
        response
            .headers_mut()
            .insert(header::CONTENT_LENGTH, content_length);
    }

    response
}

async fn lookup_recording_for_request(
    storage: &Storage,
    route_match: Option<&RouteMatchConfig>,
    request_uri: &Uri,
    match_key: &str,
) -> anyhow::Result<Option<StoredRecording>> {
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
) -> anyhow::Result<Option<StoredRecording>> {
    let query_mode = route_match
        .map(|route_match| route_match.query)
        .unwrap_or(QueryMatchMode::Exact);

    if query_mode != QueryMatchMode::Subset {
        return storage.get_recording_with_id_by_match_key(match_key).await;
    }

    let request_query = request_uri.query();
    if let Some(subset_query_normalizations) =
        matching::subset_query_candidate_normalizations_with_limit(
            request_query,
            subset_candidate_limit,
        )
    {
        return storage
            .get_latest_recording_with_id_by_match_key_and_query_subset(
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

    let fallback_result = storage
        .get_latest_recording_with_id_by_match_key_and_query_subset_scan_with_stats(
            match_key,
            request_query,
        )
        .await?;
    tracing::debug!(
        match_key = %sanitize_match_key(match_key),
        subset_candidate_limit,
        request_query_param_count,
        matched = fallback_result.recording.is_some(),
        scanned_rows = fallback_result.scanned_rows,
        "completed subset lookup fallback recording scan"
    );
    Ok(fallback_result.recording)
}

fn build_upstream_uri(upstream_base: &Uri, original: &Uri) -> anyhow::Result<Uri> {
    let mut parts = original.clone().into_parts();
    parts.scheme = upstream_base.scheme().cloned();
    parts.authority = upstream_base.authority().cloned();
    Uri::from_parts(parts).map_err(|err| anyhow::anyhow!("construct upstream uri: {err}"))
}

fn resolve_upstream_uri_for_request(
    route: &ProxyRoute,
    request_uri: &Uri,
) -> anyhow::Result<Option<Uri>> {
    if let Some(upstream_base) = route.upstream.as_ref() {
        return build_upstream_uri(upstream_base, request_uri).map(Some);
    }
    Ok(forward_proxy_upstream_uri(request_uri))
}

fn use_http2_prior_knowledge_upstream(upstream_req: &Request<ProxyBody>) -> bool {
    upstream_req.version() == hyper::Version::HTTP_2
        && matches!(upstream_req.uri().scheme_str(), Some("http"))
}

async fn send_upstream_request(
    state: &ProxyState,
    upstream_req: Request<ProxyBody>,
) -> Result<Response<Incoming>, LegacyClientError> {
    if use_http2_prior_knowledge_upstream(&upstream_req) {
        return state.h2_upstream_client.request(upstream_req).await;
    }
    state.client.request(upstream_req).await
}

fn forward_proxy_upstream_uri(original: &Uri) -> Option<Uri> {
    if !matches!(original.scheme_str(), Some("http" | "https")) {
        return None;
    }
    original.authority()?;
    Some(original.clone())
}

fn upstream_authority_for_rate_limit_scope(upstream_uri: &Uri) -> Option<String> {
    upstream_uri
        .authority()
        .map(|authority| authority.as_str().to_ascii_lowercase())
}

async fn maybe_wait_for_record_rate_limit(
    state: &ProxyState,
    route: &ProxyRoute,
    upstream_uri: &Uri,
) -> Result<(), RecordRateLimitRejection> {
    if route.mode != RouteMode::Record {
        return Ok(());
    }
    let Some(rate_limit) = route.rate_limit.as_ref() else {
        return Ok(());
    };
    let Some(upstream_authority) = upstream_authority_for_rate_limit_scope(upstream_uri) else {
        return Ok(());
    };

    let limiter = state.record_rate_limiters.limiter(
        RecordRateLimitKey {
            route_ref: route.route_ref.clone(),
            upstream_authority: upstream_authority.clone(),
            mode: RateLimitScopeMode::Record,
        },
        rate_limit,
    );
    let delay = limiter.reserve_delay().await?;
    if delay.is_zero() {
        return Ok(());
    }

    let delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
    tracing::debug!(
        route = %route.route_ref,
        upstream = %upstream_authority,
        delay_ms,
        "record mode rate limiter delayed upstream request"
    );
    tokio::time::sleep(delay).await;
    Ok(())
}

async fn maybe_reject_for_replay_rate_limit(
    state: &ProxyState,
    route: &ProxyRoute,
    upstream_uri: &Uri,
) -> Option<Duration> {
    if route.mode != RouteMode::Replay {
        return None;
    }
    let rate_limit = route.rate_limit.as_ref()?;
    let upstream_authority = upstream_authority_for_rate_limit_scope(upstream_uri)?;

    let limiter = state.record_rate_limiters.limiter(
        RecordRateLimitKey {
            route_ref: route.route_ref.clone(),
            upstream_authority: upstream_authority.clone(),
            mode: RateLimitScopeMode::Replay,
        },
        rate_limit,
    );
    let required_delay = match limiter.reserve_replay_request().await {
        Ok(()) => return None,
        Err(required_delay) => required_delay,
    };

    let required_delay_ms = u64::try_from(required_delay.as_millis()).unwrap_or(u64::MAX);
    let retry_after_seconds = retry_after_seconds_from_delay(required_delay);
    tracing::debug!(
        route = %route.route_ref,
        upstream = %upstream_authority,
        required_delay_ms,
        retry_after_seconds,
        "replay mode rate limiter rejected request"
    );
    Some(required_delay)
}

fn connect_tunnel_target(authority: &hyper::http::uri::Authority) -> String {
    if authority.port().is_some() {
        return authority.as_str().to_owned();
    }
    let host = authority.host();
    if host.contains(':') {
        if host.starts_with('[') && host.ends_with(']') {
            format!("{host}:443")
        } else {
            format!("[{host}]:443")
        }
    } else {
        format!("{host}:443")
    }
}

async fn tunnel_upgraded_connection(
    on_upgrade: hyper::upgrade::OnUpgrade,
    mut upstream_stream: TcpStream,
) -> anyhow::Result<()> {
    let upgraded = on_upgrade
        .await
        .map_err(|err| anyhow::anyhow!("upgrade client connection: {err}"))?;
    let mut upgraded = TokioIo::new(upgraded);
    tokio::io::copy_bidirectional(&mut upgraded, &mut upstream_stream)
        .await
        .map_err(|err| anyhow::anyhow!("copy tunnel bytes: {err}"))?;
    Ok(())
}

async fn tunnel_websocket_upgraded_connections(
    client_on_upgrade: hyper::upgrade::OnUpgrade,
    upstream_on_upgrade: hyper::upgrade::OnUpgrade,
) -> anyhow::Result<()> {
    let client_upgraded = client_on_upgrade
        .await
        .map_err(|err| anyhow::anyhow!("upgrade client websocket connection: {err}"))?;
    let upstream_upgraded = upstream_on_upgrade
        .await
        .map_err(|err| anyhow::anyhow!("upgrade upstream websocket connection: {err}"))?;
    let mut client_upgraded = TokioIo::new(client_upgraded);
    let mut upstream_upgraded = TokioIo::new(upstream_upgraded);
    tokio::io::copy_bidirectional(&mut client_upgraded, &mut upstream_upgraded)
        .await
        .map_err(|err| anyhow::anyhow!("copy websocket upgraded bytes: {err}"))?;
    Ok(())
}

fn normalize_tunneled_https_request_uri(
    connect_authority: &Authority,
    request_uri: &Uri,
) -> anyhow::Result<Uri> {
    let has_scheme = request_uri.scheme().is_some();
    let has_authority = request_uri.authority().is_some();
    if has_scheme || has_authority {
        if !(has_scheme && has_authority) {
            anyhow::bail!(
                "HTTPS CONNECT request target must be origin-form or absolute-form URI with authority"
            );
        }
        if !matches!(request_uri.scheme_str(), Some("http" | "https")) {
            anyhow::bail!("HTTPS CONNECT request target scheme must be `http` or `https`");
        }
        return Ok(request_uri.clone());
    }

    if request_uri.path() == "*" {
        anyhow::bail!("HTTPS CONNECT request target `*` is not supported");
    }
    let path_and_query = request_uri
        .path_and_query()
        .map(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("/");
    let uri = format!("https://{}{path_and_query}", connect_authority.as_str());
    uri.parse()
        .map_err(|err| anyhow::anyhow!("construct tunneled HTTPS request URI: {err}"))
}

fn normalize_tunneled_https_request(
    mut req: Request<Incoming>,
    connect_authority: &Authority,
) -> anyhow::Result<Request<Incoming>> {
    let normalized_uri = normalize_tunneled_https_request_uri(connect_authority, req.uri())?;
    *req.uri_mut() = normalized_uri;
    Ok(req)
}

fn build_leaf_tls_acceptor(leaf: &ca::LeafCertMaterial) -> anyhow::Result<TlsAcceptor> {
    let cert_chain = vec![CertificateDer::from(leaf.cert_der.clone())];
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.key_der.clone()));
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|err| anyhow::anyhow!("build TLS server certificate: {err}"))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

async fn mitm_upgraded_connection(
    on_upgrade: hyper::upgrade::OnUpgrade,
    connect_authority: Authority,
    state: Arc<ProxyState>,
    mitm_tls: Arc<MitmTlsState>,
) -> anyhow::Result<()> {
    let upgraded = on_upgrade
        .await
        .map_err(|err| anyhow::anyhow!("upgrade client CONNECT tunnel: {err}"))?;
    let leaf = mitm_tls
        .leaf_generator
        .issue_for_host(connect_authority.host())
        .map_err(|err| {
            anyhow::anyhow!(
                "issue leaf certificate for CONNECT authority `{}`: {err}",
                connect_authority.host()
            )
        })?;
    let acceptor = build_leaf_tls_acceptor(&leaf)?;
    let upgraded = TokioIo::new(upgraded);
    let tls_stream = acceptor.accept(upgraded).await.map_err(|err| {
        anyhow::anyhow!(
            "TLS handshake for CONNECT authority `{connect_authority}` failed: {err}; ensure client trust includes the replayproxy CA certificate"
        )
    })?;

    let io = TokioIo::new(tls_stream);
    let service_connect_authority = connect_authority.clone();
    let service = service_fn(move |req| {
        let state = Arc::clone(&state);
        let connect_authority = service_connect_authority.clone();
        async move {
            let response = dispatch_tunneled_https_request(req, state, connect_authority).await;
            Ok::<_, Infallible>(response)
        }
    });
    let builder = ConnectionBuilder::new(TokioExecutor::new());
    builder
        .serve_connection_with_upgrades(io, service)
        .await
        .map_err(|err| anyhow::anyhow!("serve CONNECT tunneled HTTP session: {err}"))?;
    Ok(())
}

fn dispatch_tunneled_https_request(
    req: Request<Incoming>,
    state: Arc<ProxyState>,
    connect_authority: Authority,
) -> Pin<Box<dyn Future<Output = Response<ProxyBody>> + Send>> {
    Box::pin(async move {
        let req = match normalize_tunneled_https_request(req, &connect_authority) {
            Ok(req) => req,
            Err(err) => {
                tracing::debug!(
                    authority = %connect_authority,
                    "failed to normalize CONNECT tunneled request: {err}"
                );
                return proxy_simple_response(
                    StatusCode::BAD_REQUEST,
                    "invalid HTTPS request target inside CONNECT tunnel",
                );
            }
        };

        match proxy_handler(req, state).await {
            Ok(response) => response,
            Err(never) => match never {},
        }
    })
}

fn set_host_header(headers: &mut hyper::HeaderMap, uri: &Uri) {
    let Some(authority) = uri.authority() else {
        return;
    };
    if let Ok(value) = HeaderValue::from_str(authority.as_str()) {
        headers.insert(header::HOST, value);
    }
}

#[cfg(feature = "scripting")]
fn apply_on_request_script(
    route_ref: &str,
    script: &LoadedScript,
    parts: &mut hyper::http::request::Parts,
    body_bytes: &mut Bytes,
) -> anyhow::Result<()> {
    let ScriptHeaderProjection {
        utf8_headers: request_utf8_headers,
        binary_headers: request_binary_headers,
    } = script_headers_from_http(&parts.headers);
    let mut request = ScriptRequest::new(
        parts.method.to_string(),
        parts.uri.to_string(),
        request_utf8_headers,
        body_bytes.to_vec(),
    );
    run_on_request_script(
        route_ref,
        &script.path.display().to_string(),
        script.source.as_ref(),
        &mut request,
    )?;

    parts.method = Method::from_bytes(request.method.as_bytes()).map_err(|err| {
        anyhow::anyhow!("apply transformed request method for route `{route_ref}`: {err}")
    })?;
    parts.uri = request.url.parse::<Uri>().map_err(|err| {
        anyhow::anyhow!("apply transformed request URL for route `{route_ref}`: {err}")
    })?;
    parts.headers = script_headers_to_http(request.headers, request_binary_headers)?;
    strip_hop_by_hop_headers(&mut parts.headers);
    let content_length = HeaderValue::from_str(&request.body.len().to_string()).map_err(|err| {
        anyhow::anyhow!("set transformed request content-length for route `{route_ref}`: {err}")
    })?;
    parts.headers.insert(header::CONTENT_LENGTH, content_length);
    *body_bytes = Bytes::from(request.body);
    Ok(())
}

#[cfg(feature = "scripting")]
fn apply_on_response_script(
    route_ref: &str,
    script: &LoadedScript,
    parts: &mut hyper::http::response::Parts,
    body_bytes: &mut Bytes,
) -> anyhow::Result<()> {
    let ScriptHeaderProjection {
        utf8_headers: response_utf8_headers,
        binary_headers: response_binary_headers,
    } = script_headers_from_http(&parts.headers);
    let mut response = ScriptResponse::new(
        parts.status.as_u16(),
        response_utf8_headers,
        body_bytes.to_vec(),
    );
    run_on_response_script(
        route_ref,
        &script.path.display().to_string(),
        script.source.as_ref(),
        &mut response,
    )?;

    parts.status = StatusCode::from_u16(response.status).map_err(|err| {
        anyhow::anyhow!("apply transformed response status for route `{route_ref}`: {err}")
    })?;
    parts.headers = script_headers_to_http(response.headers, response_binary_headers)?;
    strip_hop_by_hop_headers(&mut parts.headers);
    let content_length =
        HeaderValue::from_str(&response.body.len().to_string()).map_err(|err| {
            anyhow::anyhow!(
                "set transformed response content-length for route `{route_ref}`: {err}"
            )
        })?;
    parts.headers.insert(header::CONTENT_LENGTH, content_length);
    *body_bytes = Bytes::from(response.body);
    Ok(())
}

#[cfg(feature = "scripting")]
fn apply_on_record_script(
    route_ref: &str,
    script: &LoadedScript,
    recording: &mut Recording,
) -> anyhow::Result<()> {
    let ScriptHeaderProjection {
        utf8_headers: request_utf8_headers,
        binary_headers: request_binary_headers,
    } = script_headers_from_recording_headers(&recording.request_headers);
    let ScriptHeaderProjection {
        utf8_headers: response_utf8_headers,
        binary_headers: response_binary_headers,
    } = script_headers_from_recording_headers(&recording.response_headers);
    let mut script_recording = ScriptRecording::new(
        ScriptRequest::new(
            recording.request_method.clone(),
            recording.request_uri.clone(),
            request_utf8_headers,
            recording.request_body.clone(),
        ),
        ScriptResponse::new(
            recording.response_status,
            response_utf8_headers,
            recording.response_body.clone(),
        ),
    );
    run_on_record_script(
        route_ref,
        &script.path.display().to_string(),
        script.source.as_ref(),
        &mut script_recording,
    )?;

    recording.request_method = script_recording.request.method;
    recording.request_uri = script_recording.request.url;
    recording.request_headers = script_headers_to_recording_headers(
        script_recording.request.headers,
        request_binary_headers,
    )?;
    recording.request_body = script_recording.request.body;
    recording.response_status = script_recording.response.status;
    recording.response_headers = script_headers_to_recording_headers(
        script_recording.response.headers,
        response_binary_headers,
    )?;
    recording.response_body = script_recording.response.body;
    Ok(())
}

#[cfg(feature = "scripting")]
fn apply_on_replay_script(
    route_ref: &str,
    script: &LoadedScript,
    recording: &mut Recording,
    response_chunks: &mut Option<Vec<ResponseChunk>>,
) -> anyhow::Result<()> {
    let original_body = recording.response_body.clone();
    let ScriptHeaderProjection {
        utf8_headers: response_utf8_headers,
        binary_headers: response_binary_headers,
    } = script_headers_from_recording_headers(&recording.response_headers);
    let mut response = ScriptResponse::new(
        recording.response_status,
        response_utf8_headers,
        recording.response_body.clone(),
    );
    run_on_replay_script(
        route_ref,
        &script.path.display().to_string(),
        script.source.as_ref(),
        &mut response,
    )?;

    recording.response_status = response.status;
    recording.response_headers =
        script_headers_to_recording_headers(response.headers, response_binary_headers)?;
    recording.response_body = response.body;

    if let Some(chunks) = response_chunks.take() {
        let adjusted = response_chunks_for_storage(
            original_body.as_slice(),
            recording.response_body.as_slice(),
            chunks,
        );
        *response_chunks = Some(adjusted).filter(|chunks| !chunks.is_empty());
    }
    Ok(())
}

#[cfg(feature = "scripting")]
#[derive(Debug, Default)]
struct ScriptHeaderProjection {
    utf8_headers: BTreeMap<String, String>,
    binary_headers: BTreeMap<String, Vec<u8>>,
}

#[cfg(feature = "scripting")]
impl ScriptHeaderProjection {
    fn insert_utf8(&mut self, name: String, value: String) {
        remove_header_case_insensitive(&mut self.binary_headers, &name);
        remove_header_case_insensitive(&mut self.utf8_headers, &name);
        self.utf8_headers.insert(name, value);
    }

    fn insert_binary(&mut self, name: String, value: Vec<u8>) {
        remove_header_case_insensitive(&mut self.utf8_headers, &name);
        remove_header_case_insensitive(&mut self.binary_headers, &name);
        self.binary_headers.insert(name, value);
    }
}

#[cfg(feature = "scripting")]
fn remove_header_case_insensitive<T>(headers: &mut BTreeMap<String, T>, name: &str) {
    if let Some(existing_name) = headers
        .keys()
        .find(|existing_name| existing_name.eq_ignore_ascii_case(name))
        .cloned()
    {
        headers.remove(&existing_name);
    }
}

#[cfg(feature = "scripting")]
fn has_header_case_insensitive<T>(headers: &BTreeMap<String, T>, name: &str) -> bool {
    headers
        .keys()
        .any(|existing_name| existing_name.eq_ignore_ascii_case(name))
}

#[cfg(feature = "scripting")]
fn script_headers_from_http(headers: &hyper::HeaderMap) -> ScriptHeaderProjection {
    let mut out = ScriptHeaderProjection::default();
    for (name, value) in headers {
        let name = name.as_str().to_owned();
        match value.to_str() {
            Ok(value) => out.insert_utf8(name, value.to_owned()),
            Err(_) => out.insert_binary(name, value.as_bytes().to_vec()),
        }
    }
    out
}

#[cfg(feature = "scripting")]
fn script_headers_from_recording_headers(headers: &[(String, Vec<u8>)]) -> ScriptHeaderProjection {
    let mut out = ScriptHeaderProjection::default();
    for (name, value) in headers {
        match std::str::from_utf8(value) {
            Ok(value) => out.insert_utf8(name.clone(), value.to_owned()),
            Err(_) => out.insert_binary(name.clone(), value.clone()),
        }
    }
    out
}

#[cfg(feature = "scripting")]
fn script_headers_to_http(
    headers: BTreeMap<String, String>,
    preserved_binary_headers: BTreeMap<String, Vec<u8>>,
) -> anyhow::Result<hyper::HeaderMap> {
    let mut out = hyper::HeaderMap::new();
    for (name, value) in preserved_binary_headers {
        if has_header_case_insensitive(&headers, &name) {
            continue;
        }
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|err| anyhow::anyhow!("invalid preserved header name `{name}`: {err}"))?;
        let header_value = HeaderValue::from_bytes(&value)
            .map_err(|err| anyhow::anyhow!("invalid preserved header value for `{name}`: {err}"))?;
        out.insert(header_name, header_value);
    }
    for (name, value) in headers {
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|err| anyhow::anyhow!("invalid transformed header name `{name}`: {err}"))?;
        let header_value = HeaderValue::from_str(&value).map_err(|err| {
            anyhow::anyhow!("invalid transformed header value for `{name}`: {err}")
        })?;
        out.insert(header_name, header_value);
    }
    Ok(out)
}

#[cfg(feature = "scripting")]
fn script_headers_to_recording_headers(
    headers: BTreeMap<String, String>,
    preserved_binary_headers: BTreeMap<String, Vec<u8>>,
) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::with_capacity(headers.len() + preserved_binary_headers.len());
    for (name, value) in headers {
        HeaderName::from_bytes(name.as_bytes())
            .map_err(|err| anyhow::anyhow!("invalid transformed header name `{name}`: {err}"))?;
        HeaderValue::from_str(&value).map_err(|err| {
            anyhow::anyhow!("invalid transformed header value for `{name}`: {err}")
        })?;
        out.push((name, value.into_bytes()));
    }
    for (name, value) in preserved_binary_headers {
        if out
            .iter()
            .any(|(existing_name, _)| existing_name.eq_ignore_ascii_case(&name))
        {
            continue;
        }
        HeaderName::from_bytes(name.as_bytes())
            .map_err(|err| anyhow::anyhow!("invalid preserved header name `{name}`: {err}"))?;
        HeaderValue::from_bytes(&value)
            .map_err(|err| anyhow::anyhow!("invalid preserved header value for `{name}`: {err}"))?;
        out.push((name, value));
    }
    Ok(out)
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

fn header_contains_token(headers: &hyper::HeaderMap, header_name: HeaderName, token: &str) -> bool {
    headers.get_all(header_name).iter().any(|value| {
        value.to_str().ok().is_some_and(|raw| {
            raw.split(',')
                .any(|candidate| candidate.trim().eq_ignore_ascii_case(token))
        })
    })
}

fn is_websocket_upgrade_request(req: &Request<Incoming>) -> bool {
    if req.method() != Method::GET {
        return false;
    }

    if !header_contains_token(req.headers(), header::CONNECTION, "upgrade") {
        return false;
    }

    req.headers()
        .get(header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
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

fn record_rate_limit_rejection_response(error: RecordRateLimitRejection) -> Response<ProxyBody> {
    match error {
        RecordRateLimitRejection::QueueDepthExceeded { queue_depth } => proxy_simple_response(
            StatusCode::TOO_MANY_REQUESTS,
            &format!(
                "record mode rate limit queue is full (queue_depth={queue_depth}); retry later"
            ),
        ),
        RecordRateLimitRejection::QueueTimeoutExceeded {
            timeout,
            required_delay,
        } => {
            let timeout_ms = timeout.as_millis();
            let required_delay_ms = required_delay.as_millis();
            proxy_simple_response(
                StatusCode::GATEWAY_TIMEOUT,
                &format!(
                    "record mode rate limit queue timeout (timeout_ms={timeout_ms}, required_delay_ms={required_delay_ms})"
                ),
            )
        }
    }
}

fn replay_rate_limit_rejection_response(required_delay: Duration) -> Response<ProxyBody> {
    let retry_after_seconds = retry_after_seconds_from_delay(required_delay);
    let required_delay_ms = required_delay.as_millis();
    let mut response = proxy_simple_response(
        StatusCode::TOO_MANY_REQUESTS,
        &format!(
            "replay mode simulated rate limit exceeded (required_delay_ms={required_delay_ms}); retry later"
        ),
    );
    response.headers_mut().insert(
        header::RETRY_AFTER,
        HeaderValue::from_str(&retry_after_seconds.to_string())
            .expect("Retry-After delta seconds should be a valid header value"),
    );
    response
}

fn retry_after_seconds_from_delay(delay: Duration) -> u64 {
    if delay.is_zero() {
        return 1;
    }

    let seconds = delay.as_secs();
    if delay.subsec_nanos() > 0 {
        seconds.saturating_add(1)
    } else {
        seconds.max(1)
    }
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

fn admin_mode_response(state: &AdminState) -> Response<Full<Bytes>> {
    let runtime_override_mode = *state
        .runtime_mode_override
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let payload = AdminModeResponse {
        runtime_override_mode,
        default_mode: state.config_default_mode,
    };
    admin_json_response(StatusCode::OK, &payload)
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

    if path == "/_admin/mode" {
        return match method {
            hyper::Method::GET => Ok(admin_mode_response(state.as_ref())),
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
                let mode_request = match serde_json::from_slice::<AdminSetModeRequest>(&body_bytes)
                {
                    Ok(request) => request,
                    Err(err) => {
                        return Ok(admin_error_response(
                            StatusCode::BAD_REQUEST,
                            format!("invalid JSON body: {err}"),
                        ));
                    }
                };

                let payload = {
                    let mut runtime_mode = state
                        .runtime_mode_override
                        .write()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    *runtime_mode = Some(mode_request.mode);
                    let mut runtime_config = state
                        .runtime_config
                        .write()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    for route in &mut runtime_config.routes {
                        route.mode = mode_request.mode;
                        route.cache_miss = match mode_request.mode {
                            RouteMode::Replay => CacheMissPolicy::Error,
                            RouteMode::Record | RouteMode::PassthroughCache => {
                                CacheMissPolicy::Forward
                            }
                        };
                    }
                    AdminModeResponse {
                        runtime_override_mode: *runtime_mode,
                        default_mode: state.config_default_mode,
                    }
                };
                Ok(admin_json_response(StatusCode::OK, &payload))
            }
            _ => Ok(admin_error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed",
            )),
        };
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
        fs,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    use super::{
        CacheLogOutcome, ProxyRoute, REDACTION_PLACEHOLDER, connect_tunnel_target,
        emit_proxy_request_log, format_route_ref, forward_proxy_upstream_uri,
        lookup_recording_for_request_with_subset_limit, mode_log_label,
        normalize_tunneled_https_request_uri, redact_recording_body_json, redact_recording_headers,
        request_runtime_config_for_path, reserve_delay_for_bucket_with_limits,
        response_chunks_for_storage, sanitize_match_key, select_route, summarize_route_diff,
    };
    use crate::config::{
        BodyOversizePolicy, CacheMissPolicy, Config, RedactConfig, RouteConfig, RouteMatchConfig,
        RouteMode,
    };
    use crate::storage::{Recording, ResponseChunk, Storage};
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
            streaming: None,
            websocket: None,
            rate_limit: None,
            redact: None,
            transform: super::RouteTransformScripts::default(),
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
    fn request_runtime_config_snapshot_keeps_route_and_limit_together() {
        let runtime_config = super::ProxyRuntimeConfig {
            routes: vec![test_route(Some("/v2/snapshot"), None, None)],
            max_body_bytes: 256,
        };

        let snapshot = request_runtime_config_for_path(&runtime_config, "/v2/snapshot");
        let route = snapshot.route.expect("expected matching route");

        assert_eq!(snapshot.max_body_bytes, 256);
        assert_eq!(route.path_exact.as_deref(), Some("/v2/snapshot"));
    }

    #[test]
    fn reserve_delay_for_bucket_allows_burst_then_queues() {
        let now = Instant::now();
        let mut state = super::RecordTokenBucketState {
            available_tokens: 1.0,
            last_refill: now,
        };

        let first_delay =
            reserve_delay_for_bucket_with_limits(&mut state, now, 2.0, 1.0, None, None).unwrap();
        let second_delay =
            reserve_delay_for_bucket_with_limits(&mut state, now, 2.0, 1.0, None, None).unwrap();

        assert_eq!(first_delay, Duration::ZERO);
        assert!(second_delay >= Duration::from_millis(499));
    }

    #[test]
    fn reserve_delay_for_bucket_refills_tokens_over_time() {
        let now = Instant::now();
        let mut state = super::RecordTokenBucketState {
            available_tokens: 0.0,
            last_refill: now,
        };

        let delay = reserve_delay_for_bucket_with_limits(
            &mut state,
            now + Duration::from_millis(500),
            2.0,
            2.0,
            None,
            None,
        )
        .unwrap();

        assert_eq!(delay, Duration::ZERO);
    }

    #[test]
    fn reserve_delay_for_bucket_enforces_queue_depth_limit() {
        let now = Instant::now();
        let mut state = super::RecordTokenBucketState {
            available_tokens: 1.0,
            last_refill: now,
        };

        let first_delay =
            reserve_delay_for_bucket_with_limits(&mut state, now, 1.0, 1.0, Some(1), None).unwrap();
        let second_delay =
            reserve_delay_for_bucket_with_limits(&mut state, now, 1.0, 1.0, Some(1), None).unwrap();
        let third = reserve_delay_for_bucket_with_limits(&mut state, now, 1.0, 1.0, Some(1), None);

        assert_eq!(first_delay, Duration::ZERO);
        assert!(second_delay >= Duration::from_millis(999));
        assert_eq!(
            third,
            Err(super::RecordRateLimitRejection::QueueDepthExceeded { queue_depth: 1 })
        );
    }

    #[test]
    fn reserve_delay_for_bucket_enforces_queue_timeout_limit() {
        let now = Instant::now();
        let mut state = super::RecordTokenBucketState {
            available_tokens: 1.0,
            last_refill: now,
        };

        let first_delay = reserve_delay_for_bucket_with_limits(
            &mut state,
            now,
            1.0,
            1.0,
            Some(4),
            Some(Duration::from_millis(100)),
        )
        .unwrap();
        let second = reserve_delay_for_bucket_with_limits(
            &mut state,
            now,
            1.0,
            1.0,
            Some(4),
            Some(Duration::from_millis(100)),
        );

        assert_eq!(first_delay, Duration::ZERO);
        assert_eq!(
            second,
            Err(super::RecordRateLimitRejection::QueueTimeoutExceeded {
                timeout: Duration::from_millis(100),
                required_delay: Duration::from_secs(1),
            })
        );
        assert_eq!(state.available_tokens, 0.0);
    }

    #[tokio::test]
    async fn reserve_replay_request_rejects_without_consuming_tokens() {
        let rate_limit = super::RouteRateLimit {
            requests_per_second: 1,
            burst: 1,
            queue_depth: None,
            timeout: None,
        };
        let bucket = super::RecordTokenBucket::new(&rate_limit);

        assert_eq!(bucket.reserve_replay_request().await, Ok(()));
        let first_retry_after = bucket
            .reserve_replay_request()
            .await
            .expect_err("second request should be throttled in replay mode");
        let second_retry_after = bucket
            .reserve_replay_request()
            .await
            .expect_err("throttled replay requests should continue to be rejected");

        assert!(first_retry_after >= Duration::from_millis(900));
        assert!(second_retry_after >= Duration::from_millis(900));
        assert!(
            second_retry_after < Duration::from_millis(1100),
            "rejected replay requests should not consume additional tokens"
        );
    }

    #[test]
    fn retry_after_seconds_rounds_up_subsecond_delay() {
        assert_eq!(
            super::retry_after_seconds_from_delay(Duration::from_millis(1)),
            1
        );
        assert_eq!(
            super::retry_after_seconds_from_delay(Duration::from_millis(1001)),
            2
        );
        assert_eq!(
            super::retry_after_seconds_from_delay(Duration::from_secs(3)),
            3
        );
    }

    #[test]
    fn forward_proxy_upstream_uri_accepts_absolute_http_request_target() {
        let request_uri: hyper::Uri = "http://example.test/api/hello?x=1".parse().unwrap();
        let upstream_uri =
            forward_proxy_upstream_uri(&request_uri).expect("absolute-form uri should resolve");

        assert_eq!(upstream_uri, request_uri);
    }

    #[test]
    fn forward_proxy_upstream_uri_rejects_origin_form_request_target() {
        let request_uri: hyper::Uri = "/api/hello?x=1".parse().unwrap();

        assert!(forward_proxy_upstream_uri(&request_uri).is_none());
    }

    #[test]
    fn connect_tunnel_target_preserves_explicit_port() {
        let authority: hyper::http::uri::Authority = "example.test:8443".parse().unwrap();

        assert_eq!(connect_tunnel_target(&authority), "example.test:8443");
    }

    #[test]
    fn connect_tunnel_target_defaults_to_https_port_when_missing() {
        let authority: hyper::http::uri::Authority = "example.test".parse().unwrap();

        assert_eq!(connect_tunnel_target(&authority), "example.test:443");
    }

    #[test]
    fn connect_tunnel_target_brackets_ipv6_authority_when_port_missing() {
        let authority: hyper::http::uri::Authority = "[::1]".parse().unwrap();

        assert_eq!(connect_tunnel_target(&authority), "[::1]:443");
    }

    #[test]
    fn normalize_tunneled_https_request_uri_builds_absolute_uri_from_origin_form() {
        let connect_authority: hyper::http::uri::Authority =
            "api.example.test:443".parse().unwrap();
        let request_uri: hyper::Uri = "/v1/chat/completions?x=1".parse().unwrap();

        let normalized =
            normalize_tunneled_https_request_uri(&connect_authority, &request_uri).unwrap();
        assert_eq!(
            normalized,
            "https://api.example.test:443/v1/chat/completions?x=1"
        );
    }

    #[test]
    fn normalize_tunneled_https_request_uri_preserves_valid_absolute_form() {
        let connect_authority: hyper::http::uri::Authority =
            "api.example.test:443".parse().unwrap();
        let request_uri: hyper::Uri = "https://other.example.test/v1/models".parse().unwrap();

        let normalized =
            normalize_tunneled_https_request_uri(&connect_authority, &request_uri).unwrap();
        assert_eq!(normalized, request_uri);
    }

    #[test]
    fn normalize_tunneled_https_request_uri_rejects_unsupported_absolute_scheme() {
        let connect_authority: hyper::http::uri::Authority =
            "api.example.test:443".parse().unwrap();
        let request_uri: hyper::Uri = "ftp://api.example.test/v1/models".parse().unwrap();

        let err =
            normalize_tunneled_https_request_uri(&connect_authority, &request_uri).unwrap_err();
        assert!(
            err.to_string().contains("scheme must be `http` or `https`"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn summarize_route_diff_detects_added_removed_and_changed_routes() {
        let current = super::ProxyRuntimeConfig {
            routes: vec![
                test_route(Some("/v1/stable"), None, None),
                test_route(Some("/v1/removed"), None, None),
                test_route(Some("/v1/redacted"), None, None),
            ],
            max_body_bytes: 64,
        };
        let mut changed_redaction_route = test_route(Some("/v1/redacted"), None, None);
        changed_redaction_route.redact = Some(RedactConfig {
            headers: vec!["authorization".to_owned()],
            body_json: vec!["$.token".to_owned()],
            placeholder: None,
        });
        let next = super::ProxyRuntimeConfig {
            routes: vec![
                test_route(Some("/v1/stable"), None, None),
                changed_redaction_route,
                test_route(Some("/v1/new"), None, None),
                test_route(Some("/v1/added"), None, None),
            ],
            max_body_bytes: 64,
        };

        let summary = summarize_route_diff(&current, &next);
        assert_eq!(summary.changed, vec![1, 2]);
        assert_eq!(summary.added, vec![3]);
        assert!(summary.removed.is_empty());
        assert!(summary.has_changes());
    }

    #[test]
    fn summarize_route_diff_classifies_reordered_routes_as_add_remove() {
        let current = super::ProxyRuntimeConfig {
            routes: vec![
                test_route(Some("/v1/alpha"), None, None),
                test_route(Some("/v1/bravo"), None, None),
                test_route(Some("/v1/charlie"), None, None),
            ],
            max_body_bytes: 64,
        };
        let next = super::ProxyRuntimeConfig {
            routes: vec![
                test_route(Some("/v1/charlie"), None, None),
                test_route(Some("/v1/alpha"), None, None),
                test_route(Some("/v1/bravo"), None, None),
            ],
            max_body_bytes: 64,
        };

        let summary = summarize_route_diff(&current, &next);
        assert_eq!(summary.removed, vec![0, 1, 2]);
        assert_eq!(summary.added, vec![0, 1, 2]);
        assert!(summary.changed.is_empty());
        assert!(summary.has_changes());
    }

    #[test]
    fn summarize_route_diff_detects_removed_routes() {
        let current = super::ProxyRuntimeConfig {
            routes: vec![
                test_route(Some("/v1/keep"), None, None),
                test_route(Some("/v1/removed"), None, None),
            ],
            max_body_bytes: 64,
        };
        let next = super::ProxyRuntimeConfig {
            routes: vec![test_route(Some("/v1/keep"), None, None)],
            max_body_bytes: 64,
        };

        let summary = summarize_route_diff(&current, &next);
        assert_eq!(summary.removed, vec![1]);
        assert!(summary.changed.is_empty());
        assert!(summary.added.is_empty());
        assert!(summary.has_changes());
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
    fn runtime_config_loads_transform_scripts_relative_to_config_file() {
        let temp_dir = tempfile::tempdir().expect("tempdir should be created");
        let scripts_dir = temp_dir.path().join("scripts");
        fs::create_dir_all(&scripts_dir).expect("scripts dir should be created");
        let request_script_path = scripts_dir.join("on_request.lua");
        let response_script_path = scripts_dir.join("on_response.lua");
        let record_script_path = scripts_dir.join("on_record.lua");
        let replay_script_path = scripts_dir.join("on_replay.lua");
        fs::write(
            &request_script_path,
            "function transform(request) return request end",
        )
        .expect("request script should be written");
        fs::write(
            &response_script_path,
            "function transform(response) return response end",
        )
        .expect("response script should be written");
        fs::write(
            &record_script_path,
            "function transform(recording) return recording end",
        )
        .expect("record script should be written");
        fs::write(
            &replay_script_path,
            "function transform(response) return response end",
        )
        .expect("replay script should be written");
        let config_path = temp_dir.path().join("replayproxy.toml");
        fs::write(
            &config_path,
            r#"
[proxy]
listen = "127.0.0.1:0"

[[routes]]
name = "lua-route"
path_prefix = "/api"
upstream = "http://127.0.0.1:1234"

[routes.transform]
on_request = "scripts/on_request.lua"
on_response = "scripts/on_response.lua"
on_record = "scripts/on_record.lua"
on_replay = "scripts/on_replay.lua"
"#,
        )
        .expect("config should be written");

        let config = Config::from_path(&config_path).expect("config should parse");
        let runtime = super::ProxyRuntimeConfig::from_config(&config)
            .expect("runtime config should load scripts");
        let route = runtime.routes.first().expect("expected one route");

        let loaded_request = route
            .transform
            .on_request
            .as_ref()
            .expect("on_request should be loaded");
        let loaded_response = route
            .transform
            .on_response
            .as_ref()
            .expect("on_response should be loaded");
        let loaded_record = route
            .transform
            .on_record
            .as_ref()
            .expect("on_record should be loaded");
        let loaded_replay = route
            .transform
            .on_replay
            .as_ref()
            .expect("on_replay should be loaded");

        assert_eq!(loaded_request.path, request_script_path);
        assert_eq!(
            loaded_request.source.as_ref(),
            "function transform(request) return request end"
        );
        assert_eq!(loaded_response.path, response_script_path);
        assert_eq!(
            loaded_response.source.as_ref(),
            "function transform(response) return response end"
        );
        assert_eq!(loaded_record.path, record_script_path);
        assert_eq!(
            loaded_record.source.as_ref(),
            "function transform(recording) return recording end"
        );
        assert_eq!(loaded_replay.path, replay_script_path);
        assert_eq!(
            loaded_replay.source.as_ref(),
            "function transform(response) return response end"
        );
    }

    #[test]
    fn runtime_config_fails_fast_when_transform_script_is_missing() {
        let config = Config::from_toml_str(
            r#"
[proxy]
listen = "127.0.0.1:0"

[[routes]]
name = "lua-route"
path_prefix = "/api"
upstream = "http://127.0.0.1:1234"

[routes.transform]
on_request = "scripts/missing.lua"
"#,
        )
        .expect("config should parse");

        let err = super::ProxyRuntimeConfig::from_config(&config)
            .expect_err("missing scripts should fail fast");
        let message = err.to_string();
        assert!(
            message.contains("routes[0] (lua-route)"),
            "unexpected error: {message}"
        );
        assert!(
            message.contains("routes.transform.on_request"),
            "unexpected error: {message}"
        );
        assert!(
            message.contains("scripts/missing.lua"),
            "unexpected error: {message}"
        );
    }

    #[tokio::test]
    async fn serve_autogenerates_missing_tls_ca_material_for_default_file_names() {
        let temp_dir = tempfile::tempdir().expect("tempdir should be created");
        let ca_dir = temp_dir.path().join("ca");
        let cert_path = ca_dir.join(crate::ca::CA_CERT_FILE_NAME);
        let key_path = ca_dir.join(crate::ca::CA_KEY_FILE_NAME);
        let config = Config::from_toml_str(&format!(
            r#"
[proxy]
listen = "127.0.0.1:0"

[proxy.tls]
enabled = true
ca_cert = "{}"
ca_key = "{}"
"#,
            cert_path.display(),
            key_path.display()
        ))
        .expect("config should parse");

        let proxy = super::serve(&config)
            .await
            .expect("serve should auto-generate CA material");
        assert!(cert_path.exists(), "cert should be generated");
        assert!(key_path.exists(), "key should be generated");
        proxy.shutdown().await;
    }

    #[tokio::test]
    async fn serve_fails_when_tls_ca_material_is_partially_missing() {
        let temp_dir = tempfile::tempdir().expect("tempdir should be created");
        let ca_dir = temp_dir.path().join("ca");
        std::fs::create_dir_all(&ca_dir).expect("CA dir should be created");
        let cert_path = ca_dir.join(crate::ca::CA_CERT_FILE_NAME);
        let key_path = ca_dir.join(crate::ca::CA_KEY_FILE_NAME);
        std::fs::write(&cert_path, "not-a-certificate").expect("seed cert file");

        let config = Config::from_toml_str(&format!(
            r#"
[proxy]
listen = "127.0.0.1:0"

[proxy.tls]
enabled = true
ca_cert = "{}"
ca_key = "{}"
"#,
            cert_path.display(),
            key_path.display()
        ))
        .expect("config should parse");

        let err = super::serve(&config)
            .await
            .expect_err("serve should fail on partial CA material");
        assert!(
            err.to_string()
                .contains("incomplete `proxy.tls` CA material"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn serve_fails_fast_when_tls_ca_material_is_mismatched() {
        let temp_dir = tempfile::tempdir().expect("tempdir should be created");
        let first = crate::ca::generate_ca(&temp_dir.path().join("first"), false)
            .expect("first CA should generate");
        let second = crate::ca::generate_ca(&temp_dir.path().join("second"), false)
            .expect("second CA should generate");
        let config = Config::from_toml_str(&format!(
            r#"
[proxy]
listen = "127.0.0.1:0"

[proxy.tls]
enabled = true
ca_cert = "{}"
ca_key = "{}"
"#,
            first.cert_path.display(),
            second.key_path.display()
        ))
        .expect("config should parse");

        let err = super::serve(&config)
            .await
            .expect_err("serve should fail with mismatched CA cert/key");

        assert!(
            err.to_string().contains("do not match"),
            "unexpected error: {err}"
        );
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

        assert_eq!(fetched.recording.request_uri, "/api?a=1&b=2");
        assert_eq!(fetched.recording.response_body, b"newer-matching");
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
    fn response_chunks_for_storage_preserves_chunk_metadata_when_redaction_changes_body() {
        let original_body = br#"{"secret":"top-secret-1","items":[{"content":"top-secret-2"},{"content":"keep-me"}]}"#;
        let stored_body =
            br#"{"secret":"[REDACTED]","items":[{"content":"[REDACTED]"},{"content":"keep-me"}]}"#;
        let chunks = vec![
            ResponseChunk {
                chunk_index: 0,
                offset_ms: 0,
                chunk_body: original_body[..26].to_vec(),
            },
            ResponseChunk {
                chunk_index: 1,
                offset_ms: 7,
                chunk_body: original_body[26..58].to_vec(),
            },
            ResponseChunk {
                chunk_index: 2,
                offset_ms: 15,
                chunk_body: original_body[58..].to_vec(),
            },
        ];

        let stored_chunks = response_chunks_for_storage(original_body, stored_body, chunks);
        assert_eq!(stored_chunks.len(), 3);
        assert_eq!(
            stored_chunks
                .iter()
                .map(|chunk| chunk.chunk_index)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert_eq!(
            stored_chunks
                .iter()
                .map(|chunk| chunk.offset_ms)
                .collect::<Vec<_>>(),
            vec![0, 7, 15]
        );

        let reconstructed = stored_chunks
            .iter()
            .flat_map(|chunk| chunk.chunk_body.iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(reconstructed, stored_body);

        let stored_text = String::from_utf8_lossy(&reconstructed);
        assert!(!stored_text.contains("top-secret-1"));
        assert!(!stored_text.contains("top-secret-2"));
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
