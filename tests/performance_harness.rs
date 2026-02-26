use std::{
    fs,
    net::SocketAddr,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::{
    Method, Request, Response, StatusCode, Uri,
    body::Incoming,
    header::{self, HeaderValue},
    service::service_fn,
};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as ConnectionBuilder,
};
use serde_json::Value;
use tokio::{net::TcpListener, sync::oneshot, task::JoinSet};

const DEFAULT_REQUEST_COUNT: usize = 1_000;
const DEFAULT_CONCURRENCY: usize = 32;
const DEFAULT_WARMUP_COUNT: usize = 100;
const DEFAULT_RESPONSE_BYTES: usize = 2_048;

type BenchClient = Client<HttpConnector, Full<Bytes>>;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "benchmark-style harness; run explicitly with --ignored --nocapture"]
async fn performance_harness_record_replay_passthrough_cache() {
    let request_count = env_usize_nonzero("REPLAYPROXY_PERF_REQUESTS", DEFAULT_REQUEST_COUNT);
    let concurrency = env_usize_nonzero("REPLAYPROXY_PERF_CONCURRENCY", DEFAULT_CONCURRENCY);
    let warmup_count =
        env_usize("REPLAYPROXY_PERF_WARMUP", DEFAULT_WARMUP_COUNT).min(request_count);
    let response_bytes =
        env_usize_nonzero("REPLAYPROXY_PERF_RESPONSE_BYTES", DEFAULT_RESPONSE_BYTES);

    let record_paths = build_paths("/api/perf-record-replay", request_count);
    let replay_paths = record_paths.clone();
    let warmup_paths = record_paths[..warmup_count].to_vec();
    let cache_paths = build_paths("/api/perf-passthrough-cache", request_count);
    let cache_warmup_paths = cache_paths[..warmup_count].to_vec();

    let temp_dir = tempfile::tempdir().unwrap();
    let storage_root = temp_dir.path().join("storage");
    let upstream = spawn_upstream(Bytes::from(vec![b'x'; response_bytes])).await;
    let upstream_url = format!("http://{}", upstream.addr);

    let record_report = benchmark_scenario(
        "record",
        build_config_toml(
            &storage_root,
            "perf-record-replay",
            &upstream_url,
            "record",
            None,
        ),
        &warmup_paths,
        &record_paths,
        concurrency,
        StatusCode::OK,
    )
    .await;

    let replay_report = benchmark_scenario(
        "replay",
        build_config_toml(
            &storage_root,
            "perf-record-replay",
            "http://127.0.0.1:9",
            "replay",
            Some("error"),
        ),
        &warmup_paths,
        &replay_paths,
        concurrency,
        StatusCode::OK,
    )
    .await;
    assert_eq!(
        replay_report.admin_stats.upstream_requests_total, 0,
        "replay benchmark unexpectedly reached upstream"
    );

    let passthrough_cold_report = benchmark_scenario(
        "passthrough-cache-cold",
        build_config_toml(
            &storage_root,
            "perf-passthrough-cache",
            &upstream_url,
            "passthrough-cache",
            None,
        ),
        &[],
        &cache_paths,
        concurrency,
        StatusCode::OK,
    )
    .await;

    let passthrough_warm_report = benchmark_scenario(
        "passthrough-cache-warm",
        build_config_toml(
            &storage_root,
            "perf-passthrough-cache",
            &upstream_url,
            "passthrough-cache",
            None,
        ),
        &cache_warmup_paths,
        &cache_paths,
        concurrency,
        StatusCode::OK,
    )
    .await;
    assert_eq!(
        passthrough_warm_report.admin_stats.upstream_requests_total, 0,
        "warm passthrough-cache benchmark unexpectedly reached upstream"
    );

    let expected_upstream_requests =
        (warmup_paths.len() + record_paths.len() + cache_paths.len()) as u64;
    assert_eq!(
        upstream.request_count(),
        expected_upstream_requests,
        "unexpected upstream request total after benchmark scenarios"
    );

    println!();
    println!(
        "perf_harness settings request_count={} concurrency={} warmup_count={} response_bytes={}",
        request_count, concurrency, warmup_count, response_bytes
    );
    for report in [
        record_report,
        replay_report,
        passthrough_cold_report,
        passthrough_warm_report,
    ] {
        println!(
            "perf_result scenario={} requests={} success={} errors={} throughput_rps={:.2} total_ms={:.2} latency_avg_ms={:.3} latency_p50_ms={:.3} latency_p95_ms={:.3} latency_p99_ms={:.3} latency_max_ms={:.3} response_bytes_total={} rss_before_kib={} rss_after_kib={} rss_delta_kib={} hwm_after_kib={} cache_hits_total={} cache_misses_total={} upstream_requests_total={}",
            report.name,
            report.request_count,
            report.success_count,
            report.error_count,
            report.throughput_rps,
            duration_ms(report.total_elapsed),
            duration_ms(report.latency.avg),
            duration_ms(report.latency.p50),
            duration_ms(report.latency.p95),
            duration_ms(report.latency.p99),
            duration_ms(report.latency.max),
            report.response_bytes_total,
            display_opt_u64(report.rss_before_kib),
            display_opt_u64(report.rss_after_kib),
            display_opt_i64(report.rss_delta_kib),
            display_opt_u64(report.hwm_after_kib),
            report.admin_stats.cache_hits_total,
            report.admin_stats.cache_misses_total,
            report.admin_stats.upstream_requests_total,
        );
    }

    upstream.shutdown().await;
}

#[derive(Debug)]
struct UpstreamServer {
    addr: SocketAddr,
    requests_total: Arc<AtomicU64>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<()>,
}

impl UpstreamServer {
    fn request_count(&self) -> u64 {
        self.requests_total.load(Ordering::Relaxed)
    }

    async fn shutdown(mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
        let _ = self.join.await;
    }
}

async fn spawn_upstream(response_body: Bytes) -> UpstreamServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests_total = Arc::new(AtomicU64::new(0));
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let join = tokio::spawn({
        let requests_total = Arc::clone(&requests_total);
        async move {
            let mut shutdown_rx = std::pin::pin!(shutdown_rx);
            let mut connections = JoinSet::new();

            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        break;
                    }
                    accept_result = listener.accept() => {
                        let (stream, _peer) = match accept_result {
                            Ok(value) => value,
                            Err(_) => continue,
                        };

                        let io = TokioIo::new(stream);
                        let requests_total = Arc::clone(&requests_total);
                        let response_body = response_body.clone();
                        connections.spawn(async move {
                            let service = service_fn(move |_req: Request<Incoming>| {
                                let requests_total = Arc::clone(&requests_total);
                                let response_body = response_body.clone();
                                async move {
                                    requests_total.fetch_add(1, Ordering::Relaxed);
                                    let mut response = Response::new(Full::new(response_body));
                                    *response.status_mut() = StatusCode::OK;
                                    response.headers_mut().insert(
                                        header::CONTENT_TYPE,
                                        HeaderValue::from_static("application/octet-stream"),
                                    );
                                    Ok::<_, hyper::Error>(response)
                                }
                            });

                            let builder = ConnectionBuilder::new(TokioExecutor::new());
                            let _ = builder.serve_connection(io, service).await;
                        });
                    }
                }
            }

            connections.abort_all();
            while connections.join_next().await.is_some() {}
        }
    });

    UpstreamServer {
        addr,
        requests_total,
        shutdown_tx: Some(shutdown_tx),
        join,
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct AdminStats {
    cache_hits_total: u64,
    cache_misses_total: u64,
    upstream_requests_total: u64,
}

#[derive(Debug)]
struct ScenarioReport {
    name: &'static str,
    request_count: usize,
    success_count: usize,
    error_count: usize,
    response_bytes_total: usize,
    total_elapsed: Duration,
    throughput_rps: f64,
    latency: LatencyStats,
    rss_before_kib: Option<u64>,
    rss_after_kib: Option<u64>,
    rss_delta_kib: Option<i64>,
    hwm_after_kib: Option<u64>,
    admin_stats: AdminStats,
}

#[derive(Debug)]
struct RunResult {
    success_count: usize,
    error_count: usize,
    response_bytes_total: usize,
    total_elapsed: Duration,
    latency_nanos: Vec<u64>,
    sample_errors: Vec<String>,
}

#[derive(Debug)]
struct RequestOutcome {
    latency: Duration,
    status: Option<StatusCode>,
    response_bytes: usize,
    error: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct LatencyStats {
    avg: Duration,
    p50: Duration,
    p95: Duration,
    p99: Duration,
    max: Duration,
}

impl LatencyStats {
    fn from_nanos(latency_nanos: &[u64]) -> Self {
        assert!(
            !latency_nanos.is_empty(),
            "latency sample must not be empty"
        );

        let mut sorted = latency_nanos.to_vec();
        sorted.sort_unstable();

        let sum_nanos: u128 = sorted.iter().map(|value| u128::from(*value)).sum();
        let avg_nanos = (sum_nanos / latency_nanos.len() as u128).min(u128::from(u64::MAX)) as u64;

        Self {
            avg: Duration::from_nanos(avg_nanos),
            p50: Duration::from_nanos(percentile_nanos(&sorted, 50)),
            p95: Duration::from_nanos(percentile_nanos(&sorted, 95)),
            p99: Duration::from_nanos(percentile_nanos(&sorted, 99)),
            max: Duration::from_nanos(*sorted.last().unwrap()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct MemorySnapshot {
    rss_kib: Option<u64>,
    hwm_kib: Option<u64>,
}

fn current_memory_snapshot() -> MemorySnapshot {
    let status = match fs::read_to_string("/proc/self/status") {
        Ok(value) => value,
        Err(_) => {
            return MemorySnapshot {
                rss_kib: None,
                hwm_kib: None,
            };
        }
    };

    let mut rss_kib = None;
    let mut hwm_kib = None;
    for line in status.lines() {
        if rss_kib.is_none() {
            rss_kib = parse_status_kib(line, "VmRSS");
        }
        if hwm_kib.is_none() {
            hwm_kib = parse_status_kib(line, "VmHWM");
        }
    }

    MemorySnapshot { rss_kib, hwm_kib }
}

fn parse_status_kib(line: &str, key: &str) -> Option<u64> {
    let (line_key, remainder) = line.split_once(':')?;
    if line_key.trim() != key {
        return None;
    }
    remainder.split_whitespace().next()?.parse::<u64>().ok()
}

async fn benchmark_scenario(
    name: &'static str,
    config_toml: String,
    warmup_paths: &[String],
    measured_paths: &[String],
    concurrency: usize,
    expected_status: StatusCode,
) -> ScenarioReport {
    assert!(
        !measured_paths.is_empty(),
        "measured workload for `{name}` must not be empty"
    );

    let memory_before = current_memory_snapshot();

    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();
    let client = build_client();

    if !warmup_paths.is_empty() {
        let warmup_result = run_load(
            &client,
            proxy.listen_addr,
            warmup_paths,
            concurrency,
            expected_status,
        )
        .await;
        assert_eq!(
            warmup_result.error_count, 0,
            "warmup requests failed for `{name}`: {:?}",
            warmup_result.sample_errors
        );
        assert_eq!(
            warmup_result.success_count,
            warmup_paths.len(),
            "warmup request count mismatch for `{name}`"
        );
    }

    let run_result = run_load(
        &client,
        proxy.listen_addr,
        measured_paths,
        concurrency,
        expected_status,
    )
    .await;
    assert_eq!(
        run_result.error_count, 0,
        "measured requests failed for `{name}`: {:?}",
        run_result.sample_errors
    );
    assert_eq!(
        run_result.success_count,
        measured_paths.len(),
        "successful measured request count mismatch for `{name}`"
    );

    let admin_addr = proxy
        .admin_listen_addr
        .expect("admin_port=0 should start admin listener");
    let admin_stats = fetch_admin_stats(&client, admin_addr).await;
    let memory_after = current_memory_snapshot();

    proxy.shutdown().await;

    let latency = LatencyStats::from_nanos(&run_result.latency_nanos);
    let throughput_rps = if run_result.total_elapsed.is_zero() {
        0.0
    } else {
        run_result.success_count as f64 / run_result.total_elapsed.as_secs_f64()
    };
    let rss_delta_kib = match (memory_before.rss_kib, memory_after.rss_kib) {
        (Some(before), Some(after)) => Some(after as i64 - before as i64),
        _ => None,
    };

    ScenarioReport {
        name,
        request_count: measured_paths.len(),
        success_count: run_result.success_count,
        error_count: run_result.error_count,
        response_bytes_total: run_result.response_bytes_total,
        total_elapsed: run_result.total_elapsed,
        throughput_rps,
        latency,
        rss_before_kib: memory_before.rss_kib,
        rss_after_kib: memory_after.rss_kib,
        rss_delta_kib,
        hwm_after_kib: memory_after.hwm_kib,
        admin_stats,
    }
}

async fn run_load(
    client: &BenchClient,
    proxy_addr: SocketAddr,
    paths: &[String],
    concurrency: usize,
    expected_status: StatusCode,
) -> RunResult {
    let mut join_set = JoinSet::new();
    let mut next_path_index = 0usize;
    let max_in_flight = concurrency.max(1);

    let started = Instant::now();
    let mut success_count = 0usize;
    let mut error_count = 0usize;
    let mut response_bytes_total = 0usize;
    let mut latency_nanos = Vec::with_capacity(paths.len());
    let mut sample_errors = Vec::new();

    while next_path_index < paths.len() && join_set.len() < max_in_flight {
        spawn_request(
            &mut join_set,
            client.clone(),
            proxy_addr,
            paths[next_path_index].clone(),
        );
        next_path_index += 1;
    }

    while let Some(joined) = join_set.join_next().await {
        let outcome = joined.expect("benchmark request task panicked");
        let latency_ns = outcome.latency.as_nanos().min(u128::from(u64::MAX)) as u64;
        latency_nanos.push(latency_ns);
        response_bytes_total += outcome.response_bytes;

        match (outcome.status, outcome.error) {
            (Some(status), None) if status == expected_status => {
                success_count += 1;
            }
            (Some(status), None) => {
                error_count += 1;
                if sample_errors.len() < 5 {
                    sample_errors.push(format!(
                        "unexpected status {status} (expected {expected_status})"
                    ));
                }
            }
            (_, Some(error)) => {
                error_count += 1;
                if sample_errors.len() < 5 {
                    sample_errors.push(error);
                }
            }
            (None, None) => {
                error_count += 1;
                if sample_errors.len() < 5 {
                    sample_errors.push("missing status and missing error".to_owned());
                }
            }
        }

        if next_path_index < paths.len() {
            spawn_request(
                &mut join_set,
                client.clone(),
                proxy_addr,
                paths[next_path_index].clone(),
            );
            next_path_index += 1;
        }
    }

    RunResult {
        success_count,
        error_count,
        response_bytes_total,
        total_elapsed: started.elapsed(),
        latency_nanos,
        sample_errors,
    }
}

fn spawn_request(
    join_set: &mut JoinSet<RequestOutcome>,
    client: BenchClient,
    proxy_addr: SocketAddr,
    path: String,
) {
    join_set.spawn(async move {
        let request_uri: Uri = format!("http://{proxy_addr}{path}").parse().unwrap();
        let request = Request::builder()
            .method(Method::GET)
            .uri(request_uri)
            .body(Full::new(Bytes::new()))
            .unwrap();

        let request_started = Instant::now();
        match client.request(request).await {
            Ok(response) => {
                let status = response.status();
                match response.into_body().collect().await {
                    Ok(collected) => {
                        let body_len = collected.to_bytes().len();
                        RequestOutcome {
                            latency: request_started.elapsed(),
                            status: Some(status),
                            response_bytes: body_len,
                            error: None,
                        }
                    }
                    Err(error) => RequestOutcome {
                        latency: request_started.elapsed(),
                        status: Some(status),
                        response_bytes: 0,
                        error: Some(format!("response body read failed: {error}")),
                    },
                }
            }
            Err(error) => RequestOutcome {
                latency: request_started.elapsed(),
                status: None,
                response_bytes: 0,
                error: Some(format!("request failed: {error}")),
            },
        }
    });
}

async fn fetch_admin_stats(client: &BenchClient, admin_addr: SocketAddr) -> AdminStats {
    let status_uri: Uri = format!("http://{admin_addr}/_admin/status")
        .parse()
        .unwrap();
    let request = Request::builder()
        .method(Method::GET)
        .uri(status_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let response = client.request(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap();
    let stats = &body["stats"];

    AdminStats {
        cache_hits_total: stats["cache_hits_total"].as_u64().unwrap_or(0),
        cache_misses_total: stats["cache_misses_total"].as_u64().unwrap_or(0),
        upstream_requests_total: stats["upstream_requests_total"].as_u64().unwrap_or(0),
    }
}

fn build_client() -> BenchClient {
    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    Client::builder(TokioExecutor::new()).build(connector)
}

fn build_paths(prefix: &str, count: usize) -> Vec<String> {
    (0..count)
        .map(|request_id| {
            format!(
                "{prefix}/item?request_id={request_id}&bucket={}",
                request_id % 32
            )
        })
        .collect()
}

fn build_config_toml(
    storage_root: &Path,
    session: &str,
    upstream: &str,
    mode: &str,
    cache_miss: Option<&str>,
) -> String {
    let mut config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"
admin_port = 0

[storage]
path = "{}"
active_session = "{session}"

[[routes]]
path_prefix = "/api"
upstream = "{upstream}"
mode = "{mode}"
"#,
        storage_root.display(),
    );

    if let Some(cache_miss) = cache_miss {
        config_toml.push_str(&format!("cache_miss = \"{cache_miss}\"\n"));
    }

    config_toml
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

fn env_usize_nonzero(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn percentile_nanos(sorted: &[u64], percentile: u32) -> u64 {
    assert!(!sorted.is_empty(), "latency sample must not be empty");
    let len = sorted.len();
    let rank = (usize::try_from(percentile).unwrap() * len).div_ceil(100);
    let index = rank.saturating_sub(1).min(len - 1);
    sorted[index]
}

fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn display_opt_u64(value: Option<u64>) -> String {
    value
        .map(|inner| inner.to_string())
        .unwrap_or_else(|| "na".to_owned())
}

fn display_opt_i64(value: Option<i64>) -> String {
    value
        .map(|inner| inner.to_string())
        .unwrap_or_else(|| "na".to_owned())
}
