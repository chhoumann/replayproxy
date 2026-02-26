use std::{
    env, fs,
    net::SocketAddr,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::{Method, Request, StatusCode, Uri, body::Incoming};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use replayproxy::{ca::CaMaterialPaths, config::Config};
use rusqlite::Connection;
use serde_json::{Value, json};
use tempfile::tempdir;

const LIVE_TESTS_FLAG_ENV: &str = "REPLAYPROXY_LIVE_TESTS";
const LIVE_HTTP_ORIGIN_ENV: &str = "REPLAYPROXY_LIVE_HTTP_ORIGIN";
const LIVE_HTTPS_ORIGIN_ENV: &str = "REPLAYPROXY_LIVE_HTTPS_ORIGIN";
const LIVE_SECRET_ENV: &str = "REPLAYPROXY_LIVE_SECRET";

const DEFAULT_HTTP_ORIGIN: &str = "http://httpbingo.org";
const DEFAULT_HTTPS_ORIGIN: &str = "https://httpbingo.org";

#[tokio::test]
#[ignore = "opt-in live validation; set REPLAYPROXY_LIVE_TESTS=1 and run with --ignored"]
async fn live_reverse_proxy_record_replay_http() {
    require_live_tests_enabled();

    let http_origin = live_origin(LIVE_HTTP_ORIGIN_ENV, DEFAULT_HTTP_ORIGIN, "http");
    let upstream_host = origin_authority(&http_origin);
    let storage_dir = tempdir().unwrap();
    let session = "live-http";
    let nonce = unique_nonce();
    let request_path = format!("/anything?suite=live-reverse-http&nonce={nonce}");

    let record_proxy = replayproxy::proxy::serve(&reverse_config(
        storage_dir.path(),
        session,
        "record",
        &http_origin,
    ))
    .await
    .unwrap();

    let client = http_client();
    let record_res = send_request(
        &client,
        record_proxy.listen_addr,
        Method::GET,
        &request_path,
        &[("host", upstream_host.as_str())],
        Bytes::new(),
    )
    .await;
    let record_status = record_res.status();
    let record_body = response_body_bytes(record_res).await;

    record_proxy.shutdown().await;
    assert_recordings_count(storage_dir.path(), session, 1);

    let replay_proxy = replayproxy::proxy::serve(&reverse_config(
        storage_dir.path(),
        session,
        "replay",
        &http_origin,
    ))
    .await
    .unwrap();
    let admin_addr = replay_proxy
        .admin_listen_addr
        .expect("admin listener should be enabled");

    let replay_res = send_request(
        &client,
        replay_proxy.listen_addr,
        Method::GET,
        &request_path,
        &[("host", upstream_host.as_str())],
        Bytes::new(),
    )
    .await;
    let replay_status = replay_res.status();
    let replay_body = response_body_bytes(replay_res).await;
    assert_eq!(replay_status, record_status);
    assert_eq!(replay_body, record_body);

    let status = fetch_admin_status(&client, admin_addr).await;
    assert_eq!(status["stats"]["cache_hits_total"].as_u64(), Some(1));
    assert_eq!(status["stats"]["cache_misses_total"].as_u64(), Some(0));
    assert_eq!(status["stats"]["upstream_requests_total"].as_u64(), Some(0));

    replay_proxy.shutdown().await;
}

#[tokio::test]
#[ignore = "opt-in live validation; set REPLAYPROXY_LIVE_TESTS=1 and run with --ignored"]
async fn live_reverse_proxy_record_replay_https() {
    require_live_tests_enabled();

    let https_origin = live_origin(LIVE_HTTPS_ORIGIN_ENV, DEFAULT_HTTPS_ORIGIN, "https");
    let upstream_host = origin_authority(&https_origin);
    let storage_dir = tempdir().unwrap();
    let session = "live-https";
    let nonce = unique_nonce();
    let request_path = format!("/anything?suite=live-reverse-https&nonce={nonce}");

    let record_proxy = replayproxy::proxy::serve(&reverse_config(
        storage_dir.path(),
        session,
        "record",
        &https_origin,
    ))
    .await
    .unwrap();

    let client = http_client();
    let record_res = send_request(
        &client,
        record_proxy.listen_addr,
        Method::GET,
        &request_path,
        &[("host", upstream_host.as_str())],
        Bytes::new(),
    )
    .await;
    let record_status = record_res.status();
    let record_body = response_body_bytes(record_res).await;

    record_proxy.shutdown().await;
    assert_recordings_count(storage_dir.path(), session, 1);

    let replay_proxy = replayproxy::proxy::serve(&reverse_config(
        storage_dir.path(),
        session,
        "replay",
        &https_origin,
    ))
    .await
    .unwrap();
    let admin_addr = replay_proxy
        .admin_listen_addr
        .expect("admin listener should be enabled");

    let replay_res = send_request(
        &client,
        replay_proxy.listen_addr,
        Method::GET,
        &request_path,
        &[("host", upstream_host.as_str())],
        Bytes::new(),
    )
    .await;
    let replay_status = replay_res.status();
    let replay_body = response_body_bytes(replay_res).await;
    assert_eq!(replay_status, record_status);
    assert_eq!(replay_body, record_body);

    let status = fetch_admin_status(&client, admin_addr).await;
    assert_eq!(status["stats"]["cache_hits_total"].as_u64(), Some(1));
    assert_eq!(status["stats"]["cache_misses_total"].as_u64(), Some(0));
    assert_eq!(status["stats"]["upstream_requests_total"].as_u64(), Some(0));

    replay_proxy.shutdown().await;
}

#[tokio::test]
#[ignore = "opt-in live validation; set REPLAYPROXY_LIVE_TESTS=1 and run with --ignored"]
async fn live_forward_proxy_passthrough_cache_redacts_stored_payloads() {
    require_live_tests_enabled();

    let https_origin = live_origin(LIVE_HTTPS_ORIGIN_ENV, DEFAULT_HTTPS_ORIGIN, "https");
    let secret = env::var(LIVE_SECRET_ENV).unwrap_or_else(|_| "live-secret-token".to_owned());
    let storage_dir = tempdir().unwrap();
    let ca_dir = tempdir().unwrap();
    let ca_paths = replayproxy::ca::generate_ca(ca_dir.path(), false).unwrap();
    let session = "live-forward";
    let nonce = unique_nonce();
    let url = format!("{https_origin}/anything?suite=live-forward-cache&nonce={nonce}");

    let proxy = replayproxy::proxy::serve(&forward_cache_config(
        storage_dir.path(),
        session,
        &ca_paths,
    ))
    .await
    .unwrap();
    let admin_addr = proxy
        .admin_listen_addr
        .expect("admin listener should be enabled");
    let admin_client = http_client();
    let ca_cert_pem = fs::read(&ca_paths.cert_path).unwrap();

    let first_response = send_forward_post(
        proxy.listen_addr,
        &ca_cert_pem,
        &url,
        &secret,
        json!({
            "token": secret.clone(),
            "message": "live-forward"
        }),
    )
    .await;
    assert_ne!(first_response.0, StatusCode::BAD_GATEWAY);

    let status_after_first = fetch_admin_status(&admin_client, admin_addr).await;
    assert_eq!(
        status_after_first["stats"]["cache_hits_total"].as_u64(),
        Some(0)
    );
    assert_eq!(
        status_after_first["stats"]["cache_misses_total"].as_u64(),
        Some(1)
    );
    let upstream_after_first = status_after_first["stats"]["upstream_requests_total"]
        .as_u64()
        .unwrap();
    assert_eq!(upstream_after_first, 1);

    let second_response = send_forward_post(
        proxy.listen_addr,
        &ca_cert_pem,
        &url,
        &secret,
        json!({
            "token": secret.clone(),
            "message": "live-forward"
        }),
    )
    .await;
    assert_eq!(second_response.0, first_response.0);
    assert_eq!(second_response.1, first_response.1);

    let status_after_second = fetch_admin_status(&admin_client, admin_addr).await;
    assert_eq!(
        status_after_second["stats"]["cache_hits_total"].as_u64(),
        Some(1)
    );
    assert_eq!(
        status_after_second["stats"]["cache_misses_total"].as_u64(),
        Some(1)
    );
    assert_eq!(
        status_after_second["stats"]["upstream_requests_total"].as_u64(),
        Some(upstream_after_first)
    );

    assert_recordings_count(storage_dir.path(), session, 1);
    assert_stored_payload_redacted(storage_dir.path(), session, &secret);

    proxy.shutdown().await;
}

fn require_live_tests_enabled() {
    if live_tests_enabled() {
        return;
    }
    panic!(
        "live tests are opt-in: set {LIVE_TESTS_FLAG_ENV}=1 and rerun with `cargo test --test live_api_validation -- --ignored`"
    );
}

fn live_tests_enabled() -> bool {
    env::var(LIVE_TESTS_FLAG_ENV)
        .ok()
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            normalized == "1" || normalized == "true" || normalized == "yes"
        })
        .unwrap_or(false)
}

fn live_origin(env_var: &str, default: &str, expected_scheme: &str) -> String {
    let value = env::var(env_var).unwrap_or_else(|_| default.to_owned());
    let trimmed = value.trim().trim_end_matches('/').to_owned();
    assert!(
        trimmed.starts_with(&format!("{expected_scheme}://")),
        "{env_var} must use {expected_scheme}:// (got `{trimmed}`)"
    );
    trimmed
}

fn origin_authority(origin: &str) -> String {
    let uri: Uri = origin.parse().unwrap();
    uri.authority().unwrap().to_string()
}

fn reverse_config(storage_dir: &Path, session: &str, mode: &str, upstream: &str) -> Config {
    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"
admin_port = 0
mode = "{mode}"

[storage]
path = "{}"
active_session = "{session}"

[[routes]]
path_prefix = "/"
upstream = "{upstream}"
"#,
        storage_dir.display()
    );
    Config::from_toml_str(&config_toml).unwrap()
}

fn forward_cache_config(storage_dir: &Path, session: &str, ca_paths: &CaMaterialPaths) -> Config {
    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"
admin_port = 0
mode = "passthrough-cache"

[proxy.tls]
enabled = true
ca_cert = "{}"
ca_key = "{}"

[storage]
path = "{}"
active_session = "{session}"

[[routes]]
path_prefix = "/"
mode = "passthrough-cache"
cache_miss = "forward"

[routes.redact]
headers = ["authorization"]
body_json = ["$.token", "$.data", "$.json.token"]
"#,
        ca_paths.cert_path.display(),
        ca_paths.key_path.display(),
        storage_dir.display()
    );
    Config::from_toml_str(&config_toml).unwrap()
}

fn http_client() -> Client<HttpConnector, Full<Bytes>> {
    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    Client::builder(TokioExecutor::new()).build(connector)
}

async fn send_request(
    client: &Client<HttpConnector, Full<Bytes>>,
    listen_addr: SocketAddr,
    method: Method,
    path_and_query: &str,
    headers: &[(&str, &str)],
    body: Bytes,
) -> hyper::Response<Incoming> {
    let uri: Uri = format!("http://{listen_addr}{path_and_query}")
        .parse()
        .unwrap();
    let mut request_builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        request_builder = request_builder.header(*name, *value);
    }
    let request = request_builder.body(Full::new(body)).unwrap();
    client.request(request).await.unwrap()
}

async fn response_body_bytes(response: hyper::Response<Incoming>) -> Bytes {
    response.into_body().collect().await.unwrap().to_bytes()
}

async fn response_body_json(response: hyper::Response<Incoming>) -> Value {
    serde_json::from_slice(&response_body_bytes(response).await).unwrap()
}

async fn fetch_admin_status(
    client: &Client<HttpConnector, Full<Bytes>>,
    admin_addr: SocketAddr,
) -> Value {
    let response = send_request(
        client,
        admin_addr,
        Method::GET,
        "/_admin/status",
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    response_body_json(response).await
}

fn unique_nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

fn assert_recordings_count(storage_dir: &Path, session: &str, expected: i64) {
    let db_path = storage_dir.join(session).join("recordings.db");
    let conn = Connection::open(db_path).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM recordings;", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, expected);
}

async fn send_forward_post(
    proxy_addr: SocketAddr,
    ca_cert_pem: &[u8],
    url: &str,
    secret: &str,
    request_json: Value,
) -> (StatusCode, Bytes) {
    let ca_cert_pem = ca_cert_pem.to_vec();
    let url = url.to_owned();
    let auth_header = format!("Bearer {secret}");
    tokio::task::spawn_blocking(move || -> (StatusCode, Bytes) {
        let cert = reqwest::Certificate::from_pem(&ca_cert_pem).unwrap();
        let proxy = reqwest::Proxy::all(format!("http://{proxy_addr}")).unwrap();
        let client = reqwest::blocking::Client::builder()
            .proxy(proxy)
            .add_root_certificate(cert)
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap();
        let response = client
            .post(url)
            .header(reqwest::header::AUTHORIZATION, auth_header)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(&request_json).unwrap())
            .send()
            .unwrap();
        let status = StatusCode::from_u16(response.status().as_u16()).unwrap();
        let body_bytes = response.bytes().unwrap();
        (status, body_bytes)
    })
    .await
    .unwrap()
}

fn assert_stored_payload_redacted(storage_dir: &Path, session: &str, secret: &str) {
    let db_path = storage_dir.join(session).join("recordings.db");
    let conn = Connection::open(db_path).unwrap();

    let (request_headers_json, request_body, response_body): (String, Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT request_headers_json, request_body, response_body FROM recordings ORDER BY id DESC LIMIT 1;",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();

    let request_headers: Vec<(String, Vec<u8>)> =
        serde_json::from_str(&request_headers_json).unwrap();
    assert_eq!(
        request_headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.as_slice()),
        Some(b"[REDACTED]".as_slice())
    );

    let stored_request_json: Value = serde_json::from_slice(&request_body).unwrap();
    assert_eq!(
        stored_request_json
            .pointer("/token")
            .and_then(Value::as_str),
        Some("[REDACTED]")
    );

    if let Ok(stored_response_json) = serde_json::from_slice::<Value>(&response_body) {
        if stored_response_json.pointer("/data").is_some() {
            assert_eq!(
                stored_response_json
                    .pointer("/data")
                    .and_then(Value::as_str),
                Some("[REDACTED]")
            );
        }
        if stored_response_json.pointer("/json/token").is_some() {
            assert_eq!(
                stored_response_json
                    .pointer("/json/token")
                    .and_then(Value::as_str),
                Some("[REDACTED]")
            );
        }
    }

    let secret_header = format!("Bearer {secret}");
    assert!(!request_headers_json.contains(&secret_header));
    assert!(!String::from_utf8_lossy(&request_body).contains(secret));
    assert!(!String::from_utf8_lossy(&response_body).contains(secret));
}
