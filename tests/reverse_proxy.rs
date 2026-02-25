use std::{
    collections::VecDeque,
    convert::Infallible,
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::{
    Method, Request, Response, StatusCode, Uri,
    body::{Frame, Incoming},
    header::{self, HeaderValue},
    service::service_fn,
};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as ConnectionBuilder,
};
use replayproxy::storage::{Recording, Storage};
use rusqlite::Connection;
use serde_json::Value;
use tokio::{net::TcpListener, sync::mpsc, time::timeout};

const BINARY_HEADER_VALUE: &[u8] = b"\x80\xffok";
const ADMIN_API_TOKEN_HEADER: &str = "x-replayproxy-admin-token";

#[derive(Debug)]
struct CapturedRequest {
    uri: Uri,
    headers: hyper::HeaderMap,
    body: Bytes,
}

#[derive(Debug)]
struct ChunkedBody {
    chunks: VecDeque<Bytes>,
}

impl ChunkedBody {
    fn from_slices(chunks: &[&[u8]]) -> Self {
        Self {
            chunks: chunks
                .iter()
                .map(|chunk| Bytes::copy_from_slice(chunk))
                .collect(),
        }
    }

    fn new(chunks: Vec<Bytes>) -> Self {
        Self {
            chunks: chunks.into(),
        }
    }
}

impl hyper::body::Body for ChunkedBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.chunks.pop_front().map(|chunk| Ok(Frame::data(chunk))))
    }
}

#[tokio::test]
async fn reverse_proxy_forwards_request_and_strips_hop_by_hop_headers() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;

    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
"#
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let proxy_uri: Uri = format!("http://{}/api/hello?x=1", proxy.listen_addr)
        .parse()
        .unwrap();
    let mut req = Request::builder()
        .method(Method::GET)
        .uri(proxy_uri)
        .header(header::CONNECTION, "x-hop")
        .header("x-hop", "secret")
        .header("x-end", "kept")
        .body(Full::new(Bytes::new()))
        .unwrap();
    req.headers_mut()
        .insert(header::HOST, HeaderValue::from_static("proxy.invalid"));

    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    assert_eq!(
        res.headers().get("x-resp-end").unwrap(),
        &HeaderValue::from_static("ok")
    );
    assert!(res.headers().get("x-resp-hop").is_none());
    assert!(res.headers().get(header::CONNECTION).is_none());
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], b"upstream-body");

    let captured = upstream_rx.recv().await.unwrap();
    assert_eq!(captured.uri.path(), "/api/hello");
    assert_eq!(captured.uri.query(), Some("x=1"));
    assert_eq!(
        captured.headers.get("x-end").unwrap(),
        &HeaderValue::from_static("kept")
    );
    assert!(captured.headers.get("x-hop").is_none());
    assert!(captured.headers.get(header::CONNECTION).is_none());
    assert_eq!(&captured.body[..], b"");

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[tokio::test]
async fn oversized_request_body_returns_413_without_hitting_upstream() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;

    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"
max_body_bytes = 8

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "record"
"#
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let proxy_uri: Uri = format!("http://{}/api/hello", proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri(proxy_uri)
        .body(Full::new(Bytes::from_static(b"body-too-large")))
        .unwrap();
    let res = client.request(req).await.unwrap();

    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        &body_bytes[..],
        b"request body exceeds configured proxy.max_body_bytes"
    );
    assert!(
        timeout(Duration::from_millis(150), upstream_rx.recv())
            .await
            .is_err(),
        "upstream should not receive oversized requests"
    );

    proxy.shutdown().await;
    let join = upstream_shutdown();
    join.abort();
    let _ = join.await;
}

#[tokio::test]
async fn oversized_request_body_can_bypass_cache_per_route() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;

    let storage_dir = tempfile::tempdir().unwrap();
    let session = "default";
    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"
max_body_bytes = 8

[storage]
path = "{}"
active_session = "{session}"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "passthrough-cache"
body_oversize = "bypass-cache"
"#,
        storage_dir.path().display()
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let proxy_uri: Uri = format!("http://{}/api/hello", proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri(proxy_uri)
        .body(Full::new(Bytes::from_static(b"request-body-is-too-large")))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], b"upstream-body");

    let captured = upstream_rx.recv().await.unwrap();
    assert_eq!(&captured.body[..], b"request-body-is-too-large");

    let db_path = storage_dir.path().join(session).join("recordings.db");
    let conn = Connection::open(db_path).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM recordings;", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[tokio::test]
async fn oversized_chunked_request_body_can_bypass_cache_per_route() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;

    let storage_dir = tempfile::tempdir().unwrap();
    let session = "default";
    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"
max_body_bytes = 8

[storage]
path = "{}"
active_session = "{session}"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "passthrough-cache"
body_oversize = "bypass-cache"
"#,
        storage_dir.path().display()
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, ChunkedBody> =
        Client::builder(TokioExecutor::new()).build(connector);

    let proxy_uri: Uri = format!("http://{}/api/hello", proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri(proxy_uri)
        .body(ChunkedBody::from_slices(&[b"12345", b"67890"]))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], b"upstream-body");

    let captured = upstream_rx.recv().await.unwrap();
    assert_eq!(&captured.body[..], b"1234567890");

    let db_path = storage_dir.path().join(session).join("recordings.db");
    let conn = Connection::open(db_path).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM recordings;", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[tokio::test]
async fn oversized_chunked_request_body_replay_mode_still_returns_413() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;

    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"
max_body_bytes = 8

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "replay"
cache_miss = "forward"
body_oversize = "bypass-cache"
"#
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, ChunkedBody> =
        Client::builder(TokioExecutor::new()).build(connector);

    let proxy_uri: Uri = format!("http://{}/api/hello", proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri(proxy_uri)
        .body(ChunkedBody::from_slices(&[b"12345", b"67890"]))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        &body_bytes[..],
        b"request body exceeds configured proxy.max_body_bytes"
    );
    assert!(
        timeout(Duration::from_millis(150), upstream_rx.recv())
            .await
            .is_err(),
        "upstream should not receive oversized replay-mode requests"
    );

    proxy.shutdown().await;
    let join = upstream_shutdown();
    join.abort();
    let _ = join.await;
}

#[tokio::test]
async fn oversized_response_body_returns_502_without_recording() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;

    let storage_dir = tempfile::tempdir().unwrap();
    let session = "default";
    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"
max_body_bytes = 4

[storage]
path = "{}"
active_session = "{session}"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "record"
"#,
        storage_dir.path().display()
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let proxy_uri: Uri = format!("http://{}/api/hello", proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(proxy_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        &body_bytes[..],
        b"upstream response body exceeds configured proxy.max_body_bytes"
    );

    let _captured = upstream_rx.recv().await.unwrap();

    let db_path = storage_dir.path().join(session).join("recordings.db");
    let conn = Connection::open(db_path).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM recordings;", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[tokio::test]
async fn oversized_response_body_can_bypass_cache_per_route() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;

    let storage_dir = tempfile::tempdir().unwrap();
    let session = "default";
    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"
max_body_bytes = 4

[storage]
path = "{}"
active_session = "{session}"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "passthrough-cache"
body_oversize = "bypass-cache"
"#,
        storage_dir.path().display()
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let proxy_uri: Uri = format!("http://{}/api/hello", proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(proxy_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], b"upstream-body");

    let _captured = upstream_rx.recv().await.unwrap();

    let db_path = storage_dir.path().join(session).join("recordings.db");
    let conn = Connection::open(db_path).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM recordings;", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[tokio::test]
async fn oversized_chunked_response_body_can_bypass_cache_per_route() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) =
        spawn_upstream_with_response_chunks(vec![
            Bytes::from_static(b"abc"),
            Bytes::from_static(b"def"),
        ])
        .await;

    let storage_dir = tempfile::tempdir().unwrap();
    let session = "default";
    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"
max_body_bytes = 4

[storage]
path = "{}"
active_session = "{session}"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "passthrough-cache"
body_oversize = "bypass-cache"
"#,
        storage_dir.path().display()
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let proxy_uri: Uri = format!("http://{}/api/hello", proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(proxy_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], b"abcdef");

    let _captured = upstream_rx.recv().await.unwrap();

    let db_path = storage_dir.path().join(session).join("recordings.db");
    let conn = Connection::open(db_path).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM recordings;", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[tokio::test]
async fn serve_starts_admin_listener_when_configured() {
    let config = replayproxy::config::Config::from_toml_str(
        r#"
[proxy]
listen = "127.0.0.1:0"
admin_port = 0
"#,
    )
    .unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();
    let admin_addr = proxy
        .admin_listen_addr
        .expect("admin listener should be started");

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let uri: Uri = format!("http://{admin_addr}/_admin/status")
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Full::new(Bytes::new()))
        .unwrap();

    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert!(
        body.get("uptime_ms")
            .and_then(|value| value.as_u64())
            .is_some()
    );
    assert_eq!(body["active_session"].as_str(), Some("default"));
    assert_eq!(body["routes_configured"].as_u64(), Some(0));
    assert_eq!(body["stats"]["admin_requests_total"].as_u64(), Some(1));
    assert_eq!(body["stats"]["proxy_requests_total"].as_u64(), Some(0));

    proxy.shutdown().await;
}

#[tokio::test]
async fn serve_binds_admin_listener_to_loopback_by_default() {
    let config = replayproxy::config::Config::from_toml_str(
        r#"
[proxy]
listen = "0.0.0.0:0"
admin_port = 0
"#,
    )
    .unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();
    let admin_addr = proxy
        .admin_listen_addr
        .expect("admin listener should be started");
    assert_eq!(admin_addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    proxy.shutdown().await;
}

#[tokio::test]
async fn serve_uses_explicit_admin_bind_when_configured() {
    let config = replayproxy::config::Config::from_toml_str(
        r#"
[proxy]
listen = "127.0.0.1:0"
admin_port = 0
admin_bind = "0.0.0.0"
"#,
    )
    .unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();
    let admin_addr = proxy
        .admin_listen_addr
        .expect("admin listener should be started");
    assert!(admin_addr.ip().is_unspecified());
    proxy.shutdown().await;
}

#[tokio::test]
async fn admin_api_token_requires_matching_header() {
    let config = replayproxy::config::Config::from_toml_str(
        r#"
[proxy]
listen = "127.0.0.1:0"
admin_port = 0
admin_api_token = "super-secret"

[metrics]
enabled = true
"#,
    )
    .unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();
    let admin_addr = proxy
        .admin_listen_addr
        .expect("admin listener should be started");

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let status_uri: Uri = format!("http://{admin_addr}/_admin/status")
        .parse()
        .unwrap();

    let unauth_req = Request::builder()
        .method(Method::GET)
        .uri(status_uri.clone())
        .body(Full::new(Bytes::new()))
        .unwrap();
    let unauth_res = client.request(unauth_req).await.unwrap();
    assert_eq!(unauth_res.status(), StatusCode::UNAUTHORIZED);
    let unauth_body = response_json(unauth_res).await;
    assert!(
        unauth_body["error"]
            .as_str()
            .is_some_and(|error| error.contains(ADMIN_API_TOKEN_HEADER))
    );

    let wrong_token_req = Request::builder()
        .method(Method::GET)
        .uri(status_uri.clone())
        .header(ADMIN_API_TOKEN_HEADER, "wrong")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let wrong_token_res = client.request(wrong_token_req).await.unwrap();
    assert_eq!(wrong_token_res.status(), StatusCode::UNAUTHORIZED);

    let ok_req = Request::builder()
        .method(Method::GET)
        .uri(status_uri)
        .header(ADMIN_API_TOKEN_HEADER, "super-secret")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let ok_res = client.request(ok_req).await.unwrap();
    assert_eq!(ok_res.status(), StatusCode::OK);

    let metrics_uri: Uri = format!("http://{admin_addr}/metrics").parse().unwrap();
    let metrics_req = Request::builder()
        .method(Method::GET)
        .uri(metrics_uri)
        .header(ADMIN_API_TOKEN_HEADER, "super-secret")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let metrics_res = client.request(metrics_req).await.unwrap();
    assert_eq!(metrics_res.status(), StatusCode::OK);

    proxy.shutdown().await;
}

#[tokio::test]
async fn admin_status_reports_proxy_request_counters() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;

    let storage_dir = tempfile::tempdir().unwrap();
    let session = "status-session";
    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"
admin_port = 0

[storage]
path = "{}"
active_session = "{session}"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "passthrough-cache"
"#,
        storage_dir.path().display()
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();
    let admin_addr = proxy
        .admin_listen_addr
        .expect("admin listener should be started");

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let proxy_uri: Uri = format!("http://{}/api/hello?x=1", proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(proxy_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], b"upstream-body");
    let _captured = upstream_rx.recv().await.unwrap();

    let status_uri: Uri = format!("http://{admin_addr}/_admin/status")
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(status_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body["active_session"].as_str(), Some(session));
    assert_eq!(body["routes_configured"].as_u64(), Some(1));
    assert_eq!(body["stats"]["proxy_requests_total"].as_u64(), Some(1));
    assert_eq!(body["stats"]["admin_requests_total"].as_u64(), Some(1));
    assert_eq!(body["stats"]["cache_hits_total"].as_u64(), Some(0));
    assert_eq!(body["stats"]["cache_misses_total"].as_u64(), Some(1));
    assert_eq!(body["stats"]["upstream_requests_total"].as_u64(), Some(1));

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[tokio::test]
async fn admin_config_reload_endpoint_applies_config_updates() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;
    let config_dir = tempfile::tempdir().unwrap();
    let config_path = config_dir.path().join("replayproxy.toml");
    let config_source = config_path.display().to_string();

    fs::write(
        &config_path,
        format!(
            r#"
[proxy]
listen = "127.0.0.1:0"
admin_port = 0
max_body_bytes = 64

[[routes]]
path_prefix = "/v1"
upstream = "http://{upstream_addr}"
"#
        ),
    )
    .unwrap();

    let config = replayproxy::config::Config::from_path(&config_path).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();
    let admin_addr = proxy
        .admin_listen_addr
        .expect("admin listener should be started");

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    fs::write(
        &config_path,
        format!(
            r#"
[proxy]
listen = "127.0.0.1:0"
admin_port = 0
max_body_bytes = 128

[[routes]]
path_prefix = "/v2"
upstream = "http://{upstream_addr}"
"#
        ),
    )
    .unwrap();

    let reload_uri: Uri = format!("http://{admin_addr}/_admin/config/reload")
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri(reload_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = response_json(res).await;
    assert_eq!(body["source"].as_str(), Some(config_source.as_str()));
    assert_eq!(body["routes_before"].as_u64(), Some(1));
    assert_eq!(body["routes_after"].as_u64(), Some(1));
    assert_eq!(body["max_body_bytes_before"].as_u64(), Some(64));
    assert_eq!(body["max_body_bytes_after"].as_u64(), Some(128));
    assert_eq!(body["changed"].as_bool(), Some(true));

    let stale_route_uri: Uri = format!("http://{}/v1/after-reload", proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(stale_route_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let _ = res.into_body().collect().await.unwrap().to_bytes();
    assert!(
        timeout(Duration::from_millis(100), upstream_rx.recv())
            .await
            .is_err()
    );

    let reloaded_route_uri: Uri = format!("http://{}/v2/after-reload", proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(reloaded_route_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let _ = res.into_body().collect().await.unwrap().to_bytes();
    let captured = upstream_rx.recv().await.unwrap();
    assert_eq!(captured.uri.path(), "/v2/after-reload");

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[tokio::test]
async fn admin_config_reload_endpoint_returns_errors_for_unavailable_and_invalid_config() {
    let config = replayproxy::config::Config::from_toml_str(
        r#"
[proxy]
listen = "127.0.0.1:0"
admin_port = 0
"#,
    )
    .unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();
    let admin_addr = proxy
        .admin_listen_addr
        .expect("admin listener should be started");

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let reload_uri: Uri = format!("http://{admin_addr}/_admin/config/reload")
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri(reload_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT);
    let body = response_json(res).await;
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("config reload unavailable")
    );
    proxy.shutdown().await;

    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;
    let config_dir = tempfile::tempdir().unwrap();
    let config_path = config_dir.path().join("replayproxy.toml");
    fs::write(
        &config_path,
        format!(
            r#"
[proxy]
listen = "127.0.0.1:0"
admin_port = 0

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
"#
        ),
    )
    .unwrap();

    let config = replayproxy::config::Config::from_path(&config_path).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();
    let admin_addr = proxy
        .admin_listen_addr
        .expect("admin listener should be started");

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    fs::write(
        &config_path,
        r#"
[proxy
listen = "127.0.0.1:0"
"#,
    )
    .unwrap();

    let reload_uri: Uri = format!("http://{admin_addr}/_admin/config/reload")
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri(reload_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body = response_json(res).await;
    assert!(body["error"].as_str().unwrap().contains("parse config"));

    let proxy_uri: Uri = format!("http://{}/api/still-active", proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(proxy_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let _ = res.into_body().collect().await.unwrap().to_bytes();
    let _captured = upstream_rx.recv().await.unwrap();

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[tokio::test]
async fn metrics_endpoint_returns_prometheus_text_when_enabled() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;
    let storage_dir = tempfile::tempdir().unwrap();
    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"
admin_port = 0

[metrics]
enabled = true

[storage]
path = "{}"
active_session = "default"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "record"
"#,
        storage_dir.path().display()
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();
    let admin_addr = proxy
        .admin_listen_addr
        .expect("admin listener should be started");

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let proxy_uri: Uri = format!("http://{}/api/metrics", proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(proxy_uri)
        .header(header::CONNECTION, "close")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let _ = res.into_body().collect().await.unwrap().to_bytes();
    let _captured = upstream_rx.recv().await.unwrap();

    let metrics_uri: Uri = format!("http://{admin_addr}/metrics").parse().unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(metrics_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/plain; version=0.0.4; charset=utf-8")
    );

    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert!(body.contains("# HELP replayproxy_uptime_seconds"));
    assert!(body.contains("# TYPE replayproxy_requests_total counter"));
    assert!(
        body.contains(
            "replayproxy_requests_total{mode=\"record\",method=\"GET\",status=\"201\"} 1"
        )
    );
    assert!(body.contains("# TYPE replayproxy_upstream_duration_seconds histogram"));
    assert!(body.contains("replayproxy_upstream_duration_seconds_count 1"));
    assert!(body.contains("# TYPE replayproxy_replay_duration_seconds histogram"));
    assert!(body.contains("replayproxy_replay_duration_seconds_count 0"));
    assert!(body.contains("# TYPE replayproxy_active_connections gauge"));
    assert!(body.contains("# TYPE replayproxy_recordings_total gauge"));
    assert!(body.contains("replayproxy_recordings_total{session=\"default\"} 1"));
    assert!(body.contains("replayproxy_admin_requests_total 1"));

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[tokio::test]
async fn metrics_endpoint_reports_replay_duration_for_replay_lookup_miss() {
    let storage_dir = tempfile::tempdir().unwrap();
    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"
admin_port = 0

[metrics]
enabled = true

[storage]
path = "{}"
active_session = "default"

[[routes]]
path_prefix = "/api"
upstream = "http://127.0.0.1:9"
mode = "replay"
cache_miss = "error"
"#,
        storage_dir.path().display()
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();
    let admin_addr = proxy
        .admin_listen_addr
        .expect("admin listener should be started");

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let proxy_uri: Uri = format!("http://{}/api/miss", proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(proxy_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
    let _ = res.into_body().collect().await.unwrap().to_bytes();

    let metrics_uri: Uri = format!("http://{admin_addr}/metrics").parse().unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(metrics_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert!(
        body.contains(
            "replayproxy_requests_total{mode=\"replay\",method=\"GET\",status=\"502\"} 1"
        )
    );
    assert!(body.contains("replayproxy_replay_duration_seconds_count 1"));
    assert!(body.contains("replayproxy_upstream_duration_seconds_count 0"));
    assert!(body.contains("replayproxy_cache_misses_total 1"));

    proxy.shutdown().await;
}

#[tokio::test]
async fn metrics_endpoint_returns_not_found_when_disabled() {
    let config = replayproxy::config::Config::from_toml_str(
        r#"
[proxy]
listen = "127.0.0.1:0"
admin_port = 0
"#,
    )
    .unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();
    let admin_addr = proxy
        .admin_listen_addr
        .expect("admin listener should be started");

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let metrics_uri: Uri = format!("http://{admin_addr}/metrics").parse().unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(metrics_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    proxy.shutdown().await;
}

#[tokio::test]
async fn admin_sessions_crud_endpoints_manage_sessions() {
    let storage_dir = tempfile::tempdir().unwrap();
    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"
admin_port = 0

[storage]
path = "{}"
active_session = "default"
"#,
        storage_dir.path().display()
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();
    let admin_addr = proxy
        .admin_listen_addr
        .expect("admin listener should be started");

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let list_uri: Uri = format!("http://{admin_addr}/_admin/sessions")
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(list_uri.clone())
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = response_json(res).await;
    assert_eq!(body["active_session"].as_str(), Some("default"));
    let sessions = body["sessions"].as_array().unwrap();
    assert!(
        sessions
            .iter()
            .any(|value| value.as_str() == Some("default"))
    );

    let req = Request::builder()
        .method(Method::POST)
        .uri(list_uri.clone())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from_static(br#"{"name":"staging"}"#)))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body = response_json(res).await;
    assert_eq!(body["name"].as_str(), Some("staging"));
    assert!(
        storage_dir
            .path()
            .join("staging")
            .join("recordings.db")
            .exists()
    );

    let req = Request::builder()
        .method(Method::GET)
        .uri(list_uri.clone())
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = response_json(res).await;
    let sessions = body["sessions"].as_array().unwrap();
    assert!(
        sessions
            .iter()
            .any(|value| value.as_str() == Some("staging"))
    );

    let delete_uri: Uri = format!("http://{admin_addr}/_admin/sessions/staging")
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::DELETE)
        .uri(delete_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert!(!storage_dir.path().join("staging").exists());

    proxy.shutdown().await;
}

#[tokio::test]
async fn admin_sessions_endpoints_return_informative_errors() {
    let storage_dir = tempfile::tempdir().unwrap();
    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"
admin_port = 0

[storage]
path = "{}"
active_session = "default"
"#,
        storage_dir.path().display()
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();
    let admin_addr = proxy
        .admin_listen_addr
        .expect("admin listener should be started");

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let list_uri: Uri = format!("http://{admin_addr}/_admin/sessions")
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri(list_uri.clone())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from_static(b"not-json")))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body = response_json(res).await;
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("invalid JSON body")
    );

    let req = Request::builder()
        .method(Method::POST)
        .uri(list_uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from_static(br#"{"name":"default"}"#)))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT);
    let body = response_json(res).await;
    assert!(body["error"].as_str().unwrap().contains("already exists"));

    let delete_active_uri: Uri = format!("http://{admin_addr}/_admin/sessions/default")
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::DELETE)
        .uri(delete_active_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT);
    let body = response_json(res).await;
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("cannot delete active session")
    );

    let delete_missing_uri: Uri = format!("http://{admin_addr}/_admin/sessions/missing")
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::DELETE)
        .uri(delete_missing_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let body = response_json(res).await;
    assert!(body["error"].as_str().unwrap().contains("was not found"));

    proxy.shutdown().await;
}

#[tokio::test]
async fn admin_session_export_endpoint_exports_recordings_and_returns_json_result() {
    let storage_dir = tempfile::tempdir().unwrap();
    let session_name = "default";
    let session_db_path =
        replayproxy::session::resolve_session_db_path(storage_dir.path(), session_name).unwrap();
    let storage = Storage::open(session_db_path).unwrap();
    storage
        .insert_recording(Recording {
            match_key: "export-key".to_owned(),
            request_method: "POST".to_owned(),
            request_uri: "/v1/chat/completions?model=gpt-4o-mini".to_owned(),
            request_headers: vec![("authorization".to_owned(), b"[REDACTED]".to_vec())],
            request_body: br#"{"prompt":"hello"}"#.to_vec(),
            response_status: 200,
            response_headers: vec![("content-type".to_owned(), b"application/json".to_vec())],
            response_body: br#"{"ok":true}"#.to_vec(),
            created_at_unix_ms: 42,
        })
        .await
        .unwrap();

    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"
admin_port = 0

[storage]
path = "{}"
active_session = "{session_name}"
"#,
        storage_dir.path().display()
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();
    let admin_addr = proxy
        .admin_listen_addr
        .expect("admin listener should be started");

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let export_dir = tempfile::tempdir().unwrap();
    let output_dir = export_dir.path().join("session-export");
    let export_uri: Uri = format!("http://{admin_addr}/_admin/sessions/{session_name}/export")
        .parse()
        .unwrap();
    let export_payload = serde_json::json!({
        "out_dir": output_dir.to_string_lossy(),
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri(export_uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(
            serde_json::to_vec(&export_payload).unwrap(),
        )))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = response_json(res).await;
    assert_eq!(body["status"].as_str(), Some("completed"));
    assert_eq!(body["session"].as_str(), Some(session_name));
    assert_eq!(body["recordings_exported"].as_u64(), Some(1));
    assert_eq!(body["format"].as_str(), Some("json"));
    assert_eq!(
        body["output_dir"].as_str().map(std::path::PathBuf::from),
        Some(output_dir.clone())
    );

    let manifest_path = body["manifest_path"].as_str().map(std::path::PathBuf::from);
    assert_eq!(manifest_path, Some(output_dir.join("index.json")));
    assert!(manifest_path.as_ref().unwrap().exists());

    let manifest_bytes = fs::read(manifest_path.unwrap()).unwrap();
    let manifest: Value = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(manifest["session"].as_str(), Some(session_name));
    assert_eq!(manifest["recordings"].as_array().map(Vec::len), Some(1));

    let recordings = fs::read_dir(output_dir.join("recordings"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(recordings.len(), 1);

    let missing_export_uri: Uri = format!("http://{admin_addr}/_admin/sessions/missing/export")
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri(missing_export_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let body = response_json(res).await;
    assert!(body["error"].as_str().unwrap().contains("was not found"));

    proxy.shutdown().await;
}

#[tokio::test]
async fn admin_session_import_endpoint_imports_recordings_and_updates_active_stats() {
    let storage_dir = tempfile::tempdir().unwrap();
    let session_name = "default";
    let session_db_path =
        replayproxy::session::resolve_session_db_path(storage_dir.path(), session_name).unwrap();
    let storage = Storage::open(session_db_path).unwrap();
    storage
        .insert_recording(Recording {
            match_key: "import-key".to_owned(),
            request_method: "GET".to_owned(),
            request_uri: "/v1/models".to_owned(),
            request_headers: vec![("authorization".to_owned(), b"[REDACTED]".to_vec())],
            request_body: Vec::new(),
            response_status: 200,
            response_headers: vec![("content-type".to_owned(), b"application/json".to_vec())],
            response_body: br#"{"ok":true}"#.to_vec(),
            created_at_unix_ms: 42,
        })
        .await
        .unwrap();

    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"
admin_port = 0

[storage]
path = "{}"
active_session = "{session_name}"
"#,
        storage_dir.path().display()
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();
    let admin_addr = proxy
        .admin_listen_addr
        .expect("admin listener should be started");

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let export_dir = tempfile::tempdir().unwrap();
    let output_dir = export_dir.path().join("session-export");
    let export_uri: Uri = format!("http://{admin_addr}/_admin/sessions/{session_name}/export")
        .parse()
        .unwrap();
    let export_payload = serde_json::json!({
        "out_dir": output_dir.to_string_lossy(),
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri(export_uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(
            serde_json::to_vec(&export_payload).unwrap(),
        )))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let status_uri: Uri = format!("http://{admin_addr}/_admin/status")
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(status_uri.clone())
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let status_body = response_json(res).await;
    assert_eq!(
        status_body["stats"]["active_session_recordings_total"].as_u64(),
        Some(1)
    );

    let import_uri: Uri = format!("http://{admin_addr}/_admin/sessions/{session_name}/import")
        .parse()
        .unwrap();
    let import_payload = serde_json::json!({
        "in_dir": output_dir.to_string_lossy(),
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri(import_uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(
            serde_json::to_vec(&import_payload).unwrap(),
        )))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = response_json(res).await;
    assert_eq!(body["status"].as_str(), Some("completed"));
    assert_eq!(body["session"].as_str(), Some(session_name));
    assert_eq!(body["recordings_imported"].as_u64(), Some(1));
    assert_eq!(body["format"].as_str(), Some("json"));
    assert_eq!(
        body["input_dir"].as_str().map(std::path::PathBuf::from),
        Some(output_dir.clone())
    );
    assert_eq!(
        body["manifest_path"].as_str().map(std::path::PathBuf::from),
        Some(output_dir.join("index.json"))
    );

    assert_eq!(storage.count_recordings().await.unwrap(), 2);

    let req = Request::builder()
        .method(Method::GET)
        .uri(status_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let status_body = response_json(res).await;
    assert_eq!(
        status_body["stats"]["active_session_recordings_total"].as_u64(),
        Some(2)
    );

    let missing_import_uri: Uri = format!("http://{admin_addr}/_admin/sessions/missing/import")
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri(missing_import_uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(
            serde_json::to_vec(&import_payload).unwrap(),
        )))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let body = response_json(res).await;
    assert!(body["error"].as_str().unwrap().contains("was not found"));

    let bad_manifest_dir = export_dir.path().join("bad-manifest");
    fs::create_dir_all(&bad_manifest_dir).unwrap();
    fs::write(
        bad_manifest_dir.join("index.json"),
        br#"{"version":2,"session":"default","format":"json","exported_at_unix_ms":0,"recordings":[]}"#,
    )
    .unwrap();
    let bad_import_payload = serde_json::json!({
        "in_dir": bad_manifest_dir.to_string_lossy(),
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!(
            "http://{admin_addr}/_admin/sessions/{session_name}/import"
        ))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(
            serde_json::to_vec(&bad_import_payload).unwrap(),
        )))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body = response_json(res).await;
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("unsupported export manifest version")
    );

    proxy.shutdown().await;
}

#[tokio::test]
async fn admin_sessions_activation_switches_active_session_and_recording_target() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;

    let storage_dir = tempfile::tempdir().unwrap();
    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"
admin_port = 0

[storage]
path = "{}"
active_session = "default"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "record"
"#,
        storage_dir.path().display()
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();
    let admin_addr = proxy
        .admin_listen_addr
        .expect("admin listener should be started");

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let proxy_uri: Uri = format!("http://{}/api/hello?x=1", proxy.listen_addr)
        .parse()
        .unwrap();

    let sessions_uri: Uri = format!("http://{admin_addr}/_admin/sessions")
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri(sessions_uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from_static(br#"{"name":"staging"}"#)))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    let activate_uri: Uri = format!("http://{admin_addr}/_admin/sessions/staging/activate")
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri(activate_uri.clone())
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = response_json(res).await;
    assert_eq!(body["name"].as_str(), Some("staging"));

    let status_uri: Uri = format!("http://{admin_addr}/_admin/status")
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(status_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = response_json(res).await;
    assert_eq!(body["active_session"].as_str(), Some("staging"));

    let delete_active_uri: Uri = format!("http://{admin_addr}/_admin/sessions/staging")
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::DELETE)
        .uri(delete_active_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT);
    let body = response_json(res).await;
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("cannot delete active session")
    );

    let req = Request::builder()
        .method(Method::POST)
        .uri(proxy_uri)
        .body(Full::new(Bytes::from_static(b"after-switch")))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let _ = res.into_body().collect().await.unwrap().to_bytes();
    let _captured = upstream_rx.recv().await.unwrap();

    let default_db_path = storage_dir.path().join("default").join("recordings.db");
    let default_conn = Connection::open(default_db_path).unwrap();
    let default_count: i64 = default_conn
        .query_row("SELECT COUNT(*) FROM recordings;", [], |row| row.get(0))
        .unwrap();
    assert_eq!(default_count, 0);

    let staging_db_path = storage_dir.path().join("staging").join("recordings.db");
    let staging_conn = Connection::open(staging_db_path).unwrap();
    let staging_count: i64 = staging_conn
        .query_row("SELECT COUNT(*) FROM recordings;", [], |row| row.get(0))
        .unwrap();
    assert_eq!(staging_count, 1);

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[tokio::test]
async fn admin_sessions_activation_returns_informative_errors() {
    let storage_dir = tempfile::tempdir().unwrap();
    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"
admin_port = 0

[storage]
path = "{}"
active_session = "default"
"#,
        storage_dir.path().display()
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();
    let admin_addr = proxy
        .admin_listen_addr
        .expect("admin listener should be started");

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let activate_uri: Uri = format!("http://{admin_addr}/_admin/sessions/default/activate")
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(activate_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
    let body = response_json(res).await;
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("method not allowed")
    );

    let activate_missing_uri: Uri = format!("http://{admin_addr}/_admin/sessions/missing/activate")
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri(activate_missing_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let body = response_json(res).await;
    assert!(body["error"].as_str().unwrap().contains("was not found"));

    proxy.shutdown().await;

    let config = replayproxy::config::Config::from_toml_str(
        r#"
[proxy]
listen = "127.0.0.1:0"
admin_port = 0
"#,
    )
    .unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();
    let admin_addr = proxy
        .admin_listen_addr
        .expect("admin listener should be started");

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let activate_uri: Uri = format!("http://{admin_addr}/_admin/sessions/default/activate")
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri(activate_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = response_json(res).await;
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("session management is unavailable")
    );

    proxy.shutdown().await;
}

#[tokio::test]
async fn admin_recordings_endpoints_list_get_and_delete_recordings() {
    let storage_dir = tempfile::tempdir().unwrap();
    let session_name = "staging";
    let session_db_path =
        replayproxy::session::resolve_session_db_path(storage_dir.path(), session_name).unwrap();
    let storage = Storage::open(session_db_path).unwrap();

    let first_id = storage
        .insert_recording(Recording {
            match_key: "first-key".to_owned(),
            request_method: "GET".to_owned(),
            request_uri: "/api/ping".to_owned(),
            request_headers: vec![("accept".to_owned(), b"application/json".to_vec())],
            request_body: Vec::new(),
            response_status: 200,
            response_headers: vec![("content-type".to_owned(), b"application/json".to_vec())],
            response_body: br#"{"ok":true}"#.to_vec(),
            created_at_unix_ms: 10,
        })
        .await
        .unwrap();
    let second_id = storage
        .insert_recording(Recording {
            match_key: "second-key".to_owned(),
            request_method: "POST".to_owned(),
            request_uri: "/api/chat".to_owned(),
            request_headers: vec![("authorization".to_owned(), b"[REDACTED]".to_vec())],
            request_body: br#"{"token":"[REDACTED]"}"#.to_vec(),
            response_status: 201,
            response_headers: vec![("x-secret".to_owned(), b"[REDACTED]".to_vec())],
            response_body: br#"{"secret":"[REDACTED]"}"#.to_vec(),
            created_at_unix_ms: 20,
        })
        .await
        .unwrap();

    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"
admin_port = 0

[storage]
path = "{}"
active_session = "{session_name}"
"#,
        storage_dir.path().display()
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();
    let admin_addr = proxy
        .admin_listen_addr
        .expect("admin listener should be started");

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let list_uri: Uri = format!(
        "http://{admin_addr}/_admin/sessions/{session_name}/recordings?limit=1&offset=0&method=POST&url_contains=/api/chat"
    )
    .parse()
    .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(list_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = response_json(res).await;
    assert_eq!(body["session"].as_str(), Some(session_name));
    assert_eq!(body["offset"].as_u64(), Some(0));
    assert_eq!(body["limit"].as_u64(), Some(1));
    let recordings = body["recordings"].as_array().unwrap();
    assert_eq!(recordings.len(), 1);
    assert_eq!(recordings[0]["id"].as_i64(), Some(second_id));
    assert_eq!(recordings[0]["request_method"].as_str(), Some("POST"));

    let get_uri: Uri =
        format!("http://{admin_addr}/_admin/sessions/{session_name}/recordings/{second_id}")
            .parse()
            .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(get_uri.clone())
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = response_json(res).await;
    assert_eq!(body["id"].as_i64(), Some(second_id));
    assert_eq!(body["match_key"].as_str(), Some("second-key"));
    assert_eq!(body["request"]["method"].as_str(), Some("POST"));
    assert_eq!(body["request"]["uri"].as_str(), Some("/api/chat"));
    assert_eq!(body["response"]["status"].as_u64(), Some(201));
    assert_eq!(
        json_bytes(&body["request"]["body"]),
        br#"{"token":"[REDACTED]"}"#.to_vec()
    );
    assert_eq!(
        json_bytes(&body["response"]["body"]),
        br#"{"secret":"[REDACTED]"}"#.to_vec()
    );

    let delete_uri: Uri =
        format!("http://{admin_addr}/_admin/sessions/{session_name}/recordings/{second_id}")
            .parse()
            .unwrap();
    let req = Request::builder()
        .method(Method::DELETE)
        .uri(delete_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    let req = Request::builder()
        .method(Method::GET)
        .uri(get_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let body = response_json(res).await;
    assert!(body["error"].as_str().unwrap().contains("recording `"));

    let list_uri: Uri =
        format!("http://{admin_addr}/_admin/sessions/{session_name}/recordings?limit=10&offset=0")
            .parse()
            .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(list_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = response_json(res).await;
    let recordings = body["recordings"].as_array().unwrap();
    assert_eq!(recordings.len(), 1);
    assert_eq!(recordings[0]["id"].as_i64(), Some(first_id));

    let status_uri: Uri = format!("http://{admin_addr}/_admin/status")
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(status_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = response_json(res).await;
    assert_eq!(
        body["stats"]["active_session_recordings_total"].as_u64(),
        Some(1)
    );

    proxy.shutdown().await;
}

#[tokio::test]
async fn admin_recordings_endpoints_return_informative_errors() {
    let storage_dir = tempfile::tempdir().unwrap();
    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"
admin_port = 0

[storage]
path = "{}"
active_session = "default"
"#,
        storage_dir.path().display()
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();
    let admin_addr = proxy
        .admin_listen_addr
        .expect("admin listener should be started");

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let missing_session_uri: Uri =
        format!("http://{admin_addr}/_admin/sessions/missing/recordings")
            .parse()
            .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(missing_session_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let body = response_json(res).await;
    assert!(body["error"].as_str().unwrap().contains("was not found"));

    let invalid_limit_uri: Uri =
        format!("http://{admin_addr}/_admin/sessions/default/recordings?limit=abc")
            .parse()
            .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(invalid_limit_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body = response_json(res).await;
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("query parameter `limit`")
    );

    let missing_recording_uri: Uri =
        format!("http://{admin_addr}/_admin/sessions/default/recordings/9999")
            .parse()
            .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(missing_recording_uri.clone())
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let body = response_json(res).await;
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("recording `9999` was not found")
    );

    let req = Request::builder()
        .method(Method::DELETE)
        .uri(missing_recording_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let body = response_json(res).await;
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("recording `9999` was not found")
    );

    proxy.shutdown().await;
}

#[tokio::test]
async fn record_mode_persists_recording() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;

    let storage_dir = tempfile::tempdir().unwrap();
    let session = "default";
    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[storage]
path = "{}"
active_session = "{session}"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "record"
"#,
        storage_dir.path().display()
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let proxy_uri: Uri = format!("http://{}/api/hello?x=1", proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri(proxy_uri)
        .header("x-end", "kept")
        .body(Full::new(Bytes::from_static(b"client-body")))
        .unwrap();

    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    assert_eq!(
        res.headers().get("x-resp-binary").unwrap().as_bytes(),
        BINARY_HEADER_VALUE
    );
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], b"upstream-body");

    let captured = upstream_rx.recv().await.unwrap();
    assert_eq!(captured.uri.path(), "/api/hello");
    assert_eq!(captured.uri.query(), Some("x=1"));
    assert_eq!(&captured.body[..], b"client-body");

    let db_path = storage_dir.path().join(session).join("recordings.db");
    let conn = Connection::open(db_path).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM recordings;", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[tokio::test]
async fn record_mode_redacts_configured_headers_and_json_body_before_storage() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;

    let storage_dir = tempfile::tempdir().unwrap();
    let session = "default";
    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[storage]
path = "{}"
active_session = "{session}"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "record"

[routes.match]
headers = ["Authorization"]
body_json = ["$.auth.token"]

[routes.redact]
headers = ["Authorization", "X-Resp-End"]
body_json = ["$.auth.token", "$.messages[*].content"]
"#,
        storage_dir.path().display()
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let request_body =
        br#"{"auth":{"token":"client-secret"},"messages":[{"content":"first"},{"content":"second"}]}"#;
    let proxy_uri: Uri = format!("http://{}/api/hello?x=1", proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri(proxy_uri)
        .header(header::AUTHORIZATION, "Bearer top-secret")
        .body(Full::new(Bytes::from_static(request_body)))
        .unwrap();

    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], b"upstream-body");

    let captured = upstream_rx.recv().await.unwrap();
    assert_eq!(
        captured.headers.get(header::AUTHORIZATION).unwrap(),
        &HeaderValue::from_static("Bearer top-secret")
    );
    assert_eq!(captured.body.as_ref(), request_body);

    let db_path = storage_dir.path().join(session).join("recordings.db");
    let conn = Connection::open(db_path).unwrap();
    let (stored_match_key, request_headers_json, response_headers_json, stored_request_body): (
        String,
        String,
        String,
        Vec<u8>,
    ) = conn
        .query_row(
            "SELECT match_key, request_headers_json, response_headers_json, request_body FROM recordings LIMIT 1;",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();

    let request_headers: Vec<(String, Vec<u8>)> =
        serde_json::from_str(&request_headers_json).unwrap();
    let response_headers: Vec<(String, Vec<u8>)> =
        serde_json::from_str(&response_headers_json).unwrap();
    let stored_request_body: Value = serde_json::from_slice(&stored_request_body).unwrap();
    assert_eq!(
        request_headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.as_slice()),
        Some(b"[REDACTED]".as_slice())
    );
    assert_eq!(
        response_headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("x-resp-end"))
            .map(|(_, value)| value.as_slice()),
        Some(b"[REDACTED]".as_slice())
    );
    assert_eq!(
        stored_request_body
            .pointer("/auth/token")
            .and_then(Value::as_str),
        Some("[REDACTED]")
    );
    assert_eq!(
        stored_request_body
            .pointer("/messages/0/content")
            .and_then(Value::as_str),
        Some("[REDACTED]")
    );
    assert_eq!(
        stored_request_body
            .pointer("/messages/1/content")
            .and_then(Value::as_str),
        Some("[REDACTED]")
    );

    let expected_match_key = replayproxy::matching::compute_match_key(
        config.routes[0].match_.as_ref(),
        &Method::POST,
        &captured.uri,
        &captured.headers,
        &captured.body,
    )
    .unwrap();
    let mut redacted_match_headers = captured.headers.clone();
    redacted_match_headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("[REDACTED]"),
    );
    let redacted_match_key = replayproxy::matching::compute_match_key(
        config.routes[0].match_.as_ref(),
        &Method::POST,
        &captured.uri,
        &redacted_match_headers,
        &captured.body,
    )
    .unwrap();
    let redacted_match_body =
        br#"{"auth":{"token":"[REDACTED]"},"messages":[{"content":"first"},{"content":"second"}]}"#;
    let redacted_body_match_key = replayproxy::matching::compute_match_key(
        config.routes[0].match_.as_ref(),
        &Method::POST,
        &captured.uri,
        &captured.headers,
        redacted_match_body,
    )
    .unwrap();
    assert_eq!(stored_match_key, expected_match_key);
    assert_ne!(expected_match_key, redacted_match_key);
    assert_ne!(expected_match_key, redacted_body_match_key);

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[tokio::test]
async fn record_mode_uses_global_redaction_placeholder_in_storage() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;

    let storage_dir = tempfile::tempdir().unwrap();
    let session = "default";
    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[storage]
path = "{}"
active_session = "{session}"

[defaults.redact]
headers = ["Authorization", "X-Resp-End"]
body_json = ["$.auth.token"]
placeholder = "<GLOBAL-MASK>"

[[routes]]
upstream = "http://{upstream_addr}"
mode = "record"
path_prefix = "/api/inherited"
"#,
        storage_dir.path().display()
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let token = "global-secret";
    let body = format!(r#"{{"auth":{{"token":"{token}"}}}}"#);
    let proxy_uri: Uri = format!("http://{}/api/inherited", proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri(proxy_uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Full::new(Bytes::from(body)))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], b"upstream-body");

    let captured = upstream_rx.recv().await.unwrap();
    assert_eq!(captured.uri.path(), "/api/inherited");

    let db_path = storage_dir.path().join(session).join("recordings.db");
    let conn = Connection::open(db_path).unwrap();
    let (request_headers_json, response_headers_json, request_body): (String, String, Vec<u8>) =
        conn.query_row(
            "SELECT request_headers_json, response_headers_json, request_body FROM recordings LIMIT 1;",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let request_headers: Vec<(String, Vec<u8>)> =
        serde_json::from_str(&request_headers_json).unwrap();
    let response_headers: Vec<(String, Vec<u8>)> =
        serde_json::from_str(&response_headers_json).unwrap();
    let stored_request_body: Value = serde_json::from_slice(&request_body).unwrap();

    assert_eq!(
        request_headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.as_slice()),
        Some(b"<GLOBAL-MASK>".as_slice())
    );
    assert_eq!(
        response_headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("x-resp-end"))
            .map(|(_, value)| value.as_slice()),
        Some(b"<GLOBAL-MASK>".as_slice())
    );
    assert_eq!(
        stored_request_body
            .pointer("/auth/token")
            .and_then(Value::as_str),
        Some("<GLOBAL-MASK>")
    );

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[tokio::test]
async fn record_mode_redacts_configured_response_json_body_before_storage() {
    let upstream_response_body = br#"{"id":"resp-123","usage":{"prompt_tokens":7,"completion_tokens":11},"choices":[{"message":{"role":"assistant","content":"top-secret-1"}},{"message":{"role":"assistant","content":"top-secret-2"}}],"metadata":{"trace_id":"trace-abc"}}"#;
    let (upstream_addr, mut upstream_rx, upstream_shutdown) =
        spawn_upstream_with_response_chunks(vec![Bytes::from_static(upstream_response_body)]).await;

    let storage_dir = tempfile::tempdir().unwrap();
    let session = "default";
    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[storage]
path = "{}"
active_session = "{session}"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "record"

[routes.redact]
body_json = ["$.usage.prompt_tokens", "$.choices[*].message.content"]
"#,
        storage_dir.path().display()
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let proxy_uri: Uri = format!("http://{}/api/response-redaction", proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(proxy_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();

    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], upstream_response_body);

    let captured = upstream_rx.recv().await.unwrap();
    assert_eq!(captured.uri.path(), "/api/response-redaction");

    let db_path = storage_dir.path().join(session).join("recordings.db");
    let conn = Connection::open(db_path).unwrap();
    let stored_response_body: Vec<u8> = conn
        .query_row("SELECT response_body FROM recordings LIMIT 1;", [], |row| {
            row.get(0)
        })
        .unwrap();
    let stored_response_json: Value = serde_json::from_slice(&stored_response_body).unwrap();

    assert_eq!(
        stored_response_json
            .pointer("/usage/prompt_tokens")
            .and_then(Value::as_str),
        Some("[REDACTED]")
    );
    assert_eq!(
        stored_response_json
            .pointer("/choices/0/message/content")
            .and_then(Value::as_str),
        Some("[REDACTED]")
    );
    assert_eq!(
        stored_response_json
            .pointer("/choices/1/message/content")
            .and_then(Value::as_str),
        Some("[REDACTED]")
    );
    assert_eq!(
        stored_response_json
            .pointer("/usage/completion_tokens")
            .and_then(Value::as_i64),
        Some(11)
    );
    assert_eq!(
        stored_response_json
            .pointer("/choices/0/message/role")
            .and_then(Value::as_str),
        Some("assistant")
    );
    assert_eq!(
        stored_response_json
            .pointer("/metadata/trace_id")
            .and_then(Value::as_str),
        Some("trace-abc")
    );

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[tokio::test]
async fn record_mode_uses_global_redaction_placeholder_before_storage() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;

    let storage_dir = tempfile::tempdir().unwrap();
    let session = "default";
    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[storage]
path = "{}"
active_session = "{session}"

[defaults.redact]
headers = ["Authorization", "X-Resp-End"]
body_json = ["$.auth.token"]
placeholder = "<GLOBAL-MASK>"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "record"
"#,
        storage_dir.path().display()
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let request_body = br#"{"auth":{"token":"client-secret"},"other":"ok"}"#;
    let proxy_uri: Uri = format!("http://{}/api/global-mask", proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri(proxy_uri)
        .header(header::AUTHORIZATION, "Bearer top-secret")
        .body(Full::new(Bytes::from_static(request_body)))
        .unwrap();

    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let _ = res.into_body().collect().await.unwrap();

    let captured = upstream_rx.recv().await.unwrap();
    assert_eq!(
        captured.headers.get(header::AUTHORIZATION).unwrap(),
        &HeaderValue::from_static("Bearer top-secret")
    );
    assert_eq!(captured.body.as_ref(), request_body);

    let db_path = storage_dir.path().join(session).join("recordings.db");
    let conn = Connection::open(db_path).unwrap();
    let (request_headers_json, response_headers_json, stored_request_body): (
        String,
        String,
        Vec<u8>,
    ) = conn
        .query_row(
            "SELECT request_headers_json, response_headers_json, request_body FROM recordings LIMIT 1;",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();

    let request_headers: Vec<(String, Vec<u8>)> =
        serde_json::from_str(&request_headers_json).unwrap();
    let response_headers: Vec<(String, Vec<u8>)> =
        serde_json::from_str(&response_headers_json).unwrap();
    let stored_request_body: Value = serde_json::from_slice(&stored_request_body).unwrap();

    assert_eq!(
        request_headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.as_slice()),
        Some(b"<GLOBAL-MASK>".as_slice())
    );
    assert_eq!(
        response_headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("x-resp-end"))
            .map(|(_, value)| value.as_slice()),
        Some(b"<GLOBAL-MASK>".as_slice())
    );
    assert_eq!(
        stored_request_body
            .pointer("/auth/token")
            .and_then(Value::as_str),
        Some("<GLOBAL-MASK>")
    );
    assert_eq!(
        stored_request_body
            .pointer("/other")
            .and_then(Value::as_str),
        Some("ok")
    );

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[tokio::test]
async fn passthrough_cache_serves_cached_response_on_second_request() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;

    let storage_dir = tempfile::tempdir().unwrap();
    let session = "default";
    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[storage]
path = "{}"
active_session = "{session}"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "passthrough-cache"
"#,
        storage_dir.path().display()
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let proxy_uri: Uri = format!("http://{}/api/hello?x=1", proxy.listen_addr)
        .parse()
        .unwrap();

    let req = Request::builder()
        .method(Method::GET)
        .uri(proxy_uri.clone())
        .body(Full::new(Bytes::new()))
        .unwrap();

    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    assert_eq!(
        res.headers().get("x-resp-binary").unwrap().as_bytes(),
        BINARY_HEADER_VALUE
    );
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], b"upstream-body");

    let _captured = upstream_rx.recv().await.unwrap();

    let req = Request::builder()
        .method(Method::GET)
        .uri(proxy_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    assert_eq!(
        res.headers().get("x-resp-binary").unwrap().as_bytes(),
        BINARY_HEADER_VALUE
    );
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], b"upstream-body");

    let db_path = storage_dir.path().join(session).join("recordings.db");
    let conn = Connection::open(db_path).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM recordings;", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[tokio::test]
async fn replay_mode_returns_cached_response_and_errors_on_miss() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;

    let storage_dir = tempfile::tempdir().unwrap();
    let session = "default";
    let record_config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[storage]
path = "{}"
active_session = "{session}"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "record"
"#,
        storage_dir.path().display()
    );
    let record_config = replayproxy::config::Config::from_toml_str(&record_config_toml).unwrap();
    let record_proxy = replayproxy::proxy::serve(&record_config).await.unwrap();

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let uri: Uri = format!("http://{}/api/hello?x=1", record_proxy.listen_addr)
        .parse()
        .unwrap();
    let json_body = br#"{"hello":"world"}"#;
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri.clone())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from_static(json_body)))
        .unwrap();

    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    assert_eq!(
        res.headers().get("x-resp-binary").unwrap().as_bytes(),
        BINARY_HEADER_VALUE
    );
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], b"upstream-body");

    let _captured = upstream_rx.recv().await.unwrap();

    record_proxy.shutdown().await;
    let _ = upstream_shutdown().await;

    let replay_config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[storage]
path = "{}"
active_session = "{session}"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "replay"
cache_miss = "error"
"#,
        storage_dir.path().display()
    );
    let replay_config = replayproxy::config::Config::from_toml_str(&replay_config_toml).unwrap();
    let replay_proxy = replayproxy::proxy::serve(&replay_config).await.unwrap();

    let uri: Uri = format!("http://{}/api/hello?x=1", replay_proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from_static(json_body)))
        .unwrap();

    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    assert_eq!(
        res.headers().get("x-resp-binary").unwrap().as_bytes(),
        BINARY_HEADER_VALUE
    );
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], b"upstream-body");

    let uri: Uri = format!("http://{}/api/hello?x=2", replay_proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from_static(json_body)))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        res.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let miss_body: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(
        miss_body,
        serde_json::json!({
            "error": "Gateway Not Recorded",
            "route": "routes[0] path_prefix=/api",
            "session": "default",
            "match_key": miss_body["match_key"],
        })
    );
    let match_key = miss_body["match_key"].as_str().unwrap();
    assert_eq!(match_key.len(), 64);
    assert!(match_key.bytes().all(|byte| byte.is_ascii_hexdigit()));

    replay_proxy.shutdown().await;
}

#[tokio::test]
async fn record_then_replay_get_with_query_params() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;

    let storage_dir = tempfile::tempdir().unwrap();
    let session = "default";
    let record_config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[storage]
path = "{}"
active_session = "{session}"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "record"
"#,
        storage_dir.path().display()
    );
    let record_config = replayproxy::config::Config::from_toml_str(&record_config_toml).unwrap();
    let record_proxy = replayproxy::proxy::serve(&record_config).await.unwrap();

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let uri: Uri = format!("http://{}/api/hello?b=2&a=1", record_proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Full::new(Bytes::new()))
        .unwrap();

    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], b"upstream-body");

    let _captured = upstream_rx.recv().await.unwrap();

    record_proxy.shutdown().await;
    let _ = upstream_shutdown().await;

    let replay_config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[storage]
path = "{}"
active_session = "{session}"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "replay"
cache_miss = "error"
"#,
        storage_dir.path().display()
    );
    let replay_config = replayproxy::config::Config::from_toml_str(&replay_config_toml).unwrap();
    let replay_proxy = replayproxy::proxy::serve(&replay_config).await.unwrap();

    let uri: Uri = format!("http://{}/api/hello?a=1&b=2", replay_proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Full::new(Bytes::new()))
        .unwrap();

    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], b"upstream-body");

    replay_proxy.shutdown().await;
}

#[tokio::test]
async fn replay_mode_subset_query_matches_recorded_query_as_subset() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;

    let storage_dir = tempfile::tempdir().unwrap();
    let session = "default";
    let record_config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[storage]
path = "{}"
active_session = "{session}"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "record"

[routes.match]
query = "subset"
"#,
        storage_dir.path().display()
    );
    let record_config = replayproxy::config::Config::from_toml_str(&record_config_toml).unwrap();
    let record_proxy = replayproxy::proxy::serve(&record_config).await.unwrap();

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let uri: Uri = format!("http://{}/api/hello?b=2&a=1", record_proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Full::new(Bytes::new()))
        .unwrap();

    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], b"upstream-body");

    let _captured = upstream_rx.recv().await.unwrap();

    record_proxy.shutdown().await;
    let _ = upstream_shutdown().await;

    let replay_config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[storage]
path = "{}"
active_session = "{session}"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "replay"
cache_miss = "error"

[routes.match]
query = "subset"
"#,
        storage_dir.path().display()
    );
    let replay_config = replayproxy::config::Config::from_toml_str(&replay_config_toml).unwrap();
    let replay_proxy = replayproxy::proxy::serve(&replay_config).await.unwrap();

    let uri: Uri = format!("http://{}/api/hello?a=1&c=3&b=2", replay_proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], b"upstream-body");

    let uri: Uri = format!("http://{}/api/hello?a=1", replay_proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        res.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let miss_body: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(
        miss_body,
        serde_json::json!({
            "error": "Gateway Not Recorded",
            "route": "routes[0] path_prefix=/api",
            "session": "default",
            "match_key": miss_body["match_key"],
        })
    );
    let match_key = miss_body["match_key"].as_str().unwrap();
    assert_eq!(match_key.len(), 64);
    assert!(match_key.bytes().all(|byte| byte.is_ascii_hexdigit()));

    replay_proxy.shutdown().await;
}

#[tokio::test]
async fn replay_mode_cache_miss_forward_forwards_without_recording() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;

    let storage_dir = tempfile::tempdir().unwrap();
    let session = "default";
    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[storage]
path = "{}"
active_session = "{session}"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "replay"
cache_miss = "forward"
"#,
        storage_dir.path().display()
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let proxy_uri: Uri = format!("http://{}/api/hello?x=1", proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(proxy_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();

    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], b"upstream-body");

    let _captured = upstream_rx.recv().await.unwrap();

    let db_path = storage_dir.path().join(session).join("recordings.db");
    let conn = Connection::open(db_path).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM recordings;", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

async fn spawn_upstream() -> (
    SocketAddr,
    mpsc::Receiver<CapturedRequest>,
    impl FnOnce() -> tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = mpsc::channel::<CapturedRequest>(1);

    let join = tokio::spawn(async move {
        let (stream, _peer) = listener.accept().await.unwrap();
        let io = TokioIo::new(stream);
        let tx = Arc::new(tx);
        let service = service_fn(move |req: Request<Incoming>| {
            let tx = Arc::clone(&tx);
            async move {
                let (parts, body) = req.into_parts();
                let body_bytes = body.collect().await.unwrap().to_bytes();
                tx.send(CapturedRequest {
                    uri: parts.uri,
                    headers: parts.headers,
                    body: body_bytes,
                })
                .await
                .unwrap();

                let mut res = Response::new(Full::new(Bytes::from_static(b"upstream-body")));
                *res.status_mut() = StatusCode::CREATED;
                res.headers_mut().insert(
                    header::CONNECTION,
                    HeaderValue::from_static("close, x-resp-hop"),
                );
                res.headers_mut()
                    .insert("x-resp-hop", HeaderValue::from_static("yes"));
                res.headers_mut()
                    .insert("x-resp-end", HeaderValue::from_static("ok"));
                res.headers_mut().insert(
                    "x-resp-binary",
                    HeaderValue::from_bytes(BINARY_HEADER_VALUE).unwrap(),
                );
                Ok::<_, hyper::Error>(res)
            }
        });

        let builder = ConnectionBuilder::new(TokioExecutor::new());
        builder.serve_connection(io, service).await.unwrap();
    });

    (addr, rx, move || join)
}

async fn spawn_upstream_with_response_chunks(
    response_chunks: Vec<Bytes>,
) -> (
    SocketAddr,
    mpsc::Receiver<CapturedRequest>,
    impl FnOnce() -> tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = mpsc::channel::<CapturedRequest>(1);
    let response_chunks = Arc::new(response_chunks);

    let join = tokio::spawn(async move {
        let (stream, _peer) = listener.accept().await.unwrap();
        let io = TokioIo::new(stream);
        let tx = Arc::new(tx);
        let response_chunks = Arc::clone(&response_chunks);
        let service = service_fn(move |req: Request<Incoming>| {
            let tx = Arc::clone(&tx);
            let response_chunks = Arc::clone(&response_chunks);
            async move {
                let (parts, body) = req.into_parts();
                let body_bytes = body.collect().await.unwrap().to_bytes();
                tx.send(CapturedRequest {
                    uri: parts.uri,
                    headers: parts.headers,
                    body: body_bytes,
                })
                .await
                .unwrap();

                let mut res =
                    Response::new(ChunkedBody::new(response_chunks.iter().cloned().collect()));
                *res.status_mut() = StatusCode::CREATED;
                res.headers_mut().insert(
                    header::CONNECTION,
                    HeaderValue::from_static("close, x-resp-hop"),
                );
                res.headers_mut()
                    .insert("x-resp-hop", HeaderValue::from_static("yes"));
                res.headers_mut()
                    .insert("x-resp-end", HeaderValue::from_static("ok"));
                res.headers_mut().insert(
                    "x-resp-binary",
                    HeaderValue::from_bytes(BINARY_HEADER_VALUE).unwrap(),
                );
                Ok::<_, hyper::Error>(res)
            }
        });

        let builder = ConnectionBuilder::new(TokioExecutor::new());
        builder.serve_connection(io, service).await.unwrap();
    });

    (addr, rx, move || join)
}

async fn response_json(response: Response<Incoming>) -> Value {
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body_bytes).unwrap()
}

fn json_bytes(value: &Value) -> Vec<u8> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|item| u8::try_from(item.as_u64().unwrap()).unwrap())
        .collect()
}
