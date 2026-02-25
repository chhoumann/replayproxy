use std::{net::SocketAddr, sync::Arc};

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
use rusqlite::Connection;
use serde_json::Value;
use tokio::{net::TcpListener, sync::mpsc};

const BINARY_HEADER_VALUE: &[u8] = b"\x80\xffok";

#[derive(Debug)]
struct CapturedRequest {
    uri: Uri,
    headers: hyper::HeaderMap,
    body: Bytes,
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
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], b"Gateway Not Recorded");

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
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], b"Gateway Not Recorded");

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
