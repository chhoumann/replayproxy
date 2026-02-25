use std::{net::SocketAddr, sync::Arc, time::Duration};

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
use tokio::{net::TcpListener, sync::mpsc, time::timeout};

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

async fn response_json(response: Response<Incoming>) -> Value {
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body_bytes).unwrap()
}
