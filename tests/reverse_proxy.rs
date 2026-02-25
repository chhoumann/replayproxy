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
use tokio::{net::TcpListener, sync::mpsc};

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
                Ok::<_, hyper::Error>(res)
            }
        });

        let builder = ConnectionBuilder::new(TokioExecutor::new());
        builder.serve_connection(io, service).await.unwrap();
    });

    (addr, rx, move || join)
}
