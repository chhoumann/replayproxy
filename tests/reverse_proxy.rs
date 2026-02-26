use std::{
    collections::VecDeque,
    convert::Infallible,
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt as _, Full};
use hyper::{
    Method, Request, Response, StatusCode, Uri,
    body::{Frame, Incoming},
    client::conn::{http1, http2},
    header::{self, HeaderValue},
    service::service_fn,
};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as ConnectionBuilder,
};
use replayproxy::storage::{
    Recording, ResponseChunk, Storage, WebSocketFrameDirection, WebSocketMessageType,
};
use rusqlite::Connection;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde_json::Value;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::{sleep, timeout},
};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::{accept_async, connect_async, tungstenite::Message};
use x509_parser::pem::parse_x509_pem;

const BINARY_HEADER_VALUE: &[u8] = b"\x80\xffok";
const ADMIN_API_TOKEN_HEADER: &str = "x-replayproxy-admin-token";

#[derive(Debug)]
struct CapturedRequest {
    uri: Uri,
    version: hyper::Version,
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
async fn reverse_proxy_forwards_direct_http2_to_h2c_upstream() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_grpc_upstream().await;

    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[[routes]]
path_prefix = "/"
upstream = "http://{upstream_addr}"
"#
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let stream = TcpStream::connect(proxy.listen_addr).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, connection) = http2::handshake(TokioExecutor::new(), io).await.unwrap();
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });

    let grpc_payload = Bytes::from_static(b"\x00\x00\x00\x00\x05hello");
    let req = Request::builder()
        .method(Method::POST)
        .version(hyper::Version::HTTP_2)
        .uri(format!(
            "http://{}/helloworld.Greeter/SayHello?x=1",
            proxy.listen_addr
        ))
        .header(header::HOST, proxy.listen_addr.to_string())
        .header(header::CONTENT_TYPE, "application/grpc")
        .header("te", "trailers")
        .body(Full::new(grpc_payload.clone()))
        .unwrap();
    let res = sender.send_request(req).await.unwrap();
    assert_eq!(res.version(), hyper::Version::HTTP_2);
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get(header::CONTENT_TYPE).unwrap(),
        &HeaderValue::from_static("application/grpc")
    );
    assert_eq!(
        res.headers().get("grpc-status").unwrap(),
        &HeaderValue::from_static("0")
    );
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], b"\x00\x00\x00\x00\x00");

    let captured = upstream_rx.recv().await.unwrap();
    assert_eq!(captured.version, hyper::Version::HTTP_2);
    assert_eq!(captured.uri.path(), "/helloworld.Greeter/SayHello");
    assert_eq!(captured.uri.query(), Some("x=1"));
    assert_eq!(
        captured.headers.get(header::CONTENT_TYPE).unwrap(),
        &HeaderValue::from_static("application/grpc")
    );
    assert_eq!(captured.body, grpc_payload);

    drop(sender);
    let _ = connection_task.await;
    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[tokio::test]
async fn forward_proxy_connect_tunnels_grpc_over_http2_passthrough() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_grpc_upstream().await;

    let config = replayproxy::config::Config::from_toml_str(
        r#"
[proxy]
listen = "127.0.0.1:0"

[[routes]]
path_prefix = "/"
"#,
    )
    .unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let mut stream = TcpStream::connect(proxy.listen_addr).await.unwrap();
    let connect_request = format!(
        "CONNECT {upstream_addr} HTTP/1.1\r\nHost: {upstream_addr}\r\nProxy-Connection: keep-alive\r\n\r\n"
    );
    stream.write_all(connect_request.as_bytes()).await.unwrap();
    let response_head = read_http_response_head(&mut stream).await;
    assert!(
        response_head.starts_with(b"HTTP/1.1 200"),
        "unexpected CONNECT response: {}",
        String::from_utf8_lossy(&response_head)
    );

    let io = TokioIo::new(stream);
    let (mut sender, connection) = http2::handshake(TokioExecutor::new(), io).await.unwrap();
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });

    let grpc_payload = Bytes::from_static(b"\x00\x00\x00\x00\x05hello");
    let req = Request::builder()
        .method(Method::POST)
        .version(hyper::Version::HTTP_2)
        .uri(format!(
            "http://{upstream_addr}/helloworld.Greeter/SayHello"
        ))
        .header(header::HOST, upstream_addr.to_string())
        .header(header::CONTENT_TYPE, "application/grpc")
        .header("te", "trailers")
        .body(Full::new(grpc_payload.clone()))
        .unwrap();
    let res = sender.send_request(req).await.unwrap();
    assert_eq!(res.version(), hyper::Version::HTTP_2);
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get(header::CONTENT_TYPE).unwrap(),
        &HeaderValue::from_static("application/grpc")
    );
    assert_eq!(
        res.headers().get("grpc-status").unwrap(),
        &HeaderValue::from_static("0")
    );
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], b"\x00\x00\x00\x00\x00");

    let captured = upstream_rx.recv().await.unwrap();
    assert_eq!(captured.version, hyper::Version::HTTP_2);
    assert_eq!(captured.uri.path(), "/helloworld.Greeter/SayHello");
    assert_eq!(
        captured.headers.get(header::CONTENT_TYPE).unwrap(),
        &HeaderValue::from_static("application/grpc")
    );
    assert_eq!(
        captured.headers.get("te").unwrap(),
        &HeaderValue::from_static("trailers")
    );
    assert_eq!(captured.body, grpc_payload);

    drop(sender);
    let _ = connection_task.await;
    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[tokio::test]
async fn grpc_opaque_record_then_replay_matches_on_raw_request_bytes() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_grpc_upstream().await;

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
path_prefix = "/"
upstream = "http://{upstream_addr}"
mode = "record"
"#,
        storage_dir.path().display()
    );
    let record_config = replayproxy::config::Config::from_toml_str(&record_config_toml).unwrap();
    let record_proxy = replayproxy::proxy::serve(&record_config).await.unwrap();

    let stream = TcpStream::connect(record_proxy.listen_addr).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, connection) = http2::handshake(TokioExecutor::new(), io).await.unwrap();
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });

    let recorded_payload = Bytes::from_static(b"\x00\x00\x00\x00\x05hello");
    let record_request = Request::builder()
        .method(Method::POST)
        .version(hyper::Version::HTTP_2)
        .uri(format!(
            "http://{}/helloworld.Greeter/SayHello",
            record_proxy.listen_addr
        ))
        .header(header::HOST, record_proxy.listen_addr.to_string())
        .header(header::CONTENT_TYPE, "application/grpc")
        .header("te", "trailers")
        .body(Full::new(recorded_payload.clone()))
        .unwrap();
    let record_response = sender.send_request(record_request).await.unwrap();
    assert_eq!(record_response.status(), StatusCode::OK);
    assert_eq!(
        record_response.headers().get(header::CONTENT_TYPE).unwrap(),
        &HeaderValue::from_static("application/grpc")
    );
    assert_eq!(
        record_response.headers().get("grpc-status").unwrap(),
        &HeaderValue::from_static("0")
    );
    let record_body = record_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&record_body[..], b"\x00\x00\x00\x00\x00");

    let captured = upstream_rx.recv().await.unwrap();
    assert_eq!(captured.version, hyper::Version::HTTP_2);
    assert_eq!(captured.uri.path(), "/helloworld.Greeter/SayHello");
    assert_eq!(captured.body, recorded_payload.clone());

    drop(sender);
    let _ = connection_task.await;
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
path_prefix = "/"
upstream = "http://{upstream_addr}"
mode = "replay"
cache_miss = "error"
"#,
        storage_dir.path().display()
    );
    let replay_config = replayproxy::config::Config::from_toml_str(&replay_config_toml).unwrap();
    let replay_proxy = replayproxy::proxy::serve(&replay_config).await.unwrap();

    let stream = TcpStream::connect(replay_proxy.listen_addr).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, connection) = http2::handshake(TokioExecutor::new(), io).await.unwrap();
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });

    let replay_hit_request = Request::builder()
        .method(Method::POST)
        .version(hyper::Version::HTTP_2)
        .uri(format!(
            "http://{}/helloworld.Greeter/SayHello",
            replay_proxy.listen_addr
        ))
        .header(header::HOST, replay_proxy.listen_addr.to_string())
        .header(header::CONTENT_TYPE, "application/grpc")
        .header("te", "trailers")
        .body(Full::new(recorded_payload.clone()))
        .unwrap();
    let replay_hit_response = sender.send_request(replay_hit_request).await.unwrap();
    assert_eq!(replay_hit_response.status(), StatusCode::OK);
    assert_eq!(
        replay_hit_response
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap(),
        &HeaderValue::from_static("application/grpc")
    );
    assert_eq!(
        replay_hit_response.headers().get("grpc-status").unwrap(),
        &HeaderValue::from_static("0")
    );
    let replay_hit_body = replay_hit_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&replay_hit_body[..], b"\x00\x00\x00\x00\x00");

    let replay_miss_payload = Bytes::from_static(b"\x00\x00\x00\x00\x05jello");
    let replay_miss_request = Request::builder()
        .method(Method::POST)
        .version(hyper::Version::HTTP_2)
        .uri(format!(
            "http://{}/helloworld.Greeter/SayHello",
            replay_proxy.listen_addr
        ))
        .header(header::HOST, replay_proxy.listen_addr.to_string())
        .header(header::CONTENT_TYPE, "application/grpc")
        .header("te", "trailers")
        .body(Full::new(replay_miss_payload))
        .unwrap();
    let replay_miss_response = sender.send_request(replay_miss_request).await.unwrap();
    assert_eq!(replay_miss_response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        replay_miss_response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let miss_body = response_json(replay_miss_response).await;
    assert_eq!(miss_body["error"], "Gateway Not Recorded");
    assert_eq!(miss_body["route"], "routes[0] path_prefix=/");
    assert_eq!(miss_body["session"], "default");
    let match_key = miss_body["match_key"].as_str().unwrap();
    assert_eq!(match_key.len(), 64);
    assert!(match_key.bytes().all(|byte| byte.is_ascii_hexdigit()));

    drop(sender);
    let _ = connection_task.await;
    replay_proxy.shutdown().await;
}

#[tokio::test]
#[cfg(feature = "grpc")]
async fn grpc_proto_aware_record_then_replay_matches_selected_fields() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_grpc_upstream().await;

    let temp_dir = tempfile::tempdir().unwrap();
    let storage_dir = temp_dir.path().join("storage");
    fs::create_dir_all(&storage_dir).unwrap();
    let proto_path = temp_dir.path().join("inference.proto");
    fs::write(
        &proto_path,
        r#"
syntax = "proto3";
package inference;

service InferenceService {
  rpc Predict (PredictRequest) returns (PredictResponse);
}

message PredictRequest {
  string model_name = 1;
  string input_text = 2;
  string trace_id = 3;
}

message PredictResponse {
  string output_text = 1;
}
"#,
    )
    .unwrap();

    let session = "default";
    let record_config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[storage]
path = "{}"
active_session = "{session}"

[[routes]]
path_prefix = "/inference.InferenceService"
upstream = "http://{upstream_addr}"
mode = "record"

[routes.grpc]
proto_files = ["{}"]
match_fields = ["model_name", "input_text"]
"#,
        storage_dir.display(),
        proto_path.display(),
    );
    let record_config = replayproxy::config::Config::from_toml_str(&record_config_toml).unwrap();
    let record_proxy = replayproxy::proxy::serve(&record_config).await.unwrap();

    let stream = TcpStream::connect(record_proxy.listen_addr).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, connection) = http2::handshake(TokioExecutor::new(), io).await.unwrap();
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });

    let recorded_payload =
        grpc_unary_frame(&encode_predict_request("model-a", "hello world", "trace-a"));
    let record_request = Request::builder()
        .method(Method::POST)
        .version(hyper::Version::HTTP_2)
        .uri(format!(
            "http://{}/inference.InferenceService/Predict",
            record_proxy.listen_addr
        ))
        .header(header::HOST, record_proxy.listen_addr.to_string())
        .header(header::CONTENT_TYPE, "application/grpc")
        .header("te", "trailers")
        .body(Full::new(recorded_payload.clone()))
        .unwrap();
    let record_response = sender.send_request(record_request).await.unwrap();
    assert_eq!(record_response.status(), StatusCode::OK);
    let record_body = record_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&record_body[..], b"\x00\x00\x00\x00\x00");

    let captured = upstream_rx.recv().await.unwrap();
    assert_eq!(captured.uri.path(), "/inference.InferenceService/Predict");
    assert_eq!(captured.body, recorded_payload);

    drop(sender);
    let _ = connection_task.await;
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
path_prefix = "/inference.InferenceService"
upstream = "http://{upstream_addr}"
mode = "replay"
cache_miss = "error"

[routes.grpc]
proto_files = ["{}"]
match_fields = ["model_name", "input_text"]
"#,
        storage_dir.display(),
        proto_path.display(),
    );
    let replay_config = replayproxy::config::Config::from_toml_str(&replay_config_toml).unwrap();
    let replay_proxy = replayproxy::proxy::serve(&replay_config).await.unwrap();

    let stream = TcpStream::connect(replay_proxy.listen_addr).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, connection) = http2::handshake(TokioExecutor::new(), io).await.unwrap();
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });

    let replay_hit_payload =
        grpc_unary_frame(&encode_predict_request("model-a", "hello world", "trace-b"));
    let replay_hit_request = Request::builder()
        .method(Method::POST)
        .version(hyper::Version::HTTP_2)
        .uri(format!(
            "http://{}/inference.InferenceService/Predict",
            replay_proxy.listen_addr
        ))
        .header(header::HOST, replay_proxy.listen_addr.to_string())
        .header(header::CONTENT_TYPE, "application/grpc")
        .header("te", "trailers")
        .body(Full::new(replay_hit_payload))
        .unwrap();
    let replay_hit_response = sender.send_request(replay_hit_request).await.unwrap();
    assert_eq!(replay_hit_response.status(), StatusCode::OK);
    let replay_hit_body = replay_hit_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&replay_hit_body[..], b"\x00\x00\x00\x00\x00");

    let replay_miss_payload = grpc_unary_frame(&encode_predict_request(
        "model-a",
        "different prompt",
        "trace-a",
    ));
    let replay_miss_request = Request::builder()
        .method(Method::POST)
        .version(hyper::Version::HTTP_2)
        .uri(format!(
            "http://{}/inference.InferenceService/Predict",
            replay_proxy.listen_addr
        ))
        .header(header::HOST, replay_proxy.listen_addr.to_string())
        .header(header::CONTENT_TYPE, "application/grpc")
        .header("te", "trailers")
        .body(Full::new(replay_miss_payload))
        .unwrap();
    let replay_miss_response = sender.send_request(replay_miss_request).await.unwrap();
    assert_eq!(replay_miss_response.status(), StatusCode::BAD_GATEWAY);
    let miss_body = response_json(replay_miss_response).await;
    assert_eq!(miss_body["error"], "Gateway Not Recorded");

    drop(sender);
    let _ = connection_task.await;
    replay_proxy.shutdown().await;
}

#[cfg(feature = "scripting")]
#[tokio::test]
async fn on_request_script_mutates_request_before_matching_and_forwarding() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;
    let temp_dir = tempfile::tempdir().unwrap();
    let storage_dir = temp_dir.path().join("storage");
    fs::create_dir_all(&storage_dir).unwrap();
    let script_path = temp_dir.path().join("on_request.lua");
    fs::write(
        &script_path,
        r#"
function transform(request)
  request.headers["x-cache-key"] = "canonical"
  request.body = "normalized-body"
  return request
end
"#,
    )
    .unwrap();

    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[storage]
path = "{}"
active_session = "default"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "passthrough-cache"

[routes.transform]
on_request = "{}"
"#,
        storage_dir.display(),
        script_path.display()
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let proxy_uri: Uri = format!("http://{}/api/cache", proxy.listen_addr)
        .parse()
        .unwrap();

    let mut first_req = Request::builder()
        .method(Method::POST)
        .uri(proxy_uri.clone())
        .header("x-cache-key", "first")
        .body(Full::new(Bytes::from_static(b"client-body-a")))
        .unwrap();
    first_req.headers_mut().insert(
        "x-binary",
        HeaderValue::from_bytes(BINARY_HEADER_VALUE).unwrap(),
    );
    let first_res = client.request(first_req).await.unwrap();
    assert_eq!(first_res.status(), StatusCode::CREATED);
    let first_body = first_res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&first_body[..], b"upstream-body");

    let captured = upstream_rx.recv().await.unwrap();
    assert_eq!(captured.uri.path(), "/api/cache");
    assert_eq!(
        captured.headers.get("x-cache-key").unwrap(),
        &HeaderValue::from_static("canonical")
    );
    assert_eq!(
        captured.headers.get("x-binary").unwrap().as_bytes(),
        BINARY_HEADER_VALUE
    );
    assert_eq!(&captured.body[..], b"normalized-body");

    let mut second_req = Request::builder()
        .method(Method::POST)
        .uri(proxy_uri)
        .header("x-cache-key", "second")
        .body(Full::new(Bytes::from_static(b"client-body-b")))
        .unwrap();
    second_req.headers_mut().insert(
        "x-binary",
        HeaderValue::from_bytes(BINARY_HEADER_VALUE).unwrap(),
    );
    let second_res = client.request(second_req).await.unwrap();
    assert_eq!(second_res.status(), StatusCode::CREATED);
    let second_body = second_res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&second_body[..], b"upstream-body");

    assert!(
        upstream_rx.recv().await.is_none(),
        "second request should be replayed from cache without hitting upstream"
    );

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[cfg(feature = "scripting")]
#[tokio::test]
async fn on_response_script_mutates_upstream_response_before_return_and_cache() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;
    let temp_dir = tempfile::tempdir().unwrap();
    let storage_dir = temp_dir.path().join("storage");
    fs::create_dir_all(&storage_dir).unwrap();
    let script_path = temp_dir.path().join("on_response.lua");
    fs::write(
        &script_path,
        r#"
function transform(response)
  response.status = 202
  response.headers["x-resp-end"] = "scripted"
  response.headers["x-scripted"] = "1"
  response.body = "scripted-response"
  return response
end
"#,
    )
    .unwrap();

    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[storage]
path = "{}"
active_session = "default"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "passthrough-cache"

[routes.transform]
on_response = "{}"
"#,
        storage_dir.display(),
        script_path.display()
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let uri: Uri = format!("http://{}/api/cache", proxy.listen_addr)
        .parse()
        .unwrap();

    let first_req = Request::builder()
        .method(Method::GET)
        .uri(uri.clone())
        .body(Full::new(Bytes::new()))
        .unwrap();
    let first_res = client.request(first_req).await.unwrap();
    assert_eq!(first_res.status(), StatusCode::ACCEPTED);
    assert_eq!(
        first_res.headers().get("x-scripted").unwrap(),
        &HeaderValue::from_static("1")
    );
    assert_eq!(
        first_res.headers().get("x-resp-end").unwrap(),
        &HeaderValue::from_static("scripted")
    );
    assert_eq!(
        first_res.headers().get("x-resp-binary").unwrap().as_bytes(),
        BINARY_HEADER_VALUE
    );
    let first_body = first_res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&first_body[..], b"scripted-response");

    let captured = upstream_rx.recv().await.unwrap();
    assert_eq!(captured.uri.path(), "/api/cache");
    assert_eq!(&captured.body[..], b"");

    let second_req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let second_res = client.request(second_req).await.unwrap();
    assert_eq!(second_res.status(), StatusCode::ACCEPTED);
    assert_eq!(
        second_res.headers().get("x-scripted").unwrap(),
        &HeaderValue::from_static("1")
    );
    assert_eq!(
        second_res.headers().get("x-resp-end").unwrap(),
        &HeaderValue::from_static("scripted")
    );
    assert_eq!(
        second_res
            .headers()
            .get("x-resp-binary")
            .unwrap()
            .as_bytes(),
        BINARY_HEADER_VALUE
    );
    let second_body = second_res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&second_body[..], b"scripted-response");

    assert!(
        upstream_rx.recv().await.is_none(),
        "second request should be replayed from cache without hitting upstream"
    );

    let db_path = storage_dir.join("default").join("recordings.db");
    let conn = Connection::open(db_path).unwrap();
    let (stored_status, stored_headers, stored_body): (u16, String, Vec<u8>) = conn
        .query_row(
            "SELECT response_status, response_headers_json, response_body FROM recordings LIMIT 1;",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(stored_status, StatusCode::ACCEPTED.as_u16());
    let stored_headers: Vec<(String, Vec<u8>)> = serde_json::from_str(&stored_headers).unwrap();
    assert_eq!(
        stored_headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("x-scripted"))
            .map(|(_, value)| value.as_slice()),
        Some(b"1".as_slice())
    );
    assert_eq!(
        stored_headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("x-resp-end"))
            .map(|(_, value)| value.as_slice()),
        Some(b"scripted".as_slice())
    );
    assert_eq!(
        stored_headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("x-resp-binary"))
            .map(|(_, value)| value.as_slice()),
        Some(BINARY_HEADER_VALUE)
    );
    assert_eq!(&stored_body[..], b"scripted-response");

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[cfg(feature = "scripting")]
#[tokio::test]
async fn on_record_script_mutates_persisted_recording_without_changing_live_response() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;
    let temp_dir = tempfile::tempdir().unwrap();
    let storage_dir = temp_dir.path().join("storage");
    fs::create_dir_all(&storage_dir).unwrap();
    let script_path = temp_dir.path().join("on_record.lua");
    fs::write(
        &script_path,
        r#"
function transform(recording)
  recording.request.headers["authorization"] = "[REDACTED]"
  recording.request.body = "{\"stored\":true}"
  recording.response.status = 203
  recording.response.headers["x-recorded"] = "1"
  recording.response.body = "stored-response"
  return recording
end
"#,
    )
    .unwrap();

    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[storage]
path = "{}"
active_session = "default"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "record"

[routes.transform]
on_record = "{}"
"#,
        storage_dir.display(),
        script_path.display()
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let uri: Uri = format!("http://{}/api/store", proxy.listen_addr)
        .parse()
        .unwrap();

    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::AUTHORIZATION, "Bearer live-token")
        .body(Full::new(Bytes::from_static(br#"{"live":true}"#)))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    assert!(res.headers().get("x-recorded").is_none());
    assert_eq!(
        res.headers().get("x-resp-binary").unwrap().as_bytes(),
        BINARY_HEADER_VALUE
    );
    let body = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), b"upstream-body");

    let captured = upstream_rx.recv().await.unwrap();
    assert_eq!(captured.uri.path(), "/api/store");
    assert_eq!(captured.body.as_ref(), br#"{"live":true}"#);

    let db_path = storage_dir.join("default").join("recordings.db");
    let conn = Connection::open(db_path).unwrap();
    let (request_headers, response_status, response_headers, request_body, response_body): (
        String,
        u16,
        String,
        Vec<u8>,
        Vec<u8>,
    ) = conn
        .query_row(
            "SELECT request_headers_json, response_status, response_headers_json, request_body, response_body FROM recordings LIMIT 1;",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .unwrap();
    let request_headers: Vec<(String, Vec<u8>)> = serde_json::from_str(&request_headers).unwrap();
    let response_headers: Vec<(String, Vec<u8>)> = serde_json::from_str(&response_headers).unwrap();
    assert_eq!(
        request_headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.as_slice()),
        Some(b"[REDACTED]".as_slice())
    );
    assert_eq!(response_status, 203);
    assert_eq!(
        response_headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("x-recorded"))
            .map(|(_, value)| value.as_slice()),
        Some(b"1".as_slice())
    );
    assert_eq!(
        response_headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("x-resp-binary"))
            .map(|(_, value)| value.as_slice()),
        Some(BINARY_HEADER_VALUE)
    );
    assert_eq!(request_body.as_slice(), br#"{"stored":true}"#);
    assert_eq!(response_body.as_slice(), b"stored-response");

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[cfg(feature = "scripting")]
#[tokio::test]
async fn on_replay_script_mutates_cached_response_without_changing_stored_recording() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;
    let temp_dir = tempfile::tempdir().unwrap();
    let storage_dir = temp_dir.path().join("storage");
    fs::create_dir_all(&storage_dir).unwrap();
    let script_path = temp_dir.path().join("on_replay.lua");
    fs::write(
        &script_path,
        r#"
function transform(response)
  response.status = 202
  response.headers["x-replayed"] = "1"
  response.body = response.body .. "::replayed"
  return response
end
"#,
    )
    .unwrap();

    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[storage]
path = "{}"
active_session = "default"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "passthrough-cache"

[routes.transform]
on_replay = "{}"
"#,
        storage_dir.display(),
        script_path.display()
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let uri: Uri = format!("http://{}/api/replay", proxy.listen_addr)
        .parse()
        .unwrap();

    let req = Request::builder()
        .method(Method::GET)
        .uri(uri.clone())
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    assert!(res.headers().get("x-replayed").is_none());
    assert_eq!(
        res.headers().get("x-resp-binary").unwrap().as_bytes(),
        BINARY_HEADER_VALUE
    );
    let first_body = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(first_body.as_ref(), b"upstream-body");

    let captured = upstream_rx.recv().await.unwrap();
    assert_eq!(captured.uri.path(), "/api/replay");

    let req = Request::builder()
        .method(Method::GET)
        .uri(uri.clone())
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    assert_eq!(
        res.headers().get("x-replayed"),
        Some(&HeaderValue::from_static("1"))
    );
    assert_eq!(
        res.headers().get("x-resp-binary").unwrap().as_bytes(),
        BINARY_HEADER_VALUE
    );
    let second_body = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(second_body.as_ref(), b"upstream-body::replayed");

    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    assert_eq!(
        res.headers().get("x-replayed"),
        Some(&HeaderValue::from_static("1"))
    );
    assert_eq!(
        res.headers().get("x-resp-binary").unwrap().as_bytes(),
        BINARY_HEADER_VALUE
    );
    let third_body = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(third_body.as_ref(), b"upstream-body::replayed");

    assert!(
        upstream_rx.recv().await.is_none(),
        "replayed requests should not hit upstream"
    );

    let db_path = storage_dir.join("default").join("recordings.db");
    let conn = Connection::open(db_path).unwrap();
    let (response_status, response_headers, response_body): (u16, String, Vec<u8>) = conn
        .query_row(
            "SELECT response_status, response_headers_json, response_body FROM recordings LIMIT 1;",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let response_headers: Vec<(String, Vec<u8>)> = serde_json::from_str(&response_headers).unwrap();
    assert_eq!(response_status, StatusCode::CREATED.as_u16());
    assert_eq!(response_body.as_slice(), b"upstream-body");
    assert!(
        response_headers
            .iter()
            .all(|(name, _)| !name.eq_ignore_ascii_case("x-replayed")),
        "stored recording should not be modified by on_replay"
    );
    assert_eq!(
        response_headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("x-resp-binary"))
            .map(|(_, value)| value.as_slice()),
        Some(BINARY_HEADER_VALUE)
    );

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[tokio::test]
async fn forward_proxy_forwards_absolute_form_request_without_configured_upstream() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;

    let config = replayproxy::config::Config::from_toml_str(
        r#"
[proxy]
listen = "127.0.0.1:0"

[[routes]]
path_prefix = "/"
"#,
    )
    .unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let stream = TcpStream::connect(proxy.listen_addr).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, connection) = http1::handshake(io).await.unwrap();
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });

    let absolute_uri: Uri = format!("http://{upstream_addr}/forward/hello?x=1")
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(absolute_uri)
        .header(header::HOST, upstream_addr.to_string())
        .header(header::CONNECTION, "close, x-hop")
        .header("x-hop", "secret")
        .header("x-end", "kept")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = sender.send_request(req).await.unwrap();

    assert_eq!(res.status(), StatusCode::CREATED);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], b"upstream-body");

    let captured = upstream_rx.recv().await.unwrap();
    assert_eq!(captured.uri.path(), "/forward/hello");
    assert_eq!(captured.uri.query(), Some("x=1"));
    assert_eq!(
        captured.headers.get(header::HOST).unwrap(),
        &HeaderValue::from_str(&upstream_addr.to_string()).unwrap()
    );
    assert_eq!(
        captured.headers.get("x-end").unwrap(),
        &HeaderValue::from_static("kept")
    );
    assert!(captured.headers.get("x-hop").is_none());
    assert!(captured.headers.get(header::CONNECTION).is_none());
    assert_eq!(&captured.body[..], b"");

    drop(sender);
    let _ = connection_task.await;
    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[tokio::test]
async fn forward_proxy_supports_http_proxy_environment_variable() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;

    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[[routes]]
path_prefix = "/"
upstream = "http://{upstream_addr}"
"#
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let helper_binary = std::env::current_exe().unwrap();
    let proxy_url = format!("http://{}", proxy.listen_addr);
    let target_url = "http://example.invalid/forward/hello?x=1".to_owned();
    let helper_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(helper_binary)
            .arg("--ignored")
            .arg("--exact")
            .arg("http_client_honors_http_proxy_env_for_forward_proxy_helper")
            .env("REPLAYPROXY_HTTP_PROXY_TEST_HELPER", "1")
            .env("REPLAYPROXY_HTTP_PROXY_TEST_URL", &target_url)
            .env("HTTP_PROXY", &proxy_url)
            .env("http_proxy", &proxy_url)
            .env("ALL_PROXY", &proxy_url)
            .env("all_proxy", &proxy_url)
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .output()
    })
    .await
    .unwrap()
    .unwrap();
    assert!(
        helper_output.status.success(),
        "helper client failed: status={:?}\nstdout:\n{}\nstderr:\n{}",
        helper_output.status.code(),
        String::from_utf8_lossy(&helper_output.stdout),
        String::from_utf8_lossy(&helper_output.stderr),
    );

    let captured = upstream_rx.recv().await.unwrap();
    assert_eq!(captured.uri.path(), "/forward/hello");
    assert_eq!(captured.uri.query(), Some("x=1"));
    assert_eq!(
        captured.headers.get("x-end").unwrap(),
        &HeaderValue::from_static("kept")
    );

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[test]
#[ignore = "invoked by forward_proxy_supports_http_proxy_environment_variable"]
fn http_client_honors_http_proxy_env_for_forward_proxy_helper() {
    if std::env::var_os("REPLAYPROXY_HTTP_PROXY_TEST_HELPER").is_none() {
        return;
    }

    let target_url = std::env::var("REPLAYPROXY_HTTP_PROXY_TEST_URL").unwrap();
    let client = reqwest::blocking::Client::builder().build().unwrap();
    let response = client
        .get(target_url)
        .header("x-end", "kept")
        .send()
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::CREATED);
    let body = response.bytes().unwrap();
    assert_eq!(body.as_ref(), b"upstream-body");
}

#[tokio::test]
async fn forward_proxy_supports_https_proxy_environment_variable_via_connect() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_dir = temp_dir.path().join("ca");
    let ca_paths = replayproxy::ca::generate_ca(&ca_dir, false).unwrap();

    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[proxy.tls]
enabled = true
ca_cert = "{}"
ca_key = "{}"

[[routes]]
path_prefix = "/"
upstream = "http://{upstream_addr}"
"#,
        ca_paths.cert_path.display(),
        ca_paths.key_path.display(),
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let helper_binary = std::env::current_exe().unwrap();
    let proxy_url = format!("http://{}", proxy.listen_addr);
    let target_url = "https://example.invalid/forward/hello?x=1".to_owned();
    let helper_output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(helper_binary)
            .arg("--ignored")
            .arg("--exact")
            .arg("http_client_honors_https_proxy_env_for_forward_proxy_helper")
            .env("REPLAYPROXY_HTTPS_PROXY_TEST_HELPER", "1")
            .env("REPLAYPROXY_HTTPS_PROXY_TEST_URL", &target_url)
            .env("HTTPS_PROXY", &proxy_url)
            .env("https_proxy", &proxy_url)
            .env_remove("HTTP_PROXY")
            .env_remove("http_proxy")
            .env_remove("ALL_PROXY")
            .env_remove("all_proxy")
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .output()
    })
    .await
    .unwrap()
    .unwrap();
    assert!(
        helper_output.status.success(),
        "helper client failed: status={:?}\nstdout:\n{}\nstderr:\n{}",
        helper_output.status.code(),
        String::from_utf8_lossy(&helper_output.stdout),
        String::from_utf8_lossy(&helper_output.stderr),
    );

    let captured = upstream_rx.recv().await.unwrap();
    assert_eq!(captured.uri.path(), "/forward/hello");
    assert_eq!(captured.uri.query(), Some("x=1"));
    assert_eq!(
        captured.headers.get("x-end").unwrap(),
        &HeaderValue::from_static("kept")
    );

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[test]
#[ignore = "invoked by forward_proxy_supports_https_proxy_environment_variable_via_connect"]
fn http_client_honors_https_proxy_env_for_forward_proxy_helper() {
    if std::env::var_os("REPLAYPROXY_HTTPS_PROXY_TEST_HELPER").is_none() {
        return;
    }

    let target_url = std::env::var("REPLAYPROXY_HTTPS_PROXY_TEST_URL").unwrap();
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let response = client
        .get(target_url)
        .header("x-end", "kept")
        .send()
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::CREATED);
    let body = response.bytes().unwrap();
    assert_eq!(body.as_ref(), b"upstream-body");
}

#[tokio::test]
async fn forward_proxy_connect_establishes_bidirectional_tunnel() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_connect_upstream().await;

    let config = replayproxy::config::Config::from_toml_str(
        r#"
[proxy]
listen = "127.0.0.1:0"

[[routes]]
path_prefix = "/"
"#,
    )
    .unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let mut stream = TcpStream::connect(proxy.listen_addr).await.unwrap();
    let connect_request = format!(
        "CONNECT {upstream_addr} HTTP/1.1\r\nHost: {upstream_addr}\r\nProxy-Connection: keep-alive\r\n\r\n"
    );
    stream.write_all(connect_request.as_bytes()).await.unwrap();

    let response_head = read_http_response_head(&mut stream).await;
    assert!(
        response_head.starts_with(b"HTTP/1.1 200"),
        "unexpected CONNECT response: {}",
        String::from_utf8_lossy(&response_head)
    );

    stream.write_all(b"hello").await.unwrap();
    let mut first_reply = [0u8; 5];
    stream.read_exact(&mut first_reply).await.unwrap();
    assert_eq!(&first_reply, b"world");

    stream.write_all(b"ping").await.unwrap();
    let mut second_reply = [0u8; 4];
    stream.read_exact(&mut second_reply).await.unwrap();
    assert_eq!(&second_reply, b"pong");

    let first_capture = upstream_rx.recv().await.unwrap();
    assert_eq!(first_capture.as_ref(), b"hello");
    let second_capture = upstream_rx.recv().await.unwrap();
    assert_eq!(second_capture.as_ref(), b"ping");

    drop(stream);
    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[tokio::test]
async fn websocket_upgrade_route_relays_frames_bidirectionally() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_websocket_upstream().await;

    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[[routes]]
path_prefix = "/ws"
upstream = "http://{upstream_addr}"

[routes.websocket]
recording_mode = "bidirectional"
"#
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let ws_url = format!("ws://{}/ws/echo", proxy.listen_addr);
    let (mut ws_stream, response) = connect_async(ws_url).await.unwrap();
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);

    let Some(Ok(Message::Text(greeting))) = ws_stream.next().await else {
        panic!("expected upstream greeting frame");
    };
    assert_eq!(greeting.to_string(), "upstream-ready");

    ws_stream
        .send(Message::Text("hello-proxy".into()))
        .await
        .unwrap();
    let Some(Ok(Message::Text(ack))) = ws_stream.next().await else {
        panic!("expected upstream ack frame");
    };
    assert_eq!(ack.to_string(), "ack:hello-proxy");

    let captured = upstream_rx.recv().await.unwrap();
    assert_eq!(captured, "hello-proxy");

    ws_stream.close(None).await.unwrap();
    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[tokio::test]
async fn websocket_record_mode_server_only_records_only_server_to_client_frames() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_websocket_upstream().await;
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
path_prefix = "/ws"
upstream = "http://{upstream_addr}"
mode = "record"

[routes.websocket]
recording_mode = "server-only"
"#,
        storage_dir.path().display(),
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let ws_url = format!("ws://{}/ws/echo", proxy.listen_addr);
    let (mut ws_stream, response) = connect_async(ws_url).await.unwrap();
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);

    let Some(Ok(Message::Text(greeting))) = ws_stream.next().await else {
        panic!("expected upstream greeting frame");
    };
    assert_eq!(greeting.to_string(), "upstream-ready");

    ws_stream
        .send(Message::Text("hello-proxy".into()))
        .await
        .unwrap();
    let Some(Ok(Message::Text(ack))) = ws_stream.next().await else {
        panic!("expected upstream ack frame");
    };
    assert_eq!(ack.to_string(), "ack:hello-proxy");

    let captured = upstream_rx.recv().await.unwrap();
    assert_eq!(captured, "hello-proxy");

    ws_stream.close(None).await.unwrap();
    proxy.shutdown().await;
    let _ = upstream_shutdown().await;

    let db_path = storage_dir.path().join(session).join("recordings.db");
    let storage = Storage::open(db_path).unwrap();
    let mut recordings = Vec::new();
    let mut frames = Vec::new();
    for _ in 0..40 {
        recordings = storage.list_recordings(0, 10).await.unwrap();
        if let Some(recording) = recordings.first() {
            frames = storage.get_websocket_frames(recording.id).await.unwrap();
            if frames.len() == 2 {
                break;
            }
        }
        sleep(Duration::from_millis(25)).await;
    }

    assert_eq!(recordings.len(), 1);
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].frame_index, 0);
    assert_eq!(frames[1].frame_index, 1);
    assert!(frames[0].offset_ms <= frames[1].offset_ms);
    assert_eq!(frames[0].direction, WebSocketFrameDirection::ServerToClient);
    assert_eq!(frames[1].direction, WebSocketFrameDirection::ServerToClient);
    assert_eq!(frames[0].message_type, WebSocketMessageType::Text);
    assert_eq!(frames[1].message_type, WebSocketMessageType::Text);
    assert_eq!(frames[0].payload, b"upstream-ready".to_vec());
    assert_eq!(frames[1].payload, b"ack:hello-proxy".to_vec());
}

#[tokio::test]
async fn https_connect_mitm_records_and_replays_requests() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_dir = temp_dir.path().join("ca");
    let ca_paths = replayproxy::ca::generate_ca(&ca_dir, false).unwrap();
    let storage_dir = temp_dir.path().join("storage");
    let session = "default";

    let record_config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[proxy.tls]
enabled = true
ca_cert = "{}"
ca_key = "{}"

[storage]
path = "{}"
active_session = "{session}"

[[routes]]
path_prefix = "/"
upstream = "http://{upstream_addr}"
mode = "record"
"#,
        ca_paths.cert_path.display(),
        ca_paths.key_path.display(),
        storage_dir.display(),
    );
    let record_config = replayproxy::config::Config::from_toml_str(&record_config_toml).unwrap();
    let record_proxy = replayproxy::proxy::serve(&record_config).await.unwrap();
    let tls_client_config = tls_client_config_for_ca_cert(&ca_paths.cert_path);

    let (record_status, record_body) = send_https_get_via_connect(
        record_proxy.listen_addr,
        "api.example.test:443",
        "api.example.test",
        Arc::clone(&tls_client_config),
        "/api/mitm?x=1",
    )
    .await;
    assert_eq!(record_status, StatusCode::CREATED);
    assert_eq!(record_body, Bytes::from_static(b"upstream-body"));

    let captured = upstream_rx.recv().await.unwrap();
    assert_eq!(captured.uri.path(), "/api/mitm");
    assert_eq!(captured.uri.query(), Some("x=1"));

    record_proxy.shutdown().await;
    let _ = upstream_shutdown().await;

    let replay_config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[proxy.tls]
enabled = true
ca_cert = "{}"
ca_key = "{}"

[storage]
path = "{}"
active_session = "{session}"

[[routes]]
path_prefix = "/"
upstream = "http://127.0.0.1:9"
mode = "replay"
cache_miss = "error"
"#,
        ca_paths.cert_path.display(),
        ca_paths.key_path.display(),
        storage_dir.display(),
    );
    let replay_config = replayproxy::config::Config::from_toml_str(&replay_config_toml).unwrap();
    let replay_proxy = replayproxy::proxy::serve(&replay_config).await.unwrap();

    let (replay_status, replay_body) = send_https_get_via_connect(
        replay_proxy.listen_addr,
        "api.example.test:443",
        "api.example.test",
        tls_client_config,
        "/api/mitm?x=1",
    )
    .await;
    assert_eq!(replay_status, StatusCode::CREATED);
    assert_eq!(replay_body, Bytes::from_static(b"upstream-body"));

    replay_proxy.shutdown().await;
}

#[tokio::test]
async fn https_connect_mitm_replay_streaming_preserves_chunk_boundaries() {
    let expected_chunks = vec![
        Bytes::from_static(b"data: first\n\n"),
        Bytes::from_static(b"data: second\n\n"),
        Bytes::from_static(b"data: done\n\n"),
    ];
    let (upstream_addr, mut upstream_rx, upstream_shutdown) =
        spawn_upstream_with_response_chunks(expected_chunks.clone()).await;
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_dir = temp_dir.path().join("ca");
    let ca_paths = replayproxy::ca::generate_ca(&ca_dir, false).unwrap();
    let storage_dir = temp_dir.path().join("storage");
    let session = "default";
    let expected_body = Bytes::from_static(b"data: first\n\ndata: second\n\ndata: done\n\n");

    let record_config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[proxy.tls]
enabled = true
ca_cert = "{}"
ca_key = "{}"

[storage]
path = "{}"
active_session = "{session}"

[[routes]]
path_prefix = "/"
upstream = "http://{upstream_addr}"
mode = "record"

[routes.streaming]
preserve_timing = false
"#,
        ca_paths.cert_path.display(),
        ca_paths.key_path.display(),
        storage_dir.display(),
    );
    let record_config = replayproxy::config::Config::from_toml_str(&record_config_toml).unwrap();
    let record_proxy = replayproxy::proxy::serve(&record_config).await.unwrap();
    let tls_client_config = tls_client_config_for_ca_cert(&ca_paths.cert_path);

    let (record_status, record_body) = send_https_get_via_connect(
        record_proxy.listen_addr,
        "api.example.test:443",
        "api.example.test",
        Arc::clone(&tls_client_config),
        "/api/stream",
    )
    .await;
    assert_eq!(record_status, StatusCode::CREATED);
    assert_eq!(record_body, expected_body);

    let captured = upstream_rx.recv().await.unwrap();
    assert_eq!(captured.uri.path(), "/api/stream");

    let db_path = storage_dir.join(session).join("recordings.db");
    let conn = Connection::open(db_path).unwrap();
    let mut stmt = conn
        .prepare(
            r#"
            SELECT chunk_index, offset_ms, chunk_body
            FROM recording_response_chunks
            ORDER BY chunk_index ASC
            "#,
        )
        .unwrap();
    let mut rows = stmt.query([]).unwrap();
    let mut recorded_chunks = Vec::new();
    while let Some(row) = rows.next().unwrap() {
        recorded_chunks.push((
            row.get::<_, i64>(0).unwrap(),
            row.get::<_, i64>(1).unwrap(),
            row.get::<_, Vec<u8>>(2).unwrap(),
        ));
    }
    assert_eq!(recorded_chunks.len(), expected_chunks.len());
    for (index, expected_chunk) in expected_chunks.iter().enumerate() {
        let (stored_index, _, stored_body) = &recorded_chunks[index];
        assert_eq!(*stored_index, i64::try_from(index).unwrap());
        assert_eq!(stored_body.as_slice(), expected_chunk.as_ref());
    }

    record_proxy.shutdown().await;
    let _ = upstream_shutdown().await;

    let replay_config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[proxy.tls]
enabled = true
ca_cert = "{}"
ca_key = "{}"

[storage]
path = "{}"
active_session = "{session}"

[[routes]]
path_prefix = "/"
upstream = "http://127.0.0.1:9"
mode = "replay"
cache_miss = "error"

[routes.streaming]
preserve_timing = false
"#,
        ca_paths.cert_path.display(),
        ca_paths.key_path.display(),
        storage_dir.display(),
    );
    let replay_config = replayproxy::config::Config::from_toml_str(&replay_config_toml).unwrap();
    let replay_proxy = replayproxy::proxy::serve(&replay_config).await.unwrap();

    let (replay_status, replay_chunks) = send_https_get_chunks_via_connect(
        replay_proxy.listen_addr,
        "api.example.test:443",
        "api.example.test",
        tls_client_config,
        "/api/stream",
    )
    .await;
    assert_eq!(replay_status, StatusCode::CREATED);
    assert_eq!(replay_chunks, expected_chunks);

    replay_proxy.shutdown().await;
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
    let join = upstream_shutdown();
    join.abort();
    let _ = join.await;
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
    let join = upstream_shutdown();
    join.abort();
    let _ = join.await;
}

#[cfg(feature = "scripting")]
#[tokio::test]
async fn oversized_request_body_with_on_request_transform_returns_413() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;
    let temp_dir = tempfile::tempdir().unwrap();
    let script_path = temp_dir.path().join("on_request.lua");
    fs::write(
        &script_path,
        r#"
function transform(request)
  request.headers["x-from-script"] = "1"
  return request
end
"#,
    )
    .unwrap();

    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"
max_body_bytes = 8

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "passthrough-cache"
body_oversize = "bypass-cache"

[routes.transform]
on_request = "{}"
"#,
        script_path.display()
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
        "upstream should not receive oversized requests when on_request transform is configured"
    );

    proxy.shutdown().await;
    let join = upstream_shutdown();
    join.abort();
    let _ = join.await;
}

#[cfg(feature = "scripting")]
#[tokio::test]
async fn oversized_chunked_request_body_with_on_request_transform_returns_413() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;
    let temp_dir = tempfile::tempdir().unwrap();
    let script_path = temp_dir.path().join("on_request.lua");
    fs::write(
        &script_path,
        r#"
function transform(request)
  request.headers["x-from-script"] = "1"
  return request
end
"#,
    )
    .unwrap();

    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"
max_body_bytes = 8

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "passthrough-cache"
body_oversize = "bypass-cache"

[routes.transform]
on_request = "{}"
"#,
        script_path.display()
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
        "upstream should not receive oversized chunked requests when on_request transform is configured"
    );

    proxy.shutdown().await;
    let join = upstream_shutdown();
    join.abort();
    let _ = join.await;
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
    let join = upstream_shutdown();
    join.abort();
    let _ = join.await;
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
async fn record_mode_persists_chunked_response_chunks_with_offsets() {
    let expected_chunks = vec![
        Bytes::from_static(b"data: first\n\n"),
        Bytes::from_static(b"data: second\n\n"),
        Bytes::from_static(b"data: done\n\n"),
    ];
    let (upstream_addr, mut upstream_rx, upstream_shutdown) =
        spawn_upstream_with_response_chunks(expected_chunks.clone()).await;

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

    let proxy_uri: Uri = format!("http://{}/api/stream", proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(proxy_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let response_body = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        response_body,
        Bytes::from_static(b"data: first\n\ndata: second\n\ndata: done\n\n")
    );

    let captured = upstream_rx.recv().await.unwrap();
    assert_eq!(captured.uri.path(), "/api/stream");

    let db_path = storage_dir.path().join(session).join("recordings.db");
    let conn = Connection::open(db_path).unwrap();
    let mut stmt = conn
        .prepare(
            r#"
            SELECT chunk_index, offset_ms, chunk_body
            FROM recording_response_chunks
            ORDER BY chunk_index ASC
            "#,
        )
        .unwrap();
    let mut rows = stmt.query([]).unwrap();
    let mut actual_chunks = Vec::new();
    while let Some(row) = rows.next().unwrap() {
        actual_chunks.push((
            row.get::<_, i64>(0).unwrap(),
            row.get::<_, i64>(1).unwrap(),
            row.get::<_, Vec<u8>>(2).unwrap(),
        ));
    }

    assert_eq!(actual_chunks.len(), expected_chunks.len());
    for (index, expected_chunk) in expected_chunks.iter().enumerate() {
        let (stored_index, _, stored_body) = &actual_chunks[index];
        assert_eq!(*stored_index, i64::try_from(index).unwrap());
        assert_eq!(stored_body.as_slice(), expected_chunk.as_ref());
    }
    for offsets in actual_chunks.windows(2) {
        assert!(offsets[0].1 <= offsets[1].1);
    }

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[tokio::test]
async fn replay_streaming_preserve_timing_replays_slower_than_fast_mode() {
    let storage_dir = tempfile::tempdir().unwrap();
    let session = "default";
    seed_streaming_replay_recording(storage_dir.path(), session).await;

    let (preserve_elapsed, preserve_body) =
        replay_streaming_elapsed(storage_dir.path(), session, true).await;
    let (fast_elapsed, fast_body) =
        replay_streaming_elapsed(storage_dir.path(), session, false).await;

    let expected_body = Bytes::from_static(b"data: first\n\ndata: second\n\ndata: done\n\n");
    assert_eq!(preserve_body, expected_body);
    assert_eq!(fast_body, expected_body);
    assert!(
        preserve_elapsed >= Duration::from_millis(180),
        "expected preserve_timing replay to take at least ~180ms, got {preserve_elapsed:?}"
    );
    assert!(
        preserve_elapsed > fast_elapsed + Duration::from_millis(100),
        "expected preserve_timing replay to be noticeably slower; preserve={preserve_elapsed:?}, fast={fast_elapsed:?}"
    );
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
async fn admin_mode_endpoint_switches_runtime_mode_without_restart() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;

    let storage_dir = tempfile::tempdir().unwrap();
    let session = "default";
    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"
admin_port = 0
mode = "record"

[storage]
path = "{}"
active_session = "{session}"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
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

    let mode_uri: Uri = format!("http://{admin_addr}/_admin/mode").parse().unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(mode_uri.clone())
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = response_json(res).await;
    assert!(body["runtime_override_mode"].is_null());
    assert_eq!(body["default_mode"].as_str(), Some("record"));

    let mode_payload = serde_json::json!({
        "mode": "replay",
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri(mode_uri.clone())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(
            serde_json::to_vec(&mode_payload).unwrap(),
        )))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = response_json(res).await;
    assert_eq!(body["runtime_override_mode"].as_str(), Some("replay"));
    assert_eq!(body["default_mode"].as_str(), Some("record"));

    let replay_miss_uri: Uri = format!("http://{}/api/after-switch?mode=miss", proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(replay_miss_uri)
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
    let body: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body["error"].as_str(), Some("Gateway Not Recorded"));
    assert!(
        timeout(Duration::from_millis(150), upstream_rx.recv())
            .await
            .is_err(),
        "replay-mode cache miss should not call upstream"
    );

    let db_path = storage_dir.path().join(session).join("recordings.db");
    let conn = Connection::open(db_path).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM recordings;", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);

    proxy.shutdown().await;
    let join = upstream_shutdown();
    join.abort();
    let _ = join.await;
}

#[tokio::test]
async fn admin_mode_endpoint_returns_informative_errors() {
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

    let mode_uri: Uri = format!("http://{admin_addr}/_admin/mode").parse().unwrap();
    let req = Request::builder()
        .method(Method::PUT)
        .uri(mode_uri.clone())
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

    let req = Request::builder()
        .method(Method::POST)
        .uri(mode_uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from_static(b"{\"mode\":\"invalid\"}")))
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

    proxy.shutdown().await;
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
    assert_eq!(body["routes_added"].as_u64(), Some(0));
    assert_eq!(body["routes_removed"].as_u64(), Some(0));
    assert_eq!(body["routes_changed"].as_u64(), Some(1));
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
async fn admin_config_reload_endpoint_reports_route_diff_without_key_setting_changes() {
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
max_body_bytes = 64

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
    assert_eq!(body["routes_added"].as_u64(), Some(0));
    assert_eq!(body["routes_removed"].as_u64(), Some(0));
    assert_eq!(body["routes_changed"].as_u64(), Some(1));
    assert_eq!(body["max_body_bytes_before"].as_u64(), Some(64));
    assert_eq!(body["max_body_bytes_after"].as_u64(), Some(64));
    assert_eq!(body["changed"].as_bool(), Some(true));

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
async fn config_watcher_applies_config_updates_from_active_source_path() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;
    let config_dir = tempfile::tempdir().unwrap();
    let config_path = config_dir.path().join("replayproxy.toml");

    fs::write(
        &config_path,
        format!(
            r#"
[proxy]
listen = "127.0.0.1:0"

[[routes]]
path_prefix = "/v1"
upstream = "http://{upstream_addr}"
"#
        ),
    )
    .unwrap();

    let config = replayproxy::config::Config::from_path(&config_path).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

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

[[routes]]
path_prefix = "/v2"
upstream = "http://{upstream_addr}"
"#
        ),
    )
    .unwrap();

    let new_route_uri: Uri = format!("http://{}/v2/watched", proxy.listen_addr)
        .parse()
        .unwrap();
    wait_for_proxy_status(
        &client,
        new_route_uri,
        StatusCode::CREATED,
        Duration::from_secs(4),
    )
    .await;

    let captured = upstream_rx.recv().await.unwrap();
    assert_eq!(captured.uri.path(), "/v2/watched");

    let stale_route_uri: Uri = format!("http://{}/v1/stale", proxy.listen_addr)
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

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[tokio::test]
async fn config_watcher_debounces_rapid_file_changes() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream().await;
    let config_dir = tempfile::tempdir().unwrap();
    let config_path = config_dir.path().join("replayproxy.toml");

    fs::write(
        &config_path,
        format!(
            r#"
[proxy]
listen = "127.0.0.1:0"

[[routes]]
path_prefix = "/v1"
upstream = "http://{upstream_addr}"
"#
        ),
    )
    .unwrap();

    let config = replayproxy::config::Config::from_path(&config_path).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

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

[[routes]]
path_prefix = "/v2"
upstream = "http://{upstream_addr}"
"#
        ),
    )
    .unwrap();
    sleep(Duration::from_millis(20)).await;
    fs::write(
        &config_path,
        format!(
            r#"
[proxy]
listen = "127.0.0.1:0"

[[routes]]
path_prefix = "/v3"
upstream = "http://{upstream_addr}"
"#
        ),
    )
    .unwrap();

    let first_update_uri: Uri = format!(
        "http://{}/v2/should-not-apply-immediately",
        proxy.listen_addr
    )
    .parse()
    .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(first_update_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let _ = res.into_body().collect().await.unwrap().to_bytes();
    assert!(
        timeout(Duration::from_millis(150), upstream_rx.recv())
            .await
            .is_err()
    );

    let second_update_uri: Uri = format!("http://{}/v3/debounced", proxy.listen_addr)
        .parse()
        .unwrap();
    wait_for_proxy_status(
        &client,
        second_update_uri,
        StatusCode::CREATED,
        Duration::from_secs(4),
    )
    .await;

    let captured = upstream_rx.recv().await.unwrap();
    assert_eq!(captured.uri.path(), "/v3/debounced");

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
async fn admin_session_export_endpoint_honors_yaml_format_and_returns_json_result() {
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
        "format": "yaml",
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
    assert_eq!(body["format"].as_str(), Some("yaml"));
    assert_eq!(
        body["output_dir"].as_str().map(std::path::PathBuf::from),
        Some(output_dir.clone())
    );

    let manifest_path = body["manifest_path"].as_str().map(std::path::PathBuf::from);
    assert_eq!(manifest_path, Some(output_dir.join("index.yaml")));
    assert!(manifest_path.as_ref().unwrap().exists());

    let manifest_bytes = fs::read(manifest_path.unwrap()).unwrap();
    let manifest: Value = serde_yaml::from_slice(&manifest_bytes).unwrap();
    assert_eq!(manifest["session"].as_str(), Some(session_name));
    assert_eq!(manifest["format"].as_str(), Some("yaml"));
    assert_eq!(manifest["recordings"].as_array().map(Vec::len), Some(1));

    let recordings = fs::read_dir(output_dir.join("recordings"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(recordings.len(), 1);
    assert_eq!(
        recordings[0]
            .path()
            .extension()
            .and_then(std::ffi::OsStr::to_str),
        Some("yaml")
    );

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
        br#"{"version":3,"session":"default","format":"json","exported_at_unix_ms":0,"recordings":[]}"#,
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
async fn admin_session_export_import_round_trip_replays_from_imported_fresh_session() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream_with_responses(vec![
        Bytes::from_static(b"recorded-response-1"),
        Bytes::from_static(b"recorded-response-2"),
    ])
    .await;

    let storage_dir = tempfile::tempdir().unwrap();
    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"
admin_port = 0
mode = "record"

[storage]
path = "{}"
active_session = "default"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
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

    let first_uri: Uri = format!("http://{}/api/chat?turn=1", proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri(first_uri.clone())
        .body(Full::new(Bytes::from_static(br#"{"prompt":"first"}"#)))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], b"recorded-response-1");
    let captured = upstream_rx.recv().await.unwrap();
    assert_eq!(captured.uri.path(), "/api/chat");
    assert_eq!(captured.uri.query(), Some("turn=1"));
    assert_eq!(&captured.body[..], br#"{"prompt":"first"}"#);

    let second_uri: Uri = format!("http://{}/api/models?limit=2", proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(second_uri.clone())
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], b"recorded-response-2");
    let captured = upstream_rx.recv().await.unwrap();
    assert_eq!(captured.uri.path(), "/api/models");
    assert_eq!(captured.uri.query(), Some("limit=2"));
    assert_eq!(&captured.body[..], b"");

    let export_dir = tempfile::tempdir().unwrap();
    let output_dir = export_dir.path().join("session-export");
    let export_uri: Uri = format!("http://{admin_addr}/_admin/sessions/default/export")
        .parse()
        .unwrap();
    let export_payload = serde_json::json!({
        "out_dir": output_dir.to_string_lossy(),
        "format": "json",
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
    let export_body = response_json(res).await;
    assert_eq!(export_body["recordings_exported"].as_u64(), Some(2));
    assert_eq!(
        export_body["manifest_path"].as_str(),
        output_dir.join("index.json").to_str()
    );

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

    let import_uri: Uri = format!("http://{admin_addr}/_admin/sessions/staging/import")
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
    let import_body = response_json(res).await;
    assert_eq!(import_body["recordings_imported"].as_u64(), Some(2));

    let activate_uri: Uri = format!("http://{admin_addr}/_admin/sessions/staging/activate")
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri(activate_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let activate_body = response_json(res).await;
    assert_eq!(activate_body["name"].as_str(), Some("staging"));

    let delete_default_uri: Uri = format!("http://{admin_addr}/_admin/sessions/default")
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::DELETE)
        .uri(delete_default_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    let mode_uri: Uri = format!("http://{admin_addr}/_admin/mode").parse().unwrap();
    let mode_payload = serde_json::json!({
        "mode": "replay",
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri(mode_uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(
            serde_json::to_vec(&mode_payload).unwrap(),
        )))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let mode_body = response_json(res).await;
    assert_eq!(mode_body["runtime_override_mode"].as_str(), Some("replay"));

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
    let status_before_replay = response_json(res).await;
    assert_eq!(
        status_before_replay["active_session"].as_str(),
        Some("staging")
    );
    assert_eq!(
        status_before_replay["stats"]["active_session_recordings_total"].as_u64(),
        Some(2)
    );
    let upstream_total_before_replay = status_before_replay["stats"]["upstream_requests_total"]
        .as_u64()
        .unwrap();
    let cache_hits_before_replay = status_before_replay["stats"]["cache_hits_total"]
        .as_u64()
        .unwrap();

    let req = Request::builder()
        .method(Method::POST)
        .uri(first_uri)
        .body(Full::new(Bytes::from_static(br#"{"prompt":"first"}"#)))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], b"recorded-response-1");

    let req = Request::builder()
        .method(Method::GET)
        .uri(second_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], b"recorded-response-2");

    let req = Request::builder()
        .method(Method::GET)
        .uri(status_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let status_after_replay = response_json(res).await;
    assert_eq!(
        status_after_replay["stats"]["upstream_requests_total"].as_u64(),
        Some(upstream_total_before_replay)
    );
    assert_eq!(
        status_after_replay["stats"]["cache_hits_total"].as_u64(),
        Some(cache_hits_before_replay + 2)
    );

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
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
    let split_one = upstream_response_body.len() / 3;
    let split_two = (upstream_response_body.len() * 2) / 3;
    let expected_chunks = vec![
        Bytes::copy_from_slice(&upstream_response_body[..split_one]),
        Bytes::copy_from_slice(&upstream_response_body[split_one..split_two]),
        Bytes::copy_from_slice(&upstream_response_body[split_two..]),
    ];
    let (upstream_addr, mut upstream_rx, upstream_shutdown) =
        spawn_upstream_with_response_chunks(expected_chunks.clone()).await;

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
    let mut stmt = conn
        .prepare(
            r#"
            SELECT chunk_index, offset_ms, chunk_body
            FROM recording_response_chunks
            ORDER BY chunk_index ASC
            "#,
        )
        .unwrap();
    let mut rows = stmt.query([]).unwrap();
    let mut stored_chunks = Vec::new();
    while let Some(row) = rows.next().unwrap() {
        stored_chunks.push((
            row.get::<_, i64>(0).unwrap(),
            row.get::<_, i64>(1).unwrap(),
            row.get::<_, Vec<u8>>(2).unwrap(),
        ));
    }

    assert!(stored_chunks.len() > 1);
    assert_eq!(stored_chunks.len(), expected_chunks.len());
    for (index, (stored_index, _, _)) in stored_chunks.iter().enumerate() {
        assert_eq!(*stored_index, i64::try_from(index).unwrap());
    }
    for offsets in stored_chunks.windows(2) {
        assert!(offsets[0].1 <= offsets[1].1);
    }

    let reconstructed_chunks = stored_chunks
        .iter()
        .flat_map(|(_, _, chunk_body)| chunk_body.iter().copied())
        .collect::<Vec<_>>();
    assert_eq!(reconstructed_chunks, stored_response_body);
    let reconstructed_text = String::from_utf8_lossy(&reconstructed_chunks);
    assert!(!reconstructed_text.contains("top-secret-1"));
    assert!(!reconstructed_text.contains("top-secret-2"));

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

#[tokio::test]
async fn record_mode_rate_limit_delays_second_request() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream_with_responses(vec![
        Bytes::from_static(b"first-upstream"),
        Bytes::from_static(b"second-upstream"),
    ])
    .await;

    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "record"

[routes.rate_limit]
requests_per_second = 4
burst = 1
"#
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let first_uri: Uri = format!("http://{}/api/first", proxy.listen_addr)
        .parse()
        .unwrap();
    let first_req = Request::builder()
        .method(Method::GET)
        .uri(first_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let first_res = client.request(first_req).await.unwrap();
    assert_eq!(first_res.status(), StatusCode::CREATED);
    let first_body = first_res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&first_body[..], b"first-upstream");

    let second_uri: Uri = format!("http://{}/api/second", proxy.listen_addr)
        .parse()
        .unwrap();
    let second_req = Request::builder()
        .method(Method::GET)
        .uri(second_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let second_started_at = Instant::now();
    let second_res = client.request(second_req).await.unwrap();
    let second_elapsed = second_started_at.elapsed();
    assert_eq!(second_res.status(), StatusCode::CREATED);
    let second_body = second_res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&second_body[..], b"second-upstream");

    assert!(
        second_elapsed >= Duration::from_millis(180),
        "expected record-mode limiter to delay second request; elapsed={second_elapsed:?}"
    );

    let first_captured = upstream_rx.recv().await.unwrap();
    assert_eq!(first_captured.uri.path(), "/api/first");
    let second_captured = upstream_rx.recv().await.unwrap();
    assert_eq!(second_captured.uri.path(), "/api/second");

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[tokio::test]
async fn record_mode_rate_limit_scope_isolated_per_route() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream_with_responses(vec![
        Bytes::from_static(b"route-a-upstream"),
        Bytes::from_static(b"route-b-upstream"),
    ])
    .await;

    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[[routes]]
name = "route-a"
path_exact = "/api/a"
upstream = "http://{upstream_addr}"
mode = "record"

[routes.rate_limit]
requests_per_second = 1
burst = 1

[[routes]]
name = "route-b"
path_exact = "/api/b"
upstream = "http://{upstream_addr}"
mode = "record"

[routes.rate_limit]
requests_per_second = 1
burst = 1
"#
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let first_uri: Uri = format!("http://{}/api/a", proxy.listen_addr)
        .parse()
        .unwrap();
    let first_req = Request::builder()
        .method(Method::GET)
        .uri(first_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let first_res = client.request(first_req).await.unwrap();
    assert_eq!(first_res.status(), StatusCode::CREATED);
    let first_body = first_res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&first_body[..], b"route-a-upstream");

    let second_uri: Uri = format!("http://{}/api/b", proxy.listen_addr)
        .parse()
        .unwrap();
    let second_req = Request::builder()
        .method(Method::GET)
        .uri(second_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let second_started_at = Instant::now();
    let second_res = client.request(second_req).await.unwrap();
    let second_elapsed = second_started_at.elapsed();
    assert_eq!(second_res.status(), StatusCode::CREATED);
    let second_body = second_res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&second_body[..], b"route-b-upstream");

    assert!(
        second_elapsed < Duration::from_millis(700),
        "second route should not share first route's limiter; elapsed={second_elapsed:?}"
    );

    let first_captured = upstream_rx.recv().await.unwrap();
    assert_eq!(first_captured.uri.path(), "/api/a");
    let second_captured = upstream_rx.recv().await.unwrap();
    assert_eq!(second_captured.uri.path(), "/api/b");

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[tokio::test]
async fn record_mode_rate_limit_queue_depth_rejects_when_full() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) = spawn_upstream_with_responses(vec![
        Bytes::from_static(b"first-upstream"),
        Bytes::from_static(b"queued-upstream"),
    ])
    .await;

    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "record"

[routes.rate_limit]
requests_per_second = 1
burst = 1
queue_depth = 1
"#
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let first_uri: Uri = format!("http://{}/api/first", proxy.listen_addr)
        .parse()
        .unwrap();
    let first_req = Request::builder()
        .method(Method::GET)
        .uri(first_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let first_res = client.request(first_req).await.unwrap();
    assert_eq!(first_res.status(), StatusCode::CREATED);
    let first_body = first_res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&first_body[..], b"first-upstream");

    let queued_client = client.clone();
    let queued_uri: Uri = format!("http://{}/api/queued", proxy.listen_addr)
        .parse()
        .unwrap();
    let queued_task = tokio::spawn(async move {
        let queued_req = Request::builder()
            .method(Method::GET)
            .uri(queued_uri)
            .body(Full::new(Bytes::new()))
            .unwrap();
        let queued_started_at = Instant::now();
        let queued_res = queued_client.request(queued_req).await.unwrap();
        let queued_elapsed = queued_started_at.elapsed();
        let queued_status = queued_res.status();
        let queued_body = queued_res.into_body().collect().await.unwrap().to_bytes();
        (queued_status, queued_body, queued_elapsed)
    });

    sleep(Duration::from_millis(50)).await;

    let overflow_uri: Uri = format!("http://{}/api/overflow", proxy.listen_addr)
        .parse()
        .unwrap();
    let overflow_req = Request::builder()
        .method(Method::GET)
        .uri(overflow_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let overflow_started_at = Instant::now();
    let overflow_res = client.request(overflow_req).await.unwrap();
    let overflow_elapsed = overflow_started_at.elapsed();
    assert!(
        overflow_elapsed < Duration::from_millis(400),
        "overflow request should fail fast when queue is full; elapsed={overflow_elapsed:?}"
    );
    assert_eq!(overflow_res.status(), StatusCode::TOO_MANY_REQUESTS);
    let overflow_body = String::from_utf8(
        overflow_res
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(overflow_body.contains("queue is full"));
    assert!(overflow_body.contains("queue_depth=1"));

    let (queued_status, queued_body, queued_elapsed) = queued_task.await.unwrap();
    assert_eq!(queued_status, StatusCode::CREATED);
    assert_eq!(&queued_body[..], b"queued-upstream");
    assert!(
        queued_elapsed >= Duration::from_millis(800),
        "queued request should be delayed by the limiter; elapsed={queued_elapsed:?}"
    );

    let first_captured = upstream_rx.recv().await.unwrap();
    assert_eq!(first_captured.uri.path(), "/api/first");
    let queued_captured = upstream_rx.recv().await.unwrap();
    assert_eq!(queued_captured.uri.path(), "/api/queued");
    match timeout(Duration::from_millis(150), upstream_rx.recv()).await {
        Err(_) | Ok(None) => {}
        Ok(Some(captured)) => panic!(
            "overflow request should not reach upstream, but captured path={}",
            captured.uri.path()
        ),
    }

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[tokio::test]
async fn record_mode_rate_limit_queue_timeout_returns_gateway_timeout() {
    let (upstream_addr, mut upstream_rx, upstream_shutdown) =
        spawn_upstream_with_responses(vec![Bytes::from_static(b"first-upstream")]).await;

    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[[routes]]
path_prefix = "/api"
upstream = "http://{upstream_addr}"
mode = "record"

[routes.rate_limit]
requests_per_second = 1
burst = 1
queue_depth = 4
timeout_ms = 100
"#
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let first_uri: Uri = format!("http://{}/api/first", proxy.listen_addr)
        .parse()
        .unwrap();
    let first_req = Request::builder()
        .method(Method::GET)
        .uri(first_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let first_res = client.request(first_req).await.unwrap();
    assert_eq!(first_res.status(), StatusCode::CREATED);
    let first_body = first_res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&first_body[..], b"first-upstream");

    let timeout_uri: Uri = format!("http://{}/api/timeout", proxy.listen_addr)
        .parse()
        .unwrap();
    let timeout_req = Request::builder()
        .method(Method::GET)
        .uri(timeout_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let timeout_started_at = Instant::now();
    let timeout_res = client.request(timeout_req).await.unwrap();
    let timeout_elapsed = timeout_started_at.elapsed();
    assert!(
        timeout_elapsed < Duration::from_millis(400),
        "queue timeout rejection should happen before full limiter delay; elapsed={timeout_elapsed:?}"
    );
    assert_eq!(timeout_res.status(), StatusCode::GATEWAY_TIMEOUT);
    let timeout_body = String::from_utf8(
        timeout_res
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(timeout_body.contains("queue timeout"));
    assert!(timeout_body.contains("timeout_ms=100"));

    let first_captured = upstream_rx.recv().await.unwrap();
    assert_eq!(first_captured.uri.path(), "/api/first");
    match timeout(Duration::from_millis(150), upstream_rx.recv()).await {
        Err(_) | Ok(None) => {}
        Ok(Some(captured)) => panic!(
            "timed-out request should not reach upstream, but captured path={}",
            captured.uri.path()
        ),
    }

    proxy.shutdown().await;
    let _ = upstream_shutdown().await;
}

#[tokio::test]
async fn replay_mode_rate_limit_returns_429_with_retry_after() {
    let storage_dir = tempfile::tempdir().unwrap();
    let session = "default";
    seed_replay_get_recording(
        storage_dir.path(),
        session,
        "/api/limited",
        b"replayed-body",
    )
    .await;

    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[storage]
path = "{}"
active_session = "{session}"

[[routes]]
path_prefix = "/api"
upstream = "http://127.0.0.1:9"
mode = "replay"

[routes.rate_limit]
requests_per_second = 1
burst = 1
"#,
        storage_dir.path().display()
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let first_uri: Uri = format!("http://{}/api/limited", proxy.listen_addr)
        .parse()
        .unwrap();
    let first_req = Request::builder()
        .method(Method::GET)
        .uri(first_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let first_res = client.request(first_req).await.unwrap();
    assert_eq!(first_res.status(), StatusCode::OK);
    let first_body = first_res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&first_body[..], b"replayed-body");

    let second_uri: Uri = format!("http://{}/api/limited", proxy.listen_addr)
        .parse()
        .unwrap();
    let second_req = Request::builder()
        .method(Method::GET)
        .uri(second_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let second_res = client.request(second_req).await.unwrap();
    assert_eq!(second_res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        second_res
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );
    let second_body = String::from_utf8(
        second_res
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(second_body.contains("replay mode simulated rate limit"));

    sleep(Duration::from_millis(1100)).await;

    let third_uri: Uri = format!("http://{}/api/limited", proxy.listen_addr)
        .parse()
        .unwrap();
    let third_req = Request::builder()
        .method(Method::GET)
        .uri(third_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let third_res = client.request(third_req).await.unwrap();
    assert_eq!(third_res.status(), StatusCode::OK);
    let third_body = third_res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&third_body[..], b"replayed-body");

    proxy.shutdown().await;
}

#[tokio::test]
async fn replay_mode_rate_limit_rejections_are_deterministic() {
    let storage_dir = tempfile::tempdir().unwrap();
    let session = "default";
    seed_replay_get_recording(
        storage_dir.path(),
        session,
        "/api/limited",
        b"replayed-body",
    )
    .await;

    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[storage]
path = "{}"
active_session = "{session}"

[[routes]]
path_prefix = "/api"
upstream = "http://127.0.0.1:9"
mode = "replay"

[routes.rate_limit]
requests_per_second = 1
burst = 1
"#,
        storage_dir.path().display()
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let first_uri: Uri = format!("http://{}/api/limited", proxy.listen_addr)
        .parse()
        .unwrap();
    let first_req = Request::builder()
        .method(Method::GET)
        .uri(first_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let first_res = client.request(first_req).await.unwrap();
    assert_eq!(first_res.status(), StatusCode::OK);
    let _ = first_res.into_body().collect().await.unwrap();

    let second_uri: Uri = format!("http://{}/api/limited", proxy.listen_addr)
        .parse()
        .unwrap();
    let second_req = Request::builder()
        .method(Method::GET)
        .uri(second_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let second_res = client.request(second_req).await.unwrap();
    assert_eq!(second_res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        second_res
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );
    let _ = second_res.into_body().collect().await.unwrap();

    let third_uri: Uri = format!("http://{}/api/limited", proxy.listen_addr)
        .parse()
        .unwrap();
    let third_req = Request::builder()
        .method(Method::GET)
        .uri(third_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let third_res = client.request(third_req).await.unwrap();
    assert_eq!(third_res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        third_res
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );
    let _ = third_res.into_body().collect().await.unwrap();

    proxy.shutdown().await;
}

async fn spawn_connect_upstream() -> (
    SocketAddr,
    mpsc::Receiver<Bytes>,
    impl FnOnce() -> tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel::<Bytes>(2);

    let join = tokio::spawn(async move {
        let (mut stream, _peer) = listener.accept().await.unwrap();

        let mut first_message = vec![0u8; 5];
        stream.read_exact(&mut first_message).await.unwrap();
        tx.send(Bytes::from(first_message)).await.unwrap();
        stream.write_all(b"world").await.unwrap();

        let mut second_message = vec![0u8; 4];
        stream.read_exact(&mut second_message).await.unwrap();
        tx.send(Bytes::from(second_message)).await.unwrap();
        stream.write_all(b"pong").await.unwrap();
    });

    (addr, rx, move || join)
}

async fn spawn_websocket_upstream() -> (
    SocketAddr,
    mpsc::Receiver<String>,
    impl FnOnce() -> tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel::<String>(1);

    let join = tokio::spawn(async move {
        let (stream, _peer) = listener.accept().await.unwrap();
        let mut websocket = accept_async(stream).await.unwrap();
        websocket
            .send(Message::Text("upstream-ready".into()))
            .await
            .unwrap();

        let Some(Ok(message)) = websocket.next().await else {
            panic!("expected one client frame");
        };
        let Message::Text(text) = message else {
            panic!("expected text frame from client");
        };
        let text = text.to_string();
        tx.send(text.clone()).await.unwrap();

        websocket
            .send(Message::Text(format!("ack:{text}").into()))
            .await
            .unwrap();
    });

    (addr, rx, move || join)
}

async fn read_http_response_head(stream: &mut TcpStream) -> Vec<u8> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
        assert!(head.len() <= 16 * 1024, "response headers exceeded limit");
    }
    head
}

fn tls_client_config_for_ca_cert(ca_cert_path: &Path) -> Arc<ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert_pem = fs::read(ca_cert_path).unwrap();
    let (_, pem_block) = parse_x509_pem(&cert_pem).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(pem_block.contents)).unwrap();
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

async fn send_https_get_via_connect(
    proxy_addr: SocketAddr,
    connect_authority: &str,
    tls_server_name: &str,
    tls_client_config: Arc<ClientConfig>,
    request_uri: &str,
) -> (StatusCode, Bytes) {
    let (status, chunks) = send_https_get_chunks_via_connect(
        proxy_addr,
        connect_authority,
        tls_server_name,
        tls_client_config,
        request_uri,
    )
    .await;

    let total_len: usize = chunks.iter().map(Bytes::len).sum();
    let mut body = Vec::with_capacity(total_len);
    for chunk in chunks {
        body.extend_from_slice(chunk.as_ref());
    }

    (status, Bytes::from(body))
}

async fn send_https_get_chunks_via_connect(
    proxy_addr: SocketAddr,
    connect_authority: &str,
    tls_server_name: &str,
    tls_client_config: Arc<ClientConfig>,
    request_uri: &str,
) -> (StatusCode, Vec<Bytes>) {
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let connect_request = format!(
        "CONNECT {connect_authority} HTTP/1.1\r\nHost: {connect_authority}\r\nProxy-Connection: keep-alive\r\n\r\n"
    );
    stream.write_all(connect_request.as_bytes()).await.unwrap();

    let response_head = read_http_response_head(&mut stream).await;
    assert!(
        response_head.starts_with(b"HTTP/1.1 200"),
        "unexpected CONNECT response: {}",
        String::from_utf8_lossy(&response_head)
    );

    let connector = TlsConnector::from(tls_client_config);
    let tls_server_name = ServerName::try_from(tls_server_name.to_owned()).unwrap();
    let tls_stream = connector.connect(tls_server_name, stream).await.unwrap();

    let io = TokioIo::new(tls_stream);
    let (mut sender, connection) = http1::handshake(io).await.unwrap();
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });

    let req = Request::builder()
        .method(Method::GET)
        .uri(request_uri)
        .header(header::HOST, connect_authority)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = sender.send_request(req).await.unwrap();
    let status = res.status();
    let mut body = res.into_body();
    let mut chunks = Vec::new();
    while let Some(frame_result) = body.frame().await {
        let frame = frame_result.unwrap();
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if !data.is_empty() {
            chunks.push(data);
        }
    }

    drop(sender);
    let _ = connection_task.await;

    (status, chunks)
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
                    version: parts.version,
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

async fn spawn_grpc_upstream() -> (
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
                    version: parts.version,
                    headers: parts.headers,
                    body: body_bytes,
                })
                .await
                .unwrap();

                let mut res = Response::new(Full::new(Bytes::from_static(b"\x00\x00\x00\x00\x00")));
                *res.status_mut() = StatusCode::OK;
                res.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/grpc"),
                );
                res.headers_mut()
                    .insert("grpc-status", HeaderValue::from_static("0"));
                Ok::<_, hyper::Error>(res)
            }
        });

        let builder = ConnectionBuilder::new(TokioExecutor::new());
        builder.serve_connection(io, service).await.unwrap();
    });

    (addr, rx, move || join)
}

#[cfg(feature = "grpc")]
fn grpc_unary_frame(payload: &[u8]) -> Bytes {
    let mut framed = Vec::with_capacity(payload.len() + 5);
    framed.push(0);
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(payload);
    Bytes::from(framed)
}

#[cfg(feature = "grpc")]
fn encode_predict_request(model_name: &str, input_text: &str, trace_id: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    encode_proto_string_field(1, model_name, &mut encoded);
    encode_proto_string_field(2, input_text, &mut encoded);
    encode_proto_string_field(3, trace_id, &mut encoded);
    encoded
}

#[cfg(feature = "grpc")]
fn encode_proto_string_field(field_number: u32, value: &str, out: &mut Vec<u8>) {
    encode_varint(((field_number << 3) | 2).into(), out);
    encode_varint(value.len() as u64, out);
    out.extend_from_slice(value.as_bytes());
}

#[cfg(feature = "grpc")]
fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

async fn spawn_upstream_with_responses(
    response_bodies: Vec<Bytes>,
) -> (
    SocketAddr,
    mpsc::Receiver<CapturedRequest>,
    impl FnOnce() -> tokio::task::JoinHandle<()>,
) {
    assert!(
        !response_bodies.is_empty(),
        "response_bodies must not be empty"
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = mpsc::channel::<CapturedRequest>(response_bodies.len());

    let join = tokio::spawn(async move {
        for response_body in response_bodies {
            let (stream, _peer) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let tx = tx.clone();
            let service = service_fn(move |req: Request<Incoming>| {
                let tx = tx.clone();
                let response_body = response_body.clone();
                async move {
                    let (parts, body) = req.into_parts();
                    let body_bytes = body.collect().await.unwrap().to_bytes();
                    tx.send(CapturedRequest {
                        uri: parts.uri,
                        version: parts.version,
                        headers: parts.headers,
                        body: body_bytes,
                    })
                    .await
                    .unwrap();

                    let mut res = Response::new(Full::new(response_body));
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
        }
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
                    version: parts.version,
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

async fn seed_replay_get_recording(
    storage_root: &std::path::Path,
    session: &str,
    request_uri: &str,
    response_body: &[u8],
) {
    let storage = Storage::open(storage_root.join(session).join("recordings.db")).unwrap();
    let request_uri: Uri = request_uri.parse().unwrap();
    let match_key = replayproxy::matching::compute_match_key(
        None,
        &Method::GET,
        &request_uri,
        &hyper::HeaderMap::new(),
        &[],
    )
    .unwrap();

    let recording = Recording {
        match_key,
        request_method: "GET".to_owned(),
        request_uri: request_uri.to_string(),
        request_headers: Vec::new(),
        request_body: Vec::new(),
        response_status: 200,
        response_headers: vec![("content-type".to_owned(), b"text/plain".to_vec())],
        response_body: response_body.to_vec(),
        created_at_unix_ms: Recording::now_unix_ms().unwrap(),
    };
    storage.insert_recording(recording).await.unwrap();
}

async fn seed_streaming_replay_recording(storage_root: &std::path::Path, session: &str) {
    let storage = Storage::open(storage_root.join(session).join("recordings.db")).unwrap();
    let request_uri: Uri = "/api/stream".parse().unwrap();
    let match_key = replayproxy::matching::compute_match_key(
        None,
        &Method::GET,
        &request_uri,
        &hyper::HeaderMap::new(),
        &[],
    )
    .unwrap();
    let response_body = b"data: first\n\ndata: second\n\ndata: done\n\n".to_vec();
    let recording = Recording {
        match_key,
        request_method: "GET".to_owned(),
        request_uri: "/api/stream".to_owned(),
        request_headers: Vec::new(),
        request_body: Vec::new(),
        response_status: 200,
        response_headers: vec![("content-type".to_owned(), b"text/event-stream".to_vec())],
        response_body,
        created_at_unix_ms: Recording::now_unix_ms().unwrap(),
    };
    let recording_id = storage.insert_recording(recording).await.unwrap();
    storage
        .insert_response_chunks(
            recording_id,
            vec![
                ResponseChunk {
                    chunk_index: 0,
                    offset_ms: 0,
                    chunk_body: b"data: first\n\n".to_vec(),
                },
                ResponseChunk {
                    chunk_index: 1,
                    offset_ms: 120,
                    chunk_body: b"data: second\n\n".to_vec(),
                },
                ResponseChunk {
                    chunk_index: 2,
                    offset_ms: 240,
                    chunk_body: b"data: done\n\n".to_vec(),
                },
            ],
        )
        .await
        .unwrap();
}

async fn replay_streaming_elapsed(
    storage_root: &std::path::Path,
    session: &str,
    preserve_timing: bool,
) -> (Duration, Bytes) {
    let config_toml = format!(
        r#"
[proxy]
listen = "127.0.0.1:0"

[storage]
path = "{}"
active_session = "{session}"

[[routes]]
path_prefix = "/api"
upstream = "http://127.0.0.1:9"
mode = "replay"

[routes.streaming]
preserve_timing = {}
"#,
        storage_root.display(),
        preserve_timing
    );
    let config = replayproxy::config::Config::from_toml_str(&config_toml).unwrap();
    let proxy = replayproxy::proxy::serve(&config).await.unwrap();

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);
    let proxy_uri: Uri = format!("http://{}/api/stream", proxy.listen_addr)
        .parse()
        .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(proxy_uri)
        .body(Full::new(Bytes::new()))
        .unwrap();

    let started_at = std::time::Instant::now();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let elapsed = started_at.elapsed();

    proxy.shutdown().await;
    (elapsed, body)
}

async fn response_json(response: Response<Incoming>) -> Value {
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body_bytes).unwrap()
}

async fn wait_for_proxy_status(
    client: &Client<HttpConnector, Full<Bytes>>,
    uri: Uri,
    expected_status: StatusCode,
    timeout_window: Duration,
) {
    let deadline = std::time::Instant::now() + timeout_window;
    loop {
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri.clone())
            .body(Full::new(Bytes::new()))
            .unwrap();
        let res = client.request(req).await.unwrap();
        let status = res.status();
        let _ = res.into_body().collect().await.unwrap().to_bytes();
        if status == expected_status {
            return;
        }
        assert!(
            std::time::Instant::now() <= deadline,
            "timed out waiting for status {}; last status was {} for {}",
            expected_status,
            status,
            uri
        );
        sleep(Duration::from_millis(25)).await;
    }
}

fn json_bytes(value: &Value) -> Vec<u8> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|item| u8::try_from(item.as_u64().unwrap()).unwrap())
        .collect()
}
