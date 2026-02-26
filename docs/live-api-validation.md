# Live API Validation Runbook

## Purpose

Run an opt-in, release-hardening validation suite against real external APIs to confirm:

- reverse proxy record/replay works over HTTP and HTTPS
- forward proxy CONNECT + MITM works in `passthrough-cache`
- configured request redaction is persisted in recordings

This runbook is intentionally manual and is not part of default CI.

## Opt-In Environment Variables

Set these before running the matrix:

```bash
export REPLAYPROXY_RUN_LIVE_API_TESTS=1
export REPLAYPROXY_LIVE_HTTP_UPSTREAM="${REPLAYPROXY_LIVE_HTTP_UPSTREAM:-http://httpbin.org}"
export REPLAYPROXY_LIVE_HTTPS_UPSTREAM="${REPLAYPROXY_LIVE_HTTPS_UPSTREAM:-https://httpbin.org}"
export REPLAYPROXY_LIVE_FORWARD_URL="${REPLAYPROXY_LIVE_FORWARD_URL:-https://httpbin.org/post?case=forward-https-redaction}"
export REPLAYPROXY_LIVE_SECRET_HEADER="${REPLAYPROXY_LIVE_SECRET_HEADER:-Bearer live-secret-token}"
export REPLAYPROXY_LIVE_SECRET_BODY="${REPLAYPROXY_LIVE_SECRET_BODY:-live-body-secret}"
```

Hard stop if not explicitly opted in:

```bash
test "${REPLAYPROXY_RUN_LIVE_API_TESTS:-0}" = "1" || {
  echo "Refusing live validation: set REPLAYPROXY_RUN_LIVE_API_TESTS=1"
  exit 1
}
```

## Test Matrix Coverage

| Case | Coverage | Expected outcome |
| --- | --- | --- |
| Reverse HTTP record/replay | Reverse proxy, upstream `http://...`, `record` then `replay` | Record request succeeds; replay hit succeeds; replay miss returns `502 Gateway Not Recorded` |
| Reverse HTTPS record/replay | Reverse proxy, upstream `https://...`, `record` then `replay` | Same pass criteria as reverse HTTP, with TLS to upstream |
| Forward HTTPS passthrough-cache + redaction | Forward proxy CONNECT/TLS MITM, `passthrough-cache`, request redaction | First request goes upstream, second is cache hit, recording stores redacted request header/body fields |

## Exact Command Examples

Common setup:

```bash
cargo build --release
BIN=./target/release/replayproxy
WORKDIR="$(mktemp -d)"
trap 'pkill -P $$ || true; rm -rf "$WORKDIR"' EXIT
```

### 1) Reverse HTTP record/replay

```bash
cat >"$WORKDIR/reverse-http-record.toml" <<EOF
[proxy]
listen = "127.0.0.1:18080"
mode = "record"

[storage]
path = "$WORKDIR/storage-http"
active_session = "live-http"

[[routes]]
name = "live-http"
path_prefix = "/"
upstream = "$REPLAYPROXY_LIVE_HTTP_UPSTREAM"
EOF

$BIN serve --config "$WORKDIR/reverse-http-record.toml" >/tmp/replayproxy-live-http-record.log 2>&1 &
PID=$!
sleep 1
HTTP_RECORD_CODE="$(curl -sS -o /tmp/live-http-record.out -w '%{http_code}' 'http://127.0.0.1:18080/get?case=reverse-http')"
$BIN recording --config "$WORKDIR/reverse-http-record.toml" list
kill "$PID"; wait "$PID" || true

cat >"$WORKDIR/reverse-http-replay.toml" <<EOF
[proxy]
listen = "127.0.0.1:18080"
mode = "replay"

[storage]
path = "$WORKDIR/storage-http"
active_session = "live-http"

[[routes]]
name = "live-http"
path_prefix = "/"
upstream = "http://127.0.0.1:9"
cache_miss = "error"
EOF

$BIN serve --config "$WORKDIR/reverse-http-replay.toml" >/tmp/replayproxy-live-http-replay.log 2>&1 &
PID=$!
sleep 1
HTTP_REPLAY_HIT_CODE="$(curl -sS -o /tmp/live-http-replay-hit.out -w '%{http_code}' 'http://127.0.0.1:18080/get?case=reverse-http')"
HTTP_REPLAY_MISS_CODE="$(curl -sS -o /tmp/live-http-replay-miss.out -w '%{http_code}' 'http://127.0.0.1:18080/get?case=reverse-http-miss')"
kill "$PID"; wait "$PID" || true
```

### 2) Reverse HTTPS record/replay

```bash
cat >"$WORKDIR/reverse-https-record.toml" <<EOF
[proxy]
listen = "127.0.0.1:18081"
mode = "record"

[storage]
path = "$WORKDIR/storage-https"
active_session = "live-https"

[[routes]]
name = "live-https"
path_prefix = "/"
upstream = "$REPLAYPROXY_LIVE_HTTPS_UPSTREAM"
EOF

$BIN serve --config "$WORKDIR/reverse-https-record.toml" >/tmp/replayproxy-live-https-record.log 2>&1 &
PID=$!
sleep 1
HTTPS_RECORD_CODE="$(curl -sS -o /tmp/live-https-record.out -w '%{http_code}' 'http://127.0.0.1:18081/get?case=reverse-https')"
$BIN recording --config "$WORKDIR/reverse-https-record.toml" list
kill "$PID"; wait "$PID" || true

cat >"$WORKDIR/reverse-https-replay.toml" <<EOF
[proxy]
listen = "127.0.0.1:18081"
mode = "replay"

[storage]
path = "$WORKDIR/storage-https"
active_session = "live-https"

[[routes]]
name = "live-https"
path_prefix = "/"
upstream = "http://127.0.0.1:9"
cache_miss = "error"
EOF

$BIN serve --config "$WORKDIR/reverse-https-replay.toml" >/tmp/replayproxy-live-https-replay.log 2>&1 &
PID=$!
sleep 1
HTTPS_REPLAY_HIT_CODE="$(curl -sS -o /tmp/live-https-replay-hit.out -w '%{http_code}' 'http://127.0.0.1:18081/get?case=reverse-https')"
HTTPS_REPLAY_MISS_CODE="$(curl -sS -o /tmp/live-https-replay-miss.out -w '%{http_code}' 'http://127.0.0.1:18081/get?case=reverse-https-miss')"
kill "$PID"; wait "$PID" || true
```

### 3) Forward HTTPS passthrough-cache + redaction

```bash
$BIN ca generate --ca-dir "$WORKDIR/ca"

cat >"$WORKDIR/forward-https.toml" <<EOF
[proxy]
listen = "127.0.0.1:18082"
admin_port = 18083
mode = "passthrough-cache"

[proxy.tls]
enabled = true
ca_cert = "$WORKDIR/ca/cert.pem"
ca_key = "$WORKDIR/ca/key.pem"

[storage]
path = "$WORKDIR/storage-forward"
active_session = "live-forward"

[defaults.redact]
headers = ["authorization"]
body_json = ["$.api_key"]
placeholder = "<REDACTED>"

[[routes]]
name = "forward-all"
path_prefix = "/"
mode = "passthrough-cache"
cache_miss = "forward"

[routes.redact]
headers = ["authorization"]
body_json = ["$.api_key"]
EOF

$BIN serve --config "$WORKDIR/forward-https.toml" >/tmp/replayproxy-live-forward.log 2>&1 &
PID=$!
sleep 1
unset NO_PROXY no_proxy
FORWARD_FIRST_CODE="$(curl -sS --proxy http://127.0.0.1:18082 --cacert "$WORKDIR/ca/cert.pem" \
  -H "Authorization: $REPLAYPROXY_LIVE_SECRET_HEADER" \
  -H 'Content-Type: application/json' \
  -d "{\"api_key\":\"$REPLAYPROXY_LIVE_SECRET_BODY\",\"prompt\":\"cache me\"}" \
  -o /tmp/live-forward-first.out -w '%{http_code}' "$REPLAYPROXY_LIVE_FORWARD_URL")"
FORWARD_SECOND_CODE="$(curl -sS --proxy http://127.0.0.1:18082 --cacert "$WORKDIR/ca/cert.pem" \
  -H "Authorization: $REPLAYPROXY_LIVE_SECRET_HEADER" \
  -H 'Content-Type: application/json' \
  -d "{\"api_key\":\"$REPLAYPROXY_LIVE_SECRET_BODY\",\"prompt\":\"cache me\"}" \
  -o /tmp/live-forward-second.out -w '%{http_code}' "$REPLAYPROXY_LIVE_FORWARD_URL")"
STATUS_JSON="$(curl -sS 'http://127.0.0.1:18083/_admin/status')"
RECORDING_JSON="$(curl -sS 'http://127.0.0.1:18083/_admin/sessions/live-forward/recordings/1')"
kill "$PID"; wait "$PID" || true
```

## Release Checklist (Explicit Pass/Fail)

Use this checklist for release sign-off:

1. Opt-in gate  
Pass: `REPLAYPROXY_RUN_LIVE_API_TESTS=1` was set before running commands.  
Fail: Gate variable not set.

2. Reverse HTTP record/replay  
Pass: `HTTP_RECORD_CODE=200`, `HTTP_REPLAY_HIT_CODE=200`, `HTTP_REPLAY_MISS_CODE=502`.  
Fail: Any status differs, `recording list` is empty, or replay miss is not `502`.

3. Reverse HTTPS record/replay  
Pass: `HTTPS_RECORD_CODE=200`, `HTTPS_REPLAY_HIT_CODE=200`, `HTTPS_REPLAY_MISS_CODE=502`.  
Fail: Any status differs, `recording list` is empty, or replay miss is not `502`.

4. Forward HTTPS passthrough-cache behavior  
Pass: `FORWARD_FIRST_CODE=200`, `FORWARD_SECOND_CODE=200`, and `STATUS_JSON` includes:
- `"upstream_requests_total":1`
- `"cache_misses_total":1`
- `"cache_hits_total":1`  
Fail: Any status differs or counters do not match exactly.

5. Forward HTTPS redaction persisted  
Pass: `RECORDING_JSON` includes these byte signatures:
- header redaction: `"authorization",[60,82,69,68,65,67,84,69,68,62]`
- body redaction: `97,112,105,95,107,101,121,34,58,34,60,82,69,68,65,67,84,69,68,62,34`  
Fail: Either signature missing.

