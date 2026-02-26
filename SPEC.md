# replayproxy — Capture & Replay Proxy

## Overview

**replayproxy** is a programmable HTTP capture-and-replay proxy written in Rust. It sits between clients and upstream APIs, recording request/response pairs to a local SQLite database and replaying cached responses on subsequent matching requests. The primary motivation is reducing API costs (especially for expensive LLM APIs) during development and testing, while also enabling deterministic test environments.

---

## Proxy Modes

The proxy operates in one of three modes, **configurable per route**:

| Mode | Behavior |
|---|---|
| **Record** | Forward all requests to upstream, store request/response pairs in the database. Never serve from cache. |
| **Replay** | Serve exclusively from cache. On cache miss: configurable per route to either return a `502 Gateway Not Recorded` error or fall through to upstream. |
| **Passthrough-cache** | Forward to upstream, cache the response, and on subsequent matching requests return the cached version. |

---

## Deployment Modes

replayproxy supports **both forward and reverse proxy** operation:

### Forward Proxy
- Clients set `HTTP_PROXY` / `HTTPS_PROXY` to the proxy address.
- Works with any upstream automatically.
- Requires MITM CA for HTTPS interception (see TLS section).

### Reverse Proxy
- Configured with specific upstream URL(s) in the config file.
- Clients hit the proxy directly as if it were the target API.
- Useful for simpler setups or when modifying proxy env vars is impractical.

---

## TLS / HTTPS

Full MITM CA support for intercepting HTTPS traffic:

- **Auto-generation**: On first run, generate a root CA certificate and private key, stored in a well-known config directory (`~/.replayproxy/ca/`).
- **Auto-installation**: Attempt to install the CA into the system trust store automatically (prompting for `sudo` when required). Support macOS Keychain, and Linux `update-ca-certificates`.
- **Per-connection certs**: Dynamically generate leaf certificates for each upstream host, signed by the local CA.
- **User-provided CA**: Optionally accept a user-supplied CA cert + key via config for environments with existing PKI.

---

## Request Matching

Matching determines when to serve a cached response vs. forwarding to upstream. Rules are **configurable per route** in the TOML config file.

### Match dimensions

Each route can match on any combination of:

- **Method** — `GET`, `POST`, etc.
- **URL path** — exact, prefix, or regex match
- **Query parameters** — exact match, subset match, or ignored
- **Headers** — match on specific headers, ignore others (e.g., ignore `Date`, `X-Request-Id`)
- **Body (JSON)** — extract fields using **JSONPath (RFC 9535)** expressions and match on their values
- **Body (raw)** — SHA-256 hash of the full body for non-JSON payloads

### Match key computation

The selected dimensions are normalized and hashed to produce a deterministic cache key. The config specifies which dimensions participate per route.

#### Ordering decision: matching vs redaction

For requests that are both matched and redacted, matching uses the **original request values** (after any `on_request` transform) and redaction applies only to persisted request/response data.

Implications:

- Route behavior remains correct when matching on sensitive inputs such as `Authorization`.
- Fields listed in both `[routes.match]` and `[routes.redact]` are valid: the original value participates in cache lookup, while the stored value is replaced with the redaction placeholder.
- Match-key inputs are treated as sensitive operational data: do not log raw pre-hash values.

#### Normalization (match key v1)

To ensure deterministic matching, request components are normalized before hashing:

- **Scheme/authority**: ignored for matching (only `path`/`query` participate).
- **Method**: normalized as an ASCII-uppercase token.
- **Path**: `URI.path` as-is (no percent-decoding).
- **Query**: parsed as raw `name=value` pairs (no percent-decoding), sorted by name then value; repeated keys are preserved.
- **Headers**: names are handled case-insensitively (serialized lowercased); values are treated as raw bytes. When configured, headers are selected via an allowlist and/or ignore list, then sorted by name then value.
- **Body**: treated as raw bytes (higher-level JSON matching via JSONPath is specified separately).

### Example config

```toml
[[routes]]
path_prefix = "/v1/chat/completions"
mode = "passthrough-cache"
cache_miss = "forward"   # or "error"

[routes.match]
method = true
path = true
headers = ["Authorization"]  # only match on this header
body_json = [
  "$.model",
  "$.messages",
  "$.temperature",
]

[routes.redact]
headers = ["Authorization", "X-Api-Key"]
body_json = ["$.api_key"]
```

---

## Sessions / Cassettes

Recordings are organized into **named sessions** (inspired by VCR cassettes):

- Each session is an isolated collection of recordings.
- Active session precedence at startup is: CLI `--active-session` override > config `storage.active_session` (or `default` if unset).
- Admin API activation is a process-local runtime override (not persisted to config) and lasts until restart.
- Sessions can be created, listed, switched, and deleted.
- Use cases: separate recording sets for different test scenarios, API versions, or environments.

---

## Streaming Support

First-class support for streamed responses (SSE, chunked transfer encoding):

- **Recording**: Store each chunk individually with its timestamp offset from the start of the response.
- **Replay with preserved timing**: Replay chunks with the original inter-chunk delays to faithfully simulate upstream behavior.
- **Replay fast mode**: Optionally replay all chunks immediately (configurable per route, useful for CI).

---

## WebSocket Support

Capture and replay WebSocket connections, **configurable per route**:

- **Full bidirectional recording**: Record both client→server and server→client messages with timestamps. On replay, expect the client to send matching messages and replay the corresponding server responses.
- **Server-only recording**: Record only server→client messages. On replay, ignore client messages and play back the server stream.
- Messages stored with frame type (text/binary), payload, and timestamp offset.

---

## gRPC Support

HTTP/2 gRPC traffic handling with two modes:

- **Opaque mode** (default): Treat protobuf payloads as binary blobs. Match by hashing the raw bytes. No `.proto` files required.
- **Proto-aware mode**: Load `.proto` descriptor files (configured per route) to decode messages. Apply JSONPath-style field matching on the decoded JSON representation. Enables partial matching on specific gRPC message fields.

---

## Rate Limiting & Throttling

Bidirectional rate control:

### Record mode (protect upstream)
- Configurable rate limits on outgoing requests to avoid hitting real API rate limits.
- Token bucket or sliding window rate limiter per upstream host/route.
- Requests exceeding the limit are queued (with configurable max queue depth and timeout).

### Replay mode (simulate limits)
- Simulate upstream rate limiting by returning `429 Too Many Requests` after a configurable threshold.
- Include realistic `Retry-After` headers.
- Test application backoff and retry logic against deterministic rate limit scenarios.

---

## Redaction

Configurable sanitization of sensitive data **before** storing to the database:

- **Headers**: Strip or replace specific request/response headers (e.g., `Authorization`, `X-Api-Key`).
- **JSON body fields**: Redact specific fields using JSONPath expressions (e.g., `$.api_key`).
- Redacted values are replaced with a configurable placeholder (default: `"[REDACTED]"`).
- Redaction rules are defined per route in the TOML config.

### Implementation plan for matched + redacted fields

1. Compute an effective redaction config per route by merging `[defaults.redact]` with `[routes.redact]`.
2. For each request, run `on_request` transforms first, then compute the match key from the transformed, non-redacted request according to `[routes.match]`.
3. Before writing to SQLite, create redacted copies of request/response headers and bodies using the effective redaction config and placeholder.
4. Persist the redacted copies and the already-computed match key.

Acceptance expectations:

- If two requests differ only in a matched sensitive field (for example `Authorization`), they produce different match keys.
- Stored recordings redact that field in headers/body according to policy.
- Logs and error messages do not emit raw matched sensitive values.

---

## Request/Response Transforms

**Lua scripting** for full programmatic transforms:

- Embed a Lua interpreter (via `mlua` or `rlua` crate).
- Transform hooks at four points:
  1. **`on_request`** — modify the request before matching / forwarding
  2. **`on_response`** — modify the response before caching / returning to client
  3. **`on_record`** — modify the recording before writing to the database
  4. **`on_replay`** — modify the cached response before returning to the client
- Lua scripts have access to request/response headers, body, method, URL, and status code.
- Scripts are referenced per route in the TOML config:
  ```toml
  [[routes]]
  path_prefix = "/v1/models"
  transform.on_request = "scripts/add_auth.lua"
  transform.on_response = "scripts/strip_debug.lua"
  ```
- Oversized request handling contract: when `routes.transform.on_request` is configured, request
  bodies must be fully buffered before forwarding/matching. If body size exceeds
  `proxy.max_body_bytes`, replayproxy returns `413` and does **not** apply `body_oversize = "bypass-cache"`
  passthrough behavior for that request.

---

## Storage

### Primary: SQLite

- Single `.db` file per session (stored in `~/.replayproxy/sessions/<name>/recordings.db`).
- Schema stores: request method, URL, headers, body (or body hash), response status, headers, body, chunks (for streaming), timestamps, match key hash.
- WAL mode for concurrent read/write access.

#### SQLite schema (v1)

**Table: `recordings`**

- `id` — `INTEGER PRIMARY KEY AUTOINCREMENT`
- `match_key` — `TEXT NOT NULL` (hex-encoded hash of selected match dimensions)
- `request_method` — `TEXT NOT NULL`
- `request_uri` — `TEXT NOT NULL` (path + query)
- `request_headers_json` — `TEXT NOT NULL` (JSON array of `[name, value]` pairs)
- `request_body` — `BLOB NOT NULL`
- `response_status` — `INTEGER NOT NULL`
- `response_headers_json` — `TEXT NOT NULL` (JSON array of `[name, value]` pairs)
- `response_body` — `BLOB NOT NULL`
- `created_at_unix_ms` — `INTEGER NOT NULL`

**Indexes**

- `recordings_match_key_idx` on `recordings(match_key)`

**DB settings**

- `PRAGMA journal_mode = WAL`
- `PRAGMA synchronous = NORMAL`
- `PRAGMA foreign_keys = ON`
- `PRAGMA user_version = 1`

### Export: JSON/YAML

- Export a session to a directory of human-readable files for version control and CI:
  ```
  session-name/
  ├── index.{json|yaml}   # manifest with metadata
  ├── recordings/
  │   ├── 0001-post-v1-chat-completions-id42.json
  │   ├── 0002-get-v1-models-id43.json
  │   └── ...
  ```
- Import from exported directories back into SQLite.
- Canonical v1 schema details (manifest required fields + deterministic naming rules) live in
  `docs/session-export-format.md`.

---

## CLI

A companion CLI (`replayproxy`) with subcommands:

| Command | Description |
|---|---|
| `replayproxy serve` | Start the proxy server |
| `replayproxy session list` | List all sessions |
| `replayproxy session create <name>` | Create a new session |
| `replayproxy session delete <name>` | Delete a session and its recordings |
| `replayproxy session export <name> --format <json\|yaml> --out ./dir` | Export session to files |
| `replayproxy session import <dir>` | Import session from exported files |
| `replayproxy recording list [--session <name>]` | List recordings in a session |
| `replayproxy recording search <query>` | Search recordings by URL, method, body content |
| `replayproxy recording delete <id>` | Delete a specific recording |
| `replayproxy ca generate` | Generate a new CA certificate |
| `replayproxy ca install` | Install the CA into the system trust store |
| `replayproxy ca export` | Export the CA cert for manual installation |

---

## Admin HTTP API

Exposed on a configurable admin port under the `/_admin` path prefix:

| Endpoint | Method | Description |
|---|---|---|
| `/_admin/sessions` | GET | List sessions |
| `/_admin/sessions` | POST | Create a session |
| `/_admin/sessions/:name/activate` | POST | Activate a session for the running process (runtime only, not persisted) |
| `/_admin/sessions/:name` | DELETE | Delete a session |
| `/_admin/sessions/:name/recordings` | GET | List recordings (with pagination, filtering) |
| `/_admin/sessions/:name/recordings/:id` | GET | Get a specific recording |
| `/_admin/sessions/:name/recordings/:id` | DELETE | Delete a recording |
| `/_admin/sessions/:name/export` | POST | Export session to files |
| `/_admin/config/reload` | POST | Trigger config reload |
| `/_admin/status` | GET | Proxy status, uptime, active session |

Security expectations:
- When `proxy.admin_port` is configured, the admin listener binds to loopback by default.
- Use `proxy.admin_bind` to override bind IP explicitly (for example `0.0.0.0` when intentional).
- Use `proxy.admin_api_token` to require header `x-replayproxy-admin-token` on admin requests.

---

## Observability

### Structured Logging
- JSON-formatted logs to stdout/stderr.
- Log levels: `error`, `warn`, `info`, `debug`, `trace`.
- Each request logs: method, URL, mode (record/replay/cache), cache hit/miss, upstream latency, response status.

### Prometheus Metrics
- Exposed at `/metrics` on the admin port.
- Key metrics:
  - `replayproxy_requests_total{mode, method, status}` — request counter
  - `replayproxy_cache_hits_total` / `replayproxy_cache_misses_total`
  - `replayproxy_upstream_duration_seconds` — histogram of upstream response times
  - `replayproxy_replay_duration_seconds` — histogram of replay response times
  - `replayproxy_recordings_total{session}` — gauge of recordings per session
  - `replayproxy_active_connections` — gauge of active client connections

---

## Configuration

### File format: TOML

Located at `./replayproxy.toml` or `~/.replayproxy/config.toml` (with CLI `--config` override).

### Hot reload

- Watch the config file for changes using filesystem notifications (`notify` crate).
- Automatically reload matching rules, routes, and transforms without restarting the proxy.
- Log a summary of what changed on each reload.

### Full example

```toml
[proxy]
listen = "127.0.0.1:8080"
admin_port = 8081
# admin_bind = "127.0.0.1"
# admin_api_token = "replace-with-strong-secret"
mode = "passthrough-cache"           # default mode for unmatched routes

[proxy.tls]
enabled = true
ca_cert = "~/.replayproxy/ca/cert.pem"
ca_key = "~/.replayproxy/ca/key.pem"

[storage]
path = "~/.replayproxy/sessions"
active_session = "default"

[logging]
level = "info"
format = "json"                      # "json" or "pretty"

[metrics]
enabled = true

# Default redaction applied to all routes
[defaults.redact]
headers = ["Authorization", "X-Api-Key", "Cookie"]

# Route-specific configuration
[[routes]]
name = "openai-chat"
path_prefix = "/v1/chat/completions"
upstream = "https://api.openai.com"  # for reverse proxy mode
mode = "passthrough-cache"
cache_miss = "forward"

[routes.match]
method = true
path = true
body_json = ["$.model", "$.messages", "$.temperature"]

[routes.redact]
headers = ["Authorization"]
body_json = ["$.api_key"]

[routes.streaming]
preserve_timing = true

[routes.rate_limit]
requests_per_second = 10
burst = 20

[[routes]]
name = "anthropic-messages"
path_prefix = "/v1/messages"
upstream = "https://api.anthropic.com"
mode = "record"

[routes.match]
method = true
path = true
body_json = ["$.model", "$.messages", "$.max_tokens"]

[routes.transform]
on_request = "scripts/anthropic_auth.lua"

[[routes]]
name = "grpc-inference"
path_prefix = "/inference.InferenceService"
mode = "replay"
cache_miss = "error"

[routes.grpc]
proto_files = ["protos/inference.proto"]
match_fields = ["model_name", "input_text"]

[[routes]]
name = "ws-streaming"
path_prefix = "/ws/stream"
mode = "passthrough-cache"

[routes.websocket]
recording_mode = "server-only"       # or "bidirectional"
```

---

## Community Presets

- Ship the proxy as a generic tool with no built-in API knowledge.
- Maintain a `presets/` directory in the repository with community-contributed configs:
  ```
  presets/
  ├── openai.toml
  ├── anthropic.toml
  ├── stripe.toml
  └── ...
  ```
- Users import presets via CLI: `replayproxy preset import openai`
- Presets define sensible defaults for matching rules, redaction, streaming config, and rate limits.

---

## Technology Stack

| Component | Choice |
|---|---|
| Language | Rust (latest stable edition) |
| Async runtime | Tokio |
| HTTP framework | `hyper` + `tower` (for proxy internals) |
| TLS | `rustls` + `rcgen` (for cert generation) |
| SQLite | `rusqlite` with `bundled` feature |
| JSON | `serde_json` |
| JSONPath | `serde_json_path` (RFC 9535 compliant) |
| Lua | `mlua` with Luau or LuaJIT |
| Protobuf | `prost` + `prost-reflect` for dynamic message decoding |
| Config | `toml` crate |
| File watching | `notify` crate |
| Logging | `tracing` + `tracing-subscriber` (JSON formatter) |
| Metrics | `metrics` + `metrics-exporter-prometheus` |
| CLI | `clap` (derive API) |
| WebSocket | `tokio-tungstenite` |

---

## Design Scale

Designed to serve two primary use cases:

1. **Local development**: Single developer, low concurrency (~10–50 connections). Priority: ease of setup, fast startup.
2. **CI / test infrastructure**: High throughput with many parallel test suites. Priority: concurrent access safety (SQLite WAL mode), low latency on cache hits, stability under load.
