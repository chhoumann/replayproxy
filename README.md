# replayproxy

`replayproxy` is an HTTP capture-and-replay proxy for deterministic local development and testing.

It sits between your client and upstream APIs, stores responses in SQLite, and can replay them later by request match key.

## Why replayproxy

- Record once, replay many times without calling upstream services.
- Isolate recordings by session (cassette-like workflow).
- Redact secrets before data is persisted.
- Switch runtime mode/session from CLI or admin API.
- Support reverse-proxy and forward-proxy (including HTTPS MITM) workflows.

## Architecture

```text
Client traffic
    |
    v
+---------------------+        +-------------------------------+
| replayproxy listener| -----> | Route match + mode resolution |
+---------------------+        +-------------------------------+
                                          |         |
                                          |         +--> Upstream HTTP(S)
                                          |
                                          +--> SQLite session storage

Admin client (CLI/curl)
    |
    v
+---------------------+
| admin listener      | --> status, mode override, session activation, reload, metrics
+---------------------+
```

Runtime mode resolution is:

1. `routes[].mode` (if set)
2. `proxy.mode` (if set)
3. fallback `passthrough-cache`

## Install

Prerequisite: stable Rust toolchain.

```bash
# build
cargo build --release

# optional feature builds
cargo build --release --features grpc
cargo build --release --features scripting
cargo build --release --features grpc,scripting

# run directly
./target/release/replayproxy --help

# optional install to cargo bin dir
cargo install --path .
replayproxy --help
```

Feature notes:

- `grpc` enables proto-aware matching via `[routes.grpc]`.
- `scripting` enables Lua hooks via `[routes.transform]`.

## Bootstrap with `replayproxy init`

Generate a starter config and local directory layout:

```bash
# project-local scaffold (default)
replayproxy init

# include an enabled sample route
replayproxy init --sample-route

# target a specific project root
replayproxy init --root ./my-proxy-project

# scaffold in home layout (~/.replayproxy/config.toml)
replayproxy init --home

# preview changes without writing
replayproxy init --dry-run

# overwrite existing config
replayproxy init --force
```

Generated layout (project-local default):

```text
./replayproxy.toml
./.replayproxy/sessions/
./.replayproxy/ca/
./.replayproxy/presets/
```

The generated config is valid for `replayproxy serve --config ...`; add or adjust `[[routes]]`
for your upstream APIs.

## Config discovery and examples

When `--config` is omitted, replayproxy loads the first existing file from:

1. `./replayproxy.toml`
2. `~/.replayproxy/config.toml`

Example configs:

- [`examples/replayproxy.minimal.toml`](examples/replayproxy.minimal.toml)
- [`examples/replayproxy.llm-redacted.toml`](examples/replayproxy.llm-redacted.toml)
- [`examples/replayproxy.websocket.toml`](examples/replayproxy.websocket.toml)
- [`examples/replayproxy.grpc.toml`](examples/replayproxy.grpc.toml)

Lua transform examples:

- [`examples/scripts/llm_on_request.lua`](examples/scripts/llm_on_request.lua)
- [`examples/scripts/llm_on_response.lua`](examples/scripts/llm_on_response.lua)

`examples/replayproxy.llm-redacted.toml` wires those files via `[routes.transform]`.
Lua hooks require a build with scripting enabled:

```bash
cargo run --features scripting -- serve --config ./examples/replayproxy.llm-redacted.toml
```

When `body_oversize = "bypass-cache"` is configured, transform hooks still default to strict
buffering behavior for safety. To allow oversized requests/responses to bypass cache instead of
returning `413`/`502`, set:

```toml
[routes.transform]
oversize_behavior = "skip"
```

With `oversize_behavior = "skip"`, oversized bypassed traffic skips `on_request`/`on_response`
hooks and is streamed upstream/downstream without recording.

Proto-aware gRPC matching via `[routes.grpc]` requires the `grpc` feature:

```bash
cargo run --features grpc -- serve --config ./replayproxy.toml
```

See [Quickstart: gRPC record then replay](#quickstart-grpc-record-then-replay) for a command-driven workflow.

## Quickstart: record then replay (reverse proxy)

Use this minimal config (`replayproxy.toml`):

```toml
[proxy]
listen = "127.0.0.1:8080"
admin_port = 8081
mode = "record"

[storage]
path = "./.replayproxy-data"
active_session = "default"

[[routes]]
name = "httpbin"
path_prefix = "/"
upstream = "https://httpbin.org"
```

1. Start the proxy:

```bash
replayproxy serve --config ./replayproxy.toml
```

2. Send a request through replayproxy:

```bash
curl -i "http://127.0.0.1:8080/get?demo=1"
```

Expected: upstream success (`HTTP/1.1 200 OK`) and response body from httpbin.

3. Confirm recording was stored:

```bash
replayproxy recording --config ./replayproxy.toml list
```

Expected: output contains `session \`default\`` and at least one row in the `id method status uri` table.

4. Switch runtime mode to replay:

```bash
replayproxy mode --config ./replayproxy.toml set replay --admin-addr 127.0.0.1:8081
```

Expected: output like `set runtime mode override via admin 127.0.0.1:8081: \`replay\``.

5. Send the same request again:

```bash
curl -i "http://127.0.0.1:8080/get?demo=1"
```

Expected: same response served from local storage (no upstream call).

6. Send a request you did not record:

```bash
curl -i "http://127.0.0.1:8080/get?not-recorded=1"
```

Expected in replay mode: `502` with JSON body including `error`, `route`, `session`, and `match_key`.

## Quickstart: WebSocket record then replay

This flow uses [`examples/replayproxy.websocket.toml`](examples/replayproxy.websocket.toml) and `websocat`.

1. Start your WebSocket upstream at `127.0.0.1:9001`, then run replayproxy:

```bash
replayproxy serve --config ./examples/replayproxy.websocket.toml
```

2. Connect through replayproxy in record mode and send frames:

```bash
websocat ws://127.0.0.1:8080/ws/echo
```

3. Confirm recording state, then switch to replay mode:

```bash
replayproxy recording --config ./examples/replayproxy.websocket.toml list
replayproxy mode --config ./examples/replayproxy.websocket.toml set replay --admin-addr 127.0.0.1:8081
```

4. Re-run the same WebSocket flow:

```bash
websocat ws://127.0.0.1:8080/ws/echo
```

Expected: replay serves recorded frames from local storage. In `bidirectional` mode, client frame order/type/payload must match the original recording.

## Quickstart: gRPC record then replay

This flow uses [`examples/replayproxy.grpc.toml`](examples/replayproxy.grpc.toml), a local gRPC upstream on `127.0.0.1:50051`, and `grpcurl`.

1. Start replayproxy with gRPC feature support:

```bash
cargo run --features grpc -- serve --config ./examples/replayproxy.grpc.toml
```

2. Record one request:

```bash
grpcurl -plaintext \
  -import-path ./examples/protos \
  -proto inference.proto \
  -d '{"model_name":"model-a","input_text":"hello world","trace_id":"trace-a"}' \
  127.0.0.1:8080 inference.InferenceService/Predict
```

3. Switch to replay mode:

```bash
replayproxy mode --config ./examples/replayproxy.grpc.toml set replay --admin-addr 127.0.0.1:8081
```

4. Replay hit (same gRPC `match_fields`, different non-match field):

```bash
grpcurl -plaintext \
  -import-path ./examples/protos \
  -proto inference.proto \
  -d '{"model_name":"model-a","input_text":"hello world","trace_id":"trace-b"}' \
  127.0.0.1:8080 inference.InferenceService/Predict
```

5. Replay miss (change a configured gRPC `match_field`):

```bash
grpcurl -plaintext \
  -import-path ./examples/protos \
  -proto inference.proto \
  -d '{"model_name":"model-a","input_text":"different prompt","trace_id":"trace-c"}' \
  127.0.0.1:8080 inference.InferenceService/Predict
```

Expected: replay hit is served from storage; replay miss returns `502 Gateway Not Recorded` unless `cache_miss = "forward"`.

## Reverse proxy vs forward proxy

Reverse proxy route (set `upstream`):

- Incoming request path/query is forwarded to the configured upstream host.
- Good for local endpoint remapping like `/api/* -> https://service.example`.

Forward proxy route (omit `upstream`):

- Client sends absolute-form URLs (and optionally CONNECT for HTTPS).
- Route should use `path_prefix = "/"` so CONNECT/absolute-form requests match.
- Good for tooling that supports `HTTP_PROXY` / `HTTPS_PROXY`.

## Forward proxy with HTTPS MITM (macOS/Linux)

1. Generate CA material:

```bash
replayproxy ca generate
```

Default output:

- `~/.replayproxy/ca/cert.pem`
- `~/.replayproxy/ca/key.pem`

2. Install trust (best effort):

```bash
replayproxy ca install
```

If automatic install does not complete, run the manual command printed by replayproxy.

3. Export CA cert for manual trust installation (optional):

```bash
replayproxy ca export --out ./replayproxy-ca-cert.pem
```

4. Configure forward proxy + TLS interception:

```toml
[proxy]
listen = "127.0.0.1:8080"
mode = "passthrough-cache"

[proxy.tls]
enabled = true
ca_cert = "~/.replayproxy/ca/cert.pem"
ca_key = "~/.replayproxy/ca/key.pem"

[storage]
path = "./.replayproxy-data"
active_session = "default"

[[routes]]
name = "forward-all"
path_prefix = "/"
```

5. Start proxy and route client traffic:

```bash
replayproxy serve --config ./replayproxy.toml
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
curl https://example.com/
```

Notes:

- Without `[proxy.tls].enabled = true`, CONNECT is tunneled raw (no HTTPS body visibility).
- If `ca_cert` and `ca_key` point to missing default filenames (`cert.pem`/`key.pem`), startup can auto-generate CA material.

## Session and recording operations

Session commands:

```bash
replayproxy session --config ./replayproxy.toml list
replayproxy session --config ./replayproxy.toml create test-session
replayproxy session --config ./replayproxy.toml switch test-session --admin-addr 127.0.0.1:8081
replayproxy session --config ./replayproxy.toml prune test-session
replayproxy session --config ./replayproxy.toml delete old-session
```

Export/import:

```bash
replayproxy session --config ./replayproxy.toml export default --format yaml --out ./exports/default
replayproxy session --config ./replayproxy.toml import recovered --in ./exports/default
```

Recording commands:

```bash
replayproxy recording --config ./replayproxy.toml list
replayproxy recording --config ./replayproxy.toml search "POST /v1/chat body:gpt"
replayproxy recording --config ./replayproxy.toml delete 42
```

Operational notes:

- `session` and `recording` commands require `[storage].path`.
- Session names are validated; path traversal and empty/invalid names are rejected.
- Active session cannot be deleted.
- Optional `storage.max_recordings = <N>` keeps only the newest `N` recordings per session by evicting oldest rows during writes/imports.
- Optional `storage.max_age_days = <N>` or `storage.max_age_hours = <N>` prunes recordings older than that window during writes/imports (`max_age_days` and `max_age_hours` are mutually exclusive).
- Use `replayproxy session ... prune <name>` to force retention pruning immediately for low-write or idle sessions and report deleted counts.

## Admin API and runtime operations

Enable admin listener in config:

```toml
[proxy]
listen = "127.0.0.1:8080"
admin_port = 8081
# optional: admin_bind = "0.0.0.0"
# optional: admin_api_token = "replace-with-strong-secret"
```

Security behavior:

- If `admin_bind` is omitted, admin binds to loopback.
- If `admin_api_token` is set, all admin endpoints (including `/metrics`) require header:
  - `x-replayproxy-admin-token: <token>`
- `admin_api_token` is read at process start. `/_admin/config/reload` does not rotate admin auth tokens; restart the process to apply token changes.

Core endpoints:

- `GET /_admin/status`
- `GET|POST /_admin/mode`
- `POST /_admin/config/reload`
- `GET|POST /_admin/sessions`
- `POST /_admin/sessions/:name/activate`
- `GET|DELETE /_admin/sessions/:name/recordings/:id`
- `GET /_admin/sessions/:name/recordings`
- `POST /_admin/sessions/:name/export`
- `POST /_admin/sessions/:name/import`
- `POST /_admin/sessions/:name/prune`
- `DELETE /_admin/sessions/:name`
- `GET /metrics` (only when `[metrics].enabled = true`)

Mode workflow from CLI:

```bash
replayproxy mode --config ./replayproxy.toml show --admin-addr 127.0.0.1:8081
replayproxy mode --config ./replayproxy.toml set replay --admin-addr 127.0.0.1:8081
replayproxy mode --config ./replayproxy.toml set record --admin-addr 127.0.0.1:8081 --persist
```

`mode set --persist` updates `proxy.mode` in the loaded config file.

## Matching, redaction, and replay miss behavior

Matching:

- Match key is built from normalized method/path/query/headers/body rules.
- Query mode `subset` excludes query from hash and resolves candidates at lookup time.
- Recording lookup is latest-match wins.

Redaction:

- Redaction runs before persistence.
- Supports header, query-parameter, and JSONPath body redaction.
- Matching still uses pre-redaction request values.
- Internal subset-query lookup metadata is persisted as hashed query-parameter fingerprints.

Replay miss behavior:

- Default in `replay` mode is `cache_miss = "error"` -> `502 Gateway Not Recorded`.
- Set `cache_miss = "forward"` on a route to forward upstream instead of returning `502`.

## Metrics and observability

When enabled:

```toml
[metrics]
enabled = true
```

`GET /metrics` exposes Prometheus text metrics, including:

- request totals
- cache hit/miss totals
- upstream/replay latency histograms
- active connections
- active-session recording totals

`GET /_admin/status` returns runtime state (`uptime_ms`, `active_session`, listener addresses, route count, and counters).

## Presets

Bundled presets:

- `openai`
- `anthropic`

Commands:

```bash
replayproxy preset list
replayproxy preset import openai
```

Import behavior is copy-only:

- writes `~/.replayproxy/presets/<name>.toml`
- overwrites existing file at that path
- does not merge into your active project config

## Troubleshooting

### `502 Gateway Not Recorded`

Checks:

```bash
replayproxy mode --config ./replayproxy.toml show --admin-addr 127.0.0.1:8081
replayproxy recording --config ./replayproxy.toml list
replayproxy recording --config ./replayproxy.toml search "GET /get"
curl -sS http://127.0.0.1:8081/_admin/status
```

Common fixes:

- Seed recordings first in `record` or `passthrough-cache` mode.
- Confirm active session is the one you expect.
- Confirm route match settings (method/path/query/headers/body) still match the traffic.
- Use `cache_miss = "forward"` if replay misses should fall back upstream.

### `mode` or `session switch` commands fail

- Ensure admin listener is enabled via `proxy.admin_port` or pass explicit `--admin-addr`.
- If `admin_api_token` is configured, ensure the loaded config has the matching token (CLI admin calls forward it automatically).
- `mode set --persist` requires a config file path source.

### gRPC proto-aware matching not taking effect

- Build/run replayproxy with `--features grpc` when using `[routes.grpc].match_fields`.
- Without the `grpc` feature, replayproxy falls back to opaque request-body matching, which can cause unexpected replay misses.
- `routes.grpc.match_fields` requires at least one `routes.grpc.proto_files` entry, and proto paths are resolved relative to the config file.
- Ensure the client sends gRPC content types (`application/grpc` or `application/grpc+...`) and that `path_prefix` matches your service path.

### WebSocket replay closes with mismatch

- In replay mode with `recording_mode = "bidirectional"`, client frames must match the recorded order, type, and payload.
- On mismatch, replayproxy closes the socket with a WebSocket policy close frame and mismatch reason.
- Use `recording_mode = "server-only"` when client payloads are nondeterministic and should not be enforced in replay.
- If you get `502 Gateway Not Recorded` before upgrade, verify mode/session and recording presence:

```bash
replayproxy mode --config ./examples/replayproxy.websocket.toml show --admin-addr 127.0.0.1:8081
replayproxy recording --config ./examples/replayproxy.websocket.toml search "/ws/echo"
```

### CA/TLS issues

- Generate CA first: `replayproxy ca generate`.
- Install trust: `replayproxy ca install` (or run manual instructions shown).
- Verify CA files:

```bash
ls -l ~/.replayproxy/ca/cert.pem ~/.replayproxy/ca/key.pem
```

### Config reload not applied

```bash
curl -sS -X POST http://127.0.0.1:8081/_admin/config/reload
```

- `409 config reload unavailable` means replayproxy does not have a config source path.
- Default builds include file-watch reload with debounce; multiple rapid edits may coalesce.
- `200` reload responses include `restart_required` and `reload_hints`; if `proxy.admin_api_token` changed, reload reports restart required and keeps the existing runtime token until restart.

## Known limitations (current)

- gRPC proto-aware matching (`routes.grpc.match_fields`) requires a build with `--features grpc`; without it, matching falls back to opaque request-body behavior.
- Time-based retention is enforced during writes/imports; for idle sessions trigger pruning manually with `replayproxy session ... prune <name>` or `POST /_admin/sessions/:name/prune`.
- Query `subset` matching fallback uses a per-param inverted index, but extremely broad buckets can still trigger additional candidate scanning.

## Additional docs

- [`docs/session-export-format.md`](docs/session-export-format.md)
- [`docs/live-api-validation.md`](docs/live-api-validation.md)
- [`docs/performance.md`](docs/performance.md)
- [`RELEASE_POLICY.md`](RELEASE_POLICY.md)
