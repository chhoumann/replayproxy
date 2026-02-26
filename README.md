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

# run directly
./target/release/replayproxy --help

# optional install to cargo bin dir
cargo install --path .
replayproxy --help
```

## Config discovery and examples

When `--config` is omitted, replayproxy loads the first existing file from:

1. `./replayproxy.toml`
2. `~/.replayproxy/config.toml`

Example configs:

- [`examples/replayproxy.minimal.toml`](examples/replayproxy.minimal.toml)
- [`examples/replayproxy.llm-redacted.toml`](examples/replayproxy.llm-redacted.toml)

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
replayproxy recording list --config ./replayproxy.toml
```

Expected: output contains `session \`default\`` and at least one row in the `id method status uri` table.

4. Switch runtime mode to replay:

```bash
replayproxy mode set replay --config ./replayproxy.toml --admin-addr 127.0.0.1:8081
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

3. Configure forward proxy + TLS interception:

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

4. Start proxy and route client traffic:

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
replayproxy session list --config ./replayproxy.toml
replayproxy session create test-session --config ./replayproxy.toml
replayproxy session switch test-session --config ./replayproxy.toml --admin-addr 127.0.0.1:8081
replayproxy session delete old-session --config ./replayproxy.toml
```

Export/import:

```bash
replayproxy session export default --format yaml --out ./exports/default --config ./replayproxy.toml
replayproxy session import recovered --in ./exports/default --config ./replayproxy.toml
```

Recording commands:

```bash
replayproxy recording list --config ./replayproxy.toml
replayproxy recording search "POST /v1/chat body:gpt" --config ./replayproxy.toml
replayproxy recording delete 42 --config ./replayproxy.toml
```

Operational notes:

- `session` and `recording` commands require `[storage].path`.
- Session names are validated; path traversal and empty/invalid names are rejected.
- Active session cannot be deleted.

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
- `DELETE /_admin/sessions/:name`
- `GET /metrics` (only when `[metrics].enabled = true`)

Mode workflow from CLI:

```bash
replayproxy mode show --config ./replayproxy.toml --admin-addr 127.0.0.1:8081
replayproxy mode set replay --config ./replayproxy.toml --admin-addr 127.0.0.1:8081
replayproxy mode set record --config ./replayproxy.toml --admin-addr 127.0.0.1:8081 --persist
```

`mode set --persist` updates `proxy.mode` in the loaded config file.

## Matching, redaction, and replay miss behavior

Matching:

- Match key is built from normalized method/path/query/headers/body rules.
- Query mode `subset` excludes query from hash and resolves candidates at lookup time.
- Recording lookup is latest-match wins.

Redaction:

- Redaction runs before persistence.
- Supports header redaction and JSONPath body redaction.
- Matching still uses pre-redaction request values.

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
replayproxy mode show --config ./replayproxy.toml --admin-addr 127.0.0.1:8081
replayproxy recording list --config ./replayproxy.toml
replayproxy recording search "GET /get" --config ./replayproxy.toml
curl -sS http://127.0.0.1:8081/_admin/status
```

Common fixes:

- Seed recordings first in `record` or `passthrough-cache` mode.
- Confirm active session is the one you expect.
- Confirm route match settings (method/path/query/headers/body) still match the traffic.
- Use `cache_miss = "forward"` if replay misses should fall back upstream.

### `mode` or `session switch` commands fail

- Ensure admin listener is enabled via `proxy.admin_port` or pass explicit `--admin-addr`.
- If `admin_api_token` is configured, send the matching token.
- `mode set --persist` requires a config file path source.

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

## Known limitations (current)

- WebSocket capture/replay is not implemented yet.
- gRPC capture/replay is not implemented yet.
- Lua transform runtime currently applies `on_request`; `on_response`, `on_record`, and `on_replay` are not wired yet.
- Session export/import moves recording objects but not streaming chunk metadata.
- No built-in TTL/retention/eviction policy for stored recordings.
- Query `subset` matching can fall back to scan-heavy behavior on very large candidate sets.
- `body_oversize = "bypass-cache"` does not bypass in replay mode, and does not bypass when `on_request` transform is configured.

## Additional docs

- [`docs/session-export-format.md`](docs/session-export-format.md)
- [`docs/live-api-validation.md`](docs/live-api-validation.md)
- [`docs/performance.md`](docs/performance.md)
