# replayproxy

`replayproxy` is a local reverse proxy that can record upstream HTTP responses and replay them later from local storage.

## Build and install

Prerequisite: Rust toolchain (stable) with Cargo.

```bash
# build a release binary
cargo build --release

# run from the built binary
./target/release/replayproxy --help
```

Optional local install:

```bash
cargo install --path .
replayproxy --help
```

## Minimal reverse proxy config

Create `replayproxy.toml` in the project root:

```toml
[proxy]
listen = "127.0.0.1:8080"
mode = "record"

[storage]
path = "./.replayproxy-data"
active_session = "default"

[[routes]]
name = "httpbin"
path_prefix = "/api"
upstream = "https://httpbin.org"
```

Config discovery (if `--config` is omitted):
- `./replayproxy.toml`
- `~/.replayproxy/config.toml`

## Example configs

Sample configs are included in [`examples/`](examples):
- [`examples/replayproxy.minimal.toml`](examples/replayproxy.minimal.toml): minimal reverse-proxy setup.
- [`examples/replayproxy.llm-redacted.toml`](examples/replayproxy.llm-redacted.toml): LLM-focused setup with route matching and redaction.

Try one directly:

```bash
cp ./examples/replayproxy.llm-redacted.toml ./replayproxy.toml
./target/release/replayproxy serve --config ./replayproxy.toml
```

## Admin API safety

If `proxy.admin_port` is configured, the admin listener binds to loopback by default
(`127.0.0.1` for IPv4 configs, `::1` for IPv6 configs), so admin endpoints are local-only.

To expose the admin listener intentionally, set `proxy.admin_bind`:

```toml
[proxy]
listen = "0.0.0.0:8080"
admin_port = 8081
admin_bind = "0.0.0.0"
```

You can also require a shared secret header on all admin endpoints:

```toml
[proxy]
listen = "127.0.0.1:8080"
admin_port = 8081
admin_api_token = "replace-with-strong-secret"
```

When `admin_api_token` is set, clients must send:
- Header: `x-replayproxy-admin-token`
- Value: exact token string from config

## Quickstart: record then replay

1. Start the proxy in record mode:

```bash
./target/release/replayproxy serve --config ./replayproxy.toml
```

2. In another terminal, send traffic through the proxy route:

```bash
curl -sS http://127.0.0.1:8080/api/get?demo=1
```

3. Confirm recordings were stored:

```bash
./target/release/replayproxy recording list --config ./replayproxy.toml
```

4. Stop the proxy, change config to replay mode, then start again:

```toml
[proxy]
listen = "127.0.0.1:8080"
mode = "replay"
```

```bash
./target/release/replayproxy serve --config ./replayproxy.toml
```

5. Send the same request again:

```bash
curl -i http://127.0.0.1:8080/api/get?demo=1
```

The response should now come from local storage (no upstream call). If no recording matches, replay mode returns `502 Gateway Not Recorded`.

## Troubleshooting

### `502 Gateway Not Recorded` in replay mode

Replay misses return `502` and include JSON fields like `error`, `route`, `session`, and `match_key`.

Quick checks:

```bash
# Verify current runtime mode (requires admin API)
replayproxy mode show --config ./replayproxy.toml --admin-addr 127.0.0.1:8081

# Inspect recordings in the active session
replayproxy recording list --config ./replayproxy.toml
replayproxy recording search "GET /api/get?demo=1" --config ./replayproxy.toml

# Inspect runtime counters (cache_misses_total, active_session, etc.)
curl -sS http://127.0.0.1:8081/_admin/status
```

Common fixes:
- Record seed traffic first (`record` or `passthrough-cache`) so replay has matching entries.
- Confirm you are querying the expected session (`storage.active_session` or `session switch`).
- Ensure method/path/query/body/header matching config has not drifted from recorded traffic.
- For replay fallback behavior, set route `cache_miss = "forward"` instead of returning `502`.

### TLS/CA trust and cert/key errors

If TLS is enabled but CA paths are missing, startup fails fast with config errors:
- `proxy.tls.ca_cert` is required when `proxy.tls.enabled = true`
- `proxy.tls.ca_key` is required when `proxy.tls.enabled = true`

Use an explicit TLS block:

```toml
[proxy.tls]
enabled = true
ca_cert = "~/.replayproxy/ca/cert.pem"
ca_key = "~/.replayproxy/ca/key.pem"
```

When both configured paths end in `cert.pem` and `key.pem` and both files are absent, `serve` auto-generates local CA material at startup using the same secure code path as `replayproxy ca generate`.

For custom file names or partially missing files, generate material explicitly and verify both files exist/readable:

```bash
ls -l ~/.replayproxy/ca/cert.pem ~/.replayproxy/ca/key.pem
```

If clients report trust failures (for example, unknown authority), make sure the client trusts the configured CA certificate. For quick local checks with `curl`, you can point directly at the CA:

```bash
curl --cacert ~/.replayproxy/ca/cert.pem https://example.test
```

### Config reload not applying

Manual reload endpoint:

```bash
curl -sS -X POST http://127.0.0.1:8081/_admin/config/reload
```

Notes:
- `409` + `config reload unavailable` means proxy was not started from a config file path. Start with `serve --config ./replayproxy.toml`.
- `400` parse errors indicate invalid TOML/route parsing in the updated config file.
- Reload response includes `changed`, `routes_before/routes_after`, and route diff counts; use it to confirm whether anything was actually applied.
- Automatic file watching is enabled in default builds and reloads are debounced (~250ms), so rapid edits may apply as a single update.

## Common commands

```bash
# sessions
replayproxy session list --config ./replayproxy.toml
replayproxy session create test-session --config ./replayproxy.toml

# mode (requires admin API to be enabled)
replayproxy mode show --config ./replayproxy.toml --admin-addr 127.0.0.1:8081
replayproxy mode set replay --config ./replayproxy.toml --admin-addr 127.0.0.1:8081
replayproxy mode set record --config ./replayproxy.toml --admin-addr 127.0.0.1:8081 --persist

# recordings
replayproxy recording list --config ./replayproxy.toml
replayproxy recording search "GET /api/get" --config ./replayproxy.toml

# local CA management
replayproxy ca generate
replayproxy ca install
replayproxy ca export --out ./replayproxy-ca.pem

# bundled presets
replayproxy preset import openai
```

`mode set` changes the running proxy immediately through `/_admin/mode`; `--persist` also writes
`proxy.mode` back to the loaded config file.

## Session export format

The stable on-disk export contract for `session export` is documented in
`docs/session-export-format.md` (layout, required fields, and deterministic
recording filename rules).
