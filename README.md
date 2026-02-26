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

## Forward proxy + HTTPS MITM (macOS/Linux)

Use forward proxy mode when clients should call original upstream URLs and route through `replayproxy` via `HTTP_PROXY`/`HTTPS_PROXY`.

### 1) Generate local CA material

```bash
replayproxy ca generate
```

Default output:
- `~/.replayproxy/ca/cert.pem`
- `~/.replayproxy/ca/key.pem`

### 2) Trust the CA certificate

macOS:

```bash
replayproxy ca install
```

If automatic install falls back to manual mode, run:

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.replayproxy/ca/cert.pem
```

Linux:

```bash
replayproxy ca install
```

On Debian/Ubuntu/Alpine, the automatic path copies the cert to
`/usr/local/share/ca-certificates/replayproxy-ca.crt` and runs
`update-ca-certificates`. If that does not complete, run:

```bash
sudo cp ~/.replayproxy/ca/cert.pem /usr/local/share/ca-certificates/replayproxy-ca.crt
sudo update-ca-certificates
```

On Fedora/RHEL-family distros, install manually:

```bash
sudo trust anchor ~/.replayproxy/ca/cert.pem
```

### 3) Configure forward proxy routing

Create `replayproxy.toml`:

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

`path_prefix = "/"` is required so CONNECT and absolute-form proxy requests match a route.
Leave `upstream` unset to allow forwarding to arbitrary hosts from client request targets.

### 4) Run and route client traffic through the proxy

```bash
replayproxy serve --config ./replayproxy.toml
```

In another terminal:

```bash
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
curl https://example.com/
```

If your client ignores proxy env vars, pass proxy settings explicitly in that client/tool.

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

### Forward proxy + CA install failures

`replayproxy ca install` prints either an installed method or:

```text
automatic CA install did not complete
```

Follow the platform-specific manual command printed after that line.

Common failures and fixes:
- `CA certificate not found ... run replayproxy ca generate first`: run `replayproxy ca generate` before install/export.
- `permission denied writing /usr/local/share/ca-certificates/replayproxy-ca.crt`: rerun Linux trust steps with `sudo`.
- `update-ca-certificates` command not found: install CA certificates tooling for your distro, or use distro-specific manual trust commands.
- `TLS handshake for CONNECT authority ... ensure client trust includes the replayproxy CA certificate`: client does not trust the replayproxy CA yet; complete install and restart the client process.
- `incomplete proxy.tls CA material` or `missing proxy.tls CA material`: verify both configured files exist and point to matching `cert.pem` + `key.pem`.
- Requests are not hitting replayproxy at all: clear or adjust `NO_PROXY`/`no_proxy` so your target host is not bypassing proxy env vars.

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
