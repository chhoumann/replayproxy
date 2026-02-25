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

## Common commands

```bash
# sessions
replayproxy session list --config ./replayproxy.toml
replayproxy session create test-session --config ./replayproxy.toml

# recordings
replayproxy recording list --config ./replayproxy.toml
replayproxy recording search "GET /api/get" --config ./replayproxy.toml
```

## Session export format

The stable on-disk export contract for `session export` is documented in
`docs/session-export-format.md` (layout, required fields, and deterministic
recording filename rules).
