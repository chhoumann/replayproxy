# Hardening Evidence - TLS/Connectivity Chaos and Idle Socket Recovery

Date (UTC): 2026-02-26T13:51:38Z
Issue: replayproxy-ivx.35

## Scope
- Add and execute targeted chaos scenarios for:
  - Repeated TLS MITM handshake failures (untrusted client trust roots)
  - Repeated upstream connect failures over direct HTTP/2 request path
  - Slow/idle partial-client-request sockets and disconnect recovery
- Validate recovery behavior with explicit `active_connections` drain checks.

## Commands and Results

### Targeted hardening tests
- `cargo test --test reverse_proxy direct_http2_route_recovers_after_repeated_upstream_connect_failures -- --exact --nocapture`
  - Passed: 1
  - Failed: 0
  - Duration: ~10.74s (initial compile path)

- `cargo test --test reverse_proxy https_connect_mitm_untrusted_tls_handshake_failures_recover_without_connection_leak -- --exact --nocapture`
  - Passed: 1
  - Failed: 0
  - Duration: ~1.07s

- `cargo test --test reverse_proxy slow_and_idle_clients_disconnect_without_sticking_active_connections -- --exact --nocapture`
  - Passed: 1
  - Failed: 0
  - Duration: ~0.32s

### Post-format verification rerun
- `cargo test --test reverse_proxy direct_http2_route_recovers_after_repeated_upstream_connect_failures -- --exact`
  - Passed: 1
  - Failed: 0

- `cargo test --test reverse_proxy https_connect_mitm_untrusted_tls_handshake_failures_recover_without_connection_leak -- --exact`
  - Passed: 1
  - Failed: 0

- `cargo test --test reverse_proxy slow_and_idle_clients_disconnect_without_sticking_active_connections -- --exact`
  - Passed: 1
  - Failed: 0

## Findings
- Repeated TLS handshake failures in CONNECT+MITM mode do not leave stuck `active_connections`; trusted follow-up requests succeed without restart.
- Repeated direct HTTP/2 upstream connect failures return controlled `502` responses and do not prevent subsequent healthy HTTP/2 upstream requests.
- Slow/idle client sockets (partial HTTP/1.1 headers, delayed disconnect) do not leak upstream requests and active connection counts drain to zero after disconnect.

## Follow-up Beads
- `replayproxy-ivx.37` - Add deterministic HTTP/2 truncated-upstream-response chaos test coverage (coverage gap tracked from this pass).
- `replayproxy-ivx.36` - Hardening loop next pass: DNS chaos, dual-stack connectivity, and TLS MITM edge conditions (queued next iteration prompt).
