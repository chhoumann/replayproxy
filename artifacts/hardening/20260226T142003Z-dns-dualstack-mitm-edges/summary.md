# Hardening Evidence - DNS Chaos, Dual-Stack CONNECT, and MITM TLS Edge Recovery

Date (UTC): 2026-02-26T14:20:03Z
Issue: replayproxy-ivx.36

## Scope
- Execute targeted chaos scenarios for:
  - repeated upstream DNS resolution failures on direct HTTP/2 routes
  - repeated CONNECT tunnel failures across mixed dual-stack authorities (`localhost`, IPv4 literal, IPv6 literal)
  - repeated CONNECT+MITM flows where clients disconnect before TLS handshake completion
- Validate recovery behavior and `active_connections` drain after repeated fault cycles.

## Commands and Results

### Targeted hardening tests
- `cargo test --test reverse_proxy direct_http2_route_dns_resolution_failures_recover_without_connection_leak -- --exact --nocapture`
  - Passed: 1
  - Failed: 0
  - Duration: ~0.38s

- `cargo test --test reverse_proxy forward_proxy_connect_dual_stack_failures_recover_without_connection_leak -- --exact --nocapture`
  - Passed: 1
  - Failed: 0
  - Duration: ~0.14s

- `cargo test --test reverse_proxy https_connect_mitm_client_disconnects_before_tls_handshake_recover_without_connection_leak -- --exact --nocapture`
  - Passed: 1
  - Failed: 0
  - Duration: ~0.13s

## Findings
- Repeated DNS resolution failures on a direct HTTP/2 route return controlled `502` errors and do not prevent subsequent healthy HTTP/2 upstream requests.
- Repeated CONNECT dial failures across `localhost`, IPv4 literal (`127.0.0.1`), and IPv6 literal (`[::1]`) authorities recover cleanly; a subsequent healthy CONNECT tunnel succeeds and `active_connections` drains to zero.
- Repeated CONNECT+MITM client disconnects before TLS handshake completion do not leave stuck connections; subsequent trusted MITM traffic succeeds without restart.

## Follow-up Beads
- None required from this pass.
