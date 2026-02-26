# Hardening Evidence - Portability and Failure Modes

Date (UTC): 2026-02-26T13:14:42Z
Issue: replayproxy-ivx.32

## Scope
- Validate export -> import -> replay workflows for:
  - HTTP streaming recordings
  - WebSocket recordings
  - gRPC recordings
- Execute failure-mode scenarios for:
  - upstream reset / malformed upstream response
  - timeout boundary behavior
  - admin API auth misconfiguration recovery
- Check portability behavior across default and `grpc` feature builds.

## Commands and Results

### Export/Import/Replay coverage
- `cargo test --test reverse_proxy export_import_round_trip -- --nocapture`
  - Passed: 4
  - Failed: 0
  - Coverage includes:
    - websocket_export_import_round_trip_replays_from_imported_session
    - admin_session_export_import_round_trip_replays_from_imported_fresh_session
    - streaming_export_import_round_trip_replays_from_imported_session
    - grpc_export_import_round_trip_replays_from_imported_session

### Failure-mode scenarios
- `cargo test --test reverse_proxy record_mode_upstream_reset_returns_502_and_subsequent_requests_recover -- --exact --nocapture`
  - Passed: 1
  - Failed: 0
  - Validates first-request upstream reset failure (`502`) and subsequent request recovery.

- `cargo test --test reverse_proxy record_mode_rate_limit_queue_timeout_returns_gateway_timeout -- --exact --nocapture`
  - Passed: 1
  - Failed: 0
  - Validates timeout boundary behavior and no unintended upstream forwarding.

- `cargo test --test reverse_proxy admin_config_reload_recovers_from_admin_api_token_misconfiguration -- --exact --nocapture`
  - Passed: 1
  - Failed: 0
  - Validates admin auth misconfiguration rejection, unchanged live auth after failed reload, and successful recovery reload.

### Portability checks (`grpc` feature build)
- `cargo test --features grpc --test reverse_proxy grpc_export_import_round_trip_replays_from_imported_session -- --exact --nocapture`
  - Passed: 1
  - Failed: 0
  - Compile: ~18.06s (cold feature compile), test: ~0.40s

- `cargo test --features grpc --test reverse_proxy grpc_opaque_record_then_replay_matches_on_raw_request_bytes -- --exact --nocapture`
  - Passed: 1
  - Failed: 0
  - Compile: ~0.98s, test: ~0.28s

- `cargo test --features grpc --test reverse_proxy grpc_proto_aware_record_then_replay_matches_selected_fields -- --exact --nocapture`
  - Passed: 1
  - Failed: 0
  - Compile: ~0.14s, test: ~0.30s

## Notes
- Initial implementation of upstream reset hardening test was nondeterministic due connection/retry behavior; helper revised to deterministically consume the first request and emit a truncated response before entering healthy-response mode for follow-up requests.
- No additional regressions observed in targeted hardening coverage.
