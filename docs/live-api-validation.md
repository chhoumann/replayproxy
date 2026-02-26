# Live API Validation

## Purpose

Run opt-in end-to-end checks against real external APIs before release. This suite validates:

- reverse proxy `record -> replay` on HTTP
- reverse proxy `record -> replay` on HTTPS
- forward proxy `passthrough-cache` over HTTPS CONNECT/MITM
- redaction persistence in stored recordings for real captured payloads

These tests are intentionally excluded from default CI and run only when explicitly enabled.

## Opt-In Environment Variables

Required gate:

```bash
export REPLAYPROXY_LIVE_TESTS=1
```

Optional overrides:

```bash
# Defaults shown below:
export REPLAYPROXY_LIVE_HTTP_ORIGIN="${REPLAYPROXY_LIVE_HTTP_ORIGIN:-http://httpbingo.org}"
export REPLAYPROXY_LIVE_HTTPS_ORIGIN="${REPLAYPROXY_LIVE_HTTPS_ORIGIN:-https://httpbingo.org}"
export REPLAYPROXY_LIVE_SECRET="${REPLAYPROXY_LIVE_SECRET:-live-secret-token}"
```

`REPLAYPROXY_LIVE_SECRET` is injected into live request headers/body and must never appear unredacted in stored recordings.

## Matrix Coverage

| Test | Path | Mode(s) | Protocol | Verification |
| --- | --- | --- | --- | --- |
| `live_reverse_proxy_record_replay_http` | Reverse | `record`, `replay` | HTTP | Same request replays from storage; admin stats show replay cache hit and no upstream requests in replay run |
| `live_reverse_proxy_record_replay_https` | Reverse | `record`, `replay` | HTTPS upstream | Same as HTTP case, over TLS upstream |
| `live_forward_proxy_passthrough_cache_redacts_stored_payloads` | Forward (CONNECT/MITM) | `passthrough-cache` | HTTPS target | First request miss + upstream call; second request cache hit; SQLite recording confirms request/response redaction |

## Commands

Run the full live suite:

```bash
REPLAYPROXY_LIVE_TESTS=1 cargo test --test live_api_validation -- --ignored
```

Run a single case while iterating:

```bash
REPLAYPROXY_LIVE_TESTS=1 cargo test --test live_api_validation live_forward_proxy_passthrough_cache_redacts_stored_payloads -- --ignored --exact
```

If `REPLAYPROXY_LIVE_TESTS` is not set to a truthy value (`1`, `true`, `yes`), each live test intentionally fails fast.

## GitHub Actions workflow

Scheduled and manual CI runs are defined in
[`.github/workflows/live-api-validation.yml`](../.github/workflows/live-api-validation.yml).

- Schedule: weekly (`cron: 23 4 * * 1`).
- Manual: `workflow_dispatch` with optional `live_http_origin` and `live_https_origin` input overrides.
- Run command: `cargo test --locked --test live_api_validation -- --ignored --nocapture`.

Configuration precedence used by the workflow:

1. `workflow_dispatch` inputs (`live_http_origin`, `live_https_origin`)
2. repository variables (`REPLAYPROXY_LIVE_HTTP_ORIGIN`, `REPLAYPROXY_LIVE_HTTPS_ORIGIN`)
3. safe defaults (`http://httpbingo.org`, `https://httpbingo.org`)

Secret handling:

- Optional repository secret `REPLAYPROXY_LIVE_SECRET` is used when set.
- Safe fallback default is `live-secret-token`.
- The workflow masks the runtime secret and writes a job summary including resolved sources and run log links.

## Release Checklist (Pass/Fail)

1. Opt-in gating
- Pass: suite runs only with `REPLAYPROXY_LIVE_TESTS=1`.
- Fail: live tests run unintentionally in default `cargo test` flow.

2. Reverse HTTP record/replay
- Pass: test `live_reverse_proxy_record_replay_http` succeeds.
- Fail: test fails on status mismatch, replay mismatch, or cache/upstream counters.

3. Reverse HTTPS record/replay
- Pass: test `live_reverse_proxy_record_replay_https` succeeds.
- Fail: test fails on TLS upstream behavior, replay mismatch, or cache/upstream counters.

4. Forward HTTPS passthrough-cache correctness
- Pass: test `live_forward_proxy_passthrough_cache_redacts_stored_payloads` records one miss, then one hit, with no additional upstream request on second call.
- Fail: cache stats do not match expected miss/hit/upstream progression.

5. Redaction persistence with real payloads
- Pass: same forward test confirms SQLite recording stores redacted request authorization/token and redacted response fields.
- Fail: any secret value remains in persisted request/response recording artifacts.
