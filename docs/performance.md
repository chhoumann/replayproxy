# Performance Harness

`tests/performance_harness.rs` provides an ignored, benchmark-style integration test for the
main traffic modes:
- `record`
- `replay` (cache-hit path)
- `passthrough-cache` cold (populate cache)
- `passthrough-cache` warm (cache-hit path)

It runs local upstream/proxy servers in-process, drives concurrent request load, and prints
throughput + latency summaries. On Linux, it also prints best-effort RSS/HWM memory snapshots
from `/proc/self/status`.

## Run

Compile-check only:

```bash
cargo test --test performance_harness --no-run
```

Run the harness (ignored test, with output):

```bash
cargo test --test performance_harness -- --ignored --nocapture
```

Tune load shape:

```bash
REPLAYPROXY_PERF_REQUESTS=2000 \
REPLAYPROXY_PERF_CONCURRENCY=64 \
REPLAYPROXY_PERF_WARMUP=200 \
REPLAYPROXY_PERF_RESPONSE_BYTES=4096 \
cargo test --test performance_harness -- --ignored --nocapture
```

Environment knobs:
- `REPLAYPROXY_PERF_REQUESTS` default `1000`: measured requests per scenario.
- `REPLAYPROXY_PERF_CONCURRENCY` default `32`: in-flight request cap.
- `REPLAYPROXY_PERF_WARMUP` default `100`: warmup requests before measured run.
- `REPLAYPROXY_PERF_RESPONSE_BYTES` default `2048`: upstream response payload size.

## Output Fields

The harness prints one `perf_result ...` line per scenario. Key fields:
- `scenario`: benchmark scenario name.
- `requests`: measured request count.
- `success` / `errors`: status/result correctness counts.
- `throughput_rps`: successful requests per second.
- `total_ms`: wall-clock duration of measured run.
- `latency_avg_ms`, `latency_p50_ms`, `latency_p95_ms`, `latency_p99_ms`, `latency_max_ms`.
- `response_bytes_total`: total response bytes read by the client.
- `rss_before_kib`, `rss_after_kib`, `rss_delta_kib`, `hwm_after_kib` (Linux best-effort).
- `cache_hits_total`, `cache_misses_total`, `upstream_requests_total` (from `/_admin/status`).

Example shape:

```text
perf_result scenario=replay requests=1000 success=1000 errors=0 throughput_rps=12345.67 total_ms=80.91 latency_avg_ms=2.101 latency_p50_ms=1.722 latency_p95_ms=4.938 latency_p99_ms=7.244 latency_max_ms=15.332 response_bytes_total=2048000 rss_before_kib=91500 rss_after_kib=93240 rss_delta_kib=1740 hwm_after_kib=94012 cache_hits_total=1100 cache_misses_total=0 upstream_requests_total=0
```

## Performance Guardrails

Use this harness for regression detection, not absolute cross-machine comparison.

Recommended process:
1. Run at least 3 times on the same machine and take the median per field.
2. Keep baseline artifacts in release notes/PR comments.
3. Flag regressions when any of the below trigger:
- `errors > 0` for any scenario.
- `throughput_rps` drops by more than 15% vs baseline in the same scenario.
- `latency_p95_ms` increases by more than 20% vs baseline in the same scenario.
- `replay` does not outperform `record` throughput on the same run.
- `passthrough-cache-warm` does not outperform `passthrough-cache-cold` throughput on the same run.
- `rss_delta_kib` grows unexpectedly (for example > 131072 KiB / 128 MiB) without a justified change.

These thresholds are starting points. Tighten them after you collect stable baselines for your
CI runners and representative developer machines.
