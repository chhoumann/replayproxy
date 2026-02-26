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
REPLAYPROXY_PERF_REPETITIONS=5 \
REPLAYPROXY_PERF_MAX_CV=0.20 \
cargo test --test performance_harness -- --ignored --nocapture
```

Environment knobs:
- `REPLAYPROXY_PERF_REQUESTS` default `1000`: measured requests per scenario.
- `REPLAYPROXY_PERF_CONCURRENCY` default `32`: in-flight request cap.
- `REPLAYPROXY_PERF_WARMUP` default `100`: warmup requests before measured run.
- `REPLAYPROXY_PERF_RESPONSE_BYTES` default `2048`: upstream response payload size.
- `REPLAYPROXY_PERF_REPETITIONS` default `3`: number of full harness repetitions.
- `REPLAYPROXY_PERF_MAX_CV` default `0.20`: max allowed throughput coefficient of variation (CV)
  for `replay` and `passthrough-cache-warm`. Exceeding this threshold fails the test with a
  non-zero exit.

## Output Fields

The harness prints:
- one `perf_result ...` line per scenario per repetition (single-run metrics stay visible), and
- one `perf_summary ...` line per scenario with aggregated metrics across repetitions.

Key `perf_result` fields:
- `scenario`: benchmark scenario name.
- `requests`: measured request count.
- `success` / `errors`: status/result correctness counts.
- `throughput_rps`: successful requests per second.
- `total_ms`: wall-clock duration of measured run.
- `latency_avg_ms`, `latency_p50_ms`, `latency_p95_ms`, `latency_p99_ms`, `latency_max_ms`.
- `response_bytes_total`: total response bytes read by the client.
- `rss_before_kib`, `rss_after_kib`, `rss_delta_kib`, `hwm_after_kib` (Linux best-effort).
- `cache_hits_total`, `cache_misses_total`, `upstream_requests_total` (from `/_admin/status`).

Key `perf_summary` fields:
- `runs`: number of repetitions included.
- `throughput_median_rps`: per-scenario median throughput across runs.
- `latency_p95_median_ms`: per-scenario median p95 latency across runs.
- `throughput_min_rps` / `throughput_max_rps` / `throughput_cv`: spread of throughput.
- `latency_p95_min_ms` / `latency_p95_max_ms` / `latency_p95_cv`: spread of p95 latency.

Example shape:

```text
perf_result repetition=2 repetitions=5 scenario=replay requests=1000 success=1000 errors=0 throughput_rps=12345.67 total_ms=80.91 latency_avg_ms=2.101 latency_p50_ms=1.722 latency_p95_ms=4.938 latency_p99_ms=7.244 latency_max_ms=15.332 response_bytes_total=2048000 rss_before_kib=91500 rss_after_kib=93240 rss_delta_kib=1740 hwm_after_kib=94012 cache_hits_total=1100 cache_misses_total=0 upstream_requests_total=0
perf_summary scenario=replay runs=5 throughput_median_rps=12123.45 latency_p95_median_ms=5.112 throughput_min_rps=11800.11 throughput_max_rps=12456.78 throughput_cv=0.0213 latency_p95_min_ms=4.938 latency_p95_max_ms=5.491 latency_p95_cv=0.0407
```

## Baseline Snapshot (2026-02-26)

Captured with:

```bash
REPLAYPROXY_PERF_REQUESTS=240 \
REPLAYPROXY_PERF_CONCURRENCY=24 \
REPLAYPROXY_PERF_WARMUP=48 \
REPLAYPROXY_PERF_RESPONSE_BYTES=2048 \
REPLAYPROXY_PERF_REPETITIONS=1 \
cargo test --test performance_harness performance_harness_record_replay_passthrough_cache -- --ignored --nocapture
```

Results:

| Scenario | Throughput (rps) | p95 (ms) | p99 (ms) | RSS delta (KiB) |
| --- | ---: | ---: | ---: | ---: |
| `record` | 1190.96 | 62.141 | 133.628 | 19200 |
| `replay` | 3180.01 | 12.539 | 15.483 | 896 |
| `passthrough-cache-cold` | 873.59 | 67.868 | 128.601 | 1664 |
| `passthrough-cache-warm` | 3546.21 | 11.370 | 17.146 | 128 |

## Profiling Artifact + Optimization Measurement

Targeted CPU hotspot probe for subset-query replay fallback:

```bash
REPLAYPROXY_PERF_MATCHING_ITERS=300 \
cargo test perf_normalized_subset_query_matcher_vs_legacy_sorting --release -- --ignored --nocapture
```

Measured artifact output:

```text
perf_subset_matching legacy_ms=157.15 optimized_ms=68.70 speedup=2.29x iterations=300 dataset=2000
```

Hotspot identified:
- Repeated parse+sort of `request_query_norm` during subset-scan fallback lookups.

Optimization implemented:
- `subset_normalized_query_matches_parsed_request` now uses ordered matching directly on normalized
  query strings and only falls back to the legacy parser for unsorted legacy rows.
- Fallback subset lookup now prefilters candidates through `recording_query_param_index`, which
  reduces large `match_key` bucket scans before semantic verification.

## Performance Guardrails

Use this harness for regression detection, not absolute cross-machine comparison.

Recommended process:
1. Use `REPLAYPROXY_PERF_REPETITIONS` (for example `3` or `5`) to gather medians/spread in one run.
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
