# Release Policy (v1)

This document defines how `replayproxy` v1 releases are cut and promoted.

## Scope

This policy applies to public GitHub Releases for:

- `linux` (`amd64`, `arm64`)
- `macos` (`amd64`, `arm64`)

This policy explicitly excludes for v1:

- Windows binaries
- Docker images
- Homebrew tap/formula distribution

## SemVer and Tag Rules

`replayproxy` uses Semantic Versioning tags:

- Stable release tags: `vMAJOR.MINOR.PATCH` (example: `v1.2.3`)
- Release candidate tags: `vMAJOR.MINOR.PATCH-rc.N` (example: `v1.2.3-rc.1`)

Rules:

- Stable tags MUST be immutable; no retagging.
- RC tags MUST be immutable; fixes require a new `-rc.N+1` tag.
- Stable promotion MUST use the same commit as the final RC.
- If code changes are needed after an RC, cut a new RC instead of promoting.

Version bump intent:

- `PATCH`: backward-compatible fixes and internal hardening
- `MINOR`: backward-compatible features/behavior additions
- `MAJOR`: breaking changes to CLI/API/config/runtime behavior

## RC Cadence and Promotion

Cadence for each planned stable release:

- Cut `-rc.1` when target scope is merged and default CI is green on `main`.
- If an RC fails any gate, merge fixes and cut the next RC within 2 business days.
- Promote to stable only after one RC has passed all gates and has at least a 24-hour soak window.

Promotion rule:

- Promote by creating `vMAJOR.MINOR.PATCH` from the exact final RC commit.

## Artifact and Platform Matrix (v1)

Release workflow MUST publish exactly these target binaries:

| OS | Arch | Rust target triple |
| --- | --- | --- |
| Linux | amd64 | `x86_64-unknown-linux-gnu` |
| Linux | arm64 | `aarch64-unknown-linux-gnu` |
| macOS | amd64 | `x86_64-apple-darwin` |
| macOS | arm64 | `aarch64-apple-darwin` |

Required release assets:

- One archive per supported target
- `SHA256SUMS` file with checksums for every archive

## Pre-Release Quality Gates (Must Pass)

All gates are required before promoting RC to stable:

1. Commit quality gate (release commit):
   - `cargo fmt --all -- --check`
   - `cargo clippy --all-targets --all-features --locked`
   - `cargo test --all-targets --all-features --locked`
2. Build/publish gate (tag workflow):
   - All four target builds succeed
   - All required assets are uploaded to GitHub Release
   - `SHA256SUMS` is present in release assets
3. Artifact validation gate:
   - Every asset checksum verifies against `SHA256SUMS`
   - Each artifact passes smoke checks (`--version`, `--help`, startup sanity)
4. Evidence gate:
   - RC issue notes include links to successful build/publish and validation workflow runs

Any failed gate blocks stable promotion until fixed in a new RC.
