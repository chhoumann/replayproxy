# Releasing replayproxy (RC -> Stable)

This runbook defines the operator steps to cut release candidates (RCs), verify them, and
promote to stable tags.

Use this together with [RELEASE_POLICY.md](RELEASE_POLICY.md).

## CI Workflows and Required Secrets

Release automation and validation are implemented by:

- [`.github/workflows/ci.yml`](.github/workflows/ci.yml): `cargo fmt`, `cargo clippy`,
  `cargo test` on branch/PR pushes.
- [`.github/workflows/release.yml`](.github/workflows/release.yml): runs on `v*` tags, builds
  Linux/macOS amd64+arm64 archives, generates `SHA256SUMS`, and publishes GitHub Release assets.
- [`.github/workflows/release-validate.yml`](.github/workflows/release-validate.yml): validates
  published assets (checksum + smoke tests), and can be run manually for a specific tag.
- [`.github/workflows/live-api-validation.yml`](.github/workflows/live-api-validation.yml):
  scheduled + manual live-origin validation for opt-in external API checks.

Secrets/tokens:

- No custom repository secrets are required for release publish/validate workflows.
- Optional live-validation configuration:
  - repository variables: `REPLAYPROXY_LIVE_HTTP_ORIGIN`, `REPLAYPROXY_LIVE_HTTPS_ORIGIN`
  - repository secret: `REPLAYPROXY_LIVE_SECRET`
  - safe defaults are used when these are unset (see `docs/live-api-validation.md`)
- GitHub Actions uses the built-in `GITHUB_TOKEN` (`github.token`), surfaced as `GH_TOKEN` where
  needed in workflow steps.
- Human operators need `gh` CLI authenticated locally (`gh auth status`) to run the manual
  commands in this runbook.

## Supported Release Matrix (v1)

- Linux: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`
- macOS: `x86_64-apple-darwin`, `aarch64-apple-darwin`

Expected assets per tag:

- `replayproxy-<tag>-<target>.tar.gz` for each target above
- `SHA256SUMS`

## 1) Preflight Checklist (Before Cutting RC)

1. Ensure local repo is clean and up to date:
   ```bash
   git fetch origin --tags
   git checkout main
   git pull --ff-only origin main
   git status --short
   ```
2. Confirm default CI is green on `main` (`.github/workflows/ci.yml`).
3. Run local quality gate commands on the release commit:
   ```bash
   cargo fmt --all -- --check
   cargo clippy --all-targets --all-features --locked
   cargo test --all-targets --all-features --locked
   ```
4. Pick the next SemVer and RC number:
   - RC tag: `vMAJOR.MINOR.PATCH-rc.N` (for example `v1.4.0-rc.1`)
   - Stable tag: `vMAJOR.MINOR.PATCH` (for example `v1.4.0`)
5. Verify the RC tag does not already exist:
   ```bash
   RC_TAG="v1.4.0-rc.1"
   git rev-parse "${RC_TAG}" >/dev/null 2>&1 && echo "tag exists" && exit 1 || true
   ```

## 2) Cut an RC Tag

1. Create annotated RC tag from `main` HEAD:
   ```bash
   RC_TAG="v1.4.0-rc.1"
   git tag -a "${RC_TAG}" -m "replayproxy ${RC_TAG}"
   ```
2. Push the tag:
   ```bash
   git push origin "${RC_TAG}"
   ```
3. Confirm the `Release` workflow started for the RC tag:
   ```bash
   gh run list --workflow Release --limit 10
   ```

## 3) RC Verification Checklist

All checks must pass before promotion:

1. `Release` workflow succeeded for the RC tag (`.github/workflows/release.yml`).
2. GitHub Release exists for the RC tag and includes:
   - four `replayproxy-<tag>-<target>.tar.gz` assets
   - `SHA256SUMS`
3. `Validate Release Artifacts` workflow succeeded for all four targets
   (`.github/workflows/release-validate.yml`).
4. Optional manual re-run (if needed):
   ```bash
   gh workflow run "Validate Release Artifacts" -f tag="${RC_TAG}"
   gh run list --workflow "Validate Release Artifacts" --limit 10
   ```
5. Optional local verification from published assets:
   ```bash
   mkdir -p /tmp/replayproxy-release-check && cd /tmp/replayproxy-release-check
   gh release download "${RC_TAG}" --pattern "SHA256SUMS" --pattern "replayproxy-${RC_TAG}-*.tar.gz"
   if command -v sha256sum >/dev/null 2>&1; then
     sha256sum --check SHA256SUMS
   else
     shasum -a 256 -c SHA256SUMS
   fi
   ```
6. Record evidence links (Release run + validation run + release page) in the tracking issue.
7. Observe a minimum 24-hour soak after a fully passing RC before stable promotion.

## 4) Promote RC to Stable

Promotion must use the exact commit from the final RC tag.

1. Resolve commit SHA of final RC:
   ```bash
   RC_TAG="v1.4.0-rc.2"
   STABLE_TAG="v1.4.0"
   RC_SHA="$(git rev-list -n 1 "${RC_TAG}")"
   echo "${RC_SHA}"
   ```
2. Ensure stable tag does not exist:
   ```bash
   git rev-parse "${STABLE_TAG}" >/dev/null 2>&1 && echo "stable tag exists" && exit 1 || true
   ```
3. Create stable tag from RC commit and push:
   ```bash
   git tag -a "${STABLE_TAG}" "${RC_SHA}" -m "replayproxy ${STABLE_TAG}"
   git push origin "${STABLE_TAG}"
   ```
4. Verify the same checklist as RC (`Release` + `Validate Release Artifacts` + assets present).
5. Announce stable release with links to release notes and validation evidence.

## 5) Rollback and Revocation

### RC Failure Recovery

- Do not retag or move an existing RC tag.
- Fix forward on `main`, then cut a new RC (`-rc.N+1`) and repeat verification.
- If metadata needs correction (notes/title), edit the existing GitHub Release without changing the tag:
  ```bash
  gh release edit "${RC_TAG}" --title "replayproxy ${RC_TAG}" --notes-file ./release-notes.md
  ```

### Stable Rollback (Bad Release)

1. Mark the bad stable release as revoked in title/notes:
   ```bash
   STABLE_TAG="v1.4.0"
   gh release edit "${STABLE_TAG}" \
     --title "REVOKED: replayproxy ${STABLE_TAG}" \
     --notes-file ./revocation-notes.md
   ```
2. Cut a fixed patch release via new version (`vMAJOR.MINOR.PATCH+1-rc.1`), then promote normally.
3. Never re-use an existing stable tag.

### Emergency Revocation (Security/Legal)

Use only when release artifacts must be removed from distribution:

1. Delete GitHub Release:
   ```bash
   gh release delete "${STABLE_TAG}" --yes
   ```
2. Delete remote tag:
   ```bash
   git push origin ":refs/tags/${STABLE_TAG}"
   ```
3. Publish incident context in the tracker and create a new patched version tag; do not recreate the deleted tag.

## 6) Post-Release Cleanup

1. Update/close release tracking issues with links to:
   - tag
   - GitHub Release page
   - `Release` workflow run
   - `Validate Release Artifacts` workflow run
2. Capture follow-up work as new beads for any anomalies or manual interventions.
