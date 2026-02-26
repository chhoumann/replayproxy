#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: autocodex-closeout.sh --quality-gates-summary <text> --handoff-note <text> [options]

Validates completion criteria, emits a final handoff log line, and terminates a
replayproxy-autocodex tmux session.

Required arguments:
  --quality-gates-summary <text>  Summary of tests/lints/build checks run
  --handoff-note <text>           Final handoff note

Options:
  --tmux-session <name>           Explicit tmux session to terminate
  --session-prefix <prefix>       Allowed tmux session prefix (default: replayproxy-autocodex)
  --dry-run                       Validate and log only; do not terminate session
  -h, --help                      Show this help text
EOF
}

quality_gates_summary=""
handoff_note=""
tmux_session=""
session_prefix="replayproxy-autocodex"
dry_run=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --quality-gates-summary)
      quality_gates_summary="${2:-}"
      shift 2
      ;;
    --handoff-note)
      handoff_note="${2:-}"
      shift 2
      ;;
    --tmux-session)
      tmux_session="${2:-}"
      shift 2
      ;;
    --session-prefix)
      session_prefix="${2:-}"
      shift 2
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "${quality_gates_summary}" || -z "${handoff_note}" ]]; then
  echo "Both --quality-gates-summary and --handoff-note are required." >&2
  usage >&2
  exit 1
fi

for dependency in bd jq git tmux; do
  if ! command -v "${dependency}" >/dev/null 2>&1; then
    echo "Missing required dependency: ${dependency}" >&2
    exit 1
  fi
done

if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "autocodex-closeout.sh must run inside a git repository." >&2
  exit 1
fi

if [[ -z "${tmux_session}" ]]; then
  if [[ -z "${TMUX:-}" ]]; then
    echo "Not running inside tmux. Pass --tmux-session <name> explicitly." >&2
    exit 1
  fi
  tmux_session="$(tmux display-message -p '#S')"
fi

if [[ "${tmux_session}" != "${session_prefix}"* ]]; then
  echo "Refusing to terminate tmux session '${tmux_session}' (does not match prefix '${session_prefix}')." >&2
  exit 1
fi

if ! tmux has-session -t "${tmux_session}" 2>/dev/null; then
  echo "tmux session '${tmux_session}' does not exist." >&2
  exit 1
fi

open_count="$(bd list --status open --json | jq 'length')"
in_progress_count="$(bd list --status in_progress --json | jq 'length')"
blocked_count="$(bd blocked --json | jq 'length')"
ready_count="$(bd ready --json | jq 'length')"

if [[ "${open_count}" != "0" || "${in_progress_count}" != "0" || "${blocked_count}" != "0" || "${ready_count}" != "0" ]]; then
  echo "Completion criteria failed: open=${open_count}, in_progress=${in_progress_count}, blocked=${blocked_count}, ready=${ready_count}" >&2
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Git working tree is not clean. Commit/push all work before shutdown." >&2
  exit 1
fi

if git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' >/dev/null 2>&1; then
  read -r ahead_count behind_count <<<"$(git rev-list --left-right --count HEAD...@{upstream})"
  if [[ "${ahead_count}" != "0" || "${behind_count}" != "0" ]]; then
    echo "Branch is not up to date with upstream (ahead=${ahead_count}, behind=${behind_count})." >&2
    exit 1
  fi
fi

timestamp="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
final_log="[autocodex-closeout] ${timestamp} session=${tmux_session} quality_gates=\"${quality_gates_summary}\" handoff=\"${handoff_note}\" completion=open:0,in_progress:0,blocked:0,ready:0"

printf '%s\n' "${final_log}"
tmux display-message -t "${tmux_session}" "${final_log}"

if [[ "${dry_run}" == "1" ]]; then
  echo "Dry run requested; tmux session '${tmux_session}' was not terminated."
  exit 0
fi

tmux kill-session -t "${tmux_session}"
