#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: generate-release-notes.sh --tag <tag> --output <path> [--repo <owner/name>]

Builds release notes with:
- Highlights
- Breaking Changes
- Migration Notes
- Full changelog

Manual override:
If .github/release-notes/<tag>.md exists, it is used directly.
EOF
}

tag=""
output_path=""
repo="${GH_REPO:-${GITHUB_REPOSITORY:-}}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)
      tag="${2:-}"
      shift 2
      ;;
    --output)
      output_path="${2:-}"
      shift 2
      ;;
    --repo)
      repo="${2:-}"
      shift 2
      ;;
    --help|-h)
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

if [[ -z "${tag}" || -z "${output_path}" || -z "${repo}" ]]; then
  usage >&2
  exit 1
fi

if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "generate-release-notes.sh must run from a git repository" >&2
  exit 1
fi

mkdir -p "$(dirname "${output_path}")"

override_file=".github/release-notes/${tag}.md"
if [[ -f "${override_file}" ]]; then
  cp "${override_file}" "${output_path}"
  exit 0
fi

repo_url="https://github.com/${repo}"

mapfile -t tags < <(git tag --list 'v*' --sort=-version:refname)
previous_tag=""
for candidate in "${tags[@]}"; do
  if [[ "${candidate}" != "${tag}" ]]; then
    previous_tag="${candidate}"
    break
  fi
done

range_spec="${tag}"
if [[ -n "${previous_tag}" ]]; then
  range_spec="${previous_tag}..${tag}"
fi

format_entry() {
  local sha="$1"
  local subject="$2"
  local short_sha="${sha:0:7}"
  local line="- ${subject} ([\`${short_sha}\`](${repo_url}/commit/${sha})"

  if [[ "${subject}" =~ \#([0-9]+) ]]; then
    line="${line}, [#${BASH_REMATCH[1]}](${repo_url}/pull/${BASH_REMATCH[1]})"
  fi

  line="${line})"
  printf '%s\n' "${line}"
}

declare -a all_entries=()
declare -a highlight_entries=()
declare -a breaking_entries=()

while IFS='|' read -r sha subject; do
  [[ -z "${sha}" ]] && continue
  entry="$(format_entry "${sha}" "${subject}")"
  all_entries+=("${entry}")

  lower_subject="$(printf '%s' "${subject}" | tr '[:upper:]' '[:lower:]')"
  if [[ "${lower_subject}" =~ (^|[[:space:]])breaking([[:space:]]|:|$) ]] || [[ "${subject}" =~ ^[a-zA-Z0-9_-]+!\: ]]; then
    breaking_entries+=("${entry}")
  fi

  if [[ ! "${lower_subject}" =~ ^(ci|chore|docs|test)(\(.+\))?: ]]; then
    highlight_entries+=("${entry}")
  fi
done < <(git log --no-merges --format='%H|%s' "${range_spec}")

generated_notes=""
if command -v gh >/dev/null 2>&1; then
  generate_args=(api "repos/${repo}/releases/generate-notes" --method POST -f "tag_name=${tag}")
  if [[ -n "${previous_tag}" ]]; then
    generate_args+=(-f "previous_tag_name=${previous_tag}")
  fi

  if generated_notes="$(gh "${generate_args[@]}" --jq '.body' 2>/dev/null)"; then
    :
  else
    generated_notes=""
  fi
fi

{
  echo "# replayproxy ${tag}"
  echo
  echo "## Highlights"
  if [[ "${#highlight_entries[@]}" -eq 0 ]]; then
    echo "- No user-facing changes identified in this tag."
  else
    for entry in "${highlight_entries[@]:0:8}"; do
      echo "${entry}"
    done
  fi
  echo
  echo "## Breaking Changes"
  if [[ "${#breaking_entries[@]}" -eq 0 ]]; then
    echo "- None."
  else
    for entry in "${breaking_entries[@]}"; do
      echo "${entry}"
    done
  fi
  echo
  echo "## Migration Notes"
  if [[ "${#breaking_entries[@]}" -eq 0 ]]; then
    echo "- No migration actions required."
  else
    echo "- Review breaking changes above and validate replayproxy CLI/config flows before rollout."
  fi
  echo
  echo "## Full Changelog"
  if [[ -n "${generated_notes}" ]]; then
    echo
    echo "${generated_notes}"
  else
    echo
    if [[ -n "${previous_tag}" ]]; then
      echo "- Compare: ${repo_url}/compare/${previous_tag}...${tag}"
    else
      echo "- First tagged release in this repository."
    fi
    for entry in "${all_entries[@]}"; do
      echo "${entry}"
    done
  fi
} > "${output_path}"
