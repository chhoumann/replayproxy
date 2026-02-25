# Session Export Format (v1)

This document defines the stable on-disk export format used by:

```bash
replayproxy session export <name> --format json --out <dir>
```

Current format support is JSON only (`--format json`).

## Directory Layout

Exports are written into a single output directory:

```text
<out>/
├── index.json
└── recordings/
    ├── 0001-post-v1-chat-completions-id42.json
    ├── 0002-get-v1-models-id43.json
    └── ...
```

Notes:
- `<out>` must either not exist (it will be created) or be an empty directory.
- `index.json` is the manifest.
- `recordings/` contains one JSON file per recording.

## Manifest Schema (`index.json`)

Required top-level fields:
- `version` (`number`): format version. Current value is `1`.
- `session` (`string`): exported session name.
- `format` (`string`): serialization format. Current value is `"json"`.
- `exported_at_unix_ms` (`number`): export timestamp in Unix milliseconds.
- `recordings` (`array`): ordered list of exported recording entries.

Each `recordings[]` entry contains:
- `id` (`number`): SQLite recording id.
- `file` (`string`): relative path to the recording file, always under `recordings/`.
- `request_method` (`string`): request method.
- `request_uri` (`string`): request URI (path + query).
- `response_status` (`number`): HTTP response status code.
- `created_at_unix_ms` (`number`): recording creation timestamp in Unix milliseconds.

Example (abridged):

```json
{
  "version": 1,
  "session": "default",
  "format": "json",
  "exported_at_unix_ms": 1767066000123,
  "recordings": [
    {
      "id": 42,
      "file": "recordings/0001-post-v1-chat-completions-id42.json",
      "request_method": "POST",
      "request_uri": "/v1/chat/completions",
      "response_status": 200,
      "created_at_unix_ms": 1767065999000
    }
  ]
}
```

## Recording File Schema (`recordings/*.json`)

Each recording file is a JSON object with required fields:
- `id`
- `match_key`
- `request_method`
- `request_uri`
- `request_headers`
- `request_body`
- `response_status`
- `response_headers`
- `response_body`
- `created_at_unix_ms`

`request_headers` and `response_headers` are arrays of `[name, value]` pairs where `value` is bytes.

`request_body` and `response_body` are raw bytes serialized as JSON arrays of integers (`0..255`).

## Deterministic Ordering And Filenames

Exported recordings are sorted by recording `id` ascending before writing files.

Filenames are deterministic and generated from:
- recording order index in the sorted export list
- recording `id`
- request method
- request URI

Format:

```text
{index:04}-{method_slug}-{uri_slug}-id{id}.json
```

Rules:
- `index` is 1-based, zero-padded to 4 digits.
- `method_slug`:
  - lowercases ASCII characters
  - keeps only ASCII alphanumerics
  - collapses runs of non-alphanumeric characters into a single `-`
  - trims leading/trailing `-`
  - truncates to max 16 chars
  - falls back to `request` if empty
- `uri_slug` uses the same normalization with max 48 chars and fallback `path`.

Given identical exported data, output ordering and filenames are stable.
