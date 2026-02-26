# Session Export Format (v2)

This document defines the stable on-disk export format used by:

```bash
replayproxy session export <name> --format <json|yaml> --out <dir>
```

Current format support is JSON (`--format json`) and YAML (`--format yaml`).

## Directory Layout

Exports are written into a single output directory:

JSON export:

```text
<out>/
├── index.json
└── recordings/
    ├── 0001-post-v1-chat-completions-id42.json
    ├── 0002-get-v1-models-id43.json
    └── ...
```

YAML export:

```text
<out>/
├── index.yaml
└── recordings/
    ├── 0001-post-v1-chat-completions-id42.yaml
    ├── 0002-get-v1-models-id43.yaml
    └── ...
```

Notes:
- `<out>` must either not exist (it will be created) or be an empty directory.
- `index.json` or `index.yaml` is the manifest.
- `recordings/` contains one file per recording in the selected format.

## Manifest Schema (`index.json` / `index.yaml`)

Required top-level fields:
- `version` (`number`): manifest version. Current value is `2`.
- `session` (`string`): exported session name.
- `format` (`string`): serialization format (`"json"` or `"yaml"`).
- `exported_at_unix_ms` (`number`): export timestamp in Unix milliseconds.
- `recordings` (`array`): ordered list of exported recording entries.

Each `recordings[]` entry contains:
- `id` (`number`): SQLite recording id.
- `file` (`string`): relative path to the recording file, always under `recordings/`.
- `request_method` (`string`): request method.
- `request_uri` (`string`): request URI (path + query).
- `response_status` (`number`): HTTP response status code.
- `created_at_unix_ms` (`number`): recording creation timestamp in Unix milliseconds.

Example (JSON, abridged):

```json
{
  "version": 2,
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

## Recording File Schema (`recordings/*.{json|yaml}`)

Each recording file is an object with required fields:
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

`request_body` and `response_body` are raw bytes serialized in the selected format.

Optional fields:
- `response_chunks` (`array`): streaming replay metadata. Present when the source recording has stored response chunks.
  - `chunk_index` (`number`): zero-based chunk order.
  - `offset_ms` (`number`): elapsed milliseconds from stream start.
  - `chunk_body` (`bytes`): response bytes for the chunk.
- `websocket_frames` (`array`): websocket replay transcript metadata. Present when the source recording has stored websocket frames.
  - `frame_index` (`number`): zero-based frame order.
  - `offset_ms` (`number`): elapsed milliseconds from websocket session start.
  - `direction` (`string`): `"client-to-server"` or `"server-to-client"`.
  - `message_type` (`string`): `"text"` or `"binary"`.
  - `payload` (`bytes`): websocket frame payload.

When `response_chunks` is missing or empty, replay falls back to non-stream chunked-body reconstruction.
When `websocket_frames` is missing or empty, websocket replay has no transcript frames to serve.

## Versioning And Compatibility

- Export currently writes manifest `version: 2`.
- Import accepts both `version: 1` and `version: 2`.
- `version: 1` bundles do not include `response_chunks` or `websocket_frames`.
- `version: 2` bundles may include optional `response_chunks` and `websocket_frames` per recording.

## Deterministic Ordering And Filenames

Exported recordings are sorted by recording `id` ascending before writing files.

Filenames are deterministic and generated from:
- recording order index in the sorted export list
- recording `id`
- request method
- request URI

Format:

```text
{index:04}-{method_slug}-{uri_slug}-id{id}.{json|yaml}
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
