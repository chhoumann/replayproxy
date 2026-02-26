use std::{
    collections::HashSet,
    ffi::OsStr,
    fs,
    io::ErrorKind,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    legacy_redaction, session,
    session_export::{EXPORT_MANIFEST_VERSION_V1, EXPORT_MANIFEST_VERSION_V2, SessionExportFormat},
    storage::{
        Recording, ResponseChunk, SessionManager, SessionManagerError, Storage, WebSocketFrame,
    },
};

#[derive(Debug, Clone)]
pub struct SessionImportRequest {
    pub session_name: String,
    pub in_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SessionImportResult {
    pub status: &'static str,
    pub session: String,
    pub format: SessionExportFormat,
    pub input_dir: PathBuf,
    pub manifest_path: PathBuf,
    pub recordings_imported: usize,
}

#[derive(Debug)]
pub enum SessionImportError {
    InvalidRequest(String),
    Session(SessionManagerError),
    Io(String),
    Internal(String),
}

impl std::fmt::Display for SessionImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(message) | Self::Io(message) | Self::Internal(message) => {
                f.write_str(message)
            }
            Self::Session(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for SessionImportError {}

impl From<SessionManagerError> for SessionImportError {
    fn from(value: SessionManagerError) -> Self {
        Self::Session(value)
    }
}

#[derive(Debug, Deserialize)]
struct ImportManifest {
    version: u32,
    session: String,
    format: SessionExportFormat,
    exported_at_unix_ms: i64,
    recordings: Vec<ImportManifestEntry>,
}

#[derive(Debug, Deserialize)]
struct ImportManifestEntry {
    id: i64,
    file: String,
    request_method: String,
    request_uri: String,
    response_status: u16,
    created_at_unix_ms: i64,
}

#[derive(Debug, Deserialize)]
struct ImportRecordingDocument {
    id: i64,
    #[serde(flatten)]
    recording: Recording,
    #[serde(default)]
    response_chunks: Vec<ResponseChunk>,
    #[serde(default)]
    websocket_frames: Vec<WebSocketFrame>,
}

#[derive(Debug)]
struct ParsedImport {
    manifest_path: PathBuf,
    format: SessionExportFormat,
    recordings: Vec<ParsedImportRecording>,
}

#[derive(Debug)]
struct ParsedImportRecording {
    source: String,
    recording: Recording,
    response_chunks: Vec<ResponseChunk>,
    websocket_frames: Vec<WebSocketFrame>,
}

pub async fn import_session(
    session_manager: &SessionManager,
    request: SessionImportRequest,
) -> Result<SessionImportResult, SessionImportError> {
    let SessionImportRequest {
        session_name,
        in_dir,
    } = request;
    session::validate_session_name(&session_name)
        .map_err(|err| SessionImportError::InvalidRequest(err.to_string()))?;

    let storage = session_manager
        .open_session_storage(&session_name)
        .await
        .map_err(SessionImportError::Session)?;

    let in_dir_for_task = in_dir.clone();
    let parsed_import = tokio::task::spawn_blocking(move || parse_import_bundle(&in_dir_for_task))
        .await
        .map_err(|err| {
            SessionImportError::Internal(format!("join import parse task failed: {err}"))
        })??;

    let recordings_imported = parsed_import.recordings.len();
    for parsed_recording in parsed_import.recordings {
        let source = parsed_recording.source;
        let recording_id = storage
            .insert_recording(parsed_recording.recording)
            .await
            .map_err(|err| {
                SessionImportError::Internal(format!(
                    "insert recording from `{}` into session `{}`: {err}",
                    source, session_name
                ))
            })?;
        if let Err(err) = storage
            .insert_response_chunks(recording_id, parsed_recording.response_chunks)
            .await
        {
            return Err(rollback_import_error(
                &storage,
                recording_id,
                "response chunks",
                &source,
                &session_name,
                err,
            )
            .await);
        }
        if let Err(err) = storage
            .insert_websocket_frames(recording_id, parsed_recording.websocket_frames)
            .await
        {
            return Err(rollback_import_error(
                &storage,
                recording_id,
                "websocket frames",
                &source,
                &session_name,
                err,
            )
            .await);
        }
    }

    Ok(SessionImportResult {
        status: "completed",
        session: session_name,
        format: parsed_import.format,
        input_dir: in_dir,
        manifest_path: parsed_import.manifest_path,
        recordings_imported,
    })
}

async fn rollback_import_error(
    storage: &Storage,
    recording_id: i64,
    stage: &str,
    source: &str,
    session_name: &str,
    stage_err: anyhow::Error,
) -> SessionImportError {
    let base = format!("insert {stage} from `{source}` into session `{session_name}`: {stage_err}");
    match storage.delete_recording(recording_id).await {
        Ok(true) => SessionImportError::Internal(format!(
            "{base}; rolled back recording id `{recording_id}`"
        )),
        Ok(false) => SessionImportError::Internal(format!(
            "{base}; rollback could not find recording id `{recording_id}`"
        )),
        Err(rollback_err) => SessionImportError::Internal(format!(
            "{base}; rollback failed for recording id `{recording_id}`: {rollback_err}"
        )),
    }
}

fn parse_import_bundle(in_dir: &Path) -> Result<ParsedImport, SessionImportError> {
    validate_input_dir(in_dir)?;
    let manifest_path = resolve_manifest_path(in_dir)?;
    let manifest = read_manifest(&manifest_path)?;
    validate_manifest(&manifest, &manifest_path)?;

    let mut recordings = Vec::with_capacity(manifest.recordings.len());
    let mut seen_recording_ids = HashSet::new();
    for entry in &manifest.recordings {
        if !seen_recording_ids.insert(entry.id) {
            return Err(SessionImportError::InvalidRequest(format!(
                "manifest has duplicate recording id `{}`",
                entry.id
            )));
        }
        validate_recording_file_extension(&entry.file, manifest.format)?;
        let recording_path = resolve_recording_path(in_dir, &entry.file)?;
        let mut document = read_recording_document(&recording_path, entry, manifest.format)?;
        validate_unique_stream_indices(
            &recording_path,
            &document.response_chunks,
            &document.websocket_frames,
        )?;
        legacy_redaction::scrub_recording_for_legacy_redaction(&mut document.recording);
        let response_chunks = document.response_chunks;
        let websocket_frames = document.websocket_frames;
        recordings.push(ParsedImportRecording {
            source: recording_path.to_string_lossy().into_owned(),
            recording: document.recording,
            response_chunks,
            websocket_frames,
        });
    }

    Ok(ParsedImport {
        manifest_path: manifest_path.to_path_buf(),
        format: manifest.format,
        recordings,
    })
}

fn validate_unique_stream_indices(
    recording_path: &Path,
    response_chunks: &[ResponseChunk],
    websocket_frames: &[WebSocketFrame],
) -> Result<(), SessionImportError> {
    let mut seen_chunk_indices = HashSet::new();
    for chunk in response_chunks {
        if !seen_chunk_indices.insert(chunk.chunk_index) {
            return Err(SessionImportError::InvalidRequest(format!(
                "recording `{}` has duplicate response_chunks chunk_index `{}`",
                recording_path.display(),
                chunk.chunk_index
            )));
        }
    }

    let mut seen_frame_indices = HashSet::new();
    for frame in websocket_frames {
        if !seen_frame_indices.insert(frame.frame_index) {
            return Err(SessionImportError::InvalidRequest(format!(
                "recording `{}` has duplicate websocket_frames frame_index `{}`",
                recording_path.display(),
                frame.frame_index
            )));
        }
    }

    Ok(())
}

fn validate_input_dir(in_dir: &Path) -> Result<(), SessionImportError> {
    let metadata = fs::metadata(in_dir).map_err(|err| match err.kind() {
        ErrorKind::NotFound => SessionImportError::InvalidRequest(format!(
            "import input directory `{}` does not exist",
            in_dir.display()
        )),
        _ => SessionImportError::Io(format!(
            "inspect import input directory {}: {err}",
            in_dir.display()
        )),
    })?;

    if !metadata.is_dir() {
        return Err(SessionImportError::InvalidRequest(format!(
            "import input path `{}` is not a directory",
            in_dir.display()
        )));
    }

    Ok(())
}

fn read_manifest(manifest_path: &Path) -> Result<ImportManifest, SessionImportError> {
    let manifest_format = format_for_path(manifest_path, "manifest")?;
    let manifest_bytes = read_bundle_file(manifest_path, "manifest")?;
    deserialize_import_bytes(manifest_format, &manifest_bytes, "manifest", manifest_path)
}

fn validate_manifest(
    manifest: &ImportManifest,
    manifest_path: &Path,
) -> Result<(), SessionImportError> {
    if !matches!(
        manifest.version,
        EXPORT_MANIFEST_VERSION_V1 | EXPORT_MANIFEST_VERSION_V2
    ) {
        return Err(SessionImportError::InvalidRequest(format!(
            "unsupported export manifest version `{}`; expected `1` or `2`",
            manifest.version,
        )));
    }

    let manifest_path_format = format_for_path(manifest_path, "manifest")?;
    if manifest.format != manifest_path_format {
        return Err(SessionImportError::InvalidRequest(format!(
            "manifest format `{}` does not match `{}`",
            manifest.format,
            manifest_path.display()
        )));
    }

    if manifest.session.trim().is_empty() {
        return Err(SessionImportError::InvalidRequest(
            "manifest `session` cannot be empty".to_owned(),
        ));
    }

    if manifest.exported_at_unix_ms < 0 {
        return Err(SessionImportError::InvalidRequest(
            "manifest `exported_at_unix_ms` must be non-negative".to_owned(),
        ));
    }
    Ok(())
}

fn read_recording_document(
    recording_path: &Path,
    entry: &ImportManifestEntry,
    format: SessionExportFormat,
) -> Result<ImportRecordingDocument, SessionImportError> {
    let recording_bytes = read_bundle_file(recording_path, "recording")?;
    let document: ImportRecordingDocument =
        deserialize_import_bytes(format, &recording_bytes, "recording", recording_path)?;

    if document.id != entry.id {
        return Err(SessionImportError::InvalidRequest(format!(
            "recording `{}` id `{}` does not match manifest id `{}`",
            recording_path.display(),
            document.id,
            entry.id
        )));
    }

    if document.recording.request_method != entry.request_method {
        return Err(SessionImportError::InvalidRequest(format!(
            "recording `{}` request_method `{}` does not match manifest `{}`",
            recording_path.display(),
            document.recording.request_method,
            entry.request_method
        )));
    }

    if document.recording.request_uri != entry.request_uri {
        return Err(SessionImportError::InvalidRequest(format!(
            "recording `{}` request_uri `{}` does not match manifest `{}`",
            recording_path.display(),
            document.recording.request_uri,
            entry.request_uri
        )));
    }

    if document.recording.response_status != entry.response_status {
        return Err(SessionImportError::InvalidRequest(format!(
            "recording `{}` response_status `{}` does not match manifest `{}`",
            recording_path.display(),
            document.recording.response_status,
            entry.response_status
        )));
    }

    if document.recording.created_at_unix_ms != entry.created_at_unix_ms {
        return Err(SessionImportError::InvalidRequest(format!(
            "recording `{}` created_at_unix_ms `{}` does not match manifest `{}`",
            recording_path.display(),
            document.recording.created_at_unix_ms,
            entry.created_at_unix_ms
        )));
    }

    Ok(document)
}

fn resolve_recording_path(
    in_dir: &Path,
    relative_path: &str,
) -> Result<PathBuf, SessionImportError> {
    if relative_path.is_empty() {
        return Err(SessionImportError::InvalidRequest(
            "manifest recording `file` cannot be empty".to_owned(),
        ));
    }

    let relative = Path::new(relative_path);
    if relative.is_absolute() {
        return Err(SessionImportError::InvalidRequest(format!(
            "recording file `{relative_path}` must be a relative path"
        )));
    }

    let mut components = relative.components();
    match components.next() {
        Some(Component::Normal(component)) if component == OsStr::new("recordings") => {}
        _ => {
            return Err(SessionImportError::InvalidRequest(format!(
                "recording file `{relative_path}` must be under `recordings/`"
            )));
        }
    }

    for component in components {
        if !matches!(component, Component::Normal(_)) {
            return Err(SessionImportError::InvalidRequest(format!(
                "recording file `{relative_path}` cannot contain path traversal"
            )));
        }
    }

    Ok(in_dir.join(relative))
}

fn resolve_manifest_path(in_dir: &Path) -> Result<PathBuf, SessionImportError> {
    let json_path = in_dir.join(SessionExportFormat::Json.manifest_file_name());
    let yaml_path = in_dir.join(SessionExportFormat::Yaml.manifest_file_name());

    match (json_path.is_file(), yaml_path.is_file()) {
        (true, false) => Ok(json_path),
        (false, true) => Ok(yaml_path),
        (false, false) => Err(SessionImportError::InvalidRequest(format!(
            "manifest file `{}` or `{}` does not exist",
            json_path.display(),
            yaml_path.display()
        ))),
        (true, true) => Err(SessionImportError::InvalidRequest(format!(
            "import input directory `{}` contains both `{}` and `{}`; keep only one manifest",
            in_dir.display(),
            SessionExportFormat::Json.manifest_file_name(),
            SessionExportFormat::Yaml.manifest_file_name()
        ))),
    }
}

fn validate_recording_file_extension(
    relative_path: &str,
    format: SessionExportFormat,
) -> Result<(), SessionImportError> {
    let expected_ext = format.recording_file_extension();
    let ext = Path::new(relative_path)
        .extension()
        .and_then(OsStr::to_str)
        .ok_or_else(|| {
            SessionImportError::InvalidRequest(format!(
                "recording file `{relative_path}` must end with `.{expected_ext}`"
            ))
        })?;
    if ext.eq_ignore_ascii_case(expected_ext) {
        return Ok(());
    }
    Err(SessionImportError::InvalidRequest(format!(
        "recording file `{relative_path}` must end with `.{expected_ext}`"
    )))
}

fn format_for_path(path: &Path, label: &str) -> Result<SessionExportFormat, SessionImportError> {
    match path.extension().and_then(OsStr::to_str) {
        Some("json") => Ok(SessionExportFormat::Json),
        Some("yaml") | Some("yml") => Ok(SessionExportFormat::Yaml),
        _ => Err(SessionImportError::InvalidRequest(format!(
            "{label} file `{}` must end with `.json` or `.yaml`",
            path.display()
        ))),
    }
}

fn deserialize_import_bytes<T: for<'de> Deserialize<'de>>(
    format: SessionExportFormat,
    bytes: &[u8],
    label: &str,
    path: &Path,
) -> Result<T, SessionImportError> {
    match format {
        SessionExportFormat::Json => serde_json::from_slice(bytes).map_err(|err| {
            SessionImportError::InvalidRequest(format!("parse {label} `{}`: {err}", path.display()))
        }),
        SessionExportFormat::Yaml => serde_yaml::from_slice(bytes).map_err(|err| {
            SessionImportError::InvalidRequest(format!("parse {label} `{}`: {err}", path.display()))
        }),
    }
}

fn read_bundle_file(path: &Path, label: &str) -> Result<Vec<u8>, SessionImportError> {
    fs::read(path).map_err(|err| match err.kind() {
        ErrorKind::NotFound => SessionImportError::InvalidRequest(format!(
            "{label} file `{}` does not exist",
            path.display()
        )),
        _ => SessionImportError::Io(format!("read {label} file `{}`: {err}", path.display())),
    })
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use serde::Serialize;
    use tempfile::tempdir;

    use crate::{
        session_export::SessionExportFormat,
        storage::{
            Recording, ResponseChunk, SessionManager, WebSocketFrame, WebSocketFrameDirection,
            WebSocketMessageType,
        },
    };

    use super::{
        EXPORT_MANIFEST_VERSION_V2, SessionImportError, SessionImportRequest, import_session,
        resolve_manifest_path, resolve_recording_path,
    };

    #[derive(Debug, Serialize)]
    struct TestImportManifest {
        version: u32,
        session: String,
        format: SessionExportFormat,
        exported_at_unix_ms: i64,
        recordings: Vec<TestImportManifestEntry>,
    }

    #[derive(Debug, Serialize)]
    struct TestImportManifestEntry {
        id: i64,
        file: String,
        request_method: String,
        request_uri: String,
        response_status: u16,
        created_at_unix_ms: i64,
    }

    #[derive(Debug, Serialize)]
    struct TestImportRecording {
        id: i64,
        #[serde(flatten)]
        recording: Recording,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        response_chunks: Vec<ResponseChunk>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        websocket_frames: Vec<WebSocketFrame>,
    }

    fn recording_fixture(match_key: &str, uri: &str, created_at_unix_ms: i64) -> Recording {
        Recording {
            match_key: match_key.to_owned(),
            request_method: "GET".to_owned(),
            request_uri: uri.to_owned(),
            request_headers: Vec::new(),
            request_body: Vec::new(),
            response_status: 200,
            response_headers: Vec::new(),
            response_body: b"ok".to_vec(),
            created_at_unix_ms,
        }
    }

    fn write_json_import_bundle(
        import_dir: &Path,
        recording_id: i64,
        recording: Recording,
        response_chunks: Vec<ResponseChunk>,
        websocket_frames: Vec<WebSocketFrame>,
    ) {
        let request_method = recording.request_method.clone();
        let request_uri = recording.request_uri.clone();
        let response_status = recording.response_status;
        let created_at_unix_ms = recording.created_at_unix_ms;
        let relative_recording_path = format!("recordings/{recording_id}.json");

        fs::create_dir_all(import_dir.join("recordings")).expect("recordings dir should exist");

        let document = TestImportRecording {
            id: recording_id,
            recording,
            response_chunks,
            websocket_frames,
        };
        fs::write(
            import_dir.join(&relative_recording_path),
            serde_json::to_vec_pretty(&document).expect("recording doc should serialize"),
        )
        .expect("recording doc should write");

        let manifest = TestImportManifest {
            version: EXPORT_MANIFEST_VERSION_V2,
            session: "source".to_owned(),
            format: SessionExportFormat::Json,
            exported_at_unix_ms: 0,
            recordings: vec![TestImportManifestEntry {
                id: recording_id,
                file: relative_recording_path,
                request_method,
                request_uri,
                response_status,
                created_at_unix_ms,
            }],
        };
        fs::write(
            import_dir.join(SessionExportFormat::Json.manifest_file_name()),
            serde_json::to_vec_pretty(&manifest).expect("manifest should serialize"),
        )
        .expect("manifest should write");
    }

    async fn recording_count(manager: &SessionManager, session_name: &str) -> u64 {
        manager
            .open_session_storage(session_name)
            .await
            .expect("session storage should open")
            .count_recordings()
            .await
            .expect("recording count should load")
    }

    #[test]
    fn resolve_recording_path_rejects_non_recordings_prefix() {
        let err = resolve_recording_path(Path::new("/tmp/export"), "index.json").unwrap_err();
        assert!(err.to_string().contains("must be under `recordings/`"));
    }

    #[test]
    fn resolve_recording_path_rejects_parent_traversal() {
        let err = resolve_recording_path(Path::new("/tmp/export"), "recordings/../../evil.json")
            .unwrap_err();
        assert!(err.to_string().contains("path traversal"));
    }

    #[test]
    fn resolve_manifest_path_accepts_yaml_manifest() {
        let dir = tempdir().expect("tempdir should be created");
        let manifest_path = dir.path().join("index.yaml");
        std::fs::write(&manifest_path, "version: 1").expect("manifest should be written");

        let resolved = resolve_manifest_path(dir.path()).expect("manifest should resolve");
        assert_eq!(resolved, manifest_path);
    }

    #[test]
    fn resolve_manifest_path_rejects_ambiguous_manifests() {
        let dir = tempdir().expect("tempdir should be created");
        std::fs::write(dir.path().join("index.json"), "{}")
            .expect("json manifest should be written");
        std::fs::write(dir.path().join("index.yaml"), "{}")
            .expect("yaml manifest should be written");

        let err = resolve_manifest_path(dir.path()).expect_err("ambiguous manifests should fail");
        assert!(err.to_string().contains("contains both"));
    }

    #[tokio::test]
    async fn import_session_rejects_duplicate_response_chunk_indices_without_side_effects() {
        let temp_dir = tempdir().expect("tempdir should be created");
        let manager = SessionManager::new(temp_dir.path().join("sessions"));
        manager
            .create_session("staging")
            .await
            .expect("staging session should exist");

        let import_dir = temp_dir.path().join("bundle-duplicate-chunks");
        let chunks = vec![
            ResponseChunk {
                chunk_index: 0,
                offset_ms: 0,
                chunk_body: b"first".to_vec(),
            },
            ResponseChunk {
                chunk_index: 0,
                offset_ms: 5,
                chunk_body: b"duplicate".to_vec(),
            },
        ];
        write_json_import_bundle(
            &import_dir,
            1,
            recording_fixture("chunk-dup", "/v1/stream", 10),
            chunks,
            Vec::new(),
        );

        assert_eq!(recording_count(&manager, "staging").await, 0);
        let err = import_session(
            &manager,
            SessionImportRequest {
                session_name: "staging".to_owned(),
                in_dir: import_dir,
            },
        )
        .await
        .expect_err("duplicate chunk indices should fail");

        match err {
            SessionImportError::InvalidRequest(message) => {
                assert!(message.contains("duplicate response_chunks chunk_index `0`"));
            }
            other => panic!("expected invalid request, got {other:?}"),
        }
        assert_eq!(recording_count(&manager, "staging").await, 0);
    }

    #[tokio::test]
    async fn import_session_rejects_duplicate_websocket_frame_indices_without_side_effects() {
        let temp_dir = tempdir().expect("tempdir should be created");
        let manager = SessionManager::new(temp_dir.path().join("sessions"));
        manager
            .create_session("staging")
            .await
            .expect("staging session should exist");

        let import_dir = temp_dir.path().join("bundle-duplicate-frames");
        let frames = vec![
            WebSocketFrame {
                frame_index: 0,
                offset_ms: 0,
                direction: WebSocketFrameDirection::ServerToClient,
                message_type: WebSocketMessageType::Text,
                payload: b"hello".to_vec(),
            },
            WebSocketFrame {
                frame_index: 0,
                offset_ms: 2,
                direction: WebSocketFrameDirection::ClientToServer,
                message_type: WebSocketMessageType::Text,
                payload: b"dup".to_vec(),
            },
        ];
        write_json_import_bundle(
            &import_dir,
            2,
            recording_fixture("frame-dup", "/ws", 11),
            Vec::new(),
            frames,
        );

        assert_eq!(recording_count(&manager, "staging").await, 0);
        let err = import_session(
            &manager,
            SessionImportRequest {
                session_name: "staging".to_owned(),
                in_dir: import_dir,
            },
        )
        .await
        .expect_err("duplicate websocket frame indices should fail");

        match err {
            SessionImportError::InvalidRequest(message) => {
                assert!(message.contains("duplicate websocket_frames frame_index `0`"));
            }
            other => panic!("expected invalid request, got {other:?}"),
        }
        assert_eq!(recording_count(&manager, "staging").await, 0);
    }

    #[tokio::test]
    async fn import_session_rolls_back_recording_when_websocket_frame_insert_fails() {
        let temp_dir = tempdir().expect("tempdir should be created");
        let manager = SessionManager::new(temp_dir.path().join("sessions"));
        manager
            .create_session("staging")
            .await
            .expect("staging session should exist");

        let import_dir = temp_dir.path().join("bundle-rollback");
        let frames = vec![WebSocketFrame {
            frame_index: 0,
            offset_ms: u64::MAX,
            direction: WebSocketFrameDirection::ServerToClient,
            message_type: WebSocketMessageType::Binary,
            payload: b"overflow".to_vec(),
        }];
        write_json_import_bundle(
            &import_dir,
            3,
            recording_fixture("rollback", "/ws", 12),
            Vec::new(),
            frames,
        );

        let err = import_session(
            &manager,
            SessionImportRequest {
                session_name: "staging".to_owned(),
                in_dir: import_dir,
            },
        )
        .await
        .expect_err("oversized websocket offset should fail");

        match err {
            SessionImportError::Internal(message) => {
                assert!(message.contains("insert websocket frames"));
                assert!(message.contains("rolled back recording id"));
            }
            other => panic!("expected internal import error, got {other:?}"),
        }
        assert_eq!(recording_count(&manager, "staging").await, 0);
    }
}
