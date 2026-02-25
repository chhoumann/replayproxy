use std::{
    collections::HashSet,
    ffi::OsStr,
    fs,
    io::ErrorKind,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    session,
    session_export::SessionExportFormat,
    storage::{Recording, SessionManager, SessionManagerError},
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
}

#[derive(Debug)]
struct ParsedImport {
    format: SessionExportFormat,
    recordings: Vec<ParsedImportRecording>,
}

#[derive(Debug)]
struct ParsedImportRecording {
    source: String,
    recording: Recording,
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

    let manifest_path = in_dir.join("index.json");
    let in_dir_for_task = in_dir.clone();
    let manifest_path_for_task = manifest_path.clone();
    let parsed_import = tokio::task::spawn_blocking(move || {
        parse_import_bundle(&in_dir_for_task, &manifest_path_for_task)
    })
    .await
    .map_err(|err| {
        SessionImportError::Internal(format!("join import parse task failed: {err}"))
    })??;

    for parsed_recording in &parsed_import.recordings {
        storage
            .insert_recording(parsed_recording.recording.clone())
            .await
            .map_err(|err| {
                SessionImportError::Internal(format!(
                    "insert recording from `{}` into session `{}`: {err}",
                    parsed_recording.source, session_name
                ))
            })?;
    }

    Ok(SessionImportResult {
        status: "completed",
        session: session_name,
        format: parsed_import.format,
        input_dir: in_dir,
        manifest_path,
        recordings_imported: parsed_import.recordings.len(),
    })
}

fn parse_import_bundle(
    in_dir: &Path,
    manifest_path: &Path,
) -> Result<ParsedImport, SessionImportError> {
    validate_input_dir(in_dir)?;
    let manifest = read_manifest(manifest_path)?;
    validate_manifest(&manifest)?;

    let mut recordings = Vec::with_capacity(manifest.recordings.len());
    let mut seen_recording_ids = HashSet::new();
    for entry in &manifest.recordings {
        if !seen_recording_ids.insert(entry.id) {
            return Err(SessionImportError::InvalidRequest(format!(
                "manifest has duplicate recording id `{}`",
                entry.id
            )));
        }
        let recording_path = resolve_recording_path(in_dir, &entry.file)?;
        let recording = read_recording_document(&recording_path, entry)?;
        recordings.push(ParsedImportRecording {
            source: recording_path.to_string_lossy().into_owned(),
            recording,
        });
    }

    Ok(ParsedImport {
        format: manifest.format,
        recordings,
    })
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
    let manifest_bytes = read_json_file(manifest_path, "manifest")?;
    serde_json::from_slice(&manifest_bytes).map_err(|err| {
        SessionImportError::InvalidRequest(format!(
            "parse manifest `{}`: {err}",
            manifest_path.display()
        ))
    })
}

fn validate_manifest(manifest: &ImportManifest) -> Result<(), SessionImportError> {
    if manifest.version != 1 {
        return Err(SessionImportError::InvalidRequest(format!(
            "unsupported export manifest version `{}`; expected `1`",
            manifest.version
        )));
    }

    if manifest.format != SessionExportFormat::Json {
        return Err(SessionImportError::InvalidRequest(format!(
            "unsupported export format `{:?}`; expected `json`",
            manifest.format
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
) -> Result<Recording, SessionImportError> {
    let recording_bytes = read_json_file(recording_path, "recording")?;
    let document: ImportRecordingDocument =
        serde_json::from_slice(&recording_bytes).map_err(|err| {
            SessionImportError::InvalidRequest(format!(
                "parse recording `{}`: {err}",
                recording_path.display()
            ))
        })?;

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

    Ok(document.recording)
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

fn read_json_file(path: &Path, label: &str) -> Result<Vec<u8>, SessionImportError> {
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
    use std::path::Path;

    use super::resolve_recording_path;

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
}
