use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{
    session,
    storage::{Recording, SessionManager, SessionManagerError, Storage},
};

const EXPORT_LIST_PAGE_SIZE: usize = 256;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SessionExportFormat {
    Json,
}

impl Default for SessionExportFormat {
    fn default() -> Self {
        Self::Json
    }
}

#[derive(Debug, Clone)]
pub struct SessionExportRequest {
    pub session_name: String,
    pub out_dir: Option<PathBuf>,
    pub format: SessionExportFormat,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SessionExportResult {
    pub status: &'static str,
    pub session: String,
    pub format: SessionExportFormat,
    pub output_dir: PathBuf,
    pub manifest_path: PathBuf,
    pub recordings_exported: usize,
}

#[derive(Debug)]
pub enum SessionExportError {
    InvalidRequest(String),
    Session(SessionManagerError),
    Io(String),
    Internal(String),
}

impl std::fmt::Display for SessionExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(message) | Self::Io(message) | Self::Internal(message) => {
                f.write_str(message)
            }
            Self::Session(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for SessionExportError {}

impl From<SessionManagerError> for SessionExportError {
    fn from(value: SessionManagerError) -> Self {
        Self::Session(value)
    }
}

#[derive(Debug)]
struct ExportRecording {
    id: i64,
    recording: Recording,
}

#[derive(Debug, Serialize)]
struct ExportManifest {
    version: u32,
    session: String,
    format: SessionExportFormat,
    exported_at_unix_ms: i64,
    recordings: Vec<ExportManifestEntry>,
}

#[derive(Debug, Serialize)]
struct ExportManifestEntry {
    id: i64,
    file: String,
    request_method: String,
    request_uri: String,
    response_status: u16,
    created_at_unix_ms: i64,
}

#[derive(Debug, Serialize)]
struct ExportRecordingDocument {
    id: i64,
    #[serde(flatten)]
    recording: Recording,
}

pub async fn export_session(
    session_manager: &SessionManager,
    request: SessionExportRequest,
) -> Result<SessionExportResult, SessionExportError> {
    session::validate_session_name(&request.session_name)
        .map_err(|err| SessionExportError::InvalidRequest(err.to_string()))?;

    let storage = session_manager
        .open_session_storage(&request.session_name)
        .await
        .map_err(SessionExportError::Session)?;
    let recordings = collect_recordings_for_export(&request.session_name, &storage).await?;

    let exported_at_unix_ms = unix_timestamp_ms();
    let output_dir = request.out_dir.unwrap_or_else(|| {
        default_output_dir(
            session_manager.base_path(),
            &request.session_name,
            exported_at_unix_ms,
        )
    });

    let session_name = request.session_name.clone();
    let format = request.format;
    let output_dir_for_task = output_dir.clone();
    let write_result = tokio::task::spawn_blocking(move || {
        write_export(
            &session_name,
            format,
            &output_dir_for_task,
            exported_at_unix_ms,
            recordings,
        )
    })
    .await
    .map_err(|err| {
        SessionExportError::Internal(format!("join export write task failed: {err}"))
    })??;

    Ok(SessionExportResult {
        status: "completed",
        session: request.session_name,
        format,
        output_dir,
        manifest_path: write_result.manifest_path,
        recordings_exported: write_result.recordings_exported,
    })
}

#[derive(Debug)]
struct WriteExportResult {
    manifest_path: PathBuf,
    recordings_exported: usize,
}

fn write_export(
    session_name: &str,
    format: SessionExportFormat,
    output_dir: &Path,
    exported_at_unix_ms: i64,
    recordings: Vec<ExportRecording>,
) -> Result<WriteExportResult, SessionExportError> {
    if output_dir.exists() {
        if !output_dir.is_dir() {
            return Err(SessionExportError::Io(format!(
                "export output path `{}` exists and is not a directory",
                output_dir.display()
            )));
        }
        let mut entries = fs::read_dir(output_dir).map_err(|err| {
            SessionExportError::Io(format!(
                "inspect export output dir {}: {err}",
                output_dir.display()
            ))
        })?;
        if entries.next().is_some() {
            return Err(SessionExportError::Io(format!(
                "export output dir `{}` must be empty",
                output_dir.display()
            )));
        }
    } else {
        fs::create_dir_all(output_dir).map_err(|err| {
            SessionExportError::Io(format!(
                "create export output dir {}: {err}",
                output_dir.display()
            ))
        })?;
    }

    let recordings_dir = output_dir.join("recordings");
    fs::create_dir_all(&recordings_dir).map_err(|err| {
        SessionExportError::Io(format!(
            "create export recordings dir {}: {err}",
            recordings_dir.display()
        ))
    })?;

    let mut manifest_entries = Vec::with_capacity(recordings.len());
    for (index, export_recording) in recordings.into_iter().enumerate() {
        let file_name = recording_file_name(
            index,
            export_recording.id,
            &export_recording.recording.request_method,
            &export_recording.recording.request_uri,
        );
        let relative_file = Path::new("recordings").join(&file_name);
        let file_path = output_dir.join(&relative_file);

        let request_method = export_recording.recording.request_method.clone();
        let request_uri = export_recording.recording.request_uri.clone();
        let response_status = export_recording.recording.response_status;
        let created_at_unix_ms = export_recording.recording.created_at_unix_ms;

        let document = ExportRecordingDocument {
            id: export_recording.id,
            recording: export_recording.recording,
        };
        let document_bytes = serde_json::to_vec_pretty(&document).map_err(|err| {
            SessionExportError::Internal(format!(
                "serialize recording `{}` for export: {err}",
                document.id
            ))
        })?;
        fs::write(&file_path, document_bytes).map_err(|err| {
            SessionExportError::Io(format!(
                "write exported recording {}: {err}",
                file_path.display()
            ))
        })?;

        manifest_entries.push(ExportManifestEntry {
            id: document.id,
            file: relative_file.to_string_lossy().into_owned(),
            request_method,
            request_uri,
            response_status,
            created_at_unix_ms,
        });
    }

    let manifest = ExportManifest {
        version: 1,
        session: session_name.to_owned(),
        format,
        exported_at_unix_ms,
        recordings: manifest_entries,
    };
    let manifest_path = output_dir.join("index.json");
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(|err| {
        SessionExportError::Internal(format!(
            "serialize export manifest for session `{session_name}`: {err}"
        ))
    })?;
    fs::write(&manifest_path, manifest_bytes).map_err(|err| {
        SessionExportError::Io(format!(
            "write export manifest {}: {err}",
            manifest_path.display()
        ))
    })?;

    Ok(WriteExportResult {
        manifest_path,
        recordings_exported: manifest.recordings.len(),
    })
}

async fn collect_recordings_for_export(
    session_name: &str,
    storage: &Storage,
) -> Result<Vec<ExportRecording>, SessionExportError> {
    let mut summaries = Vec::new();
    let mut offset = 0;
    loop {
        let page = storage
            .list_recordings(offset, EXPORT_LIST_PAGE_SIZE)
            .await
            .map_err(|err| {
                SessionExportError::Internal(format!(
                    "list recordings for session `{session_name}`: {err}"
                ))
            })?;
        if page.is_empty() {
            break;
        }
        offset += page.len();
        summaries.extend(page);
    }

    let mut recordings = Vec::with_capacity(summaries.len());
    for summary in summaries {
        let recording = storage
            .get_recording_by_id(summary.id)
            .await
            .map_err(|err| {
                SessionExportError::Internal(format!(
                    "read recording `{}` from session `{session_name}`: {err}",
                    summary.id
                ))
            })?
            .ok_or_else(|| {
                SessionExportError::Internal(format!(
                    "recording `{}` disappeared while exporting session `{session_name}`",
                    summary.id
                ))
            })?;
        recordings.push(ExportRecording {
            id: summary.id,
            recording,
        });
    }

    recordings.sort_by_key(|recording| recording.id);
    Ok(recordings)
}

fn default_output_dir(base_path: &Path, session_name: &str, exported_at_unix_ms: i64) -> PathBuf {
    base_path
        .join("_exports")
        .join(format!("{session_name}-{exported_at_unix_ms}"))
}

fn unix_timestamp_ms() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_millis()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

fn recording_file_name(index: usize, id: i64, method: &str, uri: &str) -> String {
    let method_slug = slug_ascii(method, 16, "request");
    let uri_slug = slug_ascii(uri, 48, "path");
    format!("{:04}-{method_slug}-{uri_slug}-id{id}.json", index + 1)
}

fn slug_ascii(value: &str, max_len: usize, fallback: &str) -> String {
    let mut slug = String::new();
    let mut previous_dash = false;
    for ch in value.chars() {
        let lowered = ch.to_ascii_lowercase();
        if lowered.is_ascii_alphanumeric() {
            slug.push(lowered);
            previous_dash = false;
        } else if !previous_dash {
            slug.push('-');
            previous_dash = true;
        }
        if slug.len() >= max_len {
            break;
        }
    }
    let slug = slug.trim_matches('-');
    if slug.is_empty() {
        fallback.to_owned()
    } else {
        slug.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::{recording_file_name, slug_ascii};

    #[test]
    fn recording_file_name_is_deterministic() {
        let file_name = recording_file_name(0, 42, "POST", "/v1/chat/completions?stream=true");
        assert_eq!(
            file_name,
            "0001-post-v1-chat-completions-stream-true-id42.json"
        );
    }

    #[test]
    fn recording_file_name_uses_fallback_slugs() {
        let file_name = recording_file_name(3, 9, "***", "////");
        assert_eq!(file_name, "0004-request-path-id9.json");
    }

    #[test]
    fn slug_ascii_collapses_delimiters_and_truncates() {
        let slug = slug_ascii("AAA___BBB___CCC___DDD", 10, "fallback");
        assert_eq!(slug, "aaa-bbb-cc");
    }
}
