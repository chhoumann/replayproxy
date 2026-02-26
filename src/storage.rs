use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context as _;
use rusqlite::{Connection, OpenFlags, params, params_from_iter, types::Value as SqlValue};
use serde::{Deserialize, Serialize};

use crate::{config::Config, matching, session};

const SCHEMA_VERSION: i32 = 7;
const SQLITE_MAX_BIND_PARAMS: usize = 999;
const QUERY_SUBSET_CHUNK_SIZE: usize = SQLITE_MAX_BIND_PARAMS - 1;

#[derive(Debug, Clone)]
pub struct Storage {
    db_path: PathBuf,
    max_recordings: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct SessionManager {
    base_path: PathBuf,
    max_recordings: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionManagerError {
    InvalidName(String),
    AlreadyExists(String),
    NotFound(String),
    Io(String),
    Internal(String),
}

impl std::fmt::Display for SessionManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidName(reason) => write!(f, "{reason}"),
            Self::AlreadyExists(name) => write!(f, "session `{name}` already exists"),
            Self::NotFound(name) => write!(f, "session `{name}` was not found"),
            Self::Io(message) | Self::Internal(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for SessionManagerError {}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Recording {
    pub match_key: String,
    pub request_method: String,
    pub request_uri: String,
    pub request_headers: Vec<(String, Vec<u8>)>,
    pub request_body: Vec<u8>,
    pub response_status: u16,
    pub response_headers: Vec<(String, Vec<u8>)>,
    pub response_body: Vec<u8>,
    pub created_at_unix_ms: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ResponseChunk {
    pub chunk_index: u32,
    pub offset_ms: u64,
    pub chunk_body: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WebSocketFrameDirection {
    ClientToServer,
    ServerToClient,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WebSocketMessageType {
    Text,
    Binary,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct WebSocketFrame {
    pub frame_index: u32,
    pub offset_ms: u64,
    pub direction: WebSocketFrameDirection,
    pub message_type: WebSocketMessageType,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordingSummary {
    pub id: i64,
    pub match_key: String,
    pub request_method: String,
    pub request_uri: String,
    pub response_status: u16,
    pub created_at_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubsetScanLookupResult {
    pub recording: Option<Recording>,
    pub scanned_rows: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRecording {
    pub id: i64,
    pub recording: Recording,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubsetScanLookupResultWithId {
    pub recording: Option<StoredRecording>,
    pub scanned_rows: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordingSearch {
    pub method: Option<String>,
    pub url_contains: Option<String>,
    pub body_contains: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum StoredHeaderValue {
    Bytes(Vec<u8>),
    Text(String),
}

impl Recording {
    pub fn now_unix_ms() -> anyhow::Result<i64> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time before unix epoch")?;
        Ok(i64::try_from(duration.as_millis()).unwrap_or(i64::MAX))
    }
}

fn deserialize_headers(
    headers_json: &str,
    field_name: &str,
) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let parsed: Vec<(String, StoredHeaderValue)> = serde_json::from_str(headers_json)
        .with_context(|| format!("deserialize {field_name} headers"))?;

    Ok(parsed
        .into_iter()
        .map(|(name, value)| {
            let bytes = match value {
                StoredHeaderValue::Bytes(bytes) => bytes,
                StoredHeaderValue::Text(text) => text.into_bytes(),
            };
            (name, bytes)
        })
        .collect())
}

impl Storage {
    pub fn from_config(config: &Config) -> anyhow::Result<Option<Self>> {
        let Some(storage) = config.storage.as_ref() else {
            return Ok(None);
        };
        let session_name = storage
            .active_session
            .as_deref()
            .unwrap_or(session::DEFAULT_SESSION_NAME);
        let db_path = session::resolve_session_db_path(&storage.path, session_name)
            .map_err(|err| anyhow::anyhow!("resolve storage session `{session_name}`: {err}"))?;
        Ok(Some(Self::open_with_max_recordings(
            db_path,
            storage.max_recordings,
        )?))
    }

    pub fn open(db_path: PathBuf) -> anyhow::Result<Self> {
        Self::open_with_max_recordings(db_path, None)
    }

    pub fn open_with_max_recordings(
        db_path: PathBuf,
        max_recordings: Option<u64>,
    ) -> anyhow::Result<Self> {
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create storage dir {}", parent.display()))?;
        }

        let storage = Self {
            db_path,
            max_recordings,
        };
        storage.init()?;
        Ok(storage)
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub async fn insert_recording(&self, recording: Recording) -> anyhow::Result<i64> {
        self.insert_recording_with_query_norm(recording, None).await
    }

    pub async fn insert_recording_with_query_norm(
        &self,
        recording: Recording,
        request_query_norm: Option<String>,
    ) -> anyhow::Result<i64> {
        let db_path = self.db_path.clone();
        let max_recordings = self.max_recordings;
        tokio::task::spawn_blocking(move || {
            insert_recording_blocking(&db_path, recording, request_query_norm, max_recordings)
        })
        .await
        .context("join insert_recording task")?
    }

    pub async fn insert_response_chunks(
        &self,
        recording_id: i64,
        chunks: Vec<ResponseChunk>,
    ) -> anyhow::Result<()> {
        if chunks.is_empty() {
            return Ok(());
        }

        let db_path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            insert_response_chunks_blocking(&db_path, recording_id, chunks)
        })
        .await
        .context("join insert_response_chunks task")?
    }

    pub async fn insert_websocket_frames(
        &self,
        recording_id: i64,
        frames: Vec<WebSocketFrame>,
    ) -> anyhow::Result<()> {
        if frames.is_empty() {
            return Ok(());
        }

        let db_path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            insert_websocket_frames_blocking(&db_path, recording_id, frames)
        })
        .await
        .context("join insert_websocket_frames task")?
    }

    pub async fn get_recording_by_match_key(
        &self,
        match_key: &str,
    ) -> anyhow::Result<Option<Recording>> {
        let result = self.get_recording_with_id_by_match_key(match_key).await?;
        Ok(result.map(|stored| stored.recording))
    }

    pub async fn get_recording_with_id_by_match_key(
        &self,
        match_key: &str,
    ) -> anyhow::Result<Option<StoredRecording>> {
        let db_path = self.db_path.clone();
        let match_key = match_key.to_owned();
        tokio::task::spawn_blocking(move || {
            get_recording_with_id_by_match_key_blocking(&db_path, &match_key)
        })
        .await
        .context("join get_recording_with_id_by_match_key task")?
    }

    pub async fn get_recordings_by_match_key(
        &self,
        match_key: &str,
    ) -> anyhow::Result<Vec<Recording>> {
        let db_path = self.db_path.clone();
        let match_key = match_key.to_owned();
        tokio::task::spawn_blocking(move || {
            get_recordings_by_match_key_blocking(&db_path, &match_key)
        })
        .await
        .context("join get_recordings_by_match_key task")?
    }

    pub async fn get_recording_by_id(
        &self,
        recording_id: i64,
    ) -> anyhow::Result<Option<Recording>> {
        let db_path = self.db_path.clone();
        tokio::task::spawn_blocking(move || get_recording_by_id_blocking(&db_path, recording_id))
            .await
            .context("join get_recording_by_id task")?
    }

    pub async fn get_response_chunks(
        &self,
        recording_id: i64,
    ) -> anyhow::Result<Vec<ResponseChunk>> {
        let db_path = self.db_path.clone();
        tokio::task::spawn_blocking(move || get_response_chunks_blocking(&db_path, recording_id))
            .await
            .context("join get_response_chunks task")?
    }

    pub async fn get_websocket_frames(
        &self,
        recording_id: i64,
    ) -> anyhow::Result<Vec<WebSocketFrame>> {
        let db_path = self.db_path.clone();
        tokio::task::spawn_blocking(move || get_websocket_frames_blocking(&db_path, recording_id))
            .await
            .context("join get_websocket_frames task")?
    }

    pub async fn get_latest_recording_by_match_key_and_query_subset(
        &self,
        match_key: &str,
        subset_query_normalizations: Vec<String>,
    ) -> anyhow::Result<Option<Recording>> {
        let result = self
            .get_latest_recording_with_id_by_match_key_and_query_subset(
                match_key,
                subset_query_normalizations,
            )
            .await?;
        Ok(result.map(|stored| stored.recording))
    }

    pub async fn get_latest_recording_with_id_by_match_key_and_query_subset(
        &self,
        match_key: &str,
        subset_query_normalizations: Vec<String>,
    ) -> anyhow::Result<Option<StoredRecording>> {
        let db_path = self.db_path.clone();
        let match_key = match_key.to_owned();
        tokio::task::spawn_blocking(move || {
            get_latest_recording_with_id_by_match_key_and_query_subset_blocking(
                &db_path,
                &match_key,
                &subset_query_normalizations,
            )
        })
        .await
        .context("join get_latest_recording_with_id_by_match_key_and_query_subset task")?
    }

    pub async fn get_latest_recording_by_match_key_and_query_subset_scan(
        &self,
        match_key: &str,
        request_query: Option<&str>,
    ) -> anyhow::Result<Option<Recording>> {
        let result = self
            .get_latest_recording_by_match_key_and_query_subset_scan_with_stats(
                match_key,
                request_query,
            )
            .await?;
        Ok(result.recording)
    }

    pub async fn get_latest_recording_by_match_key_and_query_subset_scan_with_stats(
        &self,
        match_key: &str,
        request_query: Option<&str>,
    ) -> anyhow::Result<SubsetScanLookupResult> {
        let result = self
            .get_latest_recording_with_id_by_match_key_and_query_subset_scan_with_stats(
                match_key,
                request_query,
            )
            .await?;
        Ok(SubsetScanLookupResult {
            recording: result.recording.map(|stored| stored.recording),
            scanned_rows: result.scanned_rows,
        })
    }

    pub async fn get_latest_recording_with_id_by_match_key_and_query_subset_scan_with_stats(
        &self,
        match_key: &str,
        request_query: Option<&str>,
    ) -> anyhow::Result<SubsetScanLookupResultWithId> {
        let db_path = self.db_path.clone();
        let match_key = match_key.to_owned();
        let request_query = request_query.map(str::to_owned);
        tokio::task::spawn_blocking(move || {
            get_latest_recording_with_id_by_match_key_and_query_subset_scan_with_stats_blocking(
                &db_path,
                &match_key,
                request_query.as_deref(),
            )
        })
        .await
        .context(
            "join get_latest_recording_with_id_by_match_key_and_query_subset_scan_with_stats task",
        )?
    }

    pub async fn list_recordings(
        &self,
        offset: usize,
        limit: usize,
    ) -> anyhow::Result<Vec<RecordingSummary>> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let (offset, limit) = validate_pagination(offset, limit)?;
        let db_path = self.db_path.clone();
        tokio::task::spawn_blocking(move || list_recordings_blocking(&db_path, offset, limit))
            .await
            .context("join list_recordings task")?
    }

    pub async fn search_recordings(
        &self,
        search: RecordingSearch,
        offset: usize,
        limit: usize,
    ) -> anyhow::Result<Vec<RecordingSummary>> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let (offset, limit) = validate_pagination(offset, limit)?;
        let db_path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            search_recordings_blocking(&db_path, &search, offset, limit)
        })
        .await
        .context("join search_recordings task")?
    }

    pub async fn delete_recording(&self, id: i64) -> anyhow::Result<bool> {
        let db_path = self.db_path.clone();
        tokio::task::spawn_blocking(move || delete_recording_blocking(&db_path, id))
            .await
            .context("join delete_recording task")?
    }

    pub async fn count_recordings(&self) -> anyhow::Result<u64> {
        let db_path = self.db_path.clone();
        tokio::task::spawn_blocking(move || count_recordings_blocking(&db_path))
            .await
            .context("join count_recordings task")?
    }

    fn init(&self) -> anyhow::Result<()> {
        let mut conn = open_connection(&self.db_path)?;
        migrate(&mut conn)?;
        Ok(())
    }
}

impl SessionManager {
    pub fn from_config(config: &Config) -> anyhow::Result<Option<Self>> {
        let Some(storage) = config.storage.as_ref() else {
            return Ok(None);
        };

        fs::create_dir_all(&storage.path)
            .with_context(|| format!("create sessions dir {}", storage.path.display()))?;

        Ok(Some(Self::new_with_max_recordings(
            storage.path.clone(),
            storage.max_recordings,
        )))
    }

    pub fn new(base_path: PathBuf) -> Self {
        Self::new_with_max_recordings(base_path, None)
    }

    fn new_with_max_recordings(base_path: PathBuf, max_recordings: Option<u64>) -> Self {
        Self {
            base_path,
            max_recordings,
        }
    }

    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    pub async fn list_sessions(&self) -> Result<Vec<String>, SessionManagerError> {
        let base_path = self.base_path.clone();
        tokio::task::spawn_blocking(move || list_sessions_blocking(&base_path))
            .await
            .map_err(|err| {
                SessionManagerError::Internal(format!("join list sessions task failed: {err}"))
            })?
    }

    pub async fn create_session(&self, name: &str) -> Result<(), SessionManagerError> {
        let base_path = self.base_path.clone();
        let name = name.to_owned();
        tokio::task::spawn_blocking(move || create_session_blocking(&base_path, &name))
            .await
            .map_err(|err| {
                SessionManagerError::Internal(format!("join create session task failed: {err}"))
            })?
    }

    pub async fn delete_session(&self, name: &str) -> Result<(), SessionManagerError> {
        let base_path = self.base_path.clone();
        let name = name.to_owned();
        tokio::task::spawn_blocking(move || delete_session_blocking(&base_path, &name))
            .await
            .map_err(|err| {
                SessionManagerError::Internal(format!("join delete session task failed: {err}"))
            })?
    }

    pub async fn open_session_storage(&self, name: &str) -> Result<Storage, SessionManagerError> {
        let base_path = self.base_path.clone();
        let name = name.to_owned();
        let max_recordings = self.max_recordings;
        tokio::task::spawn_blocking(move || {
            open_session_storage_blocking(&base_path, &name, max_recordings)
        })
        .await
        .map_err(|err| {
            SessionManagerError::Internal(format!("join open session storage task failed: {err}"))
        })?
    }
}

fn open_connection(path: &Path) -> anyhow::Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_URI
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(path, flags)
        .with_context(|| format!("open sqlite {}", path.display()))?;

    conn.pragma_update(None, "journal_mode", "WAL")
        .context("set PRAGMA journal_mode=WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .context("set PRAGMA synchronous=NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .context("set PRAGMA foreign_keys=ON")?;
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .context("set sqlite busy_timeout")?;

    Ok(conn)
}

fn migrate(conn: &mut Connection) -> anyhow::Result<()> {
    let user_version: i32 = conn
        .query_row("PRAGMA user_version;", [], |row| row.get(0))
        .context("read PRAGMA user_version")?;

    match user_version {
        0 => {
            conn.execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS recordings (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  match_key TEXT NOT NULL,
                  request_method TEXT NOT NULL,
                  request_uri TEXT NOT NULL,
                  request_query_norm TEXT NOT NULL DEFAULT '',
                  request_query_param_count INTEGER NOT NULL DEFAULT 0,
                  request_headers_json TEXT NOT NULL,
                  request_body BLOB NOT NULL,
                  response_status INTEGER NOT NULL,
                  response_headers_json TEXT NOT NULL,
                  response_body BLOB NOT NULL,
                  created_at_unix_ms INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS recordings_match_key_idx ON recordings(match_key);
                CREATE INDEX IF NOT EXISTS recordings_match_key_query_norm_idx
                  ON recordings(match_key, request_query_norm, id DESC);
                CREATE INDEX IF NOT EXISTS recordings_match_key_query_param_count_idx
                  ON recordings(match_key, request_query_param_count, id DESC);

                CREATE TABLE IF NOT EXISTS recording_response_chunks (
                  recording_id INTEGER NOT NULL,
                  chunk_index INTEGER NOT NULL,
                  offset_ms INTEGER NOT NULL,
                  chunk_body BLOB NOT NULL,
                  PRIMARY KEY (recording_id, chunk_index),
                  FOREIGN KEY (recording_id) REFERENCES recordings(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS recording_response_chunks_replay_idx
                  ON recording_response_chunks(recording_id, chunk_index);

                CREATE TABLE IF NOT EXISTS recording_websocket_frames (
                  recording_id INTEGER NOT NULL,
                  frame_index INTEGER NOT NULL,
                  direction TEXT NOT NULL CHECK(direction IN ('client-to-server', 'server-to-client')),
                  message_type TEXT NOT NULL CHECK(message_type IN ('text', 'binary')),
                  offset_ms INTEGER NOT NULL,
                  payload BLOB NOT NULL,
                  PRIMARY KEY (recording_id, frame_index),
                  FOREIGN KEY (recording_id) REFERENCES recordings(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS recording_websocket_frames_replay_idx
                  ON recording_websocket_frames(recording_id, frame_index);

                CREATE TABLE IF NOT EXISTS recording_query_param_index (
                  recording_id INTEGER NOT NULL,
                  match_key TEXT NOT NULL,
                  request_query_param_count INTEGER NOT NULL,
                  query_param_fingerprint TEXT NOT NULL,
                  FOREIGN KEY (recording_id) REFERENCES recordings(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS recording_query_param_index_lookup_idx
                  ON recording_query_param_index(
                    match_key,
                    query_param_fingerprint,
                    request_query_param_count,
                    recording_id DESC
                  );
                CREATE INDEX IF NOT EXISTS recording_query_param_index_recording_id_idx
                  ON recording_query_param_index(recording_id);
                "#,
            )
            .context("create sqlite schema v7")?;

            conn.pragma_update(None, "user_version", SCHEMA_VERSION)
                .context("set PRAGMA user_version=7")?;
            Ok(())
        }
        1 => {
            migrate_v1_to_v2(conn)?;
            migrate_v2_to_v3(conn)?;
            migrate_v3_to_v4(conn)?;
            migrate_v4_to_v5(conn)?;
            migrate_v5_to_v6(conn)?;
            migrate_v6_to_v7(conn)
        }
        2 => {
            migrate_v2_to_v3(conn)?;
            migrate_v3_to_v4(conn)?;
            migrate_v4_to_v5(conn)?;
            migrate_v5_to_v6(conn)?;
            migrate_v6_to_v7(conn)
        }
        3 => {
            migrate_v3_to_v4(conn)?;
            migrate_v4_to_v5(conn)?;
            migrate_v5_to_v6(conn)?;
            migrate_v6_to_v7(conn)
        }
        4 => {
            migrate_v4_to_v5(conn)?;
            migrate_v5_to_v6(conn)?;
            migrate_v6_to_v7(conn)
        }
        5 => {
            migrate_v5_to_v6(conn)?;
            migrate_v6_to_v7(conn)
        }
        6 => migrate_v6_to_v7(conn),
        SCHEMA_VERSION => Ok(()),
        _ => anyhow::bail!(
            "unsupported recordings.db schema version {user_version} (expected {SCHEMA_VERSION})"
        ),
    }
}

fn migrate_v1_to_v2(conn: &mut Connection) -> anyhow::Result<()> {
    conn.execute_batch(
        r#"
        ALTER TABLE recordings
          ADD COLUMN request_query_norm TEXT NOT NULL DEFAULT '';

        CREATE INDEX IF NOT EXISTS recordings_match_key_query_norm_idx
          ON recordings(match_key, request_query_norm, id DESC);
        "#,
    )
    .context("migrate sqlite schema v1 -> v2")?;

    backfill_request_query_norm(conn)?;

    conn.pragma_update(None, "user_version", 2)
        .context("set PRAGMA user_version=2")?;
    Ok(())
}

fn migrate_v2_to_v3(conn: &mut Connection) -> anyhow::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS recording_response_chunks (
          recording_id INTEGER NOT NULL,
          chunk_index INTEGER NOT NULL,
          offset_ms INTEGER NOT NULL,
          chunk_body BLOB NOT NULL,
          PRIMARY KEY (recording_id, chunk_index),
          FOREIGN KEY (recording_id) REFERENCES recordings(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS recording_response_chunks_replay_idx
          ON recording_response_chunks(recording_id, chunk_index);
        "#,
    )
    .context("migrate sqlite schema v2 -> v3")?;

    conn.pragma_update(None, "user_version", 3)
        .context("set PRAGMA user_version=3")?;
    Ok(())
}

fn migrate_v3_to_v4(conn: &mut Connection) -> anyhow::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS recording_websocket_frames (
          recording_id INTEGER NOT NULL,
          frame_index INTEGER NOT NULL,
          direction TEXT NOT NULL CHECK(direction IN ('client-to-server', 'server-to-client')),
          message_type TEXT NOT NULL CHECK(message_type IN ('text', 'binary')),
          offset_ms INTEGER NOT NULL,
          payload BLOB NOT NULL,
          PRIMARY KEY (recording_id, frame_index),
          FOREIGN KEY (recording_id) REFERENCES recordings(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS recording_websocket_frames_replay_idx
          ON recording_websocket_frames(recording_id, frame_index);
        "#,
    )
    .context("migrate sqlite schema v3 -> v4")?;

    conn.pragma_update(None, "user_version", 4)
        .context("set PRAGMA user_version=4")?;
    Ok(())
}

fn migrate_v4_to_v5(conn: &mut Connection) -> anyhow::Result<()> {
    backfill_request_query_norm_fingerprints(conn)?;

    conn.pragma_update(None, "user_version", 5)
        .context("set PRAGMA user_version=5")?;
    Ok(())
}

fn migrate_v5_to_v6(conn: &mut Connection) -> anyhow::Result<()> {
    conn.execute_batch(
        r#"
        ALTER TABLE recordings
          ADD COLUMN request_query_param_count INTEGER NOT NULL DEFAULT 0;

        CREATE INDEX IF NOT EXISTS recordings_match_key_query_param_count_idx
          ON recordings(match_key, request_query_param_count, id DESC);
        "#,
    )
    .context("migrate sqlite schema v5 -> v6")?;

    backfill_request_query_param_counts(conn)?;

    conn.pragma_update(None, "user_version", 6)
        .context("set PRAGMA user_version=6")?;
    Ok(())
}

fn migrate_v6_to_v7(conn: &mut Connection) -> anyhow::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS recording_query_param_index (
          recording_id INTEGER NOT NULL,
          match_key TEXT NOT NULL,
          request_query_param_count INTEGER NOT NULL,
          query_param_fingerprint TEXT NOT NULL,
          FOREIGN KEY (recording_id) REFERENCES recordings(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS recording_query_param_index_lookup_idx
          ON recording_query_param_index(
            match_key,
            query_param_fingerprint,
            request_query_param_count,
            recording_id DESC
          );
        CREATE INDEX IF NOT EXISTS recording_query_param_index_recording_id_idx
          ON recording_query_param_index(recording_id);
        "#,
    )
    .context("migrate sqlite schema v6 -> v7")?;

    backfill_recording_query_param_index(conn)?;

    conn.pragma_update(None, "user_version", 7)
        .context("set PRAGMA user_version=7")?;
    Ok(())
}

fn invalid_session_name(err: session::SessionNameError) -> SessionManagerError {
    SessionManagerError::InvalidName(err.to_string())
}

fn list_sessions_blocking(base_path: &Path) -> Result<Vec<String>, SessionManagerError> {
    if !base_path.exists() {
        return Ok(Vec::new());
    }

    let mut sessions = Vec::new();
    let entries = fs::read_dir(base_path).map_err(|err| {
        SessionManagerError::Io(format!("read sessions dir {}: {err}", base_path.display()))
    })?;

    for entry_result in entries {
        let entry = entry_result.map_err(|err| {
            SessionManagerError::Io(format!(
                "iterate sessions dir {}: {err}",
                base_path.display()
            ))
        })?;

        let file_type = entry.file_type().map_err(|err| {
            SessionManagerError::Io(format!(
                "read file type for session entry {}: {err}",
                entry.path().display()
            ))
        })?;

        if !file_type.is_dir() {
            continue;
        }

        let name = entry.file_name().to_string_lossy().into_owned();
        if session::validate_session_name(&name).is_err() {
            continue;
        }

        let db_path =
            session::resolve_session_db_path(base_path, &name).map_err(invalid_session_name)?;
        if !db_path.exists() {
            continue;
        }
        sessions.push(name);
    }

    sessions.sort();
    Ok(sessions)
}

fn create_session_blocking(base_path: &Path, name: &str) -> Result<(), SessionManagerError> {
    let session_dir =
        session::resolve_session_dir(base_path, name).map_err(invalid_session_name)?;
    let db_path =
        session::resolve_session_db_path(base_path, name).map_err(invalid_session_name)?;

    fs::create_dir_all(base_path).map_err(|err| {
        SessionManagerError::Io(format!(
            "create sessions dir {}: {err}",
            base_path.display()
        ))
    })?;

    match fs::create_dir(&session_dir) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(SessionManagerError::AlreadyExists(name.to_owned()));
        }
        Err(err) => {
            return Err(SessionManagerError::Io(format!(
                "create session dir {}: {err}",
                session_dir.display()
            )));
        }
    }

    Storage::open(db_path).map_err(|err| {
        SessionManagerError::Internal(format!("initialize session `{name}`: {err}"))
    })?;
    Ok(())
}

fn delete_session_blocking(base_path: &Path, name: &str) -> Result<(), SessionManagerError> {
    let session_dir =
        session::resolve_session_dir(base_path, name).map_err(invalid_session_name)?;
    if !session_dir.exists() {
        return Err(SessionManagerError::NotFound(name.to_owned()));
    }

    fs::remove_dir_all(&session_dir).map_err(|err| {
        SessionManagerError::Io(format!(
            "delete session dir {}: {err}",
            session_dir.display()
        ))
    })?;
    Ok(())
}

fn open_session_storage_blocking(
    base_path: &Path,
    name: &str,
    max_recordings: Option<u64>,
) -> Result<Storage, SessionManagerError> {
    let session_dir =
        session::resolve_session_dir(base_path, name).map_err(invalid_session_name)?;
    let db_path =
        session::resolve_session_db_path(base_path, name).map_err(invalid_session_name)?;

    if !session_dir.is_dir() || !db_path.exists() {
        return Err(SessionManagerError::NotFound(name.to_owned()));
    }

    Storage::open_with_max_recordings(db_path, max_recordings)
        .map_err(|err| SessionManagerError::Internal(format!("open session `{name}`: {err}")))
}

fn backfill_request_query_norm(conn: &Connection) -> anyhow::Result<()> {
    let mut stmt = conn
        .prepare(
            r#"
            SELECT id, request_uri
            FROM recordings
            "#,
        )
        .context("prepare select recordings for request_query_norm backfill")?;

    let mut rows = stmt
        .query([])
        .context("query recordings for request_query_norm backfill")?;

    let mut updates = Vec::new();
    while let Some(row) = rows
        .next()
        .context("iterate recordings for request_query_norm backfill")?
    {
        let id = row
            .get::<_, i64>(0)
            .context("deserialize id for backfill")?;
        let request_uri = row
            .get::<_, String>(1)
            .context("deserialize request_uri for backfill")?;
        updates.push((id, normalized_query_from_request_uri(&request_uri)));
    }
    drop(rows);
    drop(stmt);

    for (id, query_norm) in updates {
        conn.execute(
            "UPDATE recordings SET request_query_norm = ?1 WHERE id = ?2",
            params![query_norm, id],
        )
        .with_context(|| format!("backfill request_query_norm for recording id {id}"))?;
    }
    Ok(())
}

fn backfill_request_query_norm_fingerprints(conn: &Connection) -> anyhow::Result<()> {
    let mut stmt = conn
        .prepare(
            r#"
            SELECT id, request_query_norm
            FROM recordings
            "#,
        )
        .context("prepare select recordings for request_query_norm fingerprint migration")?;
    let mut rows = stmt
        .query([])
        .context("query recordings for request_query_norm fingerprint migration")?;

    let mut updates = Vec::new();
    while let Some(row) = rows
        .next()
        .context("iterate recordings for request_query_norm fingerprint migration")?
    {
        let id = row
            .get::<_, i64>(0)
            .context("deserialize id for request_query_norm fingerprint migration")?;
        let request_query_norm = row
            .get::<_, String>(1)
            .context("deserialize request_query_norm for fingerprint migration")?;
        let fingerprinted_query_norm =
            matching::normalize_stored_query_norm_to_fingerprint(&request_query_norm);
        if fingerprinted_query_norm != request_query_norm {
            updates.push((id, fingerprinted_query_norm));
        }
    }
    drop(rows);
    drop(stmt);

    for (id, query_norm) in updates {
        conn.execute(
            "UPDATE recordings SET request_query_norm = ?1 WHERE id = ?2",
            params![query_norm, id],
        )
        .with_context(|| {
            format!("migrate request_query_norm fingerprint representation for recording id {id}")
        })?;
    }

    Ok(())
}

fn backfill_request_query_param_counts(conn: &Connection) -> anyhow::Result<()> {
    let mut stmt = conn
        .prepare(
            r#"
            SELECT id, request_query_norm, request_query_param_count
            FROM recordings
            "#,
        )
        .context("prepare select recordings for request_query_param_count backfill")?;
    let mut rows = stmt
        .query([])
        .context("query recordings for request_query_param_count backfill")?;

    let mut updates = Vec::new();
    while let Some(row) = rows
        .next()
        .context("iterate recordings for request_query_param_count backfill")?
    {
        let id = row
            .get::<_, i64>(0)
            .context("deserialize id for request_query_param_count backfill")?;
        let request_query_norm = row
            .get::<_, String>(1)
            .context("deserialize request_query_norm for request_query_param_count backfill")?;
        let request_query_param_count = row
            .get::<_, i64>(2)
            .context("deserialize request_query_param_count for backfill")?;
        let expected_query_param_count =
            i64::try_from(matching::stored_query_norm_param_count(&request_query_norm))
                .context("request_query_param_count exceeds sqlite integer range")?;
        if request_query_param_count != expected_query_param_count {
            updates.push((id, expected_query_param_count));
        }
    }
    drop(rows);
    drop(stmt);

    for (id, request_query_param_count) in updates {
        conn.execute(
            "UPDATE recordings SET request_query_param_count = ?1 WHERE id = ?2",
            params![request_query_param_count, id],
        )
        .with_context(|| format!("backfill request_query_param_count for recording id {id}"))?;
    }

    Ok(())
}

fn backfill_recording_query_param_index(conn: &Connection) -> anyhow::Result<()> {
    conn.execute("DELETE FROM recording_query_param_index", [])
        .context("clear recording_query_param_index before backfill")?;

    let mut select_stmt = conn
        .prepare(
            r#"
            SELECT id, match_key, request_query_norm, request_query_param_count
            FROM recordings
            "#,
        )
        .context("prepare select recordings for query-param index backfill")?;
    let mut rows = select_stmt
        .query([])
        .context("query recordings for query-param index backfill")?;

    let mut insert_stmt = conn
        .prepare(
            r#"
            INSERT INTO recording_query_param_index (
              recording_id,
              match_key,
              request_query_param_count,
              query_param_fingerprint
            ) VALUES (?1, ?2, ?3, ?4)
            "#,
        )
        .context("prepare insert query-param index backfill row")?;

    while let Some(row) = rows
        .next()
        .context("iterate recordings for query-param index backfill")?
    {
        let recording_id = row
            .get::<_, i64>(0)
            .context("deserialize recording id for query-param index backfill")?;
        let match_key = row
            .get::<_, String>(1)
            .context("deserialize match_key for query-param index backfill")?;
        let request_query_norm = row
            .get::<_, String>(2)
            .context("deserialize request_query_norm for query-param index backfill")?;
        let request_query_param_count = row
            .get::<_, i64>(3)
            .context("deserialize request_query_param_count for query-param index backfill")?;

        for fingerprint in matching::stored_query_norm_fingerprints(&request_query_norm) {
            insert_stmt
                .execute(params![
                    recording_id,
                    match_key,
                    request_query_param_count,
                    fingerprint
                ])
                .with_context(|| {
                    format!("insert query-param index row for recording id {recording_id}")
                })?;
        }
    }

    Ok(())
}

fn insert_recording_query_param_index_rows(
    conn: &Connection,
    recording_id: i64,
    match_key: &str,
    request_query_norm: &str,
    request_query_param_count: i64,
) -> anyhow::Result<()> {
    let mut insert_stmt = conn
        .prepare(
            r#"
            INSERT INTO recording_query_param_index (
              recording_id,
              match_key,
              request_query_param_count,
              query_param_fingerprint
            ) VALUES (?1, ?2, ?3, ?4)
            "#,
        )
        .context("prepare insert query-param index row")?;

    for fingerprint in matching::stored_query_norm_fingerprints(request_query_norm) {
        insert_stmt
            .execute(params![
                recording_id,
                match_key,
                request_query_param_count,
                fingerprint
            ])
            .with_context(|| {
                format!("insert query-param index row for recording id {recording_id}")
            })?;
    }

    Ok(())
}

fn insert_recording_blocking(
    path: &Path,
    recording: Recording,
    request_query_norm: Option<String>,
    max_recordings: Option<u64>,
) -> anyhow::Result<i64> {
    let mut conn = open_connection(path)?;
    let match_key = recording.match_key.clone();
    let request_query_norm = request_query_norm
        .unwrap_or_else(|| normalized_query_from_request_uri(&recording.request_uri));
    let request_query_norm =
        matching::normalize_stored_query_norm_to_fingerprint(&request_query_norm);
    let request_query_param_count =
        i64::try_from(matching::stored_query_norm_param_count(&request_query_norm))
            .context("request_query_param_count exceeds sqlite integer range")?;
    let request_headers_json =
        serde_json::to_string(&recording.request_headers).context("serialize request headers")?;
    let response_headers_json =
        serde_json::to_string(&recording.response_headers).context("serialize response headers")?;

    let tx = conn
        .transaction()
        .context("open recording insert transaction")?;

    tx.execute(
        r#"
        INSERT INTO recordings (
          match_key,
          request_method,
          request_uri,
          request_query_norm,
          request_query_param_count,
          request_headers_json,
          request_body,
          response_status,
          response_headers_json,
          response_body,
          created_at_unix_ms
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        "#,
        params![
            recording.match_key,
            recording.request_method,
            recording.request_uri,
            request_query_norm,
            request_query_param_count,
            request_headers_json,
            recording.request_body,
            i64::from(recording.response_status),
            response_headers_json,
            recording.response_body,
            recording.created_at_unix_ms,
        ],
    )
    .context("insert recording")?;

    let recording_id = tx.last_insert_rowid();
    insert_recording_query_param_index_rows(
        &tx,
        recording_id,
        &match_key,
        &request_query_norm,
        request_query_param_count,
    )?;
    if let Some(max_recordings) = max_recordings {
        enforce_max_recordings(&tx, max_recordings)?;
    }
    tx.commit().context("commit recording insert transaction")?;

    Ok(recording_id)
}

fn enforce_max_recordings(
    tx: &rusqlite::Transaction<'_>,
    max_recordings: u64,
) -> anyhow::Result<()> {
    let keep = i64::try_from(max_recordings)
        .context("`storage.max_recordings` exceeds sqlite integer range")?;
    tx.execute(
        r#"
        DELETE FROM recordings
        WHERE id IN (
          SELECT id
          FROM recordings
          ORDER BY id DESC
          LIMIT -1 OFFSET ?1
        )
        "#,
        params![keep],
    )
    .context("enforce `storage.max_recordings` retention policy")?;
    Ok(())
}

fn insert_response_chunks_blocking(
    path: &Path,
    recording_id: i64,
    chunks: Vec<ResponseChunk>,
) -> anyhow::Result<()> {
    let mut conn = open_connection(path)?;
    let tx = conn
        .transaction()
        .context("open response chunk transaction")?;
    {
        let mut stmt = tx
            .prepare(
                r#"
                INSERT INTO recording_response_chunks (
                  recording_id,
                  chunk_index,
                  offset_ms,
                  chunk_body
                ) VALUES (?1, ?2, ?3, ?4)
                "#,
            )
            .context("prepare insert response chunk")?;

        for chunk in chunks {
            let offset_ms = i64::try_from(chunk.offset_ms)
                .context("response chunk offset_ms exceeds sqlite integer range")?;
            stmt.execute(params![
                recording_id,
                i64::from(chunk.chunk_index),
                offset_ms,
                chunk.chunk_body
            ])
            .context("insert recording response chunk")?;
        }
    }
    tx.commit().context("commit response chunk transaction")?;
    Ok(())
}

fn websocket_frame_direction_to_db_value(direction: WebSocketFrameDirection) -> &'static str {
    match direction {
        WebSocketFrameDirection::ClientToServer => "client-to-server",
        WebSocketFrameDirection::ServerToClient => "server-to-client",
    }
}

fn websocket_frame_direction_from_db_value(value: &str) -> anyhow::Result<WebSocketFrameDirection> {
    match value {
        "client-to-server" => Ok(WebSocketFrameDirection::ClientToServer),
        "server-to-client" => Ok(WebSocketFrameDirection::ServerToClient),
        _ => anyhow::bail!("deserialize websocket frame direction `{value}`"),
    }
}

fn websocket_message_type_to_db_value(message_type: WebSocketMessageType) -> &'static str {
    match message_type {
        WebSocketMessageType::Text => "text",
        WebSocketMessageType::Binary => "binary",
    }
}

fn websocket_message_type_from_db_value(value: &str) -> anyhow::Result<WebSocketMessageType> {
    match value {
        "text" => Ok(WebSocketMessageType::Text),
        "binary" => Ok(WebSocketMessageType::Binary),
        _ => anyhow::bail!("deserialize websocket message_type `{value}`"),
    }
}

fn insert_websocket_frames_blocking(
    path: &Path,
    recording_id: i64,
    frames: Vec<WebSocketFrame>,
) -> anyhow::Result<()> {
    let mut conn = open_connection(path)?;
    let tx = conn
        .transaction()
        .context("open websocket frame transaction")?;
    {
        let mut stmt = tx
            .prepare(
                r#"
                INSERT INTO recording_websocket_frames (
                  recording_id,
                  frame_index,
                  direction,
                  message_type,
                  offset_ms,
                  payload
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                "#,
            )
            .context("prepare insert websocket frame")?;

        for frame in frames {
            let offset_ms = i64::try_from(frame.offset_ms)
                .context("websocket frame offset_ms exceeds sqlite integer range")?;
            stmt.execute(params![
                recording_id,
                i64::from(frame.frame_index),
                websocket_frame_direction_to_db_value(frame.direction),
                websocket_message_type_to_db_value(frame.message_type),
                offset_ms,
                frame.payload
            ])
            .context("insert recording websocket frame")?;
        }
    }
    tx.commit().context("commit websocket frame transaction")?;
    Ok(())
}

fn get_response_chunks_blocking(
    path: &Path,
    recording_id: i64,
) -> anyhow::Result<Vec<ResponseChunk>> {
    let conn = open_connection(path)?;
    let mut stmt = conn
        .prepare(
            r#"
            SELECT
              chunk_index,
              offset_ms,
              chunk_body
            FROM recording_response_chunks
            WHERE recording_id = ?1
            ORDER BY chunk_index ASC
            "#,
        )
        .context("prepare select response chunks by recording id")?;

    let mut rows = stmt
        .query(params![recording_id])
        .context("query response chunks by recording id")?;

    let mut chunks = Vec::new();
    while let Some(row) = rows
        .next()
        .context("iterate response chunks by recording id")?
    {
        let chunk_index = row
            .get::<_, i64>(0)
            .context("deserialize response chunk index")?;
        let offset_ms = row
            .get::<_, i64>(1)
            .context("deserialize response chunk offset_ms")?;
        let chunk_body = row
            .get::<_, Vec<u8>>(2)
            .context("deserialize response chunk body")?;

        chunks.push(ResponseChunk {
            chunk_index: u32::try_from(chunk_index)
                .context("response chunk index cannot be negative or exceed u32")?,
            offset_ms: u64::try_from(offset_ms)
                .context("response chunk offset_ms cannot be negative")?,
            chunk_body,
        });
    }

    Ok(chunks)
}

fn get_websocket_frames_blocking(
    path: &Path,
    recording_id: i64,
) -> anyhow::Result<Vec<WebSocketFrame>> {
    let conn = open_connection(path)?;
    let mut stmt = conn
        .prepare(
            r#"
            SELECT
              frame_index,
              direction,
              message_type,
              offset_ms,
              payload
            FROM recording_websocket_frames
            WHERE recording_id = ?1
            ORDER BY frame_index ASC
            "#,
        )
        .context("prepare select websocket frames by recording id")?;

    let mut rows = stmt
        .query(params![recording_id])
        .context("query websocket frames by recording id")?;

    let mut frames = Vec::new();
    while let Some(row) = rows
        .next()
        .context("iterate websocket frames by recording id")?
    {
        let frame_index = row
            .get::<_, i64>(0)
            .context("deserialize websocket frame index")?;
        let direction = row
            .get::<_, String>(1)
            .context("deserialize websocket frame direction")?;
        let message_type = row
            .get::<_, String>(2)
            .context("deserialize websocket message_type")?;
        let offset_ms = row
            .get::<_, i64>(3)
            .context("deserialize websocket frame offset_ms")?;
        let payload = row
            .get::<_, Vec<u8>>(4)
            .context("deserialize websocket frame payload")?;

        frames.push(WebSocketFrame {
            frame_index: u32::try_from(frame_index)
                .context("websocket frame index cannot be negative or exceed u32")?,
            direction: websocket_frame_direction_from_db_value(&direction)?,
            message_type: websocket_message_type_from_db_value(&message_type)?,
            offset_ms: u64::try_from(offset_ms)
                .context("websocket frame offset_ms cannot be negative")?,
            payload,
        });
    }

    Ok(frames)
}

fn recording_query_from_uri(uri: &str) -> Option<&str> {
    uri.split_once('?').map(|(_, query)| query)
}

fn normalized_query_from_request_uri(uri: &str) -> String {
    matching::normalized_query_fingerprint(recording_query_from_uri(uri))
}

fn validate_pagination(offset: usize, limit: usize) -> anyhow::Result<(i64, i64)> {
    let offset = i64::try_from(offset).context("pagination offset exceeds sqlite range")?;
    let limit = i64::try_from(limit).context("pagination limit exceeds sqlite range")?;
    Ok((offset, limit))
}

fn deserialize_recording_at(row: &rusqlite::Row<'_>, offset: usize) -> anyhow::Result<Recording> {
    let match_key = row
        .get::<_, String>(offset)
        .context("deserialize match_key")?;
    let request_method = row
        .get::<_, String>(offset + 1)
        .context("deserialize request_method")?;
    let request_uri = row
        .get::<_, String>(offset + 2)
        .context("deserialize request_uri")?;
    let request_headers_json = row
        .get::<_, String>(offset + 3)
        .context("deserialize request_headers_json")?;
    let request_body = row
        .get::<_, Vec<u8>>(offset + 4)
        .context("deserialize request_body")?;
    let response_status = row
        .get::<_, i64>(offset + 5)
        .context("deserialize response_status")?;
    let response_headers_json = row
        .get::<_, String>(offset + 6)
        .context("deserialize response_headers_json")?;
    let response_body = row
        .get::<_, Vec<u8>>(offset + 7)
        .context("deserialize response_body")?;
    let created_at_unix_ms = row
        .get::<_, i64>(offset + 8)
        .context("deserialize created_at_unix_ms")?;

    let request_headers = deserialize_headers(&request_headers_json, "request")?;
    let response_headers = deserialize_headers(&response_headers_json, "response")?;
    let response_status = u16::try_from(response_status).context("deserialize response_status")?;

    Ok(Recording {
        match_key,
        request_method,
        request_uri,
        request_headers,
        request_body,
        response_status,
        response_headers,
        response_body,
        created_at_unix_ms,
    })
}

fn deserialize_stored_recording_at(
    row: &rusqlite::Row<'_>,
    id_offset: usize,
) -> anyhow::Result<StoredRecording> {
    let id = row
        .get::<_, i64>(id_offset)
        .context("deserialize recording id")?;
    let recording = deserialize_recording_at(row, id_offset + 1)?;
    Ok(StoredRecording { id, recording })
}

fn deserialize_recording_summary_at(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> anyhow::Result<RecordingSummary> {
    let id = row
        .get::<_, i64>(offset)
        .context("deserialize recording id")?;
    let match_key = row
        .get::<_, String>(offset + 1)
        .context("deserialize match_key")?;
    let request_method = row
        .get::<_, String>(offset + 2)
        .context("deserialize request_method")?;
    let request_uri = row
        .get::<_, String>(offset + 3)
        .context("deserialize request_uri")?;
    let response_status = row
        .get::<_, i64>(offset + 4)
        .context("deserialize response_status")?;
    let created_at_unix_ms = row
        .get::<_, i64>(offset + 5)
        .context("deserialize created_at_unix_ms")?;

    Ok(RecordingSummary {
        id,
        match_key,
        request_method,
        request_uri,
        response_status: u16::try_from(response_status).context("deserialize response_status")?,
        created_at_unix_ms,
    })
}

fn get_recording_with_id_by_match_key_blocking(
    path: &Path,
    match_key: &str,
) -> anyhow::Result<Option<StoredRecording>> {
    let conn = open_connection(path)?;

    let mut stmt = conn
        .prepare(
            r#"
            SELECT
              id,
              match_key,
              request_method,
              request_uri,
              request_headers_json,
              request_body,
              response_status,
              response_headers_json,
              response_body,
              created_at_unix_ms
            FROM recordings
            WHERE match_key = ?1
            ORDER BY id DESC
            LIMIT 1
            "#,
        )
        .context("prepare select latest recording by match_key")?;

    let mut rows = stmt
        .query(params![match_key])
        .context("query latest recording by match_key")?;

    let Some(row) = rows
        .next()
        .context("iterate latest recording by match_key")?
    else {
        return Ok(None);
    };

    Ok(Some(deserialize_stored_recording_at(row, 0)?))
}

fn get_recording_by_id_blocking(
    path: &Path,
    recording_id: i64,
) -> anyhow::Result<Option<Recording>> {
    let conn = open_connection(path)?;
    get_recording_by_id_from_conn(&conn, recording_id)
}

fn get_recording_by_id_from_conn(
    conn: &Connection,
    recording_id: i64,
) -> anyhow::Result<Option<Recording>> {
    let mut stmt = conn
        .prepare(
            r#"
            SELECT
              match_key,
              request_method,
              request_uri,
              request_headers_json,
              request_body,
              response_status,
              response_headers_json,
              response_body,
              created_at_unix_ms
            FROM recordings
            WHERE id = ?1
            LIMIT 1
            "#,
        )
        .context("prepare select recording by id")?;

    let mut rows = stmt
        .query(params![recording_id])
        .context("query recording by id")?;

    let Some(row) = rows.next().context("iterate recording by id")? else {
        return Ok(None);
    };

    Ok(Some(deserialize_recording_at(row, 0)?))
}

fn find_subset_match_from_rows(
    rows: &mut rusqlite::Rows<'_>,
    parsed_request_query: &matching::ParsedSubsetQuery<'_>,
    row_context: &'static str,
) -> anyhow::Result<(Option<i64>, usize)> {
    let mut matched_recording_id = None;
    let mut scanned_rows = 0usize;

    while let Some(row) = rows.next().context(row_context)? {
        scanned_rows += 1;
        let recording_id = row
            .get::<_, i64>(0)
            .with_context(|| format!("deserialize recording id while {row_context}"))?;
        let request_query_norm = row
            .get::<_, String>(1)
            .with_context(|| format!("deserialize request_query_norm while {row_context}"))?;
        let recorded_query_norm = if request_query_norm.is_empty() {
            None
        } else {
            Some(request_query_norm.as_str())
        };

        if matching::subset_normalized_query_matches_parsed_request(
            recorded_query_norm,
            parsed_request_query,
        ) {
            matched_recording_id = Some(recording_id);
            break;
        }
    }

    Ok((matched_recording_id, scanned_rows))
}

fn try_find_subset_match_with_query_param_index(
    conn: &Connection,
    match_key: &str,
    request_query_param_count: i64,
    request_query_fingerprint_counts: &[(String, usize)],
    parsed_request_query: &matching::ParsedSubsetQuery<'_>,
) -> anyhow::Result<Option<(Option<i64>, usize)>> {
    if request_query_fingerprint_counts.is_empty() {
        let mut stmt = conn
            .prepare(
                r#"
                SELECT
                  id,
                  request_query_norm
                FROM recordings
                WHERE match_key = ?1
                  AND request_query_param_count = 0
                ORDER BY id DESC
                "#,
            )
            .context("prepare zero-param subset candidate lookup")?;
        let mut rows = stmt
            .query(params![match_key])
            .context("query zero-param subset candidates")?;
        return find_subset_match_from_rows(
            &mut rows,
            parsed_request_query,
            "iterating zero-param subset candidates",
        )
        .map(Some);
    }

    let required_bind_params = request_query_fingerprint_counts
        .len()
        .checked_mul(2)
        .and_then(|count| count.checked_add(2))
        .context("subset index lookup bind parameter count overflow")?;
    if required_bind_params > SQLITE_MAX_BIND_PARAMS {
        return Ok(None);
    }

    let values_placeholders = request_query_fingerprint_counts
        .iter()
        .enumerate()
        .map(|(idx, _)| format!("(?{}, ?{})", idx * 2 + 1, idx * 2 + 2))
        .collect::<Vec<_>>()
        .join(", ");
    let match_key_bind_index = request_query_fingerprint_counts.len() * 2 + 1;
    let request_param_count_bind_index = match_key_bind_index + 1;

    let query = format!(
        r#"
        WITH request(query_param_fingerprint, max_count) AS (
          VALUES {values_placeholders}
        ),
        matched AS (
          SELECT
            q.recording_id,
            q.request_query_param_count,
            q.query_param_fingerprint,
            req.max_count AS max_count,
            COUNT(*) AS recording_count
          FROM recording_query_param_index q
          INNER JOIN request req
            ON req.query_param_fingerprint = q.query_param_fingerprint
          WHERE q.match_key = ?{match_key_bind_index}
            AND q.request_query_param_count <= ?{request_param_count_bind_index}
          GROUP BY
            q.recording_id,
            q.request_query_param_count,
            q.query_param_fingerprint,
            req.max_count
        ),
        valid_nonempty AS (
          SELECT recording_id
          FROM matched
          GROUP BY recording_id, request_query_param_count
          HAVING
            SUM(recording_count) = request_query_param_count
            AND SUM(CASE WHEN recording_count > max_count THEN 1 ELSE 0 END) = 0
        ),
        zero_param AS (
          SELECT id AS recording_id
          FROM recordings
          WHERE match_key = ?{match_key_bind_index}
            AND request_query_param_count = 0
        ),
        candidates AS (
          SELECT recording_id FROM valid_nonempty
          UNION
          SELECT recording_id FROM zero_param
        )
        SELECT
          r.id,
          r.request_query_norm
        FROM recordings r
        INNER JOIN candidates c
          ON c.recording_id = r.id
        ORDER BY r.id DESC
        "#
    );

    let mut values = Vec::with_capacity(required_bind_params);
    for (fingerprint, count) in request_query_fingerprint_counts {
        values.push(SqlValue::Text(fingerprint.clone()));
        values.push(SqlValue::Integer(i64::try_from(*count).context(
            "subset index lookup fingerprint count exceeds sqlite range",
        )?));
    }
    values.push(SqlValue::Text(match_key.to_owned()));
    values.push(SqlValue::Integer(request_query_param_count));

    let mut stmt = conn
        .prepare(query.as_str())
        .context("prepare indexed subset scan candidate lookup")?;
    let mut rows = stmt
        .query(params_from_iter(values.iter()))
        .context("query indexed subset scan candidates")?;

    let result = find_subset_match_from_rows(
        &mut rows,
        parsed_request_query,
        "iterating indexed subset scan candidates",
    )?;
    Ok(Some(result))
}

fn find_subset_match_with_legacy_scan(
    conn: &Connection,
    match_key: &str,
    request_query_param_count: i64,
    parsed_request_query: &matching::ParsedSubsetQuery<'_>,
) -> anyhow::Result<(Option<i64>, usize)> {
    let mut stmt = conn
        .prepare(
            r#"
            SELECT
              id,
              request_query_norm
            FROM recordings
            WHERE match_key = ?1
              AND request_query_param_count <= ?2
            ORDER BY id DESC
            "#,
        )
        .context("prepare legacy subset lookup scan")?;
    let mut rows = stmt
        .query(params![match_key, request_query_param_count])
        .context("query legacy subset lookup scan")?;

    find_subset_match_from_rows(
        &mut rows,
        parsed_request_query,
        "iterating legacy subset lookup scan",
    )
}

fn get_latest_recording_with_id_by_match_key_and_query_subset_scan_with_stats_blocking(
    path: &Path,
    match_key: &str,
    request_query: Option<&str>,
) -> anyhow::Result<SubsetScanLookupResultWithId> {
    let conn = open_connection(path)?;
    let request_query_param_count = i64::try_from(matching::query_param_count(request_query))
        .context("request_query_param_count exceeds sqlite integer range")?;
    let parsed_request_query = matching::ParsedSubsetQuery::from_query(request_query);
    let request_query_fingerprint_counts = matching::query_param_fingerprint_counts(request_query);

    let (matched_recording_id, scanned_rows) = if let Some(result) =
        try_find_subset_match_with_query_param_index(
            &conn,
            match_key,
            request_query_param_count,
            request_query_fingerprint_counts.as_slice(),
            &parsed_request_query,
        )? {
        result
    } else {
        find_subset_match_with_legacy_scan(
            &conn,
            match_key,
            request_query_param_count,
            &parsed_request_query,
        )?
    };

    let Some(matched_recording_id) = matched_recording_id else {
        return Ok(SubsetScanLookupResultWithId {
            recording: None,
            scanned_rows,
        });
    };

    Ok(SubsetScanLookupResultWithId {
        recording: get_recording_by_id_from_conn(&conn, matched_recording_id)?.map(|recording| {
            StoredRecording {
                id: matched_recording_id,
                recording,
            }
        }),
        scanned_rows,
    })
}

fn get_latest_recording_with_id_by_match_key_and_query_subset_blocking(
    path: &Path,
    match_key: &str,
    subset_query_normalizations: &[String],
) -> anyhow::Result<Option<StoredRecording>> {
    if subset_query_normalizations.is_empty() {
        return Ok(None);
    }

    let conn = open_connection(path)?;
    let mut latest: Option<StoredRecording> = None;

    for subset_chunk in subset_query_normalizations.chunks(QUERY_SUBSET_CHUNK_SIZE) {
        let maybe_row = get_latest_recording_for_subset_chunk(&conn, match_key, subset_chunk)?;
        if let Some(recording) = maybe_row {
            match latest.as_ref() {
                Some(latest_recording) if latest_recording.id >= recording.id => {}
                _ => latest = Some(recording),
            }
        }
    }

    Ok(latest)
}

fn get_latest_recording_for_subset_chunk(
    conn: &Connection,
    match_key: &str,
    subset_chunk: &[String],
) -> anyhow::Result<Option<StoredRecording>> {
    let placeholders = (2..(subset_chunk.len() + 2))
        .map(|idx| format!("?{idx}"))
        .collect::<Vec<_>>()
        .join(", ");

    let query = format!(
        r#"
        SELECT
          id,
          match_key,
          request_method,
          request_uri,
          request_headers_json,
          request_body,
          response_status,
          response_headers_json,
          response_body,
          created_at_unix_ms
        FROM recordings
        WHERE match_key = ?1
          AND request_query_norm IN ({placeholders})
        ORDER BY id DESC
        LIMIT 1
        "#
    );

    let mut stmt = conn
        .prepare(&query)
        .context("prepare select latest recording by match_key and query subset")?;

    let params_iter = std::iter::once(match_key).chain(subset_chunk.iter().map(String::as_str));
    let mut rows = stmt
        .query(params_from_iter(params_iter))
        .context("query latest recording by match_key and query subset")?;

    let Some(row) = rows
        .next()
        .context("iterate latest recording by match_key and query subset")?
    else {
        return Ok(None);
    };

    Ok(Some(deserialize_stored_recording_at(row, 0)?))
}

fn get_recordings_by_match_key_blocking(
    path: &Path,
    match_key: &str,
) -> anyhow::Result<Vec<Recording>> {
    let conn = open_connection(path)?;

    let mut stmt = conn
        .prepare(
            r#"
            SELECT
              match_key,
              request_method,
              request_uri,
              request_headers_json,
              request_body,
              response_status,
              response_headers_json,
              response_body,
              created_at_unix_ms
            FROM recordings
            WHERE match_key = ?1
            ORDER BY id DESC
            "#,
        )
        .context("prepare select recordings by match_key")?;

    let mut rows = stmt
        .query(params![match_key])
        .context("query recordings by match_key")?;

    let mut recordings = Vec::new();
    while let Some(row) = rows.next().context("iterate recordings by match_key")? {
        recordings.push(deserialize_recording_at(row, 0)?);
    }

    Ok(recordings)
}

fn list_recordings_blocking(
    path: &Path,
    offset: i64,
    limit: i64,
) -> anyhow::Result<Vec<RecordingSummary>> {
    let conn = open_connection(path)?;
    let mut stmt = conn
        .prepare(
            r#"
            SELECT
              id,
              match_key,
              request_method,
              request_uri,
              response_status,
              created_at_unix_ms
            FROM recordings
            ORDER BY id DESC
            LIMIT ?1 OFFSET ?2
            "#,
        )
        .context("prepare list recordings")?;

    let mut rows = stmt
        .query(params![limit, offset])
        .context("query list recordings")?;

    let mut summaries = Vec::new();
    while let Some(row) = rows.next().context("iterate list recordings")? {
        summaries.push(deserialize_recording_summary_at(row, 0)?);
    }
    Ok(summaries)
}

fn search_recordings_blocking(
    path: &Path,
    search: &RecordingSearch,
    offset: i64,
    limit: i64,
) -> anyhow::Result<Vec<RecordingSummary>> {
    let conn = open_connection(path)?;
    let method = search
        .method
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let url_contains = search
        .url_contains
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let body_contains = search
        .body_contains
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);

    let mut stmt = conn
        .prepare(
            r#"
            SELECT
              id,
              match_key,
              request_method,
              request_uri,
              response_status,
              created_at_unix_ms
            FROM recordings
            WHERE (?1 IS NULL OR request_method = ?1)
              AND (?2 IS NULL OR instr(request_uri, ?2) > 0)
              AND (
                ?3 IS NULL
                OR instr(CAST(request_body AS TEXT), ?3) > 0
                OR instr(CAST(response_body AS TEXT), ?3) > 0
              )
            ORDER BY id DESC
            LIMIT ?4 OFFSET ?5
            "#,
        )
        .context("prepare search recordings")?;

    let mut rows = stmt
        .query(params![method, url_contains, body_contains, limit, offset])
        .context("query search recordings")?;

    let mut summaries = Vec::new();
    while let Some(row) = rows.next().context("iterate search recordings")? {
        summaries.push(deserialize_recording_summary_at(row, 0)?);
    }
    Ok(summaries)
}

fn delete_recording_blocking(path: &Path, id: i64) -> anyhow::Result<bool> {
    let conn = open_connection(path)?;
    let deleted = conn
        .execute("DELETE FROM recordings WHERE id = ?1", params![id])
        .context("delete recording by id")?;
    Ok(deleted == 1)
}

fn count_recordings_blocking(path: &Path) -> anyhow::Result<u64> {
    let conn = open_connection(path)?;
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM recordings", [], |row| row.get(0))
        .context("count recordings")?;
    u64::try_from(count).context("recording count cannot be negative")
}

#[cfg(test)]
mod tests {
    use rusqlite::params;

    use super::{
        Recording, RecordingSearch, ResponseChunk, SessionManager, SessionManagerError, Storage,
        WebSocketFrame, WebSocketFrameDirection, WebSocketMessageType,
    };
    use crate::{config::Config, matching, session};

    fn test_recording(request_uri: &str, created_at_unix_ms: i64) -> Recording {
        Recording {
            match_key: "retention-key".to_owned(),
            request_method: "GET".to_owned(),
            request_uri: request_uri.to_owned(),
            request_headers: Vec::new(),
            request_body: Vec::new(),
            response_status: 200,
            response_headers: Vec::new(),
            response_body: request_uri.as_bytes().to_vec(),
            created_at_unix_ms,
        }
    }

    #[test]
    fn from_config_resolves_default_session_db_path() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = Config::from_toml_str(&format!(
            r#"
[proxy]
listen = "127.0.0.1:0"

[storage]
path = "{}"
"#,
            temp_dir.path().display()
        ))
        .unwrap();

        let storage = Storage::from_config(&config).unwrap().unwrap();
        let expected_path = temp_dir
            .path()
            .join(session::DEFAULT_SESSION_NAME)
            .join(session::RECORDINGS_DB_FILENAME);
        assert_eq!(storage.db_path(), expected_path.as_path());
    }

    #[test]
    fn from_config_rejects_unsafe_active_session_name() {
        let mut config = Config::from_toml_str(
            r#"
[proxy]
listen = "127.0.0.1:0"

[storage]
path = "/tmp/replayproxy-tests"
active_session = "default"
"#,
        )
        .unwrap();
        config.storage.as_mut().unwrap().active_session = Some("../prod".to_owned());

        let err = Storage::from_config(&config).unwrap_err();
        assert!(
            err.to_string()
                .contains("session name cannot contain path separators"),
            "err: {err}"
        );
    }

    #[tokio::test]
    async fn from_config_applies_max_recordings_retention() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = Config::from_toml_str(&format!(
            r#"
[proxy]
listen = "127.0.0.1:0"

[storage]
path = "{}"
active_session = "default"
max_recordings = 1
"#,
            temp_dir.path().display()
        ))
        .unwrap();

        let storage = Storage::from_config(&config).unwrap().unwrap();
        let first = test_recording("/one", Recording::now_unix_ms().unwrap());
        let mut second = first.clone();
        second.request_uri = "/two".to_owned();
        second.response_body = b"/two".to_vec();
        second.created_at_unix_ms += 1;

        storage.insert_recording(first).await.unwrap();
        storage.insert_recording(second).await.unwrap();

        let summaries = storage.list_recordings(0, 10).await.unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].request_uri, "/two");
    }

    #[tokio::test]
    async fn insert_and_fetch_round_trips_binary_headers_and_bodies() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp_dir.path().join("recordings.db")).unwrap();

        let recording = Recording {
            match_key: "match-key".to_owned(),
            request_method: "POST".to_owned(),
            request_uri: "/v1/chat/completions".to_owned(),
            request_headers: vec![
                ("content-type".to_owned(), b"application/json".to_vec()),
                ("x-request-binary".to_owned(), vec![0x80, 0xff, 0x7f]),
            ],
            request_body: vec![0x00, 0x01, 0x02, 0xff],
            response_status: 201,
            response_headers: vec![
                ("x-response-binary".to_owned(), vec![0x80, 0xff, 0x40]),
                ("cache-control".to_owned(), b"no-store".to_vec()),
            ],
            response_body: vec![0xff, 0x02, 0x01, 0x00],
            created_at_unix_ms: Recording::now_unix_ms().unwrap(),
        };

        storage.insert_recording(recording.clone()).await.unwrap();
        let fetched = storage
            .get_recording_by_match_key(&recording.match_key)
            .await
            .unwrap();

        assert_eq!(fetched, Some(recording));
    }

    #[tokio::test]
    async fn insert_and_fetch_response_chunks_orders_by_chunk_index() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp_dir.path().join("recordings.db")).unwrap();

        let recording = Recording {
            match_key: "stream-key".to_owned(),
            request_method: "GET".to_owned(),
            request_uri: "/v1/chat/completions?stream=true".to_owned(),
            request_headers: Vec::new(),
            request_body: Vec::new(),
            response_status: 200,
            response_headers: Vec::new(),
            response_body: Vec::new(),
            created_at_unix_ms: Recording::now_unix_ms().unwrap(),
        };
        let recording_id = storage.insert_recording(recording).await.unwrap();

        storage
            .insert_response_chunks(
                recording_id,
                vec![
                    ResponseChunk {
                        chunk_index: 2,
                        offset_ms: 40,
                        chunk_body: b"third".to_vec(),
                    },
                    ResponseChunk {
                        chunk_index: 0,
                        offset_ms: 5,
                        chunk_body: b"first".to_vec(),
                    },
                    ResponseChunk {
                        chunk_index: 1,
                        offset_ms: 15,
                        chunk_body: b"second".to_vec(),
                    },
                ],
            )
            .await
            .unwrap();

        let chunks = storage.get_response_chunks(recording_id).await.unwrap();
        assert_eq!(
            chunks,
            vec![
                ResponseChunk {
                    chunk_index: 0,
                    offset_ms: 5,
                    chunk_body: b"first".to_vec(),
                },
                ResponseChunk {
                    chunk_index: 1,
                    offset_ms: 15,
                    chunk_body: b"second".to_vec(),
                },
                ResponseChunk {
                    chunk_index: 2,
                    offset_ms: 40,
                    chunk_body: b"third".to_vec(),
                },
            ]
        );
    }

    #[tokio::test]
    async fn insert_response_chunks_requires_existing_recording() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp_dir.path().join("recordings.db")).unwrap();

        let err = storage
            .insert_response_chunks(
                42,
                vec![ResponseChunk {
                    chunk_index: 0,
                    offset_ms: 0,
                    chunk_body: b"missing-parent".to_vec(),
                }],
            )
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("insert recording response chunk"),
            "err: {err}"
        );
    }

    #[tokio::test]
    async fn insert_and_fetch_websocket_frames_orders_by_frame_index() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp_dir.path().join("recordings.db")).unwrap();

        let recording = Recording {
            match_key: "ws-key".to_owned(),
            request_method: "GET".to_owned(),
            request_uri: "/ws/echo".to_owned(),
            request_headers: Vec::new(),
            request_body: Vec::new(),
            response_status: 101,
            response_headers: Vec::new(),
            response_body: Vec::new(),
            created_at_unix_ms: Recording::now_unix_ms().unwrap(),
        };
        let recording_id = storage.insert_recording(recording).await.unwrap();

        storage
            .insert_websocket_frames(
                recording_id,
                vec![
                    WebSocketFrame {
                        frame_index: 2,
                        offset_ms: 55,
                        direction: WebSocketFrameDirection::ServerToClient,
                        message_type: WebSocketMessageType::Binary,
                        payload: vec![0xde, 0xad, 0xbe, 0xef],
                    },
                    WebSocketFrame {
                        frame_index: 0,
                        offset_ms: 5,
                        direction: WebSocketFrameDirection::ServerToClient,
                        message_type: WebSocketMessageType::Text,
                        payload: b"hello".to_vec(),
                    },
                    WebSocketFrame {
                        frame_index: 1,
                        offset_ms: 20,
                        direction: WebSocketFrameDirection::ClientToServer,
                        message_type: WebSocketMessageType::Text,
                        payload: b"ack".to_vec(),
                    },
                ],
            )
            .await
            .unwrap();

        let frames = storage.get_websocket_frames(recording_id).await.unwrap();
        assert_eq!(
            frames,
            vec![
                WebSocketFrame {
                    frame_index: 0,
                    offset_ms: 5,
                    direction: WebSocketFrameDirection::ServerToClient,
                    message_type: WebSocketMessageType::Text,
                    payload: b"hello".to_vec(),
                },
                WebSocketFrame {
                    frame_index: 1,
                    offset_ms: 20,
                    direction: WebSocketFrameDirection::ClientToServer,
                    message_type: WebSocketMessageType::Text,
                    payload: b"ack".to_vec(),
                },
                WebSocketFrame {
                    frame_index: 2,
                    offset_ms: 55,
                    direction: WebSocketFrameDirection::ServerToClient,
                    message_type: WebSocketMessageType::Binary,
                    payload: vec![0xde, 0xad, 0xbe, 0xef],
                },
            ]
        );
    }

    #[tokio::test]
    async fn insert_websocket_frames_requires_existing_recording() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp_dir.path().join("recordings.db")).unwrap();

        let err = storage
            .insert_websocket_frames(
                42,
                vec![WebSocketFrame {
                    frame_index: 0,
                    offset_ms: 0,
                    direction: WebSocketFrameDirection::ServerToClient,
                    message_type: WebSocketMessageType::Text,
                    payload: b"missing-parent".to_vec(),
                }],
            )
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("insert recording websocket frame"),
            "err: {err}"
        );
    }

    #[tokio::test]
    async fn fetch_supports_legacy_string_header_values() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp_dir.path().join("recordings.db")).unwrap();
        let conn = rusqlite::Connection::open(storage.db_path()).unwrap();

        conn.execute(
            r#"
            INSERT INTO recordings (
              match_key,
              request_method,
              request_uri,
              request_headers_json,
              request_body,
              response_status,
              response_headers_json,
              response_body,
              created_at_unix_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
            params![
                "legacy-key",
                "GET",
                "/legacy",
                r#"[["x-request","legacy"]]"#,
                vec![1u8, 2, 3],
                200i64,
                r#"[["x-response","legacy"]]"#,
                vec![4u8, 5, 6],
                Recording::now_unix_ms().unwrap(),
            ],
        )
        .unwrap();

        let fetched = storage
            .get_recording_by_match_key("legacy-key")
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            fetched.request_headers,
            vec![("x-request".to_owned(), b"legacy".to_vec())]
        );
        assert_eq!(
            fetched.response_headers,
            vec![("x-response".to_owned(), b"legacy".to_vec())]
        );
    }

    #[tokio::test]
    async fn fetch_recordings_by_match_key_returns_newest_first() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp_dir.path().join("recordings.db")).unwrap();

        let older = Recording {
            match_key: "same-key".to_owned(),
            request_method: "GET".to_owned(),
            request_uri: "/older?a=1".to_owned(),
            request_headers: Vec::new(),
            request_body: Vec::new(),
            response_status: 200,
            response_headers: Vec::new(),
            response_body: b"older".to_vec(),
            created_at_unix_ms: Recording::now_unix_ms().unwrap(),
        };
        let mut newer = older.clone();
        newer.request_uri = "/newer?a=1".to_owned();
        newer.response_body = b"newer".to_vec();
        newer.created_at_unix_ms = older.created_at_unix_ms + 1;

        storage.insert_recording(older).await.unwrap();
        storage.insert_recording(newer).await.unwrap();

        let recordings = storage
            .get_recordings_by_match_key("same-key")
            .await
            .unwrap();

        assert_eq!(recordings.len(), 2);
        assert_eq!(recordings[0].request_uri, "/newer?a=1");
        assert_eq!(recordings[1].request_uri, "/older?a=1");
    }

    #[tokio::test]
    async fn list_recordings_supports_pagination() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp_dir.path().join("recordings.db")).unwrap();

        let first = Recording {
            match_key: "match-1".to_owned(),
            request_method: "GET".to_owned(),
            request_uri: "/one".to_owned(),
            request_headers: Vec::new(),
            request_body: Vec::new(),
            response_status: 200,
            response_headers: Vec::new(),
            response_body: b"one".to_vec(),
            created_at_unix_ms: Recording::now_unix_ms().unwrap(),
        };
        let mut second = first.clone();
        second.match_key = "match-2".to_owned();
        second.request_uri = "/two".to_owned();
        second.response_body = b"two".to_vec();
        second.created_at_unix_ms += 1;
        let mut third = second.clone();
        third.match_key = "match-3".to_owned();
        third.request_uri = "/three".to_owned();
        third.response_body = b"three".to_vec();
        third.created_at_unix_ms += 1;

        storage.insert_recording(first).await.unwrap();
        storage.insert_recording(second).await.unwrap();
        storage.insert_recording(third).await.unwrap();

        let first_page = storage.list_recordings(0, 2).await.unwrap();
        assert_eq!(first_page.len(), 2);
        assert_eq!(first_page[0].request_uri, "/three");
        assert_eq!(first_page[1].request_uri, "/two");

        let second_page = storage.list_recordings(2, 2).await.unwrap();
        assert_eq!(second_page.len(), 1);
        assert_eq!(second_page[0].request_uri, "/one");
    }

    #[tokio::test]
    async fn search_recordings_filters_by_method_and_url_substring() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp_dir.path().join("recordings.db")).unwrap();

        let mut base = Recording {
            match_key: "search-key".to_owned(),
            request_method: "GET".to_owned(),
            request_uri: "/v1/chat/completions".to_owned(),
            request_headers: Vec::new(),
            request_body: Vec::new(),
            response_status: 200,
            response_headers: Vec::new(),
            response_body: b"body".to_vec(),
            created_at_unix_ms: Recording::now_unix_ms().unwrap(),
        };

        storage.insert_recording(base.clone()).await.unwrap();

        base.request_method = "POST".to_owned();
        base.request_uri = "/v1/chat/completions".to_owned();
        base.created_at_unix_ms += 1;
        storage.insert_recording(base.clone()).await.unwrap();

        base.request_method = "POST".to_owned();
        base.request_uri = "/v1/embeddings".to_owned();
        base.created_at_unix_ms += 1;
        storage.insert_recording(base).await.unwrap();

        let results = storage
            .search_recordings(
                RecordingSearch {
                    method: Some("POST".to_owned()),
                    url_contains: Some("/chat".to_owned()),
                    body_contains: None,
                },
                0,
                10,
            )
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].request_method, "POST");
        assert_eq!(results[0].request_uri, "/v1/chat/completions");
    }

    #[tokio::test]
    async fn search_recordings_filters_by_body_content_in_request_or_response() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp_dir.path().join("recordings.db")).unwrap();

        let mut base = Recording {
            match_key: "body-search".to_owned(),
            request_method: "POST".to_owned(),
            request_uri: "/v1/chat/completions".to_owned(),
            request_headers: Vec::new(),
            request_body: br#"{"prompt":"alpha"}"#.to_vec(),
            response_status: 200,
            response_headers: Vec::new(),
            response_body: br#"{"message":"chat-completion"}"#.to_vec(),
            created_at_unix_ms: Recording::now_unix_ms().unwrap(),
        };
        let chat_id = storage.insert_recording(base.clone()).await.unwrap();

        base.request_method = "POST".to_owned();
        base.request_uri = "/v1/embeddings".to_owned();
        base.request_body = br#"{"input":"vector me"}"#.to_vec();
        base.response_body = br#"{"embedding":"[0.1,0.2]"}"#.to_vec();
        base.created_at_unix_ms += 1;
        let embeddings_id = storage.insert_recording(base.clone()).await.unwrap();

        base.request_method = "GET".to_owned();
        base.request_uri = "/v1/models".to_owned();
        base.request_body = Vec::new();
        base.response_body = br#"{"data":["model-a","model-b"]}"#.to_vec();
        base.created_at_unix_ms += 1;
        storage.insert_recording(base).await.unwrap();

        let request_body_results = storage
            .search_recordings(
                RecordingSearch {
                    method: None,
                    url_contains: None,
                    body_contains: Some("vector me".to_owned()),
                },
                0,
                10,
            )
            .await
            .unwrap();
        assert_eq!(request_body_results.len(), 1);
        assert_eq!(request_body_results[0].id, embeddings_id);

        let response_body_results = storage
            .search_recordings(
                RecordingSearch {
                    method: Some("POST".to_owned()),
                    url_contains: Some("/chat".to_owned()),
                    body_contains: Some("chat-completion".to_owned()),
                },
                0,
                10,
            )
            .await
            .unwrap();
        assert_eq!(response_body_results.len(), 1);
        assert_eq!(response_body_results[0].id, chat_id);
    }

    #[tokio::test]
    async fn delete_recording_removes_only_target_id() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp_dir.path().join("recordings.db")).unwrap();

        let base = Recording {
            match_key: "delete-key".to_owned(),
            request_method: "GET".to_owned(),
            request_uri: "/first".to_owned(),
            request_headers: Vec::new(),
            request_body: Vec::new(),
            response_status: 200,
            response_headers: Vec::new(),
            response_body: b"first".to_vec(),
            created_at_unix_ms: Recording::now_unix_ms().unwrap(),
        };
        let mut second = base.clone();
        second.request_uri = "/second".to_owned();
        second.response_body = b"second".to_vec();
        second.created_at_unix_ms += 1;

        let first_id = storage.insert_recording(base).await.unwrap();
        let second_id = storage.insert_recording(second).await.unwrap();

        assert!(storage.delete_recording(first_id).await.unwrap());
        assert!(!storage.delete_recording(first_id).await.unwrap());

        let remaining = storage.list_recordings(0, 10).await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, second_id);
        assert_eq!(remaining[0].request_uri, "/second");
    }

    #[tokio::test]
    async fn delete_recording_cascades_response_chunks() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp_dir.path().join("recordings.db")).unwrap();

        let recording = Recording {
            match_key: "cascade-key".to_owned(),
            request_method: "GET".to_owned(),
            request_uri: "/stream".to_owned(),
            request_headers: Vec::new(),
            request_body: Vec::new(),
            response_status: 200,
            response_headers: Vec::new(),
            response_body: Vec::new(),
            created_at_unix_ms: Recording::now_unix_ms().unwrap(),
        };
        let recording_id = storage.insert_recording(recording).await.unwrap();
        storage
            .insert_response_chunks(
                recording_id,
                vec![
                    ResponseChunk {
                        chunk_index: 0,
                        offset_ms: 0,
                        chunk_body: b"hello".to_vec(),
                    },
                    ResponseChunk {
                        chunk_index: 1,
                        offset_ms: 10,
                        chunk_body: b"world".to_vec(),
                    },
                ],
            )
            .await
            .unwrap();

        assert!(storage.delete_recording(recording_id).await.unwrap());
        let chunks = storage.get_response_chunks(recording_id).await.unwrap();
        assert!(chunks.is_empty());
    }

    #[tokio::test]
    async fn delete_recording_cascades_websocket_frames() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp_dir.path().join("recordings.db")).unwrap();

        let recording = Recording {
            match_key: "ws-cascade-key".to_owned(),
            request_method: "GET".to_owned(),
            request_uri: "/ws/stream".to_owned(),
            request_headers: Vec::new(),
            request_body: Vec::new(),
            response_status: 101,
            response_headers: Vec::new(),
            response_body: Vec::new(),
            created_at_unix_ms: Recording::now_unix_ms().unwrap(),
        };
        let recording_id = storage.insert_recording(recording).await.unwrap();
        storage
            .insert_websocket_frames(
                recording_id,
                vec![
                    WebSocketFrame {
                        frame_index: 0,
                        offset_ms: 0,
                        direction: WebSocketFrameDirection::ServerToClient,
                        message_type: WebSocketMessageType::Text,
                        payload: b"hello".to_vec(),
                    },
                    WebSocketFrame {
                        frame_index: 1,
                        offset_ms: 10,
                        direction: WebSocketFrameDirection::ClientToServer,
                        message_type: WebSocketMessageType::Text,
                        payload: b"world".to_vec(),
                    },
                ],
            )
            .await
            .unwrap();

        assert!(storage.delete_recording(recording_id).await.unwrap());
        let frames = storage.get_websocket_frames(recording_id).await.unwrap();
        assert!(frames.is_empty());
    }

    #[tokio::test]
    async fn count_recordings_returns_total_rows() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp_dir.path().join("recordings.db")).unwrap();

        assert_eq!(storage.count_recordings().await.unwrap(), 0);

        let recording = Recording {
            match_key: "count-key".to_owned(),
            request_method: "GET".to_owned(),
            request_uri: "/first".to_owned(),
            request_headers: Vec::new(),
            request_body: Vec::new(),
            response_status: 200,
            response_headers: Vec::new(),
            response_body: b"body".to_vec(),
            created_at_unix_ms: Recording::now_unix_ms().unwrap(),
        };

        storage.insert_recording(recording.clone()).await.unwrap();
        storage.insert_recording(recording).await.unwrap();

        assert_eq!(storage.count_recordings().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn open_with_max_recordings_prunes_oldest_recordings() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage =
            Storage::open_with_max_recordings(temp_dir.path().join("recordings.db"), Some(2))
                .unwrap();

        let first = test_recording("/one", Recording::now_unix_ms().unwrap());
        let mut second = test_recording("/two", first.created_at_unix_ms + 1);
        second.match_key = "retention-key-2".to_owned();
        let mut third = test_recording("/three", first.created_at_unix_ms + 2);
        third.match_key = "retention-key-3".to_owned();

        let first_id = storage.insert_recording(first).await.unwrap();
        storage.insert_recording(second).await.unwrap();
        storage.insert_recording(third).await.unwrap();

        assert_eq!(storage.count_recordings().await.unwrap(), 2);
        assert!(
            storage
                .get_recording_by_id(first_id)
                .await
                .unwrap()
                .is_none()
        );

        let summaries = storage.list_recordings(0, 10).await.unwrap();
        assert_eq!(
            summaries
                .iter()
                .map(|summary| summary.request_uri.as_str())
                .collect::<Vec<_>>(),
            vec!["/three", "/two"]
        );
    }

    #[tokio::test]
    async fn subset_lookup_returns_newest_matching_recording() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp_dir.path().join("recordings.db")).unwrap();

        let mut base = Recording {
            match_key: "same-key".to_owned(),
            request_method: "GET".to_owned(),
            request_uri: "/api?a=1".to_owned(),
            request_headers: Vec::new(),
            request_body: Vec::new(),
            response_status: 200,
            response_headers: Vec::new(),
            response_body: b"older".to_vec(),
            created_at_unix_ms: Recording::now_unix_ms().unwrap(),
        };

        storage.insert_recording(base.clone()).await.unwrap();

        base.request_uri = "/api?a=1&b=2".to_owned();
        base.response_body = b"newer-matching".to_vec();
        base.created_at_unix_ms += 1;
        storage.insert_recording(base.clone()).await.unwrap();

        base.request_uri = "/api?x=9".to_owned();
        base.response_body = b"newest-nonmatching".to_vec();
        base.created_at_unix_ms += 1;
        storage.insert_recording(base).await.unwrap();

        let subset_query_norms = matching::subset_query_candidate_fingerprints_with_limit(
            Some("a=1&b=2&c=3"),
            usize::MAX,
        )
        .unwrap();
        let fetched = storage
            .get_latest_recording_by_match_key_and_query_subset("same-key", subset_query_norms)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(fetched.request_uri, "/api?a=1&b=2");
        assert_eq!(&fetched.response_body[..], b"newer-matching");
    }

    #[tokio::test]
    async fn subset_scan_lookup_returns_newest_matching_recording() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp_dir.path().join("recordings.db")).unwrap();

        let mut base = Recording {
            match_key: "same-key".to_owned(),
            request_method: "GET".to_owned(),
            request_uri: "/api?a=1".to_owned(),
            request_headers: Vec::new(),
            request_body: Vec::new(),
            response_status: 200,
            response_headers: Vec::new(),
            response_body: b"older".to_vec(),
            created_at_unix_ms: Recording::now_unix_ms().unwrap(),
        };

        storage.insert_recording(base.clone()).await.unwrap();

        base.request_uri = "/api?a=1&b=2".to_owned();
        base.response_body = b"newer-matching".to_vec();
        base.created_at_unix_ms += 1;
        storage.insert_recording(base.clone()).await.unwrap();

        base.request_uri = "/api?x=9".to_owned();
        base.response_body = b"newest-nonmatching".to_vec();
        base.created_at_unix_ms += 1;
        storage.insert_recording(base).await.unwrap();

        let fetched = storage
            .get_latest_recording_by_match_key_and_query_subset_scan_with_stats(
                "same-key",
                Some("a=1&b=2&c=3"),
            )
            .await
            .unwrap();

        assert_eq!(fetched.scanned_rows, 1);
        let recording = fetched.recording.unwrap();
        assert_eq!(recording.request_uri, "/api?a=1&b=2");
        assert_eq!(&recording.response_body[..], b"newer-matching");
    }

    #[tokio::test]
    async fn subset_scan_lookup_filters_out_rows_with_too_many_query_params() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp_dir.path().join("recordings.db")).unwrap();

        let mut base = Recording {
            match_key: "same-key".to_owned(),
            request_method: "GET".to_owned(),
            request_uri: "/api?a=1&b=2".to_owned(),
            request_headers: Vec::new(),
            request_body: Vec::new(),
            response_status: 200,
            response_headers: Vec::new(),
            response_body: b"matching-two-params".to_vec(),
            created_at_unix_ms: Recording::now_unix_ms().unwrap(),
        };

        storage.insert_recording(base.clone()).await.unwrap();

        base.request_uri = "/api?a=1&b=2&c=3".to_owned();
        base.response_body = b"newest-too-many-params".to_vec();
        base.created_at_unix_ms += 1;
        storage.insert_recording(base).await.unwrap();

        let fetched = storage
            .get_latest_recording_by_match_key_and_query_subset_scan_with_stats(
                "same-key",
                Some("a=1&b=2"),
            )
            .await
            .unwrap();

        assert_eq!(fetched.scanned_rows, 1);
        let recording = fetched.recording.unwrap();
        assert_eq!(recording.request_uri, "/api?a=1&b=2");
        assert_eq!(&recording.response_body[..], b"matching-two-params");
    }

    #[tokio::test]
    async fn subset_scan_lookup_returns_none_when_no_recording_matches() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp_dir.path().join("recordings.db")).unwrap();

        let recording = Recording {
            match_key: "same-key".to_owned(),
            request_method: "GET".to_owned(),
            request_uri: "/api?x=9".to_owned(),
            request_headers: Vec::new(),
            request_body: Vec::new(),
            response_status: 200,
            response_headers: Vec::new(),
            response_body: b"only-recording".to_vec(),
            created_at_unix_ms: Recording::now_unix_ms().unwrap(),
        };
        storage.insert_recording(recording).await.unwrap();

        let fetched = storage
            .get_latest_recording_by_match_key_and_query_subset_scan_with_stats(
                "same-key",
                Some("a=1&b=2"),
            )
            .await
            .unwrap();

        assert!(fetched.recording.is_none());
        assert_eq!(fetched.scanned_rows, 0);
    }

    #[tokio::test]
    async fn subset_scan_lookup_compat_method_returns_recording_without_stats() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp_dir.path().join("recordings.db")).unwrap();

        let recording = Recording {
            match_key: "same-key".to_owned(),
            request_method: "GET".to_owned(),
            request_uri: "/api?a=1".to_owned(),
            request_headers: Vec::new(),
            request_body: Vec::new(),
            response_status: 200,
            response_headers: Vec::new(),
            response_body: b"matched".to_vec(),
            created_at_unix_ms: Recording::now_unix_ms().unwrap(),
        };
        storage.insert_recording(recording).await.unwrap();

        let fetched = storage
            .get_latest_recording_by_match_key_and_query_subset_scan("same-key", Some("a=1&b=2"))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(fetched.request_uri, "/api?a=1");
    }

    #[tokio::test]
    async fn subset_scan_lookup_preserves_behavior_for_unsorted_query_norm_rows() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp_dir.path().join("recordings.db")).unwrap();

        let recording = Recording {
            match_key: "same-key".to_owned(),
            request_method: "GET".to_owned(),
            request_uri: "/api?a=1&b=2".to_owned(),
            request_headers: Vec::new(),
            request_body: Vec::new(),
            response_status: 200,
            response_headers: Vec::new(),
            response_body: b"matched".to_vec(),
            created_at_unix_ms: Recording::now_unix_ms().unwrap(),
        };
        storage.insert_recording(recording).await.unwrap();

        let conn = rusqlite::Connection::open(storage.db_path()).unwrap();
        conn.execute(
            "UPDATE recordings SET request_query_norm = 'b=2&a=1' WHERE match_key = 'same-key'",
            [],
        )
        .unwrap();
        drop(conn);

        let fetched = storage
            .get_latest_recording_by_match_key_and_query_subset_scan_with_stats(
                "same-key",
                Some("a=1&b=2&c=3"),
            )
            .await
            .unwrap();

        assert_eq!(fetched.scanned_rows, 1);
        let recording = fetched.recording.unwrap();
        assert_eq!(recording.request_uri, "/api?a=1&b=2");
    }

    #[tokio::test]
    async fn open_migrates_v1_schema_and_backfills_query_normalization() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("recordings.db");
        let conn = rusqlite::Connection::open(&db_path).unwrap();

        conn.execute_batch(
            r#"
            CREATE TABLE recordings (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              match_key TEXT NOT NULL,
              request_method TEXT NOT NULL,
              request_uri TEXT NOT NULL,
              request_headers_json TEXT NOT NULL,
              request_body BLOB NOT NULL,
              response_status INTEGER NOT NULL,
              response_headers_json TEXT NOT NULL,
              response_body BLOB NOT NULL,
              created_at_unix_ms INTEGER NOT NULL
            );

            CREATE INDEX recordings_match_key_idx ON recordings(match_key);
            PRAGMA user_version = 1;
            "#,
        )
        .unwrap();

        conn.execute(
            r#"
            INSERT INTO recordings (
              match_key,
              request_method,
              request_uri,
              request_headers_json,
              request_body,
              response_status,
              response_headers_json,
              response_body,
              created_at_unix_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
            params![
                "legacy-key",
                "GET",
                "/api?b=2&a=1",
                r#"[["x-request","legacy"]]"#,
                Vec::<u8>::new(),
                200i64,
                r#"[["x-response","legacy"]]"#,
                b"body".to_vec(),
                Recording::now_unix_ms().unwrap(),
            ],
        )
        .unwrap();
        drop(conn);

        let storage = Storage::open(db_path).unwrap();
        let conn = rusqlite::Connection::open(storage.db_path()).unwrap();
        let user_version: i64 = conn
            .query_row("PRAGMA user_version;", [], |row| row.get(0))
            .unwrap();
        assert_eq!(user_version, 7);

        let query_norm: String = conn
            .query_row(
                "SELECT request_query_norm FROM recordings WHERE match_key = 'legacy-key'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            query_norm,
            matching::normalized_query_fingerprint(Some("a=1&b=2"))
        );

        let query_param_count: i64 = conn
            .query_row(
                "SELECT request_query_param_count FROM recordings WHERE match_key = 'legacy-key'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(query_param_count, 2);

        let chunk_table_exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'recording_response_chunks'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(chunk_table_exists, 1);

        let websocket_frame_table_exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'recording_websocket_frames'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(websocket_frame_table_exists, 1);

        let query_param_index_table_exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'recording_query_param_index'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(query_param_index_table_exists, 1);

        let subset_query_norms = matching::subset_query_candidate_fingerprints_with_limit(
            Some("a=1&b=2&c=3"),
            usize::MAX,
        )
        .unwrap();
        let fetched = storage
            .get_latest_recording_by_match_key_and_query_subset("legacy-key", subset_query_norms)
            .await
            .unwrap();
        assert!(fetched.is_some());
    }

    #[tokio::test]
    async fn open_migrates_v2_schema_to_v7_streaming_and_websocket_tables() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("recordings.db");
        let conn = rusqlite::Connection::open(&db_path).unwrap();

        conn.execute_batch(
            r#"
            CREATE TABLE recordings (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              match_key TEXT NOT NULL,
              request_method TEXT NOT NULL,
              request_uri TEXT NOT NULL,
              request_query_norm TEXT NOT NULL DEFAULT '',
              request_headers_json TEXT NOT NULL,
              request_body BLOB NOT NULL,
              response_status INTEGER NOT NULL,
              response_headers_json TEXT NOT NULL,
              response_body BLOB NOT NULL,
              created_at_unix_ms INTEGER NOT NULL
            );

            CREATE INDEX recordings_match_key_idx ON recordings(match_key);
            CREATE INDEX recordings_match_key_query_norm_idx
              ON recordings(match_key, request_query_norm, id DESC);
            PRAGMA user_version = 2;
            "#,
        )
        .unwrap();
        drop(conn);

        let storage = Storage::open(db_path).unwrap();
        let conn = rusqlite::Connection::open(storage.db_path()).unwrap();
        let user_version: i64 = conn
            .query_row("PRAGMA user_version;", [], |row| row.get(0))
            .unwrap();
        assert_eq!(user_version, 7);

        let chunk_table_exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'recording_response_chunks'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(chunk_table_exists, 1);

        let websocket_frame_table_exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'recording_websocket_frames'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(websocket_frame_table_exists, 1);

        let query_param_index_table_exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'recording_query_param_index'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(query_param_index_table_exists, 1);
    }

    #[tokio::test]
    async fn open_migrates_v3_schema_to_v7_websocket_frame_table() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("recordings.db");
        let conn = rusqlite::Connection::open(&db_path).unwrap();

        conn.execute_batch(
            r#"
            CREATE TABLE recordings (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              match_key TEXT NOT NULL,
              request_method TEXT NOT NULL,
              request_uri TEXT NOT NULL,
              request_query_norm TEXT NOT NULL DEFAULT '',
              request_headers_json TEXT NOT NULL,
              request_body BLOB NOT NULL,
              response_status INTEGER NOT NULL,
              response_headers_json TEXT NOT NULL,
              response_body BLOB NOT NULL,
              created_at_unix_ms INTEGER NOT NULL
            );

            CREATE INDEX recordings_match_key_idx ON recordings(match_key);
            CREATE INDEX recordings_match_key_query_norm_idx
              ON recordings(match_key, request_query_norm, id DESC);

            CREATE TABLE recording_response_chunks (
              recording_id INTEGER NOT NULL,
              chunk_index INTEGER NOT NULL,
              offset_ms INTEGER NOT NULL,
              chunk_body BLOB NOT NULL,
              PRIMARY KEY (recording_id, chunk_index),
              FOREIGN KEY (recording_id) REFERENCES recordings(id) ON DELETE CASCADE
            );

            CREATE INDEX recording_response_chunks_replay_idx
              ON recording_response_chunks(recording_id, chunk_index);
            PRAGMA user_version = 3;
            "#,
        )
        .unwrap();
        drop(conn);

        let storage = Storage::open(db_path).unwrap();
        let conn = rusqlite::Connection::open(storage.db_path()).unwrap();
        let user_version: i64 = conn
            .query_row("PRAGMA user_version;", [], |row| row.get(0))
            .unwrap();
        assert_eq!(user_version, 7);

        let websocket_frame_table_exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'recording_websocket_frames'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(websocket_frame_table_exists, 1);
    }

    #[tokio::test]
    async fn open_migrates_v4_schema_to_v7_query_norm_fingerprints() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("recordings.db");
        let conn = rusqlite::Connection::open(&db_path).unwrap();

        conn.execute_batch(
            r#"
            CREATE TABLE recordings (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              match_key TEXT NOT NULL,
              request_method TEXT NOT NULL,
              request_uri TEXT NOT NULL,
              request_query_norm TEXT NOT NULL DEFAULT '',
              request_headers_json TEXT NOT NULL,
              request_body BLOB NOT NULL,
              response_status INTEGER NOT NULL,
              response_headers_json TEXT NOT NULL,
              response_body BLOB NOT NULL,
              created_at_unix_ms INTEGER NOT NULL
            );

            CREATE INDEX recordings_match_key_idx ON recordings(match_key);
            CREATE INDEX recordings_match_key_query_norm_idx
              ON recordings(match_key, request_query_norm, id DESC);

            CREATE TABLE recording_response_chunks (
              recording_id INTEGER NOT NULL,
              chunk_index INTEGER NOT NULL,
              offset_ms INTEGER NOT NULL,
              chunk_body BLOB NOT NULL,
              PRIMARY KEY (recording_id, chunk_index),
              FOREIGN KEY (recording_id) REFERENCES recordings(id) ON DELETE CASCADE
            );

            CREATE INDEX recording_response_chunks_replay_idx
              ON recording_response_chunks(recording_id, chunk_index);

            CREATE TABLE recording_websocket_frames (
              recording_id INTEGER NOT NULL,
              frame_index INTEGER NOT NULL,
              direction TEXT NOT NULL CHECK(direction IN ('client-to-server', 'server-to-client')),
              message_type TEXT NOT NULL CHECK(message_type IN ('text', 'binary')),
              offset_ms INTEGER NOT NULL,
              payload BLOB NOT NULL,
              PRIMARY KEY (recording_id, frame_index),
              FOREIGN KEY (recording_id) REFERENCES recordings(id) ON DELETE CASCADE
            );

            CREATE INDEX recording_websocket_frames_replay_idx
              ON recording_websocket_frames(recording_id, frame_index);

            PRAGMA user_version = 4;
            "#,
        )
        .unwrap();

        conn.execute(
            r#"
            INSERT INTO recordings (
              match_key,
              request_method,
              request_uri,
              request_query_norm,
              request_headers_json,
              request_body,
              response_status,
              response_headers_json,
              response_body,
              created_at_unix_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
            params![
                "legacy-v4-key",
                "GET",
                "/api?b=2&a=1",
                "b=2&a=1",
                r#"[["x-request","legacy"]]"#,
                Vec::<u8>::new(),
                200i64,
                r#"[["x-response","legacy"]]"#,
                b"body".to_vec(),
                Recording::now_unix_ms().unwrap(),
            ],
        )
        .unwrap();
        drop(conn);

        let storage = Storage::open(db_path).unwrap();
        let conn = rusqlite::Connection::open(storage.db_path()).unwrap();
        let user_version: i64 = conn
            .query_row("PRAGMA user_version;", [], |row| row.get(0))
            .unwrap();
        assert_eq!(user_version, 7);

        let query_norm: String = conn
            .query_row(
                "SELECT request_query_norm FROM recordings WHERE match_key = 'legacy-v4-key'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            query_norm,
            matching::normalized_query_fingerprint(Some("a=1&b=2"))
        );

        let query_param_count: i64 = conn
            .query_row(
                "SELECT request_query_param_count FROM recordings WHERE match_key = 'legacy-v4-key'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(query_param_count, 2);
    }

    #[tokio::test]
    async fn open_migrates_v5_schema_to_v7_query_param_counts() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("recordings.db");
        let conn = rusqlite::Connection::open(&db_path).unwrap();

        conn.execute_batch(
            r#"
            CREATE TABLE recordings (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              match_key TEXT NOT NULL,
              request_method TEXT NOT NULL,
              request_uri TEXT NOT NULL,
              request_query_norm TEXT NOT NULL DEFAULT '',
              request_headers_json TEXT NOT NULL,
              request_body BLOB NOT NULL,
              response_status INTEGER NOT NULL,
              response_headers_json TEXT NOT NULL,
              response_body BLOB NOT NULL,
              created_at_unix_ms INTEGER NOT NULL
            );

            CREATE INDEX recordings_match_key_idx ON recordings(match_key);
            CREATE INDEX recordings_match_key_query_norm_idx
              ON recordings(match_key, request_query_norm, id DESC);

            CREATE TABLE recording_response_chunks (
              recording_id INTEGER NOT NULL,
              chunk_index INTEGER NOT NULL,
              offset_ms INTEGER NOT NULL,
              chunk_body BLOB NOT NULL,
              PRIMARY KEY (recording_id, chunk_index),
              FOREIGN KEY (recording_id) REFERENCES recordings(id) ON DELETE CASCADE
            );

            CREATE INDEX recording_response_chunks_replay_idx
              ON recording_response_chunks(recording_id, chunk_index);

            CREATE TABLE recording_websocket_frames (
              recording_id INTEGER NOT NULL,
              frame_index INTEGER NOT NULL,
              direction TEXT NOT NULL CHECK(direction IN ('client-to-server', 'server-to-client')),
              message_type TEXT NOT NULL CHECK(message_type IN ('text', 'binary')),
              offset_ms INTEGER NOT NULL,
              payload BLOB NOT NULL,
              PRIMARY KEY (recording_id, frame_index),
              FOREIGN KEY (recording_id) REFERENCES recordings(id) ON DELETE CASCADE
            );

            CREATE INDEX recording_websocket_frames_replay_idx
              ON recording_websocket_frames(recording_id, frame_index);

            PRAGMA user_version = 5;
            "#,
        )
        .unwrap();

        let fingerprint_norm = matching::normalized_query_fingerprint(Some("a=1&b=2&c=3"));
        conn.execute(
            r#"
            INSERT INTO recordings (
              match_key,
              request_method,
              request_uri,
              request_query_norm,
              request_headers_json,
              request_body,
              response_status,
              response_headers_json,
              response_body,
              created_at_unix_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
            params![
                "legacy-v5-fingerprint",
                "GET",
                "/api?a=1&b=2&c=3",
                fingerprint_norm,
                r#"[["x-request","legacy"]]"#,
                Vec::<u8>::new(),
                200i64,
                r#"[["x-response","legacy"]]"#,
                b"body".to_vec(),
                Recording::now_unix_ms().unwrap(),
            ],
        )
        .unwrap();

        conn.execute(
            r#"
            INSERT INTO recordings (
              match_key,
              request_method,
              request_uri,
              request_query_norm,
              request_headers_json,
              request_body,
              response_status,
              response_headers_json,
              response_body,
              created_at_unix_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
            params![
                "legacy-v5-legacy",
                "GET",
                "/api?b=2&a=1",
                "b=2&a=1",
                r#"[["x-request","legacy"]]"#,
                Vec::<u8>::new(),
                200i64,
                r#"[["x-response","legacy"]]"#,
                b"body".to_vec(),
                Recording::now_unix_ms().unwrap(),
            ],
        )
        .unwrap();
        drop(conn);

        let storage = Storage::open(db_path).unwrap();
        let conn = rusqlite::Connection::open(storage.db_path()).unwrap();
        let user_version: i64 = conn
            .query_row("PRAGMA user_version;", [], |row| row.get(0))
            .unwrap();
        assert_eq!(user_version, 7);

        let fingerprint_count: i64 = conn
            .query_row(
                "SELECT request_query_param_count FROM recordings WHERE match_key = 'legacy-v5-fingerprint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(fingerprint_count, 3);

        let legacy_count: i64 = conn
            .query_row(
                "SELECT request_query_param_count FROM recordings WHERE match_key = 'legacy-v5-legacy'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(legacy_count, 2);

        let fingerprint_index_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM recording_query_param_index WHERE match_key = 'legacy-v5-fingerprint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(fingerprint_index_count, 3);

        let legacy_index_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM recording_query_param_index WHERE match_key = 'legacy-v5-legacy'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(legacy_index_count, 2);
    }

    #[tokio::test]
    async fn open_migrates_v6_schema_to_v7_query_param_index() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("recordings.db");
        let conn = rusqlite::Connection::open(&db_path).unwrap();

        conn.execute_batch(
            r#"
            CREATE TABLE recordings (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              match_key TEXT NOT NULL,
              request_method TEXT NOT NULL,
              request_uri TEXT NOT NULL,
              request_query_norm TEXT NOT NULL DEFAULT '',
              request_query_param_count INTEGER NOT NULL DEFAULT 0,
              request_headers_json TEXT NOT NULL,
              request_body BLOB NOT NULL,
              response_status INTEGER NOT NULL,
              response_headers_json TEXT NOT NULL,
              response_body BLOB NOT NULL,
              created_at_unix_ms INTEGER NOT NULL
            );

            CREATE INDEX recordings_match_key_idx ON recordings(match_key);
            CREATE INDEX recordings_match_key_query_norm_idx
              ON recordings(match_key, request_query_norm, id DESC);
            CREATE INDEX recordings_match_key_query_param_count_idx
              ON recordings(match_key, request_query_param_count, id DESC);

            CREATE TABLE recording_response_chunks (
              recording_id INTEGER NOT NULL,
              chunk_index INTEGER NOT NULL,
              offset_ms INTEGER NOT NULL,
              chunk_body BLOB NOT NULL,
              PRIMARY KEY (recording_id, chunk_index),
              FOREIGN KEY (recording_id) REFERENCES recordings(id) ON DELETE CASCADE
            );

            CREATE INDEX recording_response_chunks_replay_idx
              ON recording_response_chunks(recording_id, chunk_index);

            CREATE TABLE recording_websocket_frames (
              recording_id INTEGER NOT NULL,
              frame_index INTEGER NOT NULL,
              direction TEXT NOT NULL CHECK(direction IN ('client-to-server', 'server-to-client')),
              message_type TEXT NOT NULL CHECK(message_type IN ('text', 'binary')),
              offset_ms INTEGER NOT NULL,
              payload BLOB NOT NULL,
              PRIMARY KEY (recording_id, frame_index),
              FOREIGN KEY (recording_id) REFERENCES recordings(id) ON DELETE CASCADE
            );

            CREATE INDEX recording_websocket_frames_replay_idx
              ON recording_websocket_frames(recording_id, frame_index);

            PRAGMA user_version = 6;
            "#,
        )
        .unwrap();

        let query_norm = matching::normalized_query_fingerprint(Some("a=1&b=2"));
        conn.execute(
            r#"
            INSERT INTO recordings (
              match_key,
              request_method,
              request_uri,
              request_query_norm,
              request_query_param_count,
              request_headers_json,
              request_body,
              response_status,
              response_headers_json,
              response_body,
              created_at_unix_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            "#,
            params![
                "legacy-v6-key",
                "GET",
                "/api?a=1&b=2",
                query_norm,
                2i64,
                r#"[["x-request","legacy"]]"#,
                Vec::<u8>::new(),
                200i64,
                r#"[["x-response","legacy"]]"#,
                b"body".to_vec(),
                Recording::now_unix_ms().unwrap(),
            ],
        )
        .unwrap();
        drop(conn);

        let storage = Storage::open(db_path).unwrap();
        let conn = rusqlite::Connection::open(storage.db_path()).unwrap();
        let user_version: i64 = conn
            .query_row("PRAGMA user_version;", [], |row| row.get(0))
            .unwrap();
        assert_eq!(user_version, 7);

        let index_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM recording_query_param_index WHERE match_key = 'legacy-v6-key'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(index_rows, 2);
    }

    #[tokio::test]
    async fn session_manager_lists_create_and_delete_sessions() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manager = SessionManager::new(temp_dir.path().to_path_buf());

        assert_eq!(manager.list_sessions().await.unwrap(), Vec::<String>::new());

        manager.create_session("default").await.unwrap();
        manager.create_session("staging").await.unwrap();

        let mut sessions = manager.list_sessions().await.unwrap();
        sessions.sort();
        assert_eq!(sessions, vec!["default".to_owned(), "staging".to_owned()]);
        assert!(
            temp_dir
                .path()
                .join("staging")
                .join("recordings.db")
                .exists()
        );

        manager.delete_session("default").await.unwrap();
        let sessions = manager.list_sessions().await.unwrap();
        assert_eq!(sessions, vec!["staging".to_owned()]);
    }

    #[tokio::test]
    async fn session_manager_rejects_invalid_duplicate_and_missing_sessions() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manager = SessionManager::new(temp_dir.path().to_path_buf());

        let err = manager.create_session("..").await.unwrap_err();
        assert_eq!(
            err,
            SessionManagerError::InvalidName("session name cannot be `.` or `..`".to_owned())
        );

        manager.create_session("default").await.unwrap();
        let err = manager.create_session("default").await.unwrap_err();
        assert_eq!(
            err,
            SessionManagerError::AlreadyExists("default".to_owned())
        );

        let err = manager.delete_session("missing").await.unwrap_err();
        assert_eq!(err, SessionManagerError::NotFound("missing".to_owned()));
    }

    #[tokio::test]
    async fn session_manager_open_session_storage_requires_existing_session() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manager = SessionManager::new(temp_dir.path().to_path_buf());

        let err = manager.open_session_storage("missing").await.unwrap_err();
        assert_eq!(err, SessionManagerError::NotFound("missing".to_owned()));

        manager.create_session("default").await.unwrap();
        let storage = manager.open_session_storage("default").await.unwrap();
        assert!(storage.db_path().exists());
    }

    #[tokio::test]
    async fn session_manager_from_config_propagates_max_recordings() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = Config::from_toml_str(&format!(
            r#"
[proxy]
listen = "127.0.0.1:0"

[storage]
path = "{}"
max_recordings = 1
"#,
            temp_dir.path().display()
        ))
        .unwrap();

        let manager = SessionManager::from_config(&config).unwrap().unwrap();
        manager.create_session("default").await.unwrap();
        let storage = manager.open_session_storage("default").await.unwrap();

        let first = test_recording("/one", Recording::now_unix_ms().unwrap());
        let mut second = test_recording("/two", first.created_at_unix_ms + 1);
        second.match_key = "manager-retention-key".to_owned();

        storage.insert_recording(first).await.unwrap();
        storage.insert_recording(second).await.unwrap();

        let summaries = storage.list_recordings(0, 10).await.unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].request_uri, "/two");
    }
}
