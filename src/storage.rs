use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context as _;
use rusqlite::{Connection, OpenFlags, params, params_from_iter};
use serde::{Deserialize, Serialize};

use crate::{config::Config, matching};

const SCHEMA_VERSION: i32 = 2;
const SQLITE_MAX_BIND_PARAMS: usize = 999;
const QUERY_SUBSET_CHUNK_SIZE: usize = SQLITE_MAX_BIND_PARAMS - 1;

#[derive(Debug, Clone)]
pub struct Storage {
    db_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct SessionManager {
    base_path: PathBuf,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordingSummary {
    pub id: i64,
    pub match_key: String,
    pub request_method: String,
    pub request_uri: String,
    pub response_status: u16,
    pub created_at_unix_ms: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordingSearch {
    pub method: Option<String>,
    pub url_contains: Option<String>,
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
        let session = storage
            .active_session
            .as_deref()
            .unwrap_or("default")
            .to_owned();
        let db_path = storage.path.join(session).join("recordings.db");
        Ok(Some(Self::open(db_path)?))
    }

    pub fn open(db_path: PathBuf) -> anyhow::Result<Self> {
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create storage dir {}", parent.display()))?;
        }

        let storage = Self { db_path };
        storage.init()?;
        Ok(storage)
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub async fn insert_recording(&self, recording: Recording) -> anyhow::Result<i64> {
        let db_path = self.db_path.clone();
        tokio::task::spawn_blocking(move || insert_recording_blocking(&db_path, recording))
            .await
            .context("join insert_recording task")?
    }

    pub async fn get_recording_by_match_key(
        &self,
        match_key: &str,
    ) -> anyhow::Result<Option<Recording>> {
        let db_path = self.db_path.clone();
        let match_key = match_key.to_owned();
        tokio::task::spawn_blocking(move || {
            get_recording_by_match_key_blocking(&db_path, &match_key)
        })
        .await
        .context("join get_recording_by_match_key task")?
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

    pub async fn get_latest_recording_by_match_key_and_query_subset(
        &self,
        match_key: &str,
        subset_query_normalizations: Vec<String>,
    ) -> anyhow::Result<Option<Recording>> {
        let db_path = self.db_path.clone();
        let match_key = match_key.to_owned();
        tokio::task::spawn_blocking(move || {
            get_latest_recording_by_match_key_and_query_subset_blocking(
                &db_path,
                &match_key,
                &subset_query_normalizations,
            )
        })
        .await
        .context("join get_latest_recording_by_match_key_and_query_subset task")?
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

        Ok(Some(Self::new(storage.path.clone())))
    }

    pub fn new(base_path: PathBuf) -> Self {
        Self { base_path }
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
                "#,
            )
            .context("create sqlite schema v2")?;

            conn.pragma_update(None, "user_version", SCHEMA_VERSION)
                .context("set PRAGMA user_version=2")?;
            Ok(())
        }
        1 => migrate_v1_to_v2(conn),
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

    conn.pragma_update(None, "user_version", SCHEMA_VERSION)
        .context("set PRAGMA user_version=2")?;
    Ok(())
}

fn validate_session_name(name: &str) -> Result<(), SessionManagerError> {
    if name.trim().is_empty() {
        return Err(SessionManagerError::InvalidName(
            "session name cannot be empty".to_owned(),
        ));
    }
    if name != name.trim() {
        return Err(SessionManagerError::InvalidName(
            "session name cannot have leading or trailing whitespace".to_owned(),
        ));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(SessionManagerError::InvalidName(
            "session name cannot contain path separators".to_owned(),
        ));
    }
    if name == "." || name == ".." {
        return Err(SessionManagerError::InvalidName(
            "session name cannot be `.` or `..`".to_owned(),
        ));
    }

    Ok(())
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

        let session_dir = entry.path();
        let db_path = session_dir.join("recordings.db");
        if !db_path.exists() {
            continue;
        }

        let name = entry.file_name().to_string_lossy().into_owned();
        sessions.push(name);
    }

    sessions.sort();
    Ok(sessions)
}

fn create_session_blocking(base_path: &Path, name: &str) -> Result<(), SessionManagerError> {
    validate_session_name(name)?;

    fs::create_dir_all(base_path).map_err(|err| {
        SessionManagerError::Io(format!(
            "create sessions dir {}: {err}",
            base_path.display()
        ))
    })?;

    let session_dir = base_path.join(name);
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

    let db_path = session_dir.join("recordings.db");
    Storage::open(db_path).map_err(|err| {
        SessionManagerError::Internal(format!("initialize session `{name}`: {err}"))
    })?;
    Ok(())
}

fn delete_session_blocking(base_path: &Path, name: &str) -> Result<(), SessionManagerError> {
    validate_session_name(name)?;

    let session_dir = base_path.join(name);
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

fn insert_recording_blocking(path: &Path, recording: Recording) -> anyhow::Result<i64> {
    let conn = open_connection(path)?;
    let request_query_norm = normalized_query_from_request_uri(&recording.request_uri);
    let request_headers_json =
        serde_json::to_string(&recording.request_headers).context("serialize request headers")?;
    let response_headers_json =
        serde_json::to_string(&recording.response_headers).context("serialize response headers")?;

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
            recording.match_key,
            recording.request_method,
            recording.request_uri,
            request_query_norm,
            request_headers_json,
            recording.request_body,
            i64::from(recording.response_status),
            response_headers_json,
            recording.response_body,
            recording.created_at_unix_ms,
        ],
    )
    .context("insert recording")?;

    Ok(conn.last_insert_rowid())
}

fn recording_query_from_uri(uri: &str) -> Option<&str> {
    uri.split_once('?').map(|(_, query)| query)
}

fn normalized_query_from_request_uri(uri: &str) -> String {
    matching::normalized_query(recording_query_from_uri(uri))
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

fn get_recording_by_match_key_blocking(
    path: &Path,
    match_key: &str,
) -> anyhow::Result<Option<Recording>> {
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

    Ok(Some(deserialize_recording_at(row, 0)?))
}

fn get_latest_recording_by_match_key_and_query_subset_blocking(
    path: &Path,
    match_key: &str,
    subset_query_normalizations: &[String],
) -> anyhow::Result<Option<Recording>> {
    if subset_query_normalizations.is_empty() {
        return Ok(None);
    }

    let conn = open_connection(path)?;
    let mut latest: Option<(i64, Recording)> = None;

    for subset_chunk in subset_query_normalizations.chunks(QUERY_SUBSET_CHUNK_SIZE) {
        let maybe_row = get_latest_recording_for_subset_chunk(&conn, match_key, subset_chunk)?;
        if let Some((recording_id, recording)) = maybe_row {
            match latest.as_ref() {
                Some((latest_id, _)) if *latest_id >= recording_id => {}
                _ => latest = Some((recording_id, recording)),
            }
        }
    }

    Ok(latest.map(|(_, recording)| recording))
}

fn get_latest_recording_for_subset_chunk(
    conn: &Connection,
    match_key: &str,
    subset_chunk: &[String],
) -> anyhow::Result<Option<(i64, Recording)>> {
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

    let id = row
        .get::<_, i64>(0)
        .context("deserialize recording id for subset lookup")?;
    let recording = deserialize_recording_at(row, 1)?;
    Ok(Some((id, recording)))
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
            ORDER BY id DESC
            LIMIT ?3 OFFSET ?4
            "#,
        )
        .context("prepare search recordings")?;

    let mut rows = stmt
        .query(params![method, url_contains, limit, offset])
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

#[cfg(test)]
mod tests {
    use rusqlite::params;

    use super::{Recording, RecordingSearch, SessionManager, SessionManagerError, Storage};
    use crate::matching;

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

        let subset_query_norms =
            matching::subset_query_candidate_normalizations(Some("a=1&b=2&c=3"));
        let fetched = storage
            .get_latest_recording_by_match_key_and_query_subset("same-key", subset_query_norms)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(fetched.request_uri, "/api?a=1&b=2");
        assert_eq!(&fetched.response_body[..], b"newer-matching");
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
        let query_norm: String = conn
            .query_row(
                "SELECT request_query_norm FROM recordings WHERE match_key = 'legacy-key'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(query_norm, "a=1&b=2");

        let subset_query_norms =
            matching::subset_query_candidate_normalizations(Some("a=1&b=2&c=3"));
        let fetched = storage
            .get_latest_recording_by_match_key_and_query_subset("legacy-key", subset_query_norms)
            .await
            .unwrap();
        assert!(fetched.is_some());
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
}
