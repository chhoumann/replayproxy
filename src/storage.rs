use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context as _;
use rusqlite::{Connection, OpenFlags, params};
use serde::{Deserialize, Serialize};

use crate::config::Config;

const SCHEMA_VERSION: i32 = 1;

#[derive(Debug, Clone)]
pub struct Storage {
    db_path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Recording {
    pub match_key: String,
    pub request_method: String,
    pub request_uri: String,
    pub request_headers: Vec<(String, String)>,
    pub request_body: Vec<u8>,
    pub response_status: u16,
    pub response_headers: Vec<(String, String)>,
    pub response_body: Vec<u8>,
    pub created_at_unix_ms: i64,
}

impl Recording {
    pub fn now_unix_ms() -> anyhow::Result<i64> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time before unix epoch")?;
        Ok(i64::try_from(duration.as_millis()).unwrap_or(i64::MAX))
    }
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

    fn init(&self) -> anyhow::Result<()> {
        let conn = open_connection(&self.db_path)?;
        migrate(&conn)?;
        Ok(())
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

fn migrate(conn: &Connection) -> anyhow::Result<()> {
    let user_version: i32 = conn
        .query_row("PRAGMA user_version;", [], |row| row.get(0))
        .context("read PRAGMA user_version")?;

    if user_version == 0 {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS recordings (
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

            CREATE INDEX IF NOT EXISTS recordings_match_key_idx ON recordings(match_key);
            "#,
        )
        .context("create sqlite schema v1")?;

        conn.pragma_update(None, "user_version", SCHEMA_VERSION)
            .context("set PRAGMA user_version=1")?;
        return Ok(());
    }

    if user_version != SCHEMA_VERSION {
        anyhow::bail!(
            "unsupported recordings.db schema version {user_version} (expected {SCHEMA_VERSION})"
        );
    }

    Ok(())
}

fn insert_recording_blocking(path: &Path, recording: Recording) -> anyhow::Result<i64> {
    let conn = open_connection(path)?;
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
          request_headers_json,
          request_body,
          response_status,
          response_headers_json,
          response_body,
          created_at_unix_ms
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "#,
        params![
            recording.match_key,
            recording.request_method,
            recording.request_uri,
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
