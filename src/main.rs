use std::{
    fmt::Write as _,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::bail;
use bytes::Bytes;
use clap::{Parser, Subcommand};
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Uri};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use replayproxy::{
    config::{Config, RouteMode},
    logging, session,
    session_export::{self, SessionExportFormat, SessionExportRequest, SessionExportResult},
    session_import::{self, SessionImportRequest, SessionImportResult},
    storage::{RecordingSearch, RecordingSummary, SessionManager, Storage},
};
use serde::{Deserialize, Serialize};

const DEFAULT_RECORDING_PAGE_LIMIT: usize = 100;
const ADMIN_API_TOKEN_HEADER: &str = "x-replayproxy-admin-token";

#[derive(Debug, Parser)]
#[command(name = "replayproxy")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the proxy server.
    Serve {
        /// Optional path to config TOML. If omitted, default discovery is used.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Override the active storage session.
        #[arg(long)]
        active_session: Option<String>,
        /// Override log level (trace, debug, info, warn, error, off).
        #[arg(long)]
        log_level: Option<String>,
    },
    /// Manage storage sessions.
    Session {
        /// Optional path to config TOML. If omitted, default discovery is used.
        #[arg(long)]
        config: Option<PathBuf>,
        #[command(subcommand)]
        action: SessionCommand,
    },
    /// Manage stored recordings.
    Recording {
        /// Optional path to config TOML. If omitted, default discovery is used.
        #[arg(long)]
        config: Option<PathBuf>,
        #[command(subcommand)]
        action: RecordingCommand,
    },
    /// Show or change runtime proxy mode.
    Mode {
        /// Optional path to config TOML. If omitted, default discovery is used.
        #[arg(long)]
        config: Option<PathBuf>,
        #[command(subcommand)]
        action: ModeCommand,
    },
}

#[derive(Debug, Subcommand, Clone, PartialEq, Eq)]
enum SessionCommand {
    /// List available sessions.
    List,
    /// Create a new session.
    Create { name: String },
    /// Delete a session.
    Delete { name: String },
    /// Activate a session on a running proxy admin endpoint.
    Switch {
        name: String,
        /// Explicit admin listen address (`host:port`), required when config uses `admin_port = 0`.
        #[arg(long)]
        admin_addr: Option<SocketAddr>,
    },
    /// Export a session into JSON or YAML files.
    Export {
        name: String,
        /// Optional output directory. Must not already contain files.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Export format (`json` or `yaml`).
        #[arg(long, default_value_t = SessionExportFormat::Json)]
        format: SessionExportFormat,
    },
    /// Import recordings from exported files into an existing session.
    Import {
        name: String,
        /// Input directory containing `index.json` or `index.yaml` and `recordings/`.
        #[arg(long = "in")]
        input: PathBuf,
    },
}

#[derive(Debug, Subcommand, Clone, PartialEq, Eq)]
enum RecordingCommand {
    /// List recordings.
    List {
        /// Optional session to query. Defaults to active session from config.
        #[arg(long)]
        session: Option<String>,
        /// Pagination offset.
        #[arg(long, default_value_t = 0)]
        offset: usize,
        /// Pagination limit.
        #[arg(long, default_value_t = DEFAULT_RECORDING_PAGE_LIMIT)]
        limit: usize,
    },
    /// Search recordings by URL substring, optional leading HTTP method token, and body content.
    Search {
        /// Query text (examples: `/chat/completions`, `POST /chat`, `POST /chat body:gpt-4o`).
        query: String,
        /// Optional session to query. Defaults to active session from config.
        #[arg(long)]
        session: Option<String>,
        /// Pagination offset.
        #[arg(long, default_value_t = 0)]
        offset: usize,
        /// Pagination limit.
        #[arg(long, default_value_t = DEFAULT_RECORDING_PAGE_LIMIT)]
        limit: usize,
    },
    /// Delete a recording by id.
    Delete {
        id: i64,
        /// Optional session to query. Defaults to active session from config.
        #[arg(long)]
        session: Option<String>,
    },
}

#[derive(Debug, Subcommand, Clone, PartialEq, Eq)]
enum ModeCommand {
    /// Show current runtime/default mode from the running admin API.
    Show {
        /// Explicit admin listen address (`host:port`), required when config uses `admin_port = 0`.
        #[arg(long)]
        admin_addr: Option<SocketAddr>,
    },
    /// Set runtime mode on a running proxy process.
    Set {
        /// Mode value (`record`, `replay`, or `passthrough-cache`).
        mode: RouteMode,
        /// Explicit admin listen address (`host:port`), required when config uses `admin_port = 0`.
        #[arg(long)]
        admin_addr: Option<SocketAddr>,
        /// Persist `proxy.mode` back to the loaded config file.
        #[arg(long)]
        persist: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SessionCommandOutcome {
    Listed {
        sessions: Vec<String>,
        active_session: String,
    },
    Created {
        name: String,
    },
    Deleted {
        name: String,
    },
    Switched {
        name: String,
        admin_addr: SocketAddr,
    },
    Exported {
        result: SessionExportResult,
    },
    Imported {
        result: SessionImportResult,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RecordingCommandOutcome {
    Listed {
        session: String,
        recordings: Vec<RecordingSummary>,
    },
    Searched {
        session: String,
        recordings: Vec<RecordingSummary>,
    },
    Deleted {
        session: String,
        id: i64,
        deleted: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AdminModeState {
    runtime_override_mode: Option<RouteMode>,
    default_mode: RouteMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ModeCommandOutcome {
    Shown {
        admin_addr: SocketAddr,
        state: AdminModeState,
    },
    Set {
        admin_addr: SocketAddr,
        state: AdminModeState,
        persisted_path: Option<PathBuf>,
    },
}

fn require_session_manager(config: &Config) -> anyhow::Result<SessionManager> {
    SessionManager::from_config(config)?
        .ok_or_else(|| anyhow::anyhow!("storage not configured; set `[storage].path` in config"))
}

fn configured_active_session(config: &Config) -> String {
    config
        .storage
        .as_ref()
        .and_then(|storage| storage.active_session.as_deref())
        .unwrap_or(session::DEFAULT_SESSION_NAME)
        .to_owned()
}

fn resolve_admin_addr_for_command(
    config: &Config,
    admin_addr_override: Option<SocketAddr>,
    command_name: &str,
) -> anyhow::Result<SocketAddr> {
    if let Some(admin_addr) = admin_addr_override {
        return Ok(admin_addr);
    }

    let Some(admin_port) = config.proxy.admin_port else {
        bail!("`{command_name}` requires `proxy.admin_port` in config or `--admin-addr` override");
    };
    if admin_port == 0 {
        bail!(
            "`{command_name}` cannot infer admin port from `proxy.admin_port = 0`; pass `--admin-addr`"
        );
    }

    let admin_ip = config
        .proxy
        .admin_connect_ip()
        .expect("admin connect IP should exist when admin_port is configured");
    Ok(SocketAddr::new(admin_ip, admin_port))
}

fn resolve_admin_addr_for_switch(
    config: &Config,
    admin_addr_override: Option<SocketAddr>,
) -> anyhow::Result<SocketAddr> {
    resolve_admin_addr_for_command(config, admin_addr_override, "session switch")
}

fn resolve_admin_addr_for_mode(
    config: &Config,
    admin_addr_override: Option<SocketAddr>,
) -> anyhow::Result<SocketAddr> {
    resolve_admin_addr_for_command(config, admin_addr_override, "mode")
}

fn encode_uri_path_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            let _ = write!(&mut encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn extract_admin_error_message(response_body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(response_body).ok()?;
    value
        .get("error")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

fn admin_http_client() -> Client<HttpConnector, Full<Bytes>> {
    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    Client::builder(TokioExecutor::new()).build(connector)
}

#[derive(Debug, Deserialize)]
struct AdminModeApiResponse {
    runtime_override_mode: Option<RouteMode>,
    default_mode: RouteMode,
}

#[derive(Debug, Serialize)]
struct AdminSetModeApiRequest {
    mode: RouteMode,
}

async fn switch_session_via_admin(
    admin_addr: SocketAddr,
    session_name: &str,
    admin_api_token: Option<&str>,
) -> anyhow::Result<()> {
    let uri: Uri = format!(
        "http://{admin_addr}/_admin/sessions/{}/activate",
        encode_uri_path_segment(session_name)
    )
    .parse()
    .map_err(|err| anyhow::anyhow!("build admin activation URI: {err}"))?;

    let client = admin_http_client();

    let mut request_builder = Request::builder().method(Method::POST).uri(uri);
    if let Some(admin_api_token) = admin_api_token {
        request_builder = request_builder.header(ADMIN_API_TOKEN_HEADER, admin_api_token);
    }
    let request = request_builder
        .body(Full::new(Bytes::new()))
        .map_err(|err| anyhow::anyhow!("build admin activation request: {err}"))?;

    let response = client
        .request(request)
        .await
        .map_err(|err| anyhow::anyhow!("request admin activation endpoint: {err}"))?;
    let status = response.status();
    let response_body = response
        .into_body()
        .collect()
        .await
        .map_err(|err| anyhow::anyhow!("read admin activation response body: {err}"))?
        .to_bytes();
    if !status.is_success() {
        let message = extract_admin_error_message(&response_body)
            .unwrap_or_else(|| String::from_utf8_lossy(&response_body).into_owned());
        bail!(
            "activate session `{session_name}` failed via admin {admin_addr}: {status} {message}"
        );
    }

    Ok(())
}

async fn get_mode_via_admin(
    admin_addr: SocketAddr,
    admin_api_token: Option<&str>,
) -> anyhow::Result<AdminModeState> {
    let uri: Uri = format!("http://{admin_addr}/_admin/mode")
        .parse()
        .map_err(|err| anyhow::anyhow!("build admin mode URI: {err}"))?;
    let client = admin_http_client();

    let mut request_builder = Request::builder().method(Method::GET).uri(uri);
    if let Some(admin_api_token) = admin_api_token {
        request_builder = request_builder.header(ADMIN_API_TOKEN_HEADER, admin_api_token);
    }
    let request = request_builder
        .body(Full::new(Bytes::new()))
        .map_err(|err| anyhow::anyhow!("build admin mode request: {err}"))?;

    let response = client
        .request(request)
        .await
        .map_err(|err| anyhow::anyhow!("request admin mode endpoint: {err}"))?;
    let status = response.status();
    let response_body = response
        .into_body()
        .collect()
        .await
        .map_err(|err| anyhow::anyhow!("read admin mode response body: {err}"))?
        .to_bytes();
    if !status.is_success() {
        let message = extract_admin_error_message(&response_body)
            .unwrap_or_else(|| String::from_utf8_lossy(&response_body).into_owned());
        bail!("read mode failed via admin {admin_addr}: {status} {message}");
    }

    let body: AdminModeApiResponse = serde_json::from_slice(&response_body)
        .map_err(|err| anyhow::anyhow!("parse admin mode response JSON: {err}"))?;
    Ok(AdminModeState {
        runtime_override_mode: body.runtime_override_mode,
        default_mode: body.default_mode,
    })
}

async fn set_mode_via_admin(
    admin_addr: SocketAddr,
    mode: RouteMode,
    admin_api_token: Option<&str>,
) -> anyhow::Result<AdminModeState> {
    let uri: Uri = format!("http://{admin_addr}/_admin/mode")
        .parse()
        .map_err(|err| anyhow::anyhow!("build admin mode URI: {err}"))?;
    let client = admin_http_client();
    let request_body = serde_json::to_vec(&AdminSetModeApiRequest { mode })
        .map_err(|err| anyhow::anyhow!("serialize admin mode request JSON: {err}"))?;

    let mut request_builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(admin_api_token) = admin_api_token {
        request_builder = request_builder.header(ADMIN_API_TOKEN_HEADER, admin_api_token);
    }
    let request = request_builder
        .body(Full::new(Bytes::from(request_body)))
        .map_err(|err| anyhow::anyhow!("build admin mode request: {err}"))?;

    let response = client
        .request(request)
        .await
        .map_err(|err| anyhow::anyhow!("request admin mode endpoint: {err}"))?;
    let status = response.status();
    let response_body = response
        .into_body()
        .collect()
        .await
        .map_err(|err| anyhow::anyhow!("read admin mode response body: {err}"))?
        .to_bytes();
    if !status.is_success() {
        let message = extract_admin_error_message(&response_body)
            .unwrap_or_else(|| String::from_utf8_lossy(&response_body).into_owned());
        bail!("set mode to `{mode}` failed via admin {admin_addr}: {status} {message}");
    }

    let body: AdminModeApiResponse = serde_json::from_slice(&response_body)
        .map_err(|err| anyhow::anyhow!("parse admin mode response JSON: {err}"))?;
    Ok(AdminModeState {
        runtime_override_mode: body.runtime_override_mode,
        default_mode: body.default_mode,
    })
}

fn update_proxy_mode_in_toml(config_toml: &str, mode: RouteMode) -> anyhow::Result<String> {
    let mut config_value: toml::Value = toml::from_str(config_toml)
        .map_err(|err| anyhow::anyhow!("parse config TOML for mode persistence: {err}"))?;
    let root = config_value
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("config root must be a TOML table"))?;
    let proxy_value = root
        .entry("proxy")
        .or_insert_with(|| toml::Value::Table(Default::default()));
    let proxy_table = proxy_value
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("`proxy` must be a TOML table"))?;
    proxy_table.insert("mode".to_owned(), toml::Value::String(mode.to_string()));
    toml::to_string_pretty(&config_value)
        .map_err(|err| anyhow::anyhow!("serialize updated config TOML: {err}"))
}

fn write_file_atomically(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("config.toml");
    let temp_path = parent.join(format!(".{file_name}.tmp.{}", std::process::id()));

    fs::write(&temp_path, contents)
        .map_err(|err| anyhow::anyhow!("write temporary config {}: {err}", temp_path.display()))?;
    fs::rename(&temp_path, path).map_err(|err| {
        anyhow::anyhow!(
            "replace config {} with {}: {err}",
            path.display(),
            temp_path.display()
        )
    })?;
    Ok(())
}

fn persist_proxy_mode(config: &Config, mode: RouteMode) -> anyhow::Result<PathBuf> {
    let source_path = config.source_path().ok_or_else(|| {
        anyhow::anyhow!("`mode set --persist` requires a config file path (`--config`)")
    })?;
    let source_path = source_path.to_path_buf();
    let config_toml = fs::read_to_string(&source_path)
        .map_err(|err| anyhow::anyhow!("read config {}: {err}", source_path.display()))?;
    let updated_toml = update_proxy_mode_in_toml(&config_toml, mode)?;
    write_file_atomically(&source_path, updated_toml.as_bytes())?;
    Ok(source_path)
}

async fn run_session_command(
    config: &Config,
    command: SessionCommand,
) -> anyhow::Result<SessionCommandOutcome> {
    let session_manager = require_session_manager(config)?;

    match command {
        SessionCommand::List => {
            let sessions = session_manager
                .list_sessions()
                .await
                .map_err(|err| anyhow::anyhow!("{err}"))?;
            Ok(SessionCommandOutcome::Listed {
                sessions,
                active_session: configured_active_session(config),
            })
        }
        SessionCommand::Create { name } => {
            session_manager
                .create_session(&name)
                .await
                .map_err(|err| anyhow::anyhow!("{err}"))?;
            Ok(SessionCommandOutcome::Created { name })
        }
        SessionCommand::Delete { name } => {
            let active_session = configured_active_session(config);
            if name == active_session {
                bail!("cannot delete active session `{name}`");
            }
            session_manager
                .delete_session(&name)
                .await
                .map_err(|err| anyhow::anyhow!("{err}"))?;
            Ok(SessionCommandOutcome::Deleted { name })
        }
        SessionCommand::Switch { name, admin_addr } => {
            session_manager
                .open_session_storage(&name)
                .await
                .map_err(|err| anyhow::anyhow!("{err}"))?;
            let admin_addr = resolve_admin_addr_for_switch(config, admin_addr)?;
            switch_session_via_admin(admin_addr, &name, config.proxy.admin_api_token.as_deref())
                .await?;
            Ok(SessionCommandOutcome::Switched { name, admin_addr })
        }
        SessionCommand::Export { name, out, format } => {
            let result = session_export::export_session(
                &session_manager,
                SessionExportRequest {
                    session_name: name,
                    out_dir: out,
                    format,
                },
            )
            .await
            .map_err(|err| anyhow::anyhow!("{err}"))?;
            Ok(SessionCommandOutcome::Exported { result })
        }
        SessionCommand::Import { name, input } => {
            let result = session_import::import_session(
                &session_manager,
                SessionImportRequest {
                    session_name: name,
                    in_dir: input,
                },
            )
            .await
            .map_err(|err| anyhow::anyhow!("{err}"))?;
            Ok(SessionCommandOutcome::Imported { result })
        }
    }
}

async fn resolve_recording_storage(
    config: &Config,
    session_override: Option<&str>,
) -> anyhow::Result<(String, Storage)> {
    if let Some(session_name) = session_override {
        let session_manager = require_session_manager(config)?;
        let storage = session_manager
            .open_session_storage(session_name)
            .await
            .map_err(|err| anyhow::anyhow!("{err}"))?;
        return Ok((session_name.to_owned(), storage));
    }

    let storage = Storage::from_config(config)?
        .ok_or_else(|| anyhow::anyhow!("storage not configured; set `[storage].path` in config"))?;
    Ok((configured_active_session(config), storage))
}

fn is_http_method_token(value: &str) -> bool {
    matches!(
        value.to_ascii_uppercase().as_str(),
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "TRACE" | "CONNECT"
    )
}

fn parse_recording_body_filter(query: &str) -> anyhow::Result<(Option<String>, Option<String>)> {
    const BODY_FILTER_PREFIX: &str = "body:";

    let body_filter_start = if query.starts_with(BODY_FILTER_PREFIX) {
        Some(0)
    } else {
        query.find(" body:").map(|idx| idx + 1)
    };

    let Some(body_filter_start) = body_filter_start else {
        return Ok(((!query.is_empty()).then_some(query.to_owned()), None));
    };

    let url_contains = query[..body_filter_start].trim();
    let body_contains = query[(body_filter_start + BODY_FILTER_PREFIX.len())..].trim();
    if body_contains.is_empty() {
        bail!("body filter cannot be empty; use `body:<text>`");
    }

    Ok((
        (!url_contains.is_empty()).then_some(url_contains.to_owned()),
        Some(body_contains.to_owned()),
    ))
}

fn parse_recording_search_query(query: &str) -> anyhow::Result<RecordingSearch> {
    let query = query.trim();
    if query.is_empty() {
        bail!("search query cannot be empty");
    }

    let first_token_end = query.find(char::is_whitespace).unwrap_or(query.len());
    let first_token = &query[..first_token_end];
    if is_http_method_token(first_token) {
        let remaining = query[first_token_end..].trim_start();
        let (url_contains, body_contains) = parse_recording_body_filter(remaining)?;
        return Ok(RecordingSearch {
            method: Some(first_token.to_ascii_uppercase()),
            url_contains,
            body_contains,
        });
    }

    let (url_contains, body_contains) = parse_recording_body_filter(query)?;
    Ok(RecordingSearch {
        method: None,
        url_contains,
        body_contains,
    })
}

async fn run_recording_command(
    config: &Config,
    command: RecordingCommand,
) -> anyhow::Result<RecordingCommandOutcome> {
    match command {
        RecordingCommand::List {
            session,
            offset,
            limit,
        } => {
            let (session, storage) = resolve_recording_storage(config, session.as_deref()).await?;
            let recordings = storage.list_recordings(offset, limit).await?;
            Ok(RecordingCommandOutcome::Listed {
                session,
                recordings,
            })
        }
        RecordingCommand::Search {
            query,
            session,
            offset,
            limit,
        } => {
            let (session, storage) = resolve_recording_storage(config, session.as_deref()).await?;
            let search = parse_recording_search_query(&query)?;
            let recordings = storage.search_recordings(search, offset, limit).await?;
            Ok(RecordingCommandOutcome::Searched {
                session,
                recordings,
            })
        }
        RecordingCommand::Delete { id, session } => {
            let (session, storage) = resolve_recording_storage(config, session.as_deref()).await?;
            let deleted = storage.delete_recording(id).await?;
            Ok(RecordingCommandOutcome::Deleted {
                session,
                id,
                deleted,
            })
        }
    }
}

async fn run_mode_command(
    config: &Config,
    command: ModeCommand,
) -> anyhow::Result<ModeCommandOutcome> {
    match command {
        ModeCommand::Show { admin_addr } => {
            let admin_addr = resolve_admin_addr_for_mode(config, admin_addr)?;
            let state =
                get_mode_via_admin(admin_addr, config.proxy.admin_api_token.as_deref()).await?;
            Ok(ModeCommandOutcome::Shown { admin_addr, state })
        }
        ModeCommand::Set {
            mode,
            admin_addr,
            persist,
        } => {
            let admin_addr = resolve_admin_addr_for_mode(config, admin_addr)?;
            let state =
                set_mode_via_admin(admin_addr, mode, config.proxy.admin_api_token.as_deref())
                    .await?;
            let persisted_path = if persist {
                Some(persist_proxy_mode(config, mode).map_err(|err| {
                    anyhow::anyhow!(
                        "set runtime mode via admin {admin_addr}, but failed to persist config: {err}"
                    )
                })?)
            } else {
                None
            };
            Ok(ModeCommandOutcome::Set {
                admin_addr,
                state,
                persisted_path,
            })
        }
    }
}

fn print_session_command_outcome(outcome: SessionCommandOutcome) {
    match outcome {
        SessionCommandOutcome::Listed {
            sessions,
            active_session,
        } => {
            for session in sessions {
                if session == active_session {
                    println!("{session} (active)");
                } else {
                    println!("{session}");
                }
            }
        }
        SessionCommandOutcome::Created { name } => {
            println!("created session `{name}`");
        }
        SessionCommandOutcome::Deleted { name } => {
            println!("deleted session `{name}`");
        }
        SessionCommandOutcome::Switched { name, admin_addr } => {
            println!("switched active session to `{name}` via admin {admin_addr}");
        }
        SessionCommandOutcome::Exported { result } => {
            println!(
                "exported session `{}`: {} recordings to {}",
                result.session,
                result.recordings_exported,
                result.output_dir.display()
            );
        }
        SessionCommandOutcome::Imported { result } => {
            println!(
                "imported session `{}`: {} recordings from {}",
                result.session,
                result.recordings_imported,
                result.input_dir.display()
            );
        }
    }
}

fn print_mode_command_outcome(outcome: ModeCommandOutcome) {
    match outcome {
        ModeCommandOutcome::Shown { admin_addr, state } => {
            if let Some(runtime_override_mode) = state.runtime_override_mode {
                println!("runtime mode override via admin {admin_addr}: `{runtime_override_mode}`");
            } else {
                println!(
                    "no runtime mode override via admin {admin_addr}; default mode is `{}`",
                    state.default_mode
                );
            }
        }
        ModeCommandOutcome::Set {
            admin_addr,
            state,
            persisted_path,
        } => {
            let current_mode = state.runtime_override_mode.unwrap_or(state.default_mode);
            println!("set runtime mode override via admin {admin_addr}: `{current_mode}`");
            if let Some(persisted_path) = persisted_path {
                println!(
                    "persisted `proxy.mode = \"{current_mode}\"` to {}",
                    persisted_path.display()
                );
            }
        }
    }
}

fn print_recording_summaries(recordings: &[RecordingSummary]) {
    println!("id\tmethod\tstatus\turi\tcreated_at_unix_ms");
    for recording in recordings {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            recording.id,
            recording.request_method,
            recording.response_status,
            recording.request_uri,
            recording.created_at_unix_ms
        );
    }
}

fn print_recording_command_outcome(outcome: RecordingCommandOutcome) {
    match outcome {
        RecordingCommandOutcome::Listed {
            session,
            recordings,
        }
        | RecordingCommandOutcome::Searched {
            session,
            recordings,
        } => {
            if recordings.is_empty() {
                println!("no recordings found in session `{session}`");
                return;
            }
            println!("session `{session}`");
            print_recording_summaries(&recordings);
        }
        RecordingCommandOutcome::Deleted {
            session,
            id,
            deleted,
        } => {
            if deleted {
                println!("deleted recording `{id}` in session `{session}`");
            } else {
                println!("recording `{id}` not found in session `{session}`");
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Serve {
            config,
            active_session,
            log_level,
        } => {
            let mut config = Config::load(config.as_deref())?;
            config.apply_active_session_override(active_session.as_deref())?;
            logging::init(&config, log_level.as_deref())?;
            let proxy = replayproxy::proxy::serve(&config).await?;
            eprintln!(
                "{}",
                startup_summary(&config, proxy.listen_addr, proxy.admin_listen_addr)
            );
            tokio::signal::ctrl_c().await?;
            proxy.shutdown().await;
        }
        Command::Session { config, action } => {
            let config = Config::load(config.as_deref())?;
            let outcome = run_session_command(&config, action).await?;
            print_session_command_outcome(outcome);
        }
        Command::Recording { config, action } => {
            let config = Config::load(config.as_deref())?;
            let outcome = run_recording_command(&config, action).await?;
            print_recording_command_outcome(outcome);
        }
        Command::Mode { config, action } => {
            let config = Config::load(config.as_deref())?;
            let outcome = run_mode_command(&config, action).await?;
            print_mode_command_outcome(outcome);
        }
    }

    Ok(())
}

fn startup_summary(
    config: &Config,
    proxy_listen_addr: std::net::SocketAddr,
    admin_listen_addr: Option<std::net::SocketAddr>,
) -> String {
    let (storage_path, active_session) = match config.storage.as_ref() {
        Some(storage) => (
            redact_if_present(Some(&storage.path)),
            redact_active_session(storage.active_session.as_deref()),
        ),
        None => ("disabled", "disabled"),
    };
    let tls_summary = match config.proxy.tls.as_ref() {
        Some(tls) => format!(
            "enabled={},ca_cert={},ca_key={}",
            tls.enabled,
            redact_if_present(tls.ca_cert.as_ref()),
            redact_if_present(tls.ca_key.as_ref())
        ),
        None => "disabled".to_owned(),
    };
    let admin_listen_addr = admin_listen_addr
        .map(|addr| addr.to_string())
        .unwrap_or_else(|| "disabled".to_owned());

    format!(
        "startup config: proxy_listen={}, admin_listen={}, routes={}, storage_path={}, active_session={}, tls={}",
        proxy_listen_addr,
        admin_listen_addr,
        config.routes.len(),
        storage_path,
        active_session,
        tls_summary
    )
}

fn redact_if_present<T>(value: Option<T>) -> &'static str {
    if value.is_some() {
        "[REDACTED]"
    } else {
        "none"
    }
}

fn redact_active_session(value: Option<&str>) -> &'static str {
    if value.is_some() {
        "[REDACTED]"
    } else {
        "default"
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use super::{
        Cli, Command, ModeCommand, ModeCommandOutcome, RecordingCommand, RecordingCommandOutcome,
        SessionCommand, SessionCommandOutcome, encode_uri_path_segment,
        parse_recording_search_query, redact_active_session, redact_if_present,
        resolve_admin_addr_for_mode, resolve_admin_addr_for_switch, run_mode_command,
        run_recording_command, run_session_command, startup_summary, update_proxy_mode_in_toml,
    };
    use clap::Parser;
    use replayproxy::{
        config::{Config, RouteMode},
        session_export::SessionExportFormat,
        storage::{Recording, RecordingSearch, SessionManager, Storage},
    };
    use tempfile::tempdir;

    fn config_with_storage(base_path: &Path, active_session: Option<&str>) -> Config {
        let active_session_line = active_session
            .map(|name| format!("active_session = \"{name}\""))
            .unwrap_or_default();
        Config::from_toml_str(&format!(
            r#"
[proxy]
listen = "127.0.0.1:8080"

[storage]
path = "{}"
{active_session_line}
"#,
            base_path.display()
        ))
        .expect("config should parse")
    }

    fn config_without_storage() -> Config {
        Config::from_toml_str(
            r#"
[proxy]
listen = "127.0.0.1:8080"
"#,
        )
        .expect("config should parse")
    }

    fn config_with_ephemeral_admin(base_path: &Path, active_session: &str) -> Config {
        Config::from_toml_str(&format!(
            r#"
[proxy]
listen = "127.0.0.1:0"
admin_port = 0

[storage]
path = "{}"
active_session = "{active_session}"
"#,
            base_path.display()
        ))
        .expect("config should parse")
    }

    fn config_with_ephemeral_admin_mode(
        base_path: &Path,
        active_session: &str,
        mode: RouteMode,
    ) -> Config {
        Config::from_toml_str(&format!(
            r#"
[proxy]
listen = "127.0.0.1:0"
admin_port = 0
mode = "{mode}"

[storage]
path = "{}"
active_session = "{active_session}"
"#,
            base_path.display()
        ))
        .expect("config should parse")
    }

    fn config_with_ephemeral_admin_token(base_path: &Path, active_session: &str) -> Config {
        Config::from_toml_str(&format!(
            r#"
[proxy]
listen = "127.0.0.1:0"
admin_port = 0
admin_api_token = "super-secret"

[storage]
path = "{}"
active_session = "{active_session}"
"#,
            base_path.display()
        ))
        .expect("config should parse")
    }

    fn recording_fixture(
        match_key: &str,
        method: &str,
        uri: &str,
        created_at_unix_ms: i64,
    ) -> Recording {
        Recording {
            match_key: match_key.to_owned(),
            request_method: method.to_owned(),
            request_uri: uri.to_owned(),
            request_headers: Vec::new(),
            request_body: Vec::new(),
            response_status: 200,
            response_headers: Vec::new(),
            response_body: format!("response:{uri}").into_bytes(),
            created_at_unix_ms,
        }
    }

    #[test]
    fn serve_parses_without_config_flag() {
        let cli = Cli::try_parse_from(["replayproxy", "serve"]).expect("cli parse should succeed");
        let (config, active_session, log_level) = match cli.command {
            Command::Serve {
                config,
                active_session,
                log_level,
            } => (config, active_session, log_level),
            other => panic!("expected serve command, got {other:?}"),
        };
        assert_eq!(config, None);
        assert_eq!(active_session, None);
        assert_eq!(log_level, None);
    }

    #[test]
    fn serve_parses_with_config_flag() {
        let cli = Cli::try_parse_from(["replayproxy", "serve", "--config", "custom.toml"])
            .expect("cli parse should succeed");
        let (config, active_session, log_level) = match cli.command {
            Command::Serve {
                config,
                active_session,
                log_level,
            } => (config, active_session, log_level),
            other => panic!("expected serve command, got {other:?}"),
        };
        assert_eq!(config, Some(PathBuf::from("custom.toml")));
        assert_eq!(active_session, None);
        assert_eq!(log_level, None);
    }

    #[test]
    fn serve_parses_with_active_session_flag() {
        let cli = Cli::try_parse_from(["replayproxy", "serve", "--active-session", "staging"])
            .expect("cli parse should succeed");
        let (config, active_session, log_level) = match cli.command {
            Command::Serve {
                config,
                active_session,
                log_level,
            } => (config, active_session, log_level),
            other => panic!("expected serve command, got {other:?}"),
        };
        assert_eq!(config, None);
        assert_eq!(active_session.as_deref(), Some("staging"));
        assert_eq!(log_level, None);
    }

    #[test]
    fn serve_parses_with_config_and_active_session_flags() {
        let cli = Cli::try_parse_from([
            "replayproxy",
            "serve",
            "--config",
            "custom.toml",
            "--active-session",
            "staging",
        ])
        .expect("cli parse should succeed");
        let (config, active_session, log_level) = match cli.command {
            Command::Serve {
                config,
                active_session,
                log_level,
            } => (config, active_session, log_level),
            other => panic!("expected serve command, got {other:?}"),
        };
        assert_eq!(config, Some(PathBuf::from("custom.toml")));
        assert_eq!(active_session.as_deref(), Some("staging"));
        assert_eq!(log_level, None);
    }

    #[test]
    fn serve_parses_with_log_level_flag() {
        let cli = Cli::try_parse_from(["replayproxy", "serve", "--log-level", "debug"])
            .expect("cli parse should succeed");
        let (config, active_session, log_level) = match cli.command {
            Command::Serve {
                config,
                active_session,
                log_level,
            } => (config, active_session, log_level),
            other => panic!("expected serve command, got {other:?}"),
        };
        assert_eq!(config, None);
        assert_eq!(active_session, None);
        assert_eq!(log_level.as_deref(), Some("debug"));
    }

    #[test]
    fn session_list_parses_without_config_flag() {
        let cli =
            Cli::try_parse_from(["replayproxy", "session", "list"]).expect("cli parse should work");
        let (config, action) = match cli.command {
            Command::Session { config, action } => (config, action),
            other => panic!("expected session command, got {other:?}"),
        };
        assert_eq!(config, None);
        assert_eq!(action, SessionCommand::List);
    }

    #[test]
    fn session_create_parses_with_config_flag() {
        let cli = Cli::try_parse_from([
            "replayproxy",
            "session",
            "--config",
            "custom.toml",
            "create",
            "staging",
        ])
        .expect("cli parse should work");
        let (config, action) = match cli.command {
            Command::Session { config, action } => (config, action),
            other => panic!("expected session command, got {other:?}"),
        };
        assert_eq!(config, Some(PathBuf::from("custom.toml")));
        assert_eq!(
            action,
            SessionCommand::Create {
                name: "staging".to_owned()
            }
        );
    }

    #[test]
    fn session_delete_parses() {
        let cli = Cli::try_parse_from(["replayproxy", "session", "delete", "staging"])
            .expect("cli parse should work");
        let (config, action) = match cli.command {
            Command::Session { config, action } => (config, action),
            other => panic!("expected session command, got {other:?}"),
        };
        assert_eq!(config, None);
        assert_eq!(
            action,
            SessionCommand::Delete {
                name: "staging".to_owned()
            }
        );
    }

    #[test]
    fn session_switch_parses_with_admin_addr_flag() {
        let cli = Cli::try_parse_from([
            "replayproxy",
            "session",
            "switch",
            "staging",
            "--admin-addr",
            "127.0.0.1:9090",
        ])
        .expect("cli parse should work");
        let (config, action) = match cli.command {
            Command::Session { config, action } => (config, action),
            other => panic!("expected session command, got {other:?}"),
        };
        assert_eq!(config, None);
        assert_eq!(
            action,
            SessionCommand::Switch {
                name: "staging".to_owned(),
                admin_addr: Some("127.0.0.1:9090".parse().unwrap())
            }
        );
    }

    #[test]
    fn session_switch_infers_loopback_for_unspecified_admin_bind() {
        let config = Config::from_toml_str(
            r#"
[proxy]
listen = "0.0.0.0:8080"
admin_port = 9090
admin_bind = "0.0.0.0"
"#,
        )
        .expect("config should parse");

        let inferred =
            resolve_admin_addr_for_switch(&config, None).expect("admin addr should infer");
        assert_eq!(inferred, "127.0.0.1:9090".parse().unwrap());
    }

    #[test]
    fn session_switch_infers_explicit_admin_bind_ip() {
        let config = Config::from_toml_str(
            r#"
[proxy]
listen = "0.0.0.0:8080"
admin_port = 9090
admin_bind = "127.0.0.2"
"#,
        )
        .expect("config should parse");

        let inferred =
            resolve_admin_addr_for_switch(&config, None).expect("admin addr should infer");
        assert_eq!(inferred, "127.0.0.2:9090".parse().unwrap());
    }

    #[test]
    fn mode_show_parses_with_config_and_admin_addr() {
        let cli = Cli::try_parse_from([
            "replayproxy",
            "mode",
            "--config",
            "custom.toml",
            "show",
            "--admin-addr",
            "127.0.0.1:9090",
        ])
        .expect("cli parse should work");
        let (config, action) = match cli.command {
            Command::Mode { config, action } => (config, action),
            other => panic!("expected mode command, got {other:?}"),
        };
        assert_eq!(config, Some(PathBuf::from("custom.toml")));
        assert_eq!(
            action,
            ModeCommand::Show {
                admin_addr: Some("127.0.0.1:9090".parse().unwrap()),
            }
        );
    }

    #[test]
    fn mode_set_parses_with_persist_flag() {
        let cli = Cli::try_parse_from([
            "replayproxy",
            "mode",
            "set",
            "replay",
            "--persist",
            "--admin-addr",
            "127.0.0.1:9090",
        ])
        .expect("cli parse should work");
        let (config, action) = match cli.command {
            Command::Mode { config, action } => (config, action),
            other => panic!("expected mode command, got {other:?}"),
        };
        assert_eq!(config, None);
        assert_eq!(
            action,
            ModeCommand::Set {
                mode: RouteMode::Replay,
                admin_addr: Some("127.0.0.1:9090".parse().unwrap()),
                persist: true,
            }
        );
    }

    #[test]
    fn mode_resolve_infers_loopback_for_unspecified_admin_bind() {
        let config = Config::from_toml_str(
            r#"
[proxy]
listen = "0.0.0.0:8080"
admin_port = 9090
admin_bind = "0.0.0.0"
"#,
        )
        .expect("config should parse");

        let inferred = resolve_admin_addr_for_mode(&config, None).expect("admin addr should infer");
        assert_eq!(inferred, "127.0.0.1:9090".parse().unwrap());
    }

    #[test]
    fn update_proxy_mode_in_toml_updates_existing_mode() {
        let updated = update_proxy_mode_in_toml(
            r#"
[proxy]
listen = "127.0.0.1:8080"
mode = "record"
"#,
            RouteMode::Replay,
        )
        .expect("mode update should succeed");
        assert!(
            updated.contains("mode = \"replay\""),
            "updated config: {updated}"
        );
    }

    #[test]
    fn update_proxy_mode_in_toml_inserts_missing_mode() {
        let updated = update_proxy_mode_in_toml(
            r#"
[proxy]
listen = "127.0.0.1:8080"
"#,
            RouteMode::PassthroughCache,
        )
        .expect("mode update should succeed");
        assert!(
            updated.contains("mode = \"passthrough-cache\""),
            "updated config: {updated}"
        );
    }

    #[test]
    fn session_export_parses_with_out_flag() {
        let cli = Cli::try_parse_from([
            "replayproxy",
            "session",
            "--config",
            "custom.toml",
            "export",
            "staging",
            "--out",
            "./exports/staging",
        ])
        .expect("cli parse should work");
        let (config, action) = match cli.command {
            Command::Session { config, action } => (config, action),
            other => panic!("expected session command, got {other:?}"),
        };
        assert_eq!(config, Some(PathBuf::from("custom.toml")));
        assert_eq!(
            action,
            SessionCommand::Export {
                name: "staging".to_owned(),
                out: Some(PathBuf::from("./exports/staging")),
                format: SessionExportFormat::Json,
            }
        );
    }

    #[test]
    fn session_export_parses_with_yaml_format() {
        let cli = Cli::try_parse_from([
            "replayproxy",
            "session",
            "export",
            "staging",
            "--format",
            "yaml",
        ])
        .expect("cli parse should work");
        let (_, action) = match cli.command {
            Command::Session { config, action } => (config, action),
            other => panic!("expected session command, got {other:?}"),
        };
        assert_eq!(
            action,
            SessionCommand::Export {
                name: "staging".to_owned(),
                out: None,
                format: SessionExportFormat::Yaml,
            }
        );
    }

    #[test]
    fn session_import_parses_with_in_flag() {
        let cli = Cli::try_parse_from([
            "replayproxy",
            "session",
            "--config",
            "custom.toml",
            "import",
            "staging",
            "--in",
            "./exports/staging",
        ])
        .expect("cli parse should work");
        let (config, action) = match cli.command {
            Command::Session { config, action } => (config, action),
            other => panic!("expected session command, got {other:?}"),
        };
        assert_eq!(config, Some(PathBuf::from("custom.toml")));
        assert_eq!(
            action,
            SessionCommand::Import {
                name: "staging".to_owned(),
                input: PathBuf::from("./exports/staging"),
            }
        );
    }

    #[test]
    fn recording_list_parses_with_session_and_pagination_flags() {
        let cli = Cli::try_parse_from([
            "replayproxy",
            "recording",
            "--config",
            "custom.toml",
            "list",
            "--session",
            "staging",
            "--offset",
            "10",
            "--limit",
            "25",
        ])
        .expect("cli parse should work");
        let (config, action) = match cli.command {
            Command::Recording { config, action } => (config, action),
            other => panic!("expected recording command, got {other:?}"),
        };
        assert_eq!(config, Some(PathBuf::from("custom.toml")));
        assert_eq!(
            action,
            RecordingCommand::List {
                session: Some("staging".to_owned()),
                offset: 10,
                limit: 25,
            }
        );
    }

    #[test]
    fn recording_search_parses_query_and_optional_session() {
        let cli = Cli::try_parse_from([
            "replayproxy",
            "recording",
            "search",
            "POST /chat/completions",
            "--session",
            "default",
        ])
        .expect("cli parse should work");
        let (config, action) = match cli.command {
            Command::Recording { config, action } => (config, action),
            other => panic!("expected recording command, got {other:?}"),
        };
        assert_eq!(config, None);
        assert_eq!(
            action,
            RecordingCommand::Search {
                query: "POST /chat/completions".to_owned(),
                session: Some("default".to_owned()),
                offset: 0,
                limit: 100,
            }
        );
    }

    #[test]
    fn recording_delete_parses() {
        let cli = Cli::try_parse_from([
            "replayproxy",
            "recording",
            "delete",
            "42",
            "--session",
            "staging",
        ])
        .expect("cli parse should work");
        let (config, action) = match cli.command {
            Command::Recording { config, action } => (config, action),
            other => panic!("expected recording command, got {other:?}"),
        };
        assert_eq!(config, None);
        assert_eq!(
            action,
            RecordingCommand::Delete {
                id: 42,
                session: Some("staging".to_owned()),
            }
        );
    }

    #[test]
    fn recording_search_query_parser_supports_body_filter_syntax() {
        assert_eq!(
            parse_recording_search_query("POST /chat body:gpt-4o-mini").unwrap(),
            RecordingSearch {
                method: Some("POST".to_owned()),
                url_contains: Some("/chat".to_owned()),
                body_contains: Some("gpt-4o-mini".to_owned()),
            }
        );

        assert_eq!(
            parse_recording_search_query("body:assistant response text").unwrap(),
            RecordingSearch {
                method: None,
                url_contains: None,
                body_contains: Some("assistant response text".to_owned()),
            }
        );

        assert_eq!(
            parse_recording_search_query("GET").unwrap(),
            RecordingSearch {
                method: Some("GET".to_owned()),
                url_contains: None,
                body_contains: None,
            }
        );
    }

    #[test]
    fn recording_search_query_parser_rejects_empty_body_filter() {
        let err = parse_recording_search_query("POST /chat body:")
            .expect_err("empty body filter should fail");
        assert!(
            err.to_string()
                .contains("body filter cannot be empty; use `body:<text>`"),
            "error: {err}"
        );
    }

    #[tokio::test]
    async fn session_create_list_delete_round_trip() {
        let temp_dir = tempdir().expect("tempdir should be created");
        let config = config_with_storage(temp_dir.path(), Some("default"));

        let listed = run_session_command(&config, SessionCommand::List)
            .await
            .expect("session list should succeed");
        assert_eq!(
            listed,
            SessionCommandOutcome::Listed {
                sessions: Vec::new(),
                active_session: "default".to_owned()
            }
        );

        let created = run_session_command(
            &config,
            SessionCommand::Create {
                name: "staging".to_owned(),
            },
        )
        .await
        .expect("session create should succeed");
        assert_eq!(
            created,
            SessionCommandOutcome::Created {
                name: "staging".to_owned()
            }
        );

        let listed = run_session_command(&config, SessionCommand::List)
            .await
            .expect("session list should succeed");
        assert_eq!(
            listed,
            SessionCommandOutcome::Listed {
                sessions: vec!["staging".to_owned()],
                active_session: "default".to_owned()
            }
        );

        let deleted = run_session_command(
            &config,
            SessionCommand::Delete {
                name: "staging".to_owned(),
            },
        )
        .await
        .expect("session delete should succeed");
        assert_eq!(
            deleted,
            SessionCommandOutcome::Deleted {
                name: "staging".to_owned()
            }
        );
    }

    #[tokio::test]
    async fn session_switch_activates_session_via_admin_endpoint() {
        let temp_dir = tempdir().expect("tempdir should be created");
        let config = config_with_ephemeral_admin(temp_dir.path(), "default");
        run_session_command(
            &config,
            SessionCommand::Create {
                name: "default".to_owned(),
            },
        )
        .await
        .expect("session create should succeed");
        run_session_command(
            &config,
            SessionCommand::Create {
                name: "staging".to_owned(),
            },
        )
        .await
        .expect("session create should succeed");

        let proxy = replayproxy::proxy::serve(&config)
            .await
            .expect("proxy should start");
        let admin_addr = proxy
            .admin_listen_addr
            .expect("admin listener should be running");

        let switched = run_session_command(
            &config,
            SessionCommand::Switch {
                name: "staging".to_owned(),
                admin_addr: Some(admin_addr),
            },
        )
        .await
        .expect("session switch should succeed");
        assert_eq!(
            switched,
            SessionCommandOutcome::Switched {
                name: "staging".to_owned(),
                admin_addr,
            }
        );

        proxy.shutdown().await;
    }

    #[tokio::test]
    async fn session_switch_uses_admin_api_token_from_config() {
        let temp_dir = tempdir().expect("tempdir should be created");
        let config = config_with_ephemeral_admin_token(temp_dir.path(), "default");
        run_session_command(
            &config,
            SessionCommand::Create {
                name: "default".to_owned(),
            },
        )
        .await
        .expect("session create should succeed");
        run_session_command(
            &config,
            SessionCommand::Create {
                name: "staging".to_owned(),
            },
        )
        .await
        .expect("session create should succeed");

        let proxy = replayproxy::proxy::serve(&config)
            .await
            .expect("proxy should start");
        let admin_addr = proxy
            .admin_listen_addr
            .expect("admin listener should be running");

        let switched = run_session_command(
            &config,
            SessionCommand::Switch {
                name: "staging".to_owned(),
                admin_addr: Some(admin_addr),
            },
        )
        .await
        .expect("session switch should succeed");
        assert_eq!(
            switched,
            SessionCommandOutcome::Switched {
                name: "staging".to_owned(),
                admin_addr,
            }
        );

        proxy.shutdown().await;
    }

    #[tokio::test]
    async fn session_switch_requires_admin_address_when_unconfigured() {
        let temp_dir = tempdir().expect("tempdir should be created");
        let config = config_with_storage(temp_dir.path(), Some("default"));
        run_session_command(
            &config,
            SessionCommand::Create {
                name: "staging".to_owned(),
            },
        )
        .await
        .expect("session create should succeed");

        let err = run_session_command(
            &config,
            SessionCommand::Switch {
                name: "staging".to_owned(),
                admin_addr: None,
            },
        )
        .await
        .expect_err("session switch without admin address should fail");
        assert!(
            err.to_string()
                .contains("`session switch` requires `proxy.admin_port`"),
            "error: {err}"
        );
    }

    #[tokio::test]
    async fn mode_set_updates_runtime_mode_via_admin_endpoint() {
        let temp_dir = tempdir().expect("tempdir should be created");
        let config =
            config_with_ephemeral_admin_mode(temp_dir.path(), "default", RouteMode::Record);
        let proxy = replayproxy::proxy::serve(&config)
            .await
            .expect("proxy should start");
        let admin_addr = proxy
            .admin_listen_addr
            .expect("admin listener should be running");

        let shown = run_mode_command(
            &config,
            ModeCommand::Show {
                admin_addr: Some(admin_addr),
            },
        )
        .await
        .expect("mode show should succeed");
        assert_eq!(
            shown,
            ModeCommandOutcome::Shown {
                admin_addr,
                state: super::AdminModeState {
                    runtime_override_mode: None,
                    default_mode: RouteMode::Record,
                },
            }
        );

        let set = run_mode_command(
            &config,
            ModeCommand::Set {
                mode: RouteMode::Replay,
                admin_addr: Some(admin_addr),
                persist: false,
            },
        )
        .await
        .expect("mode set should succeed");
        assert_eq!(
            set,
            ModeCommandOutcome::Set {
                admin_addr,
                state: super::AdminModeState {
                    runtime_override_mode: Some(RouteMode::Replay),
                    default_mode: RouteMode::Record,
                },
                persisted_path: None,
            }
        );

        let shown_after = run_mode_command(
            &config,
            ModeCommand::Show {
                admin_addr: Some(admin_addr),
            },
        )
        .await
        .expect("mode show should succeed");
        assert_eq!(
            shown_after,
            ModeCommandOutcome::Shown {
                admin_addr,
                state: super::AdminModeState {
                    runtime_override_mode: Some(RouteMode::Replay),
                    default_mode: RouteMode::Record,
                },
            }
        );

        proxy.shutdown().await;
    }

    #[tokio::test]
    async fn mode_set_persist_writes_proxy_mode_back_to_config() {
        let temp_dir = tempdir().expect("tempdir should be created");
        let config_path = temp_dir.path().join("replayproxy.toml");
        fs::write(
            &config_path,
            r#"
[proxy]
listen = "127.0.0.1:0"
admin_port = 0
mode = "record"
"#,
        )
        .expect("config file should be written");
        let config = Config::from_path(&config_path).expect("config should load");
        let proxy = replayproxy::proxy::serve(&config)
            .await
            .expect("proxy should start");
        let admin_addr = proxy
            .admin_listen_addr
            .expect("admin listener should be running");

        let outcome = run_mode_command(
            &config,
            ModeCommand::Set {
                mode: RouteMode::Replay,
                admin_addr: Some(admin_addr),
                persist: true,
            },
        )
        .await
        .expect("mode set should succeed");
        assert_eq!(
            outcome,
            ModeCommandOutcome::Set {
                admin_addr,
                state: super::AdminModeState {
                    runtime_override_mode: Some(RouteMode::Replay),
                    default_mode: RouteMode::Record,
                },
                persisted_path: Some(config_path.clone()),
            }
        );

        let persisted = fs::read_to_string(&config_path).expect("config should be readable");
        assert!(
            persisted.contains("mode = \"replay\""),
            "persisted config: {persisted}"
        );

        proxy.shutdown().await;
    }

    #[tokio::test]
    async fn session_delete_rejects_active_session() {
        let temp_dir = tempdir().expect("tempdir should be created");
        let config = config_with_storage(temp_dir.path(), Some("default"));
        run_session_command(
            &config,
            SessionCommand::Create {
                name: "default".to_owned(),
            },
        )
        .await
        .expect("session create should succeed");

        let err = run_session_command(
            &config,
            SessionCommand::Delete {
                name: "default".to_owned(),
            },
        )
        .await
        .expect_err("deleting active session should fail");
        assert!(
            err.to_string()
                .contains("cannot delete active session `default`"),
            "error: {err}"
        );
    }

    #[tokio::test]
    async fn session_export_writes_manifest_and_recording_files() {
        let temp_dir = tempdir().expect("tempdir should be created");
        let config = config_with_storage(temp_dir.path(), Some("default"));
        run_session_command(
            &config,
            SessionCommand::Create {
                name: "default".to_owned(),
            },
        )
        .await
        .expect("default session should be created");
        let storage = Storage::from_config(&config)
            .expect("storage should load")
            .expect("storage should be configured");

        let created_at = Recording::now_unix_ms().expect("timestamp should be available");
        storage
            .insert_recording(recording_fixture("a", "GET", "/v1/models", created_at))
            .await
            .expect("first insert should succeed");
        storage
            .insert_recording(recording_fixture(
                "b",
                "POST",
                "/v1/chat/completions",
                created_at + 1,
            ))
            .await
            .expect("second insert should succeed");

        let export_dir = temp_dir.path().join("exports").join("default");
        let outcome = run_session_command(
            &config,
            SessionCommand::Export {
                name: "default".to_owned(),
                out: Some(export_dir.clone()),
                format: SessionExportFormat::Json,
            },
        )
        .await
        .expect("session export should succeed");

        let result = match outcome {
            SessionCommandOutcome::Exported { result } => result,
            other => panic!("expected exported outcome, got {other:?}"),
        };
        assert_eq!(result.session, "default");
        assert_eq!(result.recordings_exported, 2);
        assert_eq!(result.output_dir, export_dir);
        assert_eq!(result.manifest_path, export_dir.join("index.json"));
        assert!(result.manifest_path.exists());

        let manifest_bytes = std::fs::read(&result.manifest_path).expect("manifest should exist");
        let manifest: serde_json::Value =
            serde_json::from_slice(&manifest_bytes).expect("manifest should be JSON");
        assert_eq!(manifest["session"].as_str(), Some("default"));
        assert_eq!(manifest["format"].as_str(), Some("json"));
        assert_eq!(manifest["recordings"].as_array().map(Vec::len), Some(2));

        let recordings_dir = export_dir.join("recordings");
        let file_count = std::fs::read_dir(recordings_dir)
            .expect("recordings dir should exist")
            .count();
        assert_eq!(file_count, 2);
    }

    #[tokio::test]
    async fn session_import_reads_manifest_and_inserts_recordings() {
        let temp_dir = tempdir().expect("tempdir should be created");
        let config = config_with_storage(temp_dir.path(), Some("default"));
        let manager = SessionManager::from_config(&config)
            .expect("session manager should initialize")
            .expect("storage should be configured");
        manager
            .create_session("default")
            .await
            .expect("default session should be created");
        manager
            .create_session("staging")
            .await
            .expect("staging session should be created");

        let default_storage = manager
            .open_session_storage("default")
            .await
            .expect("default storage should open");
        let created_at = Recording::now_unix_ms().expect("timestamp should be available");
        default_storage
            .insert_recording(recording_fixture("a", "GET", "/v1/models", created_at))
            .await
            .expect("first insert should succeed");
        default_storage
            .insert_recording(recording_fixture(
                "b",
                "POST",
                "/v1/chat/completions",
                created_at + 1,
            ))
            .await
            .expect("second insert should succeed");

        let export_dir = temp_dir.path().join("exports").join("default");
        run_session_command(
            &config,
            SessionCommand::Export {
                name: "default".to_owned(),
                out: Some(export_dir.clone()),
                format: SessionExportFormat::Json,
            },
        )
        .await
        .expect("session export should succeed");

        let outcome = run_session_command(
            &config,
            SessionCommand::Import {
                name: "staging".to_owned(),
                input: export_dir.clone(),
            },
        )
        .await
        .expect("session import should succeed");
        let result = match outcome {
            SessionCommandOutcome::Imported { result } => result,
            other => panic!("expected imported outcome, got {other:?}"),
        };
        assert_eq!(result.session, "staging");
        assert_eq!(result.recordings_imported, 2);
        assert_eq!(result.input_dir, export_dir);
        assert_eq!(result.manifest_path, result.input_dir.join("index.json"));
        assert_eq!(result.format, SessionExportFormat::Json);

        let staging_storage = manager
            .open_session_storage("staging")
            .await
            .expect("staging storage should open");
        let summaries = staging_storage
            .list_recordings(0, 10)
            .await
            .expect("imported recordings should list");
        assert_eq!(summaries.len(), 2);

        let mut imported_uris = Vec::new();
        for summary in summaries {
            imported_uris.push(summary.request_uri);
        }
        imported_uris.sort();
        assert_eq!(
            imported_uris,
            vec!["/v1/chat/completions".to_owned(), "/v1/models".to_owned()]
        );
    }

    #[tokio::test]
    async fn session_import_accepts_yaml_exports() {
        let temp_dir = tempdir().expect("tempdir should be created");
        let config = config_with_storage(temp_dir.path(), Some("default"));
        let manager = SessionManager::from_config(&config)
            .expect("session manager should initialize")
            .expect("storage should be configured");
        manager
            .create_session("default")
            .await
            .expect("default session should be created");
        manager
            .create_session("staging")
            .await
            .expect("staging session should be created");

        let default_storage = manager
            .open_session_storage("default")
            .await
            .expect("default storage should open");
        let created_at = Recording::now_unix_ms().expect("timestamp should be available");
        default_storage
            .insert_recording(recording_fixture("a", "GET", "/v1/models", created_at))
            .await
            .expect("insert should succeed");

        let export_dir = temp_dir.path().join("exports").join("default-yaml");
        run_session_command(
            &config,
            SessionCommand::Export {
                name: "default".to_owned(),
                out: Some(export_dir.clone()),
                format: SessionExportFormat::Yaml,
            },
        )
        .await
        .expect("session export should succeed");

        let outcome = run_session_command(
            &config,
            SessionCommand::Import {
                name: "staging".to_owned(),
                input: export_dir.clone(),
            },
        )
        .await
        .expect("session import should succeed");
        let result = match outcome {
            SessionCommandOutcome::Imported { result } => result,
            other => panic!("expected imported outcome, got {other:?}"),
        };
        assert_eq!(result.format, SessionExportFormat::Yaml);
        assert_eq!(result.manifest_path, export_dir.join("index.yaml"));
        assert_eq!(result.recordings_imported, 1);
    }

    #[tokio::test]
    async fn session_commands_require_storage_configuration() {
        let config = config_without_storage();
        let err = run_session_command(&config, SessionCommand::List)
            .await
            .expect_err("missing storage should fail");
        assert!(
            err.to_string().contains("storage not configured"),
            "error: {err}"
        );
    }

    #[tokio::test]
    async fn recording_list_search_delete_round_trip() {
        let temp_dir = tempdir().expect("tempdir should be created");
        let config = config_with_storage(temp_dir.path(), Some("default"));
        let storage = Storage::from_config(&config)
            .expect("storage from config should parse")
            .expect("storage should be enabled");

        let base_timestamp = Recording::now_unix_ms().expect("timestamp should be available");
        let first = recording_fixture("recording-1", "GET", "/v1/models", base_timestamp);
        let second = recording_fixture(
            "recording-2",
            "POST",
            "/v1/chat/completions",
            base_timestamp + 1,
        );

        let first_id = storage
            .insert_recording(first)
            .await
            .expect("insert first should succeed");
        let second_id = storage
            .insert_recording(second)
            .await
            .expect("insert second should succeed");

        let listed = run_recording_command(
            &config,
            RecordingCommand::List {
                session: None,
                offset: 0,
                limit: 10,
            },
        )
        .await
        .expect("recording list should succeed");
        match listed {
            RecordingCommandOutcome::Listed {
                session,
                recordings,
            } => {
                assert_eq!(session, "default");
                assert_eq!(recordings.len(), 2);
                assert_eq!(recordings[0].id, second_id);
                assert_eq!(recordings[0].request_method, "POST");
                assert_eq!(recordings[0].request_uri, "/v1/chat/completions");
                assert_eq!(recordings[1].id, first_id);
            }
            other => panic!("expected listed outcome, got {other:?}"),
        }

        let searched = run_recording_command(
            &config,
            RecordingCommand::Search {
                query: "POST /chat".to_owned(),
                session: None,
                offset: 0,
                limit: 10,
            },
        )
        .await
        .expect("recording search should succeed");
        match searched {
            RecordingCommandOutcome::Searched {
                session,
                recordings,
            } => {
                assert_eq!(session, "default");
                assert_eq!(recordings.len(), 1);
                assert_eq!(recordings[0].id, second_id);
                assert_eq!(recordings[0].request_method, "POST");
                assert_eq!(recordings[0].request_uri, "/v1/chat/completions");
            }
            other => panic!("expected searched outcome, got {other:?}"),
        }

        let searched_by_body = run_recording_command(
            &config,
            RecordingCommand::Search {
                query: "body:response:/v1/chat/completions".to_owned(),
                session: None,
                offset: 0,
                limit: 10,
            },
        )
        .await
        .expect("recording body search should succeed");
        match searched_by_body {
            RecordingCommandOutcome::Searched {
                session,
                recordings,
            } => {
                assert_eq!(session, "default");
                assert_eq!(recordings.len(), 1);
                assert_eq!(recordings[0].id, second_id);
            }
            other => panic!("expected searched outcome, got {other:?}"),
        }

        let deleted = run_recording_command(
            &config,
            RecordingCommand::Delete {
                id: first_id,
                session: None,
            },
        )
        .await
        .expect("recording delete should succeed");
        assert_eq!(
            deleted,
            RecordingCommandOutcome::Deleted {
                session: "default".to_owned(),
                id: first_id,
                deleted: true,
            }
        );

        let deleted_again = run_recording_command(
            &config,
            RecordingCommand::Delete {
                id: first_id,
                session: None,
            },
        )
        .await
        .expect("recording delete should succeed");
        assert_eq!(
            deleted_again,
            RecordingCommandOutcome::Deleted {
                session: "default".to_owned(),
                id: first_id,
                deleted: false,
            }
        );
    }

    #[tokio::test]
    async fn recording_list_honors_session_override() {
        let temp_dir = tempdir().expect("tempdir should be created");
        let config = config_with_storage(temp_dir.path(), Some("default"));
        let manager = SessionManager::from_config(&config)
            .expect("session manager init should succeed")
            .expect("storage should be configured");
        manager
            .create_session("staging")
            .await
            .expect("staging session should be created");

        let base_timestamp = Recording::now_unix_ms().expect("timestamp should be available");
        let default_storage = Storage::from_config(&config)
            .expect("storage from config should parse")
            .expect("storage should be enabled");
        default_storage
            .insert_recording(recording_fixture(
                "default-key",
                "GET",
                "/default",
                base_timestamp,
            ))
            .await
            .expect("insert into default should succeed");

        let staging_storage = manager
            .open_session_storage("staging")
            .await
            .expect("staging storage should open");
        staging_storage
            .insert_recording(recording_fixture(
                "staging-key",
                "GET",
                "/staging",
                base_timestamp + 1,
            ))
            .await
            .expect("insert into staging should succeed");

        let listed_default = run_recording_command(
            &config,
            RecordingCommand::List {
                session: None,
                offset: 0,
                limit: 10,
            },
        )
        .await
        .expect("default list should succeed");
        match listed_default {
            RecordingCommandOutcome::Listed {
                session,
                recordings,
            } => {
                assert_eq!(session, "default");
                assert_eq!(recordings.len(), 1);
                assert_eq!(recordings[0].request_uri, "/default");
            }
            other => panic!("expected listed outcome, got {other:?}"),
        }

        let listed_staging = run_recording_command(
            &config,
            RecordingCommand::List {
                session: Some("staging".to_owned()),
                offset: 0,
                limit: 10,
            },
        )
        .await
        .expect("staging list should succeed");
        match listed_staging {
            RecordingCommandOutcome::Listed {
                session,
                recordings,
            } => {
                assert_eq!(session, "staging");
                assert_eq!(recordings.len(), 1);
                assert_eq!(recordings[0].request_uri, "/staging");
            }
            other => panic!("expected listed outcome, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn recording_commands_require_storage_configuration() {
        let config = config_without_storage();
        let err = run_recording_command(
            &config,
            RecordingCommand::List {
                session: None,
                offset: 0,
                limit: 10,
            },
        )
        .await
        .expect_err("missing storage should fail");
        assert!(
            err.to_string().contains("storage not configured"),
            "error: {err}"
        );
    }

    #[test]
    fn uri_path_segment_encoding_handles_spaces_and_slashes() {
        assert_eq!(encode_uri_path_segment("staging v2"), "staging%20v2");
        assert_eq!(encode_uri_path_segment("a/b"), "a%2Fb");
    }

    #[test]
    fn startup_summary_redacts_private_key_path() {
        let config = Config::from_toml_str(
            r#"
[proxy]
listen = "127.0.0.1:8080"
admin_port = 8081

[proxy.tls]
enabled = true
ca_cert = "/tmp/cert.pem"
ca_key = "/tmp/private-key.pem"

[storage]
path = "/tmp/sessions"
active_session = "default"
"#,
        )
        .expect("config should parse");

        let summary = startup_summary(
            &config,
            "127.0.0.1:8080".parse().unwrap(),
            Some("127.0.0.1:8081".parse().unwrap()),
        );

        assert!(summary.contains("ca_key=[REDACTED]"), "summary: {summary}");
        assert!(summary.contains("ca_cert=[REDACTED]"), "summary: {summary}");
        assert!(
            summary.contains("storage_path=[REDACTED]"),
            "summary: {summary}"
        );
        assert!(
            summary.contains("active_session=[REDACTED]"),
            "summary: {summary}"
        );
        assert!(
            !summary.contains("private-key.pem"),
            "summary leaked secret: {summary}"
        );
        assert!(
            !summary.contains("/tmp/cert.pem"),
            "summary leaked cert path: {summary}"
        );
        assert!(
            !summary.contains("/tmp/sessions"),
            "summary leaked storage path: {summary}"
        );
    }

    #[test]
    fn redact_if_present_covers_some_and_none() {
        assert_eq!(redact_if_present(Some(&PathBuf::from("x"))), "[REDACTED]");
        assert_eq!(redact_if_present(Option::<&PathBuf>::None), "none");
    }

    #[test]
    fn redact_active_session_covers_configured_and_default() {
        assert_eq!(redact_active_session(Some("staging")), "[REDACTED]");
        assert_eq!(redact_active_session(None), "default");
    }
}
