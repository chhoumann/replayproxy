use std::{fmt::Write as _, net::SocketAddr, path::PathBuf};

use anyhow::bail;
use bytes::Bytes;
use clap::{Parser, Subcommand};
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Uri};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use replayproxy::{config::Config, logging, session, storage::SessionManager};

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

fn resolve_admin_addr_for_switch(
    config: &Config,
    admin_addr_override: Option<SocketAddr>,
) -> anyhow::Result<SocketAddr> {
    if let Some(admin_addr) = admin_addr_override {
        return Ok(admin_addr);
    }

    let Some(admin_port) = config.proxy.admin_port else {
        bail!("`session switch` requires `proxy.admin_port` in config or `--admin-addr` override");
    };
    if admin_port == 0 {
        bail!(
            "`session switch` cannot infer admin port from `proxy.admin_port = 0`; pass `--admin-addr`"
        );
    }

    Ok(SocketAddr::new(config.proxy.listen.ip(), admin_port))
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

async fn switch_session_via_admin(
    admin_addr: SocketAddr,
    session_name: &str,
) -> anyhow::Result<()> {
    let uri: Uri = format!(
        "http://{admin_addr}/_admin/sessions/{}/activate",
        encode_uri_path_segment(session_name)
    )
    .parse()
    .map_err(|err| anyhow::anyhow!("build admin activation URI: {err}"))?;

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let request = Request::builder()
        .method(Method::POST)
        .uri(uri)
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
            switch_session_via_admin(admin_addr, &name).await?;
            Ok(SessionCommandOutcome::Switched { name, admin_addr })
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
    }

    Ok(())
}

fn startup_summary(
    config: &Config,
    proxy_listen_addr: std::net::SocketAddr,
    admin_listen_addr: Option<std::net::SocketAddr>,
) -> String {
    let storage_path = config
        .storage
        .as_ref()
        .map(|storage| storage.path.display().to_string())
        .unwrap_or_else(|| "disabled".to_owned());
    let active_session = config
        .storage
        .as_ref()
        .and_then(|storage| storage.active_session.as_deref())
        .unwrap_or("default");
    let tls_summary = match config.proxy.tls.as_ref() {
        Some(tls) => format!(
            "enabled={},ca_cert={},ca_key={}",
            tls.enabled,
            tls.ca_cert
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "none".to_owned()),
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

fn redact_if_present(value: Option<&PathBuf>) -> &'static str {
    if value.is_some() {
        "[REDACTED]"
    } else {
        "none"
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{
        Cli, Command, SessionCommand, SessionCommandOutcome, encode_uri_path_segment,
        redact_if_present, run_session_command, startup_summary,
    };
    use clap::Parser;
    use replayproxy::config::Config;
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
        assert!(
            !summary.contains("private-key.pem"),
            "summary leaked secret: {summary}"
        );
    }

    #[test]
    fn redact_if_present_covers_some_and_none() {
        assert_eq!(redact_if_present(Some(&PathBuf::from("x"))), "[REDACTED]");
        assert_eq!(redact_if_present(Option::<&PathBuf>::None), "none");
    }
}
