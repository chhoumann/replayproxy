use std::path::PathBuf;

use clap::{Parser, Subcommand};
use replayproxy::{config::Config, logging};

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
    use std::path::PathBuf;

    use super::{Cli, Command, redact_if_present, startup_summary};
    use clap::Parser;
    use replayproxy::config::Config;

    #[test]
    fn serve_parses_without_config_flag() {
        let cli = Cli::try_parse_from(["replayproxy", "serve"]).expect("cli parse should succeed");
        let Command::Serve {
            config,
            active_session,
            log_level,
        } = cli.command;
        assert_eq!(config, None);
        assert_eq!(active_session, None);
        assert_eq!(log_level, None);
    }

    #[test]
    fn serve_parses_with_config_flag() {
        let cli = Cli::try_parse_from(["replayproxy", "serve", "--config", "custom.toml"])
            .expect("cli parse should succeed");
        let Command::Serve {
            config,
            active_session,
            log_level,
        } = cli.command;
        assert_eq!(config, Some(PathBuf::from("custom.toml")));
        assert_eq!(active_session, None);
        assert_eq!(log_level, None);
    }

    #[test]
    fn serve_parses_with_active_session_flag() {
        let cli = Cli::try_parse_from(["replayproxy", "serve", "--active-session", "staging"])
            .expect("cli parse should succeed");
        let Command::Serve {
            config,
            active_session,
            log_level,
        } = cli.command;
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
        let Command::Serve {
            config,
            active_session,
            log_level,
        } = cli.command;
        assert_eq!(config, Some(PathBuf::from("custom.toml")));
        assert_eq!(active_session.as_deref(), Some("staging"));
        assert_eq!(log_level, None);
    }

    #[test]
    fn serve_parses_with_log_level_flag() {
        let cli = Cli::try_parse_from(["replayproxy", "serve", "--log-level", "debug"])
            .expect("cli parse should succeed");
        let Command::Serve {
            config,
            active_session,
            log_level,
        } = cli.command;
        assert_eq!(config, None);
        assert_eq!(active_session, None);
        assert_eq!(log_level.as_deref(), Some("debug"));
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
