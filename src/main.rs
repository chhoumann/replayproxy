use std::path::PathBuf;

use clap::{Parser, Subcommand};

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
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Serve { config } => {
            let config = replayproxy::config::Config::load(config.as_deref())?;
            let proxy = replayproxy::proxy::serve(&config).await?;
            eprintln!("listening on {}", proxy.listen_addr);
            tokio::signal::ctrl_c().await?;
            proxy.shutdown().await;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{Cli, Command};
    use clap::Parser;

    #[test]
    fn serve_parses_without_config_flag() {
        let cli = Cli::try_parse_from(["replayproxy", "serve"]).expect("cli parse should succeed");
        let Command::Serve { config } = cli.command;
        assert_eq!(config, None);
    }

    #[test]
    fn serve_parses_with_config_flag() {
        let cli = Cli::try_parse_from(["replayproxy", "serve", "--config", "custom.toml"])
            .expect("cli parse should succeed");
        let Command::Serve { config } = cli.command;
        assert_eq!(config, Some(PathBuf::from("custom.toml")));
    }
}
