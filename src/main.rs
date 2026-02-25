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
        /// Path to config TOML.
        #[arg(long)]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Serve { config } => {
            let config = replayproxy::config::Config::from_path(config)?;
            let proxy = replayproxy::proxy::serve(&config).await?;
            eprintln!("listening on {}", proxy.listen_addr);
            tokio::signal::ctrl_c().await?;
            proxy.shutdown().await;
        }
    }

    Ok(())
}
