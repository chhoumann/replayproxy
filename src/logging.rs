use anyhow::anyhow;
use tracing_subscriber::filter::LevelFilter;

use crate::config::{Config, LogFormat};

const DEFAULT_LOG_LEVEL: &str = "info";

pub fn init(config: &Config, cli_level_override: Option<&str>) -> anyhow::Result<()> {
    let log_level = resolve_log_level(config, cli_level_override)?;

    match resolve_log_format(config) {
        LogFormat::Json => tracing_subscriber::fmt()
            .with_max_level(log_level)
            .with_target(true)
            .json()
            .try_init(),
        LogFormat::Pretty => tracing_subscriber::fmt()
            .with_max_level(log_level)
            .with_target(true)
            .pretty()
            .try_init(),
    }
    .map_err(|err| anyhow!("initialize logging subscriber: {err}"))?;

    Ok(())
}

fn resolve_log_level(
    config: &Config,
    cli_level_override: Option<&str>,
) -> anyhow::Result<LevelFilter> {
    let raw_level = cli_level_override
        .or_else(|| {
            config
                .logging
                .as_ref()
                .and_then(|logging| logging.level.as_deref())
        })
        .unwrap_or(DEFAULT_LOG_LEVEL);
    let normalized = raw_level.trim().to_ascii_lowercase();

    normalized.parse::<LevelFilter>().map_err(|_| {
        anyhow!(
            "invalid log level `{raw_level}`; expected one of trace, debug, info, warn, error, off"
        )
    })
}

fn resolve_log_format(config: &Config) -> LogFormat {
    config
        .logging
        .as_ref()
        .and_then(|logging| logging.format)
        .unwrap_or(LogFormat::Json)
}

#[cfg(test)]
mod tests {
    use super::{resolve_log_format, resolve_log_level};
    use crate::config::{Config, LogFormat};
    use serde_json::Value;
    use tracing_subscriber::{filter::LevelFilter, fmt::MakeWriter};

    fn minimal_config() -> Config {
        Config::from_toml_str(
            r#"
[proxy]
listen = "127.0.0.1:0"
"#,
        )
        .expect("config should parse")
    }

    fn configured_logging() -> Config {
        Config::from_toml_str(
            r#"
[proxy]
listen = "127.0.0.1:0"

[logging]
level = "warn"
format = "pretty"
"#,
        )
        .expect("config should parse")
    }

    #[test]
    fn log_level_defaults_to_info() {
        assert_eq!(
            resolve_log_level(&minimal_config(), None).expect("default level should resolve"),
            LevelFilter::INFO
        );
    }

    #[test]
    fn log_level_prefers_cli_override() {
        assert_eq!(
            resolve_log_level(&configured_logging(), Some("debug"))
                .expect("cli level should resolve"),
            LevelFilter::DEBUG
        );
    }

    #[test]
    fn invalid_log_level_is_rejected() {
        let err = resolve_log_level(&minimal_config(), Some("verbose")).unwrap_err();
        assert!(
            err.to_string().contains("invalid log level"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn log_format_defaults_to_json_and_can_be_pretty() {
        assert_eq!(resolve_log_format(&minimal_config()), LogFormat::Json);
        assert_eq!(resolve_log_format(&configured_logging()), LogFormat::Pretty);
    }

    #[test]
    fn json_formatter_includes_required_fields() {
        let writer = SharedWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(LevelFilter::INFO)
            .with_target(true)
            .json()
            .with_writer(writer.clone())
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "replayproxy.tests", "hello");
        });

        let output = writer.as_string();
        let line = output.lines().next().expect("expected one JSON log line");
        let log: Value = serde_json::from_str(line).expect("log line should be valid JSON");

        assert!(log.get("timestamp").is_some(), "log: {log}");
        assert_eq!(
            log.get("level").and_then(Value::as_str),
            Some("INFO"),
            "log: {log}"
        );
        assert_eq!(
            log.get("target").and_then(Value::as_str),
            Some("replayproxy.tests"),
            "log: {log}"
        );
        assert_eq!(
            log.pointer("/fields/message").and_then(Value::as_str),
            Some("hello"),
            "log: {log}"
        );
    }

    #[derive(Clone, Default)]
    struct SharedWriter {
        buffer: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl SharedWriter {
        fn as_string(&self) -> String {
            let bytes = self.buffer.lock().expect("buffer lock poisoned").clone();
            String::from_utf8(bytes).expect("log output should be UTF-8")
        }
    }

    struct LockedWriter {
        buffer: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl<'a> MakeWriter<'a> for SharedWriter {
        type Writer = LockedWriter;

        fn make_writer(&'a self) -> Self::Writer {
            LockedWriter {
                buffer: self.buffer.clone(),
            }
        }
    }

    impl std::io::Write for LockedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.buffer
                .lock()
                .expect("buffer lock poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
