use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::bail;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub storage: Option<StorageConfig>,
    #[serde(default)]
    pub logging: Option<LoggingConfig>,
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
    #[serde(default)]
    pub defaults: Option<DefaultsConfig>,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
}

impl Config {
    pub fn from_path(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let toml = fs::read_to_string(path)
            .map_err(|err| anyhow::anyhow!("read config {}: {err}", path.display()))?;
        Self::from_toml_str(&toml)
    }

    pub fn from_toml_str(toml: &str) -> anyhow::Result<Self> {
        toml.parse()
    }

    fn validate(&self) -> anyhow::Result<()> {
        for (idx, route) in self.routes.iter().enumerate() {
            route.validate(idx)?;
        }
        Ok(())
    }
}

impl FromStr for Config {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let config: Self =
            toml::from_str(s).map_err(|err| anyhow::anyhow!("parse config TOML: {err}"))?;
        config.validate()?;
        Ok(config)
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    pub listen: SocketAddr,
    #[serde(default)]
    pub admin_port: Option<u16>,
    #[serde(default)]
    pub mode: Option<RouteMode>,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub ca_cert: Option<PathBuf>,
    #[serde(default)]
    pub ca_key: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    pub path: PathBuf,
    #[serde(default)]
    pub active_session: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    #[serde(default)]
    pub level: Option<String>,
    #[serde(default)]
    pub format: Option<LogFormat>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LogFormat {
    Json,
    Pretty,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DefaultsConfig {
    #[serde(default)]
    pub redact: Option<RedactConfig>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RedactConfig {
    #[serde(default)]
    pub headers: Vec<String>,
    #[serde(default)]
    pub body_json: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub path_exact: Option<String>,
    #[serde(default)]
    pub path_regex: Option<String>,
    #[serde(default)]
    pub upstream: Option<String>,
    #[serde(default)]
    pub mode: Option<RouteMode>,
    #[serde(default)]
    pub cache_miss: Option<CacheMissPolicy>,
    #[serde(default, rename = "match")]
    pub match_: Option<RouteMatchConfig>,
    #[serde(default)]
    pub redact: Option<RedactConfig>,
    #[serde(default)]
    pub streaming: Option<StreamingConfig>,
    #[serde(default)]
    pub websocket: Option<WebSocketConfig>,
    #[serde(default)]
    pub grpc: Option<GrpcConfig>,
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
    #[serde(default)]
    pub transform: Option<TransformConfig>,
}

impl RouteConfig {
    fn validate(&self, idx: usize) -> anyhow::Result<()> {
        if self.path_prefix.is_none() && self.path_exact.is_none() && self.path_regex.is_none() {
            bail!(
                "{}: one of `path_prefix`, `path_exact`, or `path_regex` is required",
                self.display_name(idx)
            );
        }

        Ok(())
    }

    fn display_name(&self, idx: usize) -> String {
        self.name
            .as_deref()
            .map(|name| format!("routes[{idx}] ({name})"))
            .unwrap_or_else(|| format!("routes[{idx}]"))
    }
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RouteMode {
    Record,
    Replay,
    PassthroughCache,
}

impl std::fmt::Display for RouteMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            RouteMode::Record => "record",
            RouteMode::Replay => "replay",
            RouteMode::PassthroughCache => "passthrough-cache",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CacheMissPolicy {
    Forward,
    Error,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum QueryMatchMode {
    Exact,
    Subset,
    Ignore,
}

impl Default for QueryMatchMode {
    fn default() -> Self {
        Self::Exact
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RouteMatchConfig {
    #[serde(default = "default_true")]
    pub method: bool,
    #[serde(default = "default_true")]
    pub path: bool,
    #[serde(default)]
    pub query: QueryMatchMode,
    #[serde(default)]
    pub headers: Vec<String>,
    #[serde(default)]
    pub headers_ignore: Vec<String>,
    #[serde(default)]
    pub body_json: Vec<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct StreamingConfig {
    #[serde(default)]
    pub preserve_timing: bool,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    pub requests_per_second: u64,
    #[serde(default)]
    pub burst: Option<u64>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TransformConfig {
    #[serde(default)]
    pub on_request: Option<String>,
    #[serde(default)]
    pub on_response: Option<String>,
    #[serde(default)]
    pub on_record: Option<String>,
    #[serde(default)]
    pub on_replay: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct GrpcConfig {
    #[serde(default)]
    pub proto_files: Vec<PathBuf>,
    #[serde(default)]
    pub match_fields: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct WebSocketConfig {
    #[serde(default)]
    pub recording_mode: Option<WebSocketRecordingMode>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WebSocketRecordingMode {
    ServerOnly,
    Bidirectional,
}

#[cfg(test)]
mod tests {
    use super::{Config, LogFormat, RouteMode, WebSocketRecordingMode};

    #[test]
    fn loads_spec_example_config() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:8080"
admin_port = 8081
mode = "passthrough-cache"

[proxy.tls]
enabled = true
ca_cert = "~/.replayproxy/ca/cert.pem"
ca_key = "~/.replayproxy/ca/key.pem"

[storage]
path = "~/.replayproxy/sessions"
active_session = "default"

[logging]
level = "info"
format = "json"

[metrics]
enabled = true

[defaults.redact]
headers = ["Authorization", "X-Api-Key", "Cookie"]

[[routes]]
name = "openai-chat"
path_prefix = "/v1/chat/completions"
upstream = "https://api.openai.com"
mode = "passthrough-cache"
cache_miss = "forward"

[routes.match]
method = true
path = true
body_json = ["$.model", "$.messages", "$.temperature"]

[routes.redact]
headers = ["Authorization"]
body_json = ["$.api_key"]

[routes.streaming]
preserve_timing = true

[routes.rate_limit]
requests_per_second = 10
burst = 20

[[routes]]
name = "anthropic-messages"
path_prefix = "/v1/messages"
upstream = "https://api.anthropic.com"
mode = "record"

[routes.match]
method = true
path = true
body_json = ["$.model", "$.messages", "$.max_tokens"]

[routes.transform]
on_request = "scripts/anthropic_auth.lua"

[[routes]]
name = "grpc-inference"
path_prefix = "/inference.InferenceService"
mode = "replay"
cache_miss = "error"

[routes.grpc]
proto_files = ["protos/inference.proto"]
match_fields = ["model_name", "input_text"]

[[routes]]
name = "ws-streaming"
path_prefix = "/ws/stream"
mode = "passthrough-cache"

[routes.websocket]
recording_mode = "server-only"
"#;

        let config = Config::from_toml_str(toml).unwrap();

        assert_eq!(config.proxy.listen.to_string(), "127.0.0.1:8080");
        assert_eq!(config.proxy.admin_port, Some(8081));
        assert_eq!(config.proxy.mode, Some(RouteMode::PassthroughCache));

        let logging = config.logging.as_ref().unwrap();
        assert_eq!(logging.level.as_deref(), Some("info"));
        assert_eq!(logging.format, Some(LogFormat::Json));

        assert_eq!(config.routes.len(), 4);

        let openai = &config.routes[0];
        assert_eq!(openai.name.as_deref(), Some("openai-chat"));
        assert_eq!(openai.upstream.as_deref(), Some("https://api.openai.com"));
        assert_eq!(openai.mode, Some(RouteMode::PassthroughCache));
        assert_eq!(openai.cache_miss, Some(super::CacheMissPolicy::Forward));
        assert_eq!(openai.match_.as_ref().unwrap().body_json.len(), 3);
        assert!(openai.streaming.as_ref().unwrap().preserve_timing);
        assert_eq!(openai.rate_limit.as_ref().unwrap().requests_per_second, 10);

        let anthropic = &config.routes[1];
        assert_eq!(
            anthropic.transform.as_ref().unwrap().on_request.as_deref(),
            Some("scripts/anthropic_auth.lua")
        );

        let grpc = &config.routes[2];
        assert_eq!(grpc.grpc.as_ref().unwrap().proto_files.len(), 1);

        let ws = &config.routes[3];
        assert_eq!(
            ws.websocket.as_ref().unwrap().recording_mode,
            Some(WebSocketRecordingMode::ServerOnly)
        );
    }

    #[test]
    fn unknown_fields_produce_errors() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:0"
wat = 123
"#;

        let err = Config::from_toml_str(toml).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "err: {err}");
    }

    #[test]
    fn missing_route_matcher_fails_fast() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:0"

[[routes]]
upstream = "http://127.0.0.1:1234"
"#;

        let err = Config::from_toml_str(toml).unwrap_err();
        assert!(
            err.to_string()
                .contains("one of `path_prefix`, `path_exact`, or `path_regex` is required")
        );
    }
}
