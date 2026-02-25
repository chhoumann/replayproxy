use std::{
    env,
    ffi::OsStr,
    fs, io,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    str::FromStr,
};

use anyhow::bail;
use serde::Deserialize;
use serde_json_path::JsonPath;

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
    pub fn load(config_override: Option<&Path>) -> anyhow::Result<Self> {
        let mut attempted_paths = Vec::new();

        for raw_path in config_candidate_paths(config_override) {
            let resolved_path = match expand_tilde(&raw_path) {
                Ok(path) => path,
                Err(err) => {
                    attempted_paths.push(raw_path.display().to_string());
                    return Err(anyhow::anyhow!(
                        "{err}\n{}",
                        format_attempted_paths(&attempted_paths)
                    ));
                }
            };
            attempted_paths.push(resolved_path.display().to_string());

            let toml = match fs::read_to_string(&resolved_path) {
                Ok(toml) => toml,
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(err) => {
                    return Err(anyhow::anyhow!(
                        "read config {}: {err}\n{}",
                        resolved_path.display(),
                        format_attempted_paths(&attempted_paths)
                    ));
                }
            };

            return Self::from_toml_str(&toml).map_err(|err| {
                anyhow::anyhow!(
                    "parse config {}: {err}\n{}",
                    resolved_path.display(),
                    format_attempted_paths(&attempted_paths)
                )
            });
        }

        bail!(
            "unable to find a config file\n{}",
            format_attempted_paths(&attempted_paths)
        )
    }

    pub fn from_path(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = expand_tilde(path.as_ref())?;
        let toml = fs::read_to_string(&path)
            .map_err(|err| anyhow::anyhow!("read config {}: {err}", path.display()))?;
        Self::from_toml_str(&toml)
            .map_err(|err| anyhow::anyhow!("parse config {}: {err}", path.display()))
    }

    pub fn from_toml_str(toml: &str) -> anyhow::Result<Self> {
        toml.parse()
    }

    pub fn apply_active_session_override(&mut self, active_session_override: Option<&str>) {
        let Some(active_session_override) = active_session_override else {
            return;
        };
        let Some(storage) = self.storage.as_mut() else {
            return;
        };

        storage.active_session = Some(active_session_override.to_owned());
    }

    fn validate(&self) -> anyhow::Result<()> {
        for (idx, route) in self.routes.iter().enumerate() {
            route.validate(idx)?;
        }
        Ok(())
    }
}

fn config_candidate_paths(config_override: Option<&Path>) -> Vec<PathBuf> {
    if let Some(path) = config_override {
        return vec![path.to_path_buf()];
    }

    vec![
        PathBuf::from("./replayproxy.toml"),
        PathBuf::from("~/.replayproxy/config.toml"),
    ]
}

fn expand_tilde(path: &Path) -> anyhow::Result<PathBuf> {
    let mut components = path.components();
    match components.next() {
        Some(Component::Normal(component)) if component == OsStr::new("~") => {
            let home = env::var_os("HOME").ok_or_else(|| {
                anyhow::anyhow!("cannot expand `~` in {}: HOME is not set", path.display())
            })?;
            let mut expanded = PathBuf::from(home);
            for component in components {
                expanded.push(component.as_os_str());
            }
            Ok(expanded)
        }
        _ => Ok(path.to_path_buf()),
    }
}

fn format_attempted_paths(attempted_paths: &[String]) -> String {
    if attempted_paths.is_empty() {
        return "attempted paths: (none)".to_string();
    }

    let mut message = String::from("attempted paths:");
    for path in attempted_paths {
        message.push_str("\n- ");
        message.push_str(path);
    }
    message
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

        if let Some(route_match) = self.match_.as_ref() {
            for expression in &route_match.body_json {
                JsonPath::parse(expression).map_err(|err| {
                    anyhow::anyhow!(
                        "{}: invalid `routes.match.body_json` expression `{expression}`: {err}",
                        self.display_name(idx)
                    )
                })?;
            }
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
    use std::{
        env,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

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
headers = ["Authorization", "X-Request-Id"]
headers_ignore = ["Date"]
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
        assert_eq!(
            openai.match_.as_ref().unwrap().headers,
            vec!["Authorization", "X-Request-Id"]
        );
        assert_eq!(openai.match_.as_ref().unwrap().headers_ignore, vec!["Date"]);
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

    #[test]
    fn invalid_match_body_json_path_fails_fast() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:0"

[[routes]]
path_prefix = "/api"

[routes.match]
body_json = ["$["]
"#;

        let err = Config::from_toml_str(toml).unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid `routes.match.body_json` expression"),
            "err: {err}"
        );
    }

    #[test]
    fn default_search_paths_follow_expected_order() {
        let paths = super::config_candidate_paths(None);
        assert_eq!(paths[0], PathBuf::from("./replayproxy.toml"));
        assert_eq!(paths[1], PathBuf::from("~/.replayproxy/config.toml"));
    }

    #[test]
    fn override_path_replaces_default_search_paths() {
        let override_path = Path::new("/tmp/custom-config.toml");
        let paths = super::config_candidate_paths(Some(override_path));
        assert_eq!(paths, vec![override_path.to_path_buf()]);
    }

    #[test]
    fn from_path_expands_tilde() {
        let home = env::var_os("HOME").expect("HOME should be set in test environment");
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        let missing_relative = format!(".replayproxy/replayproxy-missing-{unique}.toml");
        let tilde_path = format!("~/{missing_relative}");
        let expected_path = PathBuf::from(home).join(missing_relative);

        let err = Config::from_path(Path::new(&tilde_path)).unwrap_err();
        assert!(
            err.to_string()
                .contains(&expected_path.display().to_string()),
            "err: {err}"
        );
    }

    #[test]
    fn load_errors_include_attempted_paths() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        let missing_path = PathBuf::from(format!("/tmp/replayproxy-missing-{unique}.toml"));

        let err = Config::load(Some(missing_path.as_path())).unwrap_err();
        assert!(err.to_string().contains("attempted paths:"), "err: {err}");
        assert!(
            err.to_string()
                .contains(&missing_path.display().to_string()),
            "err: {err}"
        );
    }

    #[test]
    fn apply_active_session_override_updates_storage_session() {
        let mut config = Config::from_toml_str(
            r#"
[proxy]
listen = "127.0.0.1:0"

[storage]
path = "/tmp/replayproxy-tests"
active_session = "from-config"
"#,
        )
        .unwrap();

        config.apply_active_session_override(Some("from-cli"));

        let storage = config.storage.as_ref().expect("storage should exist");
        assert_eq!(storage.active_session.as_deref(), Some("from-cli"));
    }

    #[test]
    fn apply_active_session_override_is_noop_without_storage() {
        let mut config = Config::from_toml_str(
            r#"
[proxy]
listen = "127.0.0.1:0"
"#,
        )
        .unwrap();

        config.apply_active_session_override(Some("from-cli"));
        assert!(config.storage.is_none());
    }
}
