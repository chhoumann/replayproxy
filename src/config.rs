use std::{
    env,
    ffi::OsStr,
    fs, io,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    str::FromStr,
};

use anyhow::bail;
use hyper::Uri;
use regex::Regex;
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

    fn normalize_and_validate(&mut self) -> anyhow::Result<()> {
        self.proxy.normalize_and_validate()?;

        if let Some(storage) = self.storage.as_mut() {
            storage.normalize_and_validate()?;
        }

        for (idx, route) in self.routes.iter_mut().enumerate() {
            route.normalize_and_validate(idx)?;
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
        let mut config: Self =
            toml::from_str(s).map_err(|err| anyhow::anyhow!("parse config TOML: {err}"))?;
        config.normalize_and_validate()?;
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
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;

fn default_max_body_bytes() -> usize {
    DEFAULT_MAX_BODY_BYTES
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

impl ProxyConfig {
    fn normalize_and_validate(&mut self) -> anyhow::Result<()> {
        if let Some(admin_port) = self.admin_port
            && admin_port != 0
            && self.listen.port() != 0
            && admin_port == self.listen.port()
        {
            bail!(
                "`proxy.admin_port` ({admin_port}) must differ from `proxy.listen` port ({})",
                self.listen.port()
            );
        }

        if self.max_body_bytes == 0 {
            bail!("`proxy.max_body_bytes` must be greater than 0");
        }

        if let Some(tls) = self.tls.as_mut() {
            tls.normalize_and_validate()?;
        }

        Ok(())
    }
}

impl TlsConfig {
    fn normalize_and_validate(&mut self) -> anyhow::Result<()> {
        if let Some(ca_cert) = self.ca_cert.as_ref() {
            self.ca_cert = Some(expand_tilde(ca_cert)?);
        }
        if let Some(ca_key) = self.ca_key.as_ref() {
            self.ca_key = Some(expand_tilde(ca_key)?);
        }

        if self.enabled {
            if self.ca_cert.is_none() {
                bail!("`proxy.tls.ca_cert` is required when `proxy.tls.enabled = true`");
            }
            if self.ca_key.is_none() {
                bail!("`proxy.tls.ca_key` is required when `proxy.tls.enabled = true`");
            }
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    pub path: PathBuf,
    #[serde(default)]
    pub active_session: Option<String>,
}

impl StorageConfig {
    fn normalize_and_validate(&mut self) -> anyhow::Result<()> {
        self.path = expand_tilde(&self.path)?;

        if let Some(active_session) = self.active_session.as_ref()
            && active_session.trim().is_empty()
        {
            bail!("`storage.active_session` cannot be empty");
        }

        Ok(())
    }
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
    pub body_oversize: Option<BodyOversizePolicy>,
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

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BodyOversizePolicy {
    Error,
    BypassCache,
}

impl RouteConfig {
    fn normalize_and_validate(&mut self, idx: usize) -> anyhow::Result<()> {
        let route_name = self.display_name(idx);

        let matcher_count = usize::from(self.path_prefix.is_some())
            + usize::from(self.path_exact.is_some())
            + usize::from(self.path_regex.is_some());
        if matcher_count == 0 {
            bail!(
                "{}: one of `path_prefix`, `path_exact`, or `path_regex` is required",
                route_name
            );
        }
        if matcher_count > 1 {
            bail!(
                "{}: `path_prefix`, `path_exact`, and `path_regex` are mutually exclusive",
                route_name
            );
        }

        if let Some(path_prefix) = self.path_prefix.take() {
            self.path_prefix = Some(normalize_route_path(
                &route_name,
                "path_prefix",
                &path_prefix,
                true,
            )?);
        }
        if let Some(path_exact) = self.path_exact.take() {
            self.path_exact = Some(normalize_route_path(
                &route_name,
                "path_exact",
                &path_exact,
                false,
            )?);
        }
        if let Some(path_regex) = self.path_regex.as_deref() {
            Regex::new(path_regex).map_err(|err| {
                anyhow::anyhow!(
                    "{}: invalid `path_regex` expression `{path_regex}`: {err}",
                    route_name
                )
            })?;
        }

        if let Some(upstream) = self.upstream.take() {
            self.upstream = Some(normalize_upstream(&route_name, &upstream)?);
        }

        if self.grpc.is_some() && self.websocket.is_some() {
            bail!("{route_name}: `grpc` and `websocket` are mutually exclusive");
        }
        if let Some(grpc) = self.grpc.as_mut() {
            for proto_file in &mut grpc.proto_files {
                *proto_file = expand_tilde(proto_file)?;
            }
        }

        if let Some(route_match) = self.match_.as_ref() {
            if let Some(overlap) =
                overlapping_header_name(&route_match.headers, &route_match.headers_ignore)
            {
                bail!(
                    "{}: `routes.match.headers` and `routes.match.headers_ignore` overlap on `{overlap}`",
                    route_name
                );
            }

            for expression in &route_match.body_json {
                JsonPath::parse(expression).map_err(|err| {
                    anyhow::anyhow!(
                        "{}: invalid `routes.match.body_json` expression `{expression}`: {err}",
                        route_name
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

fn normalize_route_path(
    route_name: &str,
    field_name: &str,
    raw: &str,
    strip_trailing_slashes: bool,
) -> anyhow::Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("{route_name}: `routes.{field_name}` cannot be empty");
    }

    let mut normalized = if trimmed.starts_with('/') {
        trimmed.to_owned()
    } else {
        format!("/{trimmed}")
    };

    if normalized.contains('?') || normalized.contains('#') {
        bail!("{route_name}: `routes.{field_name}` must be a path without query/fragment");
    }

    if strip_trailing_slashes {
        while normalized.len() > 1 && normalized.ends_with('/') {
            normalized.pop();
        }
    }

    Ok(normalized)
}

fn normalize_upstream(route_name: &str, raw: &str) -> anyhow::Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("{route_name}: `upstream` cannot be empty");
    }

    let upstream_uri: Uri = trimmed.parse().map_err(|err| {
        anyhow::anyhow!("{route_name}: invalid `upstream` URL `{trimmed}`: {err}")
    })?;
    let Some(scheme) = upstream_uri.scheme_str() else {
        bail!("{route_name}: `upstream` URL must include a scheme (`http` or `https`)");
    };
    if !matches!(scheme, "http" | "https") {
        bail!("{route_name}: `upstream` URL scheme must be `http` or `https`, got `{scheme}`");
    }
    let Some(authority) = upstream_uri.authority().map(|authority| authority.as_str()) else {
        bail!("{route_name}: `upstream` URL must include a host");
    };
    if let Some(path_and_query) = upstream_uri.path_and_query() {
        let path_and_query = path_and_query.as_str();
        if path_and_query != "/" {
            bail!("{route_name}: `upstream` URL must not include a path/query");
        }
    }

    Ok(format!("{scheme}://{authority}"))
}

fn overlapping_header_name(headers: &[String], headers_ignore: &[String]) -> Option<String> {
    headers.iter().find_map(|header| {
        headers_ignore
            .iter()
            .find(|ignored| ignored.eq_ignore_ascii_case(header))
            .map(|_| header.to_ascii_lowercase())
    })
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
body_oversize = "bypass-cache"
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
        let home =
            PathBuf::from(env::var_os("HOME").expect("HOME should be set in test environment"));
        let expected_ca_cert_path = home.join(".replayproxy/ca/cert.pem");
        let expected_ca_key_path = home.join(".replayproxy/ca/key.pem");
        let expected_storage_path = home.join(".replayproxy/sessions");

        assert_eq!(config.proxy.listen.to_string(), "127.0.0.1:8080");
        assert_eq!(config.proxy.admin_port, Some(8081));
        assert_eq!(config.proxy.mode, Some(RouteMode::PassthroughCache));
        assert_eq!(config.proxy.max_body_bytes, super::DEFAULT_MAX_BODY_BYTES);
        assert_eq!(
            config
                .proxy
                .tls
                .as_ref()
                .and_then(|tls| tls.ca_cert.as_ref()),
            Some(&expected_ca_cert_path)
        );
        assert_eq!(
            config
                .proxy
                .tls
                .as_ref()
                .and_then(|tls| tls.ca_key.as_ref()),
            Some(&expected_ca_key_path)
        );
        assert_eq!(
            config
                .storage
                .as_ref()
                .map(|storage| storage.path.as_path()),
            Some(expected_storage_path.as_path())
        );

        let logging = config.logging.as_ref().unwrap();
        assert_eq!(logging.level.as_deref(), Some("info"));
        assert_eq!(logging.format, Some(LogFormat::Json));

        assert_eq!(config.routes.len(), 4);

        let openai = &config.routes[0];
        assert_eq!(openai.name.as_deref(), Some("openai-chat"));
        assert_eq!(openai.upstream.as_deref(), Some("https://api.openai.com"));
        assert_eq!(openai.mode, Some(RouteMode::PassthroughCache));
        assert_eq!(
            openai.body_oversize,
            Some(super::BodyOversizePolicy::BypassCache)
        );
        assert_eq!(openai.cache_miss, Some(super::CacheMissPolicy::Forward));
        assert_eq!(
            openai.match_.as_ref().unwrap().headers,
            vec!["Authorization", "X-Request-Id"]
        );
        assert_eq!(openai.match_.as_ref().unwrap().headers_ignore, vec!["Date"]);
        assert_eq!(openai.match_.as_ref().unwrap().body_json.len(), 3);
        assert_eq!(
            openai.redact.as_ref().unwrap().headers,
            vec!["Authorization"]
        );
        assert_eq!(
            openai.redact.as_ref().unwrap().body_json,
            vec!["$.api_key"]
        );
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
upstream = "http://127.0.0.1:1234"

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
    fn multiple_route_matchers_fail_fast() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:0"

[[routes]]
path_prefix = "/api"
path_exact = "/api/users"
upstream = "http://127.0.0.1:1234"
"#;

        let err = Config::from_toml_str(toml).unwrap_err();
        assert!(
            err.to_string()
                .contains("`path_prefix`, `path_exact`, and `path_regex` are mutually exclusive"),
            "err: {err}"
        );
    }

    #[test]
    fn overlapping_route_match_headers_fail_fast() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:0"

[[routes]]
path_prefix = "/api"
upstream = "http://127.0.0.1:1234"

[routes.match]
headers = ["Authorization"]
headers_ignore = ["authorization"]
"#;

        let err = Config::from_toml_str(toml).unwrap_err();
        assert!(
            err.to_string()
                .contains("`routes.match.headers` and `routes.match.headers_ignore` overlap"),
            "err: {err}"
        );
    }

    #[test]
    fn normalizes_route_paths_and_upstream_url() {
        let config = Config::from_toml_str(
            r#"
[proxy]
listen = "127.0.0.1:0"

[[routes]]
path_prefix = "api/v1/"
upstream = "https://api.openai.com/"
"#,
        )
        .unwrap();

        let route = &config.routes[0];
        assert_eq!(route.path_prefix.as_deref(), Some("/api/v1"));
        assert_eq!(route.upstream.as_deref(), Some("https://api.openai.com"));
    }

    #[test]
    fn upstream_with_path_or_query_is_rejected() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:0"

[[routes]]
path_prefix = "/api"
upstream = "https://api.openai.com/v1"
"#;

        let err = Config::from_toml_str(toml).unwrap_err();
        assert!(
            err.to_string()
                .contains("`upstream` URL must not include a path/query"),
            "err: {err}"
        );
    }

    #[test]
    fn admin_port_must_not_match_proxy_port() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:8080"
admin_port = 8080
"#;

        let err = Config::from_toml_str(toml).unwrap_err();
        assert!(
            err.to_string()
                .contains("`proxy.admin_port` (8080) must differ from `proxy.listen` port (8080)"),
            "err: {err}"
        );
    }

    #[test]
    fn proxy_max_body_bytes_must_be_positive() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:0"
max_body_bytes = 0
"#;

        let err = Config::from_toml_str(toml).unwrap_err();
        assert!(
            err.to_string()
                .contains("`proxy.max_body_bytes` must be greater than 0"),
            "err: {err}"
        );
    }

    #[test]
    fn tls_enabled_requires_cert_and_key() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:0"

[proxy.tls]
enabled = true
"#;

        let err = Config::from_toml_str(toml).unwrap_err();
        assert!(
            err.to_string()
                .contains("`proxy.tls.ca_cert` is required when `proxy.tls.enabled = true`"),
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
