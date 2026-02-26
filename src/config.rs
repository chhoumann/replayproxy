use std::{
    env,
    ffi::OsStr,
    fs, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Component, Path, PathBuf},
    str::FromStr,
};

use anyhow::bail;
use hyper::{Uri, header::HeaderName};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json_path::JsonPath;

use crate::session;

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
    #[serde(skip)]
    source_path: Option<PathBuf>,
}

impl Config {
    pub fn load(config_override: Option<&Path>) -> anyhow::Result<Self> {
        let mut attempted_sources = Vec::new();
        let has_override = config_override.is_some();

        for (index, raw_path) in config_candidate_paths(config_override)
            .into_iter()
            .enumerate()
        {
            let source = config_source_label(index, has_override);
            let resolved_path = match expand_tilde(&raw_path) {
                Ok(path) => path,
                Err(err) => {
                    attempted_sources.push(source);
                    let reason = if err.to_string().contains("HOME is not set") {
                        "HOME is not set"
                    } else {
                        "path expansion failed"
                    };
                    return Err(anyhow::anyhow!(
                        "resolve config path for {source}: {reason}\n{}",
                        format_attempted_sources(&attempted_sources)
                    ));
                }
            };
            attempted_sources.push(source);

            let toml = match fs::read_to_string(&resolved_path) {
                Ok(toml) => toml,
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(err) => {
                    return Err(anyhow::anyhow!(
                        "read config from {source}: {err}\n{}",
                        format_attempted_sources(&attempted_sources)
                    ));
                }
            };

            return Self::from_toml_str(&toml)
                .map(|mut config| {
                    config.source_path = Some(resolved_path);
                    config
                })
                .map_err(|err| {
                    anyhow::anyhow!(
                        "parse config from {source}: {}\n{}",
                        summarize_config_parse_error(&err),
                        format_attempted_sources(&attempted_sources)
                    )
                });
        }

        bail!(
            "unable to find a config file\n{}",
            format_attempted_sources(&attempted_sources)
        )
    }

    pub fn from_path(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = expand_tilde(path.as_ref())?;
        let toml = fs::read_to_string(&path)
            .map_err(|err| anyhow::anyhow!("read config {}: {err}", path.display()))?;
        Self::from_toml_str(&toml)
            .map(|mut config| {
                config.source_path = Some(path.clone());
                config
            })
            .map_err(|err| anyhow::anyhow!("parse config {}: {err}", path.display()))
    }

    pub fn from_toml_str(toml: &str) -> anyhow::Result<Self> {
        toml.parse()
    }

    pub fn source_path(&self) -> Option<&Path> {
        self.source_path.as_deref()
    }

    pub fn apply_active_session_override(
        &mut self,
        active_session_override: Option<&str>,
    ) -> anyhow::Result<()> {
        let Some(active_session_override) = active_session_override else {
            return Ok(());
        };
        let Some(storage) = self.storage.as_mut() else {
            return Ok(());
        };

        session::validate_session_name(active_session_override)
            .map_err(|err| anyhow::anyhow!("invalid `--active-session`: {err}"))?;
        storage.active_session = Some(active_session_override.to_owned());
        Ok(())
    }

    fn normalize_and_validate(&mut self) -> anyhow::Result<()> {
        self.proxy.normalize_and_validate()?;

        if let Some(storage) = self.storage.as_mut() {
            storage.normalize_and_validate()?;
        }

        if let Some(defaults) = self.defaults.as_mut()
            && let Some(redact) = defaults.redact.as_mut()
        {
            redact.normalize_and_validate(None, "defaults.redact")?;
        }

        let defaults_redact = self
            .defaults
            .as_ref()
            .and_then(|defaults| defaults.redact.as_ref())
            .cloned();

        for (idx, route) in self.routes.iter_mut().enumerate() {
            route.normalize_and_validate(idx)?;
            route.redact = RedactConfig::merge(defaults_redact.as_ref(), route.redact.as_ref());
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

fn config_source_label(index: usize, has_override: bool) -> &'static str {
    if has_override {
        return "cli --config override";
    }

    match index {
        0 => "project ./replayproxy.toml",
        1 => "home ~/.replayproxy/config.toml",
        _ => "unknown config source",
    }
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

fn format_attempted_sources(attempted_sources: &[&str]) -> String {
    if attempted_sources.is_empty() {
        return "attempted config sources: (none)".to_string();
    }

    let mut message = String::from("attempted config sources:");
    for source in attempted_sources {
        message.push_str("\n- ");
        message.push_str(source);
    }
    message
}

fn summarize_config_parse_error(err: &anyhow::Error) -> &'static str {
    if err.to_string().starts_with("parse config TOML:") {
        "invalid TOML syntax"
    } else {
        "invalid configuration values"
    }
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
    pub admin_bind: Option<IpAddr>,
    #[serde(default)]
    pub admin_api_token: Option<String>,
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

fn loopback_for_addr_family(addr: SocketAddr) -> IpAddr {
    if addr.is_ipv4() {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    }
}

fn normalize_unspecified_to_loopback(ip: IpAddr) -> IpAddr {
    if !ip.is_unspecified() {
        return ip;
    }

    match ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
    }
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
    pub fn admin_bind_ip(&self) -> Option<IpAddr> {
        self.admin_port.map(|_| {
            self.admin_bind
                .unwrap_or_else(|| loopback_for_addr_family(self.listen))
        })
    }

    pub fn admin_connect_ip(&self) -> Option<IpAddr> {
        self.admin_bind_ip().map(normalize_unspecified_to_loopback)
    }

    fn normalize_and_validate(&mut self) -> anyhow::Result<()> {
        if self.admin_port.is_none() {
            if self.admin_bind.is_some() {
                bail!("`proxy.admin_bind` requires `proxy.admin_port`");
            }
            if self.admin_api_token.is_some() {
                bail!("`proxy.admin_api_token` requires `proxy.admin_port`");
            }
        }

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

        if let Some(token) = self.admin_api_token.as_ref()
            && token.trim().is_empty()
        {
            bail!("`proxy.admin_api_token` must not be empty");
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

        if let Some(active_session) = self.active_session.as_ref() {
            session::validate_session_name(active_session)
                .map_err(|err| anyhow::anyhow!("invalid `storage.active_session`: {err}"))?;
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
    #[serde(default)]
    pub placeholder: Option<String>,
}

impl RedactConfig {
    fn normalize_and_validate(
        &mut self,
        route_name: Option<&str>,
        config_path: &str,
    ) -> anyhow::Result<()> {
        normalize_redact_headers(
            &mut self.headers,
            route_name,
            &format!("{config_path}.headers"),
        )?;
        normalize_redact_body_json(
            &mut self.body_json,
            route_name,
            &format!("{config_path}.body_json"),
        )?;
        normalize_redact_placeholder(
            &mut self.placeholder,
            route_name,
            &format!("{config_path}.placeholder"),
        )?;
        Ok(())
    }

    fn merge(defaults: Option<&Self>, route: Option<&Self>) -> Option<Self> {
        let mut headers = Vec::new();
        let mut body_json = Vec::new();
        let placeholder = route
            .and_then(|config| config.placeholder.as_ref())
            .or_else(|| defaults.and_then(|config| config.placeholder.as_ref()))
            .cloned();

        if let Some(defaults) = defaults {
            append_unique_header_names(&mut headers, &defaults.headers);
            append_unique_strings(&mut body_json, &defaults.body_json);
        }
        if let Some(route) = route {
            append_unique_header_names(&mut headers, &route.headers);
            append_unique_strings(&mut body_json, &route.body_json);
        }

        if headers.is_empty() && body_json.is_empty() {
            None
        } else {
            Some(Self {
                headers,
                body_json,
                placeholder,
            })
        }
    }
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

        if let Some(redact) = self.redact.as_mut() {
            redact.normalize_and_validate(Some(route_name.as_str()), "routes.redact")?;
        }
        if let Some(rate_limit) = self.rate_limit.as_ref() {
            rate_limit.validate(&route_name)?;
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

fn normalize_redact_headers(
    headers: &mut Vec<String>,
    route_name: Option<&str>,
    config_path: &str,
) -> anyhow::Result<()> {
    let mut normalized = Vec::new();
    for header in headers.drain(..) {
        let trimmed = header.trim();
        if trimmed.is_empty() {
            return Err(redact_error(
                route_name,
                format!("`{config_path}` entries must not be empty"),
            ));
        }

        HeaderName::from_bytes(trimmed.as_bytes()).map_err(|err| {
            redact_error(
                route_name,
                format!("invalid `{config_path}` header `{trimmed}`: {err}"),
            )
        })?;

        let canonical = trimmed.to_ascii_lowercase();
        if !normalized.iter().any(|existing| existing == &canonical) {
            normalized.push(canonical);
        }
    }
    *headers = normalized;
    Ok(())
}

fn normalize_redact_body_json(
    body_json: &mut Vec<String>,
    route_name: Option<&str>,
    config_path: &str,
) -> anyhow::Result<()> {
    let mut normalized = Vec::new();
    for expression in body_json.drain(..) {
        let trimmed = expression.trim();
        if trimmed.is_empty() {
            return Err(redact_error(
                route_name,
                format!("`{config_path}` entries must not be empty"),
            ));
        }

        JsonPath::parse(trimmed).map_err(|err| {
            redact_error(
                route_name,
                format!("invalid `{config_path}` expression `{trimmed}`: {err}"),
            )
        })?;

        if !normalized.iter().any(|existing| existing == trimmed) {
            normalized.push(trimmed.to_owned());
        }
    }
    *body_json = normalized;
    Ok(())
}

fn normalize_redact_placeholder(
    placeholder: &mut Option<String>,
    route_name: Option<&str>,
    config_path: &str,
) -> anyhow::Result<()> {
    let Some(current_value) = placeholder.as_mut() else {
        return Ok(());
    };

    let trimmed = current_value.trim();
    if trimmed.is_empty() {
        return Err(redact_error(
            route_name,
            format!("`{config_path}` must not be empty"),
        ));
    }

    *current_value = trimmed.to_owned();
    Ok(())
}

fn append_unique_header_names(target: &mut Vec<String>, values: &[String]) {
    for value in values {
        if !target.iter().any(|existing| existing == value) {
            target.push(value.clone());
        }
    }
}

fn append_unique_strings(target: &mut Vec<String>, values: &[String]) {
    for value in values {
        if !target.iter().any(|existing| existing == value) {
            target.push(value.clone());
        }
    }
}

fn redact_error(route_name: Option<&str>, message: String) -> anyhow::Error {
    if let Some(route_name) = route_name {
        anyhow::anyhow!("{route_name}: {message}")
    } else {
        anyhow::anyhow!("{message}")
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
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

impl FromStr for RouteMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "record" => Ok(Self::Record),
            "replay" => Ok(Self::Replay),
            "passthrough-cache" => Ok(Self::PassthroughCache),
            _ => bail!("invalid mode `{s}`; expected one of: record, replay, passthrough-cache"),
        }
    }
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CacheMissPolicy {
    Forward,
    Error,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum QueryMatchMode {
    #[default]
    Exact,
    Subset,
    Ignore,
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
    #[serde(default)]
    pub queue_depth: Option<usize>,
    #[serde(default, alias = "timeout")]
    pub timeout_ms: Option<u64>,
}

impl RateLimitConfig {
    fn validate(&self, route_name: &str) -> anyhow::Result<()> {
        if self.requests_per_second == 0 {
            bail!("{route_name}: `routes.rate_limit.requests_per_second` must be greater than 0");
        }
        if let Some(burst) = self.burst
            && burst == 0
        {
            bail!("{route_name}: `routes.rate_limit.burst` must be greater than 0");
        }
        if let Some(queue_depth) = self.queue_depth
            && queue_depth == 0
        {
            bail!("{route_name}: `routes.rate_limit.queue_depth` must be greater than 0");
        }
        if let Some(timeout_ms) = self.timeout_ms
            && timeout_ms == 0
        {
            bail!("{route_name}: `routes.rate_limit.timeout_ms` must be greater than 0");
        }

        Ok(())
    }
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
        env, fs,
        net::{IpAddr, Ipv4Addr},
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{Config, LogFormat, RouteMode, WebSocketRecordingMode};
    use tempfile::tempdir;

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
placeholder = "<REDACTED>"

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
queue_depth = 64
timeout_ms = 1500

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
            vec!["authorization", "x-api-key", "cookie"]
        );
        assert_eq!(openai.redact.as_ref().unwrap().body_json, vec!["$.api_key"]);
        assert_eq!(
            openai.redact.as_ref().unwrap().placeholder.as_deref(),
            Some("<REDACTED>")
        );
        assert!(openai.streaming.as_ref().unwrap().preserve_timing);
        assert_eq!(openai.rate_limit.as_ref().unwrap().requests_per_second, 10);
        assert_eq!(openai.rate_limit.as_ref().unwrap().burst, Some(20));
        assert_eq!(openai.rate_limit.as_ref().unwrap().queue_depth, Some(64));
        assert_eq!(openai.rate_limit.as_ref().unwrap().timeout_ms, Some(1500));

        let anthropic = &config.routes[1];
        assert_eq!(
            anthropic.redact.as_ref().unwrap().headers,
            vec!["authorization", "x-api-key", "cookie"]
        );
        assert!(anthropic.redact.as_ref().unwrap().body_json.is_empty());
        assert_eq!(
            anthropic.redact.as_ref().unwrap().placeholder.as_deref(),
            Some("<REDACTED>")
        );
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
    fn invalid_defaults_redact_body_json_path_fails_fast() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:0"

[defaults.redact]
body_json = ["$["]

[[routes]]
path_prefix = "/api"
upstream = "http://127.0.0.1:1234"
"#;

        let err = Config::from_toml_str(toml).unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid `defaults.redact.body_json` expression"),
            "err: {err}"
        );
    }

    #[test]
    fn merges_default_redaction_with_route_overrides() {
        let config = Config::from_toml_str(
            r#"
[proxy]
listen = "127.0.0.1:0"

[defaults.redact]
headers = ["Authorization", "X-Api-Key"]
body_json = ["$.api_key"]
placeholder = "<DEFAULT-MASK>"

[[routes]]
path_prefix = "/inherited"
upstream = "https://api.example.com"

[[routes]]
path_prefix = "/override"
upstream = "https://api.example.com"

[routes.redact]
headers = ["Cookie", "authorization"]
body_json = ["$.token", "$.api_key"]
placeholder = "<ROUTE-MASK>"
"#,
        )
        .unwrap();

        let inherited = config.routes[0]
            .redact
            .as_ref()
            .expect("inherited route redaction should be present");
        assert_eq!(inherited.headers, vec!["authorization", "x-api-key"]);
        assert_eq!(inherited.body_json, vec!["$.api_key"]);
        assert_eq!(inherited.placeholder.as_deref(), Some("<DEFAULT-MASK>"));

        let override_route = config.routes[1]
            .redact
            .as_ref()
            .expect("override route redaction should be present");
        assert_eq!(
            override_route.headers,
            vec!["authorization", "x-api-key", "cookie"]
        );
        assert_eq!(override_route.body_json, vec!["$.api_key", "$.token"]);
        assert_eq!(override_route.placeholder.as_deref(), Some("<ROUTE-MASK>"));
    }

    #[test]
    fn empty_redaction_placeholder_fails_fast() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:0"

[[routes]]
path_prefix = "/api"
upstream = "http://127.0.0.1:1234"

[routes.redact]
headers = ["authorization"]
placeholder = "   "
"#;

        let err = Config::from_toml_str(toml).unwrap_err();
        assert!(
            err.to_string()
                .contains("`routes.redact.placeholder` must not be empty"),
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
    fn rate_limit_values_must_be_positive() {
        for (snippet, expected_error) in [
            (
                "requests_per_second = 0",
                "`routes.rate_limit.requests_per_second` must be greater than 0",
            ),
            (
                "requests_per_second = 10\nburst = 0",
                "`routes.rate_limit.burst` must be greater than 0",
            ),
            (
                "requests_per_second = 10\nqueue_depth = 0",
                "`routes.rate_limit.queue_depth` must be greater than 0",
            ),
            (
                "requests_per_second = 10\ntimeout_ms = 0",
                "`routes.rate_limit.timeout_ms` must be greater than 0",
            ),
        ] {
            let toml = format!(
                r#"
[proxy]
listen = "127.0.0.1:0"

[[routes]]
path_prefix = "/api"
upstream = "http://127.0.0.1:1234"

[routes.rate_limit]
{snippet}
"#
            );
            let err = Config::from_toml_str(&toml).unwrap_err();
            assert!(
                err.to_string().contains(expected_error),
                "snippet `{snippet}` error did not include `{expected_error}`: {err}"
            );
        }
    }

    #[test]
    fn rate_limit_timeout_alias_is_supported() {
        let config = Config::from_toml_str(
            r#"
[proxy]
listen = "127.0.0.1:0"

[[routes]]
path_prefix = "/api"
upstream = "http://127.0.0.1:1234"

[routes.rate_limit]
requests_per_second = 10
timeout = 250
"#,
        )
        .unwrap();

        let rate_limit = config.routes[0]
            .rate_limit
            .as_ref()
            .expect("route rate limit should be present");
        assert_eq!(rate_limit.timeout_ms, Some(250));
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
    fn admin_bind_defaults_to_loopback_when_admin_port_set() {
        let config = Config::from_toml_str(
            r#"
[proxy]
listen = "0.0.0.0:8080"
admin_port = 8081
"#,
        )
        .unwrap();

        assert_eq!(
            config.proxy.admin_bind_ip(),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(
            config.proxy.admin_connect_ip(),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
    }

    #[test]
    fn admin_connect_ip_uses_loopback_when_admin_bind_is_unspecified() {
        let config = Config::from_toml_str(
            r#"
[proxy]
listen = "127.0.0.1:8080"
admin_port = 8081
admin_bind = "0.0.0.0"
"#,
        )
        .unwrap();

        assert_eq!(
            config.proxy.admin_bind_ip(),
            Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        );
        assert_eq!(
            config.proxy.admin_connect_ip(),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
    }

    #[test]
    fn admin_bind_requires_admin_port() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:8080"
admin_bind = "127.0.0.1"
"#;

        let err = Config::from_toml_str(toml).unwrap_err();
        assert!(
            err.to_string()
                .contains("`proxy.admin_bind` requires `proxy.admin_port`"),
            "err: {err}"
        );
    }

    #[test]
    fn admin_api_token_requires_admin_port() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:8080"
admin_api_token = "secret"
"#;

        let err = Config::from_toml_str(toml).unwrap_err();
        assert!(
            err.to_string()
                .contains("`proxy.admin_api_token` requires `proxy.admin_port`"),
            "err: {err}"
        );
    }

    #[test]
    fn admin_api_token_must_not_be_empty() {
        let toml = r#"
[proxy]
listen = "127.0.0.1:8080"
admin_port = 8081
admin_api_token = "   "
"#;

        let err = Config::from_toml_str(toml).unwrap_err();
        assert!(
            err.to_string()
                .contains("`proxy.admin_api_token` must not be empty"),
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
    fn load_errors_include_attempted_sources_without_raw_paths() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        let missing_path = PathBuf::from(format!("/tmp/replayproxy-missing-{unique}.toml"));

        let err = Config::load(Some(missing_path.as_path())).unwrap_err();
        assert!(
            err.to_string().contains("attempted config sources:"),
            "err: {err}"
        );
        assert!(
            err.to_string().contains("cli --config override"),
            "err: {err}"
        );
        assert!(
            !err.to_string()
                .contains(&missing_path.display().to_string()),
            "err leaked raw path: {err}"
        );
    }

    #[test]
    fn load_parse_errors_do_not_echo_secret_like_values() {
        let temp = tempdir().expect("tempdir should create");
        let config_path = temp.path().join("replayproxy.toml");
        let secret = "sk_live_super_secret_value";

        fs::write(
            &config_path,
            format!(
                r#"
[proxy]
listen = "127.0.0.1:0"
api_token = {secret}
"#
            ),
        )
        .expect("config file should be written");

        let err = Config::load(Some(config_path.as_path())).unwrap_err();
        assert!(
            err.to_string()
                .contains("parse config from cli --config override: invalid TOML syntax"),
            "err: {err}"
        );
        assert!(
            !err.to_string().contains(secret),
            "err leaked secret-like content: {err}"
        );
        assert!(
            !err.to_string().contains(&config_path.display().to_string()),
            "err leaked raw config path: {err}"
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

        config
            .apply_active_session_override(Some("from-cli"))
            .unwrap();

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

        config
            .apply_active_session_override(Some("from-cli"))
            .unwrap();
        assert!(config.storage.is_none());
    }

    #[test]
    fn rejects_storage_active_session_with_path_separator() {
        let err = Config::from_toml_str(
            r#"
[proxy]
listen = "127.0.0.1:0"

[storage]
path = "/tmp/replayproxy-tests"
active_session = "../prod"
"#,
        )
        .unwrap_err();

        assert!(
            err.to_string().contains(
                "invalid `storage.active_session`: session name cannot contain path separators"
            ),
            "err: {err}"
        );
    }

    #[test]
    fn apply_active_session_override_rejects_invalid_name() {
        let mut config = Config::from_toml_str(
            r#"
[proxy]
listen = "127.0.0.1:0"

[storage]
path = "/tmp/replayproxy-tests"
active_session = "default"
"#,
        )
        .unwrap();

        let err = config
            .apply_active_session_override(Some("../prod"))
            .unwrap_err();
        assert!(
            err.to_string().contains(
                "invalid `--active-session`: session name cannot contain path separators"
            ),
            "err: {err}"
        );
    }
}
