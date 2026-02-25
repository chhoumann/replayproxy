use std::{fs, path::Path};

use anyhow::Context as _;
use serde::Deserialize;
use std::str::FromStr;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
}

impl Config {
    pub fn from_path(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let toml =
            fs::read_to_string(path).with_context(|| format!("read config {}", path.display()))?;
        Self::from_toml_str(&toml)
    }

    pub fn from_toml_str(toml: &str) -> anyhow::Result<Self> {
        toml.parse()
    }
}

impl FromStr for Config {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        toml::from_str(s).context("parse config TOML")
    }
}

#[derive(Debug, Deserialize)]
pub struct ProxyConfig {
    pub listen: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RouteConfig {
    pub path_prefix: String,
    pub upstream: String,
}
