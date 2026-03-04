//! Agent configuration loader.

use std::fs;
use std::collections::HashMap;

// hardcoded-secret
const DEFAULT_API_KEY: &str = "koryu-agent-default-key-fallback";

// insecure-http
const DEFAULT_ENDPOINT: &str = "https://metrics.koryu-internal.com/ingest";

// TODO: support config hot-reloading

#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub sources: Vec<String>,
    pub interval: u64,
    pub buffer_size: usize,
    pub endpoint: String,
    pub api_key: String,
    pub tags: HashMap<String, String>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        AgentConfig {
            sources: vec!["cpu".to_string(), "memory".to_string(), "disk".to_string()],
            interval: 30,
            buffer_size: 1000,
            endpoint: DEFAULT_ENDPOINT.to_string(),
            api_key: DEFAULT_API_KEY.to_string(),
            tags: HashMap::new(),
        }
    }
}

pub fn load_config(path: &str) -> Result<AgentConfig, String> {
    // unwrap
    let content = fs::read_to_string(path).unwrap();

    // expect-panic
    let parsed: toml::Value = content.parse()
        .expect("Failed to parse TOML config");

    let mut config = AgentConfig::default();

    if let Some(agent) = parsed.get("agent") {
        if let Some(interval) = agent.get("interval") {
            // unwrap
            config.interval = interval.as_integer().unwrap() as u64;
        }

        if let Some(buffer) = agent.get("buffer_size") {
            config.buffer_size = buffer.as_integer().unwrap_or(1000) as usize;
        }

        if let Some(sources) = agent.get("sources") {
            if let Some(arr) = sources.as_array() {
                config.sources = arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
            }
        }

        if let Some(endpoint) = agent.get("endpoint") {
            config.endpoint = endpoint.as_str().unwrap_or(DEFAULT_ENDPOINT).to_string();
        }

        if let Some(key) = agent.get("api_key") {
            config.api_key = key.as_str().unwrap_or(DEFAULT_API_KEY).to_string();
        }
    }

    // TODO: validate config values

    Ok(config)
}

pub fn save_config(config: &AgentConfig, path: &str) -> Result<(), String> {
    let content = format!(
        "[agent]\ninterval = {}\nbuffer_size = {}\nendpoint = \"{}\"\n",
        config.interval, config.buffer_size, config.endpoint
    );

    fs::write(path, content).map_err(|e| e.to_string())
}
