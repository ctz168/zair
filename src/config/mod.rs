//! Configuration management
//!
//! Handles loading/saving agent configuration from ~/.zair/config.json

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub agent: AgentConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub agent_id: String,
    pub nickname: String,
    pub server_url: String,
    pub data_dir: String,
    pub model: String,
    pub system_prompt: String,
    pub masters: Vec<String>,
    pub auto_accept_friends: bool,
    pub max_history_per_chat: usize,
    pub stream_chunk_size: usize,
    pub stream_chunk_delay_ms: u64,
    /// API key for open.bigmodel.cn (fallback when chat.z.ai is blocked by CDN)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,

    // ── Agent mode (glm-5.2 with general_agent flag) ──
    /// Default user name injected into the `variables` map as `{{USER_NAME}}`.
    /// Used when building the Agent-mode payload in `chat_web_api_agent`.
    #[serde(default = "default_user_name")]
    pub user_name: String,

    /// Extra variables to merge into the Agent payload's `variables` dict.
    /// Should be a JSON object mapping `"{{KEY}}"` -> value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variables: Option<serde_json::Value>,

    /// Hardcoded captcha_verify_param for Agent mode (short-term solution).
    /// Agent mode may trigger Z.AI's risk control, which requires a valid
    /// captcha token in the request. Long-term this should be fetched
    /// automatically from the browser session via CDP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captcha_verify_param: Option<String>,
}

fn default_user_name() -> String {
    "Wei Liu".to_string()
}

impl Default for AppConfig {
    fn default() -> Self {
        let data_dir = dirs::home_dir()
            .map(|p| p.join(".zair").to_string_lossy().to_string())
            .unwrap_or_else(|| "/root/.zair".to_string());

        Self {
            agent: AgentConfig {
                agent_id: format!("zair-{}", &uuid::Uuid::new_v4().to_string()[..8]),
                nickname: "ZAI Agent".to_string(),
                server_url: "https://aicq.online".to_string(),
                data_dir,
                model: "glm-4-plus".to_string(),
                system_prompt: "你是 ZAI Agent，一个由 Z.AI 驱动的智能助手。你可以流畅地与用户对话，回答问题，提供建议。\n当你收到消息时，请用友好、专业的方式回复。如果不确定，请诚实说明。\n支持中文和英文对话。".to_string(),
                masters: Vec::new(),
                auto_accept_friends: true,
                max_history_per_chat: 50,
                stream_chunk_size: 20,
                stream_chunk_delay_ms: 50,
                api_key: None,
                user_name: "Wei Liu".to_string(),
                variables: None,
                captcha_verify_param: None,
            },
        }
    }
}

impl AppConfig {
    /// Get the config file path: ~/.zair/config.json
    pub fn config_path() -> PathBuf {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/root"));
        home.join(".zair").join("config.json")
    }

    /// Load config from disk, or create default
    pub fn load() -> Result<Self> {
        let path = Self::config_path();
        if path.exists() {
            let content = fs::read_to_string(&path)
                .context("Failed to read config file")?;
            let config: AppConfig = serde_json::from_str(&content)
                .context("Failed to parse config JSON")?;
            Ok(config)
        } else {
            let config = AppConfig::default();
            config.save()?;
            Ok(config)
        }
    }

    /// Save config to disk
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self)?;
        fs::write(&path, content)?;
        Ok(())
    }
}
