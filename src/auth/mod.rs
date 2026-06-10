//! Z.AI Authentication
//!
//! Manages cookie/session persistence, sign generation, and token refresh
//! for the Z.AI web API. Cookies are captured from browser login and
//! stored in ~/.zair/auth.json.

use anyhow::{bail, Context, Result};
use md5::Digest;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

// ─── Constants ────────────────────────────────────────────────

/// Fixed signing secret extracted from chat.z.ai frontend JS
pub const SIGN_SECRET: &str = "8a1317a7468aa3ad86e997d08f3f31cb";

pub const ZAI_CHAT_URL: &str = "https://chat.z.ai";
pub const ZAI_API_BASE: &str = "https://chat.z.ai";

pub const X_EXP_GROUPS: &str = concat!(
    "na_android_config:exp:NA,na_4o_config:exp:4o_A,tts_config:exp:tts_config_a,",
    "na_glm4plus_config:exp:open,mainchat_server_app:exp:A,mobile_history_daycheck:exp:a,",
    "desktop_toolbar:exp:A,chat_drawing_server:exp:A,drawing_server_cogview:cogview4,",
    "app_welcome_v2:exp:A,chat_drawing_streamv2:exp:A,mainchat_rm_fc:exp:add,",
    "mainchat_dr:exp:open,chat_auto_entrance:exp:A,drawing_server_hi_dream:control:A,",
    "homepage_square:exp:close,assistant_recommend_prompt:exp:3,app_home_regular_user:exp:A,",
    "memory_common:exp:enable,mainchat_moe:exp:300,assistant_greet_user:exp:greet_user,",
    "app_welcome_personalize:exp:A,assistant_model_exp_group:exp:glm4.5,",
    "ai_wallet:exp:ai_wallet_enable"
);

/// Model ID -> assistant_id mapping for the web API
pub fn get_assistant_id(model: &str) -> &'static str {
    match model {
        "glm-4-plus" | "glm-4" => "65940acff94777010aa6b796",
        "glm-4-think" | "glm-4-zero" => "676411c38945bbc58a905d31",
        _ => "65940acff94777010aa6b796", // default
    }
}

// ─── Types ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZaiAuthState {
    pub cookie: String,
    pub user_agent: String,
    pub refresh_token: Option<String>,
    pub access_token: Option<String>,
    pub captured_at: i64,
}

// ─── Config Persistence ───────────────────────────────────────

/// Get the auth file path: ~/.zair/auth.json
pub fn auth_path() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/root"));
    home.join(".zair").join("auth.json")
}

/// Save auth state to disk
pub fn save_auth(state: &ZaiAuthState) -> Result<()> {
    let path = auth_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string_pretty(state)?;
    fs::write(&path, content)?;
    Ok(())
}

/// Load auth state from disk
pub fn load_auth() -> Option<ZaiAuthState> {
    let path = auth_path();
    if !path.exists() {
        return None;
    }
    fs::read_to_string(&path).ok().and_then(|content| {
        serde_json::from_str(&content).ok()
    })
}

/// Check if user is logged in
pub fn is_logged_in() -> bool {
    load_auth().map(|a| !a.cookie.is_empty()).unwrap_or(false)
}

// ─── Sign Generation ──────────────────────────────────────────

/// Generate the X-Sign, X-Nonce, X-Timestamp headers required by chat.z.ai
pub fn generate_sign() -> SignResult {
    let e = chrono::Utc::now().timestamp_millis();
    let a = e.to_string();
    let digits: Vec<u32> = a.chars().filter_map(|c| c.to_digit(10)).collect();
    let t = digits.len();
    let sum: u32 = digits.iter().sum();
    let i = sum - digits[t - 2];
    let a_val = i % 10;

    // Replace the second-to-last digit with a_val
    let timestamp = format!("{}{}{}", &a[..t - 2], a_val, &a[t - 1..]);

    let nonce = uuid::Uuid::new_v4().to_string().replace('-', "");

    // MD5(timestamp-nonce-secret)
    let input = format!("{}-{}-{}", timestamp, nonce, SIGN_SECRET);
    let hash = md5::Md5::default().chain_update(input.as_bytes()).finalize();
    let sign = format!("{:x}", hash);

    SignResult {
        timestamp,
        nonce,
        sign,
    }
}

#[derive(Debug, Clone)]
pub struct SignResult {
    pub timestamp: String,
    pub nonce: String,
    pub sign: String,
}

// ─── Cookie Parsing ───────────────────────────────────────────

/// Parse a cookie string into a HashMap
pub fn parse_cookie_string(cookie: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for part in cookie.split(';') {
        let trimmed = part.trim();
        if let Some(eq_idx) = trimmed.find('=') {
            let key = trimmed[..eq_idx].trim().to_string();
            let value = trimmed[eq_idx + 1..].trim().to_string();
            map.insert(key, value);
        }
    }
    map
}

/// Extract refresh token from cookie string
pub fn extract_refresh_token(cookie: &str) -> Option<String> {
    let cookies = parse_cookie_string(cookie);
    for name in &[
        "chatglm_refresh_token",
        "refresh_token",
        "auth_refresh_token",
        "glm_refresh_token",
        "zai_refresh_token",
    ] {
        if let Some(val) = cookies.get(*name) {
            return Some(val.clone());
        }
    }
    None
}

/// Extract access token from cookie string
pub fn extract_access_token(cookie: &str) -> Option<String> {
    let cookies = parse_cookie_string(cookie);
    for name in &[
        "chatglm_token",
        "access_token",
        "auth_token",
        "glm_token",
        "zai_token",
        "token",
    ] {
        if let Some(val) = cookies.get(*name) {
            return Some(val.clone());
        }
    }
    None
}

// ─── Token Refresh ────────────────────────────────────────────

/// Refresh the access token using the refresh token
pub async fn refresh_access_token(refresh_token: &str) -> Result<String> {
    let sign = generate_sign();
    let device_id = uuid::Uuid::new_v4().to_string().replace('-', "");
    let request_id = uuid::Uuid::new_v4().to_string().replace('-', "");

    let client = reqwest::Client::new();
    let res = client
        .post(format!("{}/chatglm/user-api/user/refresh", ZAI_API_BASE))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", refresh_token))
        .header("App-Name", "chatglm")
        .header("X-App-Platform", "pc")
        .header("X-App-Version", "0.0.1")
        .header("X-Device-Id", &device_id)
        .header("X-Request-Id", &request_id)
        .header("X-Sign", &sign.sign)
        .header("X-Nonce", &sign.nonce)
        .header("X-Timestamp", &sign.timestamp)
        .json(&serde_json::json!({}))
        .send()
        .await
        .context("Failed to send refresh token request")?;

    if !res.status().is_success() {
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        bail!("Token refresh failed ({}): {}", status, text);
    }

    let data: serde_json::Value = res.json().await?;
    let access_token = data["result"]["access_token"]
        .as_str()
        .or_else(|| data["result"]["accessToken"].as_str())
        .or_else(|| data["accessToken"].as_str())
        .context("No accessToken in refresh response")?;

    Ok(access_token.to_string())
}

// ─── Tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_generation() {
        let result = generate_sign();
        assert!(!result.timestamp.is_empty());
        assert!(!result.nonce.is_empty());
        assert!(result.sign.len() == 32); // MD5 hex digest
    }

    #[test]
    fn test_parse_cookie() {
        let cookie = "chatglm_token=abc123; chatglm_refresh_token=xyz789; path=/";
        let map = parse_cookie_string(cookie);
        assert_eq!(map.get("chatglm_token"), Some(&"abc123".to_string()));
        assert_eq!(map.get("chatglm_refresh_token"), Some(&"xyz789".to_string()));
    }

    #[test]
    fn test_extract_tokens() {
        let cookie = "chatglm_token=access123; chatglm_refresh_token=refresh456";
        assert_eq!(extract_access_token(cookie), Some("access123".to_string()));
        assert_eq!(extract_refresh_token(cookie), Some("refresh456".to_string()));
    }
}
