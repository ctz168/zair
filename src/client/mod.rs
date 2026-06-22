//! Z.AI HTTP Client
//!
//! Uses browser-captured cookies to call the chat.z.ai API directly.
//! Supports SSE streaming with thinking content extraction,
//! token refresh, and conversation management.
//! Also supports the open.bigmodel.cn API as a fallback when
//! chat.z.ai is blocked by CDN.

use anyhow::{bail, Context, Result};
use chrono::{Datelike, Local};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::auth::{
    self, extract_access_token, extract_refresh_token, generate_sign, refresh_access_token,
    ZaiAuthState, ZAI_API_BASE, X_EXP_GROUPS,
};
use crate::config::AppConfig;

/// Z.AI Open API base URL (not subject to CDN blocking)
const ZAI_OPEN_API_BASE: &str = "https://open.bigmodel.cn/api/paas";

// ─── Types ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone)]
pub struct ChatResult {
    pub text: String,
    pub conversation_id: String,
    pub thinking: String,
}

/// Callback for streaming text output: (delta_text, is_thinking)
pub type StreamCallback = Box<dyn Fn(&str, bool) + Send + Sync>;

// ─── Client ───────────────────────────────────────────────────

pub struct ZaiClient {
    config: AppConfig,
    auth: Arc<Mutex<Option<ZaiAuthState>>>,
    access_token: Arc<Mutex<Option<String>>>,
    device_id: String,
    conversation_map: Arc<Mutex<HashMap<String, String>>>,
    http_client: reqwest::Client,
    /// API key for open.bigmodel.cn (set via ZAI_API_KEY env or config)
    api_key: Option<String>,
    /// Captcha verify param for Agent mode (glm-5.2 + general_agent).
    /// Short-term: read from env `ZAI_CAPTCHA_PARAM` or config `agent.captcha_verify_param`.
    /// Long-term: should be refreshed from browser via CDP when risk control triggers.
    captcha_verify_param: Arc<Mutex<Option<String>>>,
}

impl ZaiClient {
    pub fn new(config: AppConfig) -> Self {
        let auth = auth::load_auth();
        let access_token = auth.as_ref().and_then(|a| a.access_token.clone());
        let device_id = uuid::Uuid::new_v4().to_string().replace('-', "");

        // Try to get API key from env var, then config
        let api_key = std::env::var("ZAI_API_KEY")
            .ok()
            .or_else(|| config.agent.api_key.clone());

        // Captcha verify param: env overrides config
        let captcha_verify_param = std::env::var("ZAI_CAPTCHA_PARAM")
            .ok()
            .or_else(|| config.agent.captcha_verify_param.clone());

        Self {
            config,
            auth: Arc::new(Mutex::new(auth)),
            access_token: Arc::new(Mutex::new(access_token)),
            device_id,
            conversation_map: Arc::new(Mutex::new(HashMap::new())),
            http_client: reqwest::Client::builder()
                .cookie_store(true)
                .build()
                .expect("Failed to create HTTP client"),
            api_key,
            captcha_verify_param: Arc::new(Mutex::new(captcha_verify_param)),
        }
    }

    /// Update the captcha_verify_param at runtime.
    ///
    /// Call this when the browser session refreshes the captcha token,
    /// or when the API returns a captcha challenge response.
    pub async fn set_captcha_verify_param(&self, param: impl Into<String>) {
        let mut g = self.captcha_verify_param.lock().await;
        *g = Some(param.into());
    }

    /// Clear the cached captcha_verify_param (e.g. when it expires).
    pub async fn clear_captcha_verify_param(&self) {
        let mut g = self.captcha_verify_param.lock().await;
        *g = None;
    }

    /// Read the current captcha_verify_param (if any).
    async fn get_captcha_verify_param(&self) -> Option<String> {
        self.captcha_verify_param.lock().await.clone()
    }

    /// Public read accessor for captcha_verify_param (used by main.rs to
    /// decide whether to launch the browser for a fresh token).
    pub async fn get_captcha_verify_param_owned(&self) -> Option<String> {
        self.captcha_verify_param.lock().await.clone()
    }

    /// Whether a given model name should use Agent mode (general_agent flag).
    ///
    /// Agent mode is enabled for `glm-5.*` family models (e.g. `glm-5.2`).
    /// Other models keep using the legacy chat completions payload.
    pub fn is_agent_model(model: &str) -> bool {
        let m = model.to_ascii_lowercase();
        m == "glm-5.2"
            || m == "glm-5.1"
            || m == "glm-5-turbo"
            || m == "glm-5"
            || m.starts_with("glm-5.")
            || m.starts_with("glm-5-")
    }

    /// Ensure we have a valid access token, refreshing if necessary
    async fn ensure_access_token(&self) -> Result<String> {
        // Try cached access token
        {
            let token = self.access_token.lock().await;
            if let Some(t) = token.as_ref() {
                return Ok(t.clone());
            }
        }

        // Try extracting from cookie
        {
            let auth_guard = self.auth.lock().await;
            if let Some(auth_state) = auth_guard.as_ref() {
                if let Some(token) = extract_access_token(&auth_state.cookie) {
                    drop(auth_guard);
                    let mut access_token = self.access_token.lock().await;
                    *access_token = Some(token.clone());
                    return Ok(token);
                }

                // Try refresh token
                let refresh_token = extract_refresh_token(&auth_state.cookie)
                    .or_else(|| auth_state.refresh_token.clone());

                if let Some(rt) = refresh_token {
                    drop(auth_guard);
                    tracing::info!("Refreshing access token...");
                    let new_token = refresh_access_token(&rt).await?;

                    // Update persisted auth
                    {
                        let mut auth_guard = self.auth.lock().await;
                        if let Some(auth_state) = auth_guard.as_mut() {
                            auth_state.access_token = Some(new_token.clone());
                            let _ = auth::save_auth(auth_state);
                        }
                    }

                    let mut access_token = self.access_token.lock().await;
                    *access_token = Some(new_token.clone());
                    return Ok(new_token);
                }
            }
        }

        bail!("No access token available. Please run `zair login` first.")
    }

    /// Build request headers required by chat.z.ai
    fn build_headers(&self, access_token: &str, auth_state: &ZaiAuthState) -> reqwest::header::HeaderMap {
        let sign = generate_sign();
        let request_id = uuid::Uuid::new_v4().to_string().replace('-', "");

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("Content-Type", "application/json".parse().unwrap());
        headers.insert("Accept", "text/event-stream".parse().unwrap());
        headers.insert("Authorization", format!("Bearer {}", access_token).parse().unwrap());
        headers.insert("App-Name", "chatglm".parse().unwrap());
        headers.insert("Origin", ZAI_API_BASE.parse().unwrap());
        headers.insert("X-App-Platform", "pc".parse().unwrap());
        headers.insert("X-App-Version", "0.0.1".parse().unwrap());
        headers.insert("X-App-fr", "default".parse().unwrap());

        // Set User-Agent to match the headless Chrome that captured the captcha
        // token. Aliyun captcha binds tokens to the requesting UA, so zair MUST
        // send the same UA the headless browser used (HeadlessChrome, not the
        // regular Chrome UA from auth_state).
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/149.0.0.0 Safari/537.36";
        if let Ok(v) = ua.parse() {
            headers.insert("User-Agent", v);
        }
        headers.insert("X-Device-Id", self.device_id.parse().unwrap());
        headers.insert("X-Exp-Groups", X_EXP_GROUPS.parse().unwrap());
        headers.insert("X-Lang", "zh".parse().unwrap());
        headers.insert("X-Nonce", sign.nonce.parse().unwrap());
        headers.insert("X-Request-Id", request_id.parse().unwrap());
        headers.insert("X-Sign", sign.sign.parse().unwrap());
        headers.insert("X-Timestamp", sign.timestamp.parse().unwrap());
        headers.insert("Cookie", auth_state.cookie.parse().unwrap());

        headers
    }

    /// Chat with streaming - tries multiple API endpoints in order:
    /// 1. chat.z.ai (web API with cookie auth)
    /// 2. open.bigmodel.cn (Open API with API key, not blocked by CDN)
    /// 3. Browser fallback (in main.rs)
    pub async fn chat_stream(
        &self,
        message: &str,
        model: &str,
        conversation_id: Option<&str>,
        system_prompt: Option<&str>,
        callback: Option<StreamCallback>,
    ) -> Result<ChatResult> {
        // Build prompt with system message if provided
        let prompt = if let Some(sp) = system_prompt {
            format!("{}\n\nUser: {}", sp, message)
        } else {
            message.to_string()
        };

        let conv_id = conversation_id
            .map(|s| s.to_string())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string().replace('-', ""));

        // ── Strategy 0 (NEW): Agent mode for glm-5.* ──
        // Models in the glm-5.x family require the `features.flags=["general_agent"]`
        // payload and a `variables` map. We dispatch to a dedicated builder that
        // assembles that payload. If Agent mode fails (e.g. captcha challenge),
        // we still fall through to the regular web API + open API strategies.
        if Self::is_agent_model(model) {
            tracing::info!(
                "Model {} detected as Agent-mode, using chat_web_api_agent",
                model
            );
            let agent_result =
                self.chat_web_api_agent(&prompt, model, &conv_id, callback.as_ref()).await;
            match agent_result {
                Ok(result) => return Ok(result),
                Err(e) => {
                    let err_str = e.to_string();
                    tracing::warn!(
                        "Agent API failed ({}); falling through to regular strategies",
                        err_str
                    );
                    // If the failure looks like a captcha challenge, don't bother
                    // retrying the regular web API - it'll hit the same wall.
                    if err_str.contains("captcha") || err_str.contains("Captcha") {
                        bail!("Agent mode captcha challenge: {}", err_str);
                    }
                }
            }
        }

        // ── Strategy 1: Try chat.z.ai web API ──
        let web_api_result = self.chat_web_api(&prompt, model, &conv_id, callback.as_ref()).await;
        match web_api_result {
            Ok(result) => return Ok(result),
            Err(e) => {
                let err_str = e.to_string();
                // If it's a 401 (token expired) and we couldn't refresh, try other strategies
                // If it's 500/403/405/404, the API is blocked/broken, try Open API
                if err_str.contains("500") || err_str.contains("403") || err_str.contains("405")
                    || err_str.contains("404") || err_str.contains("No auth state")
                    || err_str.contains("No access token")
                {
                    tracing::info!("Web API failed ({}), trying Open API...", e);
                } else {
                    // For other errors (like connection refused), also try Open API
                    tracing::info!("Web API error ({}), trying Open API...", e);
                }
            }
        }

        // ── Strategy 2: Try open.bigmodel.cn API ──
        if let Some(ref api_key) = self.api_key {
            tracing::info!("Trying open.bigmodel.cn API (model={})...", model);
            match self.chat_open_api(&prompt, model, &conv_id, api_key, callback.as_ref()).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    tracing::warn!("Open API also failed: {}", e);
                }
            }
        } else {
            tracing::info!("No ZAI_API_KEY set, skipping Open API fallback");
        }

        // ── All API strategies failed ──
        bail!(
            "All API strategies failed. Set ZAI_API_KEY for open.bigmodel.cn access, or ensure web auth is valid."
        )
    }

    /// ── Agent mode (glm-5.2 + general_agent flag) ──
    ///
    /// Builds the Agent-mode payload, matching the real chat.z.ai browser payload:
    ///   {
    ///     "stream": true,
    ///     "model": "glm-5.2",
    ///     "messages": [{"role":"user","content":...}],
    ///     "signature_prompt": <same as content>,
    ///     "params": {},
    ///     "extra": {},
    ///     "features": {
    ///       "image_generation": false,
    ///       "web_search": false,
    ///       "auto_web_search": false,
    ///       "preview_mode": true,
    ///       "flags": ["general_agent"],
    ///       "vlm_tools_enable": false,
    ///       "vlm_web_search_enable": false,
    ///       "vlm_website_mode": false,
    ///       "enable_thinking": true,
    ///       "reasoning_effort": "max"
    ///     },
    ///     "variables": {
    ///       "{{USER_NAME}}": "...",
    ///       "{{USER_LOCATION}}": "Unknown",
    ///       "{{CURRENT_DATETIME}}": "YYYY-MM-DD HH:MM:SS",
    ///       "{{CURRENT_DATE}}": "YYYY-MM-DD",
    ///       "{{CURRENT_TIME}}": "HH:MM:SS",
    ///       "{{CURRENT_WEEKDAY}}": "Monday",
    ///       "{{CURRENT_TIMEZONE}}": "...",
    ///       "{{USER_LANGUAGE}}": "zh-CN"
    ///     },
    ///     "chat_id": "<uuid>",
    ///     "id": "<uuid>",
    ///     "current_user_message_id": "<uuid>",
    ///     "current_user_message_parent_id": null,
    ///     "background_tasks": {"title_generation": true, "tags_generation": true},
    ///     "captcha_verify_param": "<base64 token>"
    ///   }
    ///
    /// The SSE response is OpenAI-style (`choices[0].delta.content` /
    /// `choices[0].delta.reasoning_content`), handled by `process_stream_response`.
    async fn chat_web_api_agent(
        &self,
        prompt: &str,
        model: &str,
        conversation_id: &str,
        callback: Option<&StreamCallback>,
    ) -> Result<ChatResult> {
        let access_token = self.ensure_access_token().await?;
        let auth_guard = self.auth.lock().await;
        let auth_state = auth_guard
            .as_ref()
            .context("No auth state available for Agent mode")?
            .clone();
        drop(auth_guard);

        // ── Build variables (matches browser payload exactly) ──
        let user_name = self.config.agent.user_name.clone();
        let user_language = "zh-CN".to_string();

        // Use the local timezone (the host this binary runs on).
        // chrono::Local::now() respects TZ env / system timezone.
        let now = chrono::Local::now();
        let current_datetime = now.format("%Y-%m-%d %H:%M:%S").to_string();
        let current_date = now.format("%Y-%m-%d").to_string();
        let current_time = now.format("%H:%M:%S").to_string();
        let current_weekday = match now.weekday() {
            chrono::Weekday::Mon => "Monday",
            chrono::Weekday::Tue => "Tuesday",
            chrono::Weekday::Wed => "Wednesday",
            chrono::Weekday::Thu => "Thursday",
            chrono::Weekday::Fri => "Friday",
            chrono::Weekday::Sat => "Saturday",
            chrono::Weekday::Sun => "Sunday",
        };
        // Get timezone offset string (e.g. "+08:00")
        let current_timezone = now.format("%:z").to_string();

        let mut variables = serde_json::json!({
            "{{USER_NAME}}": user_name,
            "{{USER_LOCATION}}": "Unknown",
            "{{CURRENT_DATETIME}}": current_datetime,
            "{{CURRENT_DATE}}": current_date,
            "{{CURRENT_TIME}}": current_time,
            "{{CURRENT_WEEKDAY}}": current_weekday,
            "{{CURRENT_TIMEZONE}}": current_timezone,
            "{{USER_LANGUAGE}}": user_language,
        });
        // Merge any extras from config (config wins)
        if let Some(extra) = self.config.agent.variables.as_ref() {
            if let Some(obj) = extra.as_object() {
                for (k, v) in obj {
                    variables[k] = v.clone();
                }
            }
        }

        // Captcha verify param
        let captcha = self.get_captcha_verify_param().await.unwrap_or_default();

        // Generate the three UUIDs the browser sends
        let id = uuid::Uuid::new_v4().to_string();
        let current_user_message_id = uuid::Uuid::new_v4().to_string();
        // current_user_message_parent_id is null on first message of a conversation

        let body = serde_json::json!({
            "stream": true,
            "model": model,
            "messages": [{ "role": "user", "content": prompt }],
            "signature_prompt": prompt,
            "params": {},
            "extra": {},
            "features": {
                "image_generation": false,
                "web_search": false,
                "auto_web_search": false,
                "preview_mode": true,
                "flags": ["general_agent"],
                "vlm_tools_enable": false,
                "vlm_web_search_enable": false,
                "vlm_website_mode": false,
                "enable_thinking": true,
                "reasoning_effort": "max",
            },
            "variables": variables,
            "chat_id": conversation_id,
            "id": id,
            "current_user_message_id": current_user_message_id,
            "current_user_message_parent_id": serde_json::Value::Null,
            "background_tasks": {
                "title_generation": true,
                "tags_generation": true,
            },
            "captcha_verify_param": captcha,
        });

        let headers = self.build_headers(&access_token, &auth_state);
        let api_base = std::env::var("ZAI_PROXY_URL")
            .map(|u| u.trim_end_matches('/').to_string())
            .unwrap_or_else(|_| ZAI_API_BASE.to_string());
        let url = format!("{}/api/v2/chat/completions", api_base);
        tracing::info!(
            "Sending Agent request to {} (model={}, flags=[general_agent], thinking=max, captcha_len={})",
            url,
            model,
            captcha.len()
        );

        let res = self
            .http_client
            .post(&url)
            .headers(headers.clone())
            .header("X-FE-Version", "prod-fe-1.1.45")
            .header("Accept-Language", "zh-CN")
            .json(&body)
            .send()
            .await?;

        // Helper: detect captcha challenge in a response body.
        fn looks_like_captcha(text: &str) -> bool {
            text.contains("captcha")
                || text.contains("Captcha")
                || text.contains("CAPTCHA")
                || text.contains("verify_param")
                || text.contains("risk")
                || text.contains("\"code\":403")
        }

        // Handle 401 - token expired, refresh and retry
        if res.status() == reqwest::StatusCode::UNAUTHORIZED {
            tracing::info!("Agent API: token expired, refreshing...");
            {
                let mut access_token_guard = self.access_token.lock().await;
                *access_token_guard = None;
            }
            let new_token = self.ensure_access_token().await?;
            let new_headers = self.build_headers(&new_token, &auth_state);

            let retry_res = self
                .http_client
                .post(&url)
                .headers(new_headers)
                .header("X-FE-Version", "prod-fe-1.1.45")
                .header("Accept-Language", "zh-CN")
                .json(&body)
                .send()
                .await?;

            if !retry_res.status().is_success() {
                let status = retry_res.status();
                let text = retry_res.text().await.unwrap_or_default();
                let truncated: String = text.chars().take(400).collect();
                if looks_like_captcha(&text) {
                    bail!(
                        "Agent API captcha challenge after retry ({}): {}",
                        status,
                        truncated
                    );
                }
                bail!("Agent API error after retry ({}): {}", status, truncated);
            }

            return self.process_stream_response(retry_res, callback).await;
        }

        if !res.status().is_success() {
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            let truncated: String = text.chars().take(400).collect();
            if looks_like_captcha(&text) {
                bail!(
                    "Agent API captcha challenge ({}): {}",
                    status,
                    truncated
                );
            }
            bail!("Agent API error ({}): {}", status, truncated);
        }

        // Log response headers + first bytes for debugging Agent-mode SSE issues.
        {
            let status = res.status();
            let ct = res
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("(none)")
                .to_string();
            tracing::info!(
                "Agent response status={} content-type={}",
                status,
                ct
            );
        }

        self.process_stream_response(res, callback).await
    }

    /// Try chat.z.ai web API (v2 and legacy endpoints)
    async fn chat_web_api(
        &self,
        prompt: &str,
        model: &str,
        conversation_id: &str,
        callback: Option<&StreamCallback>,
    ) -> Result<ChatResult> {
        let access_token = self.ensure_access_token().await?;
        let auth_guard = self.auth.lock().await;
        let auth_state = auth_guard
            .as_ref()
            .context("No auth state available")?
            .clone();
        drop(auth_guard);

        // Build v2 API request body
        let body = serde_json::json!({
            "model": model,
            "messages": [{ "role": "user", "content": prompt }],
            "signature_prompt": prompt,
            "stream": true,
            "chat_request_id": conversation_id,
        });

        let headers = self.build_headers(&access_token, &auth_state);
        let api_base = std::env::var("ZAI_PROXY_URL")
            .map(|u| u.trim_end_matches('/').to_string())
            .unwrap_or_else(|_| ZAI_API_BASE.to_string());

        let url = format!("{}/api/v2/chat/completions", api_base);
        tracing::info!("Sending request to {} (model={})", url, model);

        let res = self
            .http_client
            .post(&url)
            .headers(headers.clone())
            .header("X-FE-Version", "prod-fe-1.1.45")
            .header("Accept-Language", "zh-CN")
            .json(&body)
            .send()
            .await?;

        // Handle 401 - token expired, refresh and retry
        if res.status() == reqwest::StatusCode::UNAUTHORIZED {
            tracing::info!("Token expired, refreshing...");
            {
                let mut access_token_guard = self.access_token.lock().await;
                *access_token_guard = None;
            }
            let new_token = self.ensure_access_token().await?;
            let new_headers = self.build_headers(&new_token, &auth_state);

            let retry_res = self
                .http_client
                .post(&url)
                .headers(new_headers)
                .header("X-FE-Version", "prod-fe-1.1.45")
                .header("Accept-Language", "zh-CN")
                .json(&body)
                .send()
                .await?;

            if !retry_res.status().is_success() {
                let status = retry_res.status();
                let text = retry_res.text().await.unwrap_or_default();
                let truncated: String = text.chars().take(200).collect();
                bail!("API error after retry ({}): {}", status, truncated);
            }

            return self.process_stream_response(retry_res, callback).await;
        }

        // Handle 404/405/500 - try legacy API
        let status = res.status();
        if status == reqwest::StatusCode::NOT_FOUND
            || status == reqwest::StatusCode::METHOD_NOT_ALLOWED
            || status == reqwest::StatusCode::INTERNAL_SERVER_ERROR
        {
            tracing::info!("V2 API returned {}, trying legacy API...", status);
            return self.chat_legacy(prompt, model, conversation_id, &headers, callback).await;
        }

        if !res.status().is_success() {
            let text = res.text().await.unwrap_or_default();
            let truncated: String = text.chars().take(200).collect();
            bail!("API error ({}): {}", status, truncated);
        }

        self.process_stream_response(res, callback).await
    }

    /// Try the legacy /chatglm/backend-api/assistant/stream endpoint
    async fn chat_legacy(
        &self,
        prompt: &str,
        model: &str,
        conversation_id: &str,
        headers: &reqwest::header::HeaderMap,
        callback: Option<&StreamCallback>,
    ) -> Result<ChatResult> {
        let assistant_id = auth::get_assistant_id(model);

        let body = serde_json::json!({
            "assistant_id": assistant_id,
            "conversation_id": conversation_id,
            "project_id": "",
            "chat_type": "user_chat",
            "meta_data": {
                "cogview": { "rm_label_watermark": false },
                "is_test": false,
                "input_question_type": "xxxx",
                "channel": "",
                "draft_id": "",
                "chat_mode": "zero",
                "is_networking": false,
                "quote_log_id": "",
                "platform": "pc",
            },
            "messages": [{
                "role": "user",
                "content": [{ "type": "text", "text": prompt }]
            }],
        });

        let api_base = std::env::var("ZAI_PROXY_URL")
            .map(|u| u.trim_end_matches('/').to_string())
            .unwrap_or_else(|_| ZAI_API_BASE.to_string());

        let url = format!("{}/chatglm/backend-api/assistant/stream", api_base);
        let res = self
            .http_client
            .post(&url)
            .headers(headers.clone())
            .json(&body)
            .send()
            .await?;

        if !res.status().is_success() {
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            let truncated: String = text.chars().take(200).collect();
            bail!("Legacy API error ({}): {}", status, truncated);
        }

        self.process_stream_response(res, callback).await
    }

    /// Chat via open.bigmodel.cn API (standard OpenAI-compatible API)
    /// Uses ZAI_API_KEY for authentication (not browser cookies).
    /// This endpoint is not subject to CDN blocking.
    async fn chat_open_api(
        &self,
        prompt: &str,
        model: &str,
        conversation_id: &str,
        api_key: &str,
        callback: Option<&StreamCallback>,
    ) -> Result<ChatResult> {
        // Map web model names to Open API model names
        let open_model = match model {
            "glm-4-plus" => "glm-4-plus",
            "glm-4" => "glm-4",
            "glm-4-think" | "glm-4-zero" => "glm-4-zero",
            _ => model,
        };

        let body = serde_json::json!({
            "model": open_model,
            "messages": [{ "role": "user", "content": prompt }],
            "stream": true,
            "request_id": conversation_id,
        });

        let url = format!("{}/v4/chat/completions", ZAI_OPEN_API_BASE);
        tracing::info!("Sending Open API request to {} (model={})", url, open_model);

        let res = self
            .http_client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", api_key))
            .json(&body)
            .send()
            .await?;

        if !res.status().is_success() {
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            let truncated: String = text.chars().take(200).collect();
            bail!("Open API error ({}): {}", status, truncated);
        }

        // Process the OpenAI-compatible SSE stream
        self.process_open_api_stream(res, callback).await
    }

    /// Process OpenAI-compatible SSE stream (from open.bigmodel.cn or Agent mode)
    async fn process_open_api_stream(
        &self,
        res: reqwest::Response,
        callback: Option<&StreamCallback>,
    ) -> Result<ChatResult> {
        let mut accumulated_content = String::new();
        let mut thinking_content = String::new();
        let mut current_mode = "text".to_string();
        let mut tag_buffer = String::new();
        let mut captured_conversation_id = String::new();

        let mut stream = res.bytes_stream();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("Failed to read stream chunk")?;
            let text = String::from_utf8_lossy(&chunk);

            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || !line.starts_with("data:") {
                    continue;
                }

                let data_str = line[5..].trim();
                if data_str == "[DONE]" || data_str.is_empty() {
                    continue;
                }

                let data: serde_json::Value = match serde_json::from_str(data_str) {
                    Ok(d) => d,
                    Err(_) => continue,
                };

                // Capture conversation/id if present
                if let Some(cid) = data["id"].as_str() {
                    captured_conversation_id = cid.to_string();
                }
                if let Some(cid) = data["conversation_id"].as_str() {
                    captured_conversation_id = cid.to_string();
                }
                if let Some(cid) = data["chat_id"].as_str() {
                    captured_conversation_id = cid.to_string();
                }

                // ── Thinking delta (reasoning_content) ──
                // Agent mode with enable_thinking=true streams the reasoning
                // trace as `choices[0].delta.reasoning_content`. Route it
                // directly to the thinking buffer (bypass <think>-tag parser).
                if let Some(thinking_delta) = Self::extract_thinking_delta(&data) {
                    thinking_content.push_str(&thinking_delta);
                    if let Some(cb) = callback.as_ref() {
                        cb(&thinking_delta, true);
                    }
                }

                // ── Text delta ──
                // OpenAI-compatible format: choices[0].delta.content
                let delta = if let Some(choices) = data["choices"].as_array() {
                    if let Some(choice) = choices.first() {
                        choice["delta"]["content"]
                            .as_str()
                            .unwrap_or("")
                            .to_string()
                    } else {
                        String::new()
                    }
                } else {
                    // Fallback to other formats
                    Self::extract_delta(&data)
                };

                if !delta.is_empty() {
                    Self::emit_delta_internal(
                        &delta,
                        &mut current_mode,
                        &mut tag_buffer,
                        &mut accumulated_content,
                        &mut thinking_content,
                        &callback,
                    );
                }
            }
        }

        // Flush remaining tag buffer
        if !tag_buffer.is_empty() {
            if current_mode == "thinking" {
                thinking_content.push_str(&tag_buffer);
                if let Some(cb) = callback.as_ref() {
                    cb(&tag_buffer, true);
                }
            } else {
                accumulated_content.push_str(&tag_buffer);
                if let Some(cb) = callback.as_ref() {
                    cb(&tag_buffer, false);
                }
            }
        }

        Ok(ChatResult {
            text: accumulated_content,
            conversation_id: captured_conversation_id,
            thinking: thinking_content,
        })
    }

    /// Process SSE stream response, extracting text and thinking content.
    ///
    /// This handler supports two chunk formats:
    ///   - Legacy GLM web format: each `data:` chunk repeats the FULL accumulated
    ///     content; we dedup against the previously-seen prefix.
    ///   - OpenAI delta format (Agent mode / glm-5.2): each chunk is a small NEW
    ///     piece of content; emit it directly without dedup.
    ///
    /// Thinking (reasoning) content is detected via `extract_thinking_delta`
    /// and routed to the thinking buffer (with `is_thinking=true` to the callback).
    async fn process_stream_response(
        &self,
        res: reqwest::Response,
        callback: Option<&StreamCallback>,
    ) -> Result<ChatResult> {
        let mut accumulated_content = String::new();
        let mut thinking_content = String::new();
        let mut current_mode = "text".to_string(); // "text" or "thinking"
        let mut captured_conversation_id = String::new();
        let mut tag_buffer = String::new();

        let mut stream = res.bytes_stream();
        let mut chunk_count = 0u32;
        let mut first_data_str: Option<String> = None;

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("Failed to read stream chunk")?;
            let text = String::from_utf8_lossy(&chunk);

            // Debug: log first 5 raw chunks so we can see what the server
            // actually returns when SSE appears empty.
            if chunk_count < 5 {
                let preview: String = text.chars().take(300).collect();
                tracing::info!(
                    "SSE raw chunk #{} ({} bytes): {:?}",
                    chunk_count,
                    chunk.len(),
                    preview
                );
                chunk_count += 1;
            }

            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || !line.starts_with("data:") {
                    continue;
                }

                let data_str = line[5..].trim();
                if data_str == "[DONE]" || data_str.is_empty() {
                    continue;
                }

                let data: serde_json::Value = match serde_json::from_str(data_str) {
                    Ok(d) => d,
                    Err(_) => continue,
                };

                // ── Detect embedded business-layer errors ──
                // Agent mode may return HTTP 200 with an SSE body that contains
                // a nested error object (e.g. captcha challenge). Common shapes:
                //   {"data":{"data":{"done":true,"error":{...}}}}
                //   {"error":{"code":"FRONTEND_CAPTCHA_REQUIRED", ...}}
                //   {"data":{"error":{...}}}
                if let Some(err_msg) = Self::detect_embedded_error(&data) {
                    tracing::warn!("Agent SSE embedded error: {}", err_msg);
                    bail!("{}", err_msg);
                }

                // Capture conversation ID (multiple field names tolerated)
                if let Some(cid) = data["conversation_id"].as_str() {
                    captured_conversation_id = cid.to_string();
                }
                if let Some(cid) = data["chat_id"].as_str() {
                    captured_conversation_id = cid.to_string();
                }
                if let Some(cid) = data["id"].as_str() {
                    captured_conversation_id = cid.to_string();
                }

                // ── Thinking delta (reasoning_content) ──
                // Agent-mode streams thinking as `choices[0].delta.reasoning_content`.
                // Route directly to thinking buffer; do NOT route through the
                // <think>-tag parser since the API already separates it for us.
                if let Some(thinking_delta) = Self::extract_thinking_delta(&data) {
                    thinking_content.push_str(&thinking_delta);
                    if let Some(cb) = callback.as_ref() {
                        cb(&thinking_delta, true);
                    }
                }

                // ── Text delta ──
                let delta = Self::extract_delta(&data);
                if delta.is_empty() {
                    continue;
                }

                if Self::is_openai_delta_format(&data) {
                    // Agent mode / OpenAI style: each chunk is a new piece.
                    // Emit directly without trying to dedup against accumulated content.
                    Self::emit_delta_internal(
                        &delta,
                        &mut current_mode,
                        &mut tag_buffer,
                        &mut accumulated_content,
                        &mut thinking_content,
                        &callback,
                    );
                } else {
                    // Legacy GLM web format: `delta` is the FULL accumulated
                    // content so far. Only emit the new suffix.
                    let total_len = accumulated_content.len() + thinking_content.len();
                    if delta.len() > total_len {
                        let new_delta = &delta[total_len..];
                        if !new_delta.is_empty() {
                            Self::emit_delta_internal(
                                new_delta,
                                &mut current_mode,
                                &mut tag_buffer,
                                &mut accumulated_content,
                                &mut thinking_content,
                                &callback,
                            );
                        }
                    }
                }
            }
        }

        // Flush remaining tag buffer
        if !tag_buffer.is_empty() {
            if current_mode == "thinking" {
                thinking_content.push_str(&tag_buffer);
                if let Some(cb) = callback.as_ref() {
                    cb(&tag_buffer, true);
                }
            } else {
                accumulated_content.push_str(&tag_buffer);
                if let Some(cb) = callback.as_ref() {
                    cb(&tag_buffer, false);
                }
            }
        }

        Ok(ChatResult {
            text: accumulated_content,
            conversation_id: captured_conversation_id,
            thinking: thinking_content,
        })
    }

    /// Extract text delta from SSE data (various formats).
    ///
    /// Supported formats:
    ///   1. OpenAI-style: `choices[0].delta.content` (used by Agent mode / glm-5.2)
    ///   2. Legacy GLM web: `parts[].content[].text`
    ///   3. Fallback flat fields: `text` / `content` / `delta`
    ///
    /// NOTE: `reasoning_content` (thinking) is handled separately by
    /// `extract_thinking_delta` so the caller can route it to the thinking
    /// buffer rather than the visible-text buffer.
    fn extract_delta(data: &serde_json::Value) -> String {
        // 1. OpenAI-style: choices[0].delta.content
        if let Some(choices) = data["choices"].as_array() {
            if let Some(choice) = choices.first() {
                if let Some(content) = choice["delta"]["content"].as_str() {
                    return content.to_string();
                }
                // Non-streaming (or final) chunk may carry message.content
                if let Some(content) = choice["message"]["content"].as_str() {
                    return content.to_string();
                }
            }
        }

        // 2. Legacy GLM web format: parts[].content[].text
        if let Some(parts) = data["parts"].as_array() {
            for part in parts {
                if let Some(content) = part["content"].as_array() {
                    for c in content {
                        if c["type"].as_str() == Some("text") {
                            if let Some(text) = c["text"].as_str() {
                                return text.to_string();
                            }
                        }
                    }
                }
            }
        }

        // 3. Fallback: top-level text / content / delta
        data["text"]
            .as_str()
            .or_else(|| data["content"].as_str())
            .or_else(|| data["delta"].as_str())
            .unwrap_or("")
            .to_string()
    }

    /// Extract thinking/reasoning delta from SSE data.
    ///
    /// Returns `Some(text)` when this SSE chunk carries a piece of the model's
    /// reasoning trace, `None` otherwise. The Agent-mode API (glm-5.2 with
    /// `enable_thinking: true`) streams thinking as:
    ///   `choices[0].delta.reasoning_content`
    ///
    /// We also tolerate a few alternative placements for robustness.
    fn extract_thinking_delta(data: &serde_json::Value) -> Option<String> {
        // Primary: OpenAI-style choices[0].delta.reasoning_content
        if let Some(choices) = data["choices"].as_array() {
            if let Some(choice) = choices.first() {
                if let Some(rc) = choice["delta"]["reasoning_content"].as_str() {
                    if !rc.is_empty() {
                        return Some(rc.to_string());
                    }
                }
                // Some servers place it on the choice directly
                if let Some(rc) = choice["reasoning_content"].as_str() {
                    if !rc.is_empty() {
                        return Some(rc.to_string());
                    }
                }
                // GLM-4-think style: reasoning_content under message
                if let Some(rc) = choice["message"]["reasoning_content"].as_str() {
                    if !rc.is_empty() {
                        return Some(rc.to_string());
                    }
                }
            }
        }

        // Fallback: top-level reasoning_content
        if let Some(rc) = data["reasoning_content"].as_str() {
            if !rc.is_empty() {
                return Some(rc.to_string());
            }
        }

        None
    }

    /// Whether the SSE data uses OpenAI delta-style chunks (each chunk is a
    /// small new piece of content) vs. the legacy GLM web format where each
    /// chunk repeats the full accumulated content.
    ///
    /// Agent-mode (glm-5.2) uses delta-style; we must NOT try to dedup against
    /// accumulated content for those chunks.
    pub(crate) fn is_openai_delta_format(data: &serde_json::Value) -> bool {
        data["choices"].as_array().is_some()
    }

    /// Detect embedded business-layer errors inside an SSE `data:` JSON payload.
    ///
    /// Agent mode may return HTTP 200 with a stream body whose first chunk
    /// contains a nested `error` object (e.g. `FRONTEND_CAPTCHA_REQUIRED`).
    /// We walk the common nesting shapes and return a human-readable message
    /// when we find one. Returns `None` if no error is present.
    ///
    /// Recognised shapes:
    ///   - `{"error": {"code": "...", "detail": "..."}}`
    ///   - `{"data": {"error": {...}}}`
    ///   - `{"data": {"data": {"error": {...}}}}`
    ///   - `{"data": {"done": true, "error": {...}}}`
    pub(crate) fn detect_embedded_error(data: &serde_json::Value) -> Option<String> {
        // Collect candidate error objects from several nesting paths.
        let mut candidates: Vec<&serde_json::Value> = Vec::new();
        if let Some(e) = data.get("error") {
            candidates.push(e);
        }
        if let Some(d) = data.get("data") {
            if let Some(e) = d.get("error") {
                candidates.push(e);
            }
            if let Some(inner) = d.get("data") {
                if let Some(e) = inner.get("error") {
                    candidates.push(e);
                }
            }
        }

        for err in candidates {
            // Must look like an error: has a `code` or `error_code` field.
            let code = err["code"]
                .as_str()
                .or_else(|| err["error_code"].as_str())
                .or_else(|| err["captcha_error_type"].as_str());
            if code.is_none() {
                continue;
            }
            let code = code.unwrap();
            let detail = err["detail"]
                .as_str()
                .or_else(|| err["message"].as_str())
                .unwrap_or("");
            let captcha_type = err["captcha_error_type"]
                .as_str()
                .unwrap_or("");
            return Some(format!(
                "Agent API embedded error [code={}, captcha_error_type={}]: {}",
                code, captcha_type, detail
            ));
        }
        None
    }

    /// Emit a delta, handling <think> tags for thinking mode (static method)
    pub(crate) fn emit_delta_internal(
        delta: &str,
        current_mode: &mut String,
        tag_buffer: &mut String,
        accumulated_content: &mut String,
        thinking_content: &mut String,
        callback: &Option<&StreamCallback>,
    ) {
        tag_buffer.push_str(delta);

        // Check for <think> and </think> tags
        loop {
            let think_start_pos = tag_buffer.find("<think");
            let think_end_pos = tag_buffer.find("</think>");

            let first = match (think_start_pos, think_end_pos) {
                (Some(i), Some(j)) => {
                    if i <= j {
                        Some((i, "think_start"))
                    } else {
                        Some((j, "think_end"))
                    }
                }
                (Some(i), None) => Some((i, "think_start")),
                (None, Some(j)) => Some((j, "think_end")),
                (None, None) => None,
            };

            if let Some((idx, tag_type)) = first {
                let before = &tag_buffer[..idx];
                if !before.is_empty() {
                    if *current_mode == "thinking" {
                        thinking_content.push_str(before);
                        if let Some(cb) = callback.as_ref() {
                            cb(before, true);
                        }
                    } else {
                        accumulated_content.push_str(before);
                        if let Some(cb) = callback.as_ref() {
                            cb(before, false);
                        }
                    }
                }

                if tag_type == "think_start" {
                    *current_mode = "thinking".to_string();
                    // Find end of opening tag
                    if let Some(end_idx) = tag_buffer[idx..].find('>') {
                        *tag_buffer = tag_buffer[idx + end_idx + 1..].to_string();
                    } else {
                        *tag_buffer = String::new();
                    }
                } else {
                    *current_mode = "text".to_string();
                    let end_tag_len = "</think>".len();
                    let remaining_start = idx + end_tag_len;
                    if remaining_start < tag_buffer.len() {
                        *tag_buffer = tag_buffer[remaining_start..].to_string();
                    } else {
                        *tag_buffer = String::new();
                    }
                }
            } else {
                // No tags found - emit safe content (up to last '<')
                let last_angle = tag_buffer.rfind('<');
                match last_angle {
                    None => {
                        if *current_mode == "thinking" {
                            thinking_content.push_str(tag_buffer);
                            if let Some(cb) = callback.as_ref() {
                                cb(tag_buffer, true);
                            }
                        } else {
                            accumulated_content.push_str(tag_buffer);
                            if let Some(cb) = callback.as_ref() {
                                cb(tag_buffer, false);
                            }
                        }
                        *tag_buffer = String::new();
                    }
                    Some(0) => {
                        // Buffer starts with '<' - might be start of a tag, wait
                    }
                    Some(pos) => {
                        let safe = &tag_buffer[..pos];
                        if !safe.is_empty() {
                            if *current_mode == "thinking" {
                                thinking_content.push_str(safe);
                                if let Some(cb) = callback.as_ref() {
                                    cb(safe, true);
                                }
                            } else {
                                accumulated_content.push_str(safe);
                                if let Some(cb) = callback.as_ref() {
                                    cb(safe, false);
                                }
                            }
                        }
                        *tag_buffer = tag_buffer[pos..].to_string();
                    }
                }
                break;
            }
        }
    }

    /// Simple chat - returns full text (no streaming)
    pub async fn chat(&self, message: &str, model: &str) -> Result<ChatResult> {
        self.chat_stream(message, model, None, None, None).await
    }
}

// ── Free-function wrappers for browser module to use ──
//
// The browser module's `chat_via_browser_agent` needs to reuse the SSE
// parsing logic (embedded-error detection, delta emission with <think> tag
// handling) that lives inside `impl ZaiClient`. We expose them as free
// functions so browser/mod.rs can call them without a ZaiClient instance.

/// Public wrapper for `ZaiClient::detect_embedded_error`.
pub fn detect_embedded_error_pub(data: &serde_json::Value) -> Option<String> {
    ZaiClient::detect_embedded_error(data)
}

/// Public wrapper for `ZaiClient::emit_delta_internal`.
pub fn emit_delta_pub(
    delta: &str,
    current_mode: &mut String,
    tag_buffer: &mut String,
    accumulated_content: &mut String,
    thinking_content: &mut String,
    callback: &Option<&StreamCallback>,
) {
    ZaiClient::emit_delta_internal(
        delta,
        current_mode,
        tag_buffer,
        accumulated_content,
        thinking_content,
        callback,
    );
}

