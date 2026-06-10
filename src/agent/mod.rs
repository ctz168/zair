//! AICQ Agent Runtime
//!
//! Connects to AICQ server via WebSocket, receives messages from
//! friends/groups, processes them with Z.AI's LLM, and sends
//! streaming replies (including thinking content) back through AICQ.

use anyhow::{bail, Context, Result};
use base64::Engine;
use ed25519_dalek::{SigningKey, Signer};
use futures::{SinkExt, StreamExt};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_tungstenite::{connect_async, tungstenite};

use crate::auth;
use crate::client::ZaiClient;
use crate::config::AppConfig;

// ─── Types ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AicqIdentity {
    agent_id: String,
    signing_public_key: String,
    signing_secret_key: String,
    exchange_public_key: String,
    exchange_secret_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwt_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    server_account_id: Option<String>,
}

#[derive(Debug)]
struct ConversationMessage {
    role: String,
    content: String,
}

// ─── JWT helpers ─────────────────────────────────────────────

/// Decode the payload of a JWT token (without verification) to extract claims.
/// JWT format: header.payload.signature — we only need the payload section.
fn decode_jwt_payload(token: &str) -> Result<serde_json::Value> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        bail!("Invalid JWT format: expected 3 parts, got {}", parts.len());
    }
    let payload_b64 = parts[1];
    // JWT uses URL-safe base64 without padding
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload_bytes = engine
        .decode(payload_b64)
        .context("Failed to decode JWT payload base64")?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .context("Failed to parse JWT payload JSON")?;
    Ok(payload)
}

/// Extract the `sub` claim from a JWT token.
/// This is the account ID that AICQ server assigned during registration.
fn extract_jwt_subject(token: &str) -> Result<String> {
    let payload = decode_jwt_payload(token)?;
    let sub = payload["sub"]
        .as_str()
        .or_else(|| payload["userId"].as_str())
        .or_else(|| payload["account_id"].as_str())
        .or_else(|| payload["id"].as_str())
        .context("No 'sub' claim found in JWT token")?;
    Ok(sub.to_string())
}

// ─── Agent Runtime ────────────────────────────────────────────

pub struct AgentRuntime {
    config: AppConfig,
    identity: Arc<Mutex<Option<AicqIdentity>>>,
    zai_client: Arc<ZaiClient>,
    memory: Arc<Mutex<HashMap<String, Vec<ConversationMessage>>>>,
    processed_messages: Arc<Mutex<HashSet<String>>>,
    jwt_token: Arc<Mutex<Option<String>>>,
    server_account_id: Arc<Mutex<Option<String>>>,
}

impl AgentRuntime {
    pub fn new(config: AppConfig) -> Self {
        let zai_client = ZaiClient::new(config.clone());

        Self {
            config,
            identity: Arc::new(Mutex::new(None)),
            zai_client: Arc::new(zai_client),
            memory: Arc::new(Mutex::new(HashMap::new())),
            processed_messages: Arc::new(Mutex::new(HashSet::new())),
            jwt_token: Arc::new(Mutex::new(None)),
            server_account_id: Arc::new(Mutex::new(None)),
        }
    }

    /// Main run loop - connect to AICQ and process messages
    pub async fn run(&mut self) -> Result<()> {
        tracing::info!("Initializing ZAI Agent...");

        // Check Z.AI login
        if !auth::is_logged_in() {
            tracing::warn!("No Z.AI cookie login (SDK will be used as AI backend)");
        }

        // Load or create identity, then refresh auth
        self.ensure_identity().await?;

        // Connect to AICQ server
        self.connect_and_listen().await?;

        Ok(())
    }

    /// Load or create AICQ identity, then refresh authentication
    async fn ensure_identity(&self) -> Result<()> {
        let identity_path = self.get_identity_path()?;

        // Try to load existing identity
        if identity_path.exists() {
            let content = fs::read_to_string(&identity_path)?;
            let mut identity: AicqIdentity = serde_json::from_str(&content)?;
            tracing::info!("Loaded existing identity: {}", identity.agent_id);

            // Always refresh authentication — old JWT may have expired
            tracing::info!("Refreshing AICQ authentication...");
            match self.login_identity(&identity).await {
                Ok(token) => {
                    // Extract account_id from JWT subject
                    let account_id = extract_jwt_subject(&token)
                        .unwrap_or_else(|e| {
                            tracing::warn!("Could not extract JWT subject: {}", e);
                            identity.agent_id.clone()
                        });

                    tracing::info!("AICQ login refreshed (account_id={})", account_id);

                    // Update identity with new token and account_id
                    identity.jwt_token = Some(token.clone());
                    identity.server_account_id = Some(account_id.clone());

                    // Save updated identity
                    if let Ok(updated) = serde_json::to_string_pretty(&identity) {
                        let _ = fs::write(&identity_path, updated);
                    }

                    // Update runtime state
                    let mut jwt = self.jwt_token.lock().await;
                    *jwt = Some(token);
                    let mut acct = self.server_account_id.lock().await;
                    *acct = Some(account_id);
                }
                Err(e) => {
                    tracing::warn!("Login refresh failed: {}, trying registration...", e);

                    // If login fails (e.g. key rotated), try re-registration
                    match self.register_identity(&identity).await {
                        Ok(token) => {
                            let account_id = extract_jwt_subject(&token)
                                .unwrap_or_else(|e| {
                                    tracing::warn!("Could not extract JWT subject: {}", e);
                                    identity.agent_id.clone()
                                });

                            tracing::info!("Re-registered with AICQ (account_id={})", account_id);

                            identity.jwt_token = Some(token.clone());
                            identity.server_account_id = Some(account_id.clone());

                            if let Ok(updated) = serde_json::to_string_pretty(&identity) {
                                let _ = fs::write(&identity_path, updated);
                            }

                            let mut jwt = self.jwt_token.lock().await;
                            *jwt = Some(token);
                            let mut acct = self.server_account_id.lock().await;
                            *acct = Some(account_id);
                        }
                        Err(e2) => {
                            bail!("Both login and registration failed: login={}, register={}", e, e2);
                        }
                    }
                }
            }

            let mut guard = self.identity.lock().await;
            *guard = Some(identity);
            return Ok(());
        }

        // Generate new identity
        tracing::info!("Generating new AICQ identity...");

        let signing_keypair = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_keypair.verifying_key();

        let exchange_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let exchange_public = x25519_dalek::PublicKey::from(&exchange_secret);

        let mut identity = AicqIdentity {
            agent_id: self.config.agent.agent_id.clone(),
            signing_public_key: hex::encode(verifying_key.as_bytes()),
            signing_secret_key: hex::encode(signing_keypair.as_bytes()),
            exchange_public_key: hex::encode(exchange_public.as_bytes()),
            exchange_secret_key: hex::encode(exchange_secret.as_bytes()),
            jwt_token: None,
            server_account_id: None,
        };

        // Register with AICQ server
        let token = match self.register_identity(&identity).await {
            Ok(token) => {
                tracing::info!("Registered with AICQ server");
                token
            }
            Err(e) => {
                tracing::warn!("Registration failed ({}), trying login...", e);
                self.login_identity(&identity).await?
            }
        };

        // Extract account_id from JWT subject
        let account_id = extract_jwt_subject(&token)
            .unwrap_or_else(|e| {
                tracing::warn!("Could not extract JWT subject: {}", e);
                identity.agent_id.clone()
            });

        tracing::info!("AICQ identity account_id={}", account_id);

        // Update identity
        identity.jwt_token = Some(token.clone());
        identity.server_account_id = Some(account_id.clone());

        // Save identity to disk
        if let Some(parent) = identity_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(&identity)?;
        fs::write(&identity_path, content)?;

        // Update runtime state
        {
            let mut jwt = self.jwt_token.lock().await;
            *jwt = Some(token);
        }
        {
            let mut acct = self.server_account_id.lock().await;
            *acct = Some(account_id);
        }
        {
            let mut guard = self.identity.lock().await;
            *guard = Some(identity);
        }

        Ok(())
    }

    /// Register with AICQ server
    async fn register_identity(&self, identity: &AicqIdentity) -> Result<String> {
        let client = reqwest::Client::new();
        let url = format!("{}/api/v1/auth/register/ai", self.config.agent.server_url);

        tracing::info!("Registering with AICQ at {}...", url);

        let res = client
            .post(&url)
            .json(&serde_json::json!({
                "public_key": identity.signing_public_key,
                "agent_name": self.config.agent.nickname,
            }))
            .send()
            .await?;

        if !res.status().is_success() {
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            bail!("Registration failed ({}): {}", status, text);
        }

        let data: serde_json::Value = res.json().await?;

        // Try multiple possible token field names
        let token = data["access_token"]
            .as_str()
            .or_else(|| data["accessToken"].as_str())
            .or_else(|| data["token"].as_str())
            .context(format!("No access token in registration response: {}", data))?;

        // Also try to extract account_id from response directly
        if let Some(acct_id) = data["account_id"].as_str()
            .or_else(|| data["accountId"].as_str())
            .or_else(|| data["userId"].as_str())
            .or_else(|| data["id"].as_str())
        {
            tracing::info!("Server returned account_id: {}", acct_id);
            let mut account = self.server_account_id.lock().await;
            *account = Some(acct_id.to_string());
        }

        Ok(token.to_string())
    }

    /// Login to AICQ server with existing identity
    async fn login_identity(&self, identity: &AicqIdentity) -> Result<String> {
        let client = reqwest::Client::new();
        let api_url = format!("{}/api/v1", self.config.agent.server_url);

        // Get challenge
        tracing::info!("Requesting AICQ auth challenge...");
        let challenge_res = client
            .post(format!("{}/auth/challenge", api_url))
            .json(&serde_json::json!({
                "public_key": identity.signing_public_key,
            }))
            .send()
            .await?;

        if !challenge_res.status().is_success() {
            let status = challenge_res.status();
            let text = challenge_res.text().await.unwrap_or_default();
            bail!("Challenge request failed ({}): {}", status, text);
        }

        let challenge_data: serde_json::Value = challenge_res.json().await?;
        let challenge = challenge_data["challenge"]
            .as_str()
            .context(format!("No challenge in response: {}", challenge_data))?;

        // Sign challenge
        let secret_key_bytes = hex::decode(&identity.signing_secret_key)?;
        let key_bytes: [u8; 32] = secret_key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid secret key length"))?;
        let signing_key = SigningKey::from_bytes(&key_bytes);

        let message_bytes = if challenge.len() == 64 && challenge.chars().all(|c| c.is_ascii_hexdigit()) {
            hex::decode(challenge)?
        } else {
            challenge.as_bytes().to_vec()
        };

        let signature = signing_key.sign(&message_bytes);
        let signature_hex = hex::encode(signature.to_bytes());

        // Login
        tracing::info!("Signing AICQ auth challenge...");
        let login_res = client
            .post(format!("{}/auth/login/agent", api_url))
            .json(&serde_json::json!({
                "public_key": identity.signing_public_key,
                "signature": signature_hex,
                "challenge": challenge,
            }))
            .send()
            .await?;

        if !login_res.status().is_success() {
            let status = login_res.status();
            let text = login_res.text().await.unwrap_or_default();
            bail!("Login failed ({}): {}", status, text);
        }

        let login_data: serde_json::Value = login_res.json().await?;
        let token = login_data["access_token"]
            .as_str()
            .or_else(|| login_data["accessToken"].as_str())
            .or_else(|| login_data["token"].as_str())
            .context(format!("No access token in login response: {}", login_data))?;

        Ok(token.to_string())
    }

    /// Connect to AICQ WebSocket and listen for messages
    async fn connect_and_listen(&self) -> Result<()> {
        let ws_url = self.config.agent.server_url
            .replace("https://", "wss://")
            .replace("http://", "ws://");

        let ws_url = format!("{}/ws", ws_url);
        tracing::info!("Connecting to {}...", ws_url);

        let (mut ws_stream, _) = connect_async(&ws_url)
            .await
            .context("Failed to connect to AICQ WebSocket")?;

        // Get JWT token and determine the correct nodeId
        let jwt = self.jwt_token.lock().await;
        let token_str = match jwt.as_deref() {
            Some(t) => t.to_string(),
            None => {
                drop(jwt);
                bail!("No JWT token available for WebSocket authentication");
            }
        };
        drop(jwt);

        // The nodeId MUST match the JWT subject claim.
        // Extract it from the JWT to ensure consistency.
        let node_id = match extract_jwt_subject(&token_str) {
            Ok(sub) => {
                tracing::info!("Using JWT subject as nodeId: {}", sub);
                // Also update our stored account_id
                let mut acct = self.server_account_id.lock().await;
                *acct = Some(sub.clone());
                sub
            }
            Err(e) => {
                // Fallback: use stored account_id or agent_id
                let acct = self.server_account_id.lock().await;
                let fallback = acct
                    .as_deref()
                    .unwrap_or(&self.config.agent.agent_id)
                    .to_string();
                tracing::warn!(
                    "Could not extract JWT subject ({}), using fallback nodeId: {}",
                    e,
                    fallback
                );
                fallback
            }
        };

        let online_msg = serde_json::json!({
            "type": "online",
            "nodeId": node_id,
            "token": token_str,
        });

        tracing::info!("Sending WS auth: nodeId={}", node_id);
        ws_stream
            .send(tungstenite::Message::Text(online_msg.to_string()))
            .await?;

        tracing::info!("WebSocket connected, authenticating...");

        // Main message loop
        while let Some(msg) = ws_stream.next().await {
            match msg {
                Ok(tungstenite::Message::Text(text)) => {
                    if let Ok(data) = serde_json::from_str::<serde_json::Value>(&text) {
                        self.handle_ws_message(data).await?;
                    }
                }
                Ok(tungstenite::Message::Ping(data)) => {
                    let _ = ws_stream.send(tungstenite::Message::Pong(data)).await;
                }
                Ok(tungstenite::Message::Close(_)) => {
                    tracing::warn!("WebSocket connection closed");
                    break;
                }
                Err(e) => {
                    tracing::error!("WebSocket error: {}", e);
                    break;
                }
                _ => {}
            }
        }

        tracing::info!("WebSocket loop ended");
        Ok(())
    }

    /// Handle incoming WebSocket message
    async fn handle_ws_message(&self, data: serde_json::Value) -> Result<()> {
        let msg_type = data["type"].as_str().unwrap_or("");

        match msg_type {
            "online_ack" => {
                tracing::info!("WebSocket authenticated as {}", data["nodeId"]);
            }
            "error" => {
                tracing::error!(
                    "WS server error: {}",
                    data["message"].as_str().unwrap_or("unknown")
                );
            }
            "relay" | "message" => {
                self.process_incoming_message(data, false).await?;
            }
            "group_message" => {
                self.process_incoming_message(data, true).await?;
            }
            "handshake_initiate" | "friend_request" => {
                tracing::info!("Friend request received: {}", data);
                // Auto-accept friend requests from masters
                if let Some(from) = data["from"].as_str().or_else(|| data["fromId"].as_str()) {
                    if self.config.agent.masters.contains(&from.to_string())
                        || self.config.agent.auto_accept_friends
                    {
                        tracing::info!("Auto-accepting friend request from {}", from);
                        // TODO: send friend_accept via REST API
                    }
                }
            }
            "unread_counts" => {
                self.handle_unread_counts(data).await?;
            }
            "dm" | "chat" | "private_message" => {
                self.process_incoming_message(data, false).await?;
            }
            _ => {
                tracing::debug!("Unknown WS message type: {} data: {}", msg_type, data);
            }
        }

        Ok(())
    }

    /// Process an incoming message
    async fn process_incoming_message(
        &self,
        data: serde_json::Value,
        is_group: bool,
    ) -> Result<()> {
        // Extract from ID and content from various message formats
        let inner = if data["data"].is_object() {
            &data["data"]
        } else {
            &serde_json::Value::Null
        };

        let from_id = inner["from"]
            .as_str()
            .or_else(|| inner["fromId"].as_str())
            .or_else(|| data["from"].as_str())
            .or_else(|| data["fromId"].as_str())
            .unwrap_or("");

        let content = inner["content"]
            .as_str()
            .or_else(|| inner["payload"].as_str())
            .or_else(|| inner["text"].as_str())
            .or_else(|| data["content"].as_str())
            .or_else(|| data["payload"].as_str())
            .or_else(|| data["text"].as_str())
            .unwrap_or("");

        if from_id.is_empty() {
            return Ok(());
        }

        // Skip own messages
        let account_id = self.server_account_id.lock().await;
        if from_id == account_id.as_deref().unwrap_or("")
            || from_id == self.config.agent.agent_id
        {
            return Ok(());
        }

        // Dedup
        let msg_id = data["_msgId"]
            .as_str()
            .or_else(|| data["id"].as_str())
            .or_else(|| data["messageId"].as_str())
            .unwrap_or("");

        {
            let mut processed = self.processed_messages.lock().await;
            if !msg_id.is_empty() && processed.contains(msg_id) {
                return Ok(());
            }
            if !msg_id.is_empty() {
                processed.insert(msg_id.to_string());
            }

            // Content-based dedup
            let dedup_key = format!("{}:{}", from_id, &content[..content.len().min(100)]);
            if processed.contains(&dedup_key) {
                return Ok(());
            }
            processed.insert(dedup_key);

            // Trim dedup set
            if processed.len() > 1000 {
                let keys: Vec<String> = processed.iter().take(500).cloned().collect();
                for k in keys {
                    processed.remove(&k);
                }
            }
        }

        let chat_id = if is_group {
            data["groupId"].as_str().unwrap_or(from_id).to_string()
        } else {
            from_id.to_string()
        };

        tracing::info!(
            "Message from {}: {}",
            from_id,
            &content[..content.len().min(80)]
        );

        if content.trim().is_empty() {
            return Ok(());
        }

        // Add to conversation memory
        {
            let mut memory = self.memory.lock().await;
            let history = memory.entry(chat_id.clone()).or_insert_with(Vec::new);
            history.push(ConversationMessage {
                role: "user".to_string(),
                content: content.to_string(),
            });

            let max = self.config.agent.max_history_per_chat;
            if history.len() > max {
                let drain_count = history.len() - max;
                history.drain(..drain_count);
            }
        }

        // Generate AI response with streaming
        match self.generate_reply(&chat_id, content).await {
            Ok(reply) => {
                let mut memory = self.memory.lock().await;
                if let Some(history) = memory.get_mut(&chat_id) {
                    history.push(ConversationMessage {
                        role: "assistant".to_string(),
                        content: reply,
                    });
                }
            }
            Err(e) => {
                tracing::error!("Error generating reply: {}", e);
            }
        }

        Ok(())
    }

    /// Generate a streaming reply using Z.AI
    async fn generate_reply(&self, _chat_id: &str, user_message: &str) -> Result<String> {
        tracing::info!(
            "Generating reply for: \"{}\"...",
            &user_message[..user_message.len().min(60)]
        );

        // Stream the response
        let result = self
            .zai_client
            .chat_stream(
                user_message,
                &self.config.agent.model,
                None,
                Some(&self.config.agent.system_prompt),
                Some(Box::new(|delta: &str, is_thinking: bool| {
                    if is_thinking {
                        tracing::debug!("[thinking] {}", delta);
                    } else {
                        tracing::debug!("[text] {}", delta);
                    }
                })),
            )
            .await?;

        if !result.thinking.is_empty() {
            tracing::info!(
                "Thinking: {}...",
                &result.thinking[..result.thinking.len().min(100)]
            );
        }

        tracing::info!("Reply generated ({} chars)", result.text.len());

        Ok(result.text)
    }

    /// Handle unread_counts notification
    async fn handle_unread_counts(&self, data: serde_json::Value) -> Result<()> {
        let unread = &data["unread"];
        if !unread.is_object() {
            return Ok(());
        }

        tracing::info!("Unread counts: {}", unread);

        let jwt = self.jwt_token.lock().await;
        let token = match jwt.as_deref() {
            Some(t) => t.to_string(),
            None => return Ok(()),
        };
        drop(jwt);

        if let Some(unread_map) = unread.as_object() {
            for (friend_id, count) in unread_map {
                let count = count.as_u64().unwrap_or(0);
                if count == 0 {
                    continue;
                }

                tracing::info!(
                    "Fetching {} unread message(s) from {}...",
                    count,
                    friend_id
                );

                let client = reqwest::Client::new();
                let url = format!(
                    "{}/api/v1/chat/conversation/{}?limit={}",
                    self.config.agent.server_url, friend_id, count
                );

                let res = client
                    .get(&url)
                    .header("Authorization", format!("Bearer {}", token))
                    .send()
                    .await;

                if let Ok(res) = res {
                    if res.status().is_success() {
                        if let Ok(conv_data) = res.json::<serde_json::Value>().await {
                            if let Some(messages) = conv_data["messages"].as_array() {
                                for msg in messages {
                                    let from_id = msg["from_id"]
                                        .as_str()
                                        .or_else(|| msg["fromId"].as_str())
                                        .unwrap_or(friend_id);
                                    let content = msg["content"]
                                        .as_str()
                                        .or_else(|| msg["text"].as_str())
                                        .unwrap_or("");

                                    if content.trim().is_empty() {
                                        continue;
                                    }

                                    self.process_incoming_message(
                                        serde_json::json!({
                                            "from": from_id,
                                            "fromId": from_id,
                                            "data": content,
                                            "payload": content,
                                            "_msgId": msg["id"],
                                        }),
                                        false,
                                    )
                                    .await?;
                                }
                            }
                        }
                    }
                }

                // Mark as read
                let _ = client
                    .post(format!(
                        "{}/api/v1/chat/mark-read",
                        self.config.agent.server_url
                    ))
                    .header("Authorization", format!("Bearer {}", token))
                    .json(&serde_json::json!({ "friend_id": friend_id }))
                    .send()
                    .await;
            }
        }

        Ok(())
    }

    /// Add an owner (master) and send friend request
    pub async fn add_owner(&self, owner_id: &str) -> Result<()> {
        self.ensure_identity().await?;

        let jwt = self.jwt_token.lock().await;
        let token = match jwt.as_deref() {
            Some(t) => t.to_string(),
            None => bail!("No JWT token - cannot send friend request"),
        };
        drop(jwt);

        let client = reqwest::Client::new();
        let api_url = format!("{}/api/v1", self.config.agent.server_url);

        tracing::info!("Sending friend request to {}...", owner_id);

        // Try /friends/request endpoint
        let res = client
            .post(format!("{}/friends/request", api_url))
            .header("Authorization", format!("Bearer {}", token))
            .json(&serde_json::json!({
                "target_id": owner_id,
                "message": "Hi! I'm your ZAI Agent. Let's be friends!",
            }))
            .send()
            .await;

        match res {
            Ok(response) if response.status().is_success() => {
                tracing::info!("Friend request sent to {}", owner_id);
            }
            Ok(response) => {
                let status = response.status();
                let text = response.text().await.unwrap_or_default();
                tracing::warn!("Friend request /friends/request failed ({}): {}", status, text);

                // Try /friends/add as fallback
                let res2 = client
                    .post(format!("{}/friends/add", api_url))
                    .header("Authorization", format!("Bearer {}", token))
                    .json(&serde_json::json!({
                        "friend_id": owner_id,
                    }))
                    .send()
                    .await;

                match res2 {
                    Ok(r) if r.status().is_success() => {
                        tracing::info!("Friend request sent (via /friends/add) to {}", owner_id);
                    }
                    Ok(r) => {
                        let status = r.status();
                        let text = r.text().await.unwrap_or_default();
                        tracing::warn!("Friend request /friends/add also failed ({}): {}", status, text);
                    }
                    Err(e) => {
                        tracing::warn!("Friend request /friends/add error: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Friend request error: {}", e);
            }
        }

        Ok(())
    }

    /// Get identity file path
    fn get_identity_path(&self) -> Result<PathBuf> {
        let data_dir = &self.config.agent.data_dir;
        Ok(PathBuf::from(data_dir).join("aicq").join("identity.json"))
    }
}
