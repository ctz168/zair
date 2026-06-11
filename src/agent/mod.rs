//! AICQ Agent Runtime
//!
//! Connects to AICQ server via WebSocket, receives messages from
//! friends/groups, processes them with Z.AI's LLM, and sends
//! streaming replies back through AICQ WebSocket.
//!
//! Message format (per aicqSDK):
//! - Send: {type: "message", to: friend_id, data: {id, from_id, to_id, type: "text", content, ...}}
//! - Receive: {type: "message", from: senderId, data: {id, from_id, to_id, type, content, ...}}
//! - Stream: {type: "stream_chunk", to: friend_id, chunkType: "text", data: "..."} + {type: "stream_end", to: friend_id}

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
fn decode_jwt_payload(token: &str) -> Result<serde_json::Value> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        bail!("Invalid JWT format: expected 3 parts, got {}", parts.len());
    }
    let payload_b64 = parts[1];
    // Try URL_SAFE_NO_PAD first (most JWTs), then URL_SAFE with padding
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .or_else(|_| {
            // Add padding if needed
            let padded = {
                let pad_len = (4 - payload_b64.len() % 4) % 4;
                format!("{}{}", payload_b64, "=".repeat(pad_len))
            };
            base64::engine::general_purpose::URL_SAFE.decode(&padded)
        })
        .context("Failed to decode JWT payload base64")?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .context("Failed to parse JWT payload JSON")?;
    Ok(payload)
}

/// Extract the `sub` claim from a JWT token.
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

        if !auth::is_logged_in() {
            tracing::warn!("No Z.AI cookie login (SDK will be used as AI backend)");
        }

        // Load or create identity, then refresh auth
        self.ensure_identity().await?;

        // Connect to AICQ server with auto-reconnect
        loop {
            match self.connect_and_listen().await {
                Ok(()) => {
                    tracing::warn!("WebSocket disconnected, reconnecting in 5s...");
                }
                Err(e) => {
                    tracing::error!("WebSocket error: {}, reconnecting in 5s...", e);
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;

            // Refresh JWT on reconnect
            if let Err(e) = self.refresh_jwt().await {
                tracing::error!("JWT refresh failed: {}", e);
            }
        }
    }

    /// Load or create AICQ identity, then refresh authentication
    async fn ensure_identity(&self) -> Result<()> {
        let identity_path = self.get_identity_path()?;

        if identity_path.exists() {
            let content = fs::read_to_string(&identity_path)?;
            let identity: AicqIdentity = serde_json::from_str(&content)?;
            tracing::info!("Loaded existing identity: {}", identity.agent_id);

            {
                let mut guard = self.identity.lock().await;
                *guard = Some(identity);
            } // Drop the guard BEFORE calling refresh_jwt to avoid deadlock

            // Refresh JWT - if this fails, delete the old identity and re-register
            match self.refresh_jwt().await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    tracing::warn!("JWT refresh failed ({}), re-registering...", e);
                    
                    // Delete the broken identity file
                    let _ = fs::remove_file(&identity_path);
                    
                    // Fall through to generate new identity
                }
            }
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

    /// Refresh JWT by logging in again
    async fn refresh_jwt(&self) -> Result<()> {
        let identity_guard = self.identity.lock().await;
        let identity = identity_guard.as_ref().context("No identity loaded")?.clone();
        drop(identity_guard);

        tracing::info!("Refreshing AICQ authentication...");
        let token = self.login_identity(&identity).await?;

        let account_id = extract_jwt_subject(&token)
            .unwrap_or_else(|e| {
                tracing::warn!("Could not extract JWT subject: {}", e);
                identity.server_account_id.clone().unwrap_or_default()
            });

        tracing::info!("AICQ login refreshed (account_id={})", account_id);

        // Update runtime state
        {
            let mut jwt = self.jwt_token.lock().await;
            *jwt = Some(token.clone());
        }
        {
            let mut acct = self.server_account_id.lock().await;
            *acct = Some(account_id.clone());
        }

        // Save updated identity
        let identity_path = self.get_identity_path()?;
        let mut identity = identity;
        identity.jwt_token = Some(token);
        identity.server_account_id = Some(account_id);
        if let Ok(updated) = serde_json::to_string_pretty(&identity) {
            let _ = fs::write(identity_path, updated);
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
        let token = data["access_token"]
            .as_str()
            .or_else(|| data["accessToken"].as_str())
            .or_else(|| data["token"].as_str())
            .context(format!("No access token in registration response: {}", data))?;

        // Extract account_id from response: {"account": {"id": "..."}, ...}
        if let Some(acct_id) = data["account"]["id"].as_str()
            .or_else(|| data["account_id"].as_str())
        {
            tracing::info!("Server returned account_id: {}", acct_id);
            let mut account = self.server_account_id.lock().await;
            *account = Some(acct_id.to_string());
        }

        Ok(token.to_string())
    }

    /// Login to AICQ server with existing identity (challenge-response)
    async fn login_identity(&self, identity: &AicqIdentity) -> Result<String> {
        let client = reqwest::Client::new();
        let api_url = format!("{}/api/v1", self.config.agent.server_url);

        tracing::info!("Requesting AICQ auth challenge...");
        let challenge_res = client
            .post(format!("{}/auth/challenge", api_url))
            .json(&serde_json::json!({ "public_key": identity.signing_public_key }))
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

        let (ws_stream, _) = connect_async(&ws_url)
            .await
            .context("Failed to connect to AICQ WebSocket")?;

        // Split into sink (for sending) and stream (for receiving)
        let (mut ws_sink, mut ws_rx) = ws_stream.split();

        // Get JWT and determine nodeId
        let jwt = self.jwt_token.lock().await;
        let token_str = match jwt.as_deref() {
            Some(t) => t.to_string(),
            None => {
                drop(jwt);
                bail!("No JWT token available for WebSocket authentication");
            }
        };
        drop(jwt);

        let node_id = match extract_jwt_subject(&token_str) {
            Ok(sub) => {
                tracing::info!("Using JWT subject as nodeId: {}", sub);
                let mut acct = self.server_account_id.lock().await;
                *acct = Some(sub.clone());
                sub
            }
            Err(e) => {
                let acct = self.server_account_id.lock().await;
                let fallback = acct.as_deref().unwrap_or(&self.config.agent.agent_id).to_string();
                tracing::warn!("Could not extract JWT subject ({}), using fallback: {}", e, fallback);
                fallback
            }
        };

        // Send online message
        let online_msg = serde_json::json!({
            "type": "online",
            "nodeId": node_id,
            "token": token_str,
        });

        tracing::info!("Sending WS auth: nodeId={}", node_id);
        ws_sink
            .send(tungstenite::Message::Text(online_msg.to_string()))
            .await?;

        tracing::info!("WebSocket connected, authenticating...");

        // Main message loop
        while let Some(msg) = ws_rx.next().await {
            match msg {
                Ok(tungstenite::Message::Text(text)) => {
                    if let Ok(data) = serde_json::from_str::<serde_json::Value>(&text) {
                        if let Err(e) = self.handle_ws_message(data, &mut ws_sink).await {
                            tracing::error!("Error handling WS message: {}", e);
                        }
                    }
                }
                Ok(tungstenite::Message::Ping(data)) => {
                    let _ = ws_sink.send(tungstenite::Message::Pong(data)).await;
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
    async fn handle_ws_message(
        &self,
        data: serde_json::Value,
        ws: &mut futures::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            tungstenite::Message,
        >,
    ) -> Result<()> {
        let msg_type = data["type"].as_str().unwrap_or("");

        match msg_type {
            "online_ack" => {
                tracing::info!("✅ WebSocket authenticated as {}", data["nodeId"]);
            }
            "error" => {
                tracing::error!(
                    "❌ WS server error: {}",
                    data["message"].as_str().unwrap_or("unknown")
                );
            }
            "system_broadcast" | "system" => {
                tracing::info!(
                    "📢 System: {}",
                    data["message"].as_str().unwrap_or("")
                );
            }
            "friends_online" => {
                // Server tells us which friends are currently online
                let node_ids: Vec<&str> = data["nodeIds"]
                    .as_array()
                    .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
                    .unwrap_or_default();
                tracing::info!("👥 Friends online: {:?}", node_ids);
            }
            "presence" => {
                // Friend came online or went offline
                let node_id = data["nodeId"].as_str().unwrap_or("");
                let online = data["online"].as_bool().unwrap_or(false);
                tracing::info!("👤 {} is {}", node_id, if online { "online" } else { "offline" });
            }
            "message_ack" => {
                // Our message was acknowledged by the server
                tracing::debug!("✉️ Message ack: to={} status={}", 
                    data["to"].as_str().unwrap_or("?"),
                    data["status"].as_str().unwrap_or("?"));
            }
            "message" | "private_message" => {
                // AICQ message format: {type: "message", from: senderId, data: {id, from_id, to_id, type, content, ...}}
                let from_id = data["from"].as_str()
                    .or_else(|| data["fromId"].as_str())
                    .or_else(|| data["data"]["from_id"].as_str())
                    .unwrap_or("");

                let content = data["data"]["content"].as_str()
                    .or_else(|| data["content"].as_str())
                    .or_else(|| data["data"]["text"].as_str())
                    .unwrap_or("");

                if !from_id.is_empty() && !content.trim().is_empty() {
                    self.process_and_reply(from_id, content, ws).await?;
                }
            }
            "group_message" => {
                let from_id = data["from"].as_str()
                    .or_else(|| data["fromId"].as_str())
                    .unwrap_or("");
                let content = data["content"].as_str()
                    .or_else(|| data["data"]["content"].as_str())
                    .unwrap_or("");

                if !from_id.is_empty() && !content.trim().is_empty() {
                    self.process_and_reply(from_id, content, ws).await?;
                }
            }
            "friend_request" => {
                tracing::info!("📨 Friend request received");
                let request_id = data["data"]["id"].as_str()
                    .or_else(|| data["id"].as_str())
                    .unwrap_or("");
                let from_id = data["from"].as_str()
                    .or_else(|| data["data"]["from_id"].as_str())
                    .unwrap_or("");

                if self.config.agent.auto_accept_friends
                    || self.config.agent.masters.contains(&from_id.to_string())
                {
                    if !request_id.is_empty() {
                        tracing::info!("🤝 Auto-accepting friend request {} from {}", request_id, from_id);
                        self.accept_friend_request(request_id).await;
                    }
                }
            }
            "stream_cancel" => {
                let from_id = data["from"].as_str().unwrap_or("");
                tracing::info!("⏹ Stream cancelled by {}", from_id);
            }
            "unread_counts" => {
                self.handle_unread_counts(data).await?;
            }
            _ => {
                tracing::debug!("WS message type '{}'", msg_type);
            }
        }

        Ok(())
    }

    /// Accept a friend request via REST API
    async fn accept_friend_request(&self, request_id: &str) {
        let jwt = self.jwt_token.lock().await;
        let token = match jwt.as_deref() {
            Some(t) => t.to_string(),
            None => return,
        };
        drop(jwt);

        let client = reqwest::Client::new();
        let url = format!(
            "{}/api/v1/friends/requests/{}/accept",
            self.config.agent.server_url, request_id
        );

        match client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({}))
            .send()
            .await
        {
            Ok(res) => {
                if res.status().is_success() {
                    tracing::info!("✅ Friend request accepted!");
                } else {
                    tracing::warn!("Friend accept failed: {}", res.status());
                }
            }
            Err(e) => {
                tracing::warn!("Friend accept error: {}", e);
            }
        }
    }

    /// Process incoming message and generate a reply via Z.AI
    async fn process_and_reply(
        &self,
        from_id: &str,
        content: &str,
        ws: &mut futures::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            tungstenite::Message,
        >,
    ) -> Result<()> {
        let account_id = self.server_account_id.lock().await;
        if from_id == account_id.as_deref().unwrap_or("") || from_id == self.config.agent.agent_id {
            return Ok(());
        }
        drop(account_id);

        // Dedup - safe UTF-8 truncation
        let content_preview: String = content.chars().take(100).collect();
        let dedup_key = format!("{}:{}", from_id, content_preview);
        {
            let mut processed = self.processed_messages.lock().await;
            if processed.contains(&dedup_key) {
                return Ok(());
            }
            processed.insert(dedup_key.clone());
            if processed.len() > 1000 {
                let keys: Vec<String> = processed.iter().take(500).cloned().collect();
                for k in keys {
                    processed.remove(&k);
                }
            }
        }

        tracing::info!("📩 Message from {}: {}", from_id, &content.chars().take(80).collect::<String>());

        // Add to memory
        {
            let mut memory = self.memory.lock().await;
            let history = memory.entry(from_id.to_string()).or_insert_with(Vec::new);
            history.push(ConversationMessage {
                role: "user".to_string(),
                content: content.to_string(),
            });
            if history.len() > self.config.agent.max_history_per_chat {
                let drain_count = history.len() - self.config.agent.max_history_per_chat;
                history.drain(..drain_count);
            }
        }

        // Send "thinking" stream chunk to show we're processing
        self.send_stream_chunk(ws, from_id, "thinking", "💭").await;

        // Generate reply via Z.AI
        tracing::info!("🤖 Generating reply for: \"{}\"...", content.chars().take(60).collect::<String>());

        let reply_result = self
            .zai_client
            .chat_stream(
                content,
                &self.config.agent.model,
                None,
                Some(&self.config.agent.system_prompt),
                Some(Box::new(|_delta: &str, _is_thinking: bool| {
                    // We'll send the complete reply, not individual chunks
                })),
            )
            .await;

        match reply_result {
            Ok(result) => {
                // Send end of thinking
                self.send_stream_chunk(ws, from_id, "reasoning_end", "").await;

                // Send the actual text reply via stream chunks
                // Split into chunks for better UX on the client
                let text = &result.text;
                if !text.is_empty() {
                    // Send in chunks of ~100 chars
                    for chunk in text.as_bytes().chunks(100) {
                        let chunk_str = String::from_utf8_lossy(chunk).to_string();
                        self.send_stream_chunk(ws, from_id, "text", &chunk_str).await;
                    }
                }

                // Send stream end
                self.send_stream_end(ws, from_id).await;

                // Also send as a complete message for persistence
                self.send_message(ws, from_id, text).await;

                tracing::info!("✅ Reply sent ({} chars)", text.len());

                // Save to memory
                let mut memory = self.memory.lock().await;
                if let Some(history) = memory.get_mut(from_id) {
                    history.push(ConversationMessage {
                        role: "assistant".to_string(),
                        content: result.text,
                    });
                }
            }
            Err(e) => {
                tracing::warn!("API failed for reply ({}), trying browser chat fallback...", e);

                // Try browser chat as fallback
                let auth_state = auth::load_auth();
                match auth_state {
                    Some(auth) => {
                        match crate::browser::chat_via_browser(content, &auth).await {
                            Ok(browser_result) => {
                                // Send end of thinking
                                self.send_stream_chunk(ws, from_id, "reasoning_end", "").await;

                                let text = &browser_result.reply;
                                if !text.is_empty() {
                                    for chunk in text.as_bytes().chunks(100) {
                                        let chunk_str = String::from_utf8_lossy(chunk).to_string();
                                        self.send_stream_chunk(ws, from_id, "text", &chunk_str).await;
                                    }
                                }

                                self.send_stream_end(ws, from_id).await;
                                self.send_message(ws, from_id, text).await;
                                tracing::info!("✅ Reply sent via browser fallback ({} chars)", text.len());

                                // Save to memory
                                let mut memory = self.memory.lock().await;
                                if let Some(history) = memory.get_mut(from_id) {
                                    history.push(ConversationMessage {
                                        role: "assistant".to_string(),
                                        content: browser_result.reply,
                                    });
                                }
                            }
                            Err(be) => {
                                tracing::error!("❌ Browser fallback also failed: {}", be);
                                self.send_stream_chunk(ws, from_id, "text", "抱歉，生成回复时出错了。请稍后再试。").await;
                                self.send_stream_end(ws, from_id).await;
                            }
                        }
                    }
                    None => {
                        tracing::error!("❌ No auth state for browser fallback");
                        self.send_stream_chunk(ws, from_id, "text", "抱歉，生成回复时出错了。请先运行 zair login。").await;
                        self.send_stream_end(ws, from_id).await;
                    }
                }
            }
        }

        Ok(())
    }

    /// Send a message via WebSocket (AICQ format: {type: "message", to: friend_id, data: msg_obj})
    async fn send_message(
        &self,
        ws: &mut futures::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            tungstenite::Message,
        >,
        friend_id: &str,
        content: &str,
    ) {
        let account_id = self.server_account_id.lock().await;
        let my_id = account_id.as_deref().unwrap_or(&self.config.agent.agent_id);
        let timestamp = chrono::Utc::now().timestamp_millis();
        let msg_id = format!("msg_{}_{}", timestamp, &uuid::Uuid::new_v4().to_string()[..8]);

        let msg_obj = serde_json::json!({
            "id": msg_id,
            "from_id": my_id,
            "to_id": friend_id,
            "type": "text",
            "content": content,
            "created_at": chrono::Utc::now().to_rfc3339(),
            "status": "sent",
        });

        let msg = serde_json::json!({
            "type": "message",
            "to": friend_id,
            "data": msg_obj,
        });

        if let Err(e) = ws
            .send(tungstenite::Message::Text(msg.to_string()))
            .await
        {
            tracing::error!("Failed to send message: {}", e);
        }
    }

    /// Send a stream chunk via WebSocket
    async fn send_stream_chunk(
        &self,
        ws: &mut futures::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            tungstenite::Message,
        >,
        friend_id: &str,
        chunk_type: &str,
        data: &str,
    ) {
        let msg = serde_json::json!({
            "type": "stream_chunk",
            "to": friend_id,
            "chunkType": chunk_type,
            "data": data,
        });

        if let Err(e) = ws
            .send(tungstenite::Message::Text(msg.to_string()))
            .await
        {
            tracing::error!("Failed to send stream chunk: {}", e);
        }
    }

    /// Send stream end signal via WebSocket
    async fn send_stream_end(
        &self,
        ws: &mut futures::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            tungstenite::Message,
        >,
        friend_id: &str,
    ) {
        let msg = serde_json::json!({
            "type": "stream_end",
            "to": friend_id,
        });

        if let Err(e) = ws
            .send(tungstenite::Message::Text(msg.to_string()))
            .await
        {
            tracing::error!("Failed to send stream end: {}", e);
        }
    }

    /// Handle unread_counts notification
    async fn handle_unread_counts(&self, data: serde_json::Value) -> Result<()> {
        let unread = &data["unread"];
        if !unread.is_object() {
            return Ok(());
        }

        tracing::info!("📬 Unread counts: {}", unread);
        // TODO: Fetch unread messages via REST API and process them
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

        // Get our own server account ID for reference
        let my_account_id = self.server_account_id.lock().await;
        let my_id = my_account_id.as_deref().unwrap_or("unknown");
        tracing::info!("My server account ID: {}", my_id);
        drop(my_account_id);

        let client = reqwest::Client::new();
        let url = format!("{}/api/v1/friends/request", self.config.agent.server_url);

        tracing::info!("📨 Sending friend request to {}...", owner_id);

        let resp = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({ "to_id": owner_id }))
            .send()
            .await;

        match resp {
            Ok(res) => {
                let status = res.status();
                let body = res.text().await.unwrap_or_default();
                if status.is_success() {
                    println!("✅ 好友请求已发送给 {}！请对方在AICQ上接受请求。", owner_id);
                    tracing::info!("Friend request sent to {} (HTTP {}): {}", owner_id, status, body);
                } else {
                    println!("❌ 好友请求失败 (HTTP {}): {}", status, body);
                    tracing::warn!("Friend request failed (HTTP {}): {}", status, body);
                    // Try to parse the error for more context
                    if let Ok(err_data) = serde_json::from_str::<serde_json::Value>(&body) {
                        if let Some(msg) = err_data["detail"].as_str().or(err_data["error"].as_str()).or(err_data["message"].as_str()) {
                            println!("   错误详情: {}", msg);
                            tracing::warn!("Error detail: {}", msg);
                        }
                    }
                }
            }
            Err(e) => {
                println!("❌ 发送好友请求网络错误: {}", e);
                tracing::warn!("Friend request error: {}", e);
            }
        }

        // Also check current friends list for debugging
        let friends_url = format!("{}/api/v1/friends", self.config.agent.server_url);
        match client
            .get(&friends_url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
        {
            Ok(res) if res.status().is_success() => {
                let body = res.text().await.unwrap_or_default();
                tracing::info!("Current friends list: {}", body);
                if let Ok(friends_data) = serde_json::from_str::<serde_json::Value>(&body) {
                    let friends = friends_data["friends"].as_array()
                        .or(friends_data.as_array());
                    if let Some(flist) = friends {
                        println!("📋 当前好友列表 ({}人):", flist.len());
                        for f in flist {
                            let fid = f["id"].as_str().or(f["account_id"].as_str()).unwrap_or("?");
                            let fname = f["nickname"].as_str().or(f["display_name"].as_str()).or(f["name"].as_str()).unwrap_or("?");
                            println!("   {} - {}", fid, fname);
                        }
                    }
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Get identity file path
    fn get_identity_path(&self) -> Result<PathBuf> {
        let data_dir = &self.config.agent.data_dir;
        Ok(PathBuf::from(data_dir).join("aicq").join("identity.json"))
    }
}
