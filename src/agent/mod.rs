//! AICQ Agent Runtime
//!
//! Connects to AICQ server via WebSocket, receives messages from
//! friends/groups, processes them with Z.AI's LLM, and sends
//! replies back through AICQ WebSocket.
//!
//! Key design: WebSocket I/O is split into:
//! - Main read loop: processes incoming messages (including Pings)
//! - Writer task: forwards outgoing messages from MPSC channel to WebSocket
//! - Browser chat tasks: run in background, send replies through the channel
//!
//! Browser session is persistent - Chrome is launched once and reused
//! for all subsequent messages, reducing latency from ~50s to ~5-10s.

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
use std::time::Duration;
use tokio::sync::Mutex;
use tokio_tungstenite::{connect_async, tungstenite};

use crate::auth;
use crate::browser::{self, BrowserSession, StreamChunk};
use crate::client::{StreamCallback, ZaiClient};
use crate::config::AppConfig;

// ─── Types ────────────────────────────────────────────────────

/// Outgoing WebSocket message channel sender.
type WsSender = tokio::sync::mpsc::Sender<tungstenite::Message>;

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

fn decode_jwt_payload(token: &str) -> Result<serde_json::Value> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        bail!("Invalid JWT format: expected 3 parts, got {}", parts.len());
    }
    let payload_b64 = parts[1];
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .or_else(|_| {
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
    /// Semaphore to limit concurrent browser chats to 1 at a time
    chat_semaphore: Arc<tokio::sync::Semaphore>,
    /// Persistent browser session - Chrome stays alive between messages
    browser_session: Arc<Mutex<Option<BrowserSession>>>,
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
            chat_semaphore: Arc::new(tokio::sync::Semaphore::new(1)),
            browser_session: Arc::new(Mutex::new(None)),
        }
    }

    /// Main run loop - connect to AICQ and process messages
    pub async fn run(&mut self) -> Result<()> {
        tracing::info!("Initializing ZAI Agent...");

        if !auth::is_logged_in() {
            tracing::warn!("No Z.AI cookie login (SDK will be used as AI backend)");
        }

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
            tokio::time::sleep(Duration::from_secs(5)).await;

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
            }

            match self.refresh_jwt().await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    tracing::warn!("JWT refresh failed ({}), re-registering...", e);
                    let _ = fs::remove_file(&identity_path);
                }
            }
        }

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

        let account_id = extract_jwt_subject(&token)
            .unwrap_or_else(|e| {
                tracing::warn!("Could not extract JWT subject: {}", e);
                identity.agent_id.clone()
            });

        tracing::info!("AICQ identity account_id={}", account_id);

        identity.jwt_token = Some(token.clone());
        identity.server_account_id = Some(account_id.clone());

        if let Some(parent) = identity_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(&identity)?;
        fs::write(&identity_path, content)?;

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

        {
            let mut jwt = self.jwt_token.lock().await;
            *jwt = Some(token.clone());
        }
        {
            let mut acct = self.server_account_id.lock().await;
            *acct = Some(account_id.clone());
        }

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

    /// Connect to AICQ WebSocket and listen for messages.
    async fn connect_and_listen(&self) -> Result<()> {
        let ws_url = self.config.agent.server_url
            .replace("https://", "wss://")
            .replace("http://", "ws://");
        let ws_url = format!("{}/ws", ws_url);

        tracing::info!("Connecting to {}...", ws_url);

        let (ws_stream, _) = connect_async(&ws_url)
            .await
            .context("Failed to connect to AICQ WebSocket")?;

        let (mut ws_sink, mut ws_rx) = ws_stream.split();

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

        let (outgoing_tx, mut outgoing_rx) = tokio::sync::mpsc::channel::<tungstenite::Message>(100);

        let writer_handle = tokio::spawn(async move {
            while let Some(msg) = outgoing_rx.recv().await {
                match &msg {
                    tungstenite::Message::Text(text) => {
                        let preview: String = text.chars().take(120).collect();
                        tracing::info!("WS writer: sending text message ({} bytes): {}...", text.len(), preview);
                    }
                    tungstenite::Message::Pong(_) => {
                        tracing::debug!("WS writer: sending pong");
                    }
                    other => {
                        tracing::info!("WS writer: sending {:?} message", other);
                    }
                }
                if let Err(e) = ws_sink.send(msg).await {
                    tracing::error!("WebSocket send failed: {}, writer task exiting", e);
                    break;
                }
                if let Err(e) = ws_sink.flush().await {
                    tracing::error!("WebSocket flush failed: {}, writer task exiting", e);
                    break;
                }
            }
            tracing::info!("Writer task exited");
        });

        while let Some(msg) = ws_rx.next().await {
            match msg {
                Ok(tungstenite::Message::Text(text)) => {
                    if let Ok(data) = serde_json::from_str::<serde_json::Value>(&text) {
                        if let Err(e) = self.handle_ws_message(data, &outgoing_tx).await {
                            tracing::error!("Error handling WS message: {}", e);
                        }
                    }
                }
                Ok(tungstenite::Message::Ping(data)) => {
                    let _ = outgoing_tx.send(tungstenite::Message::Pong(data)).await;
                }
                Ok(tungstenite::Message::Close(_)) => {
                    tracing::warn!("WebSocket connection closed by server");
                    break;
                }
                Err(e) => {
                    tracing::error!("WebSocket read error: {}", e);
                    break;
                }
                _ => {}
            }
        }

        drop(outgoing_tx);
        let _ = writer_handle.await;

        // Shutdown browser session on disconnect (Chrome will be killed)
        // Actually, let's keep Chrome alive for reconnection - only kill on program exit
        // {
        //     let mut session = self.browser_session.lock().await;
        //     if let Some(ref mut s) = *session {
        //         s.shutdown();
        //     }
        //     *session = None;
        // }

        tracing::info!("WebSocket loop ended");
        Ok(())
    }

    /// Handle incoming WebSocket message
    async fn handle_ws_message(
        &self,
        data: serde_json::Value,
        outgoing_tx: &WsSender,
    ) -> Result<()> {
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
            "system_broadcast" | "system" => {
                tracing::info!(
                    "System: {}",
                    data["message"].as_str().unwrap_or("")
                );
            }
            "friends_online" => {
                let node_ids: Vec<&str> = data["nodeIds"]
                    .as_array()
                    .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
                    .unwrap_or_default();
                tracing::info!("Friends online: {:?}", node_ids);
            }
            "presence" => {
                let node_id = data["nodeId"].as_str().unwrap_or("");
                let online = data["online"].as_bool().unwrap_or(false);
                tracing::info!("{} is {}", node_id, if online { "online" } else { "offline" });
            }
            "message_ack" => {
                tracing::debug!("Message ack: to={} status={}", 
                    data["to"].as_str().unwrap_or("?"),
                    data["status"].as_str().unwrap_or("?"));
            }
            "message" | "private_message" => {
                let from_id = data["from"].as_str()
                    .or_else(|| data["fromId"].as_str())
                    .or_else(|| data["data"]["from_id"].as_str())
                    .unwrap_or("");

                let content = data["data"]["content"].as_str()
                    .or_else(|| data["content"].as_str())
                    .or_else(|| data["data"]["text"].as_str())
                    .unwrap_or("");

                if !from_id.is_empty() && !content.trim().is_empty() {
                    self.spawn_chat_reply(from_id, content, outgoing_tx.clone()).await;
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
                    self.spawn_chat_reply(from_id, content, outgoing_tx.clone()).await;
                }
            }
            "friend_request" => {
                tracing::info!("Friend request received");
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
                        tracing::info!("Auto-accepting friend request {} from {}", request_id, from_id);
                        self.accept_friend_request(request_id).await;
                    }
                }
            }
            "stream_cancel" => {
                let from_id = data["from"].as_str().unwrap_or("");
                tracing::info!("Stream cancelled by {}", from_id);
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

    /// Spawn a background task to process a message and generate a reply via browser chat.
    ///
    /// Uses a persistent BrowserSession that keeps Chrome alive between messages,
    /// reducing per-message latency from ~50s to ~5-10s.
    async fn spawn_chat_reply(
        &self,
        from_id: &str,
        content: &str,
        outgoing_tx: WsSender,
    ) {
        // Skip messages from self
        {
            let account_id = self.server_account_id.lock().await;
            if from_id == account_id.as_deref().unwrap_or("") || from_id == self.config.agent.agent_id {
                return;
            }
        }

        let memory = self.memory.clone();
        let processed_messages = self.processed_messages.clone();
        let config = self.config.clone();
        let server_account_id = self.server_account_id.clone();
        let chat_semaphore = self.chat_semaphore.clone();
        let browser_session = self.browser_session.clone();
        let auth_state = auth::load_auth();
        
        let from_id_owned = from_id.to_string();
        let content_owned = content.to_string();

        tracing::info!("Message from {}: {}", from_id, &content.chars().take(80).collect::<String>());

        tokio::spawn(async move {
            // ── Dedup check ──
            let content_preview: String = content_owned.chars().take(100).collect();
            let dedup_key = format!("{}:{}", from_id_owned, content_preview);
            {
                let mut processed = processed_messages.lock().await;
                if processed.contains(&dedup_key) {
                    tracing::debug!("Skipping duplicate message from {}", from_id_owned);
                    return;
                }
                processed.insert(dedup_key);
                if processed.len() > 1000 {
                    let keys: Vec<String> = processed.iter().take(500).cloned().collect();
                    for k in keys {
                        processed.remove(&k);
                    }
                }
            }

            // ── Add to memory (user message) ──
            {
                let mut mem = memory.lock().await;
                let history = mem.entry(from_id_owned.clone()).or_insert_with(Vec::new);
                history.push(ConversationMessage {
                    role: "user".to_string(),
                    content: content_owned.clone(),
                });
                if history.len() > config.agent.max_history_per_chat {
                    let drain_count = history.len() - config.agent.max_history_per_chat;
                    history.drain(..drain_count);
                }
            }

            // ── Acquire chat semaphore (limit to 1 concurrent browser chat) ──
            tracing::info!("Queuing browser chat for: \"{}\"...", content_owned.chars().take(60).collect::<String>());
            let _permit = match tokio::time::timeout(
                Duration::from_secs(300),
                chat_semaphore.acquire()
            ).await {
                Ok(Ok(permit)) => permit,
                Ok(Err(e)) => {
                    tracing::error!("Semaphore acquire error: {}", e);
                    return;
                }
                Err(_) => {
                    tracing::warn!("Timeout waiting for chat semaphore, dropping message from {}", from_id_owned);
                    return;
                }
            };
            tracing::info!("Semaphore acquired, starting browser chat for: \"{}\"...", content_owned.chars().take(60).collect::<String>());

            // ── Browser chat with streaming ──
            // Two paths:
            //   1. Agent mode (GLM-5.x): uses browser fetch hijack to get real
            //      SSE stream (reasoning_content + content deltas).
            //   2. Normal chat: uses BrowserSession::chat() with DOM polling,
            //      also streams thinking + reply via the same mpsc channel.
            //
            // Both paths feed StreamChunk through `stream_tx`, which a
            // forwarder task converts into AICQ `stream_chunk` WS messages
            // (chunkType="thinking" or "text"). After the chat completes,
            // we send `stream_end` and then a final `type:"message"` with
            // the full reply (so clients that don't support streaming still
            // see the complete answer).
            match auth_state {
                Some(auth) => {
                    let agent_mode = ZaiClient::is_agent_model(&config.agent.model);
                    tracing::info!(
                        "Chat path: {} (model={})",
                        if agent_mode { "AGENT (fetch hijack + SSE)" } else { "NORMAL (DOM polling)" },
                        config.agent.model
                    );

                    // ── Stream channel + forwarder ──
                    let (stream_tx, mut stream_rx) =
                        tokio::sync::mpsc::channel::<StreamChunk>(128);
                    let stream_outgoing = outgoing_tx.clone();
                    let stream_to = from_id_owned.clone();
                    let stream_forwarder = tokio::spawn(async move {
                        while let Some(chunk) = stream_rx.recv().await {
                            // AICQ stream_chunk schema (per aicqSDK):
                            //   {type:"stream_chunk", to:<friend_id>, chunkType:"text"|"thinking", data:"..."}
                            let chunk_type_str = match chunk.chunk_type.as_str() {
                                "thinking" | "think" => "thinking",
                                _ => "text",
                            };
                            let msg = serde_json::json!({
                                "type": "stream_chunk",
                                "to": stream_to,
                                "chunkType": chunk_type_str,
                                "data": chunk.data,
                            });
                            if stream_outgoing
                                .send(tungstenite::Message::Text(msg.to_string()))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    });

                    // ── Run chat (Agent or Normal) ──
                    let chat_result: Result<browser::BrowserChatResult, anyhow::Error> = if agent_mode {
                        // Agent mode: browser fetch hijack via persistent session
                        // (reuses Chrome across calls → ~10-15s instead of ~80s)
                        let stream_tx_for_cb = stream_tx.clone();
                        let cb: StreamCallback = Box::new(move |delta: &str, is_thinking: bool| {
                            let chunk = StreamChunk {
                                chunk_type: if is_thinking { "thinking".to_string() } else { "reply".to_string() },
                                data: delta.to_string(),
                            };
                            let _ = stream_tx_for_cb.try_send(chunk);
                        });
                        let agent_model = config.agent.model.clone();
                        let agent_message = content_owned.clone();

                        let agent_result = {
                            let mut session_guard = browser_session.lock().await;
                            if session_guard.is_none() {
                                tracing::info!("Creating new BrowserSession for Agent mode...");
                                *session_guard = Some(BrowserSession::new(&auth));
                            }
                            let session = session_guard.as_mut().unwrap();
                            tokio::time::timeout(
                                Duration::from_secs(180),
                                session.chat_agent(&agent_message, &agent_model, Some(&cb)),
                            ).await
                        };
                        match agent_result {
                            Ok(Ok(r)) => Ok(r),
                            Ok(Err(e)) => Err(e),
                            Err(_) => Err(anyhow::anyhow!("Agent mode timed out (3 minutes)")),
                        }
                    } else {
                        // Normal chat: BrowserSession (DOM polling, also streams)
                        let browser_result = {
                            let mut session_guard = browser_session.lock().await;
                            if session_guard.is_none() {
                                tracing::info!("Creating new BrowserSession...");
                                *session_guard = Some(BrowserSession::new(&auth));
                            }
                            let session = session_guard.as_mut().unwrap();
                            tokio::time::timeout(
                                Duration::from_secs(300),
                                session.chat(&content_owned, Some(stream_tx.clone())),
                            ).await
                        };
                        match browser_result {
                            Ok(Ok(r)) => Ok(r),
                            Ok(Err(e)) => Err(e),
                            Err(_) => Err(anyhow::anyhow!("Browser chat timed out (5 minutes)")),
                        }
                    };

                    // Drop our copy of stream_tx so the forwarder can flush and exit
                    drop(stream_tx);
                    // Wait for forwarder to finish sending all queued chunks
                    let _ = stream_forwarder.await;

                    // NOTE: stream_end is sent AFTER the fallback (if any).
                    // Sending it here would tell the client the stream is over
                    // while we're still about to send fallback chunks.

                    // ── Agent mode fallback: if Agent failed and we have a
                    // non-Agent model available, retry once with normal chat.
                    // (GLM-5.2 frequently returns MODEL_CONCURRENCY_LIMIT or
                    // WORKSPACE_TOOL_INIT_ERROR, so falling back to normal
                    // chat keeps the bot responsive.)
                    let result = match chat_result {
                        Ok(r) => Ok(r),
                        Err(e) if agent_mode => {
                            tracing::warn!(
                                "Agent mode failed ({}); falling back to normal chat",
                                e
                            );
                            // Switch the existing browser session back to a non-Agent
                            // model (glm-4.7) so the fallback doesn't hit the same
                            // Agent-mode server error. This clears the localStorage
                            // selectedModels and reloads the page.
                            {
                                let mut session_guard = browser_session.lock().await;
                                if let Some(session) = session_guard.as_mut() {
                                    if let Err(switch_err) = session.switch_to_chat_mode().await {
                                        tracing::warn!(
                                            "switch_to_chat_mode failed: {} — will reset session",
                                            switch_err
                                        );
                                        *session_guard = None;
                                    }
                                } else {
                                    // No existing session — create one and switch
                                    let mut s = BrowserSession::new(&auth);
                                    if let Err(switch_err) = s.switch_to_chat_mode().await {
                                        tracing::warn!(
                                            "switch_to_chat_mode failed: {} — will proceed anyway",
                                            switch_err
                                        );
                                    }
                                    *session_guard = Some(s);
                                }
                            }
                            let (fb_tx, mut fb_rx) =
                                tokio::sync::mpsc::channel::<StreamChunk>(128);
                            let fb_outgoing = outgoing_tx.clone();
                            let fb_to = from_id_owned.clone();
                            let fb_forwarder = tokio::spawn(async move {
                                while let Some(chunk) = fb_rx.recv().await {
                                    let chunk_type_str = match chunk.chunk_type.as_str() {
                                        "thinking" | "think" => "thinking",
                                        _ => "text",
                                    };
                                    let msg = serde_json::json!({
                                        "type": "stream_chunk",
                                        "to": fb_to,
                                        "chunkType": chunk_type_str,
                                        "data": chunk.data,
                                    });
                                    if fb_outgoing
                                        .send(tungstenite::Message::Text(msg.to_string()))
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                            });
                            let fb_auth = auth.clone();
                            let fb_result = {
                                let mut session_guard = browser_session.lock().await;
                                if session_guard.is_none() {
                                    *session_guard = Some(BrowserSession::new(&fb_auth));
                                }
                                let session = session_guard.as_mut().unwrap();
                                tokio::time::timeout(
                                    Duration::from_secs(300),
                                    session.chat(&content_owned, Some(fb_tx.clone())),
                                ).await
                            };
                            drop(fb_tx);
                            let _ = fb_forwarder.await;
                            match fb_result {
                                Ok(Ok(r)) => Ok(r),
                                Ok(Err(e2)) => Err(e2),
                                Err(_) => Err(anyhow::anyhow!("Fallback browser chat timed out (5 minutes)")),
                            }
                        }
                        Err(e) => Err(e),
                    };

                    // Send stream_end signal so AICQ clients know the stream is done.
                    // This runs AFTER the fallback (if any) so the client doesn't
                    // close the stream prematurely while fallback chunks are still
                    // being sent.
                    {
                        let end_msg = serde_json::json!({
                            "type": "stream_end",
                            "to": from_id_owned,
                        });
                        let _ = outgoing_tx
                            .send(tungstenite::Message::Text(end_msg.to_string()))
                            .await;
                    }

                    // ── Process final result ──
                    match result {
                        Ok(result) => {
                            if !result.reply.is_empty() {
                                // Strip user message from beginning of reply if present
                                let clean_reply = {
                                    let reply = result.reply.trim();
                                    let user_msg = content_owned.trim();
                                    if reply.starts_with(user_msg) && reply.len() > user_msg.len() {
                                        let after = &reply[user_msg.len()..];
                                        if after.starts_with('\n') || after.starts_with("\r\n") {
                                            tracing::info!("Stripping user message prefix from reply ({} chars)", user_msg.len());
                                            after.trim_start().to_string()
                                        } else {
                                            reply.to_string()
                                        }
                                    } else if reply == user_msg {
                                        tracing::warn!("Reply is exactly the user message, likely echo");
                                        String::new()
                                    } else {
                                        reply.to_string()
                                    }
                                };

                                let clean_reply_len = clean_reply.len();
                                let _clean_reply_preview: String = clean_reply.chars().take(80).collect();

                                // Build the full message: include thinking if present
                                let full_reply = if !result.thinking.is_empty() {
                                    format!(
                                        "💭 **思考过程：**\n{}\n\n---\n\n{}",
                                        result.thinking.trim(),
                                        clean_reply
                                    )
                                } else {
                                    clean_reply
                                };

                                tracing::info!("Extracted - thinking: {} chars, reply: {} chars, clean_reply: {} chars",
                                    result.thinking.len(), result.reply.len(), clean_reply_len);

                                // Send the final complete message (covers clients that
                                // don't merge stream_chunk sequences on their own).
                                let my_id = {
                                    let acct = server_account_id.lock().await;
                                    acct.as_deref().unwrap_or(&config.agent.agent_id).to_string();
                                };

                                let msg_id = format!("msg_{}_{}", chrono::Utc::now().timestamp_millis(), &uuid::Uuid::new_v4().to_string()[..8]);
                                let msg_obj = serde_json::json!({
                                    "id": msg_id,
                                    "from_id": my_id,
                                    "to_id": from_id_owned,
                                    "type": "text",
                                    "content": full_reply,
                                    "created_at": chrono::Utc::now().to_rfc3339(),
                                    "status": "sent",
                                });

                                let msg = serde_json::json!({
                                    "type": "message",
                                    "to": from_id_owned,
                                    "data": msg_obj,
                                });

                                match outgoing_tx.send(tungstenite::Message::Text(msg.to_string())).await {
                                    Ok(_) => {
                                        tracing::info!("Reply sent (thinking: {} chars, reply: {} chars)", result.thinking.len(), result.reply.len());
                                    }
                                    Err(e) => {
                                        tracing::error!("Failed to send reply through channel: {}", e);
                                    }
                                }

                                // Save reply to memory
                                let mut mem = memory.lock().await;
                                if let Some(history) = mem.get_mut(&from_id_owned) {
                                    history.push(ConversationMessage {
                                        role: "assistant".to_string(),
                                        content: result.reply,
                                    });
                                }
                            } else {
                                send_error_reply(&outgoing_tx, &from_id_owned, &server_account_id, &config, "抱歉，未能获取到回复。请稍后再试。").await;
                                tracing::warn!("Empty reply from browser chat");
                            }
                        }
                        Err(e) => {
                            tracing::error!("Browser chat failed: {}", e);
                            // Reset session on error so it's re-initialized next time
                            let mut session_guard = browser_session.lock().await;
                            *session_guard = None;
                            send_error_reply(&outgoing_tx, &from_id_owned, &server_account_id, &config, "抱歉，生成回复时出错了。请稍后再试。").await;
                        }
                    }
                }
                None => {
                    tracing::error!("No auth state - run zair login first");
                    send_error_reply(&outgoing_tx, &from_id_owned, &server_account_id, &config, "抱歉，生成回复时出错了。请先运行 zair login。").await;
                }
            }

            // _permit is dropped here, releasing the semaphore for the next chat
        });
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
                    tracing::info!("Friend request accepted!");
                } else {
                    tracing::warn!("Friend accept failed: {}", res.status());
                }
            }
            Err(e) => {
                tracing::warn!("Friend accept error: {}", e);
            }
        }
    }

    /// Handle unread_counts notification
    async fn handle_unread_counts(&self, data: serde_json::Value) -> Result<()> {
        let unread = &data["unread"];
        if !unread.is_object() {
            return Ok(());
        }

        tracing::info!("Unread counts: {}", unread);
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

        let my_account_id = self.server_account_id.lock().await;
        let my_id = my_account_id.as_deref().unwrap_or("unknown");
        tracing::info!("My server account ID: {}", my_id);
        drop(my_account_id);

        let client = reqwest::Client::new();
        let url = format!("{}/api/v1/friends/request", self.config.agent.server_url);

        tracing::info!("Sending friend request to {}...", owner_id);

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
                    println!("Friend request sent to {}!", owner_id);
                    tracing::info!("Friend request sent to {} (HTTP {}): {}", owner_id, status, body);
                } else {
                    println!("Friend request failed (HTTP {}): {}", status, body);
                    tracing::warn!("Friend request failed (HTTP {}): {}", status, body);
                    if let Ok(err_data) = serde_json::from_str::<serde_json::Value>(&body) {
                        if let Some(msg) = err_data["detail"].as_str().or(err_data["error"].as_str()).or(err_data["message"].as_str()) {
                            println!("   Error detail: {}", msg);
                            tracing::warn!("Error detail: {}", msg);
                        }
                    }
                }
            }
            Err(e) => {
                println!("Friend request network error: {}", e);
                tracing::warn!("Friend request error: {}", e);
            }
        }

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
                        println!("Current friends ({}):", flist.len());
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

/// Helper to send an error reply via the outgoing channel
async fn send_error_reply(
    outgoing_tx: &WsSender,
    from_id: &str,
    server_account_id: &Arc<Mutex<Option<String>>>,
    config: &AppConfig,
    error_msg: &str,
) {
    let my_id = {
        let acct = server_account_id.lock().await;
        acct.as_deref().unwrap_or(&config.agent.agent_id).to_string()
    };

    let msg_id = format!("msg_{}_{}", chrono::Utc::now().timestamp_millis(), &uuid::Uuid::new_v4().to_string()[..8]);
    let msg_obj = serde_json::json!({
        "id": msg_id,
        "from_id": my_id,
        "to_id": from_id,
        "type": "text",
        "content": error_msg,
        "created_at": chrono::Utc::now().to_rfc3339(),
        "status": "sent",
    });

    let msg = serde_json::json!({
        "type": "message",
        "to": from_id,
        "data": msg_obj,
    });

    let _ = outgoing_tx.send(tungstenite::Message::Text(msg.to_string())).await;
}
