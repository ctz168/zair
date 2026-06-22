//! Browser Automation via Raw CDP
//!
//! Launches Chrome as a subprocess with --remote-debugging-port, then
//! connects directly via WebSocket using the Chrome DevTools Protocol.
//! This avoids chromiumoxide's deserialization errors with modern Chrome.
//!
//! Key design: Chrome is launched ONCE and kept alive between chat
//! operations. Subsequent messages reuse the existing Chrome instance,
//! reducing per-message latency from ~50s to ~5-10s.

use anyhow::{bail, Context, Result};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;

use std::process::{Child, Command};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio_tungstenite::tungstenite;

use crate::auth::{extract_access_token, extract_refresh_token, ZaiAuthState, ZAI_CHAT_URL};
use crate::client::StreamCallback;

// ─── CDP Types ────────────────────────────────────────────────

static CDP_ID: AtomicU64 = AtomicU64::new(1);

fn next_cdp_id() -> u64 {
    CDP_ID.fetch_add(1, Ordering::Relaxed)
}

/// Build a CDP command as JSON string
fn cdp_command(method: &str, params: serde_json::Value) -> String {
    let id = next_cdp_id();
    serde_json::json!({
        "id": id,
        "method": method,
        "params": params,
    })
    .to_string()
}

/// Build a CDP command without params
fn cdp_command_no_params(method: &str) -> String {
    let id = next_cdp_id();
    serde_json::json!({
        "id": id,
        "method": method,
    })
    .to_string()
}

/// Chrome target info from /json endpoint
#[derive(Debug, Deserialize)]
struct ChromeTarget {
    #[serde(rename = "webSocketDebuggerUrl")]
    ws_url: Option<String>,
    url: Option<String>,
    r#type: Option<String>,
}

/// CDP cookie from Network.getCookies response
#[derive(Debug, Deserialize)]
struct CdpCookie {
    name: String,
    value: String,
    domain: Option<String>,
    path: Option<String>,
}

/// CDP response result
#[derive(Debug, Deserialize)]
struct CdpResponse {
    id: Option<u64>,
    result: Option<serde_json::Value>,
    error: Option<CdpError>,
    method: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CdpError {
    message: Option<String>,
}

// ─── CDP Port Constants ────────────────────────────────────────

/// CDP port for interactive (non-headless) Chrome (login mode)
const ZAI_CDP_PORT: u16 = 9222;
/// CDP port for headless Chrome (chat mode - persistent)
const ZAI_CDP_PORT_HEADLESS: u16 = 9223;

/// Default Chrome data directory name
fn chrome_data_dir() -> std::path::PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        .join("zair-chrome")
}

/// Kill all Chrome processes (Windows + Unix)
fn kill_chrome_processes() {
    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("taskkill")
            .args(["/f", "/im", "chrome.exe"])
            .output();
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = Command::new("pkill")
            .arg("-9")
            .arg("chrome")
            .output();
    }
}

// ─── Chrome Process Manager (for login only) ────────────────────

/// Manages a Chrome subprocess with remote debugging enabled
struct ChromeProcess {
    child: Option<Child>,
    debug_port: u16,
}

impl ChromeProcess {
    /// Launch Chrome with remote debugging port (for login)
    fn launch(headless: bool) -> Result<Self> {
        let chrome_path = which_chrome()?;
        let port = ZAI_CDP_PORT;

        tracing::info!("Launching Chrome at {} on port {}", chrome_path.display(), port);

        let data_dir = chrome_data_dir();

        let mut cmd = Command::new(&chrome_path);
        cmd.args([
            &format!("--remote-debugging-port={}", port),
            &format!("--user-data-dir={}", data_dir.display()),
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-client-side-phishing-detection",
            "--disable-default-apps",
            "--disable-hang-monitor",
            "--disable-popup-blocking",
            "--disable-prompt-on-repost",
            "--disable-sync",
            "--disable-translate",
            "--metrics-recording-only",
            "--safebrowsing-disable-auto-update",
        ]);

        if headless {
            cmd.arg("--headless=new");
        }

        let child = cmd.spawn().context("Failed to launch Chrome process")?;

        Ok(Self {
            child: Some(child),
            debug_port: port,
        })
    }

    /// Get the debug URL for the browser target
    fn debug_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.debug_port)
    }

    /// Get WebSocket URL for a page target
    async fn get_page_ws_url(&self) -> Result<String> {
        let json_url = format!("{}/json", self.debug_url());
        let client = reqwest::Client::new();

        for attempt in 0..20 {
            match client.get(&json_url).send().await {
                Ok(res) if res.status().is_success() => {
                    let targets: Vec<ChromeTarget> = res.json().await?;
                    for target in &targets {
                        if target.r#type.as_deref() == Some("page") {
                            if let Some(ws_url) = &target.ws_url {
                                tracing::debug!("Found page target: {}", ws_url);
                                return Ok(ws_url.clone());
                            }
                        }
                    }
                    for target in &targets {
                        if let Some(ws_url) = &target.ws_url {
                            return Ok(ws_url.clone());
                        }
                    }
                    bail!("No page targets found in Chrome");
                }
                _ => {
                    if attempt < 19 {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            }
        }
        bail!("Chrome did not start after 10 seconds (could not reach {})", json_url);
    }
}

impl Drop for ChromeProcess {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
            tracing::debug!("Chrome process terminated");
        }
    }
}

// ─── CDP Connection ────────────────────────────────────────────

/// Direct CDP connection to Chrome via WebSocket
pub struct CdpConnection {
    ws: futures::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        tungstenite::Message,
    >,
    ws_rx: futures::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
}

impl CdpConnection {
    /// Connect to Chrome's CDP WebSocket endpoint
    pub async fn connect(ws_url: &str) -> Result<Self> {
        tracing::info!("Connecting to Chrome CDP: {}", ws_url);

        let (ws_stream, _) = tokio_tungstenite::connect_async(ws_url)
            .await
            .context("Failed to connect to Chrome CDP WebSocket")?;

        let (ws, ws_rx) = ws_stream.split();

        Ok(Self { ws, ws_rx })
    }

    /// Send a CDP command and wait for the matching response
    pub async fn send_command(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let cmd = cdp_command(method, params);
        let cmd_id: u64 = serde_json::from_str::<serde_json::Value>(&cmd)
            .unwrap()["id"]
            .as_u64()
            .unwrap();

        self.ws
            .send(tungstenite::Message::Text(cmd))
            .await
            .context("Failed to send CDP command")?;

        let timeout = Duration::from_secs(30);
        let start = std::time::Instant::now();

        while start.elapsed() < timeout {
            match tokio::time::timeout(Duration::from_secs(5), self.ws_rx.next()).await {
                Ok(Some(Ok(tungstenite::Message::Text(text)))) => {
                    if let Ok(resp) = serde_json::from_str::<CdpResponse>(&text) {
                        if resp.id == Some(cmd_id) {
                            if let Some(error) = resp.error {
                                bail!("CDP error for {}: {:?}", method, error.message);
                            }
                            return Ok(resp.result.unwrap_or(serde_json::Value::Null));
                        }
                    }
                }
                Ok(Some(Ok(tungstenite::Message::Ping(data)))) => {
                    let _ = self.ws.send(tungstenite::Message::Pong(data)).await;
                }
                Ok(Some(Err(e))) => {
                    tracing::warn!("CDP WebSocket error: {}", e);
                    break;
                }
                Ok(None) => {
                    bail!("CDP WebSocket closed");
                }
                Ok(Some(_)) => {}
                Err(_) => {
                    continue;
                }
            }
        }

        bail!("Timeout waiting for CDP response to {}", method);
    }

    /// Send a CDP command without params, ignore response
    pub async fn send_notification(&mut self, method: &str) -> Result<()> {
        let cmd = cdp_command_no_params(method);
        self.ws
            .send(tungstenite::Message::Text(cmd))
            .await
            .context("Failed to send CDP notification")?;
        Ok(())
    }

    /// Evaluate JavaScript and return the result value
    pub async fn evaluate(&mut self, expression: &str) -> Result<serde_json::Value> {
        let result = self
            .send_command(
                "Runtime.evaluate",
                serde_json::json!({
                    "expression": expression,
                    "returnByValue": true,
                    "awaitPromise": false,
                }),
            )
            .await?;

        if let Some(exception) = result.get("exceptionDetails") {
            let desc = exception["exception"]["description"]
                .as_str()
                .unwrap_or("Unknown JS error");
            bail!("JavaScript error: {}", desc);
        }

        Ok(result.get("result").and_then(|r| r.get("value")).cloned().unwrap_or(serde_json::Value::Null))
    }

    /// Navigate to a URL
    pub async fn navigate(&mut self, url: &str) -> Result<()> {
        let _ = self
            .send_command(
                "Page.navigate",
                serde_json::json!({ "url": url }),
            )
            .await?;
        Ok(())
    }

    /// Send a CDP command, then enter an event loop that:
    ///   - forwards each CDP event to `on_event` (which can return Ok(true) to stop)
    ///   - returns the matching response when it arrives
    ///
    /// This is needed for Fetch.requestPaused / Network.responseReceived etc.
    /// where we must react to events while waiting for the response of an
    /// unrelated command.
    pub async fn send_command_with_events<F>(
        &mut self,
        method: &str,
        params: serde_json::Value,
        mut on_event: F,
    ) -> Result<serde_json::Value>
    where
        F: FnMut(&str, &serde_json::Value) -> Result<bool>,
    {
        let cmd = cdp_command(method, params);
        let cmd_id: u64 = serde_json::from_str::<serde_json::Value>(&cmd)
            .unwrap()["id"]
            .as_u64()
            .unwrap();

        self.ws
            .send(tungstenite::Message::Text(cmd))
            .await
            .context("Failed to send CDP command")?;

        let timeout = Duration::from_secs(300); // long timeout for SSE
        let start = std::time::Instant::now();

        while start.elapsed() < timeout {
            match tokio::time::timeout(Duration::from_secs(60), self.ws_rx.next()).await {
                Ok(Some(Ok(tungstenite::Message::Text(text)))) => {
                    let v: serde_json::Value = match serde_json::from_str(&text) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    // If this is the response to our command, return it.
                    if v.get("id").and_then(|i| i.as_u64()) == Some(cmd_id) {
                        if let Some(error) = v.get("error") {
                            bail!(
                                "CDP error for {}: {:?}",
                                method,
                                error.get("message").and_then(|m| m.as_str()).unwrap_or("?")
                            );
                        }
                        return Ok(v.get("result").cloned().unwrap_or(serde_json::Value::Null));
                    }
                    // Otherwise, it's an event — invoke callback.
                    if let Some(m) = v.get("method").and_then(|m| m.as_str()) {
                        let params = v.get("params").cloned().unwrap_or(serde_json::Value::Null);
                        if let Ok(true) = on_event(m, &params) {
                            // Callback says stop — but we still wait for the
                            // matching response (it'll come eventually). Loop on.
                        }
                    }
                }
                Ok(Some(Ok(tungstenite::Message::Ping(data)))) => {
                    let _ = self.ws.send(tungstenite::Message::Pong(data)).await;
                }
                Ok(Some(Err(e))) => {
                    bail!("CDP WebSocket error: {}", e);
                }
                Ok(None) => {
                    bail!("CDP WebSocket closed");
                }
                Ok(Some(_)) => {}
                Err(_) => {
                    continue;
                }
            }
        }
        bail!("Timeout waiting for CDP response to {}", method);
    }

    /// Send a raw CDP notification (with params) without waiting for response.
    /// Used for Fetch.continueRequest / Fetch.failRequest etc.
    pub async fn send_notification_with_params(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<()> {
        let cmd = cdp_command(method, params);
        self.ws
            .send(tungstenite::Message::Text(cmd))
            .await
            .context("Failed to send CDP notification")?;
        Ok(())
    }

    /// Get all cookies
    async fn get_cookies(&mut self) -> Result<Vec<CdpCookie>> {
        let result = self
            .send_command("Network.getCookies", serde_json::json!({}))
            .await?;

        let cookies: Vec<CdpCookie> = result
            .get("cookies")
            .cloned()
            .map(|v| serde_json::from_value(v).unwrap_or_default())
            .unwrap_or_default();

        Ok(cookies)
    }

    /// Set a cookie
    async fn set_cookie(&mut self, name: &str, value: &str, domain: &str, path: &str) -> Result<()> {
        self.send_command(
            "Network.setCookie",
            serde_json::json!({
                "name": name,
                "value": value,
                "domain": domain,
                "path": path,
            }),
        )
        .await?;
        Ok(())
    }
}

// ─── Browser Session (Persistent Chrome) ────────────────────────

/// Persistent browser session that keeps Chrome alive between chat operations.
///
/// Instead of launching Chrome for every message, this session launches Chrome
/// once and reuses it for subsequent messages. This reduces per-message latency
/// from ~50s to ~5-10s.
pub struct BrowserSession {
    /// Chrome child process handle - kept alive for the session lifetime
    chrome_child: Option<Child>,
    /// CDP port for the headless Chrome instance
    port: u16,
    /// Auth state for cookie injection
    auth_state: ZaiAuthState,
    /// Whether the session has been fully initialized (cookies injected, login verified)
    pub initialized: bool,
}

impl BrowserSession {
    /// Create a new browser session with the given auth state
    pub fn new(auth_state: &ZaiAuthState) -> Self {
        Self {
            chrome_child: None,
            port: ZAI_CDP_PORT_HEADLESS,
            auth_state: auth_state.clone(),
            initialized: false,
        }
    }

    /// Check if the session is fully initialized.
    pub async fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Ensure Chrome is running and reachable via CDP.
    /// Returns the CDP port number.
    pub async fn ensure_running(&mut self) -> Result<u16> {
        // Check if our Chrome process is still alive
        let child_alive = self.chrome_child.as_mut().map_or(false, |child| {
            matches!(child.try_wait(), Ok(None))
        });

        if child_alive {
            // Verify CDP is reachable
            if let Ok(ws_url) = get_page_ws_url_for_port(self.port).await {
                if let Ok(mut cdp) = CdpConnection::connect(&ws_url).await {
                    if cdp.evaluate("1+1").await.ok().and_then(|v| v.as_u64()) == Some(2) {
                        tracing::info!("Existing Chrome instance is alive on port {}", self.port);
                        return Ok(self.port);
                    }
                }
            }
            // Chrome process alive but CDP not responding - kill and relaunch
            tracing::warn!("Chrome process alive but CDP not responding, restarting...");
            if let Some(ref mut child) = self.chrome_child {
                let _ = child.kill();
                let _ = child.wait();
            }
            self.chrome_child = None;
            self.initialized = false;
        } else if self.chrome_child.is_some() {
            // Chrome process exited
            tracing::warn!("Chrome process has exited, restarting...");
            self.chrome_child = None;
            self.initialized = false;
        }

        // Try to connect to an existing Chrome instance on our port
        // (maybe from a previous run that didn't shut down cleanly)
        if let Ok(ws_url) = get_page_ws_url_for_port(self.port).await {
            if let Ok(mut cdp) = CdpConnection::connect(&ws_url).await {
                if cdp.evaluate("1+1").await.ok().and_then(|v| v.as_u64()) == Some(2) {
                    tracing::info!("Found existing Chrome on port {}, adopting it", self.port);
                    // We don't have the Child handle, but Chrome is running.
                    // This is fine - we'll check CDP reachability on each call.
                    // Check if the existing Chrome session is already on chat.z.ai and logged in
                    let url_check = cdp.evaluate("window.location.href").await
                        .ok().and_then(|v| v.as_str().map(|s| s.to_string())).unwrap_or_default();
                    let has_ta = cdp.evaluate("document.querySelector('textarea') !== null").await
                        .ok().and_then(|v| v.as_bool()).unwrap_or(false);
                    let has_auth = cdp.evaluate("document.cookie.includes('acw_tc')").await
                        .ok().and_then(|v| v.as_bool()).unwrap_or(false);
                    if url_check.contains("chat.z.ai") && has_ta && has_auth {
                        tracing::info!("Existing Chrome session already initialized on chat.z.ai");
                        self.initialized = true;
                    } else {
                        tracing::info!("Existing Chrome found but needs re-initialization (url={}, ta={}, auth={})", 
                            url_check.chars().take(50).collect::<String>(), has_ta, has_auth);
                        self.initialized = false;
                    }
                    return Ok(self.port);
                }
            }
        }

        // No existing Chrome - launch a new one
        tracing::info!("Launching persistent headless Chrome on port {}...", self.port);
        self.launch_chrome().await?;
        Ok(self.port)
    }

    /// Launch a new Chrome instance
    async fn launch_chrome(&mut self) -> Result<()> {
        let chrome_path = which_chrome()?;
        let data_dir = chrome_data_dir();

        // Kill any existing Chrome that might hold the profile lock
        kill_chrome_processes();
        tokio::time::sleep(Duration::from_secs(1)).await;

        let mut cmd = Command::new(&chrome_path);
        cmd.args([
            &format!("--remote-debugging-port={}", self.port),
            &format!("--user-data-dir={}", data_dir.display()),
            "--headless=new",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-gpu",
            "--disable-software-rasterizer",
            "--disable-dev-shm-usage",
            "--no-sandbox",
            "--disable-background-networking",
            "--disable-client-side-phishing-detection",
            "--disable-default-apps",
            "--disable-hang-monitor",
            "--disable-popup-blocking",
            "--disable-prompt-on-repost",
            "--disable-sync",
            "--disable-translate",
            "--metrics-recording-only",
            "--safebrowsing-disable-auto-update",
            "--remote-allow-origins=*",
        ]);

        tracing::info!("Launching headless Chrome on port {}", self.port);
        let child = cmd.spawn().context("Failed to launch Chrome process")?;
        self.chrome_child = Some(child);

        // Wait for Chrome to be ready
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Verify Chrome started
        for attempt in 0..15 {
            match get_page_ws_url_for_port(self.port).await {
                Ok(_) => {
                    tracing::info!("Chrome is ready on port {}", self.port);
                    return Ok(());
                }
                Err(_) => {
                    if attempt < 14 {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            }
        }

        bail!("Chrome failed to start on port {} after 10 seconds", self.port)
    }

    /// Initialize the browser session (inject cookies, verify login).
    /// Called on first use or when the session needs to be re-initialized.
    async fn initialize_session(&mut self, cdp: &mut CdpConnection) -> Result<()> {
        if self.initialized {
            return Ok(());
        }

        // Inject stealth scripts
        inject_stealth_via_cdp(cdp).await?;

        // Navigate to z.ai first (cookies need a domain context)
        tracing::info!("Initializing browser session - navigating to chat.z.ai...");
        cdp.navigate("https://chat.z.ai").await?;
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Inject cookies via CDP
        inject_cookies_cdp(cdp, &self.auth_state.cookie).await?;

        // Also inject via JavaScript as fallback
        let js_cookie_result = cdp.evaluate(&format!(r#"
            (() => {{
                const cookieStr = {:?};
                const pairs = cookieStr.split('; ');
                let count = 0;
                for (const pair of pairs) {{
                    try {{
                        document.cookie = pair + '; path=/; domain=.z.ai';
                        count++;
                    }} catch(e) {{}}
                }}
                return count;
            }})()
        "#, self.auth_state.cookie)).await;
        tracing::info!("JS cookie injection result: {:?}", js_cookie_result);

        // Reload with cookies now set
        tracing::info!("Reloading chat.z.ai with cookies...");
        cdp.navigate(ZAI_CHAT_URL).await?;
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Force a hard reload
        cdp.evaluate("location.reload(true)").await?;
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Verify we're logged in
        let login_check = cdp.evaluate(r#"
            (() => {
                const ta = document.querySelector('textarea');
                const placeholder = ta ? ta.placeholder : '';
                const cookieStr = document.cookie;
                const hasAuth = cookieStr.includes('token=') || cookieStr.includes('chatglm');
                return JSON.stringify({
                    hasTextarea: ta !== null,
                    placeholder: placeholder,
                    hasAuthCookie: hasAuth,
                    cookiePreview: cookieStr.substring(0, 200),
                    url: window.location.href,
                });
            })()
        "#).await;
        tracing::info!("Login check after cookie injection: {:?}", login_check);

        // Note: The Agent/Chat mode toggle has been removed from chat.z.ai's UI
        // as of 2026-06. The site now uses a unified chat interface.
        // Previously, there were "Chat 模式" and "Agent 模式" buttons in the sidebar.
        // If the toggle returns in the future, we can re-enable this logic.
        let agent_mode_result = cdp.evaluate(r#"
            (() => {
                // Check if Agent mode toggle exists
                const buttons = document.querySelectorAll('button');
                for (const btn of buttons) {
                    const text = btn.innerText || '';
                    if (text.includes('Agent') && (text.includes('模式') || text.includes('mode') || text.includes('Mode'))) {
                        const isActive = btn.getAttribute('data-active') === 'true';
                        if (!isActive) {
                            btn.click();
                            return 'clicked Agent mode';
                        }
                        return 'already in Agent mode';
                    }
                }
                return 'Agent mode button not found (expected - UI updated)';
            })()
        "#).await;
        tracing::info!("Agent mode switch: {:?}", agent_mode_result);
        tokio::time::sleep(Duration::from_millis(500)).await;

        self.initialized = true;
        Ok(())
    }

    /// Chat with Z.AI using the persistent browser session.
    /// Reuses the Chrome instance across calls for much faster response times.
    pub async fn chat(
        &mut self,
        message: &str,
        stream_tx: Option<tokio::sync::mpsc::Sender<StreamChunk>>,
    ) -> Result<BrowserChatResult> {
        tracing::info!("Starting browser chat...");
        let start = std::time::Instant::now();

        // Ensure Chrome is running
        self.ensure_running().await?;

        // Connect to Chrome CDP
        let ws_url = get_page_ws_url_for_port(self.port).await?;
        let mut cdp = CdpConnection::connect(&ws_url).await?;

        // Enable domains
        cdp.send_notification("Page.enable").await?;
        cdp.send_notification("Network.enable").await?;
        cdp.send_notification("Runtime.enable").await?;

        if !self.initialized {
            // Full initialization needed (first time or Chrome restarted)
            self.initialize_session(&mut cdp).await?;
        } else {
            // Session already initialized - check if page is still valid
            let current_url = cdp.evaluate("window.location.href").await
                .ok()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_default();

            let on_chat_page = current_url.contains("chat.z.ai");

            if on_chat_page {
                // Note: Agent/Chat mode toggle removed from chat.z.ai UI (2026-06).
                // The site now uses a unified chat interface.
                // If the toggle is present in the future, click it.
                let _current_mode = cdp.evaluate(r#"
                    (() => {
                        const buttons = document.querySelectorAll('button');
                        for (const btn of buttons) {
                            const text = btn.innerText || '';
                            if (text.includes('Agent') && (text.includes('模式') || text.includes('mode') || text.includes('Mode'))) {
                                return btn.getAttribute('data-active') === 'true' ? 'agent' : 'chat';
                            }
                        }
                        return 'unified';
                    })()
                "#).await.ok().and_then(|v| v.as_str().map(|s| s.to_string())).unwrap_or_default();
                
                // Navigate to root URL to start a new conversation
                tracing::info!("Starting new conversation on existing session...");
                // Try clicking "New Chat" button first (faster than full navigation)
                let new_chat_result = cdp.evaluate(r#"
                    (() => {
                        // Look for sidebar "New Chat" or similar button
                        const links = document.querySelectorAll('a[href="/"], a[href="/c"], [class*="new-chat"], [class*="newChat"]');
                        for (const link of links) {
                            if (link.innerText.includes('新对话') || link.innerText.includes('New') || link.getAttribute('href') === '/') {
                                link.click();
                                return 'clicked_new_chat';
                            }
                        }
                        // Fallback: look for any button with "new" or "新"
                        const buttons = document.querySelectorAll('button');
                        for (const btn of buttons) {
                            const text = btn.innerText || '';
                            if (text.includes('新对话') || text.includes('New Chat') || text.includes('新建')) {
                                btn.click();
                                return 'clicked_button';
                            }
                        }
                        return 'not_found';
                    })()
                "#).await.ok().and_then(|v| v.as_str().map(|s| s.to_string())).unwrap_or_default();
                if new_chat_result != "not_found" {
                    tracing::info!("New conversation via button: {}", new_chat_result);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                } else {
                    // Fallback: navigate to root URL
                    cdp.navigate("https://chat.z.ai/").await?;
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }

                // Verify textarea is present (session might have expired)
                let has_textarea = cdp.evaluate(r#"
                    (() => document.querySelector('textarea') !== null)()
                "#).await.ok().and_then(|v| v.as_bool()).unwrap_or(false);

                if !has_textarea {
                    tracing::warn!("Session expired (no textarea), re-initializing...");
                    self.initialized = false;
                    self.initialize_session(&mut cdp).await?;
                }
            } else {
                // Not on chat.z.ai - need to navigate there
                tracing::info!("Not on chat.z.ai (at {}), re-initializing...", current_url);
                self.initialized = false;
                self.initialize_session(&mut cdp).await?;
            }
        }

        // Type message and poll for response
        type_message_and_poll(&mut cdp, message, stream_tx, start).await
    }

    /// Shutdown the browser session (kill Chrome)
    pub fn shutdown(&mut self) {
        if let Some(ref mut child) = self.chrome_child {
            tracing::info!("Shutting down Chrome...");
            let _ = child.kill();
            let _ = child.wait();
        }
        self.chrome_child = None;
        self.initialized = false;
    }
}

impl Drop for BrowserSession {
    fn drop(&mut self) {
        self.shutdown();
    }
}

// ─── Cookie Injection Helpers ──────────────────────────────────

/// Inject cookies via CDP (domain-level injection)
async fn inject_cookies_cdp(cdp: &mut CdpConnection, cookie_string: &str) -> Result<()> {
    let mut cookie_count = 0;
    for cookie_part in cookie_string.split(';') {
        let trimmed = cookie_part.trim();
        if let Some(eq_idx) = trimmed.find('=') {
            let name = &trimmed[..eq_idx];
            let value = &trimmed[eq_idx + 1..];
            for domain in &[".z.ai", "chat.z.ai", "z.ai"] {
                match cdp.set_cookie(name, value, domain, "/").await {
                    Ok(_) => {}
                    Err(e) => {
                        tracing::debug!("Failed to set cookie {} for {}: {}", name, domain, e);
                    }
                }
            }
            cookie_count += 1;
        }
    }
    tracing::info!("Injected {} cookies via CDP", cookie_count);
    Ok(())
}

// ─── Message Typing & Response Polling ──────────────────────────

/// Type a message into the chat textarea and poll for the response
async fn type_message_and_poll(
    cdp: &mut CdpConnection,
    message: &str,
    stream_tx: Option<tokio::sync::mpsc::Sender<StreamChunk>>,
    start: std::time::Instant,
) -> Result<BrowserChatResult> {
    // Find and type into the textarea
    let msg_preview: String = message.chars().take(60).collect();
    tracing::info!("Sending message: \"{}\"", msg_preview);

    // Check textarea state
    let textarea_check = cdp.evaluate(r#"
        (() => {
            const ta = document.querySelector('textarea');
            const ce = document.querySelector('[contenteditable="true"]');
            return JSON.stringify({
                hasTextarea: ta !== null,
                hasContentEditable: ce !== null,
                textareaPlaceholder: ta ? ta.placeholder : null,
                url: window.location.href
            });
        })()
    "#).await?;
    tracing::info!("Page state: {:?}", textarea_check);

    // ─── Input Strategy ─────────────────────────────────────────
    // chat.z.ai uses React with a controlled textarea. The send button
    // (type="submit") is disabled until React's state sees content.
    // CDP Input.insertText sets the value but does NOT trigger React's
    // onChange/input events, so the button stays disabled and Enter
    // key submission also fails. We must use JS-based input with
    // nativeInputValueSetter + dispatched events to activate the button.
    // ────────────────────────────────────────────────────────────────

    // Click on the textarea to focus it
    cdp.evaluate(r#"
        (() => {
            const ta = document.querySelector('textarea');
            if (ta) { ta.focus(); ta.click(); }
            return ta ? 'focused' : 'not_found';
        })()
    "#).await?;

    // Small delay for focus
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Use JS-based input with React-compatible event dispatch
    // This sets the value via the native setter and fires input/change
    // events so React picks up the change and enables the submit button.
    let escaped_msg = message.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "");
    let input_result = cdp.evaluate(&format!(r#"
        (() => {{
            const ta = document.querySelector('textarea');
            if (!ta) return 'no_textarea';

            // Clear existing content
            ta.focus();
            ta.select();

            // Set value via React-compatible native setter
            const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
                window.HTMLTextAreaElement.prototype, 'value'
            ).set;
            nativeInputValueSetter.call(ta, "{escaped_msg}");

            // Dispatch React-compatible events
            ta.dispatchEvent(new Event('input', {{ bubbles: true }}));
            ta.dispatchEvent(new Event('change', {{ bubbles: true }}));

            // Also dispatch InputEvent for good measure
            ta.dispatchEvent(new InputEvent('input', {{
                bubbles: true,
                cancelable: false,
                inputType: 'insertText',
                data: "{escaped_msg}"
            }}));

            return JSON.stringify({{ value: ta.value.substring(0, 50), len: ta.value.length }});
        }})()
    "#)).await?;
    tracing::info!("JS input result: {:?}", input_result);

    // Small delay for React to process
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify textarea has content and the send button is enabled
    let send_check = cdp.evaluate(r#"
        (() => {
            const ta = document.querySelector('textarea');
            const taValue = ta ? ta.value : '';

            // Check the submit button state
            const sendDiv = document.querySelector('[aria-label="Send Message"]');
            const sendBtn = sendDiv ? sendDiv.querySelector('button') : null;
            const btnDisabled = sendBtn ? sendBtn.disabled : 'no_btn';
            const btnType = sendBtn ? sendBtn.type : 'no_btn';

            // Also check for Stop button (means message already sent)
            const stopDivs = [...document.querySelectorAll('[aria-label]')].filter(
                el => el.getAttribute('aria-label').includes('Stop')
            );

            return JSON.stringify({
                taValue: taValue.substring(0, 50),
                taLen: taValue.length,
                btnDisabled: btnDisabled,
                btnType: btnType,
                hasStopBtn: stopDivs.length > 0,
            });
        })()
    "#).await;
    tracing::info!("Send button check: {:?}", send_check);

    // ─── Submit Strategy ────────────────────────────────────────
    // The form has a button[type=submit] inside a div[aria-label="Send Message"].
    // If the button is enabled (React saw the input), pressing Enter or
    // clicking it will submit. If still disabled, force-click the button.
    // ────────────────────────────────────────────────────────────────

    // Try pressing Enter first
    cdp.send_command(
        "Input.dispatchKeyEvent",
        serde_json::json!({
            "type": "keyDown",
            "key": "Enter",
            "code": "Enter",
            "windowsVirtualKeyCode": 13,
            "nativeVirtualKeyCode": 13,
        }),
    ).await?;

    cdp.send_command(
        "Input.dispatchKeyEvent",
        serde_json::json!({
            "type": "keyUp",
            "key": "Enter",
            "code": "Enter",
            "windowsVirtualKeyCode": 13,
            "nativeVirtualKeyCode": 13,
        }),
    ).await?;

    // Wait and check if message was sent
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // Check if the page shows a response (conversation started)
    // The URL may or may not change to /c/xxx depending on the page state.
    // Better indicator: check if the textarea placeholder changed from
    // "How can I help you today?" to "Send a Message", or if a Stop
    // button appeared.
    let sent_check = cdp.evaluate(r#"
        (() => {
            const ta = document.querySelector('textarea');
            const placeholder = ta ? ta.placeholder : '';
            const taValue = ta ? ta.value : '';

            // Check for Stop button (appears while AI is thinking)
            const stopDivs = [...document.querySelectorAll('[aria-label]')].filter(
                el => el.getAttribute('aria-label').includes('Stop')
            );

            // Check for Thinking button (appears while AI is thinking)
            const thinkingBtns = [...document.querySelectorAll('button')].filter(
                b => b.innerText.includes('Thinking') || b.innerText.includes('thinking')
            );

            // Check for user-message div (means message was posted)
            const userMsg = document.querySelector('[class*="user-message"]');

            // Check URL
            const url = window.location.href;

            return JSON.stringify({
                placeholder: placeholder,
                taValue: taValue.substring(0, 50),
                hasStopBtn: stopDivs.length > 0,
                hasThinkingBtn: thinkingBtns.length > 0,
                hasUserMessage: userMsg !== null,
                url: url,
            });
        })()
    "#).await;
    tracing::info!("After Enter - sent check: {:?}", sent_check);

    // If message wasn't sent, try the submit button approach
    let sent = if let Ok(val) = &sent_check {
        if let Some(text) = val.as_str() {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(text) {
                parsed["hasStopBtn"].as_bool().unwrap_or(false)
                    || parsed["hasThinkingBtn"].as_bool().unwrap_or(false)
                    || parsed["hasUserMessage"].as_bool().unwrap_or(false)
                    || parsed["url"].as_str().map(|u| u.contains("/c/")).unwrap_or(false)
            } else { false }
        } else { false }
    } else { false };

    if !sent {
        tracing::warn!("Enter key didn't submit, trying send button click...");

        // Try clicking the submit button directly via JS (force even if disabled)
        let click_result = cdp.evaluate(r#"
            (() => {
                // Find the submit button in the Send Message container
                const sendDiv = document.querySelector('[aria-label="Send Message"]');
                const sendBtn = sendDiv ? sendDiv.querySelector('button[type="submit"]') : null;

                if (sendBtn) {
                    // Remove disabled attribute to force enable
                    sendBtn.removeAttribute('disabled');
                    sendBtn.click();
                    return 'clicked_submit';
                }

                // Fallback: try other selectors
                const btn = document.querySelector('button[type="submit"]');
                if (btn) {
                    btn.removeAttribute('disabled');
                    btn.click();
                    return 'clicked_generic_submit';
                }

                // Last resort: submit the form directly
                const form = document.querySelector('form');
                if (form) {
                    // Create and dispatch a submit event
                    const submitEvent = new Event('submit', { bubbles: true, cancelable: true });
                    form.dispatchEvent(submitEvent);
                    return 'form_dispatched';
                }

                return 'no_button_found';
            })()
        "#).await?;
        tracing::info!("Send button click result: {:?}", click_result);
    }

    tracing::info!("Message sent, waiting for response...");

    // Wait for response to start
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Poll for the response with streaming
    let mut reply_text = String::new();
    let mut thinking_text = String::new();
    let mut last_thinking_length: usize = 0;
    let mut last_reply_length: usize = 0;
    let mut last_total_length: usize = 0;
    let mut stable_count = 0;

    for poll_idx in 0..120 {
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Debug logging for first few polls
        if poll_idx < 5 {
            let debug_info = cdp.evaluate(r#"
                (() => {
                    const allClasses = new Set();
                    document.querySelectorAll('*').forEach(el => {
                        el.classList.forEach(c => allClasses.add(c));
                    });
                    const classList = [...allClasses].filter(c =>
                        c.includes('message') || c.includes('chat') || c.includes('think') ||
                        c.includes('response') || c.includes('answer') || c.includes('assistant') ||
                        c.includes('markdown') || c.includes('prose') || c.includes('bubble') ||
                        c.includes('content') || c.includes('reply') || c.includes('agent')
                    ).sort();

                    const lastElements = [];
                    document.querySelectorAll('[class*="message"], [class*="response"], [class*="answer"], [class*="think"], [class*="assistant"]').forEach(el => {
                        if (el.innerText && el.innerText.trim().length > 0 && el.children.length < 3) {
                            lastElements.push({
                                tag: el.tagName,
                                classes: el.className,
                                textLen: el.innerText.length,
                                textPreview: el.innerText.substring(0, 50),
                            });
                        }
                    });

                    // Also debug the thinking chain internal structure
                    const tcDebug = [];
                    document.querySelectorAll('[class*="thinking-chain"]').forEach(tc => {
                        tcDebug.push({
                            classes: tc.className,
                            childCount: tc.children.length,
                            innerTextLen: tc.innerText.length,
                            innerTextPreview: tc.innerText.substring(0, 80),
                            textContentLen: tc.textContent.length,
                            textContentPreview: tc.textContent.substring(0, 80),
                            innerHTML_len: tc.innerHTML.length,
                            childTags: [...tc.children].map(c => c.tagName + '.' + (c.className||'').substring(0,30)).slice(0,5),
                        });
                    });

                    return JSON.stringify({
                        relevantClasses: classList.slice(0, 30),
                        elements: lastElements.slice(-5),
                        thinkingChainDebug: tcDebug,
                        url: window.location.href,
                    });
                })()
            "#).await;
            tracing::info!("DOM debug (poll #{}): {:?}", poll_idx, debug_info);
        }

        // Extract thinking and reply text
        // Current chat.z.ai DOM structure (as of 2026-06):
        //   div.chat-assistant.markdown-prose > div > div#response-content-container
        //     > div.markdown-prose
        //       > div.thinking-chain-container (thinking/chain-of-thought)
        //       > p (reply paragraphs)
        //   div.user-message (user's sent message)
        let result = cdp.evaluate(r#"
            (() => {
                let thinkingText = '';

                // ─── Extract thinking text ─────────────────────────────
                // The thinking chain is inside thinking-chain-container divs.
                // Also check for the "Thinking..." button state (during active thinking).
                // ─── Strategy 1: Extract thinking from thinking-block (visible, contains actual reasoning) ──
                // chat.z.ai renders thinking steps in .thinking-block elements which are VISIBLE.
                // The .thinking-chain-container just shows a collapsed summary like "思考过程".
                // Always use innerText (NOT textContent) so stability detection works correctly.
                const thinkingBlocks = document.querySelectorAll('[class*="thinking-block"]');
                const placeholders = ['Thought Process', 'Thinking...', '正在思考', '跳过', 
                    '正在思考\n跳过', '跳过\n正在思考', '思考过程', '思考'];
                
                if (thinkingBlocks.length > 0) {
                    // thinking-block elements contain the actual visible reasoning text
                    thinkingBlocks.forEach(el => {
                        const text = el.innerText.trim();
                        if (text && !placeholders.includes(text) && text.length > 2) {
                            thinkingText += text + '\n';
                        }
                    });
                }
                
                // ─── Strategy 2: Fallback to thinking-chain-container ──
                if (!thinkingText) {
                    const thinkingContainers = document.querySelectorAll('[class*="thinking-chain"]');
                    thinkingContainers.forEach(el => {
                        const text = el.innerText.trim();
                        // Filter out pure placeholders
                        if (text && !placeholders.includes(text) && text.length > 2) {
                            // Remove "思考过程" header prefix if present
                            const cleaned = text.replace(/^思考过程[\s\n]*/, '');
                            if (cleaned.trim() && !placeholders.includes(cleaned.trim())) {
                                thinkingText += cleaned.trim() + '\n';
                            }
                        }
                    });
                }

                let replyText = '';

                // ─── Strategy 1: Extract from #response-content-container ──
                // This is the most reliable container for the AI response.
                const rcc = document.querySelector('#response-content-container');
                if (rcc) {
                    const innerProse = rcc.querySelector('[class*="markdown-prose"]');
                    if (innerProse) {
                        const clone = innerProse.cloneNode(true);
                        // Remove thinking chain from the clone
                        clone.querySelectorAll('[class*="thinking-chain"], [class*="thinking-block"], [class*="chain-of-thought"]').forEach(el => el.remove());
                        // Remove user message elements
                        clone.querySelectorAll('[class*="user-message"], [class*="edit-user-message"]').forEach(el => el.remove());
                        replyText = clone.innerText.trim();
                    }
                }

                // ─── Strategy 2: Extract from chat-assistant ────────────
                if (!replyText) {
                    const allChatAssistants = document.querySelectorAll('[class*="chat-assistant"]');
                    const chatAssistant = allChatAssistants.length > 0 ? allChatAssistants[allChatAssistants.length - 1] : null;
                    if (chatAssistant) {
                        const clone = chatAssistant.cloneNode(true);
                        clone.querySelectorAll('[class*="thinking-chain"], [class*="thinking-block"], [class*="think"], [class*="reasoning"], [class*="chain-of-thought"]').forEach(el => el.remove());
                        clone.querySelectorAll('[class*="user-message"], [class*="edit-user-message"], [class*="chat-user"]').forEach(el => el.remove());
                        replyText = clone.innerText.trim();
                    }
                }

                // ─── Strategy 3: Fallback - look for paragraph elements ──
                // The reply text is typically in <p> tags after the thinking chain.
                if (!replyText) {
                    const rcc2 = document.querySelector('#response-content-container');
                    if (rcc2) {
                        const paragraphs = rcc2.querySelectorAll('p');
                        const texts = [];
                        paragraphs.forEach(p => {
                            const text = p.innerText.trim();
                            if (text && text.length > 0) texts.push(text);
                        });
                        replyText = texts.join('\n');
                    }
                }

                // ─── Strategy 4: Last resort - look for any message element ──
                if (!replyText) {
                    const allMsgs = document.querySelectorAll('[class*="message"]');
                    for (let i = allMsgs.length - 1; i >= 0; i--) {
                        const el = allMsgs[i];
                        const classes = (el.className || '').toLowerCase();
                        if (classes.includes('user-message')) continue;
                        if (classes.includes('messageInputContainer')) continue;
                        if (classes.includes('think') || classes.includes('reasoning')) continue;
                        const clone = el.cloneNode(true);
                        clone.querySelectorAll('[class*="thinking-chain"], [class*="thinking-block"], [class*="think"], [class*="reasoning"], [class*="user-message"]').forEach(e => e.remove());
                        const text = clone.innerText.trim();
                        if (text && text.length > 2) { replyText = text; break; }
                    }
                }

                let rawAssistantText = '';
                const allChatAssistants = document.querySelectorAll('[class*="chat-assistant"]');
                const chatAssistant = allChatAssistants.length > 0 ? allChatAssistants[allChatAssistants.length - 1] : null;
                if (chatAssistant) {
                    rawAssistantText = chatAssistant.innerText.substring(0, 300);
                }

                return JSON.stringify({ thinking: thinkingText.trim(), reply: replyText, debug_raw: rawAssistantText });
            })()
        "#).await;

        if let Ok(val) = result {
            if let Some(text) = val.as_str() {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(text) {
                    let thinking = parsed["thinking"].as_str().unwrap_or("");
                    let reply = parsed["reply"].as_str().unwrap_or("");

                    let thinking_len = thinking.len();
                    let reply_len = reply.len();
                    let total_len = thinking_len + reply_len;

                    // Track thinking deltas
                    if thinking_len > last_thinking_length {
                        let safe_start = if last_thinking_length <= thinking_len {
                            let mut pos = last_thinking_length;
                            while pos < thinking_len && !thinking.is_char_boundary(pos) {
                                pos += 1;
                            }
                            pos
                        } else {
                            thinking_len
                        };

                        if safe_start < thinking_len {
                            let delta = &thinking[safe_start..];
                            if !delta.is_empty() {
                                eprint!("{}", delta);
                                thinking_text.push_str(delta);
                                if let Some(ref tx) = stream_tx {
                                    let _ = tx.send(StreamChunk {
                                        chunk_type: "thinking".to_string(),
                                        data: delta.to_string(),
                                    }).await;
                                }
                            }
                        }
                        last_thinking_length = thinking_len;
                    } else if thinking_len < last_thinking_length {
                        tracing::debug!("Thinking text shrunk ({} -> {})", last_thinking_length, thinking_len);
                        last_thinking_length = thinking_len;
                    }

                    // Track reply deltas
                    if reply_len > last_reply_length {
                        let safe_start = if last_reply_length <= reply_len {
                            let mut pos = last_reply_length;
                            while pos < reply_len && !reply.is_char_boundary(pos) {
                                pos += 1;
                            }
                            pos
                        } else {
                            reply_len
                        };

                        if safe_start < reply_len {
                            let delta = &reply[safe_start..];
                            if !delta.is_empty() {
                                eprint!("{}", delta);
                                reply_text.push_str(delta);
                                if let Some(ref tx) = stream_tx {
                                    let _ = tx.send(StreamChunk {
                                        chunk_type: "text".to_string(),
                                        data: delta.to_string(),
                                    }).await;
                                }
                            }
                        }
                        last_reply_length = reply_len;
                    } else if reply_len < last_reply_length {
                        tracing::debug!("Reply text shrunk ({} -> {})", last_reply_length, reply_len);
                        last_reply_length = reply_len;
                    }

                    // Check stability - but don't consider response "complete" if only
                    // thinking placeholders are present (e.g. "正在思考", "跳过")
                    let is_only_placeholder = |t: &str| -> bool {
                        let trimmed = t.trim();
                        trimmed.is_empty()
                            || trimmed == "正在思考"
                            || trimmed == "跳过"
                            || trimmed == "正在思考\n跳过"
                            || trimmed == "跳过\n正在思考"
                            || trimmed == "Thought Process"
                            || trimmed == "Thinking..."
                            || trimmed == "思考过程"
                            || trimmed == "思考"
                    };

                    let has_real_content = !is_only_placeholder(thinking) || !is_only_placeholder(reply);
                    if total_len > 0 && total_len == last_total_length {
                        if !has_real_content {
                            // Still in "thinking" phase - content is just placeholders
                            // Don't increment stable_count, keep waiting for real content
                            tracing::debug!("Stable but only placeholders (thinking: {} chars, reply: {} chars), continuing to wait", thinking_len, reply_len);
                        } else {
                            stable_count += 1;
                            if stable_count >= 5 {
                                tracing::info!("Response complete (stable for 5s, poll #{})", poll_idx);
                                break;
                            }
                        }
                    } else if total_len != last_total_length {
                        stable_count = 0;
                    }
                    last_total_length = total_len;
                }
            }
        }
    }

    println!();

    let elapsed = start.elapsed().as_millis() as u64;

    Ok(BrowserChatResult {
        reply: reply_text,
        thinking: thinking_text,
        raw_length: last_total_length,
        elapsed_ms: elapsed,
    })
}

// ─── Public API: Login ────────────────────────────────────────

/// Login to Z.AI via browser, wait for authentication, and capture cookies
pub async fn login_via_browser(headless: bool, _cdp_url: Option<&str>) -> Result<ZaiAuthState> {
    tracing::info!("Starting browser login...");

    let chrome = ChromeProcess::launch(headless)?;
    let _debug_url = chrome.debug_url();

    tokio::time::sleep(Duration::from_secs(2)).await;

    let ws_url = chrome.get_page_ws_url().await?;
    tracing::info!("Chrome CDP WebSocket: {}", ws_url);

    let mut cdp = CdpConnection::connect(&ws_url).await?;

    cdp.send_notification("Page.enable").await?;
    cdp.send_notification("Network.enable").await?;
    cdp.send_notification("Runtime.enable").await?;

    inject_stealth_via_cdp(&mut cdp).await?;

    tracing::info!("Navigating to {}...", ZAI_CHAT_URL);
    cdp.navigate(ZAI_CHAT_URL).await?;

    tokio::time::sleep(Duration::from_secs(3)).await;

    if !headless {
        tracing::info!("════════════════════════════════════════════════════");
        tracing::info!("  Please login to Z.AI (chat.z.ai) in the browser window.");
        tracing::info!("════════════════════════════════════════════════════");
    }

    // Poll for login detection
    let mut authenticated = false;
    let login_start = std::time::Instant::now();
    let login_timeout = if headless { Duration::from_secs(30) } else { Duration::from_secs(600) };

    while login_start.elapsed() < login_timeout {
        tokio::time::sleep(Duration::from_secs(3)).await;

        let result = cdp.evaluate(r#"
            (() => {
                const ta = document.querySelector('textarea');
                const ce = document.querySelector('[contenteditable="true"]');
                const hasInput = ta !== null || ce !== null;
                const cookieStr = document.cookie;
                const hasAuth = cookieStr.includes('token=') || cookieStr.includes('chatglm');
                return hasInput && hasAuth;
            })()
        "#).await;

        if let Ok(val) = result {
            if val.as_bool().unwrap_or(false) {
                tokio::time::sleep(Duration::from_secs(2)).await;
                authenticated = true;
                break;
            }
        }
    }

    if !authenticated {
        bail!("Login timeout - no authentication detected after 10 minutes");
    }

    tracing::info!("Login detected! Capturing cookies...");

    let cdp_cookies = cdp.get_cookies().await?;
    let cookie_string: String = cdp_cookies
        .iter()
        .map(|c| format!("{}={}", c.name, c.value))
        .collect::<Vec<_>>()
        .join("; ");

    let ua_result = cdp
        .evaluate("navigator.userAgent")
        .await
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default();

    let refresh_token = extract_refresh_token(&cookie_string);
    let access_token = extract_access_token(&cookie_string);

    let auth_state = ZaiAuthState {
        cookie: cookie_string,
        user_agent: ua_result,
        refresh_token,
        access_token,
        captured_at: chrono::Utc::now().timestamp_millis(),
    };

    tracing::info!(
        "Authentication captured! Cookie length: {}, Refresh token: {}, Access token: {}",
        auth_state.cookie.len(),
        auth_state.refresh_token.is_some(),
        auth_state.access_token.is_some(),
    );

    Ok(auth_state)
}

// ─── Stealth Injection ──────────────────────────────────────────

/// Inject anti-detection scripts via CDP
async fn inject_stealth_via_cdp(cdp: &mut CdpConnection) -> Result<()> {
    tracing::debug!("Injecting stealth scripts via CDP...");

    cdp.send_command(
        "Page.addScriptToEvaluateOnNewDocument",
        serde_json::json!({
            "source": r#"
                Object.defineProperty(navigator, 'webdriver', { get: () => false });
                window.chrome = { runtime: {}, loadTimes: function(){}, csi: function(){}, app: {} };
                const originalQuery = window.navigator.permissions.query;
                window.navigator.permissions.query = (parameters) =>
                    parameters.name === 'notifications'
                        ? Promise.resolve({ state: Notification.permission })
                        : originalQuery(parameters);
                Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
                Object.defineProperty(navigator, 'languages', { get: () => ['zh-CN', 'zh', 'en'] });
            "#
        }),
    )
    .await?;

    tracing::debug!("Stealth scripts injected successfully");
    Ok(())
}

// ─── Streaming Types ──────────────────────────────────────────

/// A streaming chunk emitted during browser chat polling
#[derive(Debug, Clone)]
pub struct StreamChunk {
    pub chunk_type: String,
    pub data: String,
}

/// Result of a browser chat operation
#[derive(Debug, Clone)]
pub struct BrowserChatResult {
    pub reply: String,
    pub thinking: String,
    pub raw_length: usize,
    pub elapsed_ms: u64,
}

// ─── Legacy API (compatibility wrapper) ──────────────────────────

/// Chat with Z.AI via browser automation (legacy API)
///
/// This function creates a temporary BrowserSession for a single chat.
/// For better performance, use BrowserSession directly to reuse Chrome.
pub async fn chat_via_browser(
    message: &str,
    auth_state: &ZaiAuthState,
    stream_tx: Option<tokio::sync::mpsc::Sender<StreamChunk>>,
) -> Result<BrowserChatResult> {
    let mut session = BrowserSession::new(auth_state);
    session.chat(message, stream_tx).await
}

// ─── Helper Functions ──────────────────────────────────────────

/// Get page WebSocket URL for a specific CDP port (with retry)
pub async fn get_page_ws_url_for_port(port: u16) -> Result<String> {
    let json_url = format!("http://127.0.0.1:{}/json", port);
    let client = reqwest::Client::new();

    for attempt in 0..20 {
        match client.get(&json_url).send().await {
            Ok(res) if res.status().is_success() => {
                let targets: Vec<ChromeTarget> = res.json().await?;

                for target in &targets {
                    if target.r#type.as_deref() == Some("page") {
                        if let Some(ws_url) = &target.ws_url {
                            return Ok(ws_url.replace("localhost", "127.0.0.1"));
                        }
                    }
                }

                for target in &targets {
                    if let Some(ws_url) = &target.ws_url {
                        return Ok(ws_url.replace("localhost", "127.0.0.1"));
                    }
                }

                bail!("No page targets found");
            }
            _ => {
                if attempt < 19 {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    }

    bail!("Chrome did not start on port {} after 10 seconds", port)
}

/// Find Chrome executable path
fn which_chrome() -> Result<std::path::PathBuf> {
    let candidates = if cfg!(target_os = "windows") {
        vec![
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            r"C:\Users\Administrator\AppData\Local\Google\Chrome\Application\chrome.exe",
        ]
    } else {
        vec![
            "/usr/bin/google-chrome",
            "/usr/bin/chromium-browser",
            "/usr/bin/chromium",
            "/snap/bin/chromium",
        ]
    };

    for path in &candidates {
        let p = std::path::PathBuf::from(path);
        if p.exists() {
            return Ok(p);
        }
    }

    if let Ok(entries) = std::fs::read_dir("/home/z/.agent-browser/browsers/") {
        for entry in entries.flatten() {
            let dir = entry.path();
            if dir.file_name().map(|n| n.to_string_lossy().starts_with("chrome-")).unwrap_or(false) {
                let chrome_bin = dir.join("chrome");
                if chrome_bin.exists() {
                    tracing::info!("Found agent-browser Chrome: {}", chrome_bin.display());
                    return Ok(chrome_bin);
                }
            }
        }
    }

    for cmd in &["chrome", "chromium-browser", "chromium", "google-chrome"] {
        #[cfg(windows)]
        {
            if let Ok(output) = Command::new("where").arg(cmd).output() {
                if output.status.success() {
                    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if !path.is_empty() {
                        return Ok(std::path::PathBuf::from(path));
                    }
                }
            }
        }
        #[cfg(not(windows))]
        {
            if let Ok(output) = Command::new("which").arg(cmd).output() {
                if output.status.success() {
                    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if !path.is_empty() {
                        return Ok(std::path::PathBuf::from(path));
                    }
                }
            }
        }
    }

    bail!("Chrome/Chromium not found. Please install Chrome or set CDP_URL.")
}

/// Find an available TCP port for CDP
#[allow(dead_code)]
fn find_available_port() -> u16 {
    for port in [9222, 9223, 9224, 9225, 9226, 9227, 9228, 9229] {
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    if let Ok(listener) = std::net::TcpListener::bind("127.0.0.1:0") {
        if let Ok(addr) = listener.local_addr() {
            return addr.port();
        }
    }
    9222
}

// ─── Captcha Extraction (Agent mode helper) ────────────────────

/// Chat with chat.z.ai in Agent mode by hijacking the browser's own fetch:
///   1. Launch stealth Chrome + inject cookies + navigate to chat.z.ai
///   2. Install a fetch hook that:
///      - replaces `messages[0].content` with zair's message
///      - intercepts the response stream and accumulates SSE chunks into
///        `window.__zair_sse_chunks` (an array of {ts, text})
///      - signals completion via `window.__zair_sse_done`
///   3. Type "hi" and click send to trigger the browser's chat (which gets
///      intercepted, so the actual message sent is zair's, and the SSE
///      response is captured)
///   4. Poll `__zair_sse_chunks` for new chunks, forward to callback, until
///      `__zair_sse_done` is true
///
/// This bypasses the captcha_verify_param problem entirely: the browser
/// generates and consumes its own captcha token, zair just rewrites the
/// message body and reads the response stream.
pub async fn chat_via_browser_agent(
    auth_state: &ZaiAuthState,
    message: &str,
    model: &str,
    callback: Option<&StreamCallback>,
) -> Result<BrowserChatResult> {
    let start = std::time::Instant::now();
    tracing::info!("Starting browser Agent chat: model={}, message_len={}", model, message.len());

    // Pre-escape message and model for use in JS template strings
    let escaped_msg = message
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "");
    let escaped_model = model
        .replace('\\', "\\\\")
        .replace('"', "\\\"");

    let mut session = BrowserSession::new(auth_state);
    session.ensure_running().await?;

    let ws_url = get_page_ws_url_for_port(9223).await?;
    let mut cdp = CdpConnection::connect(&ws_url).await?;
    cdp.send_notification("Page.enable").await?;
    cdp.send_notification("Network.enable").await?;
    cdp.send_notification("Runtime.enable").await?;

    // Navigate + inject cookies + reload (full session init)
    tracing::info!("Navigating to chat.z.ai for Agent chat...");
    cdp.navigate("https://chat.z.ai/").await?;
    tokio::time::sleep(Duration::from_secs(3)).await;

    // ── Set localStorage to default to the target model ──
    // chat.z.ai stores the selected model in localStorage.selectedModels.
    // By setting it to ["glm-5.2"] BEFORE reload, the page loads with
    // GLM-5.2 as the default model, which means:
    //   1. The model selector button shows "GLM-5.2"
    //   2. New conversations are created in Agent mode (GLM-5.2 = Agent)
    //   3. The browser's chat request naturally includes flags=["general_agent"]
    //
    // This is the ONLY reliable way to switch to Agent mode — clicking the
    // dropdown via JS .click() often doesn't trigger Svelte's event handlers.
    let set_model_js = format!(r#"
        (function(){{
            localStorage.setItem('selectedModels', JSON.stringify(['{escaped_model}']));
            localStorage.setItem('last_selected_agent_model', JSON.stringify(['{escaped_model}']));
            localStorage.setItem('last_mode', 'agent');
            return 'set_selectedModels=' + localStorage.getItem('selectedModels');
        }})()
    "#);
    let set_result = cdp.evaluate(&set_model_js).await?;
    tracing::info!("Set localStorage selectedModels: {:?}", set_result);

    inject_stealth_via_cdp(&mut cdp).await?;
    inject_cookies_cdp(&mut cdp, &auth_state.cookie).await?;

    // Reload to apply the localStorage settings
    cdp.evaluate("location.reload(true)").await?;
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Verify model selector now shows the target model
    let verify_model_js = format!(r#"
        (function(){{
            const sel = document.querySelector('button.modelSelectorButton, button[aria-label="选择一个模型"]');
            if (!sel) return 'no_selector';
            const text = (sel.innerText || '').trim();
            return JSON.stringify({{buttonText: text, contains_target: text.includes('{escaped_model}'), selectedModels: localStorage.getItem('selectedModels')}});
        }})()
    "#);
    let model_check = cdp.evaluate(&verify_model_js).await?;
    tracing::info!("Model selector after localStorage set: {:?}", model_check);

    // Verify we're logged in
    let check = cdp.evaluate(r#"
        (() => {
            const ta = document.querySelector('textarea');
            return JSON.stringify({
                url: window.location.href,
                hasTextarea: ta !== null,
                hasAuth: document.cookie.includes('token=') || document.cookie.includes('chatglm'),
            });
        })()
    "#).await?;
    tracing::info!("Page state: {:?}", check);

    // ── Install fetch hook that hijacks the chat request ──
    // The hook:
    //   - captures the request body (with captcha_verify_param)
    //   - rewrites messages[0].content to zair's message
    //   - rewrites model to zair's model
    //   - sets stream=true
    //   - calls original fetch with modified body
    //   - intercepts response stream, accumulates SSE text chunks
    // (escaped_msg and escaped_model are already defined at the top of this function)

    let install_js = format!(r#"
        (function(){{
            // Reset capture state
            window.__zair_agent_chat = {{
                request_body: null,
                chunks: [],
                done: false,
                error: null,
                started_at: Date.now(),
                last_chunk_at: 0,
            }};
            if (window.__zair_agent_hook_installed) {{
                // Hook already installed — just reset state (done above)
                return 'already_installed';
            }}
            window.__zair_agent_hook_installed = true;
            const origFetch = window.fetch;
            window.fetch = async function(input, init) {{
                const url = (typeof input === 'string') ? input : (input && input.url) || '';
                const method = (init && init.method) || (input && input.method) || 'GET';
                if (method.toUpperCase() === 'POST' && url.includes('/chat/completions')) {{
                    try {{
                        // Handle both fetch(url, init) and fetch(Request, init) patterns.
                        // If input is a Request object, we must extract its body and
                        // rebuild a new init — modifying init.body alone won't work
                        // because the Request's body takes precedence.
                        let bodyStr = '';
                        if (init && init.body) {{
                            const body = init.body;
                            if (typeof body === 'string') bodyStr = body;
                            else if (body instanceof Blob) bodyStr = await body.text();
                            else if (body instanceof ArrayBuffer) bodyStr = new TextDecoder().decode(body);
                        }} else if (input instanceof Request) {{
                            // Clone the request and read its body
                            const cloned = input.clone();
                            bodyStr = await cloned.text();
                        }}
                        if (bodyStr) {{
                            const parsed = JSON.parse(bodyStr);
                            // Override the message content and model
                            parsed.messages = [{{role: 'user', content: "{escaped_msg}"}}];
                            parsed.signature_prompt = "{escaped_msg}";
                            parsed.model = "{escaped_model}";
                            parsed.stream = true;
                            // Force Agent-mode features
                            parsed.features = parsed.features || {{}};
                            parsed.features.flags = ["general_agent"];
                            parsed.features.enable_thinking = true;
                            parsed.features.reasoning_effort = "max";
                            parsed.features.image_generation = false;
                            parsed.features.web_search = false;
                            parsed.features.auto_web_search = false;
                            parsed.features.preview_mode = true;
                            parsed.features.vlm_tools_enable = false;
                            parsed.features.vlm_web_search_enable = false;
                            parsed.features.vlm_website_mode = false;
                            // ── Strip fields that trigger server-side MCP init ──
                            // The browser includes `tools`, `workspace_id`,
                            // `background_tasks`, etc. — when any of these is
                            // present, chat.z.ai tries to spin up MCP servers
                            // (vibe-coding etc.) which 500s out. Removing them
                            // keeps the request in pure chat+thinking mode.
                            parsed.tools = [];
                            parsed.tool_choice = "none";
                            delete parsed.workspace_id;
                            delete parsed.mcp_servers;
                            delete parsed.background_tasks;
                            delete parsed.plugins;
                            delete parsed.agent_config;
                            // Re-encode
                            const newBody = JSON.stringify(parsed);
                            // Save the MODIFIED body (after our changes) for diagnostics
                            window.__zair_agent_chat.request_body = JSON.parse(newBody);
                            // If input is a Request, rebuild a new Request with the modified body
                            if (input instanceof Request) {{
                                const newInit = {{
                                    method: input.method,
                                    headers: input.headers,
                                    body: newBody,
                                    credentials: input.credentials,
                                    mode: input.mode,
                                }};
                                return origFetch.call(this, input.url, newInit);
                            }} else {{
                                init = init || {{}};
                                init.body = newBody;
                            }}
                        }}
                    }} catch(e) {{
                        console.error('[zair] fetch hook error:', e);
                    }}
                }}
                // Call original fetch
                const response = await origFetch.apply(this, arguments);
                // If this was the chat completions request, intercept the response stream
                if (method.toUpperCase() === 'POST' && url.includes('/chat/completions') && response.body) {{
                    const reader = response.body.getReader();
                    const decoder = new TextDecoder();
                    const state = window.__zair_agent_chat;
                    (async function() {{
                        try {{
                            while (true) {{
                                const {{ done, value }} = await reader.read();
                                if (done) break;
                                const text = decoder.decode(value, {{ stream: true }});
                                state.chunks.push({{ ts: Date.now(), text }});
                                state.last_chunk_at = Date.now();
                            }}
                            state.done = true;
                        }} catch(e) {{
                            state.done = true;
                            state.error = e.message;
                        }}
                    }})();
                    // Return a tee'd stream so the page's own JS (which expects a
                    // response) still works. We use response.clone() which
                    // internally tees the body.
                    return response.clone();
                }}
                return response;
            }};
            return 'installed';
        }})()
    "#);
    let install_result = cdp.evaluate(&install_js).await?;
    tracing::info!("Agent hook install: {:?}", install_result);

    // ── Select the model in the UI ──
    // This is CRITICAL: if the UI doesn't switch to GLM-5.2, the new
    // conversation is created in chat mode (GLM-4.7 default), and even
    // though our fetch hook forces flags=[general_agent], the server
    // stores the message under a chat-mode conversation.
    //
    // We must: open dropdown → wait for items → click GLM-5.2 → verify.

    // Step 1: Wait for the model selector button to be present
    let wait_selector_js = r#"
        (function(){
            const sel = document.querySelector('button.modelSelectorButton, button[aria-label="选择一个模型"]');
            return sel ? 'ready:' + (sel.innerText || '').trim().substring(0, 30) : 'not_found';
        })()
    "#;
    let mut selector_ready = false;
    for _ in 0..20 {
        let r = cdp.evaluate(wait_selector_js).await?;
        if let Some(s) = r.as_str() {
            if s.starts_with("ready:") {
                tracing::info!("Model selector ready: {}", s);
                selector_ready = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    if !selector_ready {
        tracing::warn!("Model selector button not found after 10s");
    }

    // Step 2: Open the dropdown
    cdp.evaluate(r#"
        (function(){
            const sel = document.querySelector('button.modelSelectorButton, button[aria-label="选择一个模型"]');
            if (sel) { sel.click(); return 'opened'; }
            return 'no_selector';
        })()
    "#).await?;

    // Step 3: Wait for the dropdown to render a VISIBLE GLM-5.2 item.
    // The dropdown popup appears immediately, but its items start hidden
    // (CSS transition) and become visible after ~500ms. We poll for a
    // VISIBLE element whose text contains exactly "GLM-5.2" on one line.
    let wait_item_js = format!(r#"
        (function(){{
            const target = "{escaped_model}";
            const all = document.querySelectorAll('*');
            for (var el of all) {{
                // Must be visible (offsetParent !== null)
                if (!el.offsetParent && el.tagName !== 'BODY') continue;
                var txt = (el.innerText || '').trim();
                if (!txt || txt.length > 200) continue;
                var lines = txt.split('\n').map(s => s.trim()).filter(s => s);
                for (var line of lines) {{
                    if (line === target) {{
                        return JSON.stringify({{found: true, tag: el.tagName, class: (el.className||'').substring(0,80), text: line}});
                    }}
                }}
            }}
            return JSON.stringify({{found: false}});
        }})()
    "#);
    let mut item_found = false;
    for _ in 0..20 {  // 20 x 300ms = 6s max
        let r = cdp.evaluate(&wait_item_js).await?;
        if let Some(s) = r.as_str() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
                if v.get("found").and_then(|b| b.as_bool()).unwrap_or(false) {
                    item_found = true;
                    tracing::info!(
                        "GLM-5.2 dropdown item visible: {:?}",
                        v.get("text")
                    );
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    if !item_found {
        tracing::warn!("GLM-5.2 item not VISIBLE in dropdown after 6s");
    }

    // Step 4: Click the GLM-5.2 item
    let model_pick_js = format!(r#"
        (function(){{
            const target = "{escaped_model}";
            const candidates = document.querySelectorAll('[role="option"], [role="menuitem"], [role="button"], li, div, button');
            // First pass: exact line match
            for (var c of candidates) {{
                var txt = (c.innerText || '').trim();
                var lines = txt.split('\n').map(s => s.trim()).filter(s => s);
                for (var line of lines) {{
                    if (line === target) {{
                        c.click();
                        return 'clicked_exact: ' + line;
                    }}
                }}
            }}
            // Second pass: line starts with target (but not target + ".")
            for (var c of candidates) {{
                var txt = (c.innerText || '').trim();
                var lines = txt.split('\n').map(s => s.trim()).filter(s => s);
                for (var line of lines) {{
                    if (line.startsWith(target) && !line.startsWith(target + '.')) {{
                        c.click();
                        return 'clicked_prefix: ' + line;
                    }}
                }}
            }}
            return 'model_not_found: ' + target;
        }})()
    "#);
    let pick_result = cdp.evaluate(&model_pick_js).await?;
    tracing::info!("Model pick: {:?}", pick_result);
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Step 5: Verify the model selector button now shows the target model.
    // This confirms the UI actually switched — if it didn't, the new
    // conversation will be created in chat mode (GLM-4.7) regardless of
    // what our fetch hook forces in the request body.
    let verify_js = format!(r#"
        (function(){{
            const sel = document.querySelector('button.modelSelectorButton, button[aria-label="选择一个模型"]');
            if (!sel) return 'no_selector';
            const text = (sel.innerText || '').trim();
            return JSON.stringify({{buttonText: text, contains_target: text.includes("{escaped_model}")}});
        }})()
    "#);
    let verify_result = cdp.evaluate(&verify_js).await?;
    tracing::info!("Model selector verify: {:?}", verify_result);

    // Check if verification shows the target model is selected
    let mut model_confirmed = false;
    if let Some(s) = verify_result.as_str() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
            if v.get("contains_target").and_then(|b| b.as_bool()).unwrap_or(false) {
                model_confirmed = true;
                tracing::info!("✓ Model UI confirmed: {} is selected", escaped_model);
            }
        }
    }
    if !model_confirmed {
        tracing::warn!(
            "✗ Model UI did NOT switch to {} — the conversation will be created in chat mode. \
            Attempting retry with keyboard navigation...",
            escaped_model
        );
        // Retry: open dropdown again and try clicking with mouse events
        cdp.evaluate(r#"
            (function(){
                const sel = document.querySelector('button.modelSelectorButton, button[aria-label="选择一个模型"]');
                if (sel) { sel.click(); return 'reopened'; }
                return 'no_selector';
            })()
        "#).await?;
        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Try a broader match — any element whose first line is exactly the target
        let retry_pick_js = format!(r#"
            (function(){{
                const target = "{escaped_model}";
                // Find ALL elements and check their direct text content (not children)
                const all = document.querySelectorAll('*');
                for (var el of all) {{
                    // Check if this element's DIRECT text (ignoring children) matches
                    var directText = '';
                    for (var child of el.childNodes) {{
                        if (child.nodeType === 3) directText += child.textContent;
                    }}
                    directText = directText.trim();
                    if (directText === target) {{
                        // Found the element — click it and its parent
                        el.click();
                        var parent = el.closest('[role="option"], [role="button"], li, div, button') || el.parentElement;
                        if (parent && parent !== el) parent.click();
                        return 'retry_clicked: ' + directText;
                    }}
                }}
                return 'retry_not_found';
            }})()
        "#);
        let retry_result = cdp.evaluate(&retry_pick_js).await?;
        tracing::info!("Model pick retry: {:?}", retry_result);
        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Verify again
        let verify2 = cdp.evaluate(&verify_js).await?;
        tracing::info!("Model selector verify (2nd): {:?}", verify2);
        if let Some(s) = verify2.as_str() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
                if v.get("contains_target").and_then(|b| b.as_bool()).unwrap_or(false) {
                    model_confirmed = true;
                    tracing::info!("✓ Model UI confirmed on retry: {} is selected", escaped_model);
                }
            }
        }
    }

    // ── Type a placeholder message and click send ──
    // The fetch hook will rewrite the content to zair's message, so the
    // placeholder value doesn't matter — it just needs to enable the send button.
    cdp.evaluate(r#"
        (function(){
            const ta = document.querySelector('textarea');
            if (!ta) return 'no_textarea';
            ta.focus();
            const setter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value').set;
            setter.call(ta, 'placeholder');
            ta.dispatchEvent(new Event('input', { bubbles: true }));
            ta.dispatchEvent(new Event('change', { bubbles: true }));
            return 'typed';
        })()
    "#).await?;
    tokio::time::sleep(Duration::from_millis(800)).await;

    // Click send button
    let click_result = cdp.evaluate(r#"
        (function(){
            const sendDivs = [...document.querySelectorAll('[aria-label]')].filter(el => {
                const al = el.getAttribute('aria-label') || '';
                return al.includes('发送') || al.includes('Send');
            });
            if (sendDivs.length === 0) return 'no_send_div';
            const sendDiv = sendDivs[0];
            const btn = sendDiv.querySelector('button') || sendDiv;
            if (btn.disabled) return 'btn_disabled';
            btn.click();
            return 'clicked';
        })()
    "#).await?;
    tracing::info!("Send click: {:?}", click_result);

    // ── Poll for SSE chunks, forward to callback ──
    let mut accumulated_content = String::new();
    let mut thinking_content = String::new();
    let mut current_mode = "text".to_string();
    let mut tag_buffer = String::new();
    let mut chunk_idx = 0usize;
    let mut captured_conversation_id = String::new();
    let mut request_body_seen = false;

    // Wait up to 120s for the SSE stream to complete
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    let poll_js = r#"
        (function(){
            const s = window.__zair_agent_chat || {};
            return JSON.stringify({
                chunks: s.chunks || [],
                done: !!s.done,
                error: s.error || null,
                request_body: s.request_body || null,
                last_chunk_at: s.last_chunk_at || 0,
            });
        })()
    "#;

    while std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let r = cdp.evaluate(poll_js).await?;
        let s = match r.as_str() {
            Some(s) => s,
            None => continue,
        };
        let v: serde_json::Value = match serde_json::from_str(s) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Log the captured request body once (for diagnostics)
        if !request_body_seen {
            if let Some(rb) = v.get("request_body") {
                if !rb.is_null() {
                    request_body_seen = true;
                    let model_used = rb.get("model").and_then(|m| m.as_str()).unwrap_or("?");
                    let flags = rb.get("features")
                        .and_then(|f| f.get("flags"))
                        .and_then(|f| f.as_array())
                        .map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(","))
                        .unwrap_or_default();
                    let captcha_len = rb.get("captcha_verify_param")
                        .and_then(|c| c.as_str())
                        .map(|s| s.len())
                        .unwrap_or(0);
                    let msg_content = rb.get("messages")
                        .and_then(|m| m.as_array())
                        .and_then(|a| a.first())
                        .and_then(|m| m.get("content"))
                        .and_then(|c| c.as_str())
                        .unwrap_or("?");
                    tracing::info!(
                        "Browser sent chat request: model={}, flags=[{}], captcha_len={}, messages[0].content={:?}",
                        model_used, flags, captcha_len, msg_content
                    );
                    // Dump full request body and top-level keys for diagnosing
                    // server-side errors (e.g. WORKSPACE_TOOL_INIT_ERROR from
                    // an unwanted `tools` / `workspace_id` field).
                    let top_keys: Vec<String> = rb.as_object()
                        .map(|o| o.keys().cloned().collect())
                        .unwrap_or_default();
                    tracing::info!(
                        "Request body top-level keys: {:?}",
                        top_keys
                    );
                    tracing::info!(
                        "Full request body: {}",
                        serde_json::to_string(&rb).unwrap_or_default()
                    );
                }
            }
        }

        // Process any new chunks
        if let Some(chunks) = v.get("chunks").and_then(|c| c.as_array()) {
            while chunk_idx < chunks.len() {
                let chunk_text = chunks[chunk_idx]
                    .get("text")
                    .and_then(|t| t.as_str())
                    .unwrap_or("");
                chunk_idx += 1;
                if chunk_text.is_empty() { continue; }

                // Parse each SSE line
                for line in chunk_text.lines() {
                    let line = line.trim();
                    if line.is_empty() || !line.starts_with("data:") { continue; }
                    let data_str = line[5..].trim();
                    if data_str == "[DONE]" || data_str.is_empty() { continue; }
                    let data: serde_json::Value = match serde_json::from_str(data_str) {
                        Ok(d) => d,
                        Err(_) => continue,
                    };

                    // Check for embedded business errors
                    if let Some(err_msg) = crate::client::detect_embedded_error_pub(&data) {
                        bail!("{}", err_msg);
                    }

                    // Capture conversation_id
                    for field in &["conversation_id", "chat_id", "id"] {
                        if let Some(cid) = data.get(*field).and_then(|v| v.as_str()) {
                            if !cid.is_empty() { captured_conversation_id = cid.to_string(); }
                        }
                    }

                    // Extract reasoning_content (thinking)
                    if let Some(rc) = data.get("choices")
                        .and_then(|c| c.as_array())
                        .and_then(|a| a.first())
                        .and_then(|c| c.get("delta"))
                        .and_then(|d| d.get("reasoning_content"))
                        .and_then(|r| r.as_str())
                    {
                        if !rc.is_empty() {
                            thinking_content.push_str(rc);
                            if let Some(cb) = callback {
                                cb(rc, true);
                            }
                        }
                    }

                    // Extract content delta
                    if let Some(content) = data.get("choices")
                        .and_then(|c| c.as_array())
                        .and_then(|a| a.first())
                        .and_then(|c| c.get("delta"))
                        .and_then(|d| d.get("content"))
                        .and_then(|r| r.as_str())
                    {
                        if !content.is_empty() {
                            crate::client::emit_delta_pub(
                                content,
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

        // Check if done
        let done = v.get("done").and_then(|d| d.as_bool()).unwrap_or(false);
        let err = v.get("error").and_then(|e| e.as_str());
        if let Some(e) = err {
            bail!("Browser SSE stream error: {}", e);
        }
        if done {
            // Flush any remaining tag_buffer
            if !tag_buffer.is_empty() {
                if current_mode == "thinking" {
                    thinking_content.push_str(&tag_buffer);
                    if let Some(cb) = callback { cb(&tag_buffer, true); }
                } else {
                    accumulated_content.push_str(&tag_buffer);
                    if let Some(cb) = callback { cb(&tag_buffer, false); }
                }
            }
            tracing::info!(
                "Browser Agent chat done: reply_chars={}, thinking_chars={}, elapsed={}ms",
                accumulated_content.chars().count(),
                thinking_content.chars().count(),
                start.elapsed().as_millis()
            );
            break;
        }
    }

    // Flush remaining tag buffer if we timed out
    if !tag_buffer.is_empty() {
        if current_mode == "thinking" {
            thinking_content.push_str(&tag_buffer);
        } else {
            accumulated_content.push_str(&tag_buffer);
        }
    }

    let elapsed_ms = start.elapsed().as_millis() as u64;
    session.shutdown();

    Ok(BrowserChatResult {
        reply: accumulated_content,
        thinking: thinking_content,
        raw_length: 0,
        elapsed_ms,
    })
}


/// Launch a stealth Chrome session, trigger one real chat on chat.z.ai,
/// intercept the fetch() to /api/v2/chat/completions, and extract the
/// `captcha_verify_param` field from the request body.
///
/// This is required because chat.z.ai uses Aliyun captcha which generates
/// one-time tokens — we cannot generate them offline, we must trigger a real
/// chat and grab the token the browser just produced.
///
/// Returns the captcha_verify_param string (base64-encoded JSON).
pub async fn extract_captcha_verify_param(auth_state: &ZaiAuthState) -> Result<String> {
    tracing::info!("Extracting captcha_verify_param via browser...");

    // Use a fresh BrowserSession — it will launch Chrome if not already running.
    let mut session = BrowserSession::new(auth_state);
    session.ensure_running().await?;

    // Connect to CDP
    let ws_url = get_page_ws_url_for_port(9223).await
        .context("Failed to get page WS URL for captcha extraction")?;
    let mut cdp = CdpConnection::connect(&ws_url).await
        .context("Failed to connect to Chrome CDP for captcha extraction")?;
    cdp.send_notification("Page.enable").await?;
    cdp.send_notification("Network.enable").await?;
    cdp.send_notification("Runtime.enable").await?;

    // Force navigate to chat.z.ai root (fresh chat page) and inject cookies
    tracing::info!("Navigating to chat.z.ai for captcha extraction...");
    cdp.navigate("https://chat.z.ai/").await?;
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Inject stealth scripts + cookies
    inject_stealth_via_cdp(&mut cdp).await?;
    inject_cookies_cdp(&mut cdp, &auth_state.cookie).await?;

    // Reload to apply cookies
    cdp.evaluate("location.reload(true)").await?;
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Verify we're on chat.z.ai and have textarea (login ok)
    let check = cdp.evaluate(r#"
        (() => {
            const ta = document.querySelector('textarea');
            return JSON.stringify({
                url: window.location.href,
                hasTextarea: ta !== null,
                hasAuth: document.cookie.includes('token=') || document.cookie.includes('chatglm'),
            });
        })()
    "#).await?;
    tracing::info!("Page state after navigation: {:?}", check);

    // Install fetch interceptor that captures the captcha_verify_param.
    // We use observation-only mode (don't block the browser's request) because:
    // 1. Aliyun captcha tokens may be tied to the browser's TLS/HTTP2 fingerprint,
    //    so zair (using reqwest) cannot replay them anyway.
    // 2. The captured token is used for DIAGNOSTIC purposes — to confirm the
    //    Agent payload structure matches what the browser sends.
    // The actual Agent-mode chat should go through the browser path
    // (chat_via_browser), not through zair's reqwest client.
    let install_js = r#"
        (function(){
            if (window.__zair_captcha_capture) return 'already';
            window.__zair_captcha_capture = { captcha: null, captured_at: 0 };
            const orig = window.fetch;
            window.fetch = async function(input, init) {
                const url = (typeof input === 'string') ? input : (input && input.url) || '';
                const method = (init && init.method) || 'GET';
                if (method.toUpperCase() === 'POST' && url.includes('/chat/completions')) {
                    try {
                        const body = init && init.body;
                        let bodyStr = '';
                        if (typeof body === 'string') bodyStr = body;
                        else if (body instanceof Blob) bodyStr = await body.text();
                        else if (body instanceof ArrayBuffer) bodyStr = new TextDecoder().decode(body);
                        if (bodyStr) {
                            const parsed = JSON.parse(bodyStr);
                            if (parsed.captcha_verify_param) {
                                window.__zair_captcha_capture.captcha = parsed.captcha_verify_param;
                                window.__zair_captcha_capture.captured_at = Date.now();
                            }
                        }
                    } catch(e) {}
                }
                return orig.apply(this, arguments);
            };
            return 'installed';
        })()
    "#;
    cdp.evaluate(install_js).await?;
    tracing::info!("Fetch interceptor installed for captcha capture");

    // Type a short message and click send (triggers captcha generation)
    let trigger_js = r#"
        (function(){
            const ta = document.querySelector('textarea');
            if (!ta) return 'no_textarea';
            ta.focus();
            const setter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value').set;
            setter.call(ta, 'hi');
            ta.dispatchEvent(new Event('input', { bubbles: true }));
            ta.dispatchEvent(new Event('change', { bubbles: true }));
            return 'typed';
        })()
    "#;
    let type_result = cdp.evaluate(trigger_js).await?;
    tracing::info!("Type result: {:?}", type_result);
    tokio::time::sleep(Duration::from_millis(800)).await;

    // Click send button (inside div[aria-label="发送消息"])
    let click_js = r#"
        (function(){
            const sendDivs = [...document.querySelectorAll('[aria-label]')].filter(el => {
                const al = el.getAttribute('aria-label') || '';
                return al.includes('发送') || al.includes('Send');
            });
            if (sendDivs.length === 0) return 'no_send_div';
            const sendDiv = sendDivs[0];
            const btn = sendDiv.querySelector('button') || sendDiv;
            if (btn.disabled) return 'btn_disabled';
            btn.click();
            return 'clicked';
        })()
    "#;
    let click_result = cdp.evaluate(click_js).await?;
    tracing::info!("Send click result: {:?}", click_result);

    // Poll for the captured captcha (max 20s)
    let poll_js = r#"
        (function(){
            return JSON.stringify(window.__zair_captcha_capture || {captcha: null});
        })()
    "#;
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let r = cdp.evaluate(poll_js).await?;
        if let Some(s) = r.as_str() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
                if let Some(captcha) = v["captcha"].as_str() {
                    if !captcha.is_empty() {
                        tracing::info!(
                            "Captured captcha_verify_param ({} chars) after waiting {}ms",
                            captcha.len(),
                            std::time::Instant::now().elapsed().as_millis()
                        );
                        tracing::debug!("captcha_verify_param value: {}", captcha);
                        session.shutdown();
                        return Ok(captcha.to_string());
                    }
                }
            }
        }
    }

    session.shutdown();
    bail!("Timeout waiting for captcha_verify_param in browser fetch")
}
