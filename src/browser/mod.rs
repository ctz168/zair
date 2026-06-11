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
struct CdpConnection {
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
    async fn connect(ws_url: &str) -> Result<Self> {
        tracing::info!("Connecting to Chrome CDP: {}", ws_url);

        let (ws_stream, _) = tokio_tungstenite::connect_async(ws_url)
            .await
            .context("Failed to connect to Chrome CDP WebSocket")?;

        let (ws, ws_rx) = ws_stream.split();

        Ok(Self { ws, ws_rx })
    }

    /// Send a CDP command and wait for the matching response
    async fn send_command(
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
    async fn send_notification(&mut self, method: &str) -> Result<()> {
        let cmd = cdp_command_no_params(method);
        self.ws
            .send(tungstenite::Message::Text(cmd))
            .await
            .context("Failed to send CDP notification")?;
        Ok(())
    }

    /// Evaluate JavaScript and return the result value
    async fn evaluate(&mut self, expression: &str) -> Result<serde_json::Value> {
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
    async fn navigate(&mut self, url: &str) -> Result<()> {
        let _ = self
            .send_command(
                "Page.navigate",
                serde_json::json!({ "url": url }),
            )
            .await?;
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
    initialized: bool,
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
                    self.initialized = false; // Re-verify session state
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
                cdp.navigate("https://chat.z.ai/").await?;
                tokio::time::sleep(Duration::from_secs(2)).await;

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

                    return JSON.stringify({
                        relevantClasses: classList.slice(0, 30),
                        elements: lastElements.slice(-5),
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
                const thinkingContainers = document.querySelectorAll('[class*="thinking-chain"]');
                thinkingContainers.forEach(el => {
                    // Get the full text content of the thinking chain
                    const text = el.innerText.trim();
                    if (text && text !== 'Thought Process' && text !== 'Thinking...' && text !== '正在思考' && text !== '跳过' && text !== '正在思考\n跳过' && text !== '跳过\n正在思考') {
                        thinkingText += text + '\n';
                    }
                });

                // Also check for the older thinking-block class (for backward compat)
                document.querySelectorAll('[class*="thinking-block"]').forEach(el => {
                    const text = el.innerText.trim();
                    if (text && text !== 'Thought Process' && text !== 'Thinking...' && text !== '正在思考' && text !== '跳过' && text !== '正在思考\n跳过' && text !== '跳过\n正在思考') {
                        thinkingText += text + '\n';
                    }
                });

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
async fn get_page_ws_url_for_port(port: u16) -> Result<String> {
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
