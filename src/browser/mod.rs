//! Browser Automation via Raw CDP
//!
//! Launches Chrome as a subprocess with --remote-debugging-port, then
//! connects directly via WebSocket using the Chrome DevTools Protocol.
//! This avoids chromiumoxide's deserialization errors with modern Chrome.

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

// ─── Chrome Process Manager ────────────────────────────────────

/// Manages a Chrome subprocess with remote debugging enabled
struct ChromeProcess {
    child: Option<Child>,
    debug_port: u16,
}

/// Default CDP port for ZAI Chrome instances
const ZAI_CDP_PORT: u16 = 9222;
const ZAI_CDP_PORT_HEADLESS: u16 = 9223;

/// Default Chrome data directory name
fn chrome_data_dir() -> std::path::PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        .join("zair-chrome")
}

impl ChromeProcess {
    /// Launch Chrome with remote debugging port
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

    /// Launch Chrome with headless mode and disable GPU (for server environments)
    fn launch_headless() -> Result<Self> {
        let chrome_path = which_chrome()?;
        let port = ZAI_CDP_PORT_HEADLESS;

        tracing::info!("Launching headless Chrome on port {}", port);

        // Use the SAME data directory as login so we inherit the auth state.
        // Kill any existing Chrome processes first to avoid profile lock conflicts.
        let data_dir = chrome_data_dir();

        // Try to kill existing Chrome instances that might hold the profile lock
        #[cfg(target_os = "windows")]
        {
            let _ = std::process::Command::new("taskkill")
                .args(["/f", "/im", "chrome.exe"])
                .output();
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = std::process::Command::new("pkill")
                .arg("-9")
                .arg("chrome")
                .output();
        }
        std::thread::sleep(std::time::Duration::from_secs(1));

        let mut cmd = Command::new(&chrome_path);
        cmd.args([
            &format!("--remote-debugging-port={}", port),
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
        ]);

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

        // Retry a few times until Chrome is ready
        for attempt in 0..20 {
            match client.get(&json_url).send().await {
                Ok(res) if res.status().is_success() => {
                    let targets: Vec<ChromeTarget> = res.json().await?;
                    // Find a page target (not the browser itself)
                    for target in &targets {
                        if target.r#type.as_deref() == Some("page") {
                            if let Some(ws_url) = &target.ws_url {
                                tracing::debug!("Found page target: {}", ws_url);
                                return Ok(ws_url.clone());
                            }
                        }
                    }
                    // If no page target found, try the first target with ws_url
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

        // Wait for response with matching id
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
                    // Not our response, skip (could be a CDP event)
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
                Ok(Some(_)) => {} // Binary, Close, etc
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

        // Check for exception
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

// ─── Public API ────────────────────────────────────────────────

/// Login to Z.AI via browser, wait for authentication, and capture cookies
pub async fn login_via_browser(headless: bool, _cdp_url: Option<&str>) -> Result<ZaiAuthState> {
    tracing::info!("Starting browser login...");

    // Launch Chrome
    let chrome = ChromeProcess::launch(headless)?;
    let _debug_url = chrome.debug_url();

    // Wait for Chrome to be ready
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Get WebSocket URL for the page
    let ws_url = chrome.get_page_ws_url().await?;
    tracing::info!("Chrome CDP WebSocket: {}", ws_url);

    // Connect to CDP
    let mut cdp = CdpConnection::connect(&ws_url).await?;

    // Enable required domains
    cdp.send_notification("Page.enable").await?;
    cdp.send_notification("Network.enable").await?;
    cdp.send_notification("Runtime.enable").await?;

    // Inject anti-detection before navigation
    inject_stealth_via_cdp(&mut cdp).await?;

    // Navigate to Z.AI
    tracing::info!("Navigating to {}...", ZAI_CHAT_URL);
    cdp.navigate(ZAI_CHAT_URL).await?;

    // Wait for page load
    tokio::time::sleep(Duration::from_secs(3)).await;

    if !headless {
        tracing::info!("════════════════════════════════════════════════════");
        tracing::info!("  Please login to Z.AI (chat.z.ai) in the browser window.");
        tracing::info!("  Waiting for authentication...");
        tracing::info!("════════════════════════════════════════════════════");
    }

    // Poll for login detection
    // We wait until we find specific auth cookies that only appear AFTER
    // the user has actually logged in. We also require the chat page to be
    // fully loaded (chat input element visible) to avoid false positives
    // from pre-login page cookies or analytics tokens.
    let mut authenticated = false;
    for _ in 0..600 {
        tokio::time::sleep(Duration::from_secs(1)).await;

        let result = cdp
            .evaluate(r#"
                (() => {
                    const cookieStr = document.cookie;
                    const currentUrl = window.location.href;

                    // Primary check: specific Z.AI auth cookies that only exist after login
                    // chatglm_refresh_token and chatglm_token are the definitive indicators
                    const hasZaiRefreshToken = cookieStr.includes("chatglm_refresh_token");
                    const hasZaiAccessToken = cookieStr.includes("chatglm_token=");

                    // Secondary check: chat page must be loaded with input element
                    // This ensures we don't detect cookies from the login page itself
                    const hasChatInput =
                        document.querySelector('textarea') !== null ||
                        document.querySelector('[contenteditable="true"]') !== null;

                    // URL check: must be on the chat page, not on login/auth pages
                    const isOnChatPage =
                        currentUrl.includes("chat.z.ai") &&
                        !currentUrl.includes("/login") &&
                        !currentUrl.includes("/auth");

                    // We need EITHER the specific auth cookies, OR a combination of
                    // being on the chat page with the chat input visible.
                    // The chat input alone is not enough (some login pages have textareas),
                    // but auth cookies + chat page is definitive.
                    if ((hasZaiRefreshToken || hasZaiAccessToken) && isOnChatPage) {
                        return true;
                    }

                    // Also detect if we're on the chat page with a visible chat input
                    // and the URL no longer has login/auth in it
                    if (isOnChatPage && hasChatInput &&
                        (cookieStr.includes("chatglm") || cookieStr.includes("token="))) {
                        return true;
                    }

                    return false;
                })()
            "#)
            .await;

        if let Ok(val) = result {
            if val.as_bool().unwrap_or(false) {
                // Extra safety: wait a bit more to ensure cookies are fully set
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

    // Get cookies from CDP
    let cdp_cookies = cdp.get_cookies().await?;
    let cookie_string: String = cdp_cookies
        .iter()
        .map(|c| format!("{}={}", c.name, c.value))
        .collect::<Vec<_>>()
        .join("; ");

    // Get user agent
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

/// Inject anti-detection scripts via CDP
async fn inject_stealth_via_cdp(cdp: &mut CdpConnection) -> Result<()> {
    tracing::debug!("Injecting stealth scripts via CDP...");

    // Use Page.addScriptToEvaluateOnNewDocument to run before any page scripts
    cdp.send_command(
        "Page.addScriptToEvaluateOnNewDocument",
        serde_json::json!({
            "source": r#"
                // Override navigator.webdriver
                Object.defineProperty(navigator, 'webdriver', { get: () => false });

                // Add chrome runtime mock
                window.chrome = { runtime: {}, loadTimes: function(){}, csi: function(){}, app: {} };

                // Override permissions query
                const originalQuery = window.navigator.permissions.query;
                window.navigator.permissions.query = (parameters) =>
                    parameters.name === 'notifications'
                        ? Promise.resolve({ state: Notification.permission })
                        : originalQuery(parameters);

                // Override plugins length
                Object.defineProperty(navigator, 'plugins', {
                    get: () => [1, 2, 3, 4, 5],
                });

                // Override languages
                Object.defineProperty(navigator, 'languages', {
                    get: () => ['zh-CN', 'zh', 'en'],
                });
            "#
        }),
    )
    .await?;

    tracing::debug!("Stealth scripts injected successfully");
    Ok(())
}

/// Chat with Z.AI via browser automation (fallback when API is blocked)
///
/// This opens chat.z.ai in headless Chrome using the stored cookies for auth,
/// types a message into the chat input, and polls the DOM for the response.
/// Supports streaming output by polling the DOM at intervals.
pub async fn chat_via_browser(
    message: &str,
    auth_state: &ZaiAuthState,
) -> Result<BrowserChatResult> {
    tracing::info!("Starting browser chat (API fallback)...");
    let start = std::time::Instant::now();

    // Try connecting to an existing Chrome instance on the login CDP port first
    // Keep chrome process alive for the entire function scope
    let (ws_url, is_existing, _chrome_guard) = match try_connect_existing_chrome().await {
        Some(url) => {
            tracing::info!("Reusing existing Chrome instance");
            (url, true, None)
        }
        None => {
            // Launch a new headless Chrome with a separate profile
            let chrome = match ChromeProcess::launch_headless() {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("Failed to launch headless Chrome ({}), killing existing Chrome and retrying...", e);
                    // Kill any lingering Chrome processes that might hold the profile lock
                    let _ = std::process::Command::new("taskkill")
                        .args(["/f", "/im", "chrome.exe"])
                        .output();
                    let _ = std::process::Command::new("killall")
                        .arg("chrome")
                        .output();
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    ChromeProcess::launch_headless()?
                }
            };
            tokio::time::sleep(Duration::from_secs(3)).await;
            let url = get_page_ws_url_for_port(ZAI_CDP_PORT_HEADLESS).await?;
            (url, false, Some(chrome))
        }
    };

    let mut cdp = CdpConnection::connect(&ws_url).await?;

    cdp.send_notification("Page.enable").await?;
    cdp.send_notification("Network.enable").await?;
    cdp.send_notification("Runtime.enable").await?;

    // Check if we're already on chat.z.ai (reusing login browser)
    let current_url = cdp.evaluate("window.location.href").await
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default();

    if current_url.contains("chat.z.ai") && is_existing {
        tracing::info!("Already on chat.z.ai, reusing session");
    } else {
        // Inject stealth first
        inject_stealth_via_cdp(&mut cdp).await?;

        // Navigate to z.ai first (cookies need a domain context)
        tracing::info!("Navigating to chat.z.ai (first pass for cookies)...");
        cdp.navigate("https://chat.z.ai").await?;
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Now inject cookies while on the correct domain
        let mut cookie_count = 0;
        for cookie_part in auth_state.cookie.split(';') {
            let trimmed = cookie_part.trim();
            if let Some(eq_idx) = trimmed.find('=') {
                let name = &trimmed[..eq_idx];
                let value = &trimmed[eq_idx + 1..];
                // Set cookie - try multiple domain formats for maximum compatibility
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

        // Verify cookies were actually set
        let verify_cookies = cdp.evaluate(r#"
            (() => {
                return document.cookie.substring(0, 500);
            })()
        "#).await;
        tracing::info!("Cookies after injection: {:?}", verify_cookies);

        // Also set cookies via JavaScript as a fallback (for non-httpOnly cookies)
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
        "#, auth_state.cookie)).await;
        tracing::info!("JS cookie injection result: {:?}", js_cookie_result);

        // Reload with cookies now set
        tracing::info!("Reloading chat.z.ai with cookies...");
        cdp.navigate(ZAI_CHAT_URL).await?;
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Force a hard reload to ensure the page picks up the new cookies
        // (SPA may have cached the unauthenticated state)
        cdp.evaluate("location.reload(true)").await?;
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Verify we're logged in by checking for auth cookies and chat UI
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
    }

    // Find and type into the textarea using JS (React-compatible)
    // Safe truncation that respects UTF-8 char boundaries
    let msg_preview: String = message.chars().take(60).collect();
    tracing::info!("Sending message: \"{}\"", msg_preview);

    // First, check if we can find the textarea
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

    // Use Input.insertText for reliable text input, then trigger React events
    // First click on the textarea
    cdp.evaluate(r#"
        (() => {
            const ta = document.querySelector('textarea') || document.querySelector('[contenteditable="true"]');
            if (ta) { ta.focus(); ta.click(); }
            return ta ? 'focused' : 'not_found';
        })()
    "#).await?;

    // Small delay for focus
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Use Input.insertText to type the message
    cdp.send_command(
        "Input.insertText",
        serde_json::json!({ "text": message }),
    ).await?;

    // Small delay for React to process
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Check if the textarea has content
    let textarea_content = cdp.evaluate(r#"
        (() => {
            const ta = document.querySelector('textarea');
            return ta ? ta.value : '';
        })()
    "#).await;
    tracing::info!("Textarea content after insert: {:?}", textarea_content);

    // If textarea is empty, try JavaScript-based input as fallback
    if let Ok(val) = &textarea_content {
        let content = val.as_str().unwrap_or("");
        if content.is_empty() {
            tracing::warn!("Input.insertText didn't work, trying JS-based input...");
            // Use React-compatible JS input method
            let escaped_msg = message.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n");
            cdp.evaluate(&format!(r#"
                (() => {{
                    const ta = document.querySelector('textarea');
                    if (!ta) return 'no_textarea';
                    
                    // Use nativeInputValueSetter to bypass React's controlled input
                    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
                        window.HTMLTextAreaElement.prototype, 'value'
                    ).set;
                    nativeInputValueSetter.call(ta, "{escaped_msg}");
                    ta.dispatchEvent(new Event('input', {{ bubbles: true }}));
                    ta.dispatchEvent(new Event('change', {{ bubbles: true }}));
                    return ta.value.substring(0, 50);
                }})()
            "#)).await?;
        }
    }

    // Press Enter key down
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

    // Press Enter key up
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

    // Wait a moment and check if the message was sent (URL should change to /c/xxx)
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let url_after_enter = cdp.evaluate("window.location.href").await
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default();

    if !url_after_enter.contains("/c/") {
        tracing::warn!("Enter key didn't submit the message (URL still: {}), trying send button...", url_after_enter);
        // Try clicking the send button
        cdp.evaluate(r#"
            (() => {
                // Look for a send/submit button near the textarea
                const btn = document.querySelector('button[type="submit"]') ||
                    document.querySelector('[class*="send"]') ||
                    document.querySelector('[aria-label*="send"]') ||
                    document.querySelector('[aria-label*="Send"]') ||
                    document.querySelector('form button') ||
                    // Try finding any button that's a sibling of the textarea
                    document.querySelector('textarea').closest('form')?.querySelector('button');
                if (btn) { btn.click(); return 'clicked'; }
                // Also try submitting the form directly
                const form = document.querySelector('textarea')?.closest('form');
                if (form) { form.submit(); return 'form_submitted'; }
                return 'no_button_found';
            })()
        "#).await?;
    }

    tracing::info!("Message sent, waiting for response...");

    // Wait for the response to start appearing
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Poll for the response, streaming as it comes in
    let mut reply_text = String::new();
    let mut thinking_text = String::new();
    let mut last_thinking_length: usize = 0;
    let mut last_reply_length: usize = 0;
    let mut last_total_length: usize = 0;
    let mut stable_count = 0;

    for poll_idx in 0..120 { // max 2 minutes
        tokio::time::sleep(Duration::from_secs(1)).await;

        // On first few polls, also log the page structure for debugging
        if poll_idx < 5 {
            let debug_info = cdp.evaluate(r#"
                (() => {
                    // Inspect the actual DOM structure of z.ai's chat page
                    // Find all direct children of the main chat area
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

                    // Find the last few elements that might contain the response
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

        // Extract thinking and reply text separately from the DOM
        // Z.AI DOM structure (confirmed from logs):
        //   - thinking-block: contains the AI's reasoning/thinking text
        //   - thinking-chain-container: header ("正在思考\n跳过")
        //   - chat-assistant.markdown-prose: contains ALL text (thinking + reply)
        //   - user-message: user's sent message
        // We extract thinking from thinking-block, and reply from chat-assistant
        // minus thinking sub-elements.
        let result = cdp.evaluate(r#"
            (() => {
                // Extract thinking text from thinking-block elements only
                let thinkingText = '';
                document.querySelectorAll('[class*="thinking-block"]').forEach(el => {
                    thinkingText += el.innerText.trim() + '\n';
                });

                // Extract reply text: find the chat-assistant container and remove thinking blocks
                let replyText = '';

                // Strategy 1: Use chat-assistant class (z.ai's actual DOM structure)
                const chatAssistant = document.querySelector('[class*="chat-assistant"]');
                if (chatAssistant) {
                    const clone = chatAssistant.cloneNode(true);
                    clone.querySelectorAll('[class*="think"], [class*="reasoning"], [class*="chain-of-thought"]').forEach(el => el.remove());
                    replyText = clone.innerText.trim();
                }

                // Strategy 2: Try markdown-prose class
                if (!replyText) {
                    const prose = document.querySelector('[class*="markdown-prose"]');
                    if (prose) {
                        const clone = prose.cloneNode(true);
                        clone.querySelectorAll('[class*="think"], [class*="reasoning"]').forEach(el => el.remove());
                        replyText = clone.innerText.trim();
                    }
                }

                // Strategy 3: Find message containers (excluding user messages and thinking)
                if (!replyText) {
                    const allMsgs = document.querySelectorAll('[class*="message"]');
                    for (let i = allMsgs.length - 1; i >= 0; i--) {
                        const el = allMsgs[i];
                        const classes = (el.className || '').toLowerCase();
                        if (classes.includes('user-message')) continue;
                        if (classes.includes('think') || classes.includes('reasoning')) continue;
                        const clone = el.cloneNode(true);
                        clone.querySelectorAll('[class*="think"], [class*="reasoning"]').forEach(e => e.remove());
                        const text = clone.innerText.trim();
                        if (text && text.length > 2) { replyText = text; break; }
                    }
                }

                return JSON.stringify({ thinking: thinkingText.trim(), reply: replyText });
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
                        // Find safe UTF-8 char boundary
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
                                eprint!("\x1b[90m{}\x1b[0m", delta); // gray for thinking
                                thinking_text.push_str(delta);
                            }
                        }
                        last_thinking_length = thinking_len;
                    } else if thinking_len < last_thinking_length {
                        // Thinking text shrank (likely collapsed/hidden by React)
                        tracing::debug!("Thinking text shrunk ({} -> {}), DOM update", last_thinking_length, thinking_len);
                        last_thinking_length = thinking_len;
                    }

                    // Track reply deltas
                    if reply_len > last_reply_length {
                        // Find safe UTF-8 char boundary
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
                            }
                        }
                        last_reply_length = reply_len;
                    } else if reply_len < last_reply_length {
                        // Reply text shrank (React re-render)
                        tracing::debug!("Reply text shrunk ({} -> {}), likely React re-render", last_reply_length, reply_len);
                        last_reply_length = reply_len;
                    }

                    // Check stability based on total content length
                    if total_len > 0 && total_len == last_total_length {
                        stable_count += 1;
                        if stable_count >= 5 {
                            tracing::info!("Response complete (stable for 5s, poll #{})", poll_idx);
                            break;
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

/// Try to connect to an already running Chrome instance on the default CDP port
async fn try_connect_existing_chrome() -> Option<String> {
    let ws_url = get_page_ws_url_for_port(ZAI_CDP_PORT).await.ok()?;
    // Replace localhost with 127.0.0.1 to avoid IPv6 issues on Windows
    let ws_url = ws_url.replace("localhost", "127.0.0.1");
    // Verify the connection works
    let mut cdp = CdpConnection::connect(&ws_url).await.ok()?;
    let result = cdp.evaluate("1+1").await.ok()?;
    if result.as_u64() == Some(2) {
        Some(ws_url)
    } else {
        None
    }
}

/// Get page WebSocket URL for a specific CDP port (with retry)
async fn get_page_ws_url_for_port(port: u16) -> Result<String> {
    let json_url = format!("http://127.0.0.1:{}/json", port);
    let client = reqwest::Client::new();

    // Retry up to 20 times (10 seconds total)
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

#[derive(Debug, Clone)]
pub struct BrowserChatResult {
    pub reply: String,
    pub thinking: String,
    pub raw_length: usize,
    pub elapsed_ms: u64,
}

// ─── Helpers ──────────────────────────────────────────────────

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

    // Try PATH lookup
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

    bail!(
        "Chrome/Chromium not found. Please install Chrome or set CDP_URL to connect to an existing instance."
    )
}

/// Find an available TCP port for CDP
fn find_available_port() -> u16 {
    // Try common CDP ports first
    for port in [9222, 9223, 9224, 9225, 9226, 9227, 9228, 9229] {
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    // Use OS-assigned port
    if let Ok(listener) = std::net::TcpListener::bind("127.0.0.1:0") {
        if let Ok(addr) = listener.local_addr() {
            return addr.port();
        }
    }
    9222
}
