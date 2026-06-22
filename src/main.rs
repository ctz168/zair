//! ZAIR - Z.AI Browser Chat Service (Rust)
//!
//! Connects to Z.AI via headless Chrome automation with cookie injection,
//! handles captcha automatically, and streams responses (including thinking)
//! through the AICQ protocol.

mod agent;
mod auth;
mod browser;
mod client;
mod config;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "zair")]
#[command(about = "Z.AI Browser Chat Service - Rust edition")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the AICQ agent (connects to AICQ, processes messages)
    Agent {
        /// Agent display name
        #[arg(long, default_value = "ZAI Agent")]
        name: String,

        /// AICQ server URL
        #[arg(long, default_value = "https://aicq.online")]
        server: String,

        /// Model to use
        #[arg(long, default_value = "glm-4-plus")]
        model: String,

        /// Run as daemon (background)
        #[arg(long)]
        daemon: bool,
    },

    /// Chat with Z.AI directly (one-shot or interactive)
    Chat {
        /// Message to send
        message: Option<String>,

        /// Model to use
        #[arg(long, default_value = "glm-4-plus")]
        model: String,
    },

    /// Login to Z.AI via browser (captures cookies)
    Login {
        /// Run browser in headless mode
        #[arg(long)]
        headless: bool,

        /// Connect to existing Chrome via CDP URL
        #[arg(long)]
        cdp_url: Option<String>,
    },

    /// Check Z.AI authentication status
    Status,

    /// Chat directly via ZaiClient (API path, NOT browser).
    /// Sends the Agent-mode payload (flags=[general_agent], variables, captcha_verify_param)
    /// and streams SSE. For glm-5.* models this triggers Agent mode.
    ApiChat {
        /// Message to send
        message: String,

        /// Model to use (glm-5.2 triggers Agent mode)
        #[arg(long, default_value = "glm-5.2")]
        model: String,

        /// Optional conversation ID for multi-turn
        #[arg(long)]
        conversation_id: Option<String>,

        /// Optional system prompt
        #[arg(long)]
        system: Option<String>,
    },

    /// Chat via browser automation (zair's stealth Chrome + persistent profile).
    /// This is the original "通过" path — does NOT use the API directly.
    BrowserChat {
        /// Message to send
        message: String,
    },

    /// Start a browser session and keep Chrome alive for external probing.
    /// Does NOT send any chat message — just launches Chrome, injects cookies,
    /// navigates to chat.z.ai, and waits forever (until Ctrl+C or killed).
    /// Used so external tools (e.g. CDP probes) can inspect the live page.
    BrowserProbe {
        /// CDP port (default 9223, same as BrowserSession)
        #[arg(long, default_value_t = 9223)]
        port: u16,
    },

    /// Set owner (master) ID and send friend request via AICQ
    Owner {
        /// Owner's AICQ user ID
        owner_id: String,

        /// AICQ server URL
        #[arg(long, default_value = "https://aicq.online")]
        server: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("zair=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Agent {
            name,
            server,
            model,
            daemon,
        } => {
            let mut config = config::AppConfig::load()?;
            config.agent.nickname = name;
            config.agent.server_url = server;
            config.agent.model = model;

            if daemon {
                // TODO: implement daemon mode with double-fork
                tracing::info!("Starting agent in daemon mode...");
            }

            let mut runtime = agent::AgentRuntime::new(config);
            runtime.run().await?;
        }

        Commands::Chat { message, model: _ } => {
            let _config = config::AppConfig::load()?;
            let message = message.unwrap_or_else(|| {
                eprintln!("Usage: zair chat <message>");
                std::process::exit(1);
            });

            let auth_state = auth::load_auth();

            // Use browser chat directly (API is unreliable - returns 500/405)
            match auth_state {
                Some(auth) => {
                    let browser_result = browser::chat_via_browser(&message, &auth, None).await?;
                    println!();
                    if !browser_result.thinking.is_empty() {
                        eprintln!("\n--- Thinking ---");
                        eprintln!("{}", browser_result.thinking);
                    }
                    eprintln!("\n--- Reply ---");
                    println!("{}", browser_result.reply);
                    eprintln!("\n({} chars, {}ms)", browser_result.reply.len(), browser_result.elapsed_ms);
                }
                None => {
                    return Err(anyhow::anyhow!(
                        "No browser auth available. Run `zair login` first."
                    ));
                }
            }
        }

        Commands::Login { headless, cdp_url } => {
            let _config = config::AppConfig::load()?;
            let auth_state = browser::login_via_browser(headless, cdp_url.as_deref()).await?;
            auth::save_auth(&auth_state)?;
            tracing::info!("Login successful! Cookies saved.");
        }

        Commands::Status => {
            match auth::load_auth() {
                Some(auth_state) => {
                    println!("Z.AI Authentication Status:");
                    println!(
                        "  Cookie length: {}",
                        auth_state.cookie.len()
                    );
                    println!(
                        "  Refresh token: {}",
                        if auth_state.refresh_token.is_some() {
                            "Yes"
                        } else {
                            "No"
                        }
                    );
                    println!(
                        "  Access token:  {}",
                        if auth_state.access_token.is_some() {
                            "Yes"
                        } else {
                            "No"
                        }
                    );
                    println!("  Captured at:   {}", auth_state.captured_at);
                    println!("  User agent:    {}", auth_state.user_agent);
                }
                None => {
                    println!("Not logged in. Run `zair login` to authenticate.");
                }
            }
        }

        Commands::Owner { owner_id, server } => {
            let mut config = config::AppConfig::load()?;
            config.agent.server_url = server;
            if !config.agent.masters.contains(&owner_id) {
                config.agent.masters.push(owner_id.clone());
            }
            config.save()?;

            let runtime = agent::AgentRuntime::new(config);
            runtime.add_owner(&owner_id).await?;
            tracing::info!("Owner {} added and friend request sent!", owner_id);
        }

        Commands::ApiChat {
            message,
            model,
            conversation_id,
            system,
        } => {
            // ── Browser-hijack Agent mode (彻底方案) ──
            // Launches stealth Chrome, navigates to chat.z.ai, installs a
            // fetch hook that:
            //   1. Replaces messages[0].content with zair's message
            //   2. Replaces model with zair's model
            //   3. Intercepts the response stream
            // Then types a placeholder + clicks send, which triggers the
            // browser's chat (with its own captcha_verify_param). zair reads
            // the SSE response chunks from window.__zair_agent_chat.chunks
            // and forwards them to the callback.
            //
            // This bypasses the captcha_verify_param problem entirely: the
            // browser generates and consumes its own token, zair only rewrites
            // the message body and reads the response stream.
            let _ = (conversation_id.as_deref(), system.as_deref());

            let agent_mode = client::ZaiClient::is_agent_model(&model);
            eprintln!();
            eprintln!("=== api-chat (browser-hijack Agent mode) ===");
            eprintln!("  model:           {}", model);
            eprintln!("  agent_mode:      {}", agent_mode);
            eprintln!("  message:         {}", message.chars().take(80).collect::<String>());
            if message.chars().count() > 80 {
                eprintln!("                   ... ({} chars total)", message.chars().count());
            }
            eprintln!();

            if !agent_mode {
                eprintln!("  WARN: model {} is not an Agent-mode model (glm-5.*).", model);
                eprintln!("        The browser will still try to send it, but the response");
                eprintln!("        may not include reasoning_content / Agent features.");
                eprintln!();
            }

            let auth_state = match auth::load_auth() {
                Some(a) => a,
                None => {
                    return Err(anyhow::anyhow!(
                        "No browser auth available. Run `zair login` first."
                    ));
                }
            };

            // ── Retry loop with exponential backoff ──
            // Retryable errors (server-side transient issues):
            //   - MODEL_CONCURRENCY_LIMIT  ("当前模型使用人数较多")
            //   - WORKSPACE_TOOL_INIT_ERROR (MCP server 500)
            //   - context deadline exceeded / timeout
            //   - connection reset / network blips
            // Non-retryable (won't fix with retry):
            //   - FRONTEND_CAPTCHA_REQUIRED (need fresh captcha, but each retry
            //     gets a fresh one anyway since we relaunch the browser, so
            //     actually we DO retry this too)
            //   - 401/403 (auth issues)
            //   - All other unknown errors
            fn is_retryable(err: &anyhow::Error) -> bool {
                let s = err.to_string();
                let retryable_markers = [
                    "MODEL_CONCURRENCY_LIMIT",
                    "WORKSPACE_TOOL_INIT_ERROR",
                    "context deadline exceeded",
                    "Timeout",
                    "timeout",
                    "connection reset",
                    "broken session",
                    "500 Internal Server Error",
                    "502 Bad Gateway",
                    "503 Service Unavailable",
                    "504 Gateway Timeout",
                    "ECONNRESET",
                    "ECONNREFUSED",
                    "ETIMEDOUT",
                ];
                retryable_markers.iter().any(|m| s.contains(m))
            }

            let started = std::time::Instant::now();
            let max_attempts = 5;
            let mut final_result: Result<browser::BrowserChatResult, anyhow::Error> =
                Err(anyhow::anyhow!("no attempt made"));

            for attempt in 1..=max_attempts {
                if attempt > 1 {
                    // Exponential backoff: 2^(attempt-2) seconds
                    // attempt=2 → 1s, attempt=3 → 2s, attempt=4 → 4s, attempt=5 → 8s
                    let delay = std::time::Duration::from_secs(1u64 << (attempt - 2));
                    eprintln!();
                    eprintln!(
                        "\x1b[33m=== retry {}/{} after {:.1}s backoff ===\x1b[0m",
                        attempt,
                        max_attempts,
                        delay.as_secs_f64()
                    );
                    tokio::time::sleep(delay).await;
                }

                // Fresh mpsc channel + printer for each attempt
                let (tx, mut rx) = tokio::sync::mpsc::channel::<browser::StreamChunk>(128);
                let printer = tokio::spawn(async move {
                    use std::io::Write;
                    while let Some(chunk) = rx.recv().await {
                        match chunk.chunk_type.as_str() {
                            "thinking" | "think" => {
                                eprint!("\x1b[2m{}\x1b[0m", chunk.data);
                                let _ = std::io::stderr().flush();
                            }
                            "reply" | "content" | "text" | "" => {
                                print!("{}", chunk.data);
                                let _ = std::io::stdout().flush();
                            }
                            _ => {
                                eprintln!("[chunk:{}] {}", chunk.chunk_type, chunk.data);
                            }
                        }
                    }
                });

                let cb: client::StreamCallback = Box::new(move |delta: &str, is_thinking: bool| {
                    let chunk = browser::StreamChunk {
                        chunk_type: if is_thinking { "thinking".to_string() } else { "reply".to_string() },
                        data: delta.to_string(),
                    };
                    let _ = tx.try_send(chunk);
                });

                let attempt_start = std::time::Instant::now();
                let result = browser::chat_via_browser_agent(&auth_state, &message, &model, Some(&cb)).await;
                drop(cb);
                let _ = printer.await;

                eprintln!();
                eprintln!("\x1b[0m");
                let attempt_elapsed = attempt_start.elapsed();

                match result {
                    Ok(r) => {
                        eprintln!();
                        eprintln!(
                            "\x1b[32m=== attempt {} succeeded in {:.2}s ===\x1b[0m",
                            attempt,
                            attempt_elapsed.as_secs_f64()
                        );
                        final_result = Ok(r);
                        break;
                    }
                    Err(e) => {
                        let err_str = e.to_string();
                        eprintln!();
                        eprintln!(
                            "\x1b[31m=== attempt {}/{} failed in {:.2}s: {} ===\x1b[0m",
                            attempt,
                            max_attempts,
                            attempt_elapsed.as_secs_f64(),
                            err_str.chars().take(300).collect::<String>()
                        );
                        if !is_retryable(&e) {
                            eprintln!("\x1b[31m  (non-retryable error, stopping)\x1b[0m");
                            final_result = Err(e);
                            break;
                        }
                        if attempt == max_attempts {
                            eprintln!("\x1b[31m  (max attempts reached, giving up)\x1b[0m");
                            final_result = Err(e);
                        } else {
                            eprintln!("\x1b[33m  (retryable, will retry)\x1b[0m");
                            final_result = Err(e);
                        }
                    }
                }
            }

            let elapsed = started.elapsed();
            let result = final_result;

            match result {
                Ok(r) => {
                    eprintln!();
                    eprintln!("=== result ===");
                    eprintln!("  reply_chars:    {}", r.reply.chars().count());
                    eprintln!("  thinking_chars: {}", r.thinking.chars().count());
                    eprintln!("  elapsed:        {:.2}s ({}ms)",
                        elapsed.as_secs_f64(), r.elapsed_ms);
                    if !r.thinking.is_empty() {
                        eprintln!();
                        eprintln!("--- Thinking (first 800 chars) ---");
                        let preview: String = r.thinking.chars().take(800).collect();
                        eprintln!("{}", preview);
                        if r.thinking.chars().count() > 800 {
                            eprintln!("... ({} more chars)", r.thinking.chars().count() - 800);
                        }
                    }
                    if !r.reply.is_empty() {
                        eprintln!();
                        eprintln!("--- Reply (first 800 chars) ---");
                        let preview: String = r.reply.chars().take(800).collect();
                        eprintln!("{}", preview);
                        if r.reply.chars().count() > 800 {
                            eprintln!("... ({} more chars)", r.reply.chars().count() - 800);
                        }
                    }
                }
                Err(e) => {
                    eprintln!();
                    eprintln!("=== ERROR (after {:.2}s) ===", elapsed.as_secs_f64());
                    eprintln!("  {}", e);
                    let chain: Vec<String> = e
                        .chain()
                        .skip(1)
                        .map(|c| c.to_string())
                        .collect();
                    if !chain.is_empty() {
                        eprintln!("  cause: {}", chain.join(" -> "));
                    }
                    std::process::exit(1);
                }
            }
        }

        Commands::BrowserChat { message } => {
            // ── Browser path (zair's own stealth Chrome + persistent profile) ──
            // This is the path that previously worked end-to-end.
            let _config = config::AppConfig::load()?;
            eprintln!();
            eprintln!("=== browser-chat (stealth Chrome path) ===");
            eprintln!("  message: {}", message.chars().take(80).collect::<String>());
            if message.chars().count() > 80 {
                eprintln!("           ... ({} chars total)", message.chars().count());
            }
            eprintln!();

            let auth_state = match auth::load_auth() {
                Some(a) => a,
                None => {
                    return Err(anyhow::anyhow!(
                        "No browser auth available. Run `zair login` first."
                    ));
                }
            };

            let (tx, mut rx) = tokio::sync::mpsc::channel::<browser::StreamChunk>(64);
            let printer = tokio::spawn(async move {
                use std::io::Write;
                while let Some(chunk) = rx.recv().await {
                    match chunk.chunk_type.as_str() {
                        "thinking" | "think" => {
                            eprint!("\x1b[2m{}\x1b[0m", chunk.data);
                            let _ = std::io::stderr().flush();
                        }
                        "reply" | "content" | "text" | "" => {
                            print!("{}", chunk.data);
                            let _ = std::io::stdout().flush();
                        }
                        _ => {
                            eprintln!("[chunk:{}] {}", chunk.chunk_type, chunk.data);
                        }
                    }
                }
            });

            let started = std::time::Instant::now();
            let result = browser::chat_via_browser(&message, &auth_state, Some(tx)).await;
            let _ = printer.await;

            eprintln!();
            eprintln!("\x1b[0m");
            let elapsed = started.elapsed();

            match result {
                Ok(r) => {
                    eprintln!();
                    eprintln!("=== result ===");
                    eprintln!("  reply_chars:    {}", r.reply.chars().count());
                    eprintln!("  thinking_chars: {}", r.thinking.chars().count());
                    eprintln!("  raw_length:     {}", r.raw_length);
                    eprintln!("  elapsed:        {:.2}s ({}ms)",
                        elapsed.as_secs_f64(), r.elapsed_ms);
                    if !r.reply.is_empty() {
                        eprintln!();
                        eprintln!("--- Reply (first 500 chars) ---");
                        let preview: String = r.reply.chars().take(500).collect();
                        eprintln!("{}", preview);
                    }
                }
                Err(e) => {
                    eprintln!();
                    eprintln!("=== ERROR (after {:.2}s) ===", elapsed.as_secs_f64());
                    eprintln!("  {}", e);
                    let chain: Vec<String> = e
                        .chain()
                        .skip(1)
                        .map(|c| c.to_string())
                        .collect();
                    if !chain.is_empty() {
                        eprintln!("  cause: {}", chain.join(" -> "));
                    }
                    std::process::exit(1);
                }
            }
        }

        Commands::BrowserProbe { port } => {
            // Launch Chrome, init session (cookies + navigate to chat.z.ai),
            // then sleep forever. External CDP clients can connect to
            // http://127.0.0.1:{port}/json and inspect/manipulate the page.
            let _ = port; // BrowserSession uses ZAI_CDP_PORT_HEADLESS (9223) internally
            let _config = config::AppConfig::load()?;
            let auth_state = match auth::load_auth() {
                Some(a) => a,
                None => {
                    return Err(anyhow::anyhow!(
                        "No browser auth available. Run `zair login` first."
                    ));
                }
            };

            eprintln!();
            eprintln!("=== browser-probe ===");
            eprintln!("  Launching Chrome and initializing session...");
            eprintln!("  CDP endpoint: http://127.0.0.1:9223/json");
            eprintln!("  (Ctrl+C to stop)");
            eprintln!();

            let mut session = browser::BrowserSession::new(&auth_state);
            session.ensure_running().await?;

            // Force a full initialize (navigate + cookies + reload) so the
            // page is on chat.z.ai with auth cookies set.
            let ws_url = browser::get_page_ws_url_for_port(9223).await
                .map_err(|e| anyhow::anyhow!("Failed to get page WS URL after Chrome launch: {}", e))?;
            let mut cdp = browser::CdpConnection::connect(&ws_url).await
                .map_err(|e| anyhow::anyhow!("Failed to connect to Chrome CDP: {}", e))?;
            cdp.send_notification("Page.enable").await?;
            cdp.send_notification("Network.enable").await?;
            cdp.send_notification("Runtime.enable").await?;

            // Force re-initialization so we definitely land on chat.z.ai with cookies.
            // We call initialize_session via a small dance: BrowserSession::chat()
            // would do this for us, but we don't want to send a message.
            // Instead, navigate directly.
            cdp.navigate("https://chat.z.ai/").await?;
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;

            eprintln!("  Session ready. Leaving Chrome running.");
            eprintln!("  Connect via CDP and trigger a chat manually to capture");
            eprintln!("  the captcha_verify_param + full Agent payload.");

            // Keep Chrome alive forever (until killed)
            // We must NOT let `session` go out of scope — Drop shuts down Chrome.
            // So we sleep indefinitely.
            tokio::signal::ctrl_c().await.ok();
            eprintln!("\nCtrl+C received, shutting down...");
            session.shutdown();
        }
    }

    Ok(())
}
