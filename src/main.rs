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

        Commands::Chat { message, model } => {
            let config = config::AppConfig::load()?;
            let message = message.unwrap_or_else(|| {
                eprintln!("Usage: zair chat <message>");
                std::process::exit(1);
            });

            let auth_state = auth::load_auth();

            // Try API strategies (web API → Open API), fallback to browser if all fail
            let zai_client = client::ZaiClient::new(config.clone());
            let api_result = zai_client
                .chat_stream(
                    &message,
                    &model,
                    None,
                    None,
                    Some(Box::new(|delta: &str, is_thinking: bool| {
                        if is_thinking {
                            eprint!("\x1b[90m{}\x1b[0m", delta);
                        } else {
                            eprint!("{}", delta);
                        }
                    })),
                )
                .await;

            match api_result {
                Ok(result) => {
                    println!();
                    if !result.thinking.is_empty() {
                        eprintln!("\n--- Thinking ---");
                        eprintln!("{}", result.thinking);
                    }
                }
                Err(e) => {
                    let err_str = e.to_string();
                    // If all API strategies failed, try browser fallback
                    if err_str.contains("All API strategies failed")
                        || err_str.contains("405")
                        || err_str.contains("403")
                        || err_str.contains("blocked")
                    {
                        tracing::info!("API unavailable, falling back to browser chat...");
                        if let Some(auth) = auth_state {
                            let browser_result = browser::chat_via_browser(&message, &auth).await?;
                            println!();
                            if !browser_result.thinking.is_empty() {
                                eprintln!("\n--- Thinking ---");
                                eprintln!("{}", browser_result.thinking);
                            }
                        } else {
                            return Err(anyhow::anyhow!(
                                "API unavailable and no browser auth. Run `zair login` first, or set ZAI_API_KEY."
                            ));
                        }
                    } else {
                        return Err(e);
                    }
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
    }

    Ok(())
}
