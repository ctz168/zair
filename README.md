# ZAIR - Z.AI Browser Chat Service (Rust)

Rust rewrite of the ZAI agent with headless Chrome automation, AICQ integration, and streaming output (including thinking content).

## Features

- **Browser Automation**: Headless Chrome via CDP with anti-detection scripts
- **Cookie Authentication**: Captures and injects Z.AI cookies from browser login
- **SSE Streaming**: Real-time streaming output with thinking content extraction
- **AICQ Integration**: WebSocket connection to AICQ server for message handling
- **Captcha Handling**: Automatic captcha bypass via browser automation
- **Conversation Memory**: Per-peer/group conversation history

## Installation

```bash
cargo build --release
```

## Usage

### Login to Z.AI
```bash
zair login              # Opens browser for login
zair login --headless   # Headless mode
zair login --cdp-url http://localhost:9222  # Connect to existing Chrome
```

### Start Agent
```bash
zair agent                          # Start with defaults
zair agent --name "My Bot"          # Set display name
zair agent --server https://aicq.online  # Custom AICQ server
zair agent --model glm-4-plus       # Select model
zair agent --daemon                  # Run as daemon
```

### Chat Directly
```bash
zair chat "Hello, who are you?"
zair chat "Explain Rust" --model glm-4-think
```

### Check Status
```bash
zair status
```

## Architecture

```
src/
├── main.rs       # CLI entry point
├── auth/         # Cookie/session management, sign generation, token refresh
├── browser/      # Headless Chrome automation (CDP), captcha handling
├── client/       # Z.AI HTTP client with SSE streaming
├── agent/        # AICQ agent runtime (WebSocket, message handling)
└── config/       # Configuration management
```

## Environment Variables

- `ZAI_PROXY_URL`: HTTP proxy for Z.AI API requests (bypass CDN blocking)
- `RUST_LOG`: Log level (e.g., `zair=debug`)

## License

MIT
