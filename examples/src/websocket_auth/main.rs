//! WebSocket Authentication Example
//!
//! This example demonstrates WebSocket security with Actix Security:
//! - JWT authentication during WebSocket handshake
//! - Origin validation (CSWSH prevention)
//! - User context in WebSocket connection
//!
//! # Run
//! ```bash
//! cargo run -p actix-security-examples --bin websocket_auth
//! ```
//!
//! # Test
//! ```bash
//! # Get a JWT token first
//! TOKEN=$(curl -s -X POST http://localhost:8080/login \
//!   -H "Content-Type: application/json" \
//!   -d '{"username":"admin","password":"admin"}' | jq -r '.token')
//!
//! # Connect to WebSocket with token (using websocat)
//! websocat "ws://localhost:8080/ws" \
//!   -H "Authorization: Bearer $TOKEN" \
//!   -H "Origin: http://localhost:8080"
//! ```

use actix_security::http::security::{
    websocket::{OriginValidator, WebSocketSecurityConfig},
    Argon2PasswordEncoder, JwtAuthenticator, JwtConfig, JwtTokenService, PasswordEncoder, User,
};
use actix_web::{
    get, post, web, App, HttpMessage, HttpRequest, HttpResponse, HttpServer, Responder,
};
use actix_ws::Message;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Login credentials
#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

/// Token response
#[derive(Serialize)]
struct TokenResponse {
    token: String,
    token_type: String,
}

/// Application state
struct AppState {
    users: Vec<User>,
    encoder: Argon2PasswordEncoder,
    jwt_service: JwtTokenService,
    jwt_authenticator: JwtAuthenticator,
    origin_validator: OriginValidator,
    ws_config: WebSocketSecurityConfig,
}

/// Login endpoint - returns JWT token for WebSocket authentication
#[post("/login")]
async fn login(
    data: web::Data<Arc<AppState>>,
    credentials: web::Json<LoginRequest>,
) -> impl Responder {
    // Find user and verify password
    let user = data
        .users
        .iter()
        .find(|u| u.get_username() == credentials.username);

    match user {
        Some(user)
            if data
                .encoder
                .matches(&credentials.password, user.get_password()) =>
        {
            // Generate JWT token
            match data.jwt_service.generate_token(user) {
                Ok(token) => HttpResponse::Ok().json(TokenResponse {
                    token,
                    token_type: "Bearer".to_string(),
                }),
                Err(e) => HttpResponse::InternalServerError().body(format!("Token error: {}", e)),
            }
        }
        _ => HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Invalid credentials"
        })),
    }
}

/// Helper function to extract and validate JWT from request
fn extract_user_from_jwt(
    req: &HttpRequest,
    jwt_authenticator: &JwtAuthenticator,
) -> Result<User, String> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    let token = match auth_header {
        Some(h) if h.starts_with("Bearer ") => &h[7..],
        _ => return Err("Missing or invalid Authorization header".to_string()),
    };

    match jwt_authenticator.validate_token(token) {
        Ok(token_data) => {
            let claims = token_data.claims;
            Ok(User::new(claims.sub, String::new())
                .roles(&claims.roles.into_iter().collect::<Vec<_>>())
                .authorities(&claims.authorities.into_iter().collect::<Vec<_>>()))
        }
        Err(e) => Err(format!("Invalid token: {}", e)),
    }
}

/// WebSocket endpoint with full security (auth + origin)
///
/// This demonstrates using WebSocketSecurityConfig for validation.
#[get("/ws")]
async fn ws_handler(
    req: HttpRequest,
    stream: web::Payload,
    data: web::Data<Arc<AppState>>,
) -> Result<HttpResponse, actix_web::Error> {
    // Step 1: Validate origin (CSWSH prevention)
    data.origin_validator.validate(&req)?;

    // Step 2: Extract and validate JWT
    let user = extract_user_from_jwt(&req, &data.jwt_authenticator)
        .map_err(actix_web::error::ErrorUnauthorized)?;

    // Step 3: Check required authority
    if !user.has_authority("ws:connect") {
        return Err(actix_web::error::ErrorForbidden(
            "Missing ws:connect authority",
        ));
    }

    log::info!(
        "WebSocket connection from user: {} (roles: {:?})",
        user.get_username(),
        user.get_roles()
    );

    // Upgrade to WebSocket
    let (response, mut session, mut msg_stream) = actix_ws::handle(&req, stream)?;

    // Spawn WebSocket handler task
    actix_web::rt::spawn(async move {
        // Send welcome message
        let welcome = format!(
            "Welcome, {}! You are connected with roles: {:?}",
            user.get_username(),
            user.get_roles()
        );
        let _ = session.text(welcome).await;

        // Handle incoming messages
        while let Some(Ok(msg)) = msg_stream.next().await {
            match msg {
                Message::Text(text) => {
                    log::info!("Received from {}: {}", user.get_username(), text);

                    // Echo back with user info
                    let response = format!("[{}] {}", user.get_username(), text);
                    if session.text(response).await.is_err() {
                        break;
                    }

                    // Example: Role-based message handling
                    if text.trim() == "admin-command" {
                        if user.has_role("ADMIN") {
                            let _ = session.text("Admin command executed!").await;
                        } else {
                            let _ = session.text("Error: Admin role required").await;
                        }
                    }
                }
                Message::Ping(bytes) => {
                    if session.pong(&bytes).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => {
                    log::info!("WebSocket closed for user: {}", user.get_username());
                    break;
                }
                _ => {}
            }
        }
    });

    Ok(response)
}

/// WebSocket endpoint using WebSocketSecurityConfig
///
/// This shows how to use the config object for validation.
#[get("/ws/config")]
async fn ws_config_handler(
    req: HttpRequest,
    stream: web::Payload,
    data: web::Data<Arc<AppState>>,
) -> Result<HttpResponse, actix_web::Error> {
    // First validate origin using config
    data.origin_validator.validate(&req)?;

    // Then validate JWT and create user
    let user = extract_user_from_jwt(&req, &data.jwt_authenticator)
        .map_err(actix_web::error::ErrorUnauthorized)?;

    // Store user in extensions for config validation
    req.extensions_mut().insert(user.clone());

    // Now use WebSocketSecurityConfig to validate (it will read user from extensions)
    let _upgrade = data.ws_config.validate_upgrade(&req)?;

    log::info!(
        "WebSocket (config) connection from user: {}",
        user.get_username()
    );

    let (response, mut session, mut msg_stream) = actix_ws::handle(&req, stream)?;

    actix_web::rt::spawn(async move {
        let _ = session
            .text(format!(
                "Welcome, {}! (using WebSocketSecurityConfig)",
                user.get_username()
            ))
            .await;

        while let Some(Ok(msg)) = msg_stream.next().await {
            match msg {
                Message::Text(text) => {
                    let response = format!("[{}] {}", user.get_username(), text);
                    if session.text(response).await.is_err() {
                        break;
                    }
                }
                Message::Ping(bytes) => {
                    if session.pong(&bytes).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    });

    Ok(response)
}

/// Public WebSocket endpoint (no auth required, origin check only)
#[get("/ws/public")]
async fn ws_public_handler(
    req: HttpRequest,
    stream: web::Payload,
    data: web::Data<Arc<AppState>>,
) -> Result<HttpResponse, actix_web::Error> {
    // Only validate origin (CSWSH prevention)
    data.origin_validator.validate(&req)?;

    // Check if user is authenticated (optional)
    let username = extract_user_from_jwt(&req, &data.jwt_authenticator)
        .map(|u| u.get_username().to_string())
        .unwrap_or_else(|_| "anonymous".to_string());

    log::info!("Public WebSocket connection from: {}", username);

    let (response, mut session, mut msg_stream) = actix_ws::handle(&req, stream)?;

    actix_web::rt::spawn(async move {
        let _ = session
            .text(format!("Welcome, {}! (public endpoint)", username))
            .await;

        while let Some(Ok(msg)) = msg_stream.next().await {
            match msg {
                Message::Text(text) => {
                    let response = format!("[{}] {}", username, text);
                    if session.text(response).await.is_err() {
                        break;
                    }
                }
                Message::Ping(bytes) => {
                    if session.pong(&bytes).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    });

    Ok(response)
}

/// Index page
#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "WebSocket Authentication Example",
        "endpoints": {
            "POST /login": "Get JWT token",
            "GET /ws": "Secure WebSocket (auth + origin)",
            "GET /ws/config": "WebSocketSecurityConfig example",
            "GET /ws/public": "Public WebSocket (origin check only)"
        },
        "usage": {
            "1": "Get token: POST /login with {username, password}",
            "2": "Connect: WebSocket to /ws with Authorization: Bearer <token>"
        }
    }))
}

/// Simple test page with JavaScript WebSocket client
#[get("/test")]
async fn test_page() -> impl Responder {
    HttpResponse::Ok().content_type("text/html").body(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>WebSocket Auth Test</title>
    <style>
        body { font-family: sans-serif; padding: 20px; max-width: 800px; margin: 0 auto; }
        #log { background: #f0f0f0; padding: 10px; height: 300px; overflow-y: scroll; font-family: monospace; }
        input, button { margin: 5px; padding: 8px; }
        button { cursor: pointer; background: #007bff; color: white; border: none; border-radius: 4px; }
        button:hover { background: #0056b3; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 4px; }
        h2 { margin-top: 0; }
    </style>
</head>
<body>
    <h1>WebSocket Authentication Test</h1>

    <div class="section">
        <h2>1. Get Token</h2>
        <input id="username" placeholder="username" value="admin">
        <input id="password" type="password" placeholder="password" value="admin">
        <button onclick="login()">Login</button>
        <div>Token: <code id="token">-</code></div>
    </div>

    <div class="section">
        <h2>2. Connect WebSocket</h2>
        <p><em>Note: Browsers don't support custom headers for WebSocket.</em></p>
        <p>Use the public endpoint or test with websocat:</p>
        <button onclick="connectPublic()">Connect to /ws/public</button>
        <button onclick="disconnect()">Disconnect</button>
    </div>

    <div class="section">
        <h2>3. Send Message</h2>
        <input id="message" placeholder="message" style="width: 300px;">
        <button onclick="send()">Send</button>
        <button onclick="sendAdminCmd()">Send Admin Command</button>
    </div>

    <div class="section">
        <h2>Log</h2>
        <div id="log"></div>
    </div>

    <div class="section">
        <h2>Test with websocat</h2>
        <pre>
# Install websocat
cargo install websocat

# Get token
TOKEN=$(curl -s -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' | jq -r '.token')

# Connect with auth
websocat "ws://localhost:8080/ws" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Origin: http://localhost:8080"
        </pre>
    </div>

    <script>
        let ws = null;
        let token = null;

        function log(msg) {
            const el = document.getElementById('log');
            const time = new Date().toLocaleTimeString();
            el.innerHTML += `[${time}] ${msg}<br>`;
            el.scrollTop = el.scrollHeight;
        }

        async function login() {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;

            try {
                const res = await fetch('/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                const data = await res.json();

                if (data.token) {
                    token = data.token;
                    document.getElementById('token').innerText = token.substring(0, 30) + '...';
                    log('Login successful!');
                } else {
                    log('Login failed: ' + JSON.stringify(data));
                }
            } catch (e) {
                log('Login error: ' + e);
            }
        }

        function connectPublic() {
            if (ws) ws.close();
            log('Connecting to /ws/public...');
            ws = new WebSocket('ws://localhost:8080/ws/public');
            setupWs();
        }

        function setupWs() {
            ws.onopen = () => log('Connected!');
            ws.onmessage = (e) => log('Received: ' + e.data);
            ws.onclose = () => log('Disconnected');
            ws.onerror = (e) => log('Error occurred');
        }

        function disconnect() {
            if (ws) {
                ws.close();
                log('Disconnecting...');
            }
        }

        function send() {
            if (!ws || ws.readyState !== WebSocket.OPEN) {
                log('Not connected!');
                return;
            }
            const msg = document.getElementById('message').value;
            ws.send(msg);
            log('Sent: ' + msg);
        }

        function sendAdminCmd() {
            if (!ws || ws.readyState !== WebSocket.OPEN) {
                log('Not connected!');
                return;
            }
            ws.send('admin-command');
            log('Sent: admin-command');
        }
    </script>
</body>
</html>"#,
    )
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    let encoder = Argon2PasswordEncoder::new();

    // Create test users
    let users = vec![
        User::with_encoded_password("admin", encoder.encode("admin"))
            .roles(&["ADMIN".into(), "USER".into()])
            .authorities(&["ws:connect".into(), "ws:admin".into()]),
        User::with_encoded_password("user", encoder.encode("user"))
            .roles(&["USER".into()])
            .authorities(&["ws:connect".into()]),
    ];

    // JWT configuration
    let jwt_config = JwtConfig::new("my-super-secret-key-for-jwt-signing")
        .issuer("actix-security-example")
        .expiration_secs(3600);

    let jwt_service = JwtTokenService::new(jwt_config.clone());
    let jwt_authenticator = JwtAuthenticator::new(jwt_config);

    // Origin validator for CSWSH prevention
    let origin_validator = OriginValidator::builder()
        .allow("http://localhost:8080")
        .allow("http://127.0.0.1:8080")
        .allow_localhost_in_dev(true)
        .build();

    // WebSocket security configuration
    let ws_config = WebSocketSecurityConfig::new()
        .allowed_origins(vec![
            "http://localhost:8080".into(),
            "http://127.0.0.1:8080".into(),
        ])
        .require_authentication(true)
        .required_authorities(vec!["ws:connect".into()]);

    let state = Arc::new(AppState {
        users,
        encoder,
        jwt_service,
        jwt_authenticator,
        origin_validator,
        ws_config,
    });

    println!("=== WebSocket Authentication Example ===");
    println!("Server running at http://localhost:8080");
    println!();
    println!("Test users: admin:admin, user:user");
    println!();
    println!("Endpoints:");
    println!("  POST /login       - Get JWT token");
    println!("  GET  /ws          - Secure WebSocket (auth + origin)");
    println!("  GET  /ws/config   - WebSocketSecurityConfig example");
    println!("  GET  /ws/public   - Public WebSocket (origin only)");
    println!("  GET  /test        - Browser test page");
    println!();
    println!("Test with websocat:");
    println!("  TOKEN=$(curl -s -X POST http://localhost:8080/login \\");
    println!("    -H 'Content-Type: application/json' \\");
    println!("    -d '{{\"username\":\"admin\",\"password\":\"admin\"}}' | jq -r '.token')");
    println!();
    println!(
        "  websocat 'ws://localhost:8080/ws' -H \"Authorization: Bearer $TOKEN\" -H \"Origin: http://localhost:8080\""
    );
    println!();

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .service(index)
            .service(test_page)
            .service(login)
            .service(ws_handler)
            .service(ws_config_handler)
            .service(ws_public_handler)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
