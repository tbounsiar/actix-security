//! OIDC Authentication with Keycloak Example
//!
//! This example demonstrates OpenID Connect authentication with Keycloak.
//!
//! # Prerequisites
//!
//! 1. Run Keycloak with Docker:
//!    ```bash
//!    docker run -p 8180:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
//!      quay.io/keycloak/keycloak:latest start-dev
//!    ```
//!
//! 2. Configure Keycloak:
//!    - Create a realm: `actix-demo`
//!    - Create a client: `actix-app` (confidential, with client secret)
//!    - Set Valid Redirect URIs: `http://localhost:8080/*`
//!    - Create a user with password
//!
//! # Run
//! ```bash
//! # Set environment variables
//! export KEYCLOAK_URL=http://localhost:8180
//! export KEYCLOAK_REALM=actix-demo
//! export KEYCLOAK_CLIENT_ID=actix-app
//! export KEYCLOAK_CLIENT_SECRET=your-client-secret
//!
//! cargo run --bin oidc_keycloak
//! ```
//!
//! # Test
//! Open http://localhost:8080 in a browser.
//! Click "Login with Keycloak" to start the OIDC flow.

use actix_security::http::security::OAuth2Config;
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::Key, get, web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use std::env;
use std::sync::Arc;

/// Application configuration
#[derive(Clone)]
struct AppConfig {
    keycloak_url: String,
    realm: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
}

impl AppConfig {
    fn from_env() -> Self {
        Self {
            keycloak_url: env::var("KEYCLOAK_URL")
                .unwrap_or_else(|_| "http://localhost:8180".to_string()),
            realm: env::var("KEYCLOAK_REALM").unwrap_or_else(|_| "actix-demo".to_string()),
            client_id: env::var("KEYCLOAK_CLIENT_ID").unwrap_or_else(|_| "actix-app".to_string()),
            client_secret: env::var("KEYCLOAK_CLIENT_SECRET")
                .unwrap_or_else(|_| "change-me".to_string()),
            redirect_uri: env::var("REDIRECT_URI")
                .unwrap_or_else(|_| "http://localhost:8081/auth/callback".to_string()),
        }
    }

    fn issuer_url(&self) -> String {
        format!("{}/realms/{}", self.keycloak_url, self.realm)
    }

    fn authorization_endpoint(&self) -> String {
        format!(
            "{}/realms/{}/protocol/openid-connect/auth",
            self.keycloak_url, self.realm
        )
    }

    fn token_endpoint(&self) -> String {
        format!(
            "{}/realms/{}/protocol/openid-connect/token",
            self.keycloak_url, self.realm
        )
    }

    fn userinfo_endpoint(&self) -> String {
        format!(
            "{}/realms/{}/protocol/openid-connect/userinfo",
            self.keycloak_url, self.realm
        )
    }

    fn logout_endpoint(&self) -> String {
        format!(
            "{}/realms/{}/protocol/openid-connect/logout",
            self.keycloak_url, self.realm
        )
    }
}

/// Stored user information in session
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionUser {
    username: String,
    email: Option<String>,
    name: Option<String>,
    roles: Vec<String>,
}

/// Application state
struct AppState {
    config: AppConfig,
    #[allow(dead_code)] // Kept for reference/future use
    oauth2_config: OAuth2Config,
}

/// Home page
#[get("/")]
async fn index(session: Session) -> impl Responder {
    // Check if user is logged in
    let user: Option<SessionUser> = session.get("user").ok().flatten();

    match user {
        Some(user) => {
            let html = format!(
                r#"<!DOCTYPE html>
<html>
<head>
    <title>Home - OIDC Keycloak Example</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }}
        .user-info {{ background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .user-info h2 {{ margin-top: 0; }}
        button {{ padding: 10px 20px; font-size: 16px; cursor: pointer; }}
        .logout {{ background: #dc3545; color: white; border: none; }}
    </style>
</head>
<body>
    <h1>Welcome!</h1>
    <div class="user-info">
        <h2>{}</h2>
        <p><strong>Username:</strong> {}</p>
        <p><strong>Email:</strong> {}</p>
        <p><strong>Roles:</strong> {:?}</p>
    </div>
    <form action="/logout" method="get">
        <button type="submit" class="logout">Logout</button>
    </form>
</body>
</html>"#,
                user.name.as_deref().unwrap_or(&user.username),
                user.username,
                user.email.as_deref().unwrap_or("N/A"),
                user.roles
            );
            HttpResponse::Ok().content_type("text/html").body(html)
        }
        None => {
            let html = r#"<!DOCTYPE html>
<html>
<head>
    <title>OIDC Keycloak Example</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }
        .login-btn {
            display: inline-block; padding: 15px 30px; font-size: 18px;
            background: #007bff; color: white; text-decoration: none;
            border-radius: 4px; margin-top: 20px;
        }
        .login-btn:hover { background: #0056b3; }
        .info { color: #666; margin-top: 30px; }
    </style>
</head>
<body>
    <h1>OIDC Keycloak Example</h1>
    <p>This example demonstrates OpenID Connect authentication with Keycloak.</p>
    <a href="/auth/login" class="login-btn">Login with Keycloak</a>
    <div class="info">
        <p>Make sure Keycloak is running at the configured URL.</p>
        <p>See the example source code for setup instructions.</p>
    </div>
</body>
</html>"#;
            HttpResponse::Ok().content_type("text/html").body(html)
        }
    }
}

/// Start OAuth2/OIDC login flow
#[get("/auth/login")]
async fn login(session: Session, data: web::Data<Arc<AppState>>) -> impl Responder {
    // Generate state for CSRF protection
    let state = uuid_simple();
    session.insert("oauth2_state", &state).ok();

    // Build authorization URL
    let auth_url = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope=openid%20profile%20email&state={}",
        data.config.authorization_endpoint(),
        data.config.client_id,
        urlencoding::encode(&data.config.redirect_uri),
        state
    );

    HttpResponse::Found()
        .append_header(("Location", auth_url))
        .finish()
}

/// OAuth2 callback - exchange code for tokens
#[get("/auth/callback")]
async fn callback(
    session: Session,
    data: web::Data<Arc<AppState>>,
    query: web::Query<CallbackQuery>,
) -> impl Responder {
    // Verify state
    let stored_state: Option<String> = session.get("oauth2_state").ok().flatten();
    if stored_state.as_ref() != Some(&query.state) {
        return HttpResponse::BadRequest().body("Invalid state parameter");
    }
    session.remove("oauth2_state");

    // Exchange code for tokens
    let client = reqwest::Client::new();
    let token_response = client
        .post(data.config.token_endpoint())
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", &data.config.client_id),
            ("client_secret", &data.config.client_secret),
            ("code", &query.code),
            ("redirect_uri", &data.config.redirect_uri),
        ])
        .send()
        .await;

    let tokens: TokenResponse = match token_response {
        Ok(resp) => match resp.json().await {
            Ok(t) => t,
            Err(e) => {
                return HttpResponse::InternalServerError()
                    .body(format!("Token parse error: {}", e))
            }
        },
        Err(e) => {
            return HttpResponse::InternalServerError().body(format!("Token exchange error: {}", e))
        }
    };

    // Get user info
    let userinfo_response = client
        .get(data.config.userinfo_endpoint())
        .bearer_auth(&tokens.access_token)
        .send()
        .await;

    let userinfo: UserInfoResponse = match userinfo_response {
        Ok(resp) => match resp.json().await {
            Ok(u) => u,
            Err(e) => {
                return HttpResponse::InternalServerError()
                    .body(format!("Userinfo parse error: {}", e))
            }
        },
        Err(e) => {
            return HttpResponse::InternalServerError().body(format!("Userinfo error: {}", e))
        }
    };

    // Extract roles from Keycloak token (realm_access.roles or resource_access)
    let roles = extract_roles_from_token(&tokens.access_token);

    // Store user in session
    let session_user = SessionUser {
        username: userinfo
            .preferred_username
            .unwrap_or_else(|| userinfo.sub.clone()),
        email: userinfo.email,
        name: userinfo.name,
        roles,
    };
    session.insert("user", &session_user).ok();

    // Redirect to home
    HttpResponse::Found()
        .append_header(("Location", "/"))
        .finish()
}

/// Logout
#[get("/logout")]
async fn logout(session: Session, data: web::Data<Arc<AppState>>) -> impl Responder {
    session.purge();

    // Redirect to Keycloak logout
    let logout_url = format!(
        "{}?redirect_uri={}",
        data.config.logout_endpoint(),
        urlencoding::encode("http://localhost:8081/")
    );

    HttpResponse::Found()
        .append_header(("Location", logout_url))
        .finish()
}

/// OAuth2 callback query parameters
#[derive(Deserialize)]
struct CallbackQuery {
    code: String,
    state: String,
}

/// Token response from Keycloak
#[derive(Deserialize)]
#[allow(dead_code)] // Fields deserialized from API response
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    token_type: String,
    expires_in: u64,
}

/// UserInfo response from Keycloak
#[derive(Deserialize)]
#[allow(dead_code)] // Fields deserialized from API response
struct UserInfoResponse {
    sub: String,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<bool>,
}

/// Simple UUID generator (for state parameter)
fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:032x}", timestamp)
}

/// Extract roles from JWT access token (Keycloak format)
fn extract_roles_from_token(token: &str) -> Vec<String> {
    // Decode JWT payload (second part)
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return vec![];
    }

    // Decode base64url
    let payload = match base64_url_decode(parts[1]) {
        Some(p) => p,
        None => return vec![],
    };

    // Parse JSON
    let claims: serde_json::Value = match serde_json::from_slice(&payload) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    // Extract roles from realm_access.roles
    let mut roles = vec![];
    if let Some(realm_access) = claims.get("realm_access") {
        if let Some(realm_roles) = realm_access.get("roles").and_then(|r| r.as_array()) {
            for role in realm_roles {
                if let Some(r) = role.as_str() {
                    roles.push(r.to_string());
                }
            }
        }
    }

    roles
}

fn base64_url_decode(input: &str) -> Option<Vec<u8>> {
    use base64::prelude::*;

    // Add padding if needed
    let padded = match input.len() % 4 {
        2 => format!("{}==", input),
        3 => format!("{}=", input),
        _ => input.to_string(),
    };

    // Replace URL-safe characters
    let standard = padded.replace('-', "+").replace('_', "/");

    BASE64_STANDARD.decode(&standard).ok()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    let config = AppConfig::from_env();

    // Build OAuth2 config (for reference, we do manual flow here for clarity)
    let oauth2_config = OAuth2Config::new(
        &config.client_id,
        &config.client_secret,
        &config.redirect_uri,
    )
    .authorization_uri(config.authorization_endpoint())
    .token_uri(config.token_endpoint())
    .userinfo_uri(config.userinfo_endpoint())
    .scopes(vec!["openid", "profile", "email"]);

    let state = Arc::new(AppState {
        config: config.clone(),
        oauth2_config,
    });

    let secret_key = Key::generate();

    println!("=== OIDC Keycloak Example ===");
    println!("Server running at http://localhost:8081");
    println!();
    println!("Keycloak configuration:");
    println!("  URL: {}", config.keycloak_url);
    println!("  Realm: {}", config.realm);
    println!("  Client ID: {}", config.client_id);
    println!("  Issuer: {}", config.issuer_url());
    println!();
    println!("Make sure Keycloak is running and configured:");
    println!(
        "  docker run -p 8180:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \\"
    );
    println!("    quay.io/keycloak/keycloak:latest start-dev");
    println!();
    println!("Open http://localhost:8081 in your browser.");
    println!();

    HttpServer::new(move || {
        App::new()
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
                    .cookie_secure(false)
                    .build(),
            )
            .app_data(web::Data::new(state.clone()))
            .service(index)
            .service(login)
            .service(callback)
            .service(logout)
    })
    .bind("127.0.0.1:8081")?
    .run()
    .await
}
