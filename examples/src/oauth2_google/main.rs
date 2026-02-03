//! Google OAuth2 Authentication Example
//!
//! This example demonstrates OAuth2 authentication with Google.
//!
//! ## Prerequisites
//!
//! 1. Create a Google Cloud project at https://console.cloud.google.com
//! 2. Enable the Google+ API or Google Identity API
//! 3. Create OAuth2 credentials (Web application type)
//! 4. Add authorized redirect URI: http://localhost:8080/auth/callback
//!
//! ## Running the example
//!
//! ```bash
//! export GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
//! export GOOGLE_CLIENT_SECRET=your-client-secret
//!
//! cargo run -p actix-security-examples --bin oauth2_google
//! ```
//!
//! ## Testing
//!
//! Open http://localhost:8080 in your browser and click "Login with Google"

use actix_security::http::security::{OAuth2Config, OAuth2Provider};
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::Key, get, web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use std::env;
use std::sync::Arc;

/// Application configuration
#[derive(Clone)]
struct AppConfig {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
}

impl AppConfig {
    fn from_env() -> Self {
        Self {
            client_id: env::var("GOOGLE_CLIENT_ID")
                .unwrap_or_else(|_| "your-client-id.apps.googleusercontent.com".to_string()),
            client_secret: env::var("GOOGLE_CLIENT_SECRET")
                .unwrap_or_else(|_| "your-client-secret".to_string()),
            redirect_uri: env::var("REDIRECT_URI")
                .unwrap_or_else(|_| "http://localhost:8080/auth/callback".to_string()),
        }
    }

    fn is_configured(&self) -> bool {
        !self.client_id.contains("your-client-id")
    }
}

/// User information stored in session
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GoogleUser {
    id: String,
    email: String,
    name: Option<String>,
    picture: Option<String>,
    verified_email: bool,
}

/// Application state
struct AppState {
    config: AppConfig,
    #[allow(dead_code)] // Kept for reference - shows how to store OAuth2Config
    oauth2_config: OAuth2Config,
}

/// Home page
#[get("/")]
async fn index(session: Session, data: web::Data<Arc<AppState>>) -> impl Responder {
    let user: Option<GoogleUser> = session.get("google_user").ok().flatten();

    match user {
        Some(user) => {
            let picture_html = user.picture.as_ref().map(|p| {
                format!(r#"<img src="{}" alt="Profile" style="border-radius: 50%; width: 80px; height: 80px; margin-bottom: 15px;">"#, p)
            }).unwrap_or_default();

            let html = format!(
                r#"<!DOCTYPE html>
<html>
<head>
    <title>Home - Google OAuth2 Example</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }}
        .user-card {{ background: #f8f9fa; padding: 30px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .email {{ color: #5f6368; font-size: 14px; }}
        .verified {{ color: #34a853; }}
        .logout-btn {{
            display: inline-block; padding: 12px 24px; margin-top: 20px;
            background: #ea4335; color: white; text-decoration: none;
            border-radius: 4px; font-size: 14px;
        }}
        .logout-btn:hover {{ background: #d33426; }}
    </style>
</head>
<body>
    <div class="user-card">
        {}
        <h2>{}</h2>
        <p class="email">{} {}</p>
        <p>Google ID: {}</p>
        <a href="/logout" class="logout-btn">Logout</a>
    </div>
</body>
</html>"#,
                picture_html,
                user.name.as_deref().unwrap_or(&user.email),
                user.email,
                if user.verified_email {
                    r#"<span class="verified">✓ Verified</span>"#
                } else {
                    ""
                },
                user.id
            );
            HttpResponse::Ok().content_type("text/html").body(html)
        }
        None => {
            let configured = data.config.is_configured();
            let login_section = if configured {
                r##"<a href="/auth/login" class="google-btn">
                    <svg viewBox="0 0 24 24" width="24" height="24" style="margin-right: 10px;">
                        <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                        <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                        <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                        <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                    </svg>
                    Sign in with Google
                </a>"##
            } else {
                r#"<div class="warning">
                    <h3>⚠️ Not Configured</h3>
                    <p>Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables.</p>
                    <p>Get credentials from <a href="https://console.cloud.google.com/apis/credentials" target="_blank">Google Cloud Console</a></p>
                </div>"#
            };

            let html = format!(
                r#"<!DOCTYPE html>
<html>
<head>
    <title>Google OAuth2 Example</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }}
        .google-btn {{
            display: inline-flex; align-items: center; padding: 12px 24px;
            background: white; color: #757575; text-decoration: none;
            border: 1px solid #ddd; border-radius: 4px; font-size: 16px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .google-btn:hover {{ box-shadow: 0 2px 6px rgba(0,0,0,0.15); }}
        .info {{ color: #666; margin-top: 40px; text-align: left; background: #f8f9fa; padding: 20px; border-radius: 8px; }}
        .warning {{ background: #fff3cd; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        code {{ background: #e9ecef; padding: 2px 6px; border-radius: 3px; font-size: 14px; }}
    </style>
</head>
<body>
    <h1>Google OAuth2 Example</h1>
    <p>Demonstrates OAuth2 authentication with Google.</p>

    <div style="margin: 40px 0;">
        {}
    </div>

    <div class="info">
        <h3>How it works:</h3>
        <ol style="text-align: left;">
            <li>Click "Sign in with Google"</li>
            <li>Authenticate with your Google account</li>
            <li>Google redirects back with an authorization code</li>
            <li>Server exchanges code for access token</li>
            <li>Server fetches user info and creates session</li>
        </ol>

        <h3>Scopes requested:</h3>
        <ul>
            <li><code>openid</code> - OpenID Connect</li>
            <li><code>email</code> - User's email address</li>
            <li><code>profile</code> - User's name and picture</li>
        </ul>
    </div>
</body>
</html>"#,
                login_section
            );
            HttpResponse::Ok().content_type("text/html").body(html)
        }
    }
}

/// Start OAuth2 login flow
#[get("/auth/login")]
async fn login(session: Session, data: web::Data<Arc<AppState>>) -> impl Responder {
    if !data.config.is_configured() {
        return HttpResponse::BadRequest().body("Google OAuth2 not configured");
    }

    // Generate state for CSRF protection
    let state = generate_state();
    session.insert("oauth2_state", &state).ok();

    // Build Google authorization URL
    let auth_url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?\
        client_id={}&\
        redirect_uri={}&\
        response_type=code&\
        scope=openid%20email%20profile&\
        state={}&\
        access_type=offline&\
        prompt=consent",
        urlencoding::encode(&data.config.client_id),
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
    // Check for error
    if let Some(ref error) = query.error {
        return HttpResponse::BadRequest().body(format!("OAuth2 error: {}", error));
    }

    let code = match &query.code {
        Some(c) => c,
        None => return HttpResponse::BadRequest().body("Missing authorization code"),
    };

    // Verify state
    let stored_state: Option<String> = session.get("oauth2_state").ok().flatten();
    if stored_state.as_ref() != query.state.as_ref() {
        return HttpResponse::BadRequest().body("Invalid state parameter");
    }
    session.remove("oauth2_state");

    // Exchange code for tokens
    let client = reqwest::Client::new();
    let token_response = client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("client_id", data.config.client_id.as_str()),
            ("client_secret", data.config.client_secret.as_str()),
            ("code", code.as_str()),
            ("redirect_uri", data.config.redirect_uri.as_str()),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await;

    let tokens: TokenResponse = match token_response {
        Ok(resp) => {
            if !resp.status().is_success() {
                let error_text = resp.text().await.unwrap_or_default();
                return HttpResponse::InternalServerError()
                    .body(format!("Token exchange failed: {}", error_text));
            }
            match resp.json().await {
                Ok(t) => t,
                Err(e) => {
                    return HttpResponse::InternalServerError()
                        .body(format!("Token parse error: {}", e))
                }
            }
        }
        Err(e) => {
            return HttpResponse::InternalServerError().body(format!("Token exchange error: {}", e))
        }
    };

    // Get user info
    let userinfo_response = client
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
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

    // Store user in session
    let google_user = GoogleUser {
        id: userinfo.id,
        email: userinfo.email,
        name: userinfo.name,
        picture: userinfo.picture,
        verified_email: userinfo.verified_email.unwrap_or(false),
    };
    session.insert("google_user", &google_user).ok();

    // Redirect to home
    HttpResponse::Found()
        .append_header(("Location", "/"))
        .finish()
}

/// Logout
#[get("/logout")]
async fn logout(session: Session) -> impl Responder {
    session.purge();
    HttpResponse::Found()
        .append_header(("Location", "/"))
        .finish()
}

/// Callback query parameters
#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// Token response from Google
#[derive(Deserialize)]
#[allow(dead_code)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    token_type: String,
    expires_in: u64,
    #[serde(default)]
    scope: Option<String>,
}

/// UserInfo response from Google
#[derive(Deserialize)]
struct UserInfoResponse {
    id: String,
    email: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    picture: Option<String>,
    #[serde(default)]
    verified_email: Option<bool>,
}

/// Generate a random state string
fn generate_state() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:032x}", timestamp)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    let config = AppConfig::from_env();

    // Build OAuth2 config using actix-security
    let oauth2_config = OAuth2Config::new(
        &config.client_id,
        &config.client_secret,
        &config.redirect_uri,
    )
    .provider(OAuth2Provider::Google)
    .scopes(vec!["openid", "email", "profile"]);

    let state = Arc::new(AppState {
        config: config.clone(),
        oauth2_config,
    });

    let secret_key = Key::generate();

    println!("=== Google OAuth2 Example ===");
    println!("Server running at http://localhost:8080");
    println!();

    if config.is_configured() {
        println!("Google OAuth2 configured:");
        println!(
            "  Client ID: {}...",
            &config.client_id[..20.min(config.client_id.len())]
        );
        println!("  Redirect URI: {}", config.redirect_uri);
    } else {
        println!("⚠️  Google OAuth2 NOT configured!");
        println!();
        println!("To configure, set environment variables:");
        println!("  export GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com");
        println!("  export GOOGLE_CLIENT_SECRET=your-client-secret");
        println!();
        println!("Get credentials from: https://console.cloud.google.com/apis/credentials");
    }

    println!();
    println!("Open http://localhost:8080 in your browser.");
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
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
