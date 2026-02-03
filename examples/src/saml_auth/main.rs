//! SAML 2.0 Authentication Example
//!
//! This example demonstrates SAML 2.0 Single Sign-On (SSO) authentication.
//! It implements the Service Provider (SP) side of SAML authentication.
//!
//! ## Running the example
//!
//! ```bash
//! cargo run -p actix-security-examples --bin saml_auth
//! ```
//!
//! ## SAML Flow Overview
//!
//! 1. User accesses protected resource on SP
//! 2. SP generates AuthnRequest and redirects to IdP (Identity Provider)
//! 3. User authenticates at IdP
//! 4. IdP sends SAML Response back to SP's ACS (Assertion Consumer Service) URL
//! 5. SP validates response and creates session
//!
//! ## Testing with a SAML IdP
//!
//! For testing, you can use:
//! - Keycloak (supports SAML 2.0)
//! - SimpleSAMLphp
//! - Okta Developer
//! - Auth0
//!
//! ## Configuration
//!
//! Set these environment variables:
//! ```bash
//! export SAML_ENTITY_ID=https://myapp.example.com/saml/metadata
//! export SAML_IDP_SSO_URL=https://idp.example.com/saml/sso
//! export SAML_ACS_URL=http://localhost:8080/saml/acs
//! export SAML_IDP_CERTIFICATE=/path/to/idp-cert.pem
//! ```

use actix_security::http::security::{
    AuthnContextClass, NameIdFormat, SamlAuthenticator, SamlBinding, SamlConfig,
};
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::Key, get, post, web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use std::env;
use std::sync::Arc;

/// Application state
struct AppState {
    saml_config: SamlConfig,
    saml_authenticator: SamlAuthenticator,
}

/// User stored in session after SAML authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SamlUser {
    name_id: String,
    session_index: Option<String>,
    attributes: std::collections::HashMap<String, Vec<String>>,
}

/// Home page
#[get("/")]
async fn index(session: Session) -> impl Responder {
    let user: Option<SamlUser> = session.get("saml_user").ok().flatten();

    match user {
        Some(user) => {
            let attrs_html = user
                .attributes
                .iter()
                .map(|(k, v)| format!("<li><strong>{}:</strong> {}</li>", k, v.join(", ")))
                .collect::<Vec<_>>()
                .join("\n");

            let html = format!(
                r#"<!DOCTYPE html>
<html>
<head>
    <title>SAML Auth Example - Home</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }}
        .user-info {{ background: #e8f5e9; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .attributes {{ background: #f5f5f5; padding: 15px; border-radius: 4px; }}
        button {{ padding: 10px 20px; font-size: 16px; cursor: pointer; margin: 5px; }}
        .logout {{ background: #dc3545; color: white; border: none; border-radius: 4px; }}
    </style>
</head>
<body>
    <h1>SAML 2.0 Authentication Example</h1>
    <div class="user-info">
        <h2>Authenticated via SAML</h2>
        <p><strong>NameID:</strong> {}</p>
        <p><strong>Session Index:</strong> {}</p>
        <div class="attributes">
            <h3>Attributes:</h3>
            <ul>{}</ul>
        </div>
    </div>
    <form action="/saml/logout" method="post">
        <button type="submit" class="logout">SAML Logout</button>
    </form>
</body>
</html>"#,
                user.name_id,
                user.session_index.as_deref().unwrap_or("N/A"),
                attrs_html
            );
            HttpResponse::Ok().content_type("text/html").body(html)
        }
        None => {
            let html = r#"<!DOCTYPE html>
<html>
<head>
    <title>SAML Auth Example</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; text-align: center; }
        .login-btn {
            display: inline-block; padding: 15px 30px; font-size: 18px;
            background: #4CAF50; color: white; text-decoration: none;
            border-radius: 4px; margin-top: 20px;
        }
        .login-btn:hover { background: #45a049; }
        .info { color: #666; margin-top: 30px; text-align: left; }
        code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>SAML 2.0 Authentication Example</h1>
    <p>This example demonstrates SAML Single Sign-On.</p>
    <a href="/saml/login" class="login-btn">Login with SAML</a>

    <div class="info">
        <h3>SAML Endpoints:</h3>
        <ul>
            <li><code>GET /saml/metadata</code> - SP Metadata (XML)</li>
            <li><code>GET /saml/login</code> - Initiate SSO</li>
            <li><code>POST /saml/acs</code> - Assertion Consumer Service</li>
            <li><code>POST /saml/logout</code> - Single Logout</li>
        </ul>

        <h3>Configuration:</h3>
        <p>This example uses demo configuration. For real SAML, set environment variables:</p>
        <ul>
            <li><code>SAML_ENTITY_ID</code> - Your SP entity ID</li>
            <li><code>SAML_IDP_SSO_URL</code> - IdP SSO URL</li>
            <li><code>SAML_ACS_URL</code> - Your ACS URL</li>
        </ul>
    </div>
</body>
</html>"#;
            HttpResponse::Ok().content_type("text/html").body(html)
        }
    }
}

/// SP Metadata endpoint
#[get("/saml/metadata")]
async fn metadata(data: web::Data<Arc<AppState>>) -> impl Responder {
    let metadata_xml = data.saml_authenticator.generate_metadata();
    HttpResponse::Ok()
        .content_type("application/xml")
        .body(metadata_xml)
}

/// Initiate SAML SSO
#[get("/saml/login")]
async fn saml_login(session: Session, data: web::Data<Arc<AppState>>) -> impl Responder {
    // Generate AuthnRequest
    let authn_request = data.saml_authenticator.create_authn_request();

    // Store the request ID for validation (relay state)
    session.insert("saml_request_id", &authn_request.id).ok();

    // Get redirect URL with encoded AuthnRequest
    let redirect_url = authn_request.to_redirect_url(None);

    println!("SAML AuthnRequest generated:");
    println!("  ID: {}", authn_request.id);
    println!("  Redirecting to IdP...");

    // For demo purposes, show the request details if no real IdP
    if data.saml_config.idp_sso_url.contains("example.com") {
        let html = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>SAML AuthnRequest</title>
    <style>
        body {{ font-family: monospace; max-width: 1000px; margin: 50px auto; padding: 20px; }}
        .request {{ background: #f5f5f5; padding: 20px; border-radius: 8px; word-wrap: break-word; }}
        .info {{ background: #fff3cd; padding: 15px; border-radius: 4px; margin: 20px 0; }}
        a {{ color: #007bff; }}
    </style>
</head>
<body>
    <h1>SAML AuthnRequest (Demo Mode)</h1>

    <div class="info">
        <strong>Note:</strong> No real IdP configured. In production, the user would be
        redirected to the IdP. For testing, you can simulate a SAML response.
    </div>

    <h2>AuthnRequest Details:</h2>
    <div class="request">
        <p><strong>ID:</strong> {}</p>
        <p><strong>Issuer:</strong> {}</p>
        <p><strong>ACS URL:</strong> {}</p>
        <p><strong>IdP SSO URL:</strong> {}</p>
        <p><strong>Binding:</strong> {:?}</p>
        <p><strong>NameID Format:</strong> {}</p>
    </div>

    <h2>Redirect URL:</h2>
    <div class="request">
        <a href="{}">{}</a>
    </div>

    <h2>Simulate Response:</h2>
    <p>Use the <a href="/saml/demo-response">Demo Response</a> endpoint to simulate a successful SAML response.</p>
</body>
</html>"#,
            authn_request.id,
            authn_request.issuer,
            authn_request.acs_url,
            data.saml_config.idp_sso_url,
            authn_request.protocol_binding,
            authn_request.name_id_format.as_urn(),
            redirect_url,
            redirect_url
        );
        return HttpResponse::Ok().content_type("text/html").body(html);
    }

    // Redirect to IdP
    HttpResponse::Found()
        .append_header(("Location", redirect_url))
        .finish()
}

/// Assertion Consumer Service (receives SAML Response from IdP)
#[post("/saml/acs")]
async fn acs(
    session: Session,
    data: web::Data<Arc<AppState>>,
    form: web::Form<AcsForm>,
) -> impl Responder {
    println!("SAML Response received at ACS");

    // Process and validate the SAML response
    match data
        .saml_authenticator
        .process_response(&form.saml_response)
    {
        Ok(auth_result) => {
            // Extract user information
            let saml_user = SamlUser {
                name_id: auth_result.name_id.clone(),
                session_index: auth_result.session_index.clone(),
                attributes: auth_result.attributes.clone(),
            };

            // Store in session
            session.insert("saml_user", &saml_user).ok();

            println!("SAML authentication successful for: {}", saml_user.name_id);

            // Redirect to home
            HttpResponse::Found()
                .append_header(("Location", "/"))
                .finish()
        }
        Err(e) => {
            println!("SAML validation error: {:?}", e);
            HttpResponse::BadRequest().body(format!("SAML validation failed: {:?}", e))
        }
    }
}

/// Demo endpoint to simulate SAML response
#[get("/saml/demo-response")]
async fn demo_response(session: Session) -> impl Responder {
    // Create a demo user
    let saml_user = SamlUser {
        name_id: "demo.user@example.com".to_string(),
        session_index: Some("_session_12345".to_string()),
        attributes: vec![
            ("firstName".to_string(), vec!["Demo".to_string()]),
            ("lastName".to_string(), vec!["User".to_string()]),
            (
                "email".to_string(),
                vec!["demo.user@example.com".to_string()],
            ),
            (
                "groups".to_string(),
                vec!["users".to_string(), "developers".to_string()],
            ),
        ]
        .into_iter()
        .collect(),
    };

    session.insert("saml_user", &saml_user).ok();

    HttpResponse::Found()
        .append_header(("Location", "/"))
        .finish()
}

/// SAML Logout
#[post("/saml/logout")]
async fn saml_logout(session: Session, data: web::Data<Arc<AppState>>) -> impl Responder {
    let user: Option<SamlUser> = session.get("saml_user").ok().flatten();

    session.purge();

    // For SLO, we would send LogoutRequest to IdP
    if let Some(user) = user {
        println!("SAML logout for user: {}", user.name_id);

        // If IdP supports SLO, redirect there
        if data.saml_config.idp_slo_url.is_some() {
            // In real implementation, create LogoutRequest and redirect
            // For demo, just redirect to home
        }
    }

    HttpResponse::Found()
        .append_header(("Location", "/"))
        .finish()
}

/// ACS form data
#[derive(Deserialize)]
struct AcsForm {
    #[serde(rename = "SAMLResponse")]
    saml_response: String,
    #[serde(rename = "RelayState", default)]
    #[allow(dead_code)]
    relay_state: Option<String>,
}

fn create_saml_config() -> SamlConfig {
    // Load from environment or use defaults
    let entity_id = env::var("SAML_ENTITY_ID")
        .unwrap_or_else(|_| "http://localhost:8080/saml/metadata".to_string());
    let idp_sso_url = env::var("SAML_IDP_SSO_URL")
        .unwrap_or_else(|_| "https://idp.example.com/saml/sso".to_string());
    let acs_url =
        env::var("SAML_ACS_URL").unwrap_or_else(|_| "http://localhost:8080/saml/acs".to_string());

    SamlConfig::new()
        .entity_id(&entity_id)
        .idp_sso_url(&idp_sso_url)
        .assertion_consumer_service_url(&acs_url)
        .name_id_format(NameIdFormat::EmailAddress)
        .authn_context_class(AuthnContextClass::PasswordProtectedTransport)
        .sso_binding(SamlBinding::HttpRedirect)
        .sign_authn_request(false) // Set to true in production with proper certificates
        .want_assertions_signed(true)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    let saml_config = create_saml_config();
    let saml_authenticator =
        SamlAuthenticator::new(saml_config.clone()).expect("Failed to create SAML authenticator");

    let state = Arc::new(AppState {
        saml_config: saml_config.clone(),
        saml_authenticator,
    });

    let secret_key = Key::generate();

    println!("=== SAML 2.0 Authentication Example ===");
    println!("Server running at http://127.0.0.1:8080");
    println!();
    println!("SAML Configuration:");
    println!("  Entity ID (SP): {}", saml_config.entity_id);
    println!("  IdP SSO URL: {}", saml_config.idp_sso_url);
    println!("  ACS URL: {}", saml_config.acs_url);
    println!();
    println!("Endpoints:");
    println!("  GET  /                  - Home page");
    println!("  GET  /saml/metadata     - SP Metadata (XML)");
    println!("  GET  /saml/login        - Initiate SAML SSO");
    println!("  POST /saml/acs          - Assertion Consumer Service");
    println!("  POST /saml/logout       - Logout");
    println!("  GET  /saml/demo-response - Simulate SAML response (for testing)");
    println!();
    println!("For testing without a real IdP, visit:");
    println!("  http://127.0.0.1:8080/saml/demo-response");
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
            .service(metadata)
            .service(saml_login)
            .service(acs)
            .service(demo_response)
            .service(saml_logout)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
