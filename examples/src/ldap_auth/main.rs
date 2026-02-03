//! LDAP Authentication Example
//!
//! This example demonstrates how to configure LDAP authentication.
//! It uses a mock LDAP client for demonstration purposes.
//!
//! ## Running the example
//!
//! ```bash
//! cargo run -p actix-security-examples --bin ldap_auth
//! ```
//!
//! ## Testing with curl
//!
//! ```bash
//! # Test users (mock LDAP)
//! curl -u john.doe:password http://127.0.0.1:8080/
//! curl -u jane.smith:secret http://127.0.0.1:8080/
//! curl -u admin:admin123 http://127.0.0.1:8080/admin
//!
//! # Invalid credentials
//! curl -u invalid:wrong http://127.0.0.1:8080/
//! ```

use actix_security::http::security::middleware::SecurityTransform;
use actix_security::http::security::web::{Access, RequestMatcherAuthorizer};
use actix_security::http::security::{
    Authenticator, AuthorizationManager, LdapConfig, MockLdapClient, User,
};
use actix_web::dev::ServiceRequest;
use actix_web::{get, App, HttpResponse, HttpServer, Responder};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

/// Home page - requires authentication
#[get("/")]
async fn index(user: actix_security::http::security::AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "Welcome to LDAP Auth Example",
        "user": user.get_username(),
        "roles": user.get_roles(),
        "authorities": user.get_authorities()
    }))
}

/// Admin endpoint - requires ADMINS role
#[get("/admin")]
async fn admin(user: actix_security::http::security::AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "Admin Dashboard",
        "user": user.get_username(),
        "admin_access": true
    }))
}

/// User profile endpoint
#[get("/profile")]
async fn profile(user: actix_security::http::security::AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "username": user.get_username(),
        "roles": user.get_roles(),
        "authorities": user.get_authorities()
    }))
}

/// Health check endpoint - public
#[get("/health")]
async fn health() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy"
    }))
}

// =============================================================================
// Static state using OnceLock pattern
// =============================================================================

static MOCK_CLIENT: OnceLock<Arc<MockLdapClient>> = OnceLock::new();
static LDAP_CONFIG: OnceLock<Arc<LdapConfig>> = OnceLock::new();

fn get_mock_client() -> Arc<MockLdapClient> {
    MOCK_CLIENT
        .get_or_init(|| {
            let mock = MockLdapClient::new();

            // Add user: john.doe (regular user)
            let mut john_attrs = HashMap::new();
            john_attrs.insert("cn".to_string(), vec!["John Doe".to_string()]);
            john_attrs.insert("mail".to_string(), vec!["john.doe@example.com".to_string()]);
            mock.add_user(
                "john.doe",
                "password",
                john_attrs,
                vec!["cn=users,ou=groups,dc=example,dc=com".to_string()],
            );

            // Add user: jane.smith (manager)
            let mut jane_attrs = HashMap::new();
            jane_attrs.insert("cn".to_string(), vec!["Jane Smith".to_string()]);
            jane_attrs.insert(
                "mail".to_string(),
                vec!["jane.smith@example.com".to_string()],
            );
            mock.add_user(
                "jane.smith",
                "secret",
                jane_attrs,
                vec![
                    "cn=users,ou=groups,dc=example,dc=com".to_string(),
                    "cn=managers,ou=groups,dc=example,dc=com".to_string(),
                ],
            );

            // Add user: admin (administrator)
            let mut admin_attrs = HashMap::new();
            admin_attrs.insert("cn".to_string(), vec!["Administrator".to_string()]);
            admin_attrs.insert("mail".to_string(), vec!["admin@example.com".to_string()]);
            mock.add_user(
                "admin",
                "admin123",
                admin_attrs,
                vec![
                    "cn=users,ou=groups,dc=example,dc=com".to_string(),
                    "cn=admins,ou=groups,dc=example,dc=com".to_string(),
                ],
            );

            Arc::new(mock)
        })
        .clone()
}

fn get_ldap_config() -> Arc<LdapConfig> {
    LDAP_CONFIG
        .get_or_init(|| {
            Arc::new(
                LdapConfig::new("ldap://localhost:389")
                    .base_dn("dc=example,dc=com")
                    .user_search_base("ou=users")
                    .user_search_filter("(uid={0})")
                    .group_search_base("ou=groups")
                    .group_search_filter("(member={0})")
                    .role_prefix("ROLE_")
                    .convert_to_uppercase(true),
            )
        })
        .clone()
}

// =============================================================================
// Authenticator
// =============================================================================

/// Simple LDAP-based authenticator using mock client
#[derive(Clone)]
struct MockLdapAuthenticator;

impl Authenticator for MockLdapAuthenticator {
    fn get_user(&self, req: &ServiceRequest) -> Option<User> {
        // Extract HTTP Basic credentials
        let auth_header = req.headers().get("Authorization")?;
        let auth_str = auth_header.to_str().ok()?;

        if !auth_str.starts_with("Basic ") {
            return None;
        }

        let credentials = &auth_str[6..];
        let decoded = base64_decode(credentials)?;
        let decoded_str = String::from_utf8(decoded).ok()?;
        let parts: Vec<&str> = decoded_str.splitn(2, ':').collect();

        if parts.len() != 2 {
            return None;
        }

        let username = parts[0];
        let password = parts[1];

        // Get shared state
        let mock = get_mock_client();
        let config = get_ldap_config();

        // For this example, we use a simple blocking approach
        // In production, you'd want to use an async-aware authenticator
        use actix_security::http::security::ldap::LdapOperations;

        let username_str = username.to_string();
        let password_str = password.to_string();

        let result = std::thread::scope(|s| {
            s.spawn(|| {
                let rt = actix_rt::Runtime::new().unwrap();
                rt.block_on(async { mock.authenticate(&username_str, &password_str).await })
            })
            .join()
            .unwrap()
        });

        match result {
            Ok(auth_result) if auth_result.success => {
                // Build user from LDAP result
                let roles: Vec<String> = auth_result
                    .groups
                    .iter()
                    .filter_map(|group_dn: &String| {
                        group_dn
                            .split(',')
                            .next()
                            .and_then(|cn_part: &str| cn_part.strip_prefix("cn="))
                            .map(|cn: &str| {
                                let role = if config.convert_to_uppercase {
                                    cn.to_uppercase()
                                } else {
                                    cn.to_string()
                                };
                                format!("{}{}", config.role_prefix, role)
                            })
                    })
                    .collect();

                Some(User::new(username_str, String::new()).roles(&roles))
            }
            _ => None,
        }
    }
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    use base64::prelude::*;
    BASE64_STANDARD.decode(input).ok()
}

fn authenticator() -> MockLdapAuthenticator {
    MockLdapAuthenticator
}

fn authorizer() -> RequestMatcherAuthorizer {
    AuthorizationManager::request_matcher()
        .http_basic()
        .add_matcher("/admin.*", Access::new().roles(vec!["ROLE_ADMINS"]))
        .add_matcher("/profile.*", Access::new().roles(vec!["ROLE_USERS"]))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    // Initialize the static state
    let _ = get_mock_client();
    let _ = get_ldap_config();

    println!("=== LDAP Authentication Example ===");
    println!("Server running at http://127.0.0.1:8080");
    println!();
    println!("Using MOCK LDAP with test users:");
    println!("  john.doe:password   - Roles: [ROLE_USERS]");
    println!("  jane.smith:secret   - Roles: [ROLE_USERS, ROLE_MANAGERS]");
    println!("  admin:admin123      - Roles: [ROLE_USERS, ROLE_ADMINS]");
    println!();
    println!("Endpoints:");
    println!("  GET /          - Home (requires auth)");
    println!("  GET /admin     - Admin only (requires ROLE_ADMINS)");
    println!("  GET /profile   - User profile (requires ROLE_USERS)");
    println!("  GET /health    - Health check (public)");
    println!();
    println!("Try:");
    println!("  curl -u john.doe:password http://127.0.0.1:8080/");
    println!("  curl -u admin:admin123 http://127.0.0.1:8080/admin");
    println!();

    HttpServer::new(move || {
        App::new()
            .wrap(
                SecurityTransform::new()
                    .config_authenticator(authenticator)
                    .config_authorizer(authorizer),
            )
            .service(index)
            .service(admin)
            .service(profile)
            .service(health)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
