//! Common test utilities and configuration.
//!
//! This module provides shared test infrastructure including:
//! - Test user configuration
//! - Test app builder
//! - Helper functions

use actix_web::{get, post, test, web, App, HttpResponse, Responder};
use base64::prelude::*;

use actix_security_codegen::{deny_all, permit_all, pre_authorize, roles_allowed, secured};
use actix_security_core::http::security::manager::AuthorizationManager;
use actix_security_core::http::security::middleware::SecurityTransform;
use actix_security_core::http::security::web::{Access, MemoryAuthenticator, RequestMatcherAuthorizer};
use actix_security_core::http::security::{
    Argon2PasswordEncoder, AuthenticatedUser, AuthenticationManager, PasswordEncoder, User,
};

// =============================================================================
// Test Configuration
// =============================================================================

/// Creates a test authenticator with predefined users.
///
/// Users:
/// - admin/admin: ADMIN, USER roles + users:read, users:write authorities
/// - user/user: USER role + users:read authority
/// - guest/guest: GUEST role, no authorities
pub fn test_authenticator() -> MemoryAuthenticator {
    let encoder = Argon2PasswordEncoder::new();

    AuthenticationManager::in_memory_authentication()
        .password_encoder(encoder.clone())
        .with_user(
            User::with_encoded_password("admin", encoder.encode("admin"))
                .roles(&["ADMIN".into(), "USER".into()])
                .authorities(&["users:read".into(), "users:write".into()]),
        )
        .with_user(
            User::with_encoded_password("user", encoder.encode("user"))
                .roles(&["USER".into()])
                .authorities(&["users:read".into()]),
        )
        .with_user(
            User::with_encoded_password("guest", encoder.encode("guest"))
                .roles(&["GUEST".into()]),
        )
}

/// Creates a test authorizer with URL patterns.
///
/// Patterns:
/// - /admin/.* requires ADMIN role
/// - /user/.* requires ADMIN or USER role
/// - /api/.* requires users:read authority
pub fn test_authorizer() -> RequestMatcherAuthorizer {
    AuthorizationManager::request_matcher()
        .login_url("/login")
        .http_basic()
        .add_matcher("/admin/.*", Access::new().roles(vec!["ADMIN"]))
        .add_matcher("/user/.*", Access::new().roles(vec!["ADMIN", "USER"]))
        .add_matcher("/api/.*", Access::new().authorities(vec!["users:read"]))
}

/// Helper function to create Basic Auth header value.
pub fn basic_auth(username: &str, password: &str) -> String {
    let credentials = format!("{}:{}", username, password);
    format!("Basic {}", BASE64_STANDARD.encode(credentials))
}

// =============================================================================
// Test Handlers
// =============================================================================

#[get("/")]
pub async fn index(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Welcome, {}!", user.get_username()))
}

#[get("/login")]
pub async fn login() -> impl Responder {
    HttpResponse::Ok().body("Login page")
}

#[get("/admin/dashboard")]
pub async fn admin_dashboard(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Admin: {}", user.get_username()))
}

#[get("/user/settings")]
pub async fn user_settings(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("User: {}", user.get_username()))
}

#[get("/api/users")]
pub async fn api_users(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("API User: {}", user.get_username()))
}

#[secured("ADMIN")]
#[get("/secured/admin")]
pub async fn secured_admin(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Secured Admin: {}", user.get_username()))
}

#[secured("ADMIN", "MANAGER")]
#[get("/secured/management")]
pub async fn secured_management(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Secured Management: {}", user.get_username()))
}

#[pre_authorize(authority = "users:write")]
#[post("/preauth/write")]
pub async fn preauth_write(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Write by: {}", user.get_username()))
}

#[pre_authorize(authorities = ["users:read", "users:write"])]
#[get("/preauth/read-or-write")]
pub async fn preauth_read_or_write(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Read/Write by: {}", user.get_username()))
}

#[pre_authorize(role = "USER")]
#[get("/preauth/user-role")]
pub async fn preauth_user_role(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("User role: {}", user.get_username()))
}

#[pre_authorize(authenticated)]
#[get("/preauth/authenticated")]
pub async fn preauth_authenticated(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Authenticated: {}", user.get_username()))
}

// =============================================================================
// Expression-based Handlers (Spring Security SpEL-like)
// =============================================================================

/// hasRole('ADMIN') OR hasAuthority('users:write')
#[pre_authorize("hasRole('ADMIN') OR hasAuthority('users:write')")]
#[get("/expr/admin-or-write")]
pub async fn expr_admin_or_write(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Admin or Write: {}", user.get_username()))
}

/// hasRole('USER') AND hasAuthority('users:read')
#[pre_authorize("hasRole('USER') AND hasAuthority('users:read')")]
#[get("/expr/user-and-read")]
pub async fn expr_user_and_read(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("User and Read: {}", user.get_username()))
}

/// NOT hasRole('GUEST')
#[pre_authorize("NOT hasRole('GUEST')")]
#[get("/expr/not-guest")]
pub async fn expr_not_guest(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Not Guest: {}", user.get_username()))
}

/// (hasRole('ADMIN') OR hasRole('USER')) AND hasAuthority('users:read')
#[pre_authorize("(hasRole('ADMIN') OR hasRole('USER')) AND hasAuthority('users:read')")]
#[get("/expr/complex")]
pub async fn expr_complex(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Complex: {}", user.get_username()))
}

/// hasAnyRole('ADMIN', 'MANAGER')
#[pre_authorize("hasAnyRole('ADMIN', 'MANAGER')")]
#[get("/expr/any-role")]
pub async fn expr_any_role(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Any Role: {}", user.get_username()))
}

/// hasAnyAuthority('users:read', 'users:write')
#[pre_authorize("hasAnyAuthority('users:read', 'users:write')")]
#[get("/expr/any-authority")]
pub async fn expr_any_authority(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Any Authority: {}", user.get_username()))
}

/// isAuthenticated()
#[pre_authorize("isAuthenticated()")]
#[get("/expr/authenticated")]
pub async fn expr_authenticated(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Authenticated: {}", user.get_username()))
}

/// permitAll()
#[pre_authorize("permitAll()")]
#[get("/expr/permit-all")]
pub async fn expr_permit_all(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Permit All: {}", user.get_username()))
}

/// denyAll()
#[pre_authorize("denyAll()")]
#[get("/expr/deny-all")]
pub async fn expr_deny_all(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Deny All: {}", user.get_username()))
}

// =============================================================================
// Simple Macro Handlers (permit_all, deny_all, roles_allowed)
// =============================================================================

/// Public endpoint - no auth required
#[permit_all]
#[get("/public/info")]
pub async fn public_info() -> impl Responder {
    HttpResponse::Ok().body("Public information")
}

/// Disabled endpoint - always forbidden
#[deny_all]
#[get("/disabled")]
pub async fn disabled_endpoint(_user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Never reached")
}

/// roles_allowed - Java EE style
#[roles_allowed("ADMIN")]
#[get("/javaee/admin")]
pub async fn javaee_admin(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Java EE Admin: {}", user.get_username()))
}

/// roles_allowed with multiple roles
#[roles_allowed("ADMIN", "MANAGER")]
#[get("/javaee/management")]
pub async fn javaee_management(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Java EE Management: {}", user.get_username()))
}

// =============================================================================
// Test App Builder
// =============================================================================

/// Creates a fully configured test application.
pub async fn create_test_app(
) -> impl actix_web::dev::Service<actix_http::Request, Response = actix_web::dev::ServiceResponse, Error = actix_web::Error>
{
    test::init_service(
        App::new().service(
            web::scope("")
                .wrap(
                    SecurityTransform::new()
                        .config_authenticator(test_authenticator)
                        .config_authorizer(test_authorizer),
                )
                .service(index)
                .service(login)
                .service(admin_dashboard)
                .service(user_settings)
                .service(api_users)
                .service(secured_admin)
                .service(secured_management)
                .service(preauth_write)
                .service(preauth_read_or_write)
                .service(preauth_user_role)
                .service(preauth_authenticated)
                // Expression-based handlers
                .service(expr_admin_or_write)
                .service(expr_user_and_read)
                .service(expr_not_guest)
                .service(expr_complex)
                .service(expr_any_role)
                .service(expr_any_authority)
                .service(expr_authenticated)
                .service(expr_permit_all)
                .service(expr_deny_all)
                // Simple macro handlers
                .service(public_info)
                .service(disabled_endpoint)
                .service(javaee_admin)
                .service(javaee_management),
        ),
    )
    .await
}

