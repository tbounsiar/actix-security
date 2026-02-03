//! Common test utilities and configuration.
//!
//! This module provides shared test infrastructure including:
//! - Test user configuration
//! - Test app builder
//! - Helper functions

use actix_web::{get, post, test, web, App, HttpResponse, Responder};
use base64::prelude::*;
use serde::Deserialize;

use actix_security::http::security::manager::AuthorizationManager;
use actix_security::http::security::middleware::SecurityTransform;
use actix_security::http::security::web::{Access, MemoryAuthenticator, RequestMatcherAuthorizer};
use actix_security::http::security::{
    Argon2PasswordEncoder, AuthenticatedUser, AuthenticationManager, PasswordEncoder, User,
};
use actix_security::{deny_all, permit_all, pre_authorize, roles_allowed, secured};

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
            User::with_encoded_password("guest", encoder.encode("guest")).roles(&["GUEST".into()]),
        )
        .with_user(
            User::with_encoded_password("premium", encoder.encode("premium"))
                .roles(&["USER".into()])
                .authorities(&["users:read".into(), "premium:access".into()]),
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
// Snake_case and Rust-style Operators Tests
// =============================================================================

/// has_role('ADMIN') - snake_case version
#[pre_authorize("has_role('ADMIN')")]
#[get("/expr/snake-role")]
pub async fn expr_snake_role(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Snake Role: {}", user.get_username()))
}

/// has_role('ADMIN') || has_authority('users:write') - using || operator
#[pre_authorize("has_role('ADMIN') || has_authority('users:write')")]
#[get("/expr/rust-or")]
pub async fn expr_rust_or(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Rust OR: {}", user.get_username()))
}

/// has_role('USER') && has_authority('users:read') - using && operator
#[pre_authorize("has_role('USER') && has_authority('users:read')")]
#[get("/expr/rust-and")]
pub async fn expr_rust_and(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Rust AND: {}", user.get_username()))
}

/// !has_role('GUEST') - using ! operator
#[pre_authorize("!has_role('GUEST')")]
#[get("/expr/rust-not")]
pub async fn expr_rust_not(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Rust NOT: {}", user.get_username()))
}

/// Mixed: has_any_role('ADMIN', 'USER') && is_authenticated()
#[pre_authorize("has_any_role('ADMIN', 'USER') && is_authenticated()")]
#[get("/expr/snake-mixed")]
pub async fn expr_snake_mixed(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Snake Mixed: {}", user.get_username()))
}

/// permit_all() - snake_case version
#[pre_authorize("permit_all()")]
#[get("/expr/snake-permit")]
pub async fn expr_snake_permit(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Snake Permit: {}", user.get_username()))
}

/// deny_all() - snake_case version
#[pre_authorize("deny_all()")]
#[get("/expr/snake-deny")]
pub async fn expr_snake_deny(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Snake Deny: {}", user.get_username()))
}

// =============================================================================
// Custom Expression Handlers (with parameter references)
// =============================================================================

/// Custom authorization function: checks if user is admin of a specific tenant
pub async fn is_tenant_admin(user: &User, tenant_id: i64) -> bool {
    // Admin user can access all tenants
    if user.has_role("ADMIN") {
        return true;
    }
    // User can only access their own tenant (tenant_id == 1 for user "user")
    if user.get_username() == "user" && tenant_id == 1 {
        return true;
    }
    false
}

/// Custom authorization function: checks if user can access a specific resource
pub async fn can_access_resource(user: &User, resource_id: String) -> bool {
    // Admin can access all resources
    if user.has_role("ADMIN") {
        return true;
    }
    // Regular users can only access public resources
    resource_id.starts_with("public-")
}

/// Handler using custom function with path parameter
#[pre_authorize("is_tenant_admin(#tenant_id)")]
#[get("/tenants/{tenant_id}")]
pub async fn get_tenant(tenant_id: web::Path<i64>, user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "Tenant {} accessed by {}",
        tenant_id.into_inner(),
        user.get_username()
    ))
}

/// Handler combining custom function with built-in
#[pre_authorize("hasRole('ADMIN') OR is_tenant_admin(#tenant_id)")]
#[get("/tenants/{tenant_id}/settings")]
pub async fn get_tenant_settings(
    tenant_id: web::Path<i64>,
    user: AuthenticatedUser,
) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "Tenant {} settings for {}",
        tenant_id.into_inner(),
        user.get_username()
    ))
}

/// Handler with string path parameter
#[pre_authorize("can_access_resource(#resource_id)")]
#[get("/resources/{resource_id}")]
pub async fn get_resource(
    resource_id: web::Path<String>,
    user: AuthenticatedUser,
) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "Resource {} accessed by {}",
        resource_id.into_inner(),
        user.get_username()
    ))
}

// =============================================================================
// Query and Json DTOs for Custom Expressions
// =============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct SearchQuery {
    pub min_price: i32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateOrderRequest {
    pub amount: i64,
}

// =============================================================================
// Custom Functions for Query and Json Parameters
// =============================================================================

/// Custom authorization function: checks if user can perform premium search.
/// Accepts the full SearchQuery struct.
pub async fn can_search_premium(user: &User, query: SearchQuery) -> bool {
    // Admin and premium users can search with any price filter
    if user.has_role("ADMIN") || user.has_authority("premium:access") {
        return true;
    }
    // Regular users limited to min_price <= 100
    query.min_price <= 100
}

/// Custom authorization function: validates order amount based on user role.
/// Accepts the full CreateOrderRequest struct.
pub async fn can_create_order(user: &User, order: CreateOrderRequest) -> bool {
    // Admin can create orders of any amount
    if user.has_role("ADMIN") {
        return true;
    }
    // Regular users limited to orders <= 1000
    order.amount <= 1000
}

// =============================================================================
// Custom Expression Handlers with Query Parameter
// =============================================================================

/// Handler with Query parameter validation.
/// References the `query` parameter which is a Query<SearchQuery>.
#[pre_authorize("can_search_premium(#query)")]
#[get("/products/search")]
pub async fn search_products(
    query: web::Query<SearchQuery>,
    user: AuthenticatedUser,
) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "Search with min_price={} by {}",
        query.min_price,
        user.get_username()
    ))
}

/// Handler combining custom function with built-in for Query.
#[pre_authorize("hasRole('ADMIN') OR can_search_premium(#query)")]
#[get("/products/premium-search")]
pub async fn premium_search_products(
    query: web::Query<SearchQuery>,
    user: AuthenticatedUser,
) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "Premium search with min_price={} by {}",
        query.min_price,
        user.get_username()
    ))
}

// =============================================================================
// Custom Expression Handlers with Json Body
// =============================================================================

/// Handler with Json body parameter validation.
/// References the `body` parameter which is a Json<CreateOrderRequest>.
#[pre_authorize("can_create_order(#body)")]
#[post("/orders")]
pub async fn create_order(
    body: web::Json<CreateOrderRequest>,
    user: AuthenticatedUser,
) -> impl Responder {
    HttpResponse::Created().body(format!(
        "Order created with amount={} by {}",
        body.amount,
        user.get_username()
    ))
}

/// Handler combining custom function with built-in for Json.
#[pre_authorize("hasRole('ADMIN') OR can_create_order(#body)")]
#[post("/orders/bulk")]
pub async fn create_bulk_orders(
    body: web::Json<CreateOrderRequest>,
    user: AuthenticatedUser,
) -> impl Responder {
    HttpResponse::Created().body(format!(
        "Bulk order created with amount={} by {}",
        body.amount,
        user.get_username()
    ))
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
pub async fn create_test_app() -> impl actix_web::dev::Service<
    actix_http::Request,
    Response = actix_web::dev::ServiceResponse,
    Error = actix_web::Error,
> {
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
                // Snake_case and Rust-style operators
                .service(expr_snake_role)
                .service(expr_rust_or)
                .service(expr_rust_and)
                .service(expr_rust_not)
                .service(expr_snake_mixed)
                .service(expr_snake_permit)
                .service(expr_snake_deny)
                // Custom expression handlers (with #param)
                .service(get_tenant)
                .service(get_tenant_settings)
                .service(get_resource)
                // Custom expression handlers with Query/Json
                .service(search_products)
                .service(premium_search_products)
                .service(create_order)
                .service(create_bulk_orders)
                // Simple macro handlers
                .service(public_info)
                .service(disabled_endpoint)
                .service(javaee_admin)
                .service(javaee_management),
        ),
    )
    .await
}
