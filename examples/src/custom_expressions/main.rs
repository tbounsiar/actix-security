//! Custom Expressions with Parameter References Example
//!
//! This example demonstrates Spring Security-style custom expressions
//! with parameter references (`#param` syntax) in `#[pre_authorize]`.
//!
//! # Run
//! ```bash
//! cargo run --bin custom_expressions
//! ```
//!
//! # Test
//! ```bash
//! # Tenant access - admin can access any tenant
//! curl -u admin:admin http://localhost:8080/tenants/123
//!
//! # Tenant access - user can only access their own tenant (1)
//! curl -u user:user http://localhost:8080/tenants/1       # OK
//! curl -u user:user http://localhost:8080/tenants/2       # 403 Forbidden
//!
//! # Resource access - admin can access any resource
//! curl -u admin:admin http://localhost:8080/resources/private-doc
//!
//! # Resource access - user can only access public resources
//! curl -u user:user http://localhost:8080/resources/public-doc   # OK
//! curl -u user:user http://localhost:8080/resources/private-doc  # 403 Forbidden
//!
//! # Combined expression - hasRole('ADMIN') OR is_tenant_admin(#tenant_id)
//! curl -u admin:admin http://localhost:8080/tenants/999/settings  # OK (admin role)
//! curl -u user:user http://localhost:8080/tenants/1/settings      # OK (tenant admin)
//! curl -u user:user http://localhost:8080/tenants/2/settings      # 403 Forbidden
//!
//! # Query parameter - search with min price filter
//! curl -u user:user "http://localhost:8080/products/search?min_price=50"   # OK
//! curl -u user:user "http://localhost:8080/products/search?min_price=500"  # 403 (premium only)
//!
//! # JSON body - create order with amount validation
//! curl -u user:user -X POST http://localhost:8080/orders \
//!      -H "Content-Type: application/json" \
//!      -d '{"amount": 100}'   # OK
//! curl -u user:user -X POST http://localhost:8080/orders \
//!      -H "Content-Type: application/json" \
//!      -d '{"amount": 5000}'  # 403 (requires ADMIN for > 1000)
//! ```

use actix_security::http::security::middleware::SecurityTransform;
use actix_security::http::security::web::{MemoryAuthenticator, RequestMatcherAuthorizer};
use actix_security::http::security::{
    Argon2PasswordEncoder, AuthenticatedUser, AuthenticationManager, AuthorizationManager,
    PasswordEncoder, User,
};
use actix_security::pre_authorize;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use serde::Deserialize;

// =============================================================================
// Custom Authorization Functions
// =============================================================================

/// Custom authorization function: checks if user is admin of a specific tenant.
///
/// This function demonstrates how to create custom authorization logic
/// that references handler parameters.
pub async fn is_tenant_admin(user: &User, tenant_id: i64) -> bool {
    // Admin user can access all tenants
    if user.has_role("ADMIN") {
        return true;
    }
    // User "user" is admin of tenant 1 only
    if user.get_username() == "user" && tenant_id == 1 {
        return true;
    }
    false
}

/// Custom authorization function: checks if user can access a specific resource.
///
/// Demonstrates string parameter handling.
pub async fn can_access_resource(user: &User, resource_id: String) -> bool {
    // Admin can access all resources
    if user.has_role("ADMIN") {
        return true;
    }
    // Regular users can only access public resources
    resource_id.starts_with("public-")
}

/// Custom authorization function: checks if user can perform premium search.
///
/// Demonstrates Query parameter validation. Accepts the full SearchQuery struct.
pub async fn can_search_premium(user: &User, query: SearchQuery) -> bool {
    // Admin and premium users can search with any price filter
    if user.has_role("ADMIN") || user.has_authority("premium:access") {
        return true;
    }
    // Regular users limited to min_price <= 100
    query.min_price <= 100
}

/// Custom authorization function: validates order amount based on user role.
///
/// Demonstrates Json body parameter validation. Accepts the full CreateOrderRequest struct.
pub async fn can_create_order(user: &User, order: CreateOrderRequest) -> bool {
    // Admin can create orders of any amount
    if user.has_role("ADMIN") {
        return true;
    }
    // Regular users limited to orders <= 1000
    order.amount <= 1000
}

// =============================================================================
// Query and Body DTOs
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
// Authentication/Authorization Configuration
// =============================================================================

/// Creates the authenticator with users stored in memory.
fn authenticator() -> MemoryAuthenticator {
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
            User::with_encoded_password("premium", encoder.encode("premium"))
                .roles(&["USER".into()])
                .authorities(&["users:read".into(), "premium:access".into()]),
        )
        .with_user(
            User::with_encoded_password("guest", encoder.encode("guest")).roles(&["GUEST".into()]),
        )
}

/// Creates the authorizer with HTTP Basic auth enabled.
fn authorizer() -> RequestMatcherAuthorizer {
    AuthorizationManager::request_matcher().http_basic()
}

// =============================================================================
// Handlers with Custom Expressions
// =============================================================================

/// Handler using custom function with Path parameter.
///
/// The `#tenant_id` references the `tenant_id` path parameter.
#[pre_authorize("is_tenant_admin(#tenant_id)")]
#[get("/tenants/{tenant_id}")]
pub async fn get_tenant(tenant_id: web::Path<i64>, user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "Tenant {} accessed by {}",
        tenant_id.into_inner(),
        user.get_username()
    ))
}

/// Handler combining custom function with built-in expression.
///
/// Access is granted if user hasRole('ADMIN') OR is_tenant_admin of the tenant.
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

/// Handler with string Path parameter.
#[pre_authorize("can_access_resource(#resource_id)")]
#[get("/resources/{resource_id}")]
pub async fn get_resource(
    resource_id: web::Path<String>,
    user: AuthenticatedUser,
) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "Resource '{}' accessed by {}",
        resource_id.into_inner(),
        user.get_username()
    ))
}

/// Handler with Query parameter validation.
///
/// The `#query` references the Query<SearchQuery> extractor parameter.
#[pre_authorize("can_search_premium(#query)")]
#[get("/products/search")]
pub async fn search_products(
    query: web::Query<SearchQuery>,
    user: AuthenticatedUser,
) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "query": {
            "min_price": query.min_price
        },
        "results": ["Product A", "Product B"],
        "searched_by": user.get_username()
    }))
}

/// Handler with Json body parameter validation.
///
/// The `#body` references the Json<CreateOrderRequest> extractor parameter.
#[pre_authorize("can_create_order(#body)")]
#[post("/orders")]
pub async fn create_order(
    body: web::Json<CreateOrderRequest>,
    user: AuthenticatedUser,
) -> impl Responder {
    HttpResponse::Created().json(serde_json::json!({
        "order_id": "ORD-12345",
        "amount": body.amount,
        "created_by": user.get_username()
    }))
}

/// Handler with multiple conditions on body fields.
#[pre_authorize("hasRole('ADMIN') OR can_create_order(#body)")]
#[post("/orders/bulk")]
pub async fn create_bulk_orders(
    body: web::Json<CreateOrderRequest>,
    user: AuthenticatedUser,
) -> impl Responder {
    HttpResponse::Created().json(serde_json::json!({
        "message": "Bulk order created",
        "amount": body.amount,
        "created_by": user.get_username()
    }))
}

// =============================================================================
// Main
// =============================================================================

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    println!("=== Custom Expressions with Parameter References Example ===");
    println!("Server running at http://localhost:8080");
    println!();
    println!("Test users:");
    println!("  admin:admin     - Roles: [ADMIN, USER]");
    println!("  user:user       - Roles: [USER], tenant admin for tenant 1");
    println!("  premium:premium - Roles: [USER], authority: premium:access");
    println!("  guest:guest     - Roles: [GUEST]");
    println!();
    println!("Endpoints:");
    println!("  GET  /tenants/{{tenant_id}}          - is_tenant_admin(#tenant_id)");
    println!(
        "  GET  /tenants/{{tenant_id}}/settings - hasRole('ADMIN') OR is_tenant_admin(#tenant_id)"
    );
    println!("  GET  /resources/{{resource_id}}      - can_access_resource(#resource_id)");
    println!("  GET  /products/search?min_price=N    - can_search_premium(#min_price)");
    println!("  POST /orders                         - can_create_order(#amount)");
    println!(
        "  POST /orders/bulk                    - hasRole('ADMIN') OR can_create_order(#amount)"
    );
    println!();
    println!("Try:");
    println!("  curl -u admin:admin http://localhost:8080/tenants/123");
    println!("  curl -u user:user http://localhost:8080/tenants/1");
    println!("  curl -u user:user http://localhost:8080/tenants/2  # 403");
    println!("  curl -u user:user http://localhost:8080/resources/public-doc");
    println!("  curl -u user:user http://localhost:8080/resources/private-doc  # 403");
    println!("  curl -u user:user 'http://localhost:8080/products/search?min_price=50'");
    println!("  curl -u premium:premium 'http://localhost:8080/products/search?min_price=500'");
    println!("  curl -u user:user -X POST http://localhost:8080/orders -H 'Content-Type: application/json' -d '{{\"amount\": 100}}'");
    println!();

    HttpServer::new(move || {
        App::new()
            .wrap(
                SecurityTransform::new()
                    .config_authenticator(authenticator)
                    .config_authorizer(authorizer),
            )
            .service(get_tenant)
            .service(get_tenant_settings)
            .service(get_resource)
            .service(search_products)
            .service(create_order)
            .service(create_bulk_orders)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
