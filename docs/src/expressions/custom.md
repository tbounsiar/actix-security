# Custom Expressions

Extend the security expression language with your own functions.

## Custom Functions with Parameter References (v0.2.2+)

The most powerful way to implement custom authorization is using async functions with parameter references. This approach allows you to reference handler parameters directly in your expressions, similar to Spring Security's SpEL:

### Defining Custom Authorization Functions

Create an async function that takes a user reference and any parameters you need:

```rust
use actix_security_core::http::security::User;

/// Check if user is admin of a specific tenant
pub async fn is_tenant_admin(user: &User, tenant_id: i64) -> bool {
    // Admin users can access all tenants
    if user.has_role("ADMIN") {
        return true;
    }
    // Check tenant-specific authority
    user.has_authority(&format!("tenant:{}:admin", tenant_id))
}

/// Check if user can access a specific resource
pub async fn can_access_resource(user: &User, resource_id: String) -> bool {
    // Your authorization logic here
    if user.has_role("ADMIN") {
        return true;
    }
    // Regular users can only access public resources
    resource_id.starts_with("public-")
}
```

### Using Parameter References

Use `#param_name` to reference handler parameters in your expressions:

```rust
use actix_web::{get, web::Path, HttpResponse, Responder};
use actix_security_codegen::pre_authorize;
use actix_security_core::http::security::AuthenticatedUser;

// Reference the tenant_id path parameter
#[pre_authorize("is_tenant_admin(#tenant_id)")]
#[get("/tenants/{tenant_id}")]
async fn get_tenant(
    tenant_id: Path<i64>,
    user: AuthenticatedUser,
) -> impl Responder {
    HttpResponse::Ok().body(format!("Tenant {}", tenant_id.into_inner()))
}

// Reference a string path parameter
#[pre_authorize("can_access_resource(#resource_id)")]
#[get("/resources/{resource_id}")]
async fn get_resource(
    resource_id: Path<String>,
    user: AuthenticatedUser,
) -> impl Responder {
    HttpResponse::Ok().body("Resource data")
}

// Combine with built-in functions
#[pre_authorize("hasRole('ADMIN') OR is_tenant_admin(#tenant_id)")]
#[get("/tenants/{tenant_id}/settings")]
async fn get_tenant_settings(
    tenant_id: Path<i64>,
    user: AuthenticatedUser,
) -> impl Responder {
    HttpResponse::Ok().body("Settings")
}
```

### Supported Extractor Types

Parameter references work with these Actix Web extractors:

| Extractor | Example | Description |
|-----------|---------|-------------|
| `Path<T>` | `tenant_id: Path<i64>` | URL path parameters |
| `Query<T>` | `params: Query<SearchParams>` | Query string parameters |
| `Json<T>` | `body: Json<CreateRequest>` | JSON request body |
| `Form<T>` | `form: Form<LoginForm>` | Form data |

**Important:** For `Query<T>`, `Json<T>`, and `Form<T>`, the parameter reference must be the extractor parameter name, not individual fields within the struct. Your custom function should accept the full struct type:

```rust
use serde::Deserialize;
use actix_web::{get, post, web};
use actix_security_codegen::pre_authorize;
use actix_security_core::http::security::{AuthenticatedUser, User};

// DTOs must implement Clone for parameter references
#[derive(Debug, Clone, Deserialize)]
pub struct SearchQuery {
    pub min_price: i32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateOrderRequest {
    pub amount: i64,
}

// Custom function accepts the full struct
pub async fn can_search_premium(user: &User, query: SearchQuery) -> bool {
    if user.has_role("ADMIN") {
        return true;
    }
    query.min_price <= 100
}

pub async fn can_create_order(user: &User, order: CreateOrderRequest) -> bool {
    if user.has_role("ADMIN") {
        return true;
    }
    order.amount <= 1000
}

// Reference the extractor parameter name (#query, not #min_price)
#[pre_authorize("can_search_premium(#query)")]
#[get("/products/search")]
async fn search_products(
    query: web::Query<SearchQuery>,
    user: AuthenticatedUser,
) -> impl actix_web::Responder {
    actix_web::HttpResponse::Ok().body("Search results")
}

// Reference the extractor parameter name (#body, not #amount)
#[pre_authorize("can_create_order(#body)")]
#[post("/orders")]
async fn create_order(
    body: web::Json<CreateOrderRequest>,
    user: AuthenticatedUser,
) -> impl actix_web::Responder {
    actix_web::HttpResponse::Created().body("Order created")
}
```

### Function Signature Requirements

Custom authorization functions must:

1. Be `async`
2. Return `bool`
3. Take `&User` as the first parameter
4. Be in scope where the handler is defined

```rust
// ✓ Valid function signature
pub async fn my_check(user: &User, param1: i64, param2: String) -> bool {
    // ...
    true
}

// ✗ Invalid - not async
pub fn my_check(user: &User, param: i64) -> bool { true }

// ✗ Invalid - wrong return type
pub async fn my_check(user: &User) -> Result<bool, Error> { Ok(true) }

// ✗ Invalid - no user parameter
pub async fn my_check(param: i64) -> bool { true }
```

### Spring Security Comparison

**Spring Security (Java):**
```java
@Service
public class TenantService {
    public boolean isTenantAdmin(Long tenantId) {
        // Uses SecurityContextHolder internally
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return checkTenantAdmin(auth, tenantId);
    }
}

@PreAuthorize("@tenantService.isTenantAdmin(#tenantId)")
@GetMapping("/tenants/{tenantId}")
public Tenant getTenant(@PathVariable Long tenantId) { }
```

**Actix Security (Rust):**
```rust
pub async fn is_tenant_admin(user: &User, tenant_id: i64) -> bool {
    user.has_authority(&format!("tenant:{}:admin", tenant_id))
}

#[pre_authorize("is_tenant_admin(#tenant_id)")]
#[get("/tenants/{tenant_id}")]
async fn get_tenant(tenant_id: Path<i64>, user: AuthenticatedUser) -> impl Responder { }
```

Key differences:
- In Rust, the user is passed explicitly (no thread-local storage)
- Function name is used directly (no `@` prefix or bean reference)
- Compile-time verification of parameter references

---

## The ExpressionRoot Trait

Custom expression functions are added by implementing `ExpressionRoot`:

```rust
use actix_security::http::security::expression::ExpressionRoot;
use actix_security::http::security::User;

pub trait ExpressionRoot: Send + Sync {
    /// Evaluate a custom function.
    ///
    /// Returns:
    /// - `Some(true)` - Function matched and returned true
    /// - `Some(false)` - Function matched and returned false
    /// - `None` - Function not recognized, try default implementation
    fn evaluate_function(
        &self,
        name: &str,
        args: &[String],
        user: Option<&User>,
    ) -> Option<bool>;
}
```

## Creating a Custom ExpressionRoot

```rust
use actix_security::http::security::expression::ExpressionRoot;
use actix_security::http::security::User;
use std::collections::HashSet;

#[derive(Clone)]
pub struct CustomExpressionRoot {
    premium_users: HashSet<String>,
    beta_features: HashSet<String>,
}

impl ExpressionRoot for CustomExpressionRoot {
    fn evaluate_function(
        &self,
        name: &str,
        args: &[String],
        user: Option<&User>,
    ) -> Option<bool> {
        match name {
            // isPremium() - check if user has premium subscription
            "isPremium" => {
                let username = user?.username.clone();
                Some(self.premium_users.contains(&username))
            }

            // hasBetaAccess('feature') - check beta feature access
            "hasBetaAccess" => {
                let feature = args.get(0)?;
                let user = user?;

                // Admins always have beta access
                if user.has_role("ADMIN") {
                    return Some(true);
                }

                // Check if feature is in beta and user has beta role
                Some(
                    self.beta_features.contains(feature)
                        && user.has_role("BETA_TESTER"),
                )
            }

            // isOwner('resource_id') - check resource ownership
            "isOwner" => {
                let resource_id = args.get(0)?;
                let user = user?;
                // Your ownership logic
                Some(self.check_ownership(&user.username, resource_id))
            }

            // Unknown function - return None to use default
            _ => None,
        }
    }
}

impl CustomExpressionRoot {
    fn check_ownership(&self, username: &str, resource_id: &str) -> bool {
        // Your database lookup logic
        true
    }
}
```

## Registering Custom Expressions

Register your custom `ExpressionRoot` with the security configuration:

```rust
use actix_security::http::security::expression::ExpressionEvaluator;

let custom_root = CustomExpressionRoot {
    premium_users: vec!["vip_user".to_string()].into_iter().collect(),
    beta_features: vec!["new_dashboard".to_string()].into_iter().collect(),
};

// Create evaluator with custom root
let evaluator = ExpressionEvaluator::with_root(Box::new(custom_root));
```

## Using Custom Functions

Once registered, use your custom functions in expressions:

```rust
// Check premium status
#[pre_authorize("isPremium()")]
#[get("/premium/content")]
async fn premium_content(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Premium content")
}

// Check beta access
#[pre_authorize("hasBetaAccess('new_dashboard')")]
#[get("/beta/dashboard")]
async fn beta_dashboard(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Beta dashboard")
}

// Combine with built-in functions
#[pre_authorize("hasRole('USER') AND isPremium()")]
#[get("/premium/profile")]
async fn premium_profile(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Premium profile")
}

// Complex custom expression
#[pre_authorize("hasRole('ADMIN') OR (hasRole('USER') AND hasBetaAccess('feature'))")]
#[get("/feature")]
async fn feature(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Feature")
}
```

## Spring Security Comparison

**Spring Security:**
```java
// Custom SecurityExpressionRoot
public class CustomSecurityExpressionRoot
    extends SecurityExpressionRoot
    implements MethodSecurityExpressionOperations {

    public boolean isPremium() {
        return premiumService.isPremium(getAuthentication().getName());
    }

    public boolean hasBetaAccess(String feature) {
        return betaService.hasAccess(getAuthentication(), feature);
    }
}

// Usage
@PreAuthorize("isPremium()")
public void premiumContent() {}

@PreAuthorize("hasBetaAccess('new_feature')")
public void betaFeature() {}
```

**Actix Security:**
```rust
// Custom ExpressionRoot
impl ExpressionRoot for CustomExpressionRoot {
    fn evaluate_function(&self, name: &str, args: &[String], user: Option<&User>) -> Option<bool> {
        match name {
            "isPremium" => Some(self.premium_service.is_premium(user?)),
            "hasBetaAccess" => Some(self.beta_service.has_access(user?, args.get(0)?)),
            _ => None,
        }
    }
}

// Usage
#[pre_authorize("isPremium()")]
async fn premium_content() {}

#[pre_authorize("hasBetaAccess('new_feature')")]
async fn beta_feature() {}
```

## Example: Organization-Based Access

```rust
#[derive(Clone)]
pub struct OrgExpressionRoot {
    org_service: OrgService,
}

impl ExpressionRoot for OrgExpressionRoot {
    fn evaluate_function(
        &self,
        name: &str,
        args: &[String],
        user: Option<&User>,
    ) -> Option<bool> {
        match name {
            // belongsToOrg('org_id') - user belongs to organization
            "belongsToOrg" => {
                let org_id = args.get(0)?;
                let user = user?;
                Some(self.org_service.user_belongs_to(&user.username, org_id))
            }

            // isOrgAdmin('org_id') - user is admin of organization
            "isOrgAdmin" => {
                let org_id = args.get(0)?;
                let user = user?;
                Some(self.org_service.is_org_admin(&user.username, org_id))
            }

            // hasOrgPermission('org_id', 'permission')
            "hasOrgPermission" => {
                let org_id = args.get(0)?;
                let permission = args.get(1)?;
                let user = user?;
                Some(self.org_service.has_permission(&user.username, org_id, permission))
            }

            _ => None,
        }
    }
}

// Usage
#[pre_authorize("belongsToOrg('acme-corp')")]
async fn org_dashboard() {}

#[pre_authorize("isOrgAdmin('acme-corp') OR hasRole('SUPER_ADMIN')")]
async fn org_settings() {}

#[pre_authorize("hasOrgPermission('acme-corp', 'billing:manage')")]
async fn billing() {}
```

## Best Practices

### 1. Return None for Unknown Functions

Allow fallback to default implementation:

```rust
fn evaluate_function(&self, name: &str, args: &[String], user: Option<&User>) -> Option<bool> {
    match name {
        "myFunction" => Some(/* ... */),
        _ => None,  // Important: let default handle unknown functions
    }
}
```

### 2. Handle Missing User

Return `false` or `None` when user is required but missing:

```rust
"isPremium" => {
    let user = user?;  // Returns None if no user
    Some(self.check_premium(&user.username))
}
```

### 3. Validate Arguments

Check for required arguments:

```rust
"hasFeature" => {
    let feature = args.get(0)?;  // Returns None if missing
    Some(self.check_feature(feature))
}
```

### 4. Keep Functions Simple

Complex logic should live in services:

```rust
// Good
"isPremium" => Some(self.premium_service.is_premium(user?))

// Bad - too much logic in expression root
"isPremium" => {
    let user = user?;
    let subscription = db.query_subscription(&user.id)?;
    Some(subscription.tier == "premium" && subscription.expires > now())
}
```

### 5. Document Your Functions

```rust
/// Custom expression functions for MyApp.
///
/// Available functions:
/// - `isPremium()` - Returns true if user has premium subscription
/// - `hasBetaAccess('feature')` - Returns true if user can access beta feature
/// - `isOrgMember('org_id')` - Returns true if user belongs to organization
impl ExpressionRoot for MyExpressionRoot { /* ... */ }
```
