# Extending the Framework

Actix Security is designed to be extensible. This guide covers the main extension points.

## Extension Points Overview

| Extension Point | Purpose | Trait/Type |
|-----------------|---------|------------|
| Authentication | Custom user extraction | `Authenticator` |
| Authorization | Custom access control | `Authorizer` |
| Password Encoding | Custom hashing | `PasswordEncoder` |
| Expressions | Custom functions | `ExpressionRoot` |

## Custom Authenticator

Extract users from custom sources (database, JWT, OAuth, etc.).

### Implement the Trait

```rust
use actix_security::http::security::config::Authenticator;
use actix_security::http::security::User;
use actix_web::dev::ServiceRequest;

#[derive(Clone)]
pub struct DatabaseAuthenticator {
    pool: PgPool,
    encoder: Argon2PasswordEncoder,
}

impl Authenticator for DatabaseAuthenticator {
    fn authenticate(&self, req: &ServiceRequest) -> Option<User> {
        // 1. Extract credentials
        let auth_header = req.headers().get("Authorization")?;
        let (username, password) = self.parse_basic_auth(auth_header)?;

        // 2. Query database (use block_on for sync context)
        let user_record = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(
                self.pool.query_one("SELECT * FROM users WHERE username = $1", &[&username])
            )
        }).ok()?;

        // 3. Verify password
        if !self.encoder.matches(&password, &user_record.password_hash) {
            return None;
        }

        // 4. Build and return User
        Some(User {
            username: user_record.username,
            password: user_record.password_hash,
            roles: user_record.roles.into_iter().collect(),
            authorities: user_record.authorities.into_iter().collect(),
        })
    }
}
```

### Register with SecurityTransform

```rust
let db_authenticator = DatabaseAuthenticator::new(pool, encoder);

App::new()
    .wrap(
        SecurityTransform::new()
            .config_authenticator(move || db_authenticator.clone())
            .config_authorizer(|| /* ... */)
    )
```

## Custom Authorizer

Implement custom authorization logic.

### Implement the Trait

```rust
use actix_security::http::security::config::{Authorizer, AuthorizationResult};
use actix_security::http::security::User;
use actix_web::dev::ServiceRequest;

#[derive(Clone)]
pub struct AbacAuthorizer {
    policy_engine: PolicyEngine,
}

impl Authorizer for AbacAuthorizer {
    fn authorize(&self, user: Option<&User>, req: &ServiceRequest) -> AuthorizationResult {
        // Build policy context
        let context = PolicyContext {
            subject: user.map(|u| Subject {
                id: u.username.clone(),
                roles: u.roles.clone(),
                attributes: self.get_user_attributes(user),
            }),
            resource: Resource {
                path: req.path().to_string(),
                method: req.method().to_string(),
            },
            environment: Environment {
                time: chrono::Utc::now(),
                ip: req.peer_addr().map(|a| a.ip()),
            },
        };

        // Evaluate policy
        match self.policy_engine.evaluate(&context) {
            PolicyDecision::Allow => AuthorizationResult::Granted,
            PolicyDecision::Deny => AuthorizationResult::Denied,
            PolicyDecision::NotApplicable => {
                if user.is_some() {
                    AuthorizationResult::Denied
                } else {
                    AuthorizationResult::LoginRequired
                }
            }
        }
    }
}
```

## Custom Password Encoder

Implement custom password hashing.

### Implement the Trait

```rust
use actix_security::http::security::PasswordEncoder;

#[derive(Clone)]
pub struct BcryptEncoder {
    cost: u32,
}

impl PasswordEncoder for BcryptEncoder {
    fn encode(&self, raw_password: &str) -> String {
        bcrypt::hash(raw_password, self.cost).unwrap()
    }

    fn matches(&self, raw_password: &str, encoded_password: &str) -> bool {
        bcrypt::verify(raw_password, encoded_password).unwrap_or(false)
    }
}
```

### Use with DelegatingPasswordEncoder

```rust
let encoder = DelegatingPasswordEncoder::new()
    .with_encoder("bcrypt", Box::new(BcryptEncoder::new(12)))
    .with_encoder("argon2", Box::new(Argon2PasswordEncoder::new()))
    .default_encoder("argon2");
```

## Custom Expression Functions

Add domain-specific expression functions.

### Implement ExpressionRoot

```rust
use actix_security::http::security::expression::ExpressionRoot;
use actix_security::http::security::User;

#[derive(Clone)]
pub struct TenantExpressionRoot {
    tenant_service: TenantService,
}

impl ExpressionRoot for TenantExpressionRoot {
    fn evaluate_function(
        &self,
        name: &str,
        args: &[String],
        user: Option<&User>,
    ) -> Option<bool> {
        match name {
            "belongsToTenant" => {
                let tenant_id = args.get(0)?;
                let user = user?;
                Some(self.tenant_service.user_belongs_to(&user.username, tenant_id))
            }
            "isTenantAdmin" => {
                let tenant_id = args.get(0)?;
                let user = user?;
                Some(self.tenant_service.is_admin(&user.username, tenant_id))
            }
            "hasTenantPermission" => {
                let tenant_id = args.get(0)?;
                let permission = args.get(1)?;
                let user = user?;
                Some(self.tenant_service.has_permission(
                    &user.username, tenant_id, permission
                ))
            }
            _ => None, // Let default handle unknown functions
        }
    }
}
```

### Use in Expressions

```rust
#[pre_authorize("belongsToTenant('acme')")]
async fn tenant_resource() {}

#[pre_authorize("isTenantAdmin('acme') OR hasRole('SUPER_ADMIN')")]
async fn tenant_admin() {}

#[pre_authorize("hasTenantPermission('acme', 'billing:manage')")]
async fn billing() {}
```

## Combining Extensions

```rust
// Custom components
let db_authenticator = DatabaseAuthenticator::new(pool.clone(), encoder.clone());
let abac_authorizer = AbacAuthorizer::new(policy_engine);
let tenant_root = TenantExpressionRoot::new(tenant_service);

// Create app
App::new()
    .wrap(SecurityHeaders::strict())
    .wrap(
        SecurityTransform::new()
            .config_authenticator(move || db_authenticator.clone())
            .config_authorizer(move || abac_authorizer.clone())
    )
    .app_data(web::Data::new(tenant_root))
    .service(/* ... */)
```

## Best Practices

### 1. Clone Efficiently

All extension traits require `Clone`. Use `Arc` for shared state:

```rust
#[derive(Clone)]
pub struct MyAuthenticator {
    pool: Arc<PgPool>,  // Shared connection pool
    cache: Arc<RwLock<Cache>>,  // Shared cache
}
```

### 2. Handle Errors Gracefully

Return `None` or default values on error:

```rust
fn authenticate(&self, req: &ServiceRequest) -> Option<User> {
    // Return None on any error
    let header = req.headers().get("Authorization")?;
    let token = header.to_str().ok()?;
    self.validate_token(token).ok()
}
```

### 3. Log Security Events

```rust
fn authorize(&self, user: Option<&User>, req: &ServiceRequest) -> AuthorizationResult {
    let result = self.do_authorize(user, req);

    match &result {
        AuthorizationResult::Denied => {
            log::warn!(
                "Access denied: user={:?} path={} method={}",
                user.map(|u| &u.username),
                req.path(),
                req.method()
            );
        }
        AuthorizationResult::Granted => {
            log::debug!("Access granted: user={:?}", user.map(|u| &u.username));
        }
        _ => {}
    }

    result
}
```

### 4. Test Extensions

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_custom_authenticator() {
        let auth = TestAuthenticator::new();
        let req = test_request_with_header("Authorization", "Basic dGVzdDp0ZXN0");

        let user = auth.authenticate(&req);
        assert!(user.is_some());
        assert_eq!(user.unwrap().username, "test");
    }

    #[test]
    fn test_custom_expression() {
        let root = TenantExpressionRoot::new(mock_tenant_service());
        let user = test_user();

        let result = root.evaluate_function(
            "belongsToTenant",
            &["acme".to_string()],
            Some(&user),
        );

        assert_eq!(result, Some(true));
    }
}
```
