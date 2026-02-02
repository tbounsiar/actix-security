# Custom Authorizers

Create custom authorizers for complex authorization logic, external policy engines, or domain-specific rules.

## Implementing the Authorizer Trait

```rust
use actix_security::http::security::config::{Authorizer, AuthorizationResult};
use actix_security::http::security::User;
use actix_web::dev::ServiceRequest;

#[derive(Clone)]
pub struct CustomAuthorizer {
    // Your configuration
}

impl Authorizer for CustomAuthorizer {
    fn authorize(&self, user: Option<&User>, req: &ServiceRequest) -> AuthorizationResult {
        // Your authorization logic
        match user {
            Some(u) if self.check_access(u, req) => AuthorizationResult::Granted,
            Some(_) => AuthorizationResult::Denied,
            None => AuthorizationResult::LoginRequired,
        }
    }
}
```

## Authorization Results

Return one of three results:

```rust
pub enum AuthorizationResult {
    Granted,       // Allow access
    Denied,        // 403 Forbidden
    LoginRequired, // 401 Unauthorized or redirect to login
}
```

## Example: Time-Based Access

```rust
use chrono::{Local, Timelike};

#[derive(Clone)]
pub struct BusinessHoursAuthorizer {
    inner: RequestMatcherAuthorizer,
}

impl Authorizer for BusinessHoursAuthorizer {
    fn authorize(&self, user: Option<&User>, req: &ServiceRequest) -> AuthorizationResult {
        // First, check standard authorization
        let result = self.inner.authorize(user, req);
        if result != AuthorizationResult::Granted {
            return result;
        }

        // Then, check business hours for certain paths
        if req.path().starts_with("/business/") {
            let hour = Local::now().hour();
            if hour < 9 || hour >= 17 {
                log::warn!("Access denied outside business hours");
                return AuthorizationResult::Denied;
            }
        }

        AuthorizationResult::Granted
    }
}
```

## Example: IP-Based Access

```rust
use std::net::IpAddr;

#[derive(Clone)]
pub struct IpWhitelistAuthorizer {
    inner: RequestMatcherAuthorizer,
    admin_ips: Vec<IpAddr>,
}

impl Authorizer for IpWhitelistAuthorizer {
    fn authorize(&self, user: Option<&User>, req: &ServiceRequest) -> AuthorizationResult {
        // Check if admin path
        if req.path().starts_with("/admin/") {
            // Get client IP
            let client_ip = req.peer_addr()
                .map(|addr| addr.ip());

            // Check whitelist
            if let Some(ip) = client_ip {
                if !self.admin_ips.contains(&ip) {
                    log::warn!("Admin access denied from IP: {}", ip);
                    return AuthorizationResult::Denied;
                }
            } else {
                return AuthorizationResult::Denied;
            }
        }

        self.inner.authorize(user, req)
    }
}
```

## Example: Resource Owner Check

```rust
#[derive(Clone)]
pub struct ResourceOwnerAuthorizer {
    inner: RequestMatcherAuthorizer,
}

impl Authorizer for ResourceOwnerAuthorizer {
    fn authorize(&self, user: Option<&User>, req: &ServiceRequest) -> AuthorizationResult {
        // Check standard authorization first
        let result = self.inner.authorize(user, req);
        if result != AuthorizationResult::Granted {
            return result;
        }

        // For user-specific paths, check ownership
        // Path: /users/{user_id}/...
        if let Some(user) = user {
            if let Some(captures) = regex::Regex::new(r"/users/(\w+)/")
                .unwrap()
                .captures(req.path())
            {
                let path_user_id = &captures[1];

                // Allow if admin OR owner
                if !user.has_role("ADMIN") && user.username != path_user_id {
                    return AuthorizationResult::Denied;
                }
            }
        }

        AuthorizationResult::Granted
    }
}
```

## Example: External Policy Engine (OPA)

```rust
use reqwest::blocking::Client;

#[derive(Clone)]
pub struct OpaAuthorizer {
    opa_url: String,
    client: Client,
}

impl OpaAuthorizer {
    pub fn new(opa_url: &str) -> Self {
        Self {
            opa_url: opa_url.to_string(),
            client: Client::new(),
        }
    }
}

impl Authorizer for OpaAuthorizer {
    fn authorize(&self, user: Option<&User>, req: &ServiceRequest) -> AuthorizationResult {
        let input = serde_json::json!({
            "input": {
                "user": user.map(|u| &u.username),
                "roles": user.map(|u| &u.roles).unwrap_or(&HashSet::new()),
                "path": req.path(),
                "method": req.method().as_str(),
            }
        });

        match self.client
            .post(&format!("{}/v1/data/authz/allow", self.opa_url))
            .json(&input)
            .send()
        {
            Ok(resp) => {
                let result: serde_json::Value = resp.json().unwrap_or_default();
                if result["result"].as_bool().unwrap_or(false) {
                    AuthorizationResult::Granted
                } else if user.is_some() {
                    AuthorizationResult::Denied
                } else {
                    AuthorizationResult::LoginRequired
                }
            }
            Err(e) => {
                log::error!("OPA request failed: {}", e);
                AuthorizationResult::Denied // Fail closed
            }
        }
    }
}
```

## Composing Authorizers

```rust
#[derive(Clone)]
pub struct CompositeAuthorizer {
    authorizers: Vec<Box<dyn Authorizer>>,
}

impl Authorizer for CompositeAuthorizer {
    fn authorize(&self, user: Option<&User>, req: &ServiceRequest) -> AuthorizationResult {
        // All authorizers must grant access
        for authorizer in &self.authorizers {
            match authorizer.authorize(user, req) {
                AuthorizationResult::Granted => continue,
                result => return result,
            }
        }
        AuthorizationResult::Granted
    }
}

// Usage
let authorizer = CompositeAuthorizer {
    authorizers: vec![
        Box::new(RequestMatcherAuthorizer::new()),
        Box::new(IpWhitelistAuthorizer::new()),
        Box::new(BusinessHoursAuthorizer::new()),
    ],
};
```

## Using with SecurityTransform

```rust
let custom_authorizer = CustomAuthorizer::new();

App::new()
    .wrap(
        SecurityTransform::new()
            .config_authenticator(|| /* ... */)
            .config_authorizer(move || custom_authorizer.clone())
    )
```

## Best Practices

### 1. Fail Closed

When in doubt, deny access:

```rust
fn authorize(&self, user: Option<&User>, req: &ServiceRequest) -> AuthorizationResult {
    // If anything goes wrong, deny
    match self.do_authorize(user, req) {
        Ok(result) => result,
        Err(e) => {
            log::error!("Authorization error: {}", e);
            AuthorizationResult::Denied
        }
    }
}
```

### 2. Log Security Decisions

```rust
fn authorize(&self, user: Option<&User>, req: &ServiceRequest) -> AuthorizationResult {
    let result = self.check_access(user, req);

    match &result {
        AuthorizationResult::Denied => {
            log::warn!(
                "Access denied: user={:?}, path={}, method={}",
                user.map(|u| &u.username),
                req.path(),
                req.method()
            );
        }
        _ => {}
    }

    result
}
```

### 3. Keep It Simple

Complex authorization logic should live in your business layer, not the authorizer:

```rust
// Good - simple authorizer, complex logic elsewhere
fn authorize(&self, user: Option<&User>, req: &ServiceRequest) -> AuthorizationResult {
    if self.policy_service.is_allowed(user, req.path(), req.method()) {
        AuthorizationResult::Granted
    } else {
        AuthorizationResult::Denied
    }
}
```

### 4. Test Thoroughly

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_ip_whitelist() {
        let authorizer = IpWhitelistAuthorizer::new(vec!["10.0.0.1".parse().unwrap()]);

        // Test allowed IP
        // Test denied IP
        // Test missing IP
    }
}
```

## Spring Security Comparison

**Spring Security:**
```java
@Component
public class CustomAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {
    @Override
    public AuthorizationDecision check(
        Supplier<Authentication> authentication,
        RequestAuthorizationContext context
    ) {
        // Your logic
        return new AuthorizationDecision(allowed);
    }
}
```

**Actix Security:**
```rust
impl Authorizer for CustomAuthorizer {
    fn authorize(&self, user: Option<&User>, req: &ServiceRequest) -> AuthorizationResult {
        // Your logic
        if allowed {
            AuthorizationResult::Granted
        } else {
            AuthorizationResult::Denied
        }
    }
}
```
