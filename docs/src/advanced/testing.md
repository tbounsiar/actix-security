# Testing

Best practices for testing secured Actix Web applications.

## Test Setup

### Create Test Helpers

```rust
// tests/common/mod.rs
use actix_security::http::security::{
    AuthenticationManager, AuthorizationManager, Argon2PasswordEncoder,
    PasswordEncoder, User, Access,
};
use actix_security::http::security::web::{MemoryAuthenticator, RequestMatcherAuthorizer};
use base64::prelude::*;

/// Create test authenticator with predefined users.
pub fn test_authenticator() -> MemoryAuthenticator {
    let encoder = Argon2PasswordEncoder::new();

    AuthenticationManager::in_memory_authentication()
        .password_encoder(encoder.clone())
        .with_user(
            User::with_encoded_password("admin", encoder.encode("admin"))
                .roles(&["ADMIN".into(), "USER".into()])
                .authorities(&["users:read".into(), "users:write".into()])
        )
        .with_user(
            User::with_encoded_password("user", encoder.encode("user"))
                .roles(&["USER".into()])
                .authorities(&["users:read".into()])
        )
        .with_user(
            User::with_encoded_password("guest", encoder.encode("guest"))
                .roles(&["GUEST".into()])
        )
}

/// Create test authorizer.
pub fn test_authorizer() -> RequestMatcherAuthorizer {
    AuthorizationManager::request_matcher()
        .login_url("/login")
        .http_basic()
        .add_matcher("/admin/.*", Access::new().roles(vec!["ADMIN"]))
        .add_matcher("/api/.*", Access::new().authenticated())
}

/// Create Basic Auth header value.
pub fn basic_auth(username: &str, password: &str) -> String {
    let credentials = format!("{}:{}", username, password);
    format!("Basic {}", BASE64_STANDARD.encode(credentials))
}
```

### Create Test App

```rust
use actix_web::{test, App};
use actix_security::http::security::middleware::SecurityTransform;

pub async fn create_test_app() -> impl actix_web::dev::Service<
    actix_http::Request,
    Response = actix_web::dev::ServiceResponse,
    Error = actix_web::Error,
> {
    test::init_service(
        App::new()
            .wrap(
                SecurityTransform::new()
                    .config_authenticator(test_authenticator)
                    .config_authorizer(test_authorizer)
            )
            .service(your_handlers)
    )
    .await
}
```

## Testing Authentication

### Test Successful Authentication

```rust
#[actix_web::test]
async fn test_authentication_success() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/api/resource")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}
```

### Test Invalid Credentials

```rust
#[actix_web::test]
async fn test_authentication_invalid_password() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/api/resource")
        .insert_header(("Authorization", basic_auth("user", "wrong_password")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
```

### Test Missing Authentication

```rust
#[actix_web::test]
async fn test_authentication_missing() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/api/resource")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
```

## Testing Authorization

### Test Role-Based Access

```rust
#[actix_web::test]
async fn test_admin_can_access_admin_endpoint() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/admin/dashboard")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_user_cannot_access_admin_endpoint() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/admin/dashboard")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
```

### Test Authority-Based Access

```rust
#[actix_web::test]
async fn test_user_with_authority_can_access() {
    let app = create_test_app().await;

    // admin has users:write authority
    let req = test::TestRequest::post()
        .uri("/api/users")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_user_without_authority_cannot_access() {
    let app = create_test_app().await;

    // user doesn't have users:write authority
    let req = test::TestRequest::post()
        .uri("/api/users")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
```

## Testing Method Security

### Test @secured Macro

```rust
#[actix_web::test]
async fn test_secured_endpoint_with_required_role() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/secured/admin")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_secured_endpoint_without_required_role() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/secured/admin")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
```

### Test @pre_authorize Expressions

```rust
#[actix_web::test]
async fn test_expression_with_and() {
    let app = create_test_app().await;

    // Endpoint: hasRole('USER') AND hasAuthority('users:read')
    // user has both
    let req = test::TestRequest::get()
        .uri("/expr/user-and-read")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_expression_with_or() {
    let app = create_test_app().await;

    // Endpoint: hasRole('ADMIN') OR hasAuthority('users:write')
    // admin has ADMIN role
    let req = test::TestRequest::get()
        .uri("/expr/admin-or-write")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}
```

## Testing Security Headers

```rust
#[actix_web::test]
async fn test_security_headers_present() {
    let app = test::init_service(
        App::new()
            .wrap(SecurityHeaders::default())
            .service(test_endpoint)
    ).await;

    let req = test::TestRequest::get().uri("/test").to_request();
    let resp = test::call_service(&app, req).await;

    let headers = resp.headers();

    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
}
```

## Testing Security Context

```rust
#[tokio::test]
async fn test_security_context() {
    let user = User::new("test".to_string(), "".to_string())
        .roles(&["USER".into()])
        .authorities(&["read".into()]);

    SecurityContext::run_with(Some(user), async {
        assert!(SecurityContext::is_authenticated());
        assert!(SecurityContext::has_role("USER"));
        assert!(SecurityContext::has_authority("read"));
        assert!(!SecurityContext::has_role("ADMIN"));

        let current = SecurityContext::get_user().unwrap();
        assert_eq!(current.username, "test");
    }).await;
}
```

## Integration Test Patterns

### Test Matrix

```rust
struct TestCase {
    name: &'static str,
    user: Option<(&'static str, &'static str)>,
    path: &'static str,
    expected_status: StatusCode,
}

#[actix_web::test]
async fn test_authorization_matrix() {
    let app = create_test_app().await;

    let test_cases = vec![
        TestCase {
            name: "admin can access admin endpoint",
            user: Some(("admin", "admin")),
            path: "/admin/dashboard",
            expected_status: StatusCode::OK,
        },
        TestCase {
            name: "user cannot access admin endpoint",
            user: Some(("user", "user")),
            path: "/admin/dashboard",
            expected_status: StatusCode::FORBIDDEN,
        },
        TestCase {
            name: "anonymous cannot access admin endpoint",
            user: None,
            path: "/admin/dashboard",
            expected_status: StatusCode::UNAUTHORIZED,
        },
    ];

    for tc in test_cases {
        let mut req = test::TestRequest::get().uri(tc.path);

        if let Some((username, password)) = tc.user {
            req = req.insert_header(("Authorization", basic_auth(username, password)));
        }

        let resp = test::call_service(&app, req.to_request()).await;
        assert_eq!(
            resp.status(),
            tc.expected_status,
            "Failed: {}",
            tc.name
        );
    }
}
```

## Best Practices

1. **Test all user types** - Admin, regular user, guest, anonymous
2. **Test edge cases** - Invalid credentials, missing headers, malformed tokens
3. **Test both positive and negative cases** - Access granted AND denied
4. **Use descriptive test names** - Clear what's being tested
5. **Keep test helpers DRY** - Share common setup code
6. **Test security headers** - Verify they're present and correct
7. **Test expressions** - Cover AND, OR, NOT combinations
