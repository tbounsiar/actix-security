# HTTP Basic Authentication

HTTP Basic Authentication sends credentials in the `Authorization` header.

## How It Works

```
Authorization: Basic base64(username:password)
```

Example:
```
Authorization: Basic YWRtaW46YWRtaW4=  // admin:admin
```

## Enabling HTTP Basic

Configure your authorizer to use HTTP Basic:

```rust
use actix_security::http::security::AuthorizationManager;

let authorizer = AuthorizationManager::request_matcher()
    .http_basic()  // Enable HTTP Basic
    .login_url("/login");
```

## Full Example

```rust
use actix_web::{get, App, HttpServer, HttpResponse, Responder};
use actix_security::secured;
use actix_security::http::security::{
    AuthenticatedUser, AuthenticationManager, AuthorizationManager,
    Argon2PasswordEncoder, PasswordEncoder, User,
};
use actix_security::http::security::middleware::SecurityTransform;

#[secured("USER")]
#[get("/api/data")]
async fn get_data(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Data for {}", user.get_username()))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let encoder = Argon2PasswordEncoder::new();

    HttpServer::new(move || {
        let enc = encoder.clone();
        App::new()
            .wrap(
                SecurityTransform::new()
                    .config_authenticator(move || {
                        AuthenticationManager::in_memory_authentication()
                            .password_encoder(enc.clone())
                            .with_user(
                                User::with_encoded_password("api_user", enc.encode("api_secret"))
                                    .roles(&["USER".into()])
                            )
                    })
                    .config_authorizer(|| {
                        AuthorizationManager::request_matcher()
                            .http_basic()  // Enable HTTP Basic
                    })
            )
            .service(get_data)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

## Testing with cURL

```bash
# Using -u flag (automatic base64 encoding)
curl -u api_user:api_secret http://127.0.0.1:8080/api/data

# Manual header
curl -H "Authorization: Basic YXBpX3VzZXI6YXBpX3NlY3JldA==" http://127.0.0.1:8080/api/data
```

## Testing in Rust

```rust
use actix_web::test;
use base64::prelude::*;

fn basic_auth(username: &str, password: &str) -> String {
    let credentials = format!("{}:{}", username, password);
    format!("Basic {}", BASE64_STANDARD.encode(credentials))
}

#[actix_web::test]
async fn test_http_basic() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/api/data")
        .insert_header(("Authorization", basic_auth("api_user", "api_secret")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}
```

## 401 Response

When authentication fails, the server returns:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="Restricted"
```

## Security Considerations

### Use HTTPS

HTTP Basic sends credentials in **base64 encoding** (not encryption). Always use HTTPS in production.

```rust
// In production, bind to HTTPS
HttpServer::new(|| App::new())
    .bind_openssl("0.0.0.0:443", ssl_builder)?
    .run()
    .await
```

### Consider Token-Based Auth

For APIs, consider using:
- JWT tokens
- API keys
- OAuth2

HTTP Basic is simple but has limitations:
- Credentials sent with every request
- No built-in expiration
- Harder to revoke access

## Spring Security Comparison

**Spring Security:**
```java
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .httpBasic(Customizer.withDefaults())
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            );
        return http.build();
    }
}
```

**Actix Security:**
```rust
SecurityTransform::new()
    .config_authenticator(|| /* ... */)
    .config_authorizer(|| {
        AuthorizationManager::request_matcher()
            .http_basic()
    })
```

## Feature Flag

HTTP Basic authentication requires the `http-basic` feature flag:

```toml
[dependencies]
actix-security = { version = "0.2", features = ["http-basic"] }
```

This feature is enabled by default.
