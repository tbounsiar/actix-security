# Introduction

**Actix Security** is a comprehensive authentication and authorization framework for [Actix Web](https://actix.rs/), inspired by [Spring Security](https://spring.io/projects/spring-security). It provides a familiar, declarative approach to securing your Rust web applications.

## Why Actix Security?

If you're coming from the Java/Spring ecosystem, you'll feel right at home. Actix Security brings Spring Security's powerful concepts to Rust:

- **Declarative Security** - Use attribute macros like `#[secured]`, `#[pre_authorize]`, and `#[roles_allowed]`
- **Expression Language** - Write security rules like `hasRole('ADMIN') OR hasAuthority('users:write')`
- **Pluggable Architecture** - Easily swap authentication and authorization implementations
- **Zero Runtime Overhead** - Security expressions are compiled at build time

## Features

### Authentication
- In-memory user store for development and testing
- HTTP Basic authentication
- Pluggable password encoders (Argon2, NoOp, Delegating)
- Custom authenticator support via traits

### Authorization
- URL pattern-based authorization (regex support)
- Method-level security with attribute macros
- Role-based access control (RBAC)
- Fine-grained authority/permission checks
- Spring Security Expression Language (SpEL-like)

### Security Macros
| Macro | Spring Equivalent | Description |
|-------|------------------|-------------|
| `#[secured("ADMIN")]` | `@Secured("ROLE_ADMIN")` | Role-based access |
| `#[pre_authorize(...)]` | `@PreAuthorize(...)` | Expression-based access |
| `#[permit_all]` | `@PermitAll` | Public access |
| `#[deny_all]` | `@DenyAll` | Deny all access |
| `#[roles_allowed("ADMIN")]` | `@RolesAllowed("ADMIN")` | Java EE style |

### Additional Features
- Security headers middleware (CSP, HSTS, X-Frame-Options, etc.)
- Security context for accessing the current user anywhere
- Extensible expression language

## Quick Example

```rust
use actix_web::{get, App, HttpServer, HttpResponse, Responder};
use actix_security::{secured, pre_authorize};
use actix_security::http::security::{
    AuthenticatedUser, AuthenticationManager, AuthorizationManager,
    Argon2PasswordEncoder, PasswordEncoder, User,
};
use actix_security::http::security::middleware::SecurityTransform;

// Role-based security
#[secured("ADMIN")]
#[get("/admin/dashboard")]
async fn admin_dashboard(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body(format!("Welcome, Admin {}!", user.get_username()))
}

// Expression-based security
#[pre_authorize("hasRole('USER') AND hasAuthority('posts:write')")]
#[get("/posts/new")]
async fn create_post(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().body("Create a new post")
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
                                User::with_encoded_password("admin", enc.encode("secret"))
                                    .roles(&["ADMIN".into(), "USER".into()])
                                    .authorities(&["posts:write".into()])
                            )
                    })
                    .config_authorizer(|| {
                        AuthorizationManager::request_matcher()
                            .login_url("/login")
                            .http_basic()
                    })
            )
            .service(admin_dashboard)
            .service(create_post)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

## Getting Help

- [GitHub Issues](https://github.com/your-org/actix-security/issues) - Bug reports and feature requests
- [API Documentation](https://docs.rs/actix-security) - Detailed API reference

## License

This project is licensed under the MIT License.
