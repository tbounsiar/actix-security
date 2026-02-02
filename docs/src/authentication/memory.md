# In-Memory Authentication

The `MemoryAuthenticator` stores users in memory. It's ideal for:
- Development and testing
- Small applications with static user lists
- Prototyping

> **Note**: For production applications with many users, implement a custom authenticator backed by a database.

## Basic Usage

```rust
use actix_security::http::security::{
    AuthenticationManager, Argon2PasswordEncoder, PasswordEncoder, User
};

let encoder = Argon2PasswordEncoder::new();

let authenticator = AuthenticationManager::in_memory_authentication()
    .password_encoder(encoder.clone())
    .with_user(
        User::with_encoded_password("admin", encoder.encode("admin"))
            .roles(&["ADMIN".into(), "USER".into()])
    )
    .with_user(
        User::with_encoded_password("user", encoder.encode("password"))
            .roles(&["USER".into()])
    );
```

## Creating Users

### With Roles Only

```rust
User::with_encoded_password("username", encoder.encode("password"))
    .roles(&["ROLE1".into(), "ROLE2".into()])
```

### With Authorities Only

```rust
User::with_encoded_password("username", encoder.encode("password"))
    .authorities(&["read".into(), "write".into()])
```

### With Both Roles and Authorities

```rust
User::with_encoded_password("admin", encoder.encode("admin"))
    .roles(&["ADMIN".into()])
    .authorities(&[
        "users:read".into(),
        "users:write".into(),
        "posts:read".into(),
        "posts:write".into(),
    ])
```

## Integration with SecurityTransform

```rust
use actix_security::http::security::middleware::SecurityTransform;

let encoder = Argon2PasswordEncoder::new();

App::new()
    .wrap(
        SecurityTransform::new()
            .config_authenticator(move || {
                let enc = encoder.clone();
                AuthenticationManager::in_memory_authentication()
                    .password_encoder(enc.clone())
                    .with_user(
                        User::with_encoded_password("admin", enc.encode("admin"))
                            .roles(&["ADMIN".into()])
                    )
            })
            .config_authorizer(|| {
                AuthorizationManager::request_matcher()
                    .http_basic()
            })
    )
```

## Spring Security Comparison

**Spring Security:**
```java
@Bean
public InMemoryUserDetailsManager userDetailsService() {
    UserDetails admin = User.withDefaultPasswordEncoder()
        .username("admin")
        .password("admin")
        .roles("ADMIN", "USER")
        .build();

    UserDetails user = User.withDefaultPasswordEncoder()
        .username("user")
        .password("password")
        .roles("USER")
        .build();

    return new InMemoryUserDetailsManager(admin, user);
}
```

**Actix Security:**
```rust
let encoder = Argon2PasswordEncoder::new();

AuthenticationManager::in_memory_authentication()
    .password_encoder(encoder.clone())
    .with_user(
        User::with_encoded_password("admin", encoder.encode("admin"))
            .roles(&["ADMIN".into(), "USER".into()])
    )
    .with_user(
        User::with_encoded_password("user", encoder.encode("password"))
            .roles(&["USER".into()])
    )
```

## Thread Safety

`MemoryAuthenticator` is thread-safe and can be shared across multiple worker threads. It implements `Clone + Send + Sync`.

## Limitations

- Users are stored in memory (lost on restart)
- Not suitable for large user bases
- No dynamic user management at runtime

For production use cases, consider implementing a [Custom Authenticator](./custom.md) backed by a database.
