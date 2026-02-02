# Session-Based Authentication Example

This example demonstrates session-based authentication using the actix-security library.

## Quick Start

Add these dependencies to your `Cargo.toml`:

```toml
[dependencies]
actix-web = "4"
actix-security = { version = "0.2", features = ["session", "argon2"] }
actix-session = { version = "0.10", features = ["cookie-session"] }
serde = { version = "1", features = ["derive"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Features

- Cookie-based session management
- Session fixation protection
- Remember-me functionality
- Session timeout configuration
- Secure session handling

## Running the Example

```bash
# From the project root
cargo run --bin session_auth

# Or from the examples directory
cargo run -p actix-security-examples --bin session_auth
```

The server will start at `http://localhost:8080`.

## Endpoints

| Endpoint | Method | Authorization | Description |
|----------|--------|---------------|-------------|
| `/` | GET | None | Home page with login form |
| `/login` | POST | None | Create session |
| `/logout` | POST | Authenticated | Destroy session |
| `/protected` | GET | Authenticated | Protected resource |
| `/admin` | GET | Role: ADMIN | Admin-only resource |

## Test Users

| Username | Password | Roles |
|----------|----------|-------|
| admin | admin | ADMIN, USER |
| user | user | USER |

## Testing

### Login

```bash
# Login and get session cookie
curl -c cookies.txt -X POST http://localhost:8080/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin"
```

### Access Protected Resources

```bash
# Use the session cookie
curl -b cookies.txt http://localhost:8080/protected

# Admin endpoint
curl -b cookies.txt http://localhost:8080/admin
```

### Logout

```bash
curl -b cookies.txt -c cookies.txt -X POST http://localhost:8080/logout
```

### Browser Testing

1. Navigate to `http://localhost:8080`
2. Fill in the login form
3. Click "Login"
4. Access protected resources
5. Click "Logout" when done

## Code Overview

```rust
// Session configuration
let session_config = SessionConfig::new()
    .session_key("user")
    .timeout(Duration::from_secs(3600))
    .fixation_strategy(SessionFixationStrategy::MigrateSession);

// Session authenticator
let authenticator = SessionAuthenticator::new(session_config);

// Middleware setup
App::new()
    .wrap(SessionMiddleware::new(
        CookieSessionStore::default(),
        secret_key.clone(),
    ))
    .wrap(SecurityTransform::new()
        .config_authenticator(|| authenticator.clone())
        .config_authorizer(|| authorizer.clone()))
```

## Session Fixation Protection

The library supports three session fixation strategies:

| Strategy | Description |
|----------|-------------|
| `MigrateSession` | Creates new session, copies attributes (recommended) |
| `NewSession` | Creates completely new session |
| `None` | No protection (not recommended) |

## Spring Security Equivalent

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .sessionManagement()
                .sessionFixation().migrateSession()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
            .and()
            .authorizeRequests()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/protected/**").authenticated()
                .anyRequest().permitAll()
            .and()
            .formLogin()
            .and()
            .logout();
    }
}
```

## Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `session_key` | Key for storing user in session | "user" |
| `timeout` | Session inactivity timeout | 30 minutes |
| `fixation_strategy` | Session fixation protection | MigrateSession |

## Related Examples

- [Form Login](../form_login/README.md) - Form-based login with CSRF
- [Basic Auth](../basic_auth/README.md) - HTTP Basic authentication
- [JWT Auth](../jwt_auth/README.md) - Token-based authentication
