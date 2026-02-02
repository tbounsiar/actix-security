# HTTP Basic Authentication Example

This example demonstrates HTTP Basic Authentication using the actix-security library.

## Features

- HTTP Basic Authentication (RFC 7617)
- In-memory user store
- Password encoding with Argon2
- Role-based access control

## Running the Example

```bash
# From the project root
cargo run --bin basic_auth

# Or from the examples directory
cargo run -p actix-security-examples --bin basic_auth
```

The server will start at `http://localhost:8080`.

## Endpoints

| Endpoint | Authorization | Description |
|----------|---------------|-------------|
| `/` | None | Public welcome page |
| `/protected` | Authenticated | Protected resource |
| `/admin` | Role: ADMIN | Admin-only resource |

## Test Users

| Username | Password | Roles |
|----------|----------|-------|
| admin | admin | ADMIN, USER |
| user | user | USER |

## Testing

### Using curl

```bash
# Public endpoint
curl http://localhost:8080/

# Protected endpoint (no auth - 401)
curl http://localhost:8080/protected

# Protected endpoint (with auth)
curl -u user:user http://localhost:8080/protected

# Admin endpoint (user role - 403)
curl -u user:user http://localhost:8080/admin

# Admin endpoint (admin role - 200)
curl -u admin:admin http://localhost:8080/admin
```

### Using a browser

1. Navigate to `http://localhost:8080/protected`
2. Enter credentials in the browser dialog
3. Access granted or denied based on your role

## Code Overview

```rust
// Password encoder (Argon2 recommended)
let encoder = Argon2PasswordEncoder::new();

// In-memory user store
let auth = MemoryAuthenticator::new()
    .with_user(User::with_encoded_password("admin", encoder.encode("admin"))
        .roles(&["ADMIN".into(), "USER".into()]))
    .with_user(User::with_encoded_password("user", encoder.encode("user"))
        .roles(&["USER".into()]));

// Request matcher for authorization
let authorizer = RequestMatcherAuthorizer::new()
    .add_matcher("/admin.*", Access::new().roles(vec!["ADMIN"]))
    .add_matcher("/protected.*", Access::new().authenticated());
```

## Spring Security Equivalent

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/protected/**").authenticated()
                .anyRequest().permitAll()
            .and()
            .httpBasic();
    }
}
```

## Related Examples

- [JWT Authentication](../jwt_auth/README.md) - Token-based authentication
- [Session Authentication](../session_auth/README.md) - Session-based authentication
- [Form Login](../form_login/README.md) - Form-based authentication
