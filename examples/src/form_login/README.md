# Form Login Example

This example demonstrates form-based login with CSRF protection using the actix-security library.

## Quick Start

Add these dependencies to your `Cargo.toml`:

```toml
[dependencies]
actix-web = "4"
actix-security = { version = "0.2", features = ["form-login", "csrf", "argon2"] }
actix-session = { version = "0.10", features = ["cookie-session"] }
serde = { version = "1", features = ["derive"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Features

- HTML form-based authentication
- CSRF protection
- Custom login/logout pages
- Success/failure redirects
- Remember-me support

## Running the Example

```bash
# From the project root
cargo run --bin form_login

# Or from the examples directory
cargo run -p actix-security-examples --bin form_login
```

The server will start at `http://localhost:8080`.

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Home page (redirects based on auth status) |
| `/login` | GET | Login form page |
| `/login` | POST | Process login |
| `/logout` | POST | Process logout |
| `/dashboard` | GET | Protected dashboard (requires auth) |
| `/admin` | GET | Admin area (requires ADMIN role) |

## Test Users

| Username | Password | Roles |
|----------|----------|-------|
| admin | admin | ADMIN, USER |
| user | user | USER |

## Testing

### Browser Testing

1. Navigate to `http://localhost:8080`
2. You'll be redirected to the login page
3. Enter credentials (admin/admin or user/user)
4. After successful login, you'll see the dashboard
5. Try accessing `/admin` with different users

### CSRF Protection

The login form includes a hidden CSRF token:

```html
<form method="POST" action="/login">
    <input type="hidden" name="_csrf" value="generated-token-here">
    <input type="text" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Login</button>
</form>
```

## Code Overview

```rust
// Form login configuration
let form_login = FormLoginConfig::new()
    .login_page("/login")
    .login_processing_url("/login")
    .default_success_url("/dashboard")
    .failure_url("/login?error")
    .logout_url("/logout")
    .logout_success_url("/login?logout")
    .username_parameter("username")
    .password_parameter("password");

// CSRF configuration
let csrf = CsrfConfig::new()
    .token_parameter("_csrf")
    .header_name("X-CSRF-TOKEN");
```

## CSRF Token Usage

### In HTML Forms

```html
<form method="POST" action="/login">
    <input type="hidden" name="_csrf" value="{{ csrf_token }}">
    <!-- form fields -->
</form>
```

### In AJAX Requests

```javascript
fetch('/api/action', {
    method: 'POST',
    headers: {
        'X-CSRF-TOKEN': getCsrfToken()
    },
    body: JSON.stringify(data)
});
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
                .antMatchers("/dashboard/**").authenticated()
                .anyRequest().permitAll()
            .and()
            .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/dashboard")
                .failureUrl("/login?error")
            .and()
            .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
            .and()
            .csrf();
    }
}
```

## Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `login_page` | URL of login form | "/login" |
| `login_processing_url` | URL to submit login | "/login" |
| `default_success_url` | Redirect after success | "/" |
| `failure_url` | Redirect after failure | "/login?error" |
| `logout_url` | URL to submit logout | "/logout" |
| `logout_success_url` | Redirect after logout | "/login?logout" |

## Related Examples

- [Session Auth](../session_auth/README.md) - Session management basics
- [Security Headers](../security_headers/README.md) - Security headers
- [Security Complete](../security_complete/README.md) - All features combined
