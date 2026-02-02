# Migration Guide

## Migrating from Spring Security

This guide helps Spring Security developers transition to Actix Security.

### Step 1: Update Dependencies

**Before (Maven/Gradle):**
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

**After (Cargo.toml):**
```toml
[dependencies]
actix-security = { version = "0.1", features = ["argon2", "http-basic"] }
actix-security = "0.1"
```

### Step 2: Update Annotations

**Before (Java):**
```java
@Secured("ROLE_ADMIN")
@GetMapping("/admin")
public String admin() { ... }

@PreAuthorize("hasRole('USER') and hasAuthority('posts:write')")
@PostMapping("/posts")
public String createPost() { ... }

@PermitAll
@GetMapping("/public")
public String publicEndpoint() { ... }
```

**After (Rust):**
```rust
#[secured("ADMIN")]  // No ROLE_ prefix
#[get("/admin")]
async fn admin(user: AuthenticatedUser) -> impl Responder { ... }

#[pre_authorize("hasRole('USER') AND hasAuthority('posts:write')")]  // AND not and
#[post("/posts")]
async fn create_post(user: AuthenticatedUser) -> impl Responder { ... }

#[permit_all]
#[get("/public")]
async fn public_endpoint() -> impl Responder { ... }  // No AuthenticatedUser needed
```

### Step 3: Update Configuration

**Before (Java):**
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .httpBasic(Customizer.withDefaults())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/**").authenticated()
                .anyRequest().permitAll()
            );
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        var admin = User.withDefaultPasswordEncoder()
            .username("admin")
            .password("admin")
            .roles("ADMIN")
            .build();
        return new InMemoryUserDetailsManager(admin);
    }
}
```

**After (Rust):**
```rust
use actix_security::http::security::{
    AuthenticationManager, AuthorizationManager,
    Argon2PasswordEncoder, PasswordEncoder, User, Access,
};
use actix_security::http::security::middleware::SecurityTransform;

fn configure_security(encoder: Argon2PasswordEncoder) -> SecurityTransform<...> {
    SecurityTransform::new()
        .config_authenticator(move || {
            AuthenticationManager::in_memory_authentication()
                .password_encoder(encoder.clone())
                .with_user(
                    User::with_encoded_password("admin", encoder.encode("admin"))
                        .roles(&["ADMIN".into()])
                )
        })
        .config_authorizer(|| {
            AuthorizationManager::request_matcher()
                .http_basic()
                .add_matcher("/admin/.*", Access::new().roles(vec!["ADMIN"]))
                .add_matcher("/api/.*", Access::new().authenticated())
        })
}
```

### Step 4: Update Expression Syntax

| Spring Security | Actix Security |
|-----------------|----------------|
| `hasRole("ADMIN")` | `hasRole('ADMIN')` |
| `hasRole('ADMIN')` | `hasRole('ADMIN')` |
| `expr1 and expr2` | `expr1 AND expr2` |
| `expr1 or expr2` | `expr1 OR expr2` |
| `!expr` | `NOT expr` |
| `not expr` | `NOT expr` |

### Step 5: Update Custom Expressions

**Before (Java):**
```java
public class CustomSecurityExpressionRoot extends SecurityExpressionRoot
    implements MethodSecurityExpressionOperations {

    public boolean isPremium() {
        return premiumService.isPremium(getAuthentication().getName());
    }
}
```

**After (Rust):**
```rust
impl ExpressionRoot for CustomExpressionRoot {
    fn evaluate_function(
        &self,
        name: &str,
        args: &[String],
        user: Option<&User>,
    ) -> Option<bool> {
        match name {
            "isPremium" => {
                let user = user?;
                Some(self.premium_service.is_premium(&user.username))
            }
            _ => None,
        }
    }
}
```

### Step 6: Update Password Encoding

**Before (Java):**
```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

**After (Rust):**
```rust
let encoder = Argon2PasswordEncoder::new();
```

### Step 7: Update Security Context Access

**Before (Java):**
```java
Authentication auth = SecurityContextHolder.getContext().getAuthentication();
String username = auth.getName();

if (auth.getAuthorities().stream()
        .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
    // Admin logic
}
```

**After (Rust):**
```rust
if let Some(user) = SecurityContext::get_user() {
    let username = &user.username;

    if SecurityContext::has_role("ADMIN") {
        // Admin logic
    }
}
```

## Common Migration Issues

### Issue: ROLE_ prefix not working

**Problem:** `#[secured("ROLE_ADMIN")]` doesn't match users with "ADMIN" role.

**Solution:** Actix Security doesn't use the ROLE_ prefix. Use `#[secured("ADMIN")]` instead.

### Issue: Expression operators not recognized

**Problem:** `#[pre_authorize("hasRole('ADMIN') && hasAuthority('write')")]` fails.

**Solution:** Use `AND`/`OR`/`NOT` instead of `&&`/`||`/`!`.

### Issue: Double quotes in expressions

**Problem:** `#[pre_authorize("hasRole(\"ADMIN\")")]` fails.

**Solution:** Use single quotes: `#[pre_authorize("hasRole('ADMIN')")]`.

### Issue: Missing AuthenticatedUser

**Problem:** Handler doesn't compile with security macro.

**Solution:** Add `AuthenticatedUser` parameter to secured handlers:

```rust
#[secured("USER")]
#[get("/profile")]
async fn profile(user: AuthenticatedUser) -> impl Responder { ... }
```

### Issue: permit_all still requires auth

**Problem:** `#[permit_all]` endpoint returns 401.

**Solution:** Check URL-based authorization rules. If your URL matcher requires authentication for that path, remove the matcher or add an exception.

## Testing Migration

```rust
#[actix_web::test]
async fn test_migrated_security() {
    let app = create_test_app().await;

    // Test role check
    let req = test::TestRequest::get()
        .uri("/admin")
        .insert_header(("Authorization", basic_auth("admin", "admin")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Test expression
    let req = test::TestRequest::post()
        .uri("/posts")
        .insert_header(("Authorization", basic_auth("user", "user")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    // Check expected status based on user's roles/authorities
}
```
