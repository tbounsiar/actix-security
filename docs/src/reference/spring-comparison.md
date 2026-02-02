# Spring Security Comparison

A comprehensive mapping between Spring Security and Actix Security concepts.

## Annotations / Macros

| Spring Security | Actix Security | Notes |
|-----------------|----------------|-------|
| `@Secured("ROLE_ADMIN")` | `#[secured("ADMIN")]` | No ROLE_ prefix in Actix |
| `@PreAuthorize("...")` | `#[pre_authorize("...")]` | Similar expression syntax |
| `@PermitAll` | `#[permit_all]` | Identical purpose |
| `@DenyAll` | `#[deny_all]` | Identical purpose |
| `@RolesAllowed({"A", "B"})` | `#[roles_allowed("A", "B")]` | Java EE style |

## Expression Language

| Spring Security | Actix Security |
|-----------------|----------------|
| `hasRole('ADMIN')` | `hasRole('ADMIN')` |
| `hasAnyRole('A', 'B')` | `hasAnyRole('A', 'B')` |
| `hasAuthority('read')` | `hasAuthority('read')` |
| `hasAnyAuthority('a', 'b')` | `hasAnyAuthority('a', 'b')` |
| `isAuthenticated()` | `isAuthenticated()` |
| `permitAll()` | `permitAll()` |
| `denyAll()` | `denyAll()` |
| `and` / `&&` | `AND` |
| `or` / `\|\|` | `OR` |
| `!` / `not` | `NOT` |

## Configuration Classes

### Authentication

**Spring Security:**
```java
@Bean
public UserDetailsService userDetailsService() {
    InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
    manager.createUser(User.withDefaultPasswordEncoder()
        .username("admin")
        .password("admin")
        .roles("ADMIN", "USER")
        .build());
    return manager;
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
```

### Authorization

**Spring Security:**
```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> auth
        .requestMatchers("/admin/**").hasRole("ADMIN")
        .requestMatchers("/api/**").authenticated()
        .anyRequest().permitAll()
    );
    return http.build();
}
```

**Actix Security:**
```rust
AuthorizationManager::request_matcher()
    .add_matcher("/admin/.*", Access::new().roles(vec!["ADMIN"]))
    .add_matcher("/api/.*", Access::new().authenticated())
    // No matcher = permit all
```

### Password Encoding

**Spring Security:**
```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}

// Or delegating
@Bean
public PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
}
```

**Actix Security:**
```rust
let encoder = Argon2PasswordEncoder::new();

// Or delegating
let encoder = DelegatingPasswordEncoder::new()
    .with_encoder("argon2", Box::new(Argon2PasswordEncoder::new()))
    .with_encoder("noop", Box::new(NoOpPasswordEncoder::new()))
    .default_encoder("argon2");
```

### HTTP Basic

**Spring Security:**
```java
http.httpBasic(Customizer.withDefaults());
```

**Actix Security:**
```rust
AuthorizationManager::request_matcher()
    .http_basic()
```

### Security Headers

**Spring Security:**
```java
http.headers(headers -> headers
    .frameOptions(frame -> frame.deny())
    .contentSecurityPolicy(csp -> csp
        .policyDirectives("default-src 'self'"))
);
```

**Actix Security:**
```rust
SecurityHeaders::new()
    .frame_options(FrameOptions::Deny)
    .content_security_policy("default-src 'self'")
```

## Core Interfaces / Traits

| Spring Security | Actix Security |
|-----------------|----------------|
| `AuthenticationManager` | `Authenticator` trait |
| `UserDetailsService` | `Authenticator.authenticate()` |
| `UserDetails` | `User` |
| `Authentication` | `AuthenticatedUser` |
| `AuthorizationManager` | `Authorizer` trait |
| `SecurityContext` | `SecurityContext` |
| `PasswordEncoder` | `PasswordEncoder` trait |
| `SecurityExpressionRoot` | `ExpressionRoot` trait |

## Extension Points

### Custom Authentication

**Spring Security:**
```java
public class CustomAuthenticationProvider implements AuthenticationProvider {
    @Override
    public Authentication authenticate(Authentication auth) {
        // Custom logic
    }
}
```

**Actix Security:**
```rust
impl Authenticator for CustomAuthenticator {
    fn authenticate(&self, req: &ServiceRequest) -> Option<User> {
        // Custom logic
    }
}
```

### Custom Authorization

**Spring Security:**
```java
public class CustomAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {
    @Override
    public AuthorizationDecision check(Supplier<Authentication> auth, RequestAuthorizationContext ctx) {
        // Custom logic
    }
}
```

**Actix Security:**
```rust
impl Authorizer for CustomAuthorizer {
    fn authorize(&self, user: Option<&User>, req: &ServiceRequest) -> AuthorizationResult {
        // Custom logic
    }
}
```

### Custom Expression Functions

**Spring Security:**
```java
public class CustomSecurityExpressionRoot extends SecurityExpressionRoot {
    public boolean customFunction() {
        return true;
    }
}
```

**Actix Security:**
```rust
impl ExpressionRoot for CustomRoot {
    fn evaluate_function(&self, name: &str, args: &[String], user: Option<&User>) -> Option<bool> {
        match name {
            "customFunction" => Some(true),
            _ => None,
        }
    }
}
```

## Key Differences

| Aspect | Spring Security | Actix Security |
|--------|-----------------|----------------|
| **Role prefix** | Adds `ROLE_` automatically | No prefix |
| **Expression operators** | `and`, `or`, `!` | `AND`, `OR`, `NOT` |
| **String quotes** | Double quotes `"` | Single quotes `'` |
| **Compile-time** | Runtime expression parsing | Compile-time parsing |
| **Async** | Synchronous by default | Async-first |

## Migration Checklist

- [ ] Remove `ROLE_` prefix from role names
- [ ] Change `and`/`or` to `AND`/`OR` in expressions
- [ ] Change double quotes to single quotes in expressions
- [ ] Replace `@PreAuthorize` with `#[pre_authorize]`
- [ ] Replace `@Secured` with `#[secured]`
- [ ] Replace `BCryptPasswordEncoder` with `Argon2PasswordEncoder`
- [ ] Update security configuration to builder pattern
- [ ] Add `AuthenticatedUser` parameter to secured handlers
