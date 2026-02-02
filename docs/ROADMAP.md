# Actix Security - Roadmap

This document outlines the implementation roadmap to achieve feature parity with Spring Security.

## Phase 1: Foundation ✅ COMPLETE

**Goal**: Stabilize the existing codebase and establish solid foundations.

### Tasks
- [x] Project structure (workspace with core, codegen, test)
- [x] Basic middleware architecture (SecurityTransform/SecurityService)
- [x] Authenticator/Authorizer trait design
- [x] Basic User model with roles/authorities
- [x] **Upgrade to Actix Web 4.x**
- [x] Fix bug in `login_url()` setter
- [x] Add password hashing (Argon2)
- [x] Add comprehensive integration tests (25+ tests)

---

## Phase 2: Authentication ✅ PARTIAL

**Goal**: Provide multiple authentication mechanisms like Spring Security.

### 2.1 Password Encoding
| Feature | Spring Equivalent | Status |
|---------|------------------|--------|
| Argon2 encoder | `Argon2PasswordEncoder` | ✅ Complete |
| BCrypt encoder | `BCryptPasswordEncoder` | Planned |
| PBKDF2 encoder | `Pbkdf2PasswordEncoder` | Planned |
| Delegating encoder | `DelegatingPasswordEncoder` | ✅ Complete |
| NoOp encoder | `NoOpPasswordEncoder` | ✅ Complete |

### 2.2 Authentication Providers
| Feature | Spring Equivalent | Status |
|---------|------------------|--------|
| In-memory | `InMemoryUserDetailsManager` | ✅ Complete |
| JDBC/Database | `JdbcUserDetailsManager` | Planned |
| LDAP | `LdapUserDetailsManager` | Future |
| Custom provider | `AuthenticationProvider` | ✅ Via trait |

### 2.3 Authentication Methods
| Feature | Spring Equivalent | Status |
|---------|------------------|--------|
| HTTP Basic | `httpBasic()` | ✅ Complete |
| Form login | `formLogin()` | Planned |
| JWT tokens | Spring Security JWT | Planned |
| OAuth2 Login | `oauth2Login()` | Future |
| Remember Me | `rememberMe()` | Planned |

---

## Phase 3: Authorization ✅ PARTIAL

**Goal**: Fine-grained access control with macros and configuration.

### 3.1 URL-based Authorization
| Feature | Spring Equivalent | Status |
|---------|------------------|--------|
| Regex matchers | `antMatchers()` | ✅ Complete |
| MVC matchers | `mvcMatchers()` | Planned |
| Request matchers | `requestMatchers()` | ✅ Complete |
| Method matching | `.permitAll()`, `.authenticated()` | Planned |

### 3.2 Method-level Security (Macros)
| Feature | Spring Equivalent | Status |
|---------|------------------|--------|
| `#[secured("ROLE")]` | `@Secured` | ✅ Complete |
| `#[pre_authorize(role = "...")]` | `@PreAuthorize("hasRole()")` | ✅ Complete |
| `#[pre_authorize(roles = [...])]` | `@PreAuthorize("hasAnyRole()")` | ✅ Complete |
| `#[pre_authorize(authority = "...")]` | `@PreAuthorize("hasAuthority()")` | ✅ Complete |
| `#[pre_authorize(authorities = [...])]` | `@PreAuthorize("hasAnyAuthority()")` | ✅ Complete |
| `#[pre_authorize(authenticated)]` | `@PreAuthorize("isAuthenticated()")` | ✅ Complete |
| `#[post_authorize]` | `@PostAuthorize` | Future |
| `#[roles_allowed]` | `@RolesAllowed` (JSR-250) | Planned |

### 3.3 Advanced Authorization
| Feature | Spring Equivalent | Status |
|---------|------------------|--------|
| Role hierarchy | `RoleHierarchy` | Future |
| Permission evaluator | `PermissionEvaluator` | Future |
| ACL | Spring Security ACL | Future |

---

## Phase 4: Security Features

**Goal**: Comprehensive protection against common web vulnerabilities.

### 4.1 CSRF Protection
| Feature | Spring Equivalent | Status |
|---------|------------------|--------|
| CSRF tokens | `csrf()` | Planned |
| Cookie-based CSRF | `CookieCsrfTokenRepository` | Planned |
| Ignore patterns | `csrf().ignoringAntMatchers()` | Planned |

### 4.2 CORS Configuration
| Feature | Spring Equivalent | Status |
|---------|------------------|--------|
| CORS filter | `cors()` | Planned |
| Origin whitelist | `allowedOrigins()` | Planned |
| Credentials support | `allowCredentials()` | Planned |

### 4.3 Security Headers
| Feature | Spring Equivalent | Status |
|---------|------------------|--------|
| HSTS | `headers().httpStrictTransportSecurity()` | Planned |
| X-Frame-Options | `headers().frameOptions()` | Planned |
| X-Content-Type-Options | `headers().contentTypeOptions()` | Planned |
| X-XSS-Protection | `headers().xssProtection()` | Planned |
| CSP | `headers().contentSecurityPolicy()` | Planned |

### 4.4 Session Management
| Feature | Spring Equivalent | Status |
|---------|------------------|--------|
| Session fixation | `sessionManagement().sessionFixation()` | Planned |
| Concurrent sessions | `maximumSessions()` | Future |
| Session timeout | `invalidSessionUrl()` | Planned |

---

## Phase 5: Advanced Features

**Goal**: Enterprise-grade features for complex applications.

### 5.1 OAuth2 / OpenID Connect
- OAuth2 Client
- OAuth2 Resource Server
- OAuth2 Authorization Server
- OpenID Connect support

### 5.2 SAML
- SAML 2.0 Service Provider
- SAML assertions

### 5.3 Observability
- Security event logging
- Audit trail
- Metrics integration

---

## API Design Goals

### Configuration Style (Spring-like DSL)
```rust
// Target API design
HttpSecurity::new()
    .authorize_requests(|auth| {
        auth.ant_matchers("/admin/**").has_role("ADMIN")
            .ant_matchers("/api/**").authenticated()
            .any_request().permit_all()
    })
    .http_basic(|basic| basic.realm("MyApp"))
    .form_login(|form| {
        form.login_page("/login")
            .default_success_url("/")
    })
    .csrf(|csrf| csrf.disable())
    .build()
```

### Macro Style (Annotation-like) ✅ IMPLEMENTED
```rust
// Spring: @Secured("ROLE_ADMIN")
#[secured("ADMIN")]
async fn admin_endpoint() -> impl Responder { }

// Spring: @PreAuthorize("hasAuthority('users:read')")
#[pre_authorize(authority = "users:read")]
async fn get_users() -> impl Responder { }

// Spring: @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
#[pre_authorize(roles = ["ADMIN", "MANAGER"])]
async fn management() -> impl Responder { }

// Spring: @PreAuthorize("isAuthenticated()")
#[pre_authorize(authenticated)]
async fn protected() -> impl Responder { }
```

---

## Version Milestones

| Version | Focus | Status |
|---------|-------|--------|
| 0.2.0 | Actix Web 4.x, HTTP Basic, Argon2, Macros | ✅ Complete |
| 0.3.0 | Form login, sessions, refactoring | In Progress |
| 0.4.0 | JWT authentication, feature flags | Planned |
| 0.5.0 | CSRF, CORS, security headers | Planned |
| 1.0.0 | Stable API, comprehensive docs | Planned |

## Next Steps (v0.3.0)

1. **Refactoring**
   - [ ] Separate macro files (secured.rs, pre_authorize.rs)
   - [ ] Organize core modules
   - [ ] Add feature flags for optional dependencies

2. **Features**
   - [ ] Form login support
   - [ ] Session management
   - [ ] BCrypt password encoder

3. **Documentation**
   - [ ] API documentation (rustdoc)
   - [ ] Usage examples
   - [ ] Migration guide from 0.1.x
