//! Actix Security Demo Application
//!
//! Demonstrates Spring Security-like authentication and authorization.

mod handlers;

use actix_web::{web, App, HttpServer};

use actix_security_core::http::security::manager::AuthorizationManager;
use actix_security_core::http::security::middleware::SecurityTransform;
use actix_security_core::http::security::web::{Access, MemoryAuthenticator, RequestMatcherAuthorizer};
use actix_security_core::http::security::{
    Argon2PasswordEncoder, AuthenticationManager, PasswordEncoder, User,
};

/// Creates the authenticator with test users.
///
/// # Spring Security Equivalent
/// ```java
/// @Bean
/// public UserDetailsService userDetailsService(PasswordEncoder encoder) {
///     return new InMemoryUserDetailsManager(
///         User.withUsername("admin").password(encoder.encode("admin")).roles("ADMIN", "USER").build(),
///         User.withUsername("user").password(encoder.encode("user")).roles("USER").build()
///     );
/// }
/// ```
fn authenticator() -> MemoryAuthenticator {
    let encoder = Argon2PasswordEncoder::new();

    AuthenticationManager::in_memory_authentication()
        .password_encoder(encoder.clone())
        .with_user(
            User::with_encoded_password("admin", encoder.encode("admin"))
                .roles(&["ADMIN".into(), "USER".into()])
                .authorities(&["users:read".into(), "users:write".into()]),
        )
        .with_user(
            User::with_encoded_password("user", encoder.encode("user"))
                .roles(&["USER".into()])
                .authorities(&["users:read".into()]),
        )
        .with_user(
            User::with_encoded_password("guest", encoder.encode("guest"))
                .roles(&["GUEST".into()]),
        )
}

/// Creates the authorizer with URL patterns and HTTP Basic auth.
///
/// # Spring Security Equivalent
/// ```java
/// @Bean
/// public SecurityFilterChain securityFilterChain(HttpSecurity http) {
///     return http
///         .httpBasic(Customizer.withDefaults())
///         .authorizeHttpRequests(auth -> auth
///             .requestMatchers("/admin/**").hasRole("ADMIN")
///             .requestMatchers("/user/**").hasAnyRole("ADMIN", "USER")
///             .requestMatchers("/api/**").hasAuthority("users:read")
///         )
///         .build();
/// }
/// ```
fn authorizer() -> RequestMatcherAuthorizer {
    AuthorizationManager::request_matcher()
        .login_url("/login")
        .http_basic() // Enable HTTP Basic Authentication
        .add_matcher("/admin/.*", Access::new().roles(vec!["ADMIN"]))
        .add_matcher("/user/.*", Access::new().roles(vec!["ADMIN", "USER"]))
        .add_matcher("/api/.*", Access::new().authorities(vec!["users:read"]))
}

fn print_startup_info() {
    println!("=== Actix Security Demo (Spring Security-like) ===");
    println!();
    println!("Server: http://127.0.0.1:8080");
    println!();
    println!("Features:");
    println!("  - HTTP Basic Authentication (RFC 7617)");
    println!("  - Argon2 Password Hashing");
    println!("  - Spring Security-like annotations");
    println!();
    println!("Test Users (passwords are hashed with Argon2):");
    println!("  admin/admin - Roles: [ADMIN, USER], Authorities: [users:read, users:write]");
    println!("  user/user   - Roles: [USER],        Authorities: [users:read]");
    println!("  guest/guest - Roles: [GUEST],       Authorities: []");
    println!();
    println!("Spring Security Annotation Equivalents:");
    println!("  @Secured(\"ROLE_ADMIN\")              -> #[secured(\"ADMIN\")]");
    println!("  @PreAuthorize(\"hasRole('ADMIN')\")   -> #[pre_authorize(role = \"ADMIN\")]");
    println!("  @PreAuthorize(\"hasAuthority(...)\")  -> #[pre_authorize(authority = \"...\")]");
    println!("  @PreAuthorize(\"isAuthenticated()\") -> #[pre_authorize(authenticated)]");
    println!();
    println!("Routes:");
    println!("  GET  /login           - Public login page");
    println!("  GET  /                - Home (requires auth)");
    println!("  GET  /profile         - Profile (optional auth)");
    println!("  GET  /admin/dashboard - [middleware] ADMIN role");
    println!("  GET  /admin/users     - [middleware] ADMIN role");
    println!("  GET  /user/settings   - [middleware] ADMIN or USER role");
    println!("  GET  /api/users       - [middleware] users:read authority");
    println!("  GET  /reports         - #[secured(\"ADMIN\")]");
    println!("  GET  /management      - #[secured(\"ADMIN\", \"MANAGER\")]");
    println!("  POST /api/users/create - #[pre_authorize(authority = \"users:write\")]");
    println!("  GET  /api/stats       - #[pre_authorize(authorities = [...])]");
    println!("  GET  /protected       - #[pre_authorize(authenticated)]");
    println!("  GET  /user-only       - #[pre_authorize(role = \"USER\")]");
    println!();
    println!("Examples (HTTP Basic Auth):");
    println!("  curl -u admin:admin http://127.0.0.1:8080/");
    println!("  curl -u admin:admin http://127.0.0.1:8080/reports");
    println!("  curl -u user:user http://127.0.0.1:8080/reports        # 403 Forbidden");
    println!("  curl -u admin:admin -X POST http://127.0.0.1:8080/api/users/create");
    println!("  curl -u user:user -X POST http://127.0.0.1:8080/api/users/create  # 403");
    println!();
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    print_startup_info();

    HttpServer::new(move || {
        App::new().service(
            web::scope("")
                .wrap(
                    SecurityTransform::new()
                        .config_authenticator(authenticator)
                        .config_authorizer(authorizer),
                )
                // Public routes
                .service(handlers::public::login)
                .service(handlers::public::post_login)
                // Home routes
                .service(handlers::home::index)
                .service(handlers::home::profile)
                // Admin routes (middleware-protected)
                .service(handlers::admin::admin_dashboard)
                .service(handlers::admin::admin_users)
                .service(handlers::admin::user_settings)
                // API routes (middleware-protected)
                .service(handlers::api::api_users)
                // @Secured macro routes
                .service(handlers::secured::reports)
                .service(handlers::secured::management)
                // @PreAuthorize macro routes
                .service(handlers::pre_authorize::create_user)
                .service(handlers::pre_authorize::api_stats)
                .service(handlers::pre_authorize::protected_resource)
                .service(handlers::pre_authorize::user_only),
        )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
