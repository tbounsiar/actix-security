//! Procedural macros for Spring Security-like method-level security.
//!
//! # Spring Security Equivalents
//!
//! | Spring Security | actix-security-codegen |
//! |-----------------|------------------------|
//! | `@Secured("ROLE_ADMIN")` | `#[secured("ADMIN")]` |
//! | `@PreAuthorize("hasRole('ADMIN')")` | `#[pre_authorize(role = "ADMIN")]` |
//! | `@PreAuthorize("hasAuthority('read')")` | `#[pre_authorize(authority = "read")]` |
//! | `@PreAuthorize("isAuthenticated()")` | `#[pre_authorize(authenticated)]` |
//! | `@PermitAll` | `#[permit_all]` |
//! | `@DenyAll` | `#[deny_all]` |
//! | `@RolesAllowed({"ADMIN"})` | `#[roles_allowed("ADMIN")]` |
//!
//! # Usage
//!
//! ```ignore
//! use actix_security_codegen::{secured, pre_authorize};
//! use actix_security_core::http::security::AuthenticatedUser;
//! use actix_web::{get, HttpResponse, Responder};
//!
//! // Role-based security (like @Secured)
//! #[secured("ADMIN")]
//! #[get("/admin")]
//! async fn admin_only(user: AuthenticatedUser) -> impl Responder {
//!     HttpResponse::Ok().body("Admin area")
//! }
//!
//! // Authority-based security (like @PreAuthorize)
//! #[pre_authorize(authority = "users:read")]
//! #[get("/api/users")]
//! async fn get_users(user: AuthenticatedUser) -> impl Responder {
//!     HttpResponse::Ok().body("Users")
//! }
//!
//! // Authentication check only
//! #[pre_authorize(authenticated)]
//! #[get("/protected")]
//! async fn protected(user: AuthenticatedUser) -> impl Responder {
//!     HttpResponse::Ok().body("Protected")
//! }
//! ```

use proc_macro::TokenStream;

// Internal modules
mod access;
mod helpers;
mod legacy;
mod pre_authorize;
mod secured;
mod simple;

// =============================================================================
// Primary Macros (Spring Security-like)
// =============================================================================

/// Role-based method security annotation.
///
/// # Spring Security Equivalent
/// `@Secured("ROLE_ADMIN")` or `@RolesAllowed("ADMIN")`
///
/// # Usage
/// ```ignore
/// use actix_security_core::http::security::AuthenticatedUser;
/// use actix_security_codegen::secured;
///
/// // Single role
/// #[secured("ADMIN")]
/// #[get("/admin")]
/// async fn admin_only(user: AuthenticatedUser) -> impl Responder {
///     HttpResponse::Ok().body("Admin area")
/// }
///
/// // Multiple roles (OR logic - user needs ANY of these)
/// #[secured("ADMIN", "MANAGER")]
/// #[get("/management")]
/// async fn management(user: AuthenticatedUser) -> impl Responder {
///     HttpResponse::Ok().body("Management area")
/// }
/// ```
///
/// # Note
/// Unlike Spring Security, you don't need the "ROLE_" prefix.
/// The macro checks if the user has ANY of the specified roles.
#[proc_macro_attribute]
pub fn secured(attrs: TokenStream, input: TokenStream) -> TokenStream {
    secured::secured_impl(attrs, input)
}

/// Flexible method security annotation with SpEL-like expressions.
///
/// # Spring Security Equivalent
/// `@PreAuthorize("...")`
///
/// # Supported Expressions
///
/// | Actix Security | Spring Security |
/// |----------------|-----------------|
/// | `#[pre_authorize(authenticated)]` | `@PreAuthorize("isAuthenticated()")` |
/// | `#[pre_authorize(role = "ADMIN")]` | `@PreAuthorize("hasRole('ADMIN')")` |
/// | `#[pre_authorize(roles = ["A", "B"])]` | `@PreAuthorize("hasAnyRole('A', 'B')")` |
/// | `#[pre_authorize(authority = "read")]` | `@PreAuthorize("hasAuthority('read')")` |
/// | `#[pre_authorize(authorities = ["r", "w"])]` | `@PreAuthorize("hasAnyAuthority('r', 'w')")` |
///
/// # Usage
/// ```ignore
/// use actix_security_core::http::security::AuthenticatedUser;
/// use actix_security_codegen::pre_authorize;
///
/// // Check authentication only
/// #[pre_authorize(authenticated)]
/// #[get("/protected")]
/// async fn protected(user: AuthenticatedUser) -> impl Responder {
///     HttpResponse::Ok().body("Protected")
/// }
///
/// // Check single role
/// #[pre_authorize(role = "ADMIN")]
/// #[get("/admin")]
/// async fn admin(user: AuthenticatedUser) -> impl Responder {
///     HttpResponse::Ok().body("Admin")
/// }
///
/// // Check multiple roles (OR logic)
/// #[pre_authorize(roles = ["ADMIN", "MANAGER"])]
/// #[get("/management")]
/// async fn management(user: AuthenticatedUser) -> impl Responder {
///     HttpResponse::Ok().body("Management")
/// }
///
/// // Check authority
/// #[pre_authorize(authority = "users:read")]
/// #[get("/api/users")]
/// async fn get_users(user: AuthenticatedUser) -> impl Responder {
///     HttpResponse::Ok().body("Users")
/// }
///
/// // Check multiple authorities (OR logic)
/// #[pre_authorize(authorities = ["users:read", "users:write"])]
/// #[get("/api/users/manage")]
/// async fn manage_users(user: AuthenticatedUser) -> impl Responder {
///     HttpResponse::Ok().body("Manage users")
/// }
/// ```
#[proc_macro_attribute]
pub fn pre_authorize(attrs: TokenStream, input: TokenStream) -> TokenStream {
    pre_authorize::pre_authorize_impl(attrs, input)
}

/// Marks an endpoint as publicly accessible (no authentication required).
///
/// # Spring Security / Java EE Equivalent
/// `@PermitAll`
///
/// # Usage
/// ```ignore
/// use actix_security_codegen::permit_all;
///
/// #[permit_all]
/// #[get("/public")]
/// async fn public_endpoint() -> impl Responder {
///     HttpResponse::Ok().body("Public content")
/// }
/// ```
///
/// # Note
/// This macro simply passes through to the original function.
/// No authentication or authorization checks are performed.
#[proc_macro_attribute]
pub fn permit_all(attrs: TokenStream, input: TokenStream) -> TokenStream {
    simple::permit_all_impl(attrs, input)
}

/// Marks an endpoint as completely inaccessible (always returns 403 Forbidden).
///
/// # Spring Security / Java EE Equivalent
/// `@DenyAll`
///
/// # Usage
/// ```ignore
/// use actix_security_codegen::deny_all;
/// use actix_security_core::http::security::AuthenticatedUser;
///
/// #[deny_all]
/// #[get("/disabled")]
/// async fn disabled_endpoint(user: AuthenticatedUser) -> impl Responder {
///     HttpResponse::Ok().body("Never reached")
/// }
/// ```
///
/// # Note
/// Useful for temporarily disabling endpoints or marking them as under construction.
#[proc_macro_attribute]
pub fn deny_all(attrs: TokenStream, input: TokenStream) -> TokenStream {
    simple::deny_all_impl(attrs, input)
}

/// Role-based method security annotation (Java EE standard).
///
/// # Java EE Equivalent
/// `@RolesAllowed({"ADMIN", "USER"})`
///
/// # Spring Security Equivalent
/// `@Secured({"ROLE_ADMIN", "ROLE_USER"})`
///
/// # Usage
/// ```ignore
/// use actix_security_codegen::roles_allowed;
/// use actix_security_core::http::security::AuthenticatedUser;
///
/// #[roles_allowed("ADMIN")]
/// #[get("/admin")]
/// async fn admin_only(user: AuthenticatedUser) -> impl Responder {
///     HttpResponse::Ok().body("Admin area")
/// }
///
/// #[roles_allowed("ADMIN", "MANAGER")]
/// #[get("/management")]
/// async fn management(user: AuthenticatedUser) -> impl Responder {
///     HttpResponse::Ok().body("Management area")
/// }
/// ```
///
/// # Note
/// This is an alias for `#[secured]` following Java EE naming conventions.
#[proc_macro_attribute]
pub fn roles_allowed(attrs: TokenStream, input: TokenStream) -> TokenStream {
    simple::roles_allowed_impl(attrs, input)
}

// =============================================================================
// Legacy Macros (Deprecated)
// =============================================================================

/// **Deprecated**: Use `#[secured("ROLE")]` instead.
///
/// This macro is kept for backward compatibility.
#[proc_macro_attribute]
#[deprecated(since = "0.3.0", note = "Use #[secured] instead")]
pub fn has_role(attrs: TokenStream, input: TokenStream) -> TokenStream {
    legacy::has_role_impl(attrs, input)
}

/// **Deprecated**: Use `#[pre_authorize(authority = "...")]` instead.
///
/// This macro is kept for backward compatibility.
#[proc_macro_attribute]
#[deprecated(
    since = "0.3.0",
    note = "Use #[pre_authorize(authority = \"...\")] instead"
)]
pub fn has_access(attrs: TokenStream, input: TokenStream) -> TokenStream {
    legacy::has_access_impl(attrs, input)
}

/// **Deprecated**: Use `#[pre_authorize(authenticated)]` instead.
#[proc_macro_attribute]
#[deprecated(since = "0.3.0", note = "Use #[pre_authorize(authenticated)] instead")]
pub fn authenticated(attrs: TokenStream, input: TokenStream) -> TokenStream {
    legacy::authenticated_impl(attrs, input)
}
