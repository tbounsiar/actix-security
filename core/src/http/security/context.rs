//! Security Context for accessing the current authenticated user.
//!
//! # Spring Security Equivalent
//! `org.springframework.security.core.context.SecurityContextHolder`
//!
//! # Overview
//! The SecurityContext provides access to the current authenticated user
//! from anywhere in your application, not just from request handlers.
//!
//! # Usage
//! ```ignore
//! use actix_security_core::http::security::context::SecurityContext;
//!
//! // In a service layer function
//! fn get_current_username() -> Option<String> {
//!     SecurityContext::get_user()
//!         .map(|user| user.get_username().to_string())
//! }
//!
//! // Check if current user has a role
//! fn is_admin() -> bool {
//!     SecurityContext::get_user()
//!         .map(|user| user.has_role("ADMIN"))
//!         .unwrap_or(false)
//! }
//! ```
//!
//! # Thread Safety
//! The context uses task-local storage, making it safe for async code.
//! Each async task has its own isolated security context.

use std::cell::RefCell;

use crate::http::security::User;

tokio::task_local! {
    static SECURITY_CONTEXT: RefCell<Option<User>>;
}

/// Holder for the current security context.
///
/// # Spring Security Equivalent
/// `SecurityContextHolder`
///
/// Provides static methods to access the current authenticated user
/// from anywhere in the application.
pub struct SecurityContext;

impl SecurityContext {
    /// Gets the current authenticated user.
    ///
    /// # Spring Security Equivalent
    /// ```java
    /// SecurityContextHolder.getContext().getAuthentication().getPrincipal()
    /// ```
    ///
    /// # Returns
    /// - `Some(User)` if a user is authenticated in the current context
    /// - `None` if no user is authenticated
    ///
    /// # Example
    /// ```ignore
    /// use actix_security_core::http::security::context::SecurityContext;
    ///
    /// if let Some(user) = SecurityContext::get_user() {
    ///     println!("Current user: {}", user.get_username());
    /// }
    /// ```
    pub fn get_user() -> Option<User> {
        SECURITY_CONTEXT
            .try_with(|ctx| ctx.borrow().clone())
            .ok()
            .flatten()
    }

    /// Gets the current username if authenticated.
    ///
    /// # Example
    /// ```ignore
    /// let username = SecurityContext::get_username();
    /// ```
    pub fn get_username() -> Option<String> {
        Self::get_user().map(|u| u.get_username().to_string())
    }

    /// Checks if the current user is authenticated.
    ///
    /// # Spring Security Equivalent
    /// `SecurityContextHolder.getContext().getAuthentication().isAuthenticated()`
    pub fn is_authenticated() -> bool {
        Self::get_user().is_some()
    }

    /// Checks if the current user has the specified role.
    ///
    /// # Example
    /// ```ignore
    /// if SecurityContext::has_role("ADMIN") {
    ///     // Admin-only logic
    /// }
    /// ```
    pub fn has_role(role: &str) -> bool {
        Self::get_user().map(|u| u.has_role(role)).unwrap_or(false)
    }

    /// Checks if the current user has any of the specified roles.
    pub fn has_any_role(roles: &[&str]) -> bool {
        Self::get_user()
            .map(|u| u.has_any_role(roles))
            .unwrap_or(false)
    }

    /// Checks if the current user has the specified authority.
    ///
    /// # Example
    /// ```ignore
    /// if SecurityContext::has_authority("users:write") {
    ///     // Write access logic
    /// }
    /// ```
    pub fn has_authority(authority: &str) -> bool {
        Self::get_user()
            .map(|u| u.has_authority(authority))
            .unwrap_or(false)
    }

    /// Checks if the current user has any of the specified authorities.
    pub fn has_any_authority(authorities: &[&str]) -> bool {
        Self::get_user()
            .map(|u| u.has_any_authority(authorities))
            .unwrap_or(false)
    }

    /// Runs a closure with the given user set in the security context.
    ///
    /// # Spring Security Equivalent
    /// `SecurityContextHolder.setContext(context)`
    ///
    /// This is primarily used internally by the security middleware.
    ///
    /// # Example
    /// ```ignore
    /// let user = User::new("admin".into(), "password".into());
    ///
    /// SecurityContext::run_with(Some(user), async {
    ///     // Code here can access SecurityContext::get_user()
    ///     let username = SecurityContext::get_username();
    /// }).await;
    /// ```
    pub async fn run_with<F, R>(user: Option<User>, f: F) -> R
    where
        F: std::future::Future<Output = R>,
    {
        SECURITY_CONTEXT.scope(RefCell::new(user), f).await
    }

    /// Sets the user in the current security context.
    ///
    /// # Warning
    /// This should only be called from within a `run_with` scope.
    /// Calling it outside a scope will have no effect.
    pub fn set_user(user: Option<User>) {
        let _ = SECURITY_CONTEXT.try_with(|ctx| {
            *ctx.borrow_mut() = user;
        });
    }

    /// Clears the security context.
    ///
    /// # Spring Security Equivalent
    /// `SecurityContextHolder.clearContext()`
    pub fn clear() {
        Self::set_user(None);
    }
}

/// Guard that clears the security context when dropped.
///
/// Useful for ensuring the context is cleared even if a panic occurs.
pub struct SecurityContextGuard;

impl Drop for SecurityContextGuard {
    fn drop(&mut self) {
        SecurityContext::clear();
    }
}
