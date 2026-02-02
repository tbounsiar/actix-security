//! Access control types for method-level security.
//!
//! This module provides types used by the `#[has_access]` macro for
//! method-level security checks.
//!
//! # Future Use
//! This will be used when the codegen macros are fully implemented.

#![allow(dead_code)]

/// Access requirements for a protected resource.
///
/// Used by procedural macros to specify required roles and authorities.
pub struct Access {
    roles: Vec<&'static str>,
    authorities: Vec<&'static str>,
}

impl Access {
    pub fn new(roles: Vec<&'static str>, authorities: Vec<&'static str>) -> Self {
        Access { roles, authorities }
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(&role)
    }

    pub fn has_authority(&self, authority: &str) -> bool {
        self.authorities.contains(&authority)
    }

    pub fn has_any_role(&self, roles: &[&str]) -> bool {
        roles.iter().any(|r| self.has_role(r))
    }

    pub fn has_any_authority(&self, authorities: &[&str]) -> bool {
        authorities.iter().any(|a| self.has_authority(a))
    }
}

/// Function type for custom access checks.
pub type AccessFn = fn(access: &Access) -> bool;
