//! Common helper functions for security macros.

use proc_macro::TokenStream;
use proc_macro2::{Ident, TokenStream as TokenStream2};
use proc_macro_crate::{crate_name, FoundCrate};
use quote::quote;
use syn::{FnArg, ItemFn, Pat, Type};

/// Returns the token stream for accessing actix_security_core types.
///
/// This function detects whether the user has `actix-security` (umbrella crate)
/// or `actix-security-core` as a dependency and returns the appropriate path.
///
/// - If `actix-security` is found: `::actix_security::actix_security_core`
/// - If `actix-security-core` is found: `::actix_security_core`
/// - Fallback: `::actix_security_core` (will produce a helpful error if neither is present)
pub fn core_crate_path() -> TokenStream2 {
    // First, try to find the umbrella crate `actix-security`
    if let Ok(found) = crate_name("actix-security") {
        match found {
            FoundCrate::Itself => {
                // We're being compiled as part of actix-security itself
                quote!(crate::actix_security_core)
            }
            FoundCrate::Name(name) => {
                let ident = Ident::new(&name, proc_macro2::Span::call_site());
                quote!(::#ident::actix_security_core)
            }
        }
    } else if let Ok(found) = crate_name("actix-security-core") {
        // Fall back to actix-security-core directly
        match found {
            FoundCrate::Itself => {
                quote!(crate)
            }
            FoundCrate::Name(name) => {
                let ident = Ident::new(&name, proc_macro2::Span::call_site());
                quote!(::#ident)
            }
        }
    } else {
        // Neither crate found - use the default path which will produce a clear error
        quote!(::actix_security_core)
    }
}

/// Finds the name of the AuthenticatedUser parameter in the function signature.
pub fn find_user_param(item_fn: &ItemFn) -> Option<Ident> {
    for arg in &item_fn.sig.inputs {
        if let FnArg::Typed(pat_type) = arg {
            if let Type::Path(type_path) = pat_type.ty.as_ref() {
                let type_name = type_path.path.segments.last().map(|s| s.ident.to_string());

                if type_name.as_deref() == Some("AuthenticatedUser") {
                    if let Pat::Ident(pat_ident) = pat_type.pat.as_ref() {
                        return Some(pat_ident.ident.clone());
                    }
                }
            }
        }
    }
    None
}

/// Generates a compile error for missing AuthenticatedUser parameter.
pub fn missing_user_param_error(item_fn: &ItemFn, macro_name: &str) -> TokenStream {
    syn::Error::new_spanned(
        &item_fn.sig,
        format!(
            "{} requires an AuthenticatedUser parameter. Add `user: AuthenticatedUser` to your function parameters.",
            macro_name
        ),
    )
    .to_compile_error()
    .into()
}
