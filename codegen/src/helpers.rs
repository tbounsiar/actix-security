//! Common helper functions for security macros.

use proc_macro::TokenStream;
use proc_macro2::Ident;
use syn::{FnArg, ItemFn, Pat, Type};

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
