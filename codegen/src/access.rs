use std::fmt;

use proc_macro2::Span;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{Expr, ExprLit, Lit, Token};

/// Parsed access requirements from the macro attributes.
#[derive(Debug)]
pub struct Access {
    access: Vec<String>,
}

impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Access{{ authorities: [{}] }}", self.access.join(", "))
    }
}

/// Custom parser for comma-separated string literals.
/// Example: `#[has_access("read", "write")]`
impl Parse for Access {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let args: Punctuated<Expr, Token![,]> = Punctuated::parse_terminated(input)?;

        if args.is_empty() {
            return Err(syn::Error::new(
                Span::call_site(),
                r#"expected at least one authority, e.g. #[has_access("authority")]"#,
            ));
        }

        let mut access = Vec::new();

        for arg in args {
            match arg {
                Expr::Lit(ExprLit {
                    lit: Lit::Str(lit_str),
                    ..
                }) => {
                    access.push(lit_str.value());
                }
                Expr::Path(path) => {
                    // Handle bare identifiers like `#[has_access(READ, WRITE)]`
                    if let Some(ident) = path.path.get_ident() {
                        access.push(ident.to_string());
                    } else {
                        return Err(syn::Error::new_spanned(
                            path,
                            "expected a string literal or identifier",
                        ));
                    }
                }
                _ => {
                    return Err(syn::Error::new_spanned(
                        arg,
                        r#"expected string literal like "read" or identifier like READ"#,
                    ));
                }
            }
        }

        Ok(Access { access })
    }
}

impl Access {
    pub fn get_access(self) -> Vec<String> {
        self.access
    }
}
