use std::fmt;

use proc_macro2::Span;
use syn::{AttributeArgs, NestedMeta};

#[derive(Debug)]
pub struct Access {
    access: Vec<String>
}

impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(Access{{ access: [{}] }})", self.access.join(", "))
    }
}

impl Access {
    pub fn new(attrs: AttributeArgs) -> Result<Self, syn::Error> {
        if attrs.is_empty() {
            return Err(
                syn::Error::new(
                    Span::call_site(),
                    format!(
                        r#"invalid definition, expected #[{}("<some access>")]"#,
                        "has_access"
                    ),
                )
            );
        }
        let mut access: Vec<String> = Vec::new();
        for attr in attrs {
            match attr {
                NestedMeta::Lit(syn::Lit::Str(lit)) => {
                    access.push(lit.value());
                }
                NestedMeta::Meta(syn::Meta::Path(path)) => {
                    access.push(path.get_ident().unwrap().to_string());
                }
                _ => {
                    return Err(
                        syn::Error::new(
                            Span::call_site(),
                            format!(
                                r#"invalid definition, expected #[{}("<some access>", <some access>)]"#,
                                "has_access"
                            ),
                        )
                    );
                }
            }
        }
        Ok(Access {
            access
        })
    }

    pub fn get_access(self) -> Vec<String> {
        self.access
    }
}