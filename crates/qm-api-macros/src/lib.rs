#![forbid(unsafe_code)]

use proc_macro::TokenStream;
use proc_macro2::TokenStream as Tokens;
use quote::{format_ident, quote};
use syn::{Attribute, ItemFn, LitStr, Token, punctuated::Punctuated, visit_mut::VisitMut};

#[proc_macro_attribute]
pub fn reviewed(args: TokenStream, input: TokenStream) -> TokenStream {
    if !args.is_empty() {
        return syn::Error::new(
            proc_macro2::Span::call_site(),
            "reviewed takes no arguments",
        )
        .into_compile_error()
        .into();
    }
    expand(input.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn expand(input: Tokens) -> syn::Result<Tokens> {
    let mut function: ItemFn = syn::parse2(input)?;
    let mut collector = Collector::default();
    collector.visit_block_mut(&mut function.block);
    if let Some(error) = collector.error {
        return Err(error);
    }
    if collector.entries.is_empty() {
        return Err(syn::Error::new_spanned(
            &function.sig.ident,
            "no API review annotations",
        ));
    }
    let name = format_ident!(
        "{}_API_REVIEWS",
        function.sig.ident.to_string().to_uppercase()
    );
    let entries = collector.entries;
    Ok(quote! {
        #function
        #[cfg(test)]
        pub(crate) const #name: &[crate::api_review::Entry<'static>] = &[#(#entries),*];
    })
}

#[derive(Default)]
struct Collector {
    entries: Vec<Tokens>,
    error: Option<syn::Error>,
}

impl VisitMut for Collector {
    fn visit_arm_mut(&mut self, arm: &mut syn::Arm) {
        let mut retained = Vec::new();
        for attribute in std::mem::take(&mut arm.attrs) {
            let kind = if attribute.path().is_ident("api") {
                "Recognised"
            } else if attribute.path().is_ident("api_unrecognised") {
                "Unrecognised"
            } else if attribute.path().is_ident("api_remainder") {
                "Remainder"
            } else {
                retained.push(attribute);
                continue;
            };
            match entry(&attribute, kind) {
                Ok(entry) => self.entries.push(entry),
                Err(error) => match &mut self.error {
                    Some(previous) => previous.combine(error),
                    None => self.error = Some(error),
                },
            }
        }
        arm.attrs = retained;
        syn::visit_mut::visit_arm_mut(self, arm);
    }
}

fn entry(attribute: &Attribute, kind: &str) -> syn::Result<Tokens> {
    let arguments = attribute.parse_args_with(Punctuated::<LitStr, Token![,]>::parse_terminated)?;
    let expected = if kind == "Recognised" { 2 } else { 3 };
    if arguments.len() != expected {
        return Err(syn::Error::new_spanned(
            attribute,
            "expected API key, fingerprint, and a reason for unrecognised/remainder entries",
        ));
    }
    let key = &arguments[0];
    let fingerprint = &arguments[1];
    let valid_key = if kind == "Remainder" {
        matches!(key.value().as_str(), "REST" | "GraphQL")
    } else {
        key.value().starts_with("REST ") || key.value().starts_with("GraphQL ")
    };
    if !valid_key {
        return Err(syn::Error::new_spanned(
            key,
            "expected a REST or GraphQL API key",
        ));
    }
    let digest = fingerprint.value();
    if digest.len() != 11
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(syn::Error::new_spanned(
            fingerprint,
            "expected an 11-character URL-safe base64 fingerprint without padding",
        ));
    }
    let reason = arguments
        .get(2)
        .cloned()
        .unwrap_or_else(|| LitStr::new("", key.span()));
    if expected == 3 && reason.value().trim().is_empty() {
        return Err(syn::Error::new_spanned(
            reason,
            "review reason must not be empty",
        ));
    }
    let kind = format_ident!("{kind}");
    Ok(quote! {
        crate::api_review::Entry {
            key: #key, fingerprint: #fingerprint,
            kind: crate::api_review::Kind::#kind, reason: #reason,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::ToTokens;
    use syn::{Item, ItemFn, parse_quote};

    #[test]
    fn strips_only_review_attributes_and_preserves_the_runtime_function() {
        let input: ItemFn = parse_quote! {
            pub(crate) fn inspect(input: &str) -> usize {
                match input {
                    #[api("GraphQL Query.repository", "AAAAAAAAAAA")]
                    "repository" => 1,
                    #[api_remainder("GraphQL", "__________8", "Other schema entries")]
                    _ => 0,
                }
            }
        };
        let expected: ItemFn = parse_quote! {
            pub(crate) fn inspect(input: &str) -> usize {
                match input { "repository" => 1, _ => 0, }
            }
        };
        let output: syn::File = syn::parse2(expand(quote!(#input)).unwrap()).unwrap();
        let Item::Fn(function) = &output.items[0] else {
            panic!("function missing")
        };
        assert_eq!(
            function.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
        let Item::Const(metadata) = &output.items[1] else {
            panic!("metadata missing")
        };
        assert_eq!(metadata.ident, "INSPECT_API_REVIEWS");
        assert_eq!(
            metadata.attrs[0].to_token_stream().to_string(),
            "# [cfg (test)]"
        );
    }

    #[test]
    fn rejects_invalid_hashes_missing_reasons_and_unannotated_functions() {
        for input in [
            quote! { fn inspect() { match 0 { #[api("REST GET /x", "bad")] _ => (), } } },
            quote! { fn inspect() { match 0 { #[api("REST GET /x", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")] _ => (), } } },
            quote! { fn inspect() { match 0 { #[api("REST GET /x", "AAAAAAAAAA+")] _ => (), } } },
            quote! { fn inspect() { match 0 { #[api("REST GET /x", "AAAAAAAAAA/")] _ => (), } } },
            quote! { fn inspect() { match 0 { #[api("REST GET /x", "AAAAAAAAAA=")] _ => (), } } },
            quote! { fn inspect() { match 0 { #[api_unrecognised("REST GET /x", "AAAAAAAAAAA", "")] _ => (), } } },
            quote! { fn inspect() { match 0 { _ => (), } } },
        ] {
            assert!(expand(input).is_err());
        }
    }

    #[test]
    fn collects_nested_arms_and_explicitly_unrecognised_operations() {
        let output = expand(quote! {
            fn inspect() {
                match 0 {
                    _ => match 1 {
                        #[api_unrecognised("GraphQL Mutation.mergePullRequest", "AAAAAAAAAAA", "Not modelled")]
                        _ => (),
                    }
                }
            }
        }).unwrap().to_string();
        assert!(output.contains("Kind :: Unrecognised"));
        assert!(output.contains("GraphQL Mutation.mergePullRequest"));
    }
}
