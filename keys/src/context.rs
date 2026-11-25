//! Structured contexts (since 0.17.0, audit validation 2026-11-25, L-01): one unambiguous context
//! string from several parts – the same bytes as `structuredContext` in TypeScript (`ts/src/context.ts`).
//!
//! A context made by joining ids with a separator (`<app>/client/<id>`) is unambiguous only if no id can
//! contain the separator; `a/b` + `c` and `a` + `b/c` would otherwise give the same context. Here every
//! part carries its length in UTF-8 bytes, so any text – separators included – is safe:
//!
//! `rg-ctx1` ‖ for every part: `|` ‖ decimal byte length ‖ `:` ‖ part
//!
//! e.g. `["dovernik", "client", "7f3a"]` → `rg-ctx1|8:dovernik|6:client|4:7f3a`.
//!
//! This is an **addition**: existing contexts of the apps stay as they are (changing the context of stored
//! data makes it unreadable). An app uses it for new kinds of data, or migrates by re-wrapping.

use crate::Error;

/// Prefix of every structured context.
pub const PREFIX: &str = "rg-ctx1";

/// At most this many bytes in the whole context (the same bound as `sign::MAX_CONTEXT`, so a structured
/// context can also be the context of a signature).
pub const MAX_LEN: usize = 1024;

/// Builds the context from `parts` (at least one, none empty); `Error::EmptyContext` for no part or an
/// empty part, `Error::Format` when the result would be longer than [`MAX_LEN`] bytes.
pub fn structured(parts: &[&str]) -> Result<String, Error> {
    if parts.is_empty() || parts.iter().any(|p| p.is_empty()) {
        return Err(Error::EmptyContext);
    }
    let mut out = String::from(PREFIX);
    for p in parts {
        out.push('|');
        out.push_str(&p.len().to_string());
        out.push(':');
        out.push_str(p);
        if out.len() > MAX_LEN {
            return Err(Error::Format);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parts_with_separators_do_not_collide() {
        assert_eq!(structured(&["dovernik", "client", "7f3a"]).unwrap(), "rg-ctx1|8:dovernik|6:client|4:7f3a");
        assert_ne!(structured(&["a/b", "c"]).unwrap(), structured(&["a", "b/c"]).unwrap());
        assert_ne!(structured(&["a|1:b"]).unwrap(), structured(&["a", "b"]).unwrap());
        assert_eq!(structured(&["č"]).unwrap(), "rg-ctx1|2:č");
    }

    #[test]
    fn refuses_empty_and_too_long() {
        assert!(matches!(structured(&[]), Err(Error::EmptyContext)));
        assert!(matches!(structured(&["a", ""]), Err(Error::EmptyContext)));
        // PREFIX (7) + "|1017:" (6) + 1011 bytes = 1024 → accepted; one byte more → refused
        let fits = "x".repeat(MAX_LEN - PREFIX.len() - 6);
        assert_eq!(structured(&[&fits]).unwrap().len(), MAX_LEN);
        let over = "x".repeat(MAX_LEN - PREFIX.len() - 5);
        assert!(matches!(structured(&[&over]), Err(Error::Format)));
    }
}
