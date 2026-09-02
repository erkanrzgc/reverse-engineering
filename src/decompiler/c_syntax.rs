//! Helpers for emitting syntactically safe C output.
//!
//! Decompiler output routinely contains bytes, symbols, and comments copied
//! from untrusted binaries. These helpers keep that text valid for C source
//! emission without changing the higher-level AST semantics.

use std::collections::BTreeSet;
use std::fmt::Write as _;

/// Escape a Rust string so it can be placed between double quotes in a C string
/// literal.
///
/// Non-printable and non-ASCII bytes are emitted as fixed-width octal escapes.
/// Fixed-width octal avoids the greediness of C hex escapes, where `\x41B`
/// would be parsed as a single large escape instead of `"A" "B"`.
pub fn escape_c_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());

    for byte in value.bytes() {
        match byte {
            b'"' => escaped.push_str("\\\""),
            b'\\' => escaped.push_str("\\\\"),
            b'\n' => escaped.push_str("\\n"),
            b'\r' => escaped.push_str("\\r"),
            b'\t' => escaped.push_str("\\t"),
            b'\0' => escaped.push_str("\\000"),
            0x20..=0x7e => escaped.push(byte as char),
            _ => {
                write!(&mut escaped, "\\{:03o}", byte)
                    .expect("writing to a String should never fail");
            }
        }
    }

    escaped
}

/// Quote and escape a C string literal.
pub fn quote_c_string(value: &str) -> String {
    format!("\"{}\"", escape_c_string(value))
}

/// Sanitize text that will be embedded in a C block comment.
pub fn sanitize_c_comment(value: &str) -> String {
    value.replace("*/", "* /")
}

/// Sanitize untrusted text before interpolating it into a C `//` comment.
///
/// Line-breaking and other control characters are rendered visibly, while C
/// comment delimiter pairs are separated so the result remains inert if it is
/// later moved into a different comment context.
pub fn sanitize_c_line_comment(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len());

    for character in value.chars() {
        match character {
            '\r' => sanitized.push_str("\\r"),
            '\n' => sanitized.push_str("\\n"),
            '\t' => sanitized.push_str("\\t"),
            '\\' => sanitized.push_str("\\x5C"),
            control if control.is_control() => {
                write!(&mut sanitized, "\\u{{{:X}}}", control as u32)
                    .expect("writing to a String should never fail");
            }
            printable => sanitized.push(printable),
        }
    }

    sanitized
        .replace("/*", "/ *")
        .replace("*/", "* /")
        .replace("//", "/ /")
        .replace("??/", "? ?/")
}

/// Convert arbitrary text into a valid, non-reserved C identifier.
///
/// Invalid characters are collapsed to `_`, leading digits are prefixed with
/// the sanitized fallback, C keywords receive a trailing `_`, and leading
/// underscores are avoided because many underscore-prefixed names are reserved
/// to the implementation in C.
pub fn sanitize_c_identifier(value: &str, fallback: &str) -> String {
    let fallback = sanitize_fallback_identifier(fallback);
    let mut identifier = sanitize_identifier_body(value);

    if identifier.is_empty() {
        identifier = fallback.clone();
    }

    if identifier
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_digit())
    {
        identifier = format!("{}_{}", fallback, identifier);
    }

    if is_c_keyword(&identifier) {
        identifier.push('_');
    }

    if is_reserved_c_identifier(&identifier) {
        let trimmed = identifier.trim_start_matches('_');
        identifier = if trimmed.is_empty() {
            fallback
        } else {
            format!("{}_{}", fallback, trimmed)
        };

        if is_c_keyword(&identifier) {
            identifier.push('_');
        }
    }

    identifier
}

/// Sanitize an identifier and make it unique within `used`.
///
/// The first occurrence keeps the base identifier. Later collisions receive
/// deterministic numeric suffixes: `name_2`, `name_3`, ...
pub fn unique_c_identifier(value: &str, fallback: &str, used: &mut BTreeSet<String>) -> String {
    let base = sanitize_c_identifier(value, fallback);
    let mut candidate = base.clone();
    let mut suffix = 2usize;

    while used.contains(&candidate) {
        candidate = format!("{}_{}", base, suffix);
        suffix += 1;
    }

    used.insert(candidate.clone());
    candidate
}

fn sanitize_fallback_identifier(fallback: &str) -> String {
    let mut fallback = sanitize_identifier_body(fallback);

    if fallback.is_empty() {
        fallback = "identifier".to_string();
    }

    if fallback
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_digit())
    {
        fallback = format!("identifier_{}", fallback);
    }

    if is_c_keyword(&fallback) {
        fallback.push('_');
    }

    if is_reserved_c_identifier(&fallback) {
        let trimmed = fallback.trim_start_matches('_');
        fallback = if trimmed.is_empty() {
            "identifier".to_string()
        } else {
            format!("identifier_{}", trimmed)
        };
    }

    fallback
}

fn sanitize_identifier_body(value: &str) -> String {
    let mut output = String::new();
    let mut pending_separator = false;

    for ch in value.trim().chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            if pending_separator && !output.is_empty() && !output.ends_with('_') {
                output.push('_');
            }
            pending_separator = false;
            output.push(ch);
        } else {
            pending_separator = true;
        }
    }

    output
}

fn is_reserved_c_identifier(identifier: &str) -> bool {
    identifier.starts_with('_')
}

fn is_c_keyword(identifier: &str) -> bool {
    matches!(
        identifier,
        "auto"
            | "break"
            | "case"
            | "char"
            | "const"
            | "continue"
            | "default"
            | "do"
            | "double"
            | "else"
            | "enum"
            | "extern"
            | "float"
            | "for"
            | "goto"
            | "if"
            | "inline"
            | "int"
            | "long"
            | "register"
            | "restrict"
            | "return"
            | "short"
            | "signed"
            | "sizeof"
            | "static"
            | "struct"
            | "switch"
            | "typedef"
            | "union"
            | "unsigned"
            | "void"
            | "volatile"
            | "while"
            | "_Alignas"
            | "_Alignof"
            | "_Atomic"
            | "_Bool"
            | "_Complex"
            | "_Generic"
            | "_Imaginary"
            | "_Noreturn"
            | "_Static_assert"
            | "_Thread_local"
            | "alignas"
            | "alignof"
            | "bool"
            | "false"
            | "nullptr"
            | "static_assert"
            | "thread_local"
            | "true"
            | "typeof"
            | "typeof_unqual"
            | "NULL"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_quotes_backslashes_and_common_control_characters() {
        assert_eq!(escape_c_string("a\"b\\c\n\r\t"), "a\\\"b\\\\c\\n\\r\\t");
    }

    #[test]
    fn escapes_nul_and_non_printable_bytes_as_fixed_width_octal() {
        assert_eq!(escape_c_string("a\0\x1fb"), "a\\000\\037b");
    }

    #[test]
    fn escapes_non_ascii_utf8_bytes_as_octal() {
        assert_eq!(escape_c_string("é"), "\\303\\251");
    }

    #[test]
    fn quotes_c_string_literals() {
        assert_eq!(quote_c_string("hello\n"), "\"hello\\n\"");
    }

    #[test]
    fn sanitizes_c_block_comment_terminators() {
        assert_eq!(sanitize_c_comment("a */ b"), "a * / b");
    }

    #[test]
    fn sanitizes_line_comment_controls_and_delimiters() {
        let sanitized = sanitize_c_line_comment("safe\r\n\t\u{1} /* block */ // tail");

        assert_eq!(sanitized, "safe\\r\\n\\t\\u{1} / * block * / / / tail");
        assert!(!sanitized.chars().any(char::is_control));
        assert!(!sanitized.contains("/*"));
        assert!(!sanitized.contains("*/"));
        assert!(!sanitized.contains("//"));
    }

    #[test]
    fn sanitizes_line_splicing_tokens() {
        let trailing_backslash = sanitize_c_line_comment("path\\");
        let trigraph = sanitize_c_line_comment("trigraph??/");

        assert!(!trailing_backslash.ends_with('\\'));
        assert!(!trigraph.contains("??/"));
    }

    #[test]
    fn sanitizes_invalid_identifier_characters() {
        assert_eq!(
            sanitize_c_identifier("kernel32.dll!CreateFileW", "sym"),
            "kernel32_dll_CreateFileW"
        );
    }

    #[test]
    fn prefixes_identifiers_that_start_with_digits() {
        assert_eq!(sanitize_c_identifier("123abc", "sub"), "sub_123abc");
    }

    #[test]
    fn avoids_c_keywords() {
        assert_eq!(sanitize_c_identifier("return", "sym"), "return_");
    }

    #[test]
    fn preserves_valid_trailing_underscores() {
        assert_eq!(sanitize_c_identifier("already_", "sym"), "already_");
    }

    #[test]
    fn avoids_reserved_leading_underscore_identifiers() {
        assert_eq!(sanitize_c_identifier("_init", "sym"), "sym_init");
        assert_eq!(sanitize_c_identifier("__private", "sym"), "sym_private");
    }

    #[test]
    fn uses_fallback_when_identifier_has_no_valid_body() {
        assert_eq!(sanitize_c_identifier("!!!", "sub"), "sub");
    }

    #[test]
    fn makes_identifiers_unique_deterministically() {
        let mut used = BTreeSet::new();

        assert_eq!(unique_c_identifier("name", "sym", &mut used), "name");
        assert_eq!(unique_c_identifier("name", "sym", &mut used), "name_2");
        assert_eq!(unique_c_identifier("name", "sym", &mut used), "name_3");
    }
}
