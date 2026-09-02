//! CyberChef recipe suggestions for extracted strings.

use crate::analysis::strings::StringInfo;
use serde::Serialize;
use serde_json::{json, Value};

const MIN_ENCODED_LEN: usize = 16;

/// One CyberChef operation in saved-recipe JSON shape.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CyberChefOperation {
    #[serde(rename = "op")]
    pub operation: String,
    pub args: Vec<Value>,
}

/// A suggested CyberChef recipe for one extracted string.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CyberChefRecipeReport {
    pub address: u64,
    pub symbol: String,
    pub value: String,
    pub encoding: String,
    pub signal: String,
    pub confidence: u8,
    pub reason: String,
    pub deep_link: String,
    pub recipe: Vec<CyberChefOperation>,
}

/// Build CyberChef recipe suggestions from extracted strings.
pub fn cyberchef_recipe_reports(strings: &[StringInfo]) -> Vec<CyberChefRecipeReport> {
    strings.iter().filter_map(recipe_for_string).collect()
}

fn recipe_for_string(string: &StringInfo) -> Option<CyberChefRecipeReport> {
    let value = string.value.trim();
    if value.is_empty() {
        return None;
    }

    let suggestion = detect_percent_encoded(value)
        .or_else(|| detect_hex(value))
        .or_else(|| detect_base64(value))
        .or_else(|| detect_escaped_hex(value))?;

    Some(CyberChefRecipeReport {
        address: string.address,
        symbol: format!("str_{:X}", string.address),
        value: string.value.clone(),
        encoding: format!("{:?}", string.encoding),
        signal: suggestion.signal.to_string(),
        confidence: suggestion.confidence,
        reason: suggestion.reason.to_string(),
        deep_link: cyberchef_deep_link(&suggestion.recipe, &string.value),
        recipe: suggestion.recipe,
    })
}

struct RecipeSuggestion {
    signal: &'static str,
    confidence: u8,
    reason: &'static str,
    recipe: Vec<CyberChefOperation>,
}

fn detect_percent_encoded(value: &str) -> Option<RecipeSuggestion> {
    let triplets = value
        .as_bytes()
        .windows(3)
        .filter(|window| {
            window[0] == b'%' && window[1].is_ascii_hexdigit() && window[2].is_ascii_hexdigit()
        })
        .count();

    if triplets < 2 {
        return None;
    }

    Some(RecipeSuggestion {
        signal: "url_percent_encoding",
        confidence: 85,
        reason: "contains repeated %HH escape sequences",
        recipe: vec![operation("URL Decode", vec![json!(true)])],
    })
}

fn detect_hex(value: &str) -> Option<RecipeSuggestion> {
    let compact = value
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace() && !matches!(ch, ':' | '-' | '_'))
        .collect::<String>();

    if compact.len() < MIN_ENCODED_LEN
        || compact.len() % 2 != 0
        || !compact.chars().all(|ch| ch.is_ascii_hexdigit())
        || !compact
            .chars()
            .any(|ch| matches!(ch, 'a'..='f' | 'A'..='F'))
    {
        return None;
    }

    Some(RecipeSuggestion {
        signal: "hex",
        confidence: 80,
        reason: "long even-length hexadecimal string",
        recipe: vec![operation("From Hex", vec![json!("Auto")])],
    })
}

fn detect_base64(value: &str) -> Option<RecipeSuggestion> {
    if value.len() < MIN_ENCODED_LEN
        || !value.len().is_multiple_of(4)
        || value.contains(char::is_whitespace)
    {
        return None;
    }

    let url_safe = value.contains('-') || value.contains('_');
    let alphabet = if url_safe {
        "A-Za-z0-9-_="
    } else {
        "A-Za-z0-9+/="
    };

    if !value.chars().all(|ch| {
        ch.is_ascii_alphanumeric()
            || ch == '='
            || (!url_safe && matches!(ch, '+' | '/'))
            || (url_safe && matches!(ch, '-' | '_'))
    }) || !has_valid_base64_padding(value)
        || value.chars().all(|ch| ch.is_ascii_hexdigit())
    {
        return None;
    }

    let mut recipe = vec![operation(
        "From Base64",
        vec![json!(alphabet), json!(true), json!(false)],
    )];
    let mut confidence = if value.ends_with('=') { 85 } else { 70 };
    let reason = if value.starts_with("H4sI") {
        confidence = 90;
        recipe.push(operation("Gunzip", vec![]));
        "base64 text starts with a common gzip marker"
    } else if value.starts_with("eJ") {
        confidence = 85;
        recipe.push(operation(
            "Zlib Inflate",
            vec![
                json!(0),
                json!(0),
                json!("Adaptive"),
                json!(false),
                json!(false),
            ],
        ));
        "base64 text starts with a common zlib marker"
    } else {
        "long padded base64-looking string"
    };

    Some(RecipeSuggestion {
        signal: "base64",
        confidence,
        reason,
        recipe,
    })
}

fn has_valid_base64_padding(value: &str) -> bool {
    let padding = value.chars().rev().take_while(|ch| *ch == '=').count();
    padding <= 2 && !value[..value.len().saturating_sub(padding)].contains('=')
}

fn detect_escaped_hex(value: &str) -> Option<RecipeSuggestion> {
    let escapes = value
        .as_bytes()
        .windows(4)
        .filter(|window| {
            window[0] == b'\\'
                && (window[1] == b'x' || window[1] == b'X')
                && window[2].is_ascii_hexdigit()
                && window[3].is_ascii_hexdigit()
        })
        .count();

    if escapes < 2 {
        return None;
    }

    Some(RecipeSuggestion {
        signal: "escaped_hex",
        confidence: 75,
        reason: "contains repeated \\xHH byte escapes",
        recipe: vec![operation("Unescape string", vec![])],
    })
}

fn operation(operation: &str, args: Vec<Value>) -> CyberChefOperation {
    CyberChefOperation {
        operation: operation.to_string(),
        args,
    }
}

fn cyberchef_deep_link(recipe: &[CyberChefOperation], input: &str) -> String {
    let recipe_json = serde_json::to_string(recipe).unwrap_or_else(|_| "[]".to_string());
    format!(
        "https://gchq.github.io/CyberChef/#recipe={}&input={}",
        url_encode(&recipe_json),
        url_encode(&base64_encode(input.as_bytes()))
    )
}

fn url_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{:02X}", byte));
        }
    }
    encoded
}

fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut chunks = bytes.chunks_exact(3);

    for chunk in &mut chunks {
        let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | chunk[2] as u32;
        out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        out.push(ALPHABET[(n & 0x3F) as usize] as char);
    }

    let rem = chunks.remainder();
    if rem.len() == 1 {
        let n = (rem[0] as u32) << 16;
        out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem.len() == 2 {
        let n = ((rem[0] as u32) << 16) | ((rem[1] as u32) << 8);
        out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        out.push('=');
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::strings::StringEncoding;

    fn string(address: u64, value: &str) -> StringInfo {
        StringInfo {
            address,
            value: value.to_string(),
            encoding: StringEncoding::Ascii,
            length: value.len(),
        }
    }

    #[test]
    fn suggests_base64_recipe_for_encoded_payloads() {
        let recipes = cyberchef_recipe_reports(&[string(0x3000, "SGVsbG8sIHdvcmxkIQ==")]);

        assert_eq!(recipes.len(), 1);
        assert_eq!(recipes[0].signal, "base64");
        assert_eq!(recipes[0].recipe[0].operation, "From Base64");
        assert!(recipes[0]
            .deep_link
            .starts_with("https://gchq.github.io/CyberChef/#recipe="));
        assert!(recipes[0]
            .deep_link
            .contains("&input=U0dWc2JHOHNJSGR2Y214a0lRPT0%3D"));
    }

    #[test]
    fn suggests_hex_recipe_for_long_hex_payloads() {
        let recipes =
            cyberchef_recipe_reports(&[string(0x3000, "4D5A90000300000004000000FFFF0000")]);

        assert_eq!(recipes.len(), 1);
        assert_eq!(recipes[0].signal, "hex");
        assert_eq!(recipes[0].recipe[0].operation, "From Hex");
    }

    #[test]
    fn suggests_url_decode_recipe_for_percent_encoded_values() {
        let recipes =
            cyberchef_recipe_reports(&[string(0x3000, "https%3A%2F%2Fevil.test%2Fpayload")]);

        assert_eq!(recipes.len(), 1);
        assert_eq!(recipes[0].signal, "url_percent_encoding");
        assert_eq!(recipes[0].recipe[0].operation, "URL Decode");
    }

    #[test]
    fn skips_plain_strings_and_urls() {
        let recipes = cyberchef_recipe_reports(&[
            string(0x3000, "kernel32.dll"),
            string(0x3010, "https://example.test/plain"),
            string(0x3020, "CreateFileW"),
        ]);

        assert!(recipes.is_empty());
    }
}
