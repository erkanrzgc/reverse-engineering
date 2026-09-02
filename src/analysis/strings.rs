//! String extraction from binary data

use std::collections::HashSet;

/// String information
#[derive(Debug, Clone)]
pub struct StringInfo {
    pub address: u64,
    pub value: String,
    pub encoding: StringEncoding,
    pub length: usize,
}

/// String encoding
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringEncoding {
    /// ASCII
    Ascii,
    /// UTF-8
    Utf8,
    /// UTF-16 LE
    Utf16Le,
    /// UTF-16 BE
    Utf16Be,
}

/// String extractor
pub struct StringExtractor {
    /// Minimum string length
    min_length: usize,
    /// Maximum string length
    max_length: usize,
    /// Whether to include null terminator
    include_null: bool,
}

impl StringExtractor {
    /// Create a new string extractor
    pub fn new() -> Self {
        Self {
            min_length: 4,
            max_length: 1024,
            include_null: false,
        }
    }

    /// Set minimum string length
    pub fn with_min_length(mut self, length: usize) -> Self {
        self.min_length = length;
        self
    }

    /// Set maximum string length
    pub fn with_max_length(mut self, length: usize) -> Self {
        self.max_length = length;
        self
    }

    /// Set whether to include null terminator
    pub fn with_include_null(mut self, include: bool) -> Self {
        self.include_null = include;
        self
    }

    /// Extract strings from binary data
    pub fn extract(&self, data: &[u8], base_address: u64) -> Vec<StringInfo> {
        self.extract_with_limit(data, base_address, usize::MAX)
    }

    /// Extract at most `limit` strings, stopping the scan as soon as the
    /// allowance is exhausted.
    pub fn extract_with_limit(
        &self,
        data: &[u8],
        base_address: u64,
        limit: usize,
    ) -> Vec<StringInfo> {
        if limit == 0 {
            return Vec::new();
        }

        let mut strings = Vec::new();
        let mut seen = HashSet::new();

        // Extract ASCII/UTF-8 strings
        self.extract_ascii_utf8(data, base_address, limit, &mut strings, &mut seen);

        // Extract UTF-16 strings
        if strings.len() < limit {
            self.extract_utf16(data, base_address, limit, &mut strings, &mut seen);
        }

        strings
    }

    /// Extract ASCII/UTF-8 strings
    fn extract_ascii_utf8(
        &self,
        data: &[u8],
        base_address: u64,
        limit: usize,
        strings: &mut Vec<StringInfo>,
        seen: &mut HashSet<String>,
    ) {
        let mut start = None;
        let mut current = Vec::new();

        for (i, &byte) in data.iter().enumerate() {
            if (0x20..=0x7E).contains(&byte) {
                // Printable ASCII
                if start.is_none() {
                    start = Some(i);
                }
                current.push(byte);
            } else if byte == 0 {
                // Null terminator
                if let Some(s) = start {
                    if current.len() >= self.min_length && current.len() <= self.max_length {
                        if let Ok(value) = String::from_utf8(current.clone()) {
                            if !seen.contains(&value) {
                                seen.insert(value.clone());
                                strings.push(StringInfo {
                                    address: base_address + s as u64,
                                    value,
                                    encoding: StringEncoding::Ascii,
                                    length: current.len(),
                                });
                                if strings.len() == limit {
                                    return;
                                }
                            }
                        }
                    }
                }
                start = None;
                current.clear();
            } else {
                // Non-printable, non-null
                start = None;
                current.clear();
            }
        }
    }

    /// Extract UTF-16 strings
    fn extract_utf16(
        &self,
        data: &[u8],
        base_address: u64,
        limit: usize,
        strings: &mut Vec<StringInfo>,
        seen: &mut HashSet<String>,
    ) {
        if data.len() < 2 {
            return;
        }

        let mut start = None;
        let mut current = Vec::new();

        for i in (0..data.len() - 1).step_by(2) {
            let byte1 = data[i];
            let byte2 = data[i + 1];

            // Check for UTF-16 LE printable characters
            let code_point = u16::from_le_bytes([byte1, byte2]);

            if (0x20..=0x7E).contains(&code_point) {
                if start.is_none() {
                    start = Some(i);
                }
                current.push(byte1);
                current.push(byte2);
            } else if code_point == 0 {
                // Null terminator
                if let Some(s) = start {
                    if current.len() >= self.min_length * 2 && current.len() <= self.max_length * 2
                    {
                        if let Ok(value) = String::from_utf16(
                            &current
                                .chunks(2)
                                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                .collect::<Vec<_>>(),
                        ) {
                            if !seen.contains(&value) {
                                seen.insert(value.clone());
                                strings.push(StringInfo {
                                    address: base_address + s as u64,
                                    value,
                                    encoding: StringEncoding::Utf16Le,
                                    length: current.len() / 2,
                                });
                                if strings.len() == limit {
                                    return;
                                }
                            }
                        }
                    }
                }
                start = None;
                current.clear();
            } else {
                start = None;
                current.clear();
            }
        }
    }
}

impl Default for StringExtractor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_ascii_c_string() {
        // "hello" + NUL + junk
        let data = b"hello\x00\xff\xff";
        let strings = StringExtractor::new().extract(data, 0x1000);

        let ascii: Vec<_> = strings
            .iter()
            .filter(|s| s.encoding == StringEncoding::Ascii)
            .collect();
        assert_eq!(ascii.len(), 1);
        assert_eq!(ascii[0].value, "hello");
        assert_eq!(ascii[0].address, 0x1000);
        assert_eq!(ascii[0].length, 5);
    }

    #[test]
    fn skips_strings_shorter_than_min_length() {
        // "hi" (2 chars) with min_length=4 should be skipped.
        let data = b"hi\x00world\x00";
        let strings = StringExtractor::new().with_min_length(4).extract(data, 0);

        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();
        assert!(!values.contains(&"hi"));
        assert!(values.contains(&"world"));
    }

    #[test]
    fn deduplicates_repeated_strings() {
        let data = b"test\x00test\x00test\x00";
        let strings = StringExtractor::new().extract(data, 0);

        let test_count = strings.iter().filter(|s| s.value == "test").count();
        assert_eq!(test_count, 1, "duplicate strings must be collapsed");
    }

    #[test]
    fn extracts_utf16_le_string() {
        // "Hi!" in UTF-16 LE + NUL terminator. Must be >= min_length (4) chars.
        // Use "Test" (4 chars) to satisfy default min_length.
        let data = b"T\x00e\x00s\x00t\x00\x00\x00";
        let strings = StringExtractor::new().extract(data, 0x2000);

        let utf16: Vec<_> = strings
            .iter()
            .filter(|s| s.encoding == StringEncoding::Utf16Le)
            .collect();
        assert_eq!(utf16.len(), 1);
        assert_eq!(utf16[0].value, "Test");
        assert_eq!(utf16[0].address, 0x2000);
    }

    #[test]
    fn non_printable_bytes_break_runs() {
        // "abc\x01def\x00" — 0x01 is non-printable; min_length=3 should
        // reject both "abc" and "def" individually, producing no strings.
        let data = b"abc\x01def\x00";
        let strings = StringExtractor::new().with_min_length(4).extract(data, 0);
        assert!(strings.is_empty());
    }

    #[test]
    fn respects_base_address_offset() {
        let data = b"\x00\x00hello\x00";
        let strings = StringExtractor::new().extract(data, 0x400000);
        let hello = strings
            .iter()
            .find(|s| s.value == "hello")
            .expect("string found");
        // starts at offset 2 in data, so 0x400000 + 2.
        assert_eq!(hello.address, 0x400002);
    }

    #[test]
    fn empty_and_tiny_input_produces_nothing() {
        let extractor = StringExtractor::new();
        assert!(extractor.extract(&[], 0).is_empty());
        assert!(extractor.extract(&[0x00], 0).is_empty());
    }

    #[test]
    fn limited_extraction_returns_immediately_for_zero_allowance() {
        let strings = StringExtractor::new().extract_with_limit(b"first\0second\0third\0", 0, 0);

        assert!(strings.is_empty());
    }

    #[test]
    fn limited_extraction_stops_at_the_extractor_boundary() {
        let strings =
            StringExtractor::new().extract_with_limit(b"first\0second\0third\0", 0x1000, 2);

        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].value, "first");
        assert_eq!(strings[1].value, "second");
    }
}
