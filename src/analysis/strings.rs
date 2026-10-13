//! String extraction from binary data

use std::collections::BTreeMap;

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

/// Select one deterministic interpretation for address-based references and
/// C symbols while the report retains every extracted encoding occurrence.
pub fn canonical_strings_by_address(strings: &[StringInfo]) -> BTreeMap<u64, &StringInfo> {
    let mut by_address: BTreeMap<u64, &StringInfo> = BTreeMap::new();
    for string in strings {
        by_address
            .entry(string.address)
            .and_modify(|current| {
                if (
                    encoding_preference(string.encoding),
                    &string.value,
                    string.length,
                ) < (
                    encoding_preference(current.encoding),
                    &current.value,
                    current.length,
                ) {
                    *current = string;
                }
            })
            .or_insert(string);
    }
    by_address
}

fn encoding_preference(encoding: StringEncoding) -> u8 {
    match encoding {
        StringEncoding::Ascii => 0,
        StringEncoding::Utf8 => 1,
        StringEncoding::Utf16Le => 2,
        StringEncoding::Utf16Be => 3,
    }
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

    /// Return at most `limit` occurrences and whether additional occurrences
    /// were omitted. Scanning stops after a single overflow occurrence, so
    /// temporary result growth is bounded by `limit + 1`.
    pub fn extract_bounded(
        &self,
        data: &[u8],
        base_address: u64,
        limit: usize,
    ) -> (Vec<StringInfo>, bool) {
        let mut strings = self.extract_with_limit(data, base_address, limit.saturating_add(1));
        let truncated = strings.len() > limit;
        strings.truncate(limit);
        (strings, truncated)
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
        // Extract ASCII/UTF-8 strings
        self.extract_ascii_utf8(data, base_address, limit, &mut strings);

        // Extract UTF-16 strings
        if strings.len() < limit {
            self.extract_utf16(data, base_address, limit, &mut strings);
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
    ) {
        let mut start = None;
        let mut current = String::new();
        let mut character_count = 0usize;
        let mut i = 0;
        while i < data.len() {
            if data[i] == 0 {
                if let Some(s) = start {
                    self.push_string(
                        s,
                        base_address,
                        &current,
                        character_count,
                        if current.is_ascii() {
                            StringEncoding::Ascii
                        } else {
                            StringEncoding::Utf8
                        },
                        strings,
                    );
                    if strings.len() == limit {
                        return;
                    }
                }
                start = None;
                current.clear();
                character_count = 0;
                i += 1;
                continue;
            }

            let width = match data[i] {
                0x20..=0x7E => 1,
                0xC2..=0xDF => 2,
                0xE0..=0xEF => 3,
                0xF0..=0xF4 => 4,
                _ => 0,
            };
            let character = data
                .get(i..i.saturating_add(width))
                .filter(|_| width != 0)
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .and_then(|text| text.chars().next())
                .filter(|ch| !ch.is_control());
            if let Some(character) = character {
                start.get_or_insert(i);
                character_count = character_count.saturating_add(1);
                // Continue scanning overlong candidates without accumulating bytes.
                if character_count <= self.max_length {
                    current.push(character);
                }
                i += width;
            } else {
                start = None;
                current.clear();
                character_count = 0;
                i += 1;
            }
        }
    }

    /// Extract UTF-16 strings at either alignment. Latin-1 code units and
    /// valid surrogate pairs provide endian evidence; arbitrary printable
    /// BMP pairs alone are ambiguous with ordinary byte strings.
    fn extract_utf16(
        &self,
        data: &[u8],
        base_address: u64,
        limit: usize,
        strings: &mut Vec<StringInfo>,
    ) {
        for encoding in [StringEncoding::Utf16Le, StringEncoding::Utf16Be] {
            for alignment in 0..2 {
                let mut start = None;
                let mut current = String::new();
                let mut character_count = 0usize;
                let mut encoding_evidence = 0usize;
                let mut i = alignment;
                while i + 1 < data.len() {
                    let unit = utf16_unit(data, i, encoding);
                    if unit == 0 {
                        if let Some(s) =
                            start.filter(|_| encoding_evidence >= character_count.div_ceil(2))
                        {
                            self.push_string(
                                s,
                                base_address,
                                &current,
                                character_count,
                                encoding,
                                strings,
                            );
                            if strings.len() == limit {
                                return;
                            }
                        }
                        start = None;
                        current.clear();
                        character_count = 0;
                        encoding_evidence = 0;
                        i += 2;
                        continue;
                    }
                    let (character, width) = if (0xD800..=0xDBFF).contains(&unit)
                        && i + 3 < data.len()
                    {
                        let low = utf16_unit(data, i + 2, encoding);
                        let character = if (0xDC00..=0xDFFF).contains(&low) {
                            char::from_u32(
                                0x10000 + (((unit as u32 - 0xD800) << 10) | (low as u32 - 0xDC00)),
                            )
                        } else {
                            None
                        };
                        (character, 4)
                    } else {
                        (char::from_u32(unit as u32), 2)
                    };
                    if let Some(character) = character.filter(|ch| !ch.is_control()) {
                        start.get_or_insert(i);
                        character_count = character_count.saturating_add(1);
                        if unit <= 0xFF || width == 4 {
                            encoding_evidence = encoding_evidence.saturating_add(1);
                        }
                        if character_count <= self.max_length {
                            current.push(character);
                        }
                        i += width;
                    } else {
                        start = None;
                        current.clear();
                        character_count = 0;
                        encoding_evidence = 0;
                        i += 2;
                    }
                }
            }
        }
    }

    fn push_string(
        &self,
        offset: usize,
        base_address: u64,
        value: &str,
        length: usize,
        encoding: StringEncoding,
        strings: &mut Vec<StringInfo>,
    ) {
        if length < self.min_length || length > self.max_length {
            return;
        }
        let Some(address) = base_address.checked_add(offset as u64) else {
            return;
        };
        let value = value.to_string();
        strings.push(StringInfo {
            address,
            value,
            encoding,
            length,
        });
    }
}

fn utf16_unit(data: &[u8], offset: usize, encoding: StringEncoding) -> u16 {
    let bytes = [data[offset], data[offset + 1]];
    if encoding == StringEncoding::Utf16Le {
        u16::from_le_bytes(bytes)
    } else {
        u16::from_be_bytes(bytes)
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
    fn preserves_repeated_string_locations() {
        let data = b"test\x00test\x00test\x00";
        let strings = StringExtractor::new().extract(data, 0);

        let test_count = strings.iter().filter(|s| s.value == "test").count();
        assert_eq!(test_count, 3, "each string address must be preserved");
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
