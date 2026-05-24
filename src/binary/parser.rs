//! Binary format detection and parsing

use crate::utils::error::{Error, Result};
use std::path::Path;

/// Supported binary formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFormat {
    /// PE/EXE (Windows)
    Pe,
    /// ELF (Linux)
    Elf,
    /// Mach-O (macOS)
    MachO,
}

impl BinaryFormat {
    /// Detect binary format from magic bytes
    pub fn from_magic(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 2 {
            return None;
        }

        // PE/EXE: MZ header
        if bytes[0] == 0x4D && bytes[1] == 0x5A {
            return Some(BinaryFormat::Pe);
        }

        // ELF: 0x7F 'E' 'L' 'F'
        if bytes.len() >= 4
            && bytes[0] == 0x7F
            && bytes[1] == b'E'
            && bytes[2] == b'L'
            && bytes[3] == b'F'
        {
            return Some(BinaryFormat::Elf);
        }

        // Mach-O: 0xFEEDFACE or 0xCEFAEDFE (big/little endian)
        if bytes.len() >= 4 {
            let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            // 32-bit: FEEDFACE / CEFAEDFE
            // 64-bit: FEEDFACF / CFFAEDFE
            // Fat:    CAFEBABE (le read -> BEBAFECA)
            if magic == 0xFEEDFACE
                || magic == 0xCEFAEDFE
                || magic == 0xFEEDFACF
                || magic == 0xCFFAEDFE
                || magic == 0xBEBAFECA
            {
                return Some(BinaryFormat::MachO);
            }
        }

        None
    }

    /// Get format name
    pub fn name(&self) -> &'static str {
        match self {
            BinaryFormat::Pe => "PE/EXE",
            BinaryFormat::Elf => "ELF",
            BinaryFormat::MachO => "Mach-O",
        }
    }
}

/// Binary parser trait
pub trait BinaryParser {
    /// Parse binary from bytes
    fn parse(&self, data: &[u8]) -> Result<Box<dyn BinaryInfo>>;

    /// Get the format this parser handles
    fn format(&self) -> BinaryFormat;
}

/// Binary information trait
pub trait BinaryInfo {
    /// Get the format
    fn format(&self) -> BinaryFormat;

    /// Get the architecture
    fn architecture(&self) -> &'static str;

    /// Get entry point address
    fn entry_point(&self) -> u64;

    /// Get sections
    fn sections(&self) -> Vec<SectionInfo>;

    /// Get imports
    fn imports(&self) -> Vec<ImportInfo>;

    /// Get import address table entries when the format exposes them.
    fn import_addresses(&self) -> Vec<ImportAddressInfo> {
        Vec::new()
    }

    /// Get PE data directory entries when the format exposes them.
    fn pe_data_directories(&self) -> Vec<PeDataDirectoryInfo> {
        Vec::new()
    }

    /// Get exports
    fn exports(&self) -> Vec<ExportInfo>;
}

/// Section information
#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u64,
    pub size: u64,
    pub raw_data: Vec<u8>,
    pub characteristics: SectionCharacteristics,
}

/// Section characteristics
#[derive(Debug, Clone, Copy, Default)]
pub struct SectionCharacteristics {
    pub is_code: bool,
    pub is_data: bool,
    pub is_readable: bool,
    pub is_writable: bool,
    pub is_executable: bool,
}

/// Import information
#[derive(Debug, Clone)]
pub struct ImportInfo {
    pub name: String,
    pub functions: Vec<String>,
}

/// Import address table/thunk entry.
#[derive(Debug, Clone)]
pub struct ImportAddressInfo {
    pub library: String,
    pub function: String,
    pub address: u64,
    pub ordinal: Option<u16>,
}

/// PE optional-header data directory entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PeDataDirectoryInfo {
    pub name: String,
    pub virtual_address: u64,
    pub size: u64,
    pub section: Option<String>,
}

/// Export information
#[derive(Debug, Clone)]
pub struct ExportInfo {
    pub name: String,
    pub address: u64,
    pub ordinal: Option<u16>,
}

/// Parse a binary file
pub fn parse_binary(path: &Path) -> Result<Box<dyn BinaryInfo>> {
    let data = std::fs::read(path)?;

    let format = BinaryFormat::from_magic(&data)
        .ok_or_else(|| Error::UnsupportedFormat("Unknown binary format".to_string()))?;

    tracing::info!("Detected format: {}", format.name());

    match format {
        BinaryFormat::Pe => super::pe::PeParser.parse(&data),
        BinaryFormat::Elf => super::elf::ElfParser.parse(&data),
        BinaryFormat::MachO => super::macho::MachOParser.parse(&data),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_pe_from_mz_header() {
        assert_eq!(
            BinaryFormat::from_magic(&[0x4D, 0x5A, 0x90, 0x00]),
            Some(BinaryFormat::Pe)
        );
    }

    #[test]
    fn detects_elf_from_magic() {
        assert_eq!(
            BinaryFormat::from_magic(&[0x7F, b'E', b'L', b'F', 0x02]),
            Some(BinaryFormat::Elf)
        );
    }

    #[test]
    fn detects_macho_both_endians_and_fat() {
        // Little-endian 32-bit Mach-O (0xFEEDFACE LE in file)
        assert_eq!(
            BinaryFormat::from_magic(&[0xCE, 0xFA, 0xED, 0xFE]),
            Some(BinaryFormat::MachO)
        );
        // Little-endian 64-bit Mach-O (0xFEEDFACF LE in file)
        assert_eq!(
            BinaryFormat::from_magic(&[0xCF, 0xFA, 0xED, 0xFE]),
            Some(BinaryFormat::MachO)
        );
        // Fat / universal binary
        assert_eq!(
            BinaryFormat::from_magic(&[0xCA, 0xFE, 0xBA, 0xBE]),
            Some(BinaryFormat::MachO)
        );
    }

    #[test]
    fn returns_none_for_garbage_and_tiny_input() {
        assert_eq!(BinaryFormat::from_magic(&[]), None);
        assert_eq!(BinaryFormat::from_magic(&[0x00]), None);
        assert_eq!(BinaryFormat::from_magic(&[0x00, 0x00, 0x00, 0x00]), None);
    }

    #[test]
    fn format_names_stable() {
        assert_eq!(BinaryFormat::Pe.name(), "PE/EXE");
        assert_eq!(BinaryFormat::Elf.name(), "ELF");
        assert_eq!(BinaryFormat::MachO.name(), "Mach-O");
    }
}
