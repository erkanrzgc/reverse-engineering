//! Integration tests for the `binary` layer against vendored real-world
//! ELF, PE, and Mach-O fixtures.
//!
//! ELF and PE fixtures are read from `tests/fixtures/binary/` on disk; the
//! Mach-O fixture is embedded as a `pub const` byte array (see the upstream
//! convention in `goblin`'s own `tests/macho.rs`). All fixtures and their
//! licensing are documented in `tests/fixtures/binary/ATTRIBUTION.md`.
//!
//! These tests exercise the actual format parsers (`ElfParser`, `PeParser`,
//! `MachOParser`) end-to-end via the public `BinaryParser` / `BinaryInfo`
//! contract, complementing the unit tests in `src/binary/*.rs`.

use decompiler::binary::{parse_binary, BinaryFormat};
use std::path::PathBuf;

#[path = "fixtures/binary/macho64_deadbeef.rs"]
mod macho_fixture;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("binary")
        .join(name)
}

// ---- magic byte sniffer (BinaryFormat::from_magic) ----

#[test]
fn from_magic_returns_none_for_input_shorter_than_four_bytes() {
    // Format::from_magic must not index out of bounds on truncated inputs.
    assert!(BinaryFormat::from_magic(&[]).is_none());
    assert!(BinaryFormat::from_magic(&[0x7F]).is_none());
    assert!(BinaryFormat::from_magic(&[0x7F, b'E', b'L']).is_none());
}

#[test]
fn from_magic_returns_none_for_unknown_signature() {
    // A buffer that is neither MZ, ELF, nor any Mach-O magic should be rejected
    // rather than silently mis-detected.
    assert!(BinaryFormat::from_magic(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]).is_none());
    assert!(BinaryFormat::from_magic(b"ZIPP\x00\x00").is_none());
}

// ---- ELF (real fixtures from goblin) ----

#[test]
fn parses_64bit_elf_shared_object_fixture() {
    let info = parse_binary(&fixture("hello.so")).expect("hello.so must parse as ELF64");
    assert_eq!(info.format(), BinaryFormat::Elf);
    assert_eq!(info.architecture(), "x64");

    // A real shared object always has at least one section.
    assert!(
        !info.sections().is_empty(),
        "expected at least one ELF section in hello.so"
    );
}

#[test]
fn parses_32bit_elf_shared_object_fixture() {
    let info = parse_binary(&fixture("hello32.so")).expect("hello32.so must parse as ELF32");
    assert_eq!(info.format(), BinaryFormat::Elf);
    assert_eq!(info.architecture(), "x86");
}

// ---- PE (real fixture from goblin) ----

#[test]
fn parses_minimal_pe64_executable_fixture() {
    let info =
        parse_binary(&fixture("lld_no_tls_64.exe")).expect("lld_no_tls_64.exe must parse as PE");
    assert_eq!(info.format(), BinaryFormat::Pe);
    // The lld-produced fixture is a PE32+ binary, so the parser must report x64.
    assert_eq!(info.architecture(), "x64");
}

// ---- Mach-O (inline DEADBEEF byte array) ----

#[test]
fn detects_macho_format_from_inline_deadbeef_bytes() {
    let bytes = &macho_fixture::DEADBEEF_MACH_64[..];

    // Sanity: first 4 bytes are the little-endian 64-bit Mach-O magic 0xFEEDFACF.
    assert_eq!(&bytes[..4], &[0xCF, 0xFA, 0xED, 0xFE]);

    let format =
        BinaryFormat::from_magic(bytes).expect("DEADBEEF bytes must sniff as a Mach-O image");
    assert_eq!(format, BinaryFormat::MachO);
}

#[test]
fn macho_parser_accepts_inline_deadbeef_bytes() {
    use decompiler::binary::parser::BinaryParser;
    let parser = decompiler::binary::macho::MachOParser;
    let info = parser
        .parse(&macho_fixture::DEADBEEF_MACH_64[..])
        .expect("MachOParser must accept the DEADBEEF fixture");

    assert_eq!(info.format(), BinaryFormat::MachO);
    assert_eq!(
        info.architecture(),
        "x64",
        "DEADBEEF fixture is the 64-bit Mach-O sample from goblin"
    );
}
