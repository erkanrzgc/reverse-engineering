//! Binary format parsing module

pub mod elf;
pub mod macho;
pub mod parser;
pub mod pe;

pub use parser::{
    parse_binary, parse_binary_bytes, BinaryFormat, BinaryParser, PeDataDirectoryInfo,
};
