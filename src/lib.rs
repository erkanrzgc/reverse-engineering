//! Reverse Engineering - binary-to-source decompilation tools.
//!
//! This library provides functionality to decompile compiled binaries
//! back to readable source code.

pub mod analysis;
pub mod binary;
pub mod decompiler;
pub mod disasm;
pub mod utils;

pub use utils::error::{Error, Result};
