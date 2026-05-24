//! Error types for the decompiler

use thiserror::Error;

/// Result type alias for the decompiler
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for the decompiler
#[derive(Debug, Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Binary parsing error: {0}")]
    BinaryParse(String),

    #[error("Disassembly error: {0}")]
    Disassembly(String),

    #[error("Analysis error: {0}")]
    Analysis(String),

    #[error("Code generation error: {0}")]
    CodeGeneration(String),

    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),

    #[error("Unsupported architecture: {0}")]
    UnsupportedArchitecture(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages_use_human_readable_prefixes() {
        assert_eq!(
            Error::BinaryParse("bad header".into()).to_string(),
            "Binary parsing error: bad header"
        );
        assert_eq!(
            Error::Disassembly("decoder failed".into()).to_string(),
            "Disassembly error: decoder failed"
        );
        assert_eq!(
            Error::Analysis("missing entry point".into()).to_string(),
            "Analysis error: missing entry point"
        );
        assert_eq!(
            Error::CodeGeneration("unsupported expr".into()).to_string(),
            "Code generation error: unsupported expr"
        );
        assert_eq!(
            Error::UnsupportedFormat("COFF".into()).to_string(),
            "Unsupported format: COFF"
        );
        assert_eq!(
            Error::UnsupportedArchitecture("riscv".into()).to_string(),
            "Unsupported architecture: riscv"
        );
        assert_eq!(
            Error::InvalidInput("empty".into()).to_string(),
            "Invalid input: empty"
        );
    }

    #[test]
    fn io_error_converts_into_decompiler_error_via_from() {
        // The `#[from] std::io::Error` derive guarantees `?` propagation works
        // from any io::Result into a decompiler::Result.
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let wrapped: Error = io_err.into();
        let rendered = wrapped.to_string();
        assert!(rendered.starts_with("IO error: "), "got: {rendered}");
        assert!(rendered.contains("missing"));
        assert!(matches!(wrapped, Error::Io(_)));
    }

    #[test]
    fn result_type_alias_propagates_through_question_mark() {
        // Sanity that the type alias `Result<T>` composes with `?` against the
        // From conversion above. This is what the rest of the crate relies on.
        use std::io::Read as _;

        fn read_then_parse(buf: &[u8]) -> Result<usize> {
            let cursor = std::io::Cursor::new(buf);
            let mut sink = Vec::new();
            std::io::copy(&mut cursor.take(8), &mut sink)?; // io::Error → Error via ?
            Ok(sink.len())
        }
        assert_eq!(read_then_parse(b"abc").unwrap(), 3);
    }
}
