//! Reverse Engineering - binary-to-source decompilation tools.
//!
//! This library provides functionality to decompile compiled binaries
//! back to readable source code.

pub mod analysis;
pub mod binary;
pub mod decompiler;
pub mod disasm;
pub mod engine;
pub mod output;
pub mod utils;

pub use engine::{
    AnalysisConfig, AnalysisDiagnostic, AnalysisEngine, AnalysisError, AnalysisResult,
    AnalysisStatus, BinarySummary, DiagnosticCode, DiagnosticSeverity, DiagnosticStage,
    OutputSelection, ResourceLimits,
};
pub use utils::error::{Error, Result};
