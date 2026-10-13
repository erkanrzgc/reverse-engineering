//! Stable library boundary for the production analysis pipeline.

use crate::analysis::functions::FunctionDetectionInputs;
use crate::analysis::runtime_artifacts::RuntimeArtifactLimits;
use crate::analysis::{
    AnalysisReportBuilder, AnalysisReportInputs, AnalysisReportPackage, FunctionDetector,
    RuntimeArtifactExtractor, RuntimeArtifactInputs, RuntimeArtifactResult, RuntimeDetectionInputs,
    RuntimeDetector, RuntimeReportBuilder, RuntimeReportInputs, StringExtractor,
};
use crate::binary::{parse_binary_bytes, BinaryFormat};
use crate::decompiler::{
    annotate_string_references_with_instructions, escape_c_string, import_function_declarations,
    lift_functions_with_imports, recover_function_signatures, sanitize_c_identifier,
    sanitize_c_line_comment, structure_functions_with_cfg, CGenerator, CGeneratorConfig, Function,
    OptimizationLevel, Optimizer,
};
use crate::disasm::{ArmDisassembler, ControlFlowGraph, Instruction, X86Disassembler};
use crate::utils::error::Error as PipelineError;
use serde::Serialize;
use std::fmt;
use std::io::Read;
use std::path::Path;

const SCHEMA_VERSION: &str = "1.0";

/// Final outcome of a non-fatal analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisStatus {
    Complete,
    Partial,
    Failed,
}

/// Pipeline stage associated with a diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticStage {
    Input,
    Parse,
    Disassembly,
    Strings,
    RuntimeArtifacts,
    Decompilation,
    Internal,
}

/// Severity of a structured diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Warning,
    Error,
}

/// Stable machine-readable diagnostic code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCode {
    EmptyInput,
    InputReadFailed,
    InputLimitExceeded,
    UnsupportedFormat,
    ParseFailed,
    NoCodeSections,
    UnsupportedArchitecture,
    DisassemblyFailed,
    StringLimitExceeded,
    ArtifactLimitExceeded,
    InternalFailure,
}

/// Structured warning or error emitted by the engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnalysisDiagnostic {
    pub stage: DiagnosticStage,
    pub severity: DiagnosticSeverity,
    pub code: DiagnosticCode,
    pub message: String,
}

impl fmt::Display for AnalysisDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:?}/{:?}: {}",
            self.stage, self.code, self.message
        )
    }
}

/// Fatal failure that prevented a useful analysis result.
#[derive(Debug)]
pub struct AnalysisError {
    diagnostic: AnalysisDiagnostic,
}

impl AnalysisError {
    fn fatal(stage: DiagnosticStage, code: DiagnosticCode, message: impl Into<String>) -> Self {
        Self {
            diagnostic: AnalysisDiagnostic {
                stage,
                severity: DiagnosticSeverity::Error,
                code,
                message: message.into(),
            },
        }
    }

    pub fn status(&self) -> AnalysisStatus {
        AnalysisStatus::Failed
    }

    pub fn code(&self) -> DiagnosticCode {
        self.diagnostic.code
    }

    pub fn diagnostic(&self) -> &AnalysisDiagnostic {
        &self.diagnostic
    }
}

impl fmt::Display for AnalysisError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.diagnostic.fmt(formatter)
    }
}

impl std::error::Error for AnalysisError {}

/// Optional payloads returned by an analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputSelection {
    generated_c: bool,
    report: bool,
    runtime_artifacts: bool,
}

impl OutputSelection {
    pub const fn all() -> Self {
        Self {
            generated_c: true,
            report: true,
            runtime_artifacts: true,
        }
    }

    pub const fn report_only() -> Self {
        Self {
            generated_c: false,
            report: true,
            runtime_artifacts: false,
        }
    }

    pub const fn generated_c_only() -> Self {
        Self {
            generated_c: true,
            report: false,
            runtime_artifacts: false,
        }
    }

    pub const fn none() -> Self {
        Self {
            generated_c: false,
            report: false,
            runtime_artifacts: false,
        }
    }

    pub const fn with_generated_c(mut self, enabled: bool) -> Self {
        self.generated_c = enabled;
        self
    }

    pub const fn with_report(mut self, enabled: bool) -> Self {
        self.report = enabled;
        self
    }

    pub const fn with_runtime_artifacts(mut self, enabled: bool) -> Self {
        self.runtime_artifacts = enabled;
        self
    }

    pub const fn includes_generated_c(self) -> bool {
        self.generated_c
    }

    pub const fn includes_report(self) -> bool {
        self.report
    }

    pub const fn includes_runtime_artifacts(self) -> bool {
        self.runtime_artifacts
    }
}

impl Default for OutputSelection {
    fn default() -> Self {
        Self::all()
    }
}

/// Resource ceilings applied before or during analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceLimits {
    pub max_input_bytes: u64,
    pub max_extracted_strings: usize,
    pub max_runtime_artifacts: usize,
    pub max_runtime_artifact_bytes: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 512 * 1024 * 1024,
            max_extracted_strings: 100_000,
            max_runtime_artifacts: 1024,
            max_runtime_artifact_bytes: 16 * 1024 * 1024,
        }
    }
}

/// Configuration for one deterministic analysis.
#[derive(Debug, Clone, Copy)]
pub struct AnalysisConfig {
    pub optimization: OptimizationLevel,
    pub outputs: OutputSelection,
    pub limits: ResourceLimits,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            optimization: OptimizationLevel::Basic,
            outputs: OutputSelection::default(),
            limits: ResourceLimits::default(),
        }
    }
}

/// Small, stable identity and scale summary for the analyzed binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BinarySummary {
    pub input_path: String,
    pub format: String,
    pub architecture: String,
    pub entry_point: u64,
    pub input_bytes: u64,
    pub code_section_count: usize,
    pub instruction_count: usize,
    pub function_count: usize,
    pub string_count: usize,
}

/// Serializable v1 analysis envelope.
#[derive(Debug, Clone, Serialize)]
pub struct AnalysisResult {
    pub schema_version: String,
    pub status: AnalysisStatus,
    pub binary: BinarySummary,
    pub generated_c: Option<String>,
    pub report: Option<AnalysisReportPackage>,
    pub runtime_artifacts: Option<RuntimeArtifactResult>,
    pub diagnostics: Vec<AnalysisDiagnostic>,
}

/// Stateless entry point for the production reverse-engineering pipeline.
pub struct AnalysisEngine;

impl AnalysisEngine {
    pub fn analyze_path(
        path: &Path,
        config: &AnalysisConfig,
    ) -> Result<AnalysisResult, AnalysisError> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Self::analyze_path_inner(path, config)
        }))
        .unwrap_or_else(|_| {
            Err(AnalysisError::fatal(
                DiagnosticStage::Internal,
                DiagnosticCode::InternalFailure,
                format!("analysis panicked while processing {}", path.display()),
            ))
        })
    }

    fn analyze_path_inner(
        path: &Path,
        config: &AnalysisConfig,
    ) -> Result<AnalysisResult, AnalysisError> {
        let file = std::fs::File::open(path).map_err(|error| {
            AnalysisError::fatal(
                DiagnosticStage::Input,
                DiagnosticCode::InputReadFailed,
                format!("failed to open {}: {error}", path.display()),
            )
        })?;
        let read_limit = config.limits.max_input_bytes.saturating_add(1);
        let mut bytes = Vec::new();
        file.take(read_limit)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                AnalysisError::fatal(
                    DiagnosticStage::Input,
                    DiagnosticCode::InputReadFailed,
                    format!("failed to read {}: {error}", path.display()),
                )
            })?;
        let input_bytes = u64::try_from(bytes.len()).map_err(|_| {
            AnalysisError::fatal(
                DiagnosticStage::Input,
                DiagnosticCode::InputLimitExceeded,
                format!(
                    "input {} cannot fit within a u64 byte count",
                    path.display()
                ),
            )
        })?;
        if input_bytes > config.limits.max_input_bytes {
            return Err(AnalysisError::fatal(
                DiagnosticStage::Input,
                DiagnosticCode::InputLimitExceeded,
                format!(
                    "input {} exceeds the {} byte limit",
                    path.display(),
                    config.limits.max_input_bytes
                ),
            ));
        }
        if bytes.is_empty() {
            return Err(AnalysisError::fatal(
                DiagnosticStage::Input,
                DiagnosticCode::EmptyInput,
                format!("input {} is empty", path.display()),
            ));
        }
        if BinaryFormat::from_magic(&bytes).is_none() {
            return Err(AnalysisError::fatal(
                DiagnosticStage::Parse,
                DiagnosticCode::UnsupportedFormat,
                format!("input {} is not a supported binary format", path.display()),
            ));
        }

        let binary = parse_binary_bytes(&bytes).map_err(|error| {
            let code = if matches!(error, PipelineError::UnsupportedFormat(_)) {
                DiagnosticCode::UnsupportedFormat
            } else {
                DiagnosticCode::ParseFailed
            };
            AnalysisError::fatal(
                DiagnosticStage::Parse,
                code,
                format!("failed to parse {}: {error}", path.display()),
            )
        })?;
        let mut sections = binary.sections();
        sections.sort_by(|left, right| {
            left.virtual_address
                .cmp(&right.virtual_address)
                .then_with(|| left.name.cmp(&right.name))
        });
        let code_sections = sections
            .iter()
            .filter(|section| section.characteristics.is_code)
            .collect::<Vec<_>>();
        if code_sections.is_empty() {
            return Err(AnalysisError::fatal(
                DiagnosticStage::Disassembly,
                DiagnosticCode::NoCodeSections,
                format!("{} has no executable code sections", path.display()),
            ));
        }

        let architecture = binary.architecture();
        if let Some(reason) = binary.unsupported_disassembly_reason() {
            return Err(AnalysisError::fatal(
                DiagnosticStage::Disassembly,
                DiagnosticCode::UnsupportedArchitecture,
                reason,
            ));
        }
        for pair in code_sections.windows(2) {
            let end = pair[0]
                .virtual_address
                .checked_add(pair[0].raw_data.len() as u64)
                .ok_or_else(|| {
                    AnalysisError::fatal(
                        DiagnosticStage::Disassembly,
                        DiagnosticCode::DisassemblyFailed,
                        "executable section address range overflows",
                    )
                })?;
            if end > pair[1].virtual_address {
                return Err(AnalysisError::fatal(
                    DiagnosticStage::Disassembly,
                    DiagnosticCode::DisassemblyFailed,
                    format!("overlapping executable sections {} and {} have ambiguous instruction addresses", pair[0].name, pair[1].name),
                ));
            }
        }
        let mut instructions = Vec::new();
        for section in &code_sections {
            let section_instructions =
                disassemble_section(architecture, &section.raw_data, section.virtual_address)
                    .map_err(|error| {
                        let code = if matches!(error, PipelineError::UnsupportedArchitecture(_)) {
                            DiagnosticCode::UnsupportedArchitecture
                        } else {
                            DiagnosticCode::DisassemblyFailed
                        };
                        AnalysisError::fatal(
                            DiagnosticStage::Disassembly,
                            code,
                            format!(
                                "failed to disassemble section {} in {}: {error}",
                                section.name,
                                path.display()
                            ),
                        )
                    })?;
            instructions.extend(section_instructions);
        }
        if instructions.is_empty() {
            return Err(AnalysisError::fatal(
                DiagnosticStage::Disassembly,
                DiagnosticCode::DisassemblyFailed,
                format!("disassembly of {} produced no instructions", path.display()),
            ));
        }

        let mut exports = binary.exports();
        exports
            .sort_by(|left, right| (left.address, &left.name).cmp(&(right.address, &right.name)));
        let imports = binary.imports();
        let import_addresses = binary.import_addresses();
        let functions = FunctionDetector::new().detect(FunctionDetectionInputs {
            instructions: &instructions,
            entry_point: binary.entry_point(),
            exports: &exports,
            imports: &imports,
            architecture,
        });

        let (mut strings, string_limit_hit) =
            extract_strings(&sections, config.limits.max_extracted_strings);
        strings.sort_by(|left, right| {
            left.address
                .cmp(&right.address)
                .then_with(|| left.value.cmp(&right.value))
        });
        let mut diagnostics = Vec::new();
        if string_limit_hit {
            diagnostics.push(AnalysisDiagnostic {
                stage: DiagnosticStage::Strings,
                severity: DiagnosticSeverity::Warning,
                code: DiagnosticCode::StringLimitExceeded,
                message: format!(
                    "string extraction reached the configured limit of {}",
                    config.limits.max_extracted_strings
                ),
            });
        }

        let needs_runtime_analysis =
            config.outputs.generated_c || config.outputs.report || config.outputs.runtime_artifacts;
        let runtime_matches = if needs_runtime_analysis {
            RuntimeDetector::new().detect(RuntimeDetectionInputs {
                sections: &sections,
                imports: &imports,
                exports: &exports,
                strings: &strings,
            })
        } else {
            Vec::new()
        };
        let runtime_reports = config.outputs.generated_c.then(|| {
            RuntimeReportBuilder::new().build(RuntimeReportInputs {
                runtime_matches: &runtime_matches,
                sections: &sections,
                strings: &strings,
            })
        });
        let cfg = (config.outputs.generated_c || config.outputs.report)
            .then(|| ControlFlowGraph::from_instructions(&instructions));
        let input_path = path.to_string_lossy().into_owned();

        let report = if config.outputs.report {
            let Some(cfg) = cfg.as_ref() else {
                return Err(AnalysisError::fatal(
                    DiagnosticStage::Internal,
                    DiagnosticCode::InternalFailure,
                    "report selection did not initialize a control-flow graph",
                ));
            };
            Some(
                AnalysisReportBuilder::new()
                    .build(AnalysisReportInputs {
                        input_path: &input_path,
                        format: binary.format().name(),
                        architecture,
                        entry_point: binary.entry_point(),
                        instruction_count: instructions.len(),
                        basic_block_count: cfg.blocks().len(),
                        sections: &sections,
                        functions: &functions,
                        strings: &strings,
                        imports: &imports,
                        import_addresses: &import_addresses,
                        exports: &exports,
                        runtime_matches: &runtime_matches,
                    })
                    .with_pe_data_directories(&binary.pe_data_directories()),
            )
        } else {
            None
        };

        let runtime_artifacts = config.outputs.runtime_artifacts.then(|| {
            let mut result = RuntimeArtifactExtractor::new().extract_with_limits(
                RuntimeArtifactInputs {
                    runtime_matches: &runtime_matches,
                    sections: &sections,
                    imports: &imports,
                    exports: &exports,
                    strings: &strings,
                },
                RuntimeArtifactLimits {
                    max_artifacts: config.limits.max_runtime_artifacts,
                    max_captured_bytes: config.limits.max_runtime_artifact_bytes,
                },
            );
            result.artifacts.sort_by(|left, right| {
                left.virtual_address
                    .cmp(&right.virtual_address)
                    .then_with(|| left.name.cmp(&right.name))
                    .then_with(|| left.source.cmp(&right.source))
            });
            result
        });
        if runtime_artifacts
            .as_ref()
            .is_some_and(|result| result.truncated)
        {
            diagnostics.push(AnalysisDiagnostic {
                stage: DiagnosticStage::RuntimeArtifacts,
                severity: DiagnosticSeverity::Warning,
                code: DiagnosticCode::ArtifactLimitExceeded,
                message: "runtime artifact extraction reached a configured count, captured-byte, or candidate-byte limit; inspect the manifest truncation reasons".to_string(),
            });
        }

        let generated_c = if config.outputs.generated_c {
            let (Some(cfg), Some(runtime_reports)) = (cfg.as_ref(), runtime_reports.as_deref())
            else {
                return Err(AnalysisError::fatal(
                    DiagnosticStage::Internal,
                    DiagnosticCode::InternalFailure,
                    "generated C selection did not initialize its supporting analyses",
                ));
            };
            Some(generate_c(GenerationInputs {
                input_path: &input_path,
                format: binary.format().name(),
                architecture,
                entry_point: binary.entry_point(),
                functions: &functions,
                import_addresses: &import_addresses,
                strings: &strings,
                runtime_matches: &runtime_matches,
                runtime_reports,
                cfg,
                optimization: config.optimization,
            }))
        } else {
            None
        };

        Ok(AnalysisResult {
            schema_version: SCHEMA_VERSION.to_string(),
            status: if diagnostics.is_empty() {
                AnalysisStatus::Complete
            } else {
                AnalysisStatus::Partial
            },
            binary: BinarySummary {
                input_path,
                format: binary.format().name().to_string(),
                architecture: architecture.to_string(),
                entry_point: binary.entry_point(),
                input_bytes,
                code_section_count: code_sections.len(),
                instruction_count: instructions.len(),
                function_count: functions.len(),
                string_count: strings.len(),
            },
            generated_c,
            report,
            runtime_artifacts,
            diagnostics,
        })
    }
}

fn disassemble_section(
    architecture: &str,
    bytes: &[u8],
    address: u64,
) -> crate::Result<Vec<Instruction>> {
    match architecture {
        "x86" => Ok(X86Disassembler::new_x86()
            .disassemble(bytes, address)?
            .into_iter()
            .map(Instruction::X86)
            .collect()),
        "x64" => Ok(X86Disassembler::new_x64()
            .disassemble(bytes, address)?
            .into_iter()
            .map(Instruction::X86)
            .collect()),
        "ARM" => Ok(ArmDisassembler::new_arm()?
            .disassemble(bytes, address)?
            .into_iter()
            .map(Instruction::Arm)
            .collect()),
        "ARM64" => Ok(ArmDisassembler::new_arm64()?
            .disassemble(bytes, address)?
            .into_iter()
            .map(Instruction::Arm)
            .collect()),
        other => Err(PipelineError::UnsupportedArchitecture(other.to_string())),
    }
}

fn extract_strings(
    sections: &[crate::binary::parser::SectionInfo],
    limit: usize,
) -> (Vec<crate::analysis::StringInfo>, bool) {
    let extractor = StringExtractor::new();
    let mut strings = Vec::new();
    let mut limit_hit = false;

    for section in sections
        .iter()
        .filter(|section| section.characteristics.is_data)
    {
        let remaining = limit.saturating_sub(strings.len());
        let (extracted, allowance_exhausted) =
            extractor.extract_bounded(&section.raw_data, section.virtual_address, remaining);
        strings.extend(extracted);
        if allowance_exhausted {
            limit_hit = true;
            break;
        }
    }

    (strings, limit_hit)
}

struct GenerationInputs<'a> {
    input_path: &'a str,
    format: &'a str,
    architecture: &'a str,
    entry_point: u64,
    functions: &'a [crate::analysis::FunctionInfo],
    import_addresses: &'a [crate::binary::parser::ImportAddressInfo],
    strings: &'a [crate::analysis::StringInfo],
    runtime_matches: &'a [crate::analysis::RuntimeMatch],
    runtime_reports: &'a [crate::analysis::RuntimeReport],
    cfg: &'a ControlFlowGraph,
    optimization: OptimizationLevel,
}

fn generate_c(inputs: GenerationInputs<'_>) -> String {
    let mut output = String::new();
    output.push_str("// Decompiled by reverse-engineering\n");
    output.push_str(&format!(
        "// Binary: {}\n",
        sanitize_c_line_comment(inputs.input_path)
    ));
    output.push_str(&format!(
        "// Format: {}\n",
        sanitize_c_line_comment(inputs.format)
    ));
    output.push_str(&format!(
        "// Architecture: {}\n",
        sanitize_c_line_comment(inputs.architecture)
    ));
    output.push_str(&format!("// Entry point: 0x{:X}\n", inputs.entry_point));
    if inputs.runtime_matches.is_empty() {
        output.push_str("// Runtime hints: none detected\n\n");
    } else {
        output.push_str("// Runtime hints:\n");
        for runtime in inputs.runtime_matches {
            output.push_str(&format!(
                "// - {} ({}%): {}\n",
                sanitize_c_line_comment(runtime.name),
                runtime.confidence,
                sanitize_c_line_comment(&runtime.evidence.join("; "))
            ));
            output.push_str(&format!(
                "//   Guidance: {}\n",
                sanitize_c_line_comment(runtime.guidance)
            ));
        }
        if !inputs.runtime_reports.is_empty() {
            output.push_str("// Runtime reports:\n");
            for report in inputs.runtime_reports {
                output.push_str(&format!(
                    "// - {}: {}\n",
                    sanitize_c_line_comment(&report.title),
                    sanitize_c_line_comment(&report.summary)
                ));
                for artifact in &report.artifacts {
                    output.push_str(&format!(
                        "//   Artifact: {} - {}\n",
                        sanitize_c_line_comment(&artifact.name),
                        sanitize_c_line_comment(&artifact.detail)
                    ));
                }
                for action in &report.actions {
                    output.push_str(&format!(
                        "//   Action: {} - {}\n",
                        sanitize_c_line_comment(&action.label),
                        sanitize_c_line_comment(&action.detail)
                    ));
                }
            }
        }
        output.push('\n');
    }

    output.push_str("#include <stdint.h>\n");
    output.push_str("#include <stddef.h>\n\n");
    if !inputs.strings.is_empty() {
        output.push_str("// String literals\n");
        for string in
            crate::analysis::strings::canonical_strings_by_address(inputs.strings).values()
        {
            output.push_str(&format!(
                "const char str_{:X}[] = \"{}\";\n",
                string.address,
                escape_c_string(&string.value)
            ));
        }
        output.push('\n');
    }

    if !inputs.import_addresses.is_empty() {
        output.push_str("// Import declarations\n");
        for import in import_function_declarations(inputs.import_addresses) {
            output.push_str(&format!(
                "// import: {}!{} @ 0x{:X}\n",
                sanitize_c_line_comment(&import.library),
                sanitize_c_line_comment(&import.function),
                import.address
            ));
            output.push_str(&format!("void {}(void);\n", import.c_name));
        }
        output.push('\n');
    }

    let mut ast_functions = lift_functions_with_imports(inputs.functions, inputs.import_addresses);
    structure_functions_with_cfg(&mut ast_functions, inputs.cfg);
    recover_function_signatures(
        &mut ast_functions,
        inputs.functions,
        inputs.format,
        inputs.architecture,
    );
    annotate_string_references_with_instructions(
        &mut ast_functions,
        inputs.strings,
        inputs.functions,
    );
    let optimizer = Optimizer::new(inputs.optimization);
    for function in &mut ast_functions {
        optimizer.optimize_function(function);
    }

    output.push_str("// Function declarations\n");
    for (info, function) in inputs.functions.iter().zip(ast_functions.iter()) {
        output.push_str(&format!(
            "// 0x{:X}{}\n",
            info.address,
            if info.is_export { " (export)" } else { "" }
        ));
        output.push_str(&function_prototype(function));
        output.push('\n');
    }
    output.push('\n');

    output.push_str("// Function implementations\n");
    let mut generator = CGenerator::new(CGeneratorConfig::default());
    for (info, function) in inputs.functions.iter().zip(ast_functions.iter()) {
        output.push_str(&format!(
            "// Function: {} at 0x{:X} (size: {} bytes)\n",
            sanitize_c_line_comment(&info.name),
            info.address,
            info.size
        ));
        output.push_str(&generator.generate_function(function));
        output.push('\n');
    }

    output
}

fn function_prototype(function: &Function) -> String {
    let parameters = if function.parameters.is_empty() {
        "void".to_string()
    } else {
        let mut parameters = function
            .parameters
            .iter()
            .map(|parameter| {
                format!(
                    "{} {}",
                    parameter.type_info.to_c_type(),
                    sanitize_c_identifier(&parameter.name, "arg")
                )
            })
            .collect::<Vec<_>>();
        if function.is_variadic {
            parameters.push("...".to_string());
        }
        parameters.join(", ")
    };

    format!(
        "{} {}({});",
        function.return_type.to_c_type(),
        sanitize_c_identifier(&function.name, "sub"),
        parameters
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::strings::{StringEncoding, StringInfo};

    #[test]
    fn alternate_string_decodings_do_not_redeclare_the_same_c_symbol() {
        let strings = [
            StringInfo {
                address: 0x2000,
                value: "first decoding".into(),
                encoding: StringEncoding::Ascii,
                length: 14,
            },
            StringInfo {
                address: 0x2000,
                value: "alternate decoding".into(),
                encoding: StringEncoding::Utf16Le,
                length: 18,
            },
        ];
        let cfg = ControlFlowGraph::from_instructions(&[]);
        let c = generate_c(GenerationInputs {
            input_path: "fixture",
            format: "PE/EXE",
            architecture: "x64",
            entry_point: 0,
            functions: &[],
            import_addresses: &[],
            strings: &strings,
            runtime_matches: &[],
            runtime_reports: &[],
            cfg: &cfg,
            optimization: OptimizationLevel::None,
        });
        assert_eq!(
            c.matches("const char str_2000[]").count(),
            1,
            "ambiguous string decoding must retain one C declaration per address"
        );
        assert!(
            c.contains("first decoding"),
            "use the same deterministic address mapping as report and annotation lookups"
        );
    }
}
