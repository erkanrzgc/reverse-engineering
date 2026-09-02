//! Reverse Engineering CLI

use anyhow::Context;
use clap::Parser;
use reverse_engineering::analysis::functions::FunctionDetectionInputs;
use reverse_engineering::analysis::runtime_artifacts::RuntimeArtifactStatus;
use reverse_engineering::analysis::{
    AnalysisReportBuilder, AnalysisReportInputs, AnalysisReportPackage, FunctionDetector,
    RuntimeArtifactExtractor, RuntimeArtifactInputs, RuntimeArtifactResult, RuntimeDetectionInputs,
    RuntimeDetector, RuntimeMatch, RuntimeReport, RuntimeReportBuilder, RuntimeReportInputs,
    StringExtractor,
};
use reverse_engineering::binary::{parse_binary, PeDataDirectoryInfo};
use reverse_engineering::decompiler::{
    annotate_string_references, escape_c_string, import_function_declarations,
    lift_functions_with_imports, recover_function_signatures, sanitize_c_comment,
    sanitize_c_identifier, structure_functions_with_cfg, CGenerator, CGeneratorConfig, Function,
    OptimizationLevel, Optimizer,
};
use reverse_engineering::disasm::{
    ArmDisassembler, ControlFlowGraph, Instruction, X86Disassembler,
};
use serde::Serialize;
use std::path::{Path, PathBuf};
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "reverse-engineering")]
#[command(about = "Binary to source code decompiler", long_about = None)]
struct Cli {
    /// Input binary file
    #[arg(short, long)]
    input: String,

    /// Output file (default: stdout)
    #[arg(short, long)]
    output: Option<String>,

    /// Output format
    #[arg(short, long, default_value = "c")]
    format: String,

    /// Optimization level (none, basic, aggressive)
    #[arg(short = 'O', long, default_value = "basic")]
    optimization: String,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Suppress info logs
    #[arg(long)]
    quiet: bool,

    /// Print the structured analysis package as JSON instead of C when no report directory is used
    #[arg(long)]
    json: bool,

    /// Write only report files and skip generated C output
    #[arg(long)]
    only_report: bool,

    /// Extract runtime-specific artifacts and write a manifest/report directory
    #[arg(long)]
    extract_runtime_artifacts: bool,

    /// Directory for runtime artifacts (default: <input-stem>_artifacts)
    #[arg(long)]
    artifacts_dir: Option<String>,

    /// Write a complete reverse-engineering report package to this directory
    #[arg(long)]
    report_dir: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if cli.only_report && cli.report_dir.is_none() {
        anyhow::bail!("--only-report requires --report-dir");
    }

    // Initialize logging
    let log_level = if cli.quiet {
        "warn"
    } else if cli.verbose {
        "debug"
    } else {
        "info"
    };
    tracing_subscriber::fmt()
        .with_env_filter(format!("reverse_engineering={}", log_level))
        .init();

    info!("Starting reverse-engineering...");
    let report_dir = cli.report_dir.as_deref().map(PathBuf::from);

    // Parse binary
    info!("Parsing binary: {}", cli.input);
    let binary = parse_binary(std::path::Path::new(&cli.input))?;

    info!("Format: {}", binary.format().name());
    info!("Architecture: {}", binary.architecture());
    info!("Entry point: 0x{:X}", binary.entry_point());

    // Get code sections
    let sections = binary.sections();
    let code_sections: Vec<_> = sections
        .iter()
        .filter(|s| s.characteristics.is_code)
        .collect();

    if code_sections.is_empty() {
        error!("No code sections found in binary");
        return Ok(());
    }

    info!("Found {} code section(s)", code_sections.len());

    // Disassemble code — dispatch per architecture and normalize into the
    // unified `Instruction` enum so downstream analysis is arch-agnostic.
    let mut all_instructions: Vec<Instruction> = Vec::new();
    let arch = binary.architecture();
    for section in &code_sections {
        info!(
            "Disassembling section: {} (0x{:X} - 0x{:X})",
            section.name,
            section.virtual_address,
            section.virtual_address + section.size
        );

        let instructions: Vec<Instruction> = match arch {
            "x86" => X86Disassembler::new_x86()
                .disassemble(&section.raw_data, section.virtual_address)?
                .into_iter()
                .map(Instruction::X86)
                .collect(),
            "x64" => X86Disassembler::new_x64()
                .disassemble(&section.raw_data, section.virtual_address)?
                .into_iter()
                .map(Instruction::X86)
                .collect(),
            "ARM" => ArmDisassembler::new_arm()?
                .disassemble(&section.raw_data, section.virtual_address)?
                .into_iter()
                .map(Instruction::Arm)
                .collect(),
            "ARM64" => ArmDisassembler::new_arm64()?
                .disassemble(&section.raw_data, section.virtual_address)?
                .into_iter()
                .map(Instruction::Arm)
                .collect(),
            other => {
                error!("Unsupported architecture: {}", other);
                return Ok(());
            }
        };
        info!("Found {} instructions", instructions.len());
        all_instructions.extend(instructions);
    }

    // Detect functions (seed-based: entry + exports + call targets + prologues)
    info!("Detecting functions...");
    let function_detector = FunctionDetector::new();
    let exports = binary.exports();
    let imports = binary.imports();
    let import_addresses = binary.import_addresses();
    let pe_data_directories = binary.pe_data_directories();
    let functions = function_detector.detect(FunctionDetectionInputs {
        instructions: &all_instructions,
        entry_point: binary.entry_point(),
        exports: &exports,
        imports: &imports,
        architecture: arch,
    });
    info!("Found {} functions", functions.len());

    // Extract strings
    info!("Extracting strings...");
    let string_extractor = StringExtractor::new();
    let mut all_strings = Vec::new();
    for section in &sections {
        if section.characteristics.is_data {
            let strings = string_extractor.extract(&section.raw_data, section.virtual_address);
            info!(
                "Found {} strings in section {}",
                strings.len(),
                section.name
            );
            all_strings.extend(strings);
        }
    }

    // Detect source-language/runtime family hints before decompilation output.
    let runtime_matches = RuntimeDetector::new().detect(RuntimeDetectionInputs {
        sections: &sections,
        imports: &imports,
        exports: &exports,
        strings: &all_strings,
    });
    if runtime_matches.is_empty() {
        info!("No runtime/language family hints detected");
    } else {
        for runtime in &runtime_matches {
            info!(
                "Runtime hint: {} ({}%) - {}",
                runtime.name, runtime.confidence, runtime.guidance
            );
        }
    }
    let runtime_reports = RuntimeReportBuilder::new().build(RuntimeReportInputs {
        runtime_matches: &runtime_matches,
        sections: &sections,
        strings: &all_strings,
    });
    let should_extract_runtime_artifacts = cli.extract_runtime_artifacts || report_dir.is_some();
    let _artifact_result = if should_extract_runtime_artifacts {
        let artifact_result = RuntimeArtifactExtractor::new().extract(RuntimeArtifactInputs {
            runtime_matches: &runtime_matches,
            sections: &sections,
            imports: &imports,
            exports: &exports,
            strings: &all_strings,
        });
        let artifacts_dir = resolve_artifacts_dir(
            &cli.input,
            cli.artifacts_dir.as_deref(),
            report_dir.as_deref(),
        );
        write_runtime_artifacts(
            &artifacts_dir,
            &runtime_matches,
            &runtime_reports,
            &artifact_result,
        )?;
        info!("Runtime artifacts written to: {}", artifacts_dir.display());
        Some(artifact_result)
    } else {
        None
    };

    // Build control flow graph
    info!("Building control flow graph...");
    let cfg = ControlFlowGraph::from_instructions(&all_instructions);
    info!("CFG has {} basic blocks", cfg.blocks().len());
    let analysis_package = (report_dir.is_some() || cli.json).then(|| {
        AnalysisReportBuilder::new().build(AnalysisReportInputs {
            input_path: &cli.input,
            format: binary.format().name(),
            architecture: binary.architecture(),
            entry_point: binary.entry_point(),
            instruction_count: all_instructions.len(),
            basic_block_count: cfg.blocks().len(),
            sections: &sections,
            functions: &functions,
            strings: &all_strings,
            imports: &imports,
            import_addresses: &import_addresses,
            exports: &exports,
            runtime_matches: &runtime_matches,
        })
    });

    if let (Some(report_dir), Some(package)) = (report_dir.as_ref(), analysis_package.as_ref()) {
        write_analysis_report_package(report_dir, package, &pe_data_directories, !cli.only_report)?;
        info!(
            "Analysis report package written to: {}",
            report_dir.display()
        );
    }

    if cli.json {
        let Some(package) = analysis_package.as_ref() else {
            anyhow::bail!("failed to build JSON analysis package");
        };
        println!("{}", serde_json::to_string_pretty(package)?);
        if report_dir.is_none() {
            return Ok(());
        }
    }

    if cli.only_report {
        info!("Report-only mode complete");
        return Ok(());
    }

    // Generate C code
    info!("Generating C code...");
    let mut output = String::new();

    // Add header
    output.push_str("// Decompiled by reverse-engineering\n");
    output.push_str(&format!("// Binary: {}\n", cli.input));
    output.push_str(&format!("// Format: {}\n", binary.format().name()));
    output.push_str(&format!("// Architecture: {}\n", binary.architecture()));
    output.push_str(&format!("// Entry point: 0x{:X}\n", binary.entry_point()));
    if runtime_matches.is_empty() {
        output.push_str("// Runtime hints: none detected\n\n");
    } else {
        output.push_str("// Runtime hints:\n");
        for runtime in &runtime_matches {
            output.push_str(&format!(
                "// - {} ({}%): {}\n",
                sanitize_c_comment(runtime.name),
                runtime.confidence,
                sanitize_c_comment(&runtime.evidence.join("; "))
            ));
            output.push_str(&format!(
                "//   Guidance: {}\n",
                sanitize_c_comment(runtime.guidance)
            ));
        }
        if !runtime_reports.is_empty() {
            output.push_str("// Runtime reports:\n");
            for report in &runtime_reports {
                output.push_str(&format!(
                    "// - {}: {}\n",
                    sanitize_c_comment(&report.title),
                    sanitize_c_comment(&report.summary)
                ));
                for artifact in &report.artifacts {
                    output.push_str(&format!(
                        "//   Artifact: {} - {}\n",
                        sanitize_c_comment(&artifact.name),
                        sanitize_c_comment(&artifact.detail)
                    ));
                }
                for action in &report.actions {
                    output.push_str(&format!(
                        "//   Action: {} - {}\n",
                        sanitize_c_comment(&action.label),
                        sanitize_c_comment(&action.detail)
                    ));
                }
            }
        }
        output.push('\n');
    }

    // Add includes
    output.push_str("#include <stdint.h>\n");
    output.push_str("#include <stddef.h>\n\n");

    // Add string literals
    if !all_strings.is_empty() {
        output.push_str("// String literals\n");
        for s in &all_strings {
            output.push_str(&format!(
                "const char str_{:X}[] = \"{}\";\n",
                s.address,
                escape_c_string(&s.value)
            ));
        }
        output.push('\n');
    }

    if !import_addresses.is_empty() {
        output.push_str("// Import declarations\n");
        for import in import_function_declarations(&import_addresses) {
            output.push_str(&format!(
                "// import: {}!{} @ 0x{:X}\n",
                sanitize_c_comment(&import.library),
                sanitize_c_comment(&import.function),
                import.address
            ));
            output.push_str(&format!("void {}(void);\n", import.c_name));
        }
        output.push('\n');
    }

    // Lift detected functions into AST form, then structure the unambiguous
    // instructions before emitting through the C generator. The lifter is the
    // single boundary between discovery (FunctionInfo) and synthesis
    // (ast::Function); later passes such as structuring and type recovery
    // operate on the AST, not on raw instruction streams.
    let mut ast_functions = lift_functions_with_imports(&functions, &import_addresses);
    structure_functions_with_cfg(&mut ast_functions, &cfg);
    recover_function_signatures(
        &mut ast_functions,
        &functions,
        binary.format().name(),
        binary.architecture(),
    );
    annotate_string_references(&mut ast_functions, &all_strings);

    // Apply optimization (currently a no-op for InlineAsm statements, but
    // the hook is in place for when structuring produces real expressions).
    let opt_level = match cli.optimization.as_str() {
        "none" => OptimizationLevel::None,
        "aggressive" => OptimizationLevel::Aggressive,
        _ => OptimizationLevel::Basic,
    };
    let optimizer = Optimizer::new(opt_level);
    for func in &mut ast_functions {
        optimizer.optimize_function(func);
    }

    // Declarations
    output.push_str("// Function declarations\n");
    for (info, func) in functions.iter().zip(ast_functions.iter()) {
        output.push_str(&format!(
            "// 0x{:X}{}\n",
            info.address,
            if info.is_export { " (export)" } else { "" }
        ));
        output.push_str(&function_prototype(func));
        output.push('\n');
    }
    output.push('\n');

    // Implementations
    output.push_str("// Function implementations\n");
    let mut generator = CGenerator::new(CGeneratorConfig::default());
    for (info, func) in functions.iter().zip(ast_functions.iter()) {
        output.push_str(&format!(
            "// Function: {} at 0x{:X} (size: {} bytes)\n",
            info.name, info.address, info.size
        ));
        output.push_str(&generator.generate_function(func));
        output.push('\n');
    }

    // Write output
    match cli.output.as_ref() {
        Some(path) => {
            std::fs::write(path, output)?;
            info!("Output written to: {}", path);
        }
        None if report_dir.is_some() => {
            let report_dir = report_dir.as_ref().expect("checked report dir");
            std::fs::create_dir_all(report_dir).with_context(|| {
                format!("failed to create report directory {}", report_dir.display())
            })?;
            let output_path = report_dir.join("decompiled.c");
            std::fs::write(&output_path, output).with_context(|| {
                format!(
                    "failed to write generated C output {}",
                    output_path.display()
                )
            })?;
            info!("Output written to: {}", output_path.display());
        }
        None => {
            println!("{}", output);
        }
    }

    info!("Decompilation complete!");

    Ok(())
}

fn resolve_artifacts_dir(
    input: &str,
    explicit_dir: Option<&str>,
    report_dir: Option<&Path>,
) -> PathBuf {
    if let Some(path) = explicit_dir {
        return PathBuf::from(path);
    }
    if let Some(path) = report_dir {
        return path.to_path_buf();
    }

    let stem = Path::new(input)
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("runtime");
    PathBuf::from(format!("{stem}_artifacts"))
}

fn write_analysis_report_package(
    report_dir: &Path,
    package: &AnalysisReportPackage,
    pe_data_directories: &[PeDataDirectoryInfo],
    include_decompiled: bool,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(report_dir).with_context(|| {
        format!(
            "failed to create analysis report directory {}",
            report_dir.display()
        )
    })?;

    write_json_file(report_dir, "analysis_package.json", package)?;
    write_json_file(report_dir, "functions.json", &package.functions)?;
    write_json_file(report_dir, "jump_tables.json", &package.jump_tables)?;
    write_json_file(report_dir, "call_graph.json", &package.call_graph)?;
    write_json_file(report_dir, "xrefs.json", &package.xrefs)?;
    write_json_file(report_dir, "import_xrefs.json", &package.xrefs.imports)?;
    write_json_file(report_dir, "sections.json", &package.sections)?;
    write_json_file(report_dir, "cfg_summary.json", &package.cfg_summary)?;
    write_json_file(report_dir, "strings.json", &package.strings)?;
    write_json_file(
        report_dir,
        "strings_by_function.json",
        &package.strings_by_function,
    )?;
    write_json_file(
        report_dir,
        "suspicious_strings.json",
        &package.suspicious_strings,
    )?;
    write_json_file(
        report_dir,
        "cyberchef_recipes.json",
        &package.cyberchef_recipes,
    )?;
    write_json_file(report_dir, "api_insights.json", &package.api_insights)?;
    write_json_file(report_dir, "behavior_report.json", &package.behavior_report)?;
    write_json_file(
        report_dir,
        "import_addresses.json",
        &package.import_addresses,
    )?;
    write_json_file(report_dir, "imports.json", &package.imports)?;
    write_json_file(report_dir, "exports.json", &package.exports)?;
    write_json_file(report_dir, "pe_directories.json", &pe_data_directories)?;

    let report = format_analysis_report_text(package, pe_data_directories, include_decompiled);
    let report_path = report_dir.join("report.txt");
    std::fs::write(&report_path, report).with_context(|| {
        format!(
            "failed to write analysis report text {}",
            report_path.display()
        )
    })?;

    let behavior_report = format_behavior_report_text(package);
    let behavior_report_path = report_dir.join("behavior_report.txt");
    std::fs::write(&behavior_report_path, behavior_report).with_context(|| {
        format!(
            "failed to write behavior report text {}",
            behavior_report_path.display()
        )
    })?;

    Ok(())
}

fn write_json_file<T: Serialize>(dir: &Path, name: &str, value: &T) -> anyhow::Result<()> {
    let path = dir.join(name);
    let json = serde_json::to_string_pretty(value)
        .with_context(|| format!("failed to serialize {name}"))?;
    std::fs::write(&path, json).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn function_prototype(function: &Function) -> String {
    let params = if function.parameters.is_empty() {
        "void".to_string()
    } else {
        let mut params = function
            .parameters
            .iter()
            .map(|param| {
                format!(
                    "{} {}",
                    param.type_info.to_c_type(),
                    sanitize_c_identifier(&param.name, "arg")
                )
            })
            .collect::<Vec<_>>();
        if function.is_variadic {
            params.push("...".to_string());
        }
        params.join(", ")
    };

    format!(
        "{} {}({});",
        function.return_type.to_c_type(),
        sanitize_c_identifier(&function.name, "sub"),
        params
    )
}

fn format_analysis_report_text(
    package: &AnalysisReportPackage,
    pe_data_directories: &[PeDataDirectoryInfo],
    include_decompiled: bool,
) -> String {
    let summary = &package.summary;
    let mut report = String::new();
    report.push_str("reverse-engineering analysis report\n");
    report.push_str("===================================\n\n");
    report.push_str(&format!("Binary: {}\n", summary.input_path));
    report.push_str(&format!("Format: {}\n", summary.format));
    report.push_str(&format!("Architecture: {}\n", summary.architecture));
    report.push_str(&format!("Entry point: 0x{:X}\n", summary.entry_point));
    report.push_str(&format!("Instructions: {}\n", summary.instruction_count));
    report.push_str(&format!("Basic blocks: {}\n", summary.basic_block_count));
    report.push_str(&format!(
        "Direct calls: {}\n",
        package.cfg_summary.direct_call_count
    ));
    report.push_str(&format!(
        "Jump table candidates: {}\n",
        package.jump_tables.len()
    ));
    report.push_str(&format!(
        "Suspicious strings: {}\n",
        package.suspicious_strings.len()
    ));
    report.push_str(&format!(
        "CyberChef recipes: {}\n",
        summary.cyberchef_recipe_count
    ));
    report.push_str(&format!(
        "Behavior risk: {} ({}/100)\n",
        package.behavior_report.risk_level, package.behavior_report.risk_score
    ));
    report.push_str(&format!("Functions: {}\n", summary.function_count));
    report.push_str(&format!("Strings: {}\n", summary.string_count));
    report.push_str(&format!("Imports: {}\n", summary.import_count));
    report.push_str(&format!(
        "Import addresses: {}\n",
        package.import_addresses.len()
    ));
    report.push_str(&format!(
        "PE data directories: {}\n",
        pe_data_directories.len()
    ));
    report.push_str(&format!("Exports: {}\n\n", summary.export_count));

    if summary.runtime_hints.is_empty() {
        report.push_str("Runtime hints: none detected\n\n");
    } else {
        report.push_str("Runtime hints:\n");
        for runtime in &summary.runtime_hints {
            report.push_str(&format!(
                "- {} ({}%): {}\n",
                runtime.name,
                runtime.confidence,
                runtime.evidence.join("; ")
            ));
        }
        report.push('\n');
    }

    if package.behavior_report.categories.is_empty() {
        report.push_str("Behavior categories: none detected\n\n");
    } else {
        report.push_str("Behavior categories:\n");
        for category in package.behavior_report.categories.iter().take(10) {
            report.push_str(&format!(
                "- {} ({}, {} findings)\n",
                category.name, category.severity, category.evidence_count
            ));
        }
        report.push('\n');
    }

    report.push_str("Top functions:\n");
    for function in package.functions.iter().take(20) {
        report.push_str(&format!(
            "- {} @ 0x{:X}: {} instructions, {} calls, {} string refs{}\n",
            function.name,
            function.address,
            function.instruction_count,
            function.calls.len(),
            function.string_refs.len(),
            if function.is_export { ", export" } else { "" }
        ));
    }

    report.push_str("\nFiles:\n");
    if include_decompiled {
        report.push_str("- decompiled.c\n");
    }
    report.push_str("- functions.json\n");
    report.push_str("- jump_tables.json\n");
    report.push_str("- call_graph.json\n");
    report.push_str("- xrefs.json\n");
    report.push_str("- import_xrefs.json\n");
    report.push_str("- sections.json\n");
    report.push_str("- cfg_summary.json\n");
    report.push_str("- strings.json\n");
    report.push_str("- strings_by_function.json\n");
    report.push_str("- suspicious_strings.json\n");
    report.push_str("- cyberchef_recipes.json\n");
    report.push_str("- api_insights.json\n");
    report.push_str("- behavior_report.json\n");
    report.push_str("- behavior_report.txt\n");
    report.push_str("- import_addresses.json\n");
    report.push_str("- imports.json\n");
    report.push_str("- exports.json\n");
    report.push_str("- pe_directories.json\n");
    report.push_str("- analysis_package.json\n");
    report.push_str("- runtime_report.txt\n");
    report.push_str("- artifacts_manifest.json\n");

    report
}

fn format_behavior_report_text(package: &AnalysisReportPackage) -> String {
    let mut report = String::new();
    report.push_str("reverse-engineering behavior report\n");
    report.push_str("===================================\n\n");
    report.push_str(&format!("Risk: {}\n", package.behavior_report.risk_level));
    report.push_str(&format!(
        "Score: {}/100\n",
        package.behavior_report.risk_score
    ));
    report.push_str(&format!(
        "Findings: {}\n\n",
        package.behavior_report.findings.len()
    ));

    if package.behavior_report.categories.is_empty() {
        report.push_str("No high-signal behavior categories detected.\n");
        return report;
    }

    report.push_str("Categories:\n");
    for category in &package.behavior_report.categories {
        report.push_str(&format!(
            "- {} ({}, {} findings)\n",
            category.name, category.severity, category.evidence_count
        ));
        for evidence in category.evidence.iter().take(5) {
            report.push_str(&format!("  - {}\n", evidence));
        }
    }

    report
}

fn write_runtime_artifacts(
    artifacts_dir: &Path,
    runtime_matches: &[RuntimeMatch],
    runtime_reports: &[RuntimeReport],
    artifact_result: &RuntimeArtifactResult,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(artifacts_dir).with_context(|| {
        format!(
            "failed to create runtime artifact directory {}",
            artifacts_dir.display()
        )
    })?;

    for artifact in &artifact_result.artifacts {
        if artifact.status != RuntimeArtifactStatus::Extracted {
            continue;
        }
        let Some(file_name) = artifact.file_name.as_deref() else {
            continue;
        };
        let output_path = artifacts_dir.join(file_name);
        std::fs::write(&output_path, &artifact.payload).with_context(|| {
            format!(
                "failed to write extracted artifact {}",
                output_path.display()
            )
        })?;
    }

    let manifest = serde_json::to_string_pretty(artifact_result)
        .context("failed to serialize runtime artifact manifest")?;
    let manifest_path = artifacts_dir.join("artifacts_manifest.json");
    std::fs::write(&manifest_path, manifest).with_context(|| {
        format!(
            "failed to write runtime artifact manifest {}",
            manifest_path.display()
        )
    })?;

    let report = format_runtime_artifact_report(runtime_matches, runtime_reports, artifact_result);
    let report_path = artifacts_dir.join("runtime_report.txt");
    std::fs::write(&report_path, report).with_context(|| {
        format!(
            "failed to write runtime artifact report {}",
            report_path.display()
        )
    })?;

    Ok(())
}

fn format_runtime_artifact_report(
    runtime_matches: &[RuntimeMatch],
    runtime_reports: &[RuntimeReport],
    artifact_result: &RuntimeArtifactResult,
) -> String {
    let mut report = String::new();
    report.push_str("reverse-engineering runtime artifact report\n");
    report.push_str("===========================================\n\n");

    if runtime_matches.is_empty() {
        report.push_str("No runtime/language family hints detected.\n");
        report.push_str("No runtime artifacts were found.\n\n");
    } else {
        report.push_str("Runtime hints:\n");
        for runtime in runtime_matches {
            report.push_str(&format!(
                "- {} ({}%): {}\n",
                runtime.name,
                runtime.confidence,
                runtime.evidence.join("; ")
            ));
            report.push_str(&format!("  Guidance: {}\n", runtime.guidance));
        }
        report.push('\n');
    }

    if !runtime_reports.is_empty() {
        report.push_str("Runtime reports:\n");
        for runtime_report in runtime_reports {
            report.push_str(&format!(
                "- {}: {}\n",
                runtime_report.title, runtime_report.summary
            ));
            for action in &runtime_report.actions {
                report.push_str(&format!("  Action: {} - {}\n", action.label, action.detail));
            }
        }
        report.push('\n');
    }

    if !artifact_result.notes.is_empty() {
        report.push_str("Notes:\n");
        for note in &artifact_result.notes {
            report.push_str(&format!("- {note}\n"));
        }
        report.push('\n');
    }

    if artifact_result.artifacts.is_empty() {
        report.push_str("Artifacts: none\n");
    } else {
        report.push_str("Artifacts:\n");
        for artifact in &artifact_result.artifacts {
            report.push_str(&format!(
                "- {} [{:?}/{:?}] {}\n",
                artifact.name, artifact.kind, artifact.status, artifact.detail
            ));
            if let Some(address) = artifact.virtual_address {
                report.push_str(&format!("  Address: 0x{address:X}\n"));
            }
            if let Some(file_name) = artifact.file_name.as_deref() {
                report.push_str(&format!("  File: {file_name}\n"));
            }
        }
    }

    report
}
