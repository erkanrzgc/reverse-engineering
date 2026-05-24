//! Structured reverse-engineering report package.

use crate::analysis::cyberchef::{cyberchef_recipe_reports, CyberChefRecipeReport};
use crate::analysis::functions::FunctionInfo;
use crate::analysis::runtime::RuntimeMatch;
use crate::analysis::strings::StringInfo;
use crate::binary::parser::{ExportInfo, ImportAddressInfo, ImportInfo, SectionInfo};
use crate::disasm::control_flow::Instruction;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Inputs for building a complete reverse-engineering report package.
pub struct AnalysisReportInputs<'a> {
    pub input_path: &'a str,
    pub format: &'a str,
    pub architecture: &'a str,
    pub entry_point: u64,
    pub instruction_count: usize,
    pub basic_block_count: usize,
    pub sections: &'a [SectionInfo],
    pub functions: &'a [FunctionInfo],
    pub strings: &'a [StringInfo],
    pub imports: &'a [ImportInfo],
    pub import_addresses: &'a [ImportAddressInfo],
    pub exports: &'a [ExportInfo],
    pub runtime_matches: &'a [RuntimeMatch],
}

/// Top-level structured analysis package.
#[derive(Debug, Clone, Serialize)]
pub struct AnalysisReportPackage {
    pub summary: AnalysisSummary,
    pub cfg_summary: CfgSummaryReport,
    pub functions: Vec<FunctionReport>,
    pub jump_tables: Vec<JumpTableReport>,
    pub call_graph: Vec<CallGraphEdge>,
    pub xrefs: XrefReport,
    pub sections: Vec<SectionReport>,
    pub strings: Vec<StringReport>,
    pub suspicious_strings: Vec<SuspiciousStringReport>,
    pub cyberchef_recipes: Vec<CyberChefRecipeReport>,
    pub strings_by_function: Vec<FunctionStringIndex>,
    pub api_insights: Vec<ApiInsightReport>,
    pub behavior_report: BehaviorReport,
    pub import_addresses: Vec<ImportAddressReport>,
    pub imports: Vec<ImportReport>,
    pub exports: Vec<ExportReport>,
}

/// Human-scale counts and binary identity.
#[derive(Debug, Clone, Serialize)]
pub struct AnalysisSummary {
    pub input_path: String,
    pub format: String,
    pub architecture: String,
    pub entry_point: u64,
    pub instruction_count: usize,
    pub basic_block_count: usize,
    pub function_count: usize,
    pub string_count: usize,
    pub cyberchef_recipe_count: usize,
    pub import_count: usize,
    pub export_count: usize,
    pub runtime_hints: Vec<RuntimeHintReport>,
}

/// Runtime hint summary.
#[derive(Debug, Clone, Serialize)]
pub struct RuntimeHintReport {
    pub name: String,
    pub confidence: u8,
    pub evidence: Vec<String>,
    pub guidance: String,
}

/// CFG-wide summary for quick triage.
#[derive(Debug, Clone, Serialize)]
pub struct CfgSummaryReport {
    pub basic_block_count: usize,
    pub direct_call_count: usize,
    pub conditional_branch_count: usize,
    pub unconditional_branch_count: usize,
    pub return_count: usize,
}

/// Function relationship report.
#[derive(Debug, Clone, Serialize)]
pub struct FunctionReport {
    pub name: String,
    pub address: u64,
    pub size: usize,
    pub instruction_count: usize,
    pub basic_block_estimate: usize,
    pub function_kind: String,
    pub is_import: bool,
    pub is_export: bool,
    pub calls: Vec<CallReference>,
    pub tail_calls: Vec<CallReference>,
    pub string_refs: Vec<StringReference>,
}

/// Indirect jump pattern that may represent a switch jump table.
#[derive(Debug, Clone, Serialize)]
pub struct JumpTableReport {
    pub function_name: String,
    pub function_address: u64,
    pub instruction_address: u64,
    pub expression: String,
}

/// One call graph edge, grouped by caller and callee.
#[derive(Debug, Clone, Serialize)]
pub struct CallGraphEdge {
    pub caller_name: String,
    pub caller_address: u64,
    pub callee_address: u64,
    pub callee_name: Option<String>,
    pub call_count: usize,
    pub call_sites: Vec<u64>,
}

/// Binary section report.
#[derive(Debug, Clone, Serialize)]
pub struct SectionReport {
    pub name: String,
    pub virtual_address: u64,
    pub size: u64,
    pub raw_size: usize,
    pub is_code: bool,
    pub is_data: bool,
    pub is_readable: bool,
    pub is_writable: bool,
    pub is_executable: bool,
}

/// Direct call target reference.
#[derive(Debug, Clone, Serialize)]
pub struct CallReference {
    pub instruction_address: u64,
    pub target_address: u64,
    pub target_name: Option<String>,
    pub target_kind: String,
    pub target_library: Option<String>,
    pub target_symbol: Option<String>,
}

/// String reference found inside a function.
#[derive(Debug, Clone, Serialize)]
pub struct StringReference {
    pub instruction_address: u64,
    pub address: u64,
    pub symbol: String,
    pub value: String,
}

/// Extracted string report.
#[derive(Debug, Clone, Serialize)]
pub struct StringReport {
    pub address: u64,
    pub symbol: String,
    pub value: String,
    pub encoding: String,
    pub length: usize,
}

/// Suspicious or high-signal string report.
#[derive(Debug, Clone, Serialize)]
pub struct SuspiciousStringReport {
    pub address: u64,
    pub symbol: String,
    pub value: String,
    pub category: String,
}

/// String references grouped by function.
#[derive(Debug, Clone, Serialize)]
pub struct FunctionStringIndex {
    pub function_name: String,
    pub function_address: u64,
    pub strings: Vec<StringReference>,
}

/// Cross-reference index for fast triage.
#[derive(Debug, Clone, Serialize)]
pub struct XrefReport {
    pub functions: Vec<FunctionXrefReport>,
    pub imports: Vec<ImportXrefReport>,
}

/// Per-function cross-reference view.
#[derive(Debug, Clone, Serialize)]
pub struct FunctionXrefReport {
    pub function_name: String,
    pub function_address: u64,
    pub calls_out: Vec<CallReference>,
    pub called_by: Vec<CallerReference>,
    pub strings: Vec<StringReference>,
}

/// Caller site for a function.
#[derive(Debug, Clone, Serialize)]
pub struct CallerReference {
    pub caller_name: String,
    pub caller_address: u64,
    pub instruction_address: u64,
}

/// Import-table cross-reference entry.
#[derive(Debug, Clone, Serialize)]
pub struct ImportXrefReport {
    pub library: String,
    pub function: String,
    pub address: Option<u64>,
    pub category: Option<String>,
    pub severity: Option<String>,
    pub referenced_by: Vec<ImportCallerReference>,
}

/// Caller site for an imported API.
#[derive(Debug, Clone, Serialize)]
pub struct ImportCallerReference {
    pub function_name: String,
    pub function_address: u64,
    pub instruction_address: u64,
}

/// High-signal imported API classification.
#[derive(Debug, Clone, Serialize)]
pub struct ApiInsightReport {
    pub library: String,
    pub function: String,
    pub category: String,
    pub severity: String,
    pub summary: String,
}

/// Behavior-focused triage summary.
#[derive(Debug, Clone, Serialize)]
pub struct BehaviorReport {
    pub risk_score: u8,
    pub risk_level: String,
    pub categories: Vec<BehaviorCategoryReport>,
    pub findings: Vec<BehaviorFinding>,
}

/// Behavior category aggregate.
#[derive(Debug, Clone, Serialize)]
pub struct BehaviorCategoryReport {
    pub name: String,
    pub severity: String,
    pub evidence_count: usize,
    pub evidence: Vec<String>,
}

/// One behavior finding.
#[derive(Debug, Clone, Serialize)]
pub struct BehaviorFinding {
    pub category: String,
    pub severity: String,
    pub source: String,
    pub detail: String,
}

/// Import address table report.
#[derive(Debug, Clone, Serialize)]
pub struct ImportAddressReport {
    pub library: String,
    pub function: String,
    pub address: u64,
    pub ordinal: Option<u16>,
}

/// Import table report.
#[derive(Debug, Clone, Serialize)]
pub struct ImportReport {
    pub name: String,
    pub functions: Vec<String>,
}

/// Export table report.
#[derive(Debug, Clone, Serialize)]
pub struct ExportReport {
    pub name: String,
    pub address: u64,
    pub ordinal: Option<u16>,
}

/// Builds serializable reverse-engineering report packages.
pub struct AnalysisReportBuilder;

impl AnalysisReportBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn build(&self, inputs: AnalysisReportInputs<'_>) -> AnalysisReportPackage {
        let function_names = build_function_name_map(inputs.functions);
        let string_reports = inputs.strings.iter().map(string_report).collect::<Vec<_>>();
        let string_map = inputs
            .strings
            .iter()
            .map(|string| (string.address, string))
            .collect::<HashMap<_, _>>();
        let import_address_map = build_import_address_map(inputs.import_addresses);

        let functions = inputs
            .functions
            .iter()
            .map(|function| {
                function_report(function, &function_names, &string_map, &import_address_map)
            })
            .collect::<Vec<_>>();
        let cfg_summary = cfg_summary(inputs.basic_block_count, inputs.functions);
        let jump_tables = jump_table_reports(&functions, inputs.functions);
        let call_graph = call_graph_edges(&functions);
        let strings_by_function = strings_by_function(&functions);
        let suspicious_strings = inputs
            .strings
            .iter()
            .filter_map(suspicious_string_report)
            .collect::<Vec<_>>();
        let cyberchef_recipes = cyberchef_recipe_reports(inputs.strings);
        let api_insights = api_insights(inputs.imports);
        let xrefs = xref_report(
            &functions,
            inputs.imports,
            inputs.import_addresses,
            &api_insights,
        );
        let behavior_report =
            behavior_report(&api_insights, &suspicious_strings, inputs.runtime_matches);

        AnalysisReportPackage {
            summary: AnalysisSummary {
                input_path: inputs.input_path.to_string(),
                format: inputs.format.to_string(),
                architecture: inputs.architecture.to_string(),
                entry_point: inputs.entry_point,
                instruction_count: inputs.instruction_count,
                basic_block_count: inputs.basic_block_count,
                function_count: inputs.functions.len(),
                string_count: inputs.strings.len(),
                cyberchef_recipe_count: cyberchef_recipes.len(),
                import_count: inputs.imports.len(),
                export_count: inputs.exports.len(),
                runtime_hints: inputs
                    .runtime_matches
                    .iter()
                    .map(|runtime| RuntimeHintReport {
                        name: runtime.name.to_string(),
                        confidence: runtime.confidence,
                        evidence: runtime.evidence.clone(),
                        guidance: runtime.guidance.to_string(),
                    })
                    .collect(),
            },
            cfg_summary,
            functions,
            jump_tables,
            call_graph,
            xrefs,
            sections: inputs.sections.iter().map(section_report).collect(),
            strings: string_reports,
            suspicious_strings,
            cyberchef_recipes,
            strings_by_function,
            api_insights,
            behavior_report,
            import_addresses: inputs
                .import_addresses
                .iter()
                .map(import_address_report)
                .collect(),
            imports: inputs
                .imports
                .iter()
                .map(|import| ImportReport {
                    name: import.name.clone(),
                    functions: import.functions.clone(),
                })
                .collect(),
            exports: inputs
                .exports
                .iter()
                .map(|export| ExportReport {
                    name: export.name.clone(),
                    address: export.address,
                    ordinal: export.ordinal,
                })
                .collect(),
        }
    }
}

impl Default for AnalysisReportBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn call_graph_edges(functions: &[FunctionReport]) -> Vec<CallGraphEdge> {
    let mut edges: HashMap<(u64, u64), CallGraphEdge> = HashMap::new();

    for function in functions {
        for call in &function.calls {
            let edge = edges
                .entry((function.address, call.target_address))
                .or_insert_with(|| CallGraphEdge {
                    caller_name: function.name.clone(),
                    caller_address: function.address,
                    callee_address: call.target_address,
                    callee_name: call.target_name.clone(),
                    call_count: 0,
                    call_sites: Vec::new(),
                });
            edge.call_count += 1;
            edge.call_sites.push(call.instruction_address);
        }
    }

    let mut edges = edges.into_values().collect::<Vec<_>>();
    edges.sort_by_key(|edge| (edge.caller_address, edge.callee_address));
    edges
}

fn strings_by_function(functions: &[FunctionReport]) -> Vec<FunctionStringIndex> {
    functions
        .iter()
        .filter(|function| !function.string_refs.is_empty())
        .map(|function| FunctionStringIndex {
            function_name: function.name.clone(),
            function_address: function.address,
            strings: function.string_refs.clone(),
        })
        .collect()
}

fn build_import_address_map(imports: &[ImportAddressInfo]) -> HashMap<u64, &ImportAddressInfo> {
    imports
        .iter()
        .map(|import| (import.address, import))
        .collect()
}

fn xref_report(
    functions: &[FunctionReport],
    imports: &[ImportInfo],
    import_addresses: &[ImportAddressInfo],
    api_insights: &[ApiInsightReport],
) -> XrefReport {
    let mut called_by: HashMap<u64, Vec<CallerReference>> = HashMap::new();

    for function in functions {
        for call in &function.calls {
            called_by
                .entry(call.target_address)
                .or_default()
                .push(CallerReference {
                    caller_name: function.name.clone(),
                    caller_address: function.address,
                    instruction_address: call.instruction_address,
                });
        }
    }

    let mut function_xrefs = functions
        .iter()
        .map(|function| {
            let mut callers = called_by.remove(&function.address).unwrap_or_default();
            callers.sort_by_key(|caller| (caller.caller_address, caller.instruction_address));

            FunctionXrefReport {
                function_name: function.name.clone(),
                function_address: function.address,
                calls_out: function.calls.clone(),
                called_by: callers,
                strings: function.string_refs.clone(),
            }
        })
        .collect::<Vec<_>>();
    function_xrefs.sort_by_key(|xref| xref.function_address);

    XrefReport {
        functions: function_xrefs,
        imports: import_xrefs(functions, imports, import_addresses, api_insights),
    }
}

fn import_xrefs(
    functions: &[FunctionReport],
    imports: &[ImportInfo],
    import_addresses: &[ImportAddressInfo],
    api_insights: &[ApiInsightReport],
) -> Vec<ImportXrefReport> {
    let insight_map = api_insights
        .iter()
        .map(|insight| {
            (
                (
                    insight.library.to_ascii_lowercase(),
                    insight.function.to_ascii_lowercase(),
                ),
                insight,
            )
        })
        .collect::<HashMap<_, _>>();
    let address_map = import_addresses
        .iter()
        .map(|import| {
            (
                (
                    import.library.to_ascii_lowercase(),
                    import.function.to_ascii_lowercase(),
                ),
                import.address,
            )
        })
        .collect::<HashMap<_, _>>();
    let callers = import_callers(functions);

    let mut xrefs = Vec::new();
    for import in imports {
        for function in &import.functions {
            let key = (
                import.name.to_ascii_lowercase(),
                function.to_ascii_lowercase(),
            );
            let insight = insight_map.get(&key);
            let address = address_map.get(&key).copied();
            xrefs.push(ImportXrefReport {
                library: import.name.clone(),
                function: function.clone(),
                address,
                category: insight.map(|insight| insight.category.clone()),
                severity: insight.map(|insight| insight.severity.clone()),
                referenced_by: callers.get(&key).cloned().unwrap_or_default(),
            });
        }
    }
    xrefs.sort_by(|left, right| {
        (
            left.library.to_ascii_lowercase(),
            left.function.to_ascii_lowercase(),
        )
            .cmp(&(
                right.library.to_ascii_lowercase(),
                right.function.to_ascii_lowercase(),
            ))
    });
    xrefs
}

fn import_callers(
    functions: &[FunctionReport],
) -> HashMap<(String, String), Vec<ImportCallerReference>> {
    let mut callers: HashMap<(String, String), Vec<ImportCallerReference>> = HashMap::new();

    for function in functions {
        for call in &function.calls {
            let (Some(library), Some(symbol)) = (&call.target_library, &call.target_symbol) else {
                continue;
            };
            callers
                .entry((library.to_ascii_lowercase(), symbol.to_ascii_lowercase()))
                .or_default()
                .push(ImportCallerReference {
                    function_name: function.name.clone(),
                    function_address: function.address,
                    instruction_address: call.instruction_address,
                });
        }
    }

    for caller_list in callers.values_mut() {
        caller_list.sort_by_key(|caller| (caller.function_address, caller.instruction_address));
    }

    callers
}

fn api_insights(imports: &[ImportInfo]) -> Vec<ApiInsightReport> {
    let mut insights = Vec::new();

    for import in imports {
        for function in &import.functions {
            let Some((category, severity, summary)) = classify_api(function) else {
                continue;
            };
            insights.push(ApiInsightReport {
                library: import.name.clone(),
                function: function.clone(),
                category: category.to_string(),
                severity: severity.to_string(),
                summary: summary.to_string(),
            });
        }
    }

    insights.sort_by(|left, right| {
        severity_rank(&right.severity)
            .cmp(&severity_rank(&left.severity))
            .then_with(|| left.category.cmp(&right.category))
            .then_with(|| {
                left.library
                    .to_ascii_lowercase()
                    .cmp(&right.library.to_ascii_lowercase())
            })
            .then_with(|| {
                left.function
                    .to_ascii_lowercase()
                    .cmp(&right.function.to_ascii_lowercase())
            })
    });
    insights
}

fn behavior_report(
    api_insights: &[ApiInsightReport],
    suspicious_strings: &[SuspiciousStringReport],
    runtime_matches: &[RuntimeMatch],
) -> BehaviorReport {
    let mut findings = Vec::new();

    for insight in api_insights {
        findings.push(BehaviorFinding {
            category: insight.category.clone(),
            severity: insight.severity.clone(),
            source: "import_table".to_string(),
            detail: format!(
                "{}!{} - {}",
                insight.library, insight.function, insight.summary
            ),
        });
    }

    for string in suspicious_strings {
        let (category, severity) = behavior_from_string_category(&string.category);
        findings.push(BehaviorFinding {
            category: category.to_string(),
            severity: severity.to_string(),
            source: "string".to_string(),
            detail: format!(
                "{} @ 0x{:X}: {}",
                string.symbol, string.address, string.value
            ),
        });
    }

    for runtime in runtime_matches {
        if runtime.confidence >= 70 {
            findings.push(BehaviorFinding {
                category: "runtime_packaging".to_string(),
                severity: "low".to_string(),
                source: "runtime_detector".to_string(),
                detail: format!("{} ({}%)", runtime.name, runtime.confidence),
            });
        }
    }

    findings.sort_by(|left, right| {
        severity_rank(&right.severity)
            .cmp(&severity_rank(&left.severity))
            .then_with(|| left.category.cmp(&right.category))
            .then_with(|| left.detail.cmp(&right.detail))
    });

    let categories = behavior_categories(&findings);
    let risk_score = risk_score(&findings);
    let risk_level = risk_level(risk_score).to_string();

    BehaviorReport {
        risk_score,
        risk_level,
        categories,
        findings,
    }
}

fn behavior_categories(findings: &[BehaviorFinding]) -> Vec<BehaviorCategoryReport> {
    let mut grouped: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();

    for finding in findings {
        let entry = grouped
            .entry(finding.category.clone())
            .or_insert_with(|| (finding.severity.clone(), Vec::new()));
        if severity_rank(&finding.severity) > severity_rank(&entry.0) {
            entry.0 = finding.severity.clone();
        }
        entry.1.push(finding.detail.clone());
    }

    let mut categories = grouped
        .into_iter()
        .map(|(name, (severity, evidence))| BehaviorCategoryReport {
            name,
            severity,
            evidence_count: evidence.len(),
            evidence,
        })
        .collect::<Vec<_>>();
    categories.sort_by(|left, right| {
        severity_rank(&right.severity)
            .cmp(&severity_rank(&left.severity))
            .then_with(|| left.name.cmp(&right.name))
    });
    categories
}

fn risk_score(findings: &[BehaviorFinding]) -> u8 {
    let mut category_weights: HashMap<&str, u8> = HashMap::new();

    for finding in findings {
        let weight = match finding.severity.as_str() {
            "high" => 35,
            "medium" => 8,
            "low" => 2,
            _ => 0,
        };
        let entry = category_weights
            .entry(finding.category.as_str())
            .or_insert(0);
        *entry = (*entry).max(weight);
    }

    let string_bonus = findings
        .iter()
        .filter(|finding| finding.source == "string")
        .count()
        .min(4) as u8
        * 2;
    let total = category_weights
        .values()
        .sum::<u8>()
        .saturating_add(string_bonus);
    if findings
        .iter()
        .any(|finding| finding.severity.as_str() == "high")
    {
        total.min(100)
    } else {
        total.min(69)
    }
}

fn risk_level(score: u8) -> &'static str {
    match score {
        70..=100 => "high",
        25..=69 => "medium",
        1..=24 => "low",
        _ => "none",
    }
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn build_function_name_map(functions: &[FunctionInfo]) -> HashMap<u64, String> {
    functions
        .iter()
        .map(|function| (function.address, function.name.clone()))
        .collect()
}

fn function_report(
    function: &FunctionInfo,
    function_names: &HashMap<u64, String>,
    strings: &HashMap<u64, &StringInfo>,
    import_addresses: &HashMap<u64, &ImportAddressInfo>,
) -> FunctionReport {
    let tail_calls = tail_call_references(function, function_names, import_addresses);
    FunctionReport {
        name: function.name.clone(),
        address: function.address,
        size: function.size,
        instruction_count: function.instructions.len(),
        basic_block_estimate: basic_block_estimate(function),
        function_kind: function_kind(function),
        is_import: function.is_import,
        is_export: function.is_export,
        calls: call_references(function, function_names, import_addresses),
        tail_calls,
        string_refs: string_references(function, strings),
    }
}

fn cfg_summary(basic_block_count: usize, functions: &[FunctionInfo]) -> CfgSummaryReport {
    let mut direct_call_count = 0;
    let mut conditional_branch_count = 0;
    let mut unconditional_branch_count = 0;
    let mut return_count = 0;

    for instruction in functions.iter().flat_map(|function| &function.instructions) {
        if instruction.is_call() {
            direct_call_count += 1;
        }
        if instruction.is_conditional_jump() {
            conditional_branch_count += 1;
        }
        if instruction.is_unconditional_jump() {
            unconditional_branch_count += 1;
        }
        if instruction.is_return() {
            return_count += 1;
        }
    }

    CfgSummaryReport {
        basic_block_count,
        direct_call_count,
        conditional_branch_count,
        unconditional_branch_count,
        return_count,
    }
}

fn basic_block_estimate(function: &FunctionInfo) -> usize {
    let branch_or_call_count = function
        .instructions
        .iter()
        .filter(|instruction| {
            instruction.is_call()
                || instruction.is_conditional_jump()
                || instruction.is_unconditional_jump()
        })
        .count();

    if function.instructions.is_empty() {
        0
    } else {
        branch_or_call_count + 1
    }
}

fn call_references(
    function: &FunctionInfo,
    function_names: &HashMap<u64, String>,
    import_addresses: &HashMap<u64, &ImportAddressInfo>,
) -> Vec<CallReference> {
    function
        .instructions
        .iter()
        .filter_map(|instruction| {
            let Some(target) = call_target(instruction).or_else(|| import_call_target(instruction))
            else {
                return None;
            };
            if let Some(import) = import_addresses.get(&target) {
                return Some(CallReference {
                    instruction_address: instruction.address(),
                    target_address: target,
                    target_name: Some(format!("{}!{}", import.library, import.function)),
                    target_kind: "import".to_string(),
                    target_library: Some(import.library.clone()),
                    target_symbol: Some(import.function.clone()),
                });
            }

            Some(CallReference {
                instruction_address: instruction.address(),
                target_address: target,
                target_name: function_names.get(&target).cloned(),
                target_kind: "function".to_string(),
                target_library: None,
                target_symbol: None,
            })
        })
        .collect()
}

fn tail_call_references(
    function: &FunctionInfo,
    function_names: &HashMap<u64, String>,
    import_addresses: &HashMap<u64, &ImportAddressInfo>,
) -> Vec<CallReference> {
    function
        .instructions
        .iter()
        .filter(|instruction| instruction.is_unconditional_jump())
        .filter_map(|instruction| {
            let target =
                branch_target(instruction).or_else(|| import_branch_target(instruction))?;
            Some(reference_for_target(
                instruction.address(),
                target,
                function_names,
                import_addresses,
            ))
        })
        .collect()
}

fn reference_for_target(
    instruction_address: u64,
    target: u64,
    function_names: &HashMap<u64, String>,
    import_addresses: &HashMap<u64, &ImportAddressInfo>,
) -> CallReference {
    if let Some(import) = import_addresses.get(&target) {
        return CallReference {
            instruction_address,
            target_address: target,
            target_name: Some(format!("{}!{}", import.library, import.function)),
            target_kind: "import".to_string(),
            target_library: Some(import.library.clone()),
            target_symbol: Some(import.function.clone()),
        };
    }

    CallReference {
        instruction_address,
        target_address: target,
        target_name: function_names.get(&target).cloned(),
        target_kind: "function".to_string(),
        target_library: None,
        target_symbol: None,
    }
}

fn function_kind(function: &FunctionInfo) -> String {
    if function.instructions.len() == 1
        && function
            .instructions
            .first()
            .map(|instruction| instruction.is_unconditional_jump())
            .unwrap_or(false)
    {
        "tailcall_thunk".to_string()
    } else {
        "normal".to_string()
    }
}

fn jump_table_reports(
    function_reports: &[FunctionReport],
    functions: &[FunctionInfo],
) -> Vec<JumpTableReport> {
    let names = function_reports
        .iter()
        .map(|function| (function.address, function.name.clone()))
        .collect::<HashMap<_, _>>();
    let mut reports = Vec::new();

    for function in functions {
        for instruction in &function.instructions {
            let Instruction::X86(instruction) = instruction else {
                continue;
            };
            if !instruction.is_unconditional_jump()
                || instruction.near_branch_target.is_some()
                || !looks_like_jump_table_expression(&instruction.operands)
            {
                continue;
            }
            reports.push(JumpTableReport {
                function_name: names
                    .get(&function.address)
                    .cloned()
                    .unwrap_or_else(|| function.name.clone()),
                function_address: function.address,
                instruction_address: instruction.address,
                expression: instruction.operands.clone(),
            });
        }
    }

    reports
}

fn looks_like_jump_table_expression(operands: &str) -> bool {
    operands.contains('[') && operands.contains(']') && operands.contains('*')
}

fn string_references(
    function: &FunctionInfo,
    strings: &HashMap<u64, &StringInfo>,
) -> Vec<StringReference> {
    let mut refs = Vec::new();
    let mut seen = BTreeSet::new();

    for instruction in &function.instructions {
        for address in referenced_addresses(instruction) {
            let Some(string) = strings.get(&address) else {
                continue;
            };
            if !seen.insert((instruction.address(), address)) {
                continue;
            }
            refs.push(StringReference {
                instruction_address: instruction.address(),
                address,
                symbol: string_symbol(address),
                value: string.value.clone(),
            });
        }
    }

    refs
}

fn call_target(instruction: &Instruction) -> Option<u64> {
    match instruction {
        Instruction::X86(instruction) if instruction.is_call() => instruction.near_branch_target,
        Instruction::Arm(_) if instruction.is_call() => None,
        _ => None,
    }
}

fn import_call_target(instruction: &Instruction) -> Option<u64> {
    match instruction {
        Instruction::X86(instruction) if instruction.is_call() => referenced_memory_address(
            instruction.address,
            instruction.length,
            &instruction.operands,
        ),
        _ => None,
    }
}

fn branch_target(instruction: &Instruction) -> Option<u64> {
    match instruction {
        Instruction::X86(instruction)
            if instruction.is_call() || instruction.is_unconditional_jump() =>
        {
            instruction.near_branch_target
        }
        _ => None,
    }
}

fn import_branch_target(instruction: &Instruction) -> Option<u64> {
    match instruction {
        Instruction::X86(instruction)
            if instruction.is_call() || instruction.is_unconditional_jump() =>
        {
            referenced_memory_address(
                instruction.address,
                instruction.length,
                &instruction.operands,
            )
        }
        _ => None,
    }
}

fn referenced_memory_address(address: u64, length: usize, operands: &str) -> Option<u64> {
    if !operands.contains('[') || !operands.contains(']') {
        return None;
    }

    let lower = operands.to_ascii_lowercase();
    let first_hex = collect_hex_addresses(operands).into_iter().next()?;

    if lower.contains("rip+") || lower.contains("rip +") {
        Some(address.wrapping_add(length as u64).wrapping_add(first_hex))
    } else if lower.contains("rip-") || lower.contains("rip -") {
        Some(address.wrapping_add(length as u64).wrapping_sub(first_hex))
    } else {
        Some(first_hex)
    }
}

fn referenced_addresses(instruction: &Instruction) -> Vec<u64> {
    let text = match instruction {
        Instruction::X86(instruction) => {
            if instruction.operands.is_empty() {
                instruction.mnemonic.clone()
            } else {
                format!("{} {}", instruction.mnemonic, instruction.operands)
            }
        }
        Instruction::Arm(instruction) => {
            if instruction.operands.is_empty() {
                instruction.mnemonic.clone()
            } else {
                format!("{} {}", instruction.mnemonic, instruction.operands)
            }
        }
    };

    collect_hex_addresses(&text)
}

fn collect_hex_addresses(text: &str) -> Vec<u64> {
    text.split(|ch: char| {
        !(ch.is_ascii_hexdigit() || ch == 'x' || ch == 'X' || ch == 'h' || ch == 'H')
    })
    .filter_map(parse_hex_token)
    .collect()
}

fn parse_hex_token(token: &str) -> Option<u64> {
    if token.len() < 2 {
        return None;
    }

    let stripped = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
        .or_else(|| token.strip_suffix('h'))
        .or_else(|| token.strip_suffix('H'))?;

    if stripped.is_empty() || !stripped.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }

    u64::from_str_radix(stripped, 16).ok()
}

fn string_report(string: &StringInfo) -> StringReport {
    StringReport {
        address: string.address,
        symbol: string_symbol(string.address),
        value: string.value.clone(),
        encoding: format!("{:?}", string.encoding),
        length: string.length,
    }
}

fn section_report(section: &SectionInfo) -> SectionReport {
    SectionReport {
        name: section.name.clone(),
        virtual_address: section.virtual_address,
        size: section.size,
        raw_size: section.raw_data.len(),
        is_code: section.characteristics.is_code,
        is_data: section.characteristics.is_data,
        is_readable: section.characteristics.is_readable,
        is_writable: section.characteristics.is_writable,
        is_executable: section.characteristics.is_executable,
    }
}

fn suspicious_string_report(string: &StringInfo) -> Option<SuspiciousStringReport> {
    let category = suspicious_string_category(&string.value)?;
    Some(SuspiciousStringReport {
        address: string.address,
        symbol: string_symbol(string.address),
        value: string.value.clone(),
        category: category.to_string(),
    })
}

fn import_address_report(import: &ImportAddressInfo) -> ImportAddressReport {
    ImportAddressReport {
        library: import.library.clone(),
        function: import.function.clone(),
        address: import.address,
        ordinal: import.ordinal,
    }
}

fn suspicious_string_category(value: &str) -> Option<&'static str> {
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        Some("url")
    } else if lower.contains("powershell")
        || lower.contains("cmd.exe")
        || lower.contains("/bin/sh")
        || lower.contains("curl ")
        || lower.contains("wget ")
    {
        Some("command")
    } else if lower.contains("password")
        || lower.contains("passwd")
        || lower.contains("token")
        || lower.contains("apikey")
        || lower.contains("api_key")
        || lower.contains("secret")
    {
        Some("credential_hint")
    } else if lower.ends_with(".dll")
        || lower.ends_with(".exe")
        || lower.ends_with(".sys")
        || lower.contains("\\software\\")
    {
        Some("platform_indicator")
    } else {
        None
    }
}

fn behavior_from_string_category(category: &str) -> (&'static str, &'static str) {
    match category {
        "url" => ("network", "medium"),
        "command" => ("process_execution", "medium"),
        "credential_hint" => ("credential_access", "medium"),
        "platform_indicator" => ("filesystem", "low"),
        _ => ("string_indicator", "low"),
    }
}

fn classify_api(function: &str) -> Option<(&'static str, &'static str, &'static str)> {
    let name = function.to_ascii_lowercase();

    if matches_any(
        &name,
        &[
            "createremotethread",
            "ntcreatethreadex",
            "writeprocessmemory",
            "readprocessmemory",
            "virtualallocex",
            "openprocess",
            "setthreadcontext",
            "queueuserapc",
        ],
    ) {
        Some((
            "process_injection",
            "high",
            "process memory/thread manipulation API",
        ))
    } else if matches_any(
        &name,
        &[
            "internetopen",
            "internetconnect",
            "internetopenurl",
            "httpopenrequest",
            "httpsendrequest",
            "winhttpopen",
            "winhttpconnect",
            "winhttpsendrequest",
            "wsastartup",
            "connect",
            "send",
            "recv",
            "urldownloadtofile",
        ],
    ) {
        Some(("network", "medium", "network communication API"))
    } else if matches_any(
        &name,
        &[
            "regopenkey",
            "regcreatekey",
            "regsetvalue",
            "regqueryvalue",
            "regdeletekey",
            "regdeletevalue",
        ],
    ) {
        Some(("registry", "medium", "Windows registry access API"))
    } else if matches_any(
        &name,
        &[
            "createprocess",
            "shellexecute",
            "winexec",
            "system",
            "terminateprocess",
        ],
    ) {
        Some((
            "process_execution",
            "medium",
            "process execution/control API",
        ))
    } else if matches_any(
        &name,
        &[
            "createfile",
            "readfile",
            "writefile",
            "deletefile",
            "movefile",
            "copyfile",
            "findfirstfile",
            "findnextfile",
            "getfileattributes",
            "setfileattributes",
        ],
    ) {
        Some(("filesystem", "medium", "file access or filesystem API"))
    } else if matches_any(
        &name,
        &[
            "virtualalloc",
            "virtualprotect",
            "heapalloc",
            "rtlmovememory",
            "rtlcopymemory",
        ],
    ) {
        Some(("memory", "medium", "memory allocation/protection API"))
    } else if matches_any(&name, &["loadlibrary", "getprocaddress", "ldrloaddll"]) {
        Some((
            "dynamic_loading",
            "medium",
            "runtime library loading or symbol lookup API",
        ))
    } else if matches_any(
        &name,
        &[
            "isdebuggerpresent",
            "checkremotedebuggerpresent",
            "outputdebugstring",
            "ntqueryinformationprocess",
        ],
    ) {
        Some(("anti_debug", "medium", "debugger detection API"))
    } else if matches_any(
        &name,
        &[
            "cryptacquirecontext",
            "cryptprotectdata",
            "cryptdecrypt",
            "cryptencrypt",
            "bcrypt",
            "openssl",
        ],
    ) {
        Some(("crypto", "medium", "cryptography or protected-data API"))
    } else if matches_any(
        &name,
        &[
            "createservice",
            "openservice",
            "startservice",
            "changeserviceconfig",
            "schtasks",
        ],
    ) {
        Some((
            "persistence",
            "high",
            "service or scheduled-task persistence API",
        ))
    } else {
        None
    }
}

fn matches_any(name: &str, prefixes: &[&str]) -> bool {
    prefixes
        .iter()
        .any(|candidate| api_name_matches(name, candidate))
}

fn api_name_matches(name: &str, candidate: &str) -> bool {
    let candidate = candidate.to_ascii_lowercase();
    name == candidate
        || name == format!("{candidate}a")
        || name == format!("{candidate}w")
        || name == format!("{candidate}ex")
        || name == format!("{candidate}exa")
        || name == format!("{candidate}exw")
        || name == format!("{candidate}2")
        || name == format!("{candidate}2a")
        || name == format!("{candidate}2w")
}

fn string_symbol(address: u64) -> String {
    format!("str_{:X}", address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::functions::FunctionInfo;
    use crate::analysis::strings::{StringEncoding, StringInfo};
    use crate::binary::parser::{
        ExportInfo, ImportAddressInfo, ImportInfo, SectionCharacteristics, SectionInfo,
    };
    use crate::disasm::control_flow::Instruction;
    use crate::disasm::X86Instruction;

    fn x86(address: u64, mnemonic: &str, operands: &str, target: Option<u64>) -> Instruction {
        x86_with_len(address, mnemonic, operands, 1, target)
    }

    fn x86_with_len(
        address: u64,
        mnemonic: &str,
        operands: &str,
        length: usize,
        target: Option<u64>,
    ) -> Instruction {
        Instruction::X86(X86Instruction {
            address,
            bytes: vec![0x90; length],
            mnemonic: mnemonic.to_string(),
            operands: operands.to_string(),
            length,
            ir: None,
            near_branch_target: target,
        })
    }

    fn function(name: &str, address: u64, instructions: Vec<Instruction>) -> FunctionInfo {
        FunctionInfo {
            name: name.to_string(),
            address,
            size: instructions.len(),
            instructions,
            is_import: false,
            is_export: false,
        }
    }

    fn string(address: u64, value: &str) -> StringInfo {
        StringInfo {
            address,
            value: value.to_string(),
            encoding: StringEncoding::Ascii,
            length: value.len(),
        }
    }

    fn import_address(library: &str, function: &str, address: u64) -> ImportAddressInfo {
        ImportAddressInfo {
            library: library.to_string(),
            function: function.to_string(),
            address,
            ordinal: None,
        }
    }

    #[test]
    fn package_maps_direct_calls_to_known_function_names() {
        let functions = vec![
            function(
                "sub_1000",
                0x1000,
                vec![x86(0x1000, "call", "2000h", Some(0x2000))],
            ),
            function("sub_2000", 0x2000, vec![x86(0x2000, "ret", "", None)]),
        ];

        let package = AnalysisReportBuilder::new().build(AnalysisReportInputs {
            input_path: "sample.exe",
            format: "PE/EXE",
            architecture: "x64",
            entry_point: 0x1000,
            instruction_count: 2,
            basic_block_count: 2,
            sections: &[],
            functions: &functions,
            strings: &[],
            imports: &[],
            import_addresses: &[],
            exports: &[],
            runtime_matches: &[],
        });

        let caller = package
            .functions
            .iter()
            .find(|function| function.name == "sub_1000")
            .expect("caller exists");

        assert_eq!(caller.calls.len(), 1);
        assert_eq!(caller.calls[0].target_address, 0x2000);
        assert_eq!(caller.calls[0].target_name.as_deref(), Some("sub_2000"));
    }

    #[test]
    fn package_resolves_indirect_iat_calls_to_import_names() {
        let functions = vec![function(
            "sub_1000",
            0x1000,
            vec![x86(0x1000, "call", "qword ptr [3000h]", None)],
        )];
        let imports = vec![ImportInfo {
            name: "kernel32.dll".to_string(),
            functions: vec!["CreateFileW".to_string()],
        }];
        let import_addresses = vec![import_address("kernel32.dll", "CreateFileW", 0x3000)];

        let package = AnalysisReportBuilder::new().build(AnalysisReportInputs {
            input_path: "sample.exe",
            format: "PE/EXE",
            architecture: "x64",
            entry_point: 0x1000,
            instruction_count: 1,
            basic_block_count: 1,
            sections: &[],
            functions: &functions,
            strings: &[],
            imports: &imports,
            import_addresses: &import_addresses,
            exports: &[],
            runtime_matches: &[],
        });

        let call = &package.functions[0].calls[0];
        assert_eq!(call.target_address, 0x3000);
        assert_eq!(
            call.target_name.as_deref(),
            Some("kernel32.dll!CreateFileW")
        );
        assert_eq!(call.target_kind, "import");
        assert_eq!(call.target_library.as_deref(), Some("kernel32.dll"));
        assert_eq!(call.target_symbol.as_deref(), Some("CreateFileW"));
        assert_eq!(package.import_addresses[0].address, 0x3000);
    }

    #[test]
    fn package_tracks_import_xref_call_sites() {
        let functions = vec![
            function(
                "sub_1000",
                0x1000,
                vec![x86(0x1000, "call", "qword ptr [3000h]", None)],
            ),
            function(
                "sub_2000",
                0x2000,
                vec![x86(0x2000, "call", "qword ptr [3000h]", None)],
            ),
        ];
        let imports = vec![ImportInfo {
            name: "kernel32.dll".to_string(),
            functions: vec!["CreateFileW".to_string()],
        }];
        let import_addresses = vec![import_address("kernel32.dll", "CreateFileW", 0x3000)];

        let package = AnalysisReportBuilder::new().build(AnalysisReportInputs {
            input_path: "sample.exe",
            format: "PE/EXE",
            architecture: "x64",
            entry_point: 0x1000,
            instruction_count: 2,
            basic_block_count: 2,
            sections: &[],
            functions: &functions,
            strings: &[],
            imports: &imports,
            import_addresses: &import_addresses,
            exports: &[],
            runtime_matches: &[],
        });

        let import_xref = package
            .xrefs
            .imports
            .iter()
            .find(|xref| xref.function == "CreateFileW")
            .expect("import xref exists");

        assert_eq!(import_xref.address, Some(0x3000));
        assert_eq!(import_xref.referenced_by.len(), 2);
        assert_eq!(import_xref.referenced_by[0].function_name, "sub_1000");
        assert_eq!(import_xref.referenced_by[1].function_name, "sub_2000");
    }

    #[test]
    fn package_resolves_rip_relative_iat_calls_to_import_names() {
        let functions = vec![function(
            "sub_1000",
            0x1000,
            vec![x86_with_len(
                0x1000,
                "call",
                "qword ptr [rip+1FFAh]",
                6,
                None,
            )],
        )];
        let imports = vec![ImportInfo {
            name: "kernel32.dll".to_string(),
            functions: vec!["GetProcAddress".to_string()],
        }];
        let import_addresses = vec![import_address("kernel32.dll", "GetProcAddress", 0x3000)];

        let package = AnalysisReportBuilder::new().build(AnalysisReportInputs {
            input_path: "sample.exe",
            format: "PE/EXE",
            architecture: "x64",
            entry_point: 0x1000,
            instruction_count: 1,
            basic_block_count: 1,
            sections: &[],
            functions: &functions,
            strings: &[],
            imports: &imports,
            import_addresses: &import_addresses,
            exports: &[],
            runtime_matches: &[],
        });

        assert_eq!(
            package.functions[0].calls[0].target_name.as_deref(),
            Some("kernel32.dll!GetProcAddress")
        );
        assert_eq!(package.functions[0].calls[0].target_address, 0x3000);
    }

    #[test]
    fn package_maps_exact_string_references() {
        let functions = vec![function(
            "sub_1000",
            0x1000,
            vec![x86(0x1000, "lea", "rcx, [3000h]", None)],
        )];
        let strings = vec![string(0x3000, "hello")];

        let package = AnalysisReportBuilder::new().build(AnalysisReportInputs {
            input_path: "sample.exe",
            format: "PE/EXE",
            architecture: "x64",
            entry_point: 0x1000,
            instruction_count: 1,
            basic_block_count: 1,
            sections: &[],
            functions: &functions,
            strings: &strings,
            imports: &[],
            import_addresses: &[],
            exports: &[],
            runtime_matches: &[],
        });

        let refs = &package.functions[0].string_refs;
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].address, 0x3000);
        assert_eq!(refs[0].symbol, "str_3000");
        assert_eq!(refs[0].value, "hello");
    }

    #[test]
    fn package_summary_counts_analysis_outputs() {
        let functions = vec![function(
            "sub_1000",
            0x1000,
            vec![x86(0x1000, "ret", "", None)],
        )];
        let strings = vec![string(0x3000, "hello")];
        let imports = vec![ImportInfo {
            name: "kernel32.dll".to_string(),
            functions: vec!["CreateFileW".to_string()],
        }];
        let exports = vec![ExportInfo {
            name: "Exported".to_string(),
            address: 0x1000,
            ordinal: Some(1),
        }];

        let package = AnalysisReportBuilder::new().build(AnalysisReportInputs {
            input_path: "sample.exe",
            format: "PE/EXE",
            architecture: "x64",
            entry_point: 0x1000,
            instruction_count: 1,
            basic_block_count: 1,
            sections: &[],
            functions: &functions,
            strings: &strings,
            imports: &imports,
            import_addresses: &[],
            exports: &exports,
            runtime_matches: &[],
        });

        assert_eq!(package.summary.function_count, 1);
        assert_eq!(package.summary.string_count, 1);
        assert_eq!(package.summary.import_count, 1);
        assert_eq!(package.summary.export_count, 1);
        assert_eq!(package.imports[0].functions, vec!["CreateFileW"]);
        assert_eq!(package.exports[0].ordinal, Some(1));
    }

    fn section(
        name: &str,
        address: u64,
        size: u64,
        characteristics: SectionCharacteristics,
    ) -> SectionInfo {
        SectionInfo {
            name: name.to_string(),
            virtual_address: address,
            size,
            raw_data: vec![0; size as usize],
            characteristics,
        }
    }

    #[test]
    fn package_includes_sections_cfg_summary_and_suspicious_strings() {
        let sections = vec![
            section(
                ".text",
                0x1000,
                0x200,
                SectionCharacteristics {
                    is_code: true,
                    is_readable: true,
                    is_executable: true,
                    ..SectionCharacteristics::default()
                },
            ),
            section(
                ".rdata",
                0x3000,
                0x80,
                SectionCharacteristics {
                    is_data: true,
                    is_readable: true,
                    ..SectionCharacteristics::default()
                },
            ),
        ];
        let functions = vec![function(
            "sub_1000",
            0x1000,
            vec![
                x86(0x1000, "call", "2000h", Some(0x2000)),
                x86(0x1005, "jne", "1010h", Some(0x1010)),
            ],
        )];
        let strings = vec![string(0x3000, "http://evil.test/payload")];

        let package = AnalysisReportBuilder::new().build(AnalysisReportInputs {
            input_path: "sample.exe",
            format: "PE/EXE",
            architecture: "x64",
            entry_point: 0x1000,
            instruction_count: 2,
            basic_block_count: 3,
            sections: &sections,
            functions: &functions,
            strings: &strings,
            imports: &[],
            import_addresses: &[],
            exports: &[],
            runtime_matches: &[],
        });

        assert_eq!(package.sections.len(), 2);
        assert_eq!(package.sections[0].name, ".text");
        assert!(package.sections[0].is_executable);
        assert_eq!(package.cfg_summary.basic_block_count, 3);
        assert_eq!(package.cfg_summary.direct_call_count, 1);
        assert_eq!(package.cfg_summary.conditional_branch_count, 1);
        assert_eq!(package.functions[0].basic_block_estimate, 3);
        assert_eq!(package.suspicious_strings[0].address, 0x3000);
        assert_eq!(package.suspicious_strings[0].category, "url");
    }

    #[test]
    fn package_suggests_cyberchef_recipes_for_encoded_strings() {
        let strings = vec![
            string(0x3000, "SGVsbG8sIHdvcmxkIQ=="),
            string(0x3040, "kernel32.dll"),
        ];

        let package = AnalysisReportBuilder::new().build(AnalysisReportInputs {
            input_path: "sample.exe",
            format: "PE/EXE",
            architecture: "x64",
            entry_point: 0x1000,
            instruction_count: 0,
            basic_block_count: 0,
            sections: &[],
            functions: &[],
            strings: &strings,
            imports: &[],
            import_addresses: &[],
            exports: &[],
            runtime_matches: &[],
        });

        assert_eq!(package.cyberchef_recipes.len(), 1);
        let recipe = &package.cyberchef_recipes[0];
        assert_eq!(recipe.address, 0x3000);
        assert_eq!(recipe.signal, "base64");
        assert!(recipe
            .recipe
            .iter()
            .any(|operation| operation.operation == "From Base64"));
    }

    #[test]
    fn package_builds_deduplicated_call_graph_edges_with_call_sites() {
        let functions = vec![
            function(
                "sub_1000",
                0x1000,
                vec![
                    x86(0x1000, "call", "2000h", Some(0x2000)),
                    x86(0x1005, "call", "2000h", Some(0x2000)),
                ],
            ),
            function("sub_2000", 0x2000, vec![x86(0x2000, "ret", "", None)]),
        ];

        let package = AnalysisReportBuilder::new().build(AnalysisReportInputs {
            input_path: "sample.exe",
            format: "PE/EXE",
            architecture: "x64",
            entry_point: 0x1000,
            instruction_count: 3,
            basic_block_count: 2,
            sections: &[],
            functions: &functions,
            strings: &[],
            imports: &[],
            import_addresses: &[],
            exports: &[],
            runtime_matches: &[],
        });

        assert_eq!(package.call_graph.len(), 1);
        assert_eq!(package.call_graph[0].caller_name, "sub_1000");
        assert_eq!(
            package.call_graph[0].callee_name.as_deref(),
            Some("sub_2000")
        );
        assert_eq!(package.call_graph[0].call_count, 2);
        assert_eq!(package.call_graph[0].call_sites, vec![0x1000, 0x1005]);
    }

    #[test]
    fn package_marks_tailcall_thunks_and_jump_table_candidates() {
        let functions = vec![
            function(
                "sub_1000",
                0x1000,
                vec![x86(0x1000, "jmp", "2000h", Some(0x2000))],
            ),
            function("sub_2000", 0x2000, vec![x86(0x2000, "ret", "", None)]),
            function(
                "sub_3000",
                0x3000,
                vec![x86(0x3000, "jmp", "qword ptr [rax*8+4000h]", None)],
            ),
        ];

        let package = AnalysisReportBuilder::new().build(AnalysisReportInputs {
            input_path: "sample.exe",
            format: "PE/EXE",
            architecture: "x64",
            entry_point: 0x1000,
            instruction_count: 3,
            basic_block_count: 3,
            sections: &[],
            functions: &functions,
            strings: &[],
            imports: &[],
            import_addresses: &[],
            exports: &[],
            runtime_matches: &[],
        });

        let thunk = package
            .functions
            .iter()
            .find(|function| function.name == "sub_1000")
            .expect("thunk report exists");
        assert_eq!(thunk.function_kind, "tailcall_thunk");
        assert_eq!(thunk.tail_calls.len(), 1);
        assert_eq!(thunk.tail_calls[0].target_name.as_deref(), Some("sub_2000"));

        assert_eq!(package.jump_tables.len(), 1);
        assert_eq!(package.jump_tables[0].function_name, "sub_3000");
        assert_eq!(package.jump_tables[0].instruction_address, 0x3000);
    }

    #[test]
    fn package_indexes_strings_by_function() {
        let functions = vec![
            function(
                "sub_1000",
                0x1000,
                vec![x86(0x1000, "lea", "rcx, [3000h]", None)],
            ),
            function("sub_2000", 0x2000, vec![x86(0x2000, "ret", "", None)]),
        ];
        let strings = vec![string(0x3000, "hello")];

        let package = AnalysisReportBuilder::new().build(AnalysisReportInputs {
            input_path: "sample.exe",
            format: "PE/EXE",
            architecture: "x64",
            entry_point: 0x1000,
            instruction_count: 2,
            basic_block_count: 2,
            sections: &[],
            functions: &functions,
            strings: &strings,
            imports: &[],
            import_addresses: &[],
            exports: &[],
            runtime_matches: &[],
        });

        assert_eq!(package.strings_by_function.len(), 1);
        assert_eq!(package.strings_by_function[0].function_name, "sub_1000");
        assert_eq!(package.strings_by_function[0].strings.len(), 1);
        assert_eq!(package.strings_by_function[0].strings[0].symbol, "str_3000");
    }

    #[test]
    fn package_groups_function_xrefs_with_callers_and_strings() {
        let functions = vec![
            function(
                "sub_1000",
                0x1000,
                vec![
                    x86(0x1000, "call", "2000h", Some(0x2000)),
                    x86(0x1005, "lea", "rcx, [3000h]", None),
                ],
            ),
            function("sub_2000", 0x2000, vec![x86(0x2000, "ret", "", None)]),
            function(
                "sub_3000",
                0x3000,
                vec![x86(0x3000, "call", "2000h", Some(0x2000))],
            ),
        ];
        let strings = vec![string(0x3000, "C:\\temp\\payload.exe")];

        let package = AnalysisReportBuilder::new().build(AnalysisReportInputs {
            input_path: "sample.exe",
            format: "PE/EXE",
            architecture: "x64",
            entry_point: 0x1000,
            instruction_count: 4,
            basic_block_count: 3,
            sections: &[],
            functions: &functions,
            strings: &strings,
            imports: &[],
            import_addresses: &[],
            exports: &[],
            runtime_matches: &[],
        });

        let callee = package
            .xrefs
            .functions
            .iter()
            .find(|xref| xref.function_name == "sub_2000")
            .expect("callee xref exists");
        assert_eq!(callee.called_by.len(), 2);
        assert_eq!(callee.called_by[0].caller_name, "sub_1000");
        assert_eq!(callee.called_by[1].caller_name, "sub_3000");

        let caller = package
            .xrefs
            .functions
            .iter()
            .find(|xref| xref.function_name == "sub_1000")
            .expect("caller xref exists");
        assert_eq!(caller.calls_out.len(), 1);
        assert_eq!(caller.strings.len(), 1);
        assert_eq!(caller.strings[0].symbol, "str_3000");
    }

    #[test]
    fn package_classifies_import_apis_into_behavior_report() {
        let imports = vec![
            ImportInfo {
                name: "kernel32.dll".to_string(),
                functions: vec![
                    "CreateFileW".to_string(),
                    "VirtualAlloc".to_string(),
                    "WriteProcessMemory".to_string(),
                    "CreateRemoteThread".to_string(),
                ],
            },
            ImportInfo {
                name: "wininet.dll".to_string(),
                functions: vec!["InternetOpenUrlW".to_string()],
            },
        ];
        let strings = vec![
            string(0x3000, "https://example.test/dropper"),
            string(0x3040, "powershell -nop"),
        ];

        let package = AnalysisReportBuilder::new().build(AnalysisReportInputs {
            input_path: "sample.exe",
            format: "PE/EXE",
            architecture: "x64",
            entry_point: 0x1000,
            instruction_count: 0,
            basic_block_count: 0,
            sections: &[],
            functions: &[],
            strings: &strings,
            imports: &imports,
            import_addresses: &[],
            exports: &[],
            runtime_matches: &[],
        });

        assert!(package
            .api_insights
            .iter()
            .any(|api| api.function == "CreateFileW" && api.category == "filesystem"));
        assert!(package
            .api_insights
            .iter()
            .any(|api| api.function == "InternetOpenUrlW" && api.category == "network"));
        assert!(package
            .behavior_report
            .categories
            .iter()
            .any(|category| category.name == "process_injection" && category.severity == "high"));
        assert_eq!(package.behavior_report.risk_level, "high");
        assert!(package.behavior_report.risk_score >= 60);
    }

    #[test]
    fn api_classifier_avoids_common_prefix_false_positives() {
        let imports = vec![
            ImportInfo {
                name: "user32.dll".to_string(),
                functions: vec![
                    "SendMessageW".to_string(),
                    "SystemParametersInfoForDpi".to_string(),
                ],
            },
            ImportInfo {
                name: "advapi32.dll".to_string(),
                functions: vec!["OpenProcessToken".to_string()],
            },
        ];

        let package = AnalysisReportBuilder::new().build(AnalysisReportInputs {
            input_path: "sample.exe",
            format: "PE/EXE",
            architecture: "x64",
            entry_point: 0x1000,
            instruction_count: 0,
            basic_block_count: 0,
            sections: &[],
            functions: &[],
            strings: &[],
            imports: &imports,
            import_addresses: &[],
            exports: &[],
            runtime_matches: &[],
        });

        assert!(package.api_insights.is_empty());
        assert!(package.behavior_report.categories.is_empty());
        assert_eq!(package.behavior_report.risk_level, "none");
    }
}
