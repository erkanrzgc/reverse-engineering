use clap::{Args, Parser, Subcommand, ValueEnum};
use reverse_engineering::decompiler::OptimizationLevel;
use reverse_engineering::{AnalysisConfig, AnalysisEngine, OutputSelection, ResourceLimits};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "reverse-engineering",
    version,
    about = "Binary to source code decompiler"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    Analyze(AnalyzeArgs),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Format {
    C,
    Json,
}
#[derive(Clone, Copy, Debug, ValueEnum)]
enum Optimization {
    None,
    Basic,
    Aggressive,
}
#[derive(Args)]
struct AnalyzeArgs {
    input: PathBuf,
    #[arg(short, long)]
    output: Option<PathBuf>,
    #[arg(short, long, value_enum)]
    format: Option<Format>,
    #[arg(short = 'O', long, value_enum, default_value_t = Optimization::Basic)]
    optimization: Optimization,
    #[arg(long, conflicts_with = "verbose")]
    quiet: bool,
    #[arg(short, long, conflicts_with = "quiet")]
    verbose: bool,
    #[arg(long)]
    report_dir: Option<PathBuf>,
    #[arg(long)]
    artifacts_dir: Option<PathBuf>,
    /// Build the report without generated C or runtime payload extraction.
    #[arg(long)]
    only_report: bool,
    #[arg(long, default_value_t = 512 * 1024 * 1024)]
    max_input_bytes: u64,
    #[arg(long, default_value_t = 100_000)]
    max_extracted_strings: usize,
    #[arg(long, default_value_t = 1024)]
    max_runtime_artifacts: usize,
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    max_runtime_artifact_bytes: usize,
}
fn main() -> ExitCode {
    let cli = Cli::parse();
    let Commands::Analyze(args) = cli.command;
    let format = args.format.unwrap_or(if args.only_report {
        Format::Json
    } else {
        Format::C
    });
    if args.only_report && format == Format::C {
        eprintln!("usage error: --only-report requires JSON output; omit --format or select json");
        return ExitCode::from(2);
    }
    if format == Format::C
        && args
            .output
            .as_ref()
            .is_some_and(|p| p.extension().is_some_and(|e| e == "json"))
    {
        eprintln!("usage error: C format cannot use a .json output path");
        return ExitCode::from(2);
    }
    init_logging(args.quiet, args.verbose);
    let config = AnalysisConfig {
        optimization: match args.optimization {
            Optimization::None => OptimizationLevel::None,
            Optimization::Basic => OptimizationLevel::Basic,
            Optimization::Aggressive => OptimizationLevel::Aggressive,
        },
        outputs: if args.only_report {
            OutputSelection::report_only()
        } else {
            OutputSelection::all()
        },
        limits: ResourceLimits {
            max_input_bytes: args.max_input_bytes,
            max_extracted_strings: args.max_extracted_strings,
            max_runtime_artifacts: args.max_runtime_artifacts,
            max_runtime_artifact_bytes: args.max_runtime_artifact_bytes,
        },
    };
    let result = match AnalysisEngine::analyze_path(&args.input, &config) {
        Ok(result) => result,
        Err(error) => {
            eprintln!(
                "error code={} stage={:?}: {}",
                code_name(error.code()),
                error.diagnostic().stage,
                error.diagnostic().message
            );
            return ExitCode::from(3);
        }
    };
    if let Err(error) = reverse_engineering::output::write_outputs(
        &result,
        matches!(format, Format::Json),
        args.output.as_deref(),
        args.report_dir.as_deref(),
        args.artifacts_dir.as_deref(),
    ) {
        eprintln!("error code=output_failure: {error}");
        return ExitCode::from(3);
    }
    for diagnostic in &result.diagnostics {
        eprintln!(
            "warning code={} stage={:?}: {}",
            code_name(diagnostic.code),
            diagnostic.stage,
            diagnostic.message
        );
    }
    if result.status == reverse_engineering::AnalysisStatus::Partial {
        ExitCode::from(4)
    } else {
        ExitCode::SUCCESS
    }
}
fn init_logging(quiet: bool, verbose: bool) {
    let level = if quiet {
        "warn"
    } else if verbose {
        "debug"
    } else {
        "info"
    };
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_env_filter(format!("reverse_engineering={level}"))
        .try_init();
}

fn code_name(code: reverse_engineering::DiagnosticCode) -> String {
    serde_json::to_string(&code)
        .unwrap_or_else(|_| "internal_failure".to_string())
        .trim_matches('"')
        .to_string()
}
