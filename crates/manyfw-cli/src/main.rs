use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "manyfw",
    version,
    about = "Policy-first firewall manager (preview: read-only)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate a TOML policy without accessing the firewall.
    Check {
        #[arg(short, long, default_value = "examples/manyfw.toml")]
        file: PathBuf,
    },
    /// Show a deterministic policy summary; no kernel changes are made.
    Plan {
        #[arg(short, long, default_value = "examples/manyfw.toml")]
        file: PathBuf,
    },
    /// Evaluate a normalized policy against a read-only observation snapshot.
    Audit {
        #[arg(short, long, default_value = "examples/manyfw.toml")]
        file: PathBuf,
        /// JSON snapshot produced by discovery; no live collection is performed.
        #[arg(short, long)]
        snapshot: PathBuf,
        /// Output format: human or json.
        #[arg(long, default_value = "human")]
        format: String,
    },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let file = match &cli.command {
        Command::Check { file } | Command::Plan { file } | Command::Audit { file, .. } => file,
    };
    let input = std::fs::read_to_string(file)?;
    let report = manyfw_core::parse_and_normalize(&input)?;
    let policy = report.policy;
    let diagnostics = report.diagnostics;
    match cli.command {
        Command::Check { .. } => {
            println!(
                "Valid schema v{}: {} zones, {} rules",
                policy.version,
                policy.zones.len(),
                policy.rules.len()
            );
            print_diagnostics(&diagnostics);
        }
        Command::Plan { .. } => {
            println!("PREVIEW ONLY — not a kernel firewall plan; no rules will be applied");
            print_diagnostics(&diagnostics);
            for rule in policy.rules {
                println!(
                    "rule {}: priority={} {:?} -> {:?} {:?} ports={:?} action={:?}",
                    rule.id,
                    rule.priority,
                    rule.source,
                    rule.destination,
                    rule.protocol,
                    rule.ports,
                    rule.action
                );
            }
        }
        Command::Audit {
            snapshot, format, ..
        } => {
            let snapshot_input = std::fs::read_to_string(snapshot)?;
            let snapshot: manyfw_core::snapshot::ObservationSnapshot =
                serde_json::from_str(&snapshot_input)?;
            let report = manyfw_core::audit::evaluate(&policy, &snapshot)?;
            match format.as_str() {
                "human" => print!("{}", report.human()),
                "json" => print!("{}", report.json()?),
                other => {
                    return Err(
                        format!("unsupported audit format {other:?}; use human or json").into(),
                    );
                }
            }
        }
    }
    Ok(())
}

fn print_diagnostics(diagnostics: &[manyfw_core::Diagnostic]) {
    for diagnostic in diagnostics {
        println!(
            "{:?} {:?}: {}{}{}",
            diagnostic.severity,
            diagnostic.code,
            diagnostic.message,
            diagnostic
                .location
                .as_ref()
                .map(|location| format!(" ({location})"))
                .unwrap_or_default(),
            if diagnostic.rule_ids.is_empty() {
                String::new()
            } else {
                format!(" [rules: {}]", diagnostic.rule_ids.join(", "))
            }
        );
    }
}
