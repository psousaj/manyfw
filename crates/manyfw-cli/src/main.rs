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
        Command::Check { file } | Command::Plan { file } => file,
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
