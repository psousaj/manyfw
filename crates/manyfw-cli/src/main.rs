use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "manyfw", version, about = "Policy-first firewall manager (preview: read-only)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate a TOML policy without accessing the firewall.
    Check { #[arg(short, long, default_value = "examples/manyfw.toml")] file: PathBuf },
    /// Show a deterministic policy summary; no kernel changes are made.
    Plan { #[arg(short, long, default_value = "examples/manyfw.toml")] file: PathBuf },
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
    let config = manyfw_core::parse_and_validate(&input)?;
    match cli.command {
        Command::Check { .. } => println!("Valid schema v{}: {} zones, {} services", config.version, config.zones.len(), config.services.len()),
        Command::Plan { .. } => {
            println!("PREVIEW ONLY — not a kernel firewall plan; no rules will be applied");
            for (name, service) in config.services {
                println!("service {name} ({}) <- {}", service.target, service.allow.join(", "));
            }
        }
    }
    Ok(())
}
