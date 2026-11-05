use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod docker_engine;

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
    /// Explain one stable service identity from a read-only observation snapshot.
    Explain {
        #[arg(short, long, default_value = "examples/manyfw.toml")]
        file: PathBuf,
        /// JSON snapshot produced by discovery; no live collection is performed.
        #[arg(short, long)]
        snapshot: PathBuf,
        /// Stable identity or unique short Docker service selector.
        service: String,
        /// Output format: human or json.
        #[arg(long, default_value = "human")]
        format: String,
    },
    /// Collect a read-only Docker/host observation snapshot.
    Discover {
        /// Write JSON to this file, or `-` for stdout.
        #[arg(short, long, default_value = "-")]
        output: PathBuf,
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
    if let Command::Discover { output } = &cli.command {
        return run_discover(output);
    }

    let file = match &cli.command {
        Command::Check { file }
        | Command::Plan { file }
        | Command::Audit { file, .. }
        | Command::Explain { file, .. } => file,
        Command::Discover { .. } => unreachable!("discovery is handled before policy loading"),
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
        Command::Explain {
            snapshot,
            service,
            format,
            ..
        } => {
            let snapshot_input = std::fs::read_to_string(snapshot)?;
            let snapshot: manyfw_core::snapshot::ObservationSnapshot =
                serde_json::from_str(&snapshot_input)?;
            let explanation = manyfw_core::explain::explain(&policy, &snapshot, &service)?;
            match format.as_str() {
                "human" => print!("{}", explanation.human()),
                "json" => print!("{}", explanation.json()?),
                other => {
                    return Err(
                        format!("unsupported explain format {other:?}; use human or json").into(),
                    );
                }
            }
            match &explanation.identity {
                manyfw_core::explain::IdentityResolution::AmbiguousIdentity { candidates } => {
                    return Err(format!(
                        "ambiguous service selector {service:?}; candidates: {}",
                        candidates.join(", ")
                    )
                    .into());
                }
                manyfw_core::explain::IdentityResolution::UnresolvedIdentity { candidates } => {
                    let suggestions = if candidates.is_empty() {
                        "no observed identities".into()
                    } else {
                        format!("candidates: {}", candidates.join(", "))
                    };
                    return Err(format!(
                        "service selector {service:?} did not resolve; {suggestions}"
                    )
                    .into());
                }
                manyfw_core::explain::IdentityResolution::Resolved { .. } => {}
            }
        }
        Command::Discover { .. } => unreachable!("discovery is handled before policy loading"),
    }
    Ok(())
}

fn run_discover(output: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        let docker = manyfw_core::docker::DockerDiscovery::new(
            docker_engine::local_docker_transport(),
            DiscoveryClock,
        )
        .collect();
        let host = manyfw_linux::collect();
        let snapshot = manyfw_core::snapshot::ObservationSnapshot::compose(docker, host);
        let rendered = serde_json::to_string_pretty(&snapshot)?;
        if output == std::path::Path::new("-") {
            println!("{rendered}");
        } else {
            std::fs::write(output, rendered)?;
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = output;
        Err("live discovery is supported on Linux only".into())
    }
}

#[cfg(target_os = "linux")]
struct DiscoveryClock;

#[cfg(target_os = "linux")]
impl manyfw_core::docker::Clock for DiscoveryClock {
    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis() as u64)
    }
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
