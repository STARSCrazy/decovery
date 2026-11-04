//! `decovery` command-line interface.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Recover source code from old executables.
#[derive(Parser)]
#[command(name = "decovery", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Convert a Decomp workspace into a decovery workspace.
    Migrate {
        /// Decomp workspace (contains `decomp.toml`).
        from: PathBuf,
        /// Directory for the new decovery workspace.
        to: PathBuf,
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Migrate { from, to, json } => match decovery_core::migrate_decomp(&from, &to) {
            Ok(report) => {
                if json {
                    match serde_json::to_string_pretty(&report) {
                        Ok(text) => println!("{text}"),
                        Err(e) => {
                            eprintln!("error: {e}");
                            return ExitCode::FAILURE;
                        }
                    }
                } else {
                    println!("Converted {} files:", report.converted.len());
                    for path in &report.converted {
                        println!("  {}", path.display());
                    }
                    println!("Untranslated free texts: {}", report.untranslated_texts);
                    if !report.skipped.is_empty() {
                        println!("Skipped ({}):", report.skipped.len());
                        for entry in &report.skipped {
                            println!("  {entry}");
                        }
                    }
                    if report.unmapped.is_empty() {
                        println!("Unmapped: none");
                    } else {
                        println!("Unmapped ({}):", report.unmapped.len());
                        for key in &report.unmapped {
                            println!("  {key}");
                        }
                    }
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
    }
}
