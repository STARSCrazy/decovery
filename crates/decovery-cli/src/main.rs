//! `decovery` command-line interface.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod compare;

use decovery_facade::{Budget, FacadeError, Response, Session};

/// Recover source code from old executables.
#[derive(Parser)]
#[command(name = "decovery", version, about)]
struct Cli {
    /// decovery workspace (contains `decovery.toml`).
    #[arg(long, global = true, default_value = ".")]
    workspace: PathBuf,
    /// Print the result as JSON.
    #[arg(long, global = true)]
    json: bool,
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
    },
    /// Compare one rebuilt function of an object file with the original. Exit code 0 when identical,
    /// 1 when not, 2 on errors.
    Compare {
        /// Rebuilt OMF object file; relative paths that do not exist are taken from the workspace root.
        #[arg(long)]
        object: PathBuf,
        /// Function name as in the knowledge (undecorated).
        #[arg(long)]
        function: String,
        /// Length of the original function in bytes; default: the symbol's `size`.
        #[arg(long)]
        length: Option<u32>,
        /// Tolerate alignment written as `00` where the original has `90`.
        #[arg(long)]
        padding: bool,
    },
    /// Print header and pseudo-C of a function (name, address or `file:0x…`).
    Show {
        /// Function name or address.
        target: String,
    },
    /// Page the content of a handle returned by another command.
    Detail {
        /// Handle id (`h_` plus 12 hex characters).
        handle: String,
        /// First character to return.
        #[arg(long, default_value_t = 0)]
        offset: usize,
        /// Number of characters to return.
        #[arg(long, default_value_t = 8000)]
        limit: usize,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Migrate { from, to } => match decovery_core::migrate_decomp(&from, &to) {
            Ok(report) => {
                if cli.json {
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
        Command::Compare {
            object,
            function,
            length,
            padding,
        } => {
            let request = compare::Request {
                workspace: cli.workspace,
                object,
                function,
                length,
                padding,
            };
            match compare::run(&request) {
                Ok(outcome) => {
                    if cli.json {
                        println!("{:#}", outcome.to_json());
                    } else {
                        print!("{}", outcome.to_text());
                    }
                    if outcome.identical() {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::from(1)
                    }
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::from(2)
                }
            }
        }
        Command::Show { target } => finish(show(&cli.workspace, &target, cli.json)),
        Command::Detail {
            handle,
            offset,
            limit,
        } => finish(detail(&cli.workspace, &handle, offset, limit, cli.json)),
    }
}

/// Prints the failure on stderr and maps it to its exit code.
fn finish(result: Result<(), FacadeError>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(e.exit_code())
        }
    }
}

fn print_json(response: &Response) -> Result<(), FacadeError> {
    let text =
        serde_json::to_string_pretty(response).map_err(|e| FacadeError::Invalid(e.to_string()))?;
    println!("{text}");
    Ok(())
}

fn show(workspace: &Path, target: &str, json: bool) -> Result<(), FacadeError> {
    let session = Session::open(workspace)?;
    if json {
        return print_json(&decovery_facade::show(&session, target, Budget::default())?);
    }
    let response = decovery_facade::show(&session, target, Budget { chars: usize::MAX })?;
    if let Some(text) = response.data["text"].as_str() {
        print!("{text}");
    }
    if response.data["analysis_stale"] == true {
        eprintln!("note: analysis is older than the knowledge; run `decovery analyze`");
    }
    Ok(())
}

fn detail(
    workspace: &Path,
    handle: &str,
    offset: usize,
    limit: usize,
    json: bool,
) -> Result<(), FacadeError> {
    let response = decovery_facade::detail(workspace, handle, offset, limit)?;
    if json {
        return print_json(&response);
    }
    if let Some(text) = response.data["text"].as_str() {
        print!("{text}");
    }
    Ok(())
}
