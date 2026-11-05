//! `decovery` command-line interface.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

mod compare;

use decovery_facade::{
    Budget, DEFAULT_LIMIT, FacadeError, FindQuery, FindWhat, FunctionFilter, FunctionSort,
    Response, Session,
};

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
    /// Counts of named and rebuilt functions and the next thing to do.
    Status,
    /// Search functions, names, strings, generated code or cross references.
    Find {
        /// What to search.
        what: What,
        /// Case-insensitive text, `*` matches any run; for `xrefs` the target (name or address).
        pattern: Option<String>,
        /// Restrict the function list (repeatable, all must hold); `functions` only.
        #[arg(long = "filter", value_enum)]
        filter: Vec<Filter>,
        /// Order of the function list.
        #[arg(long, value_enum, default_value = "address")]
        sort: Sort,
        /// Maximum number of rows; the rest is stored as a handle.
        #[arg(long, default_value_t = DEFAULT_LIMIT)]
        limit: usize,
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

#[derive(Clone, Copy, ValueEnum)]
enum What {
    Functions,
    Names,
    Strings,
    Code,
    Xrefs,
}

#[derive(Clone, Copy, ValueEnum)]
enum Filter {
    Named,
    Unnamed,
    Assumed,
    Confirmed,
    NotTried,
    Identical,
    Differs,
}

#[derive(Clone, Copy, ValueEnum)]
enum Sort {
    Address,
    Callers,
    Size,
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
        Command::Status => finish(status(&cli.workspace, cli.json)),
        Command::Find {
            what,
            pattern,
            filter,
            sort,
            limit,
        } => {
            let query = FindQuery {
                what: match what {
                    What::Functions => FindWhat::Functions,
                    What::Names => FindWhat::Names,
                    What::Strings => FindWhat::Strings,
                    What::Code => FindWhat::Code,
                    What::Xrefs => FindWhat::Xrefs,
                },
                pattern,
                filter: filter
                    .into_iter()
                    .map(|f| match f {
                        Filter::Named => FunctionFilter::Named,
                        Filter::Unnamed => FunctionFilter::Unnamed,
                        Filter::Assumed => FunctionFilter::Assumed,
                        Filter::Confirmed => FunctionFilter::Confirmed,
                        Filter::NotTried => FunctionFilter::NotTried,
                        Filter::Identical => FunctionFilter::Identical,
                        Filter::Differs => FunctionFilter::Differs,
                    })
                    .collect(),
                sort: match sort {
                    Sort::Address => FunctionSort::Address,
                    Sort::Callers => FunctionSort::Callers,
                    Sort::Size => FunctionSort::Size,
                },
                limit,
            };
            finish(find(&cli.workspace, &query, cli.json))
        }
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

fn status(workspace: &Path, json: bool) -> Result<(), FacadeError> {
    let session = Session::open(workspace)?;
    let response = decovery_facade::status(&session)?;
    if json {
        return print_json(&response);
    }
    let d = &response.data;
    println!("{}", response.summary);
    println!(
        "analysis: {} {} {}",
        d["analysis"]["provider"].as_str().unwrap_or(""),
        d["analysis"]["version"].as_str().unwrap_or(""),
        d["analysis"]["created"].as_str().unwrap_or("")
    );
    println!(
        "rebuild: {} identical, {} differs, {} error, {} not tried",
        d["rebuild"]["identical"],
        d["rebuild"]["differs"],
        d["rebuild"]["error"],
        d["rebuild"]["not_tried"]
    );
    println!("next: {}", d["next_step"].as_str().unwrap_or(""));
    Ok(())
}

/// The values of `keys` in `row`, tab-separated.
fn cells(row: &serde_json::Value, keys: &[&str]) -> String {
    keys.iter()
        .map(|k| match &row[*k] {
            serde_json::Value::String(s) => s.replace('\t', "\\t").replace('\n', "\\n"),
            other => other.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\t")
}

fn find(workspace: &Path, query: &FindQuery, json: bool) -> Result<(), FacadeError> {
    let session = Session::open(workspace)?;
    let budget = if json {
        Budget::default()
    } else {
        Budget { chars: usize::MAX }
    };
    let response = decovery_facade::find(&session, query, budget)?;
    if json {
        return print_json(&response);
    }
    println!("{}", response.summary);
    let d = &response.data;
    if query.what == FindWhat::Xrefs {
        println!("{}", cells(d, &["address", "name"]));
        let sections: [(&str, &str, &[&str]); 4] = [
            ("called-by", "called_by", &["address", "name", "site"]),
            ("calls", "calls", &["address", "name", "site"]),
            ("access", "accesses", &["function", "name", "kind"]),
            ("string", "strings", &["address", "text"]),
        ];
        for (kind, list, keys) in sections {
            for item in d[list].as_array().into_iter().flatten() {
                println!("{kind}\t{}", cells(item, keys));
            }
        }
        return Ok(());
    }
    let keys: &[&str] = match query.what {
        FindWhat::Functions => &["address", "name", "size", "callers", "status", "rebuild"],
        FindWhat::Code => &["file", "line", "text"],
        _ => &["address", "text"],
    };
    for item in d["items"].as_array().into_iter().flatten() {
        println!("{}", cells(item, keys));
    }
    Ok(())
}
