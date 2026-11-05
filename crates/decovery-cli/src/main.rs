//! `decovery` command-line interface.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

/// How long `migrate` waits for the new workspace's lock.
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

mod compare;
mod setup;

use decovery_core::{ClaimSource, Confidence};
use decovery_facade::{
    AnalyzeOptions, AnnotateAction, Annotation, Budget, DEFAULT_LIMIT, FacadeError, FindQuery,
    FindWhat, FunctionFilter, FunctionSort, Progress, Response, Session,
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
    /// Convert a Decomp workspace into a decovery workspace; an imported analysis (`ausgabe/`) also gets
    /// its output generated.
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
    /// Record knowledge: a name, comment, signature, type, local, refutation or type definition.
    ///
    /// Ranks: human > confirmed > assumed. A claim ranked below the record it changes does not replace an
    /// existing name, comment, line comment, signature, type or local (no change, a warning instead) unless
    /// `--force` is given; filling an empty field is always allowed. A human line comment counts as human.
    #[command(group(clap::ArgGroup::new("action").required(true).args([
        "name", "comment", "signature", "data_type", "local", "refute", "add_type",
    ])))]
    Annotate {
        /// Function or symbol name, address or `file:0x…`; not needed for `--add-type`.
        #[arg(required_unless_present = "add_type")]
        target: Option<String>,
        /// Name the target (a C identifier).
        #[arg(long)]
        name: Option<String>,
        /// Comment on the target; inside a function it becomes a line comment.
        #[arg(long)]
        comment: Option<String>,
        /// C prototype of the function.
        #[arg(long)]
        signature: Option<String>,
        /// C type of a global.
        #[arg(long = "type", id = "data_type")]
        data_type: Option<String>,
        /// Name a local: place (`param:1`, `stack:-0x10`, `reg:EAX`), name, optional type.
        #[arg(long, num_args = 2..=3, value_names = ["PLACE", "NAME", "TYPE"])]
        local: Option<Vec<String>>,
        /// Withdraw the target's name; the reason is kept in its history.
        #[arg(long, value_name = "REASON")]
        refute: Option<String>,
        /// Append a definition to `types.h`.
        #[arg(long, value_name = "DEF")]
        add_type: Option<String>,
        /// How sure the claim is.
        #[arg(long, value_enum, default_value = "assumed")]
        confidence: ClaimConfidence,
        /// Who makes the claim.
        #[arg(long, value_enum, default_value = "human")]
        source: ClaimOrigin,
        /// What the claim rests on.
        #[arg(long)]
        evidence: Option<String>,
        /// Replace a value held under a stronger claim (name, comment, signature, type, local, refute).
        #[arg(long)]
        force: bool,
    },
    /// Run the analyzer plugin over the target: functions, calls, strings, data accesses and pseudo-C.
    /// Progress goes to stderr.
    Analyze {
        /// Plugin as configured in `[plugins.<name>]` (decovery.toml or the user config).
        #[arg(long, default_value = "ghidra")]
        plugin: String,
        /// Decompile only this function again (name, address or `file:0x…`; repeatable).
        #[arg(long = "function", value_name = "TARGET")]
        function: Vec<String>,
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
    /// Serve the tools to AI agents over MCP on stdin/stdout (stdout carries only MCP frames).
    Mcp,
    /// Install tools into `extern/` and register them in the user config.
    Setup {
        #[command(subcommand)]
        what: SetupCommand,
    },
}

#[derive(Subcommand)]
enum SetupCommand {
    /// Install Ghidra, a JDK and a pyghidra venv (downloads about 500 MB) and write `[plugins.ghidra]`
    /// into the user config. Progress goes to stderr.
    Ghidra {
        /// Install directory; default: `extern/` next to the repository, else beside the user config.
        #[arg(long = "extern", value_name = "DIR")]
        extern_dir: Option<PathBuf>,
        /// Pre-downloaded Ghidra release zip (offline); its sha256 must match the pinned one.
        #[arg(long)]
        ghidra_zip: Option<PathBuf>,
        /// Pre-downloaded JDK archive (offline); its sha256 must match the pinned one.
        #[arg(long)]
        jdk_zip: Option<PathBuf>,
        /// Directory with `decovery-plugin-sdk` and `ghidra`; default: `plugins/` of the repository.
        #[arg(long, value_name = "DIR")]
        plugins_dir: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum ClaimConfidence {
    Confirmed,
    Assumed,
}

#[derive(Clone, Copy, ValueEnum)]
enum ClaimOrigin {
    Human,
    Agent,
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
        Command::Migrate { from, to } => finish(migrate(&from, &to, cli.json)),
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
        Command::Annotate {
            target,
            name,
            comment,
            signature,
            data_type,
            local,
            refute,
            add_type,
            confidence,
            source,
            evidence,
            force,
        } => {
            let action = if let Some(v) = name {
                AnnotateAction::Name(v)
            } else if let Some(v) = comment {
                AnnotateAction::Comment(v)
            } else if let Some(v) = signature {
                AnnotateAction::Signature(v)
            } else if let Some(v) = data_type {
                AnnotateAction::DataType(v)
            } else if let Some(mut v) = local {
                let data_type = if v.len() == 3 { v.pop() } else { None };
                let name = v.pop().unwrap_or_default();
                let place = v.pop().unwrap_or_default();
                AnnotateAction::Local {
                    place,
                    name,
                    data_type,
                }
            } else if let Some(reason) = refute {
                AnnotateAction::Refute { reason }
            } else if let Some(v) = add_type {
                AnnotateAction::AddType(v)
            } else {
                // clap's required argument group rules this out
                return ExitCode::from(2);
            };
            let request = Annotation {
                target: target.unwrap_or_default(),
                action,
                confidence: match confidence {
                    ClaimConfidence::Confirmed => Confidence::Confirmed,
                    ClaimConfidence::Assumed => Confidence::Assumed,
                },
                source: match source {
                    ClaimOrigin::Human => ClaimSource::Human,
                    ClaimOrigin::Agent => ClaimSource::Agent,
                },
                evidence,
                force,
            };
            finish(annotate(&cli.workspace, &request, cli.json))
        }
        Command::Analyze { plugin, function } => {
            let options = AnalyzeOptions {
                plugin,
                functions: (!function.is_empty()).then_some(function),
            };
            finish(analyze(&cli.workspace, &options, cli.json))
        }
        Command::Detail {
            handle,
            offset,
            limit,
        } => finish(detail(&cli.workspace, &handle, offset, limit, cli.json)),
        Command::Mcp => finish(decovery_mcp::serve_stdio(cli.workspace)),
        Command::Setup {
            what:
                SetupCommand::Ghidra {
                    extern_dir,
                    ghidra_zip,
                    jdk_zip,
                    plugins_dir,
                },
        } => finish(setup_ghidra(
            extern_dir,
            ghidra_zip,
            jdk_zip,
            plugins_dir,
            cli.json,
        )),
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

/// Converts the Decomp workspace and, when an analysis was imported, generates the full output (R35).
fn migrate(from: &Path, to: &Path, json: bool) -> Result<(), FacadeError> {
    let report =
        decovery_core::migrate_decomp(from, to).map_err(|e| FacadeError::Invalid(e.to_string()))?;
    let written = if decovery_core::Analysis::load(to)?.is_some() {
        let lock = decovery_core::Workspace::open(to)?.lock(LOCK_WAIT)?;
        let session = Session::open(to)?;
        Some(decovery_facade::write_all(&session, &lock)?.written)
    } else {
        None
    };
    if json {
        let mut value =
            serde_json::to_value(&report).map_err(|e| FacadeError::Invalid(e.to_string()))?;
        value["output_written"] = serde_json::json!(written.unwrap_or(0));
        let text = serde_json::to_string_pretty(&value)
            .map_err(|e| FacadeError::Invalid(e.to_string()))?;
        println!("{text}");
        return Ok(());
    }
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
    match written {
        Some(n) => println!(
            "Analysis imported ({} functions); output generated: {n} files written",
            report.analysis_functions
        ),
        None => println!("No analysis imported; run `decovery analyze` to generate the output"),
    }
    Ok(())
}

fn setup_ghidra(
    extern_dir: Option<PathBuf>,
    ghidra_zip: Option<PathBuf>,
    jdk_zip: Option<PathBuf>,
    plugins_dir: Option<PathBuf>,
    json: bool,
) -> Result<(), FacadeError> {
    let invalid = |e: String| FacadeError::Invalid(e);
    let platform = setup::Platform::current().map_err(invalid)?;
    let config_path = decovery_facade::plugins::user_config_path().ok_or_else(|| {
        invalid("cannot locate the user config dir (APPDATA / HOME unset)".into())
    })?;
    let cwd = std::env::current_dir().map_err(|e| invalid(e.to_string()))?;
    let plugins_dir = match plugins_dir {
        Some(dir) => dir,
        None => setup::find_plugins_dir(&cwd).map_err(invalid)?,
    };
    let extern_dir = extern_dir.unwrap_or_else(|| setup::default_extern_dir(&cwd, &config_path));
    let absolute = |p: PathBuf| std::path::absolute(&p).unwrap_or(p);
    let options = setup::SetupOptions {
        extern_dir: absolute(extern_dir),
        ghidra_archive: ghidra_zip.map(absolute),
        jdk_archive: jdk_zip.map(absolute),
        plugins_dir: absolute(plugins_dir),
        python: std::env::var("DECOVERY_PYTHON")
            .ok()
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| "python".into()),
        config_path,
        platform,
    };
    let report = setup::run_setup(
        &options,
        &setup::plan(platform),
        &setup::SystemRunner,
        &mut |line| eprintln!("{line}"),
    )
    .map_err(|e| invalid(e.to_string()))?;
    let summary = format!(
        "Ghidra installed in {}; plugin `ghidra` registered in {}",
        report.ghidra_dir.display(),
        report.config_path.display()
    );
    let response = Response::new(
        summary,
        serde_json::json!({
            "ghidra_dir": report.ghidra_dir.display().to_string(),
            "jdk_dir": report.jdk_dir.display().to_string(),
            "venv_python": report.venv_python.display().to_string(),
            "config": report.config_path.display().to_string(),
            "ghidra_kept": report.ghidra_kept,
            "jdk_kept": report.jdk_kept,
        }),
    );
    print_summary(&response, json)
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
        eprintln!("note: {}", decovery_facade::output::STALE_ANALYSIS);
    }
    Ok(())
}

fn annotate(workspace: &Path, request: &Annotation, json: bool) -> Result<(), FacadeError> {
    let response = decovery_facade::annotate(workspace, request)?;
    print_summary(&response, json)
}

fn analyze(workspace: &Path, options: &AnalyzeOptions, json: bool) -> Result<(), FacadeError> {
    let progress = |p: Progress| {
        let message = p
            .message
            .filter(|m| !m.trim().is_empty())
            .unwrap_or_else(|| "working …".to_string());
        match p.total {
            Some(total) => eprintln!("{}/{total} {message}", p.done),
            None => eprintln!("{message}"),
        }
    };
    let response = decovery_facade::analyze(workspace, options, &progress)?;
    print_summary(&response, json)
}

/// The JSON envelope, or the summary on stdout and `data.warnings` on stderr.
fn print_summary(response: &Response, json: bool) -> Result<(), FacadeError> {
    if json {
        return print_json(response);
    }
    println!("{}", response.summary);
    for warning in response.data["warnings"].as_array().into_iter().flatten() {
        if let Some(text) = warning.as_str() {
            eprintln!("warning: {text}");
        }
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
