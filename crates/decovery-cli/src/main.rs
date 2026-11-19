//! `decovery` command-line interface.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

/// How long `migrate` waits for the new workspace's lock.
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

mod compare;
mod overlay;
mod setup;

use decovery_core::{CallRecord, ClaimSource, Confidence, append_call};
use decovery_facade::{
    AnalyzeOptions, AnnotateAction, Annotation, Budget, BuildRequest, DEFAULT_HISTORY_LIMIT,
    DEFAULT_LIMIT, DEFAULT_SIMILAR_LIMIT, FacadeError, FindQuery, FindWhat, FunctionFilter,
    FunctionSort, JobOperation, LegacyCall, LegacyOperation, Progress, Response, Session, Variant,
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
    /// Most compile jobs in flight at once over all runners; default: the number of logical cores.
    #[arg(short = 'j', long, global = true, value_parser = clap::value_parser!(u32).range(1..))]
    jobs: Option<u32>,
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
    /// Import Decomp's attempt memory and archive into the existing workspace (safe to repeat).
    MigrateAttempts {
        /// Source Decomp workspace; default: [legacy] decomp_workspace in decovery.toml.
        #[arg(long)]
        from: Option<PathBuf>,
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
        /// Print the instruction address ranges each pseudo-C line came from in front of it.
        #[arg(long)]
        lines: bool,
        /// Print the original's disassembly of the function after the pseudo-C.
        #[arg(long)]
        asm: bool,
    },
    /// Why a rebuilt function differs from the original and what to try: findings of the diagnosis rules, the
    /// kind of deviation and the instructions side by side. Reads the object of the last `build`.
    /// With `--deep`: Decomp's model of the function as well, through the `decomp-legacy` plugin (ADR 0007;
    /// its report is German). Progress goes to stderr.
    Diagnose {
        /// Function name or address.
        target: Option<String>,
        /// Decomp's deeper analysis: context package, structure comparison, Watcom register allocation, stack
        /// slots, or structure and registers together (`joint`, the default when `--deep` has no mode). A value
        /// that is no mode is the function: `diagnose --deep NAME` is `diagnose NAME --deep joint`.
        #[arg(long, value_name = "MODE", num_args = 0..=1, default_missing_value = "joint")]
        deep: Option<String>,
        /// A candidate source of the function to analyze instead of the current one (`structure`, `registers`,
        /// `slots`, `joint`).
        #[arg(long, value_name = "FILE", requires = "deep")]
        source: Option<PathBuf>,
        /// The full register report (`registers`).
        #[arg(long, requires = "deep")]
        all: bool,
        /// Time budget in minutes (`slots`).
        #[arg(long, requires = "deep")]
        minutes: Option<f64>,
    },
    /// Search a better source for one function with Decomp's search (through the `decomp-legacy` plugin,
    /// ADR 0007). A candidate is built by decovery itself and reported with decovery's verdict next to the
    /// current source's; `--apply` writes it into `src/` only when that verdict is better. Progress goes to stderr.
    Search {
        /// Function name or address.
        target: String,
        /// Decomp's search: the search chain, the permuter, beam search or the form catalogue.
        #[arg(long, value_enum)]
        strategy: Strategy,
        /// Time budget in minutes.
        #[arg(long)]
        minutes: Option<f64>,
        /// Search rounds.
        #[arg(long)]
        rounds: Option<u32>,
        /// Start from this candidate source of the function (`permute`).
        #[arg(long, value_name = "FILE")]
        source: Option<PathBuf>,
        /// Write the candidate's function into its file in `src/` when decovery's verdict is better (identical, or
        /// fewer differing instructions), then record it with a normal build.
        #[arg(long)]
        apply: bool,
    },
    /// Check the behaviour of a rebuilt function with Decomp (through the `decomp-legacy` plugin, ADR 0007).
    /// Decomp's result is evidence, never a decovery verdict; nothing is recorded. Progress goes to stderr.
    Verify {
        /// Function name or address.
        target: String,
        /// Static and dynamic equivalence evidence, or behaviour on recorded and generated cases.
        #[arg(long, value_enum)]
        check: Check,
        /// Recorded runtime run to take cases from (`behavior`).
        #[arg(long, value_name = "NAME")]
        run: Option<String>,
        /// Time budget in minutes (`equivalence`).
        #[arg(long)]
        minutes: Option<f64>,
    },
    /// Counts of named and rebuilt functions and the next thing to do.
    Status,
    /// Search functions, names, strings, generated code, cross references or similar identical functions.
    Find {
        /// What to search.
        what: What,
        /// Case-insensitive text, `*` matches any run; for `xrefs` and `similar` the target (name or address).
        pattern: Option<String>,
        /// Restrict the function list (repeatable, all must hold); `functions` only.
        #[arg(long = "filter", value_enum)]
        filter: Vec<Filter>,
        /// Order of the function list.
        #[arg(long, value_enum, default_value = "address")]
        sort: Sort,
        /// Maximum number of rows (default 100; `similar`: 3), or `all`; the rest is stored as a handle.
        #[arg(long, value_parser = parse_limit)]
        limit: Option<usize>,
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
    /// Compile the rebuild sources (`src/`), compare their functions with the original and record the results.
    /// Exit code 0 when every built function is identical, 1 when not (or a file failed), 2 on errors.
    /// Progress goes to stderr.
    /// With `--variant` / `--function-source`: compile candidates for `--function` instead and rank them (best
    /// first, nothing is recorded); exit code 0 when the best is identical.
    Build {
        /// Source files in `src/` (e.g. `ai.c`); default: all.
        files: Vec<String>,
        /// Report this function only (name or address); its file is built.
        #[arg(long, value_name = "NAME")]
        function: Option<String>,
        /// Candidate source for `--function`: a whole replacement of the function's file, UTF-8 or code page 437
        /// (repeatable, at most 64).
        #[arg(long = "variant", value_name = "FILE")]
        variant: Vec<PathBuf>,
        /// Candidate definition of `--function` alone, spliced into its file and compiled in a file shrunk to what
        /// the function needs when that gives the same code; an identical result is judged again on the full file;
        /// UTF-8 or code page 437 (repeatable; at most 64 variants of both kinds together).
        #[arg(long = "function-source", value_name = "FILE")]
        function_source: Vec<PathBuf>,
    },
    /// Link the whole program with the original linker (`cache/rebuild/REBUILD.EXE`) and compare it
    /// with the original file (MZ: compile all rebuild sources and link them; LE: insert the identical
    /// rebuilds into the original image and link it as one module); the result goes to
    /// `knowledge/rebuild-program.toml`. After an identical MZ link, the public symbols the knowledge
    /// base lacks are recorded from the linker map (`source = link`). Exit code 0 when identical, 1 when
    /// it differs, 2 when the link failed or on errors. Progress goes to stderr.
    Link,
    /// What was tried on a function: its recorded attempts (builds, variants, search candidates) newest first with
    /// decovery's verdict, the best one, the attempt budget (parked when it is spent without reaching identical) and
    /// the failures grouped by message. With `--archive`: the archived definition and comparison of one attempt.
    History {
        /// Function name or address.
        function: String,
        /// Most attempts listed; all of them go into a handle when there are more.
        #[arg(long, default_value_t = DEFAULT_HISTORY_LIMIT)]
        limit: usize,
        /// Id of an archived attempt (the `archive` an attempt names).
        #[arg(long, value_name = "ID")]
        archive: Option<String>,
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
    Mcp {
        /// Benchmark limits file (schema one); no limits are applied without it.
        #[arg(long)]
        limits: Option<PathBuf>,
        /// Most background jobs run at once (the bridge plugin's `max_parallel`).
        #[arg(long, default_value_t = decovery_facade::DEFAULT_MAX_JOBS, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..))]
        max_jobs: usize,
    },
    /// The workspace's jobs: long commands of the CLI and of an MCP server (`build`, `link`, `analyze`,
    /// `diagnose --deep`, `search`, `verify`). A job's full result is a handle (`decovery detail`).
    Job {
        #[command(subcommand)]
        what: JobCommand,
    },
    /// Install tools into `extern/` and register them in the user config.
    Setup {
        #[command(subcommand)]
        what: SetupCommand,
    },
    /// Agent benchmarks over solution-free copies of solved functions (ADR 0009).
    Bench {
        #[command(subcommand)]
        what: BenchCommand,
    },
    /// Overlay files of the target (`[[overlay]]` in decovery.toml, ADR 0011).
    Overlay {
        #[command(subcommand)]
        what: OverlayCommand,
    },
}

#[derive(Subcommand)]
enum OverlayCommand {
    /// Add overlay files (a file of the same name replaces its entry); the name is the file stem, upper case.
    Add {
        /// Overlay files.
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Overlay format.
        #[arg(long, default_value = "aztec-c86")]
        format: String,
        /// Data segment (hex, relative to the load segment) when the startup code does not show it.
        #[arg(long, value_parser = parse_hex_u16)]
        ds: Option<u16>,
    },
    /// Every configured overlay with its segments.
    List,
    /// Remove an overlay and its memory segments.
    Remove {
        /// Overlay name.
        name: String,
    },
}

#[derive(Subcommand)]
enum JobCommand {
    /// Every job, newest first.
    List,
    /// One job's state, progress, summary and result handle.
    Poll {
        /// Job id (`j_` plus 12 hex characters).
        id: String,
    },
    /// Ask a job to stop at its next cancellation point (a cancel during recording lets it complete).
    Cancel {
        /// Job id (`j_` plus 12 hex characters).
        id: String,
    },
}

#[derive(Subcommand)]
enum BenchCommand {
    /// Run a suite with a driver from the user config (`[bench.drivers.<name>]`); writes the run record to
    /// `<suite dir>/bench/<run-id>.json`. Exit code 0 when the run is done, 1 when it is paused or stopped at
    /// a limit, 2 on errors. Progress goes to stderr.
    Run {
        /// Suite file (`suite.toml`).
        suite: PathBuf,
        /// Driver name in the user config.
        #[arg(long)]
        driver: String,
        /// Tasks run at a time.
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
        parallel: u32,
        /// Seed passed to the driver.
        #[arg(long, default_value_t = 0)]
        seed: u64,
        /// Runs of every task.
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
        repeat: u32,
        /// Run only these task ids.
        #[arg(long, num_args = 1..)]
        only: Vec<String>,
        /// Start no further task once the finished tasks used this many tokens.
        #[arg(long)]
        max_total_tokens: Option<u64>,
        /// Start no further task once the finished tasks cost this many US dollars.
        #[arg(long)]
        max_total_cost_usd: Option<f64>,
        /// Continue a paused or stopped run with this id.
        #[arg(long, value_name = "RUN")]
        resume: Option<String>,
        /// Keep the task copies.
        #[arg(long)]
        keep: bool,
        /// Hide exemplars from the agent in every task (`[rebuild] exemplars = false` in the copies).
        #[arg(long)]
        no_exemplars: bool,
    },
    /// Success rate with a 95 % Wilson interval and cost medians/means of one run record. Exit code 0, 2 on
    /// errors.
    Report {
        /// Run record (`<suite dir>/bench/<run-id>.json`).
        run: PathBuf,
        /// Group the tasks by workspace, profile or tag (a task counts in each of its tags).
        #[arg(long, value_enum)]
        group_by: Option<BenchGroupBy>,
    },
    /// Compare two run records metric by metric with 95 % intervals (difference = B minus A); paired by task
    /// when both hold the same tasks. Exit code 0, 2 on errors.
    Compare {
        /// Run record A (the baseline).
        a: PathBuf,
        /// Run record B.
        b: PathBuf,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum BenchGroupBy {
    Workspace,
    Profile,
    Tag,
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
        /// An existing Ghidra install to register instead of downloading one (the directory holding
        /// `support/` and `ghidraRun`).
        #[arg(long, value_name = "DIR", conflicts_with = "ghidra_zip")]
        ghidra_dir: Option<PathBuf>,
        /// An existing JDK (21 or newer) to register instead of downloading one (the directory holding `bin/`).
        #[arg(long, value_name = "DIR", conflicts_with = "jdk_zip")]
        jdk_dir: Option<PathBuf>,
        /// Directory with `decovery-plugin-sdk` and `ghidra`; default: `plugins/` of the repository.
        #[arg(long, value_name = "DIR")]
        plugins_dir: Option<PathBuf>,
    },
    /// Create a venv with the `unicorn-dos` plugin and unicorn, and write `[plugins.unicorn-dos]` into the
    /// user config. Progress goes to stderr.
    UnicornDos {
        /// Install directory; default: `extern/` next to the repository, else beside the user config.
        #[arg(long = "extern", value_name = "DIR")]
        extern_dir: Option<PathBuf>,
        /// Python 3.12 or newer used to create the venv; default: `DECOVERY_PYTHON`, else `python`.
        #[arg(long, value_name = "EXE")]
        python: Option<String>,
        /// Directory with `decovery-plugin-sdk` and `unicorn-dos`; default: `plugins/` of the repository.
        #[arg(long, value_name = "DIR")]
        plugins_dir: Option<PathBuf>,
    },
    /// Create a venv with the `dosbox-lab` plugin and the dosbox-lab Python package, and write
    /// `[plugins.dosbox-lab]` into the user config. The DOSBox executable is not installed. Progress goes to
    /// stderr.
    DosboxLab {
        /// Directory of the dosbox-lab Python package (holds its `pyproject.toml`; `python/` in its repository).
        #[arg(long, value_name = "DIR")]
        package: PathBuf,
        /// Install directory; default: `extern/` next to the repository, else beside the user config.
        #[arg(long = "extern", value_name = "DIR")]
        extern_dir: Option<PathBuf>,
        /// Python 3.12 or newer used to create the venv; default: `DECOVERY_PYTHON`, else `python`.
        #[arg(long, value_name = "EXE")]
        python: Option<String>,
        /// Directory with `decovery-plugin-sdk` and `dosbox-lab`; default: `plugins/` of the repository.
        #[arg(long, value_name = "DIR")]
        plugins_dir: Option<PathBuf>,
    },
    /// Register the `decomp-legacy` bridge plugin (`[plugins.decomp-legacy]` in the user config): it runs under
    /// the Python of a Decomp checkout's venv and needs no install.
    DecompLegacy {
        /// The Decomp checkout (holds `.venv/` and `src/decomp/`).
        #[arg(long, value_name = "DIR")]
        decomp: PathBuf,
        /// Directory with `decovery-plugin-sdk` and `decomp-legacy`; default: `plugins/` of the repository.
        #[arg(long, value_name = "DIR")]
        plugins_dir: Option<PathBuf>,
    },
    /// Register the directory of a compiler (`[toolchains]` in the user config).
    Toolchain {
        /// Compiler profile id, e.g. `watcom-9.5`.
        profile: String,
        /// Directory that holds the compiler.
        dir: PathBuf,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Deep {
    Context,
    Structure,
    Registers,
    Slots,
    Joint,
}

#[derive(Clone, Copy, ValueEnum)]
enum Strategy {
    Chain,
    Permute,
    Beam,
    Forms,
}

#[derive(Clone, Copy, ValueEnum)]
enum Check {
    Equivalence,
    Behavior,
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
    Similar,
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
    /// The attempt budget is spent without reaching identical.
    Parked,
}

#[derive(Clone, Copy, ValueEnum)]
enum Sort {
    Address,
    Callers,
    Size,
}

fn main() -> ExitCode {
    let mut cli = Cli::parse();
    if let Err(e) = resolve_deep(&mut cli.command) {
        e.exit();
    }
    if let Some(jobs) = cli.jobs {
        decovery_toolchain::set_global_jobs(jobs);
    }
    decovery_facade::set_actor("cli");
    let started = std::time::Instant::now();
    let record = call_record(&cli.command);
    let workspace = cli.workspace.clone();
    let code = run(cli);
    if let Some(mut record) = record {
        log_call(&workspace, &mut record, started, code);
    }
    code
}

/// Settles `diagnose`'s target and `--deep` mode: a `--deep` value that is no mode is the function when no other
/// target is given (`diagnose --deep NAME` runs `joint`); afterwards the target is set and the mode is valid.
fn resolve_deep(command: &mut Command) -> Result<(), clap::Error> {
    use clap::CommandFactory;
    let Command::Diagnose { target, deep, .. } = command else {
        return Ok(());
    };
    let modes = || {
        Deep::value_variants()
            .iter()
            .filter_map(|d| d.to_possible_value())
            .map(|v| v.get_name().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    if let Some(value) = deep.clone()
        && Deep::from_str(&value, true).is_err()
    {
        if target.is_some() {
            return Err(Cli::command().error(
                clap::error::ErrorKind::InvalidValue,
                format!(
                    "invalid value '{value}' for '--deep [<MODE>]' (possible values: {})",
                    modes()
                ),
            ));
        }
        *target = Some(value);
        *deep = Some("joint".into());
    }
    if target.is_none() {
        return Err(Cli::command().error(
            clap::error::ErrorKind::MissingRequiredArgument,
            "diagnose needs a function name or address",
        ));
    }
    Ok(())
}

/// The mode of a `--deep` value checked by [`resolve_deep`].
fn deep_mode(value: &str) -> Deep {
    Deep::from_str(value, true).unwrap_or(Deep::Joint)
}

/// The call-log record of a workspace command (`None` for `migrate`, `mcp` and `setup`, which log nothing or
/// log themselves): the command, its target and operation, and the builds and searches it runs.
fn call_record(command: &Command) -> Option<CallRecord> {
    let (tool, target, operation): (&str, Option<&str>, Option<&str>) = match command {
        Command::Migrate { .. }
        | Command::MigrateAttempts { .. }
        | Command::Mcp { .. }
        | Command::Setup { .. }
        | Command::Bench { .. } => return None,
        Command::Compare { function, .. } => ("compare", Some(function), None),
        Command::Show { target, .. } => ("show", Some(target), None),
        Command::Diagnose { target, deep, .. } => (
            "diagnose",
            target.as_deref(),
            deep.as_deref().map(|d| match deep_mode(d) {
                Deep::Context => "context",
                Deep::Structure => "structure",
                Deep::Registers => "registers",
                Deep::Slots => "slots",
                Deep::Joint => "joint",
            }),
        ),
        Command::Search {
            target, strategy, ..
        } => (
            "search",
            Some(target),
            Some(match strategy {
                Strategy::Chain => "chain",
                Strategy::Permute => "permute",
                Strategy::Beam => "beam",
                Strategy::Forms => "forms",
            }),
        ),
        Command::Verify { target, check, .. } => (
            "verify",
            Some(target),
            Some(match check {
                Check::Equivalence => "equivalence",
                Check::Behavior => "behavior",
            }),
        ),
        Command::Status => ("status", None, None),
        Command::Find { pattern, .. } => ("find", pattern.as_deref(), None),
        Command::Annotate { target, .. } => ("annotate", target.as_deref(), None),
        Command::Analyze { .. } => ("analyze", None, None),
        Command::Build { function, .. } => ("build", function.as_deref(), None),
        Command::Link => ("link", None, None),
        Command::History { function, .. } => ("history", Some(function), None),
        Command::Detail { handle, .. } => ("detail", Some(handle), None),
        Command::Overlay { what } => match what {
            OverlayCommand::Add { .. } => ("overlay", None, Some("add")),
            OverlayCommand::List => ("overlay", None, Some("list")),
            OverlayCommand::Remove { name } => ("overlay", Some(name), Some("remove")),
        },
        Command::Job { what } => match what {
            JobCommand::List => ("job", None, Some("list")),
            JobCommand::Poll { id } => ("job", Some(id), Some("poll")),
            JobCommand::Cancel { id } => ("job", Some(id), Some("cancel")),
        },
    };
    let mut record = CallRecord::new(tool);
    record.actor = Some(decovery_facade::actor());
    record.target = target.map(str::to_string);
    record.operation = operation.map(str::to_string);
    match command {
        Command::Build {
            variant,
            function_source,
            ..
        } => {
            let variants = variant.len() + function_source.len();
            record.builds = decovery_core::calls::requested_builds(variants);
        }
        Command::Search { .. } => record.searches = 1,
        _ => {}
    }
    Some(record)
}

/// Appends `record` to the workspace's call log (exit code 2 = `error`); a directory that is no workspace gets no
/// log, and a log that cannot be written is only a warning.
fn log_call(
    workspace: &Path,
    record: &mut CallRecord,
    started: std::time::Instant,
    code: ExitCode,
) {
    if !workspace
        .join(decovery_core::workspace::CONFIG_FILE)
        .is_file()
    {
        return;
    }
    record.seconds = started.elapsed().as_secs_f64();
    if code == ExitCode::from(2) {
        record.outcome = "error".into();
    } else if code == ExitCode::from(130) {
        record.outcome = "cancelled".into();
    }
    if let Err(e) = append_call(workspace, record) {
        eprintln!("warning: the call was not logged: {e}");
    }
}

fn run(cli: Cli) -> ExitCode {
    match cli.command {
        Command::Migrate { from, to } => finish(migrate(&from, &to, cli.json)),
        Command::MigrateAttempts { from } => {
            finish(migrate_attempts(&cli.workspace, from.as_deref(), cli.json))
        }
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
        Command::Show { target, lines, asm } => {
            finish(show(&cli.workspace, &target, lines, asm, cli.json))
        }
        Command::Diagnose {
            target, deep: None, ..
        } => finish(diagnose(
            &cli.workspace,
            &target.unwrap_or_default(),
            cli.json,
        )),
        Command::Diagnose {
            target,
            deep: Some(deep),
            source,
            all,
            minutes,
        } => {
            let operation = match deep_mode(&deep) {
                Deep::Context => LegacyOperation::Context,
                Deep::Structure => LegacyOperation::Structure,
                Deep::Registers => LegacyOperation::Registers,
                Deep::Slots => LegacyOperation::Slots,
                Deep::Joint => LegacyOperation::Joint,
            };
            let mut call = LegacyCall::new(target.unwrap_or_default(), operation);
            call.options.source = source;
            call.options.all = all;
            call.options.minutes = minutes;
            finish(legacy(&cli.workspace, &call, cli.json))
        }
        Command::Search {
            target,
            strategy,
            minutes,
            rounds,
            source,
            apply,
        } => {
            let operation = match strategy {
                Strategy::Chain => LegacyOperation::Chain,
                Strategy::Permute => LegacyOperation::Permute,
                Strategy::Beam => LegacyOperation::Beam,
                Strategy::Forms => LegacyOperation::Forms,
            };
            let mut call = LegacyCall::new(target, operation);
            call.options.minutes = minutes;
            call.options.rounds = rounds;
            call.options.source = source;
            call.apply = apply;
            finish(legacy(&cli.workspace, &call, cli.json))
        }
        Command::Verify {
            target,
            check,
            run,
            minutes,
        } => {
            let operation = match check {
                Check::Equivalence => LegacyOperation::Equivalence,
                Check::Behavior => LegacyOperation::Behavior,
            };
            let mut call = LegacyCall::new(target, operation);
            call.options.run = run;
            call.options.minutes = minutes;
            finish(legacy(&cli.workspace, &call, cli.json))
        }
        Command::Status => finish(status(&cli.workspace, cli.json)),
        Command::Find {
            what,
            pattern,
            filter,
            sort,
            limit,
        } => {
            let what = match what {
                What::Functions => FindWhat::Functions,
                What::Names => FindWhat::Names,
                What::Strings => FindWhat::Strings,
                What::Code => FindWhat::Code,
                What::Xrefs => FindWhat::Xrefs,
                What::Similar => FindWhat::Similar,
            };
            let query = FindQuery {
                what,
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
                        Filter::Parked => FunctionFilter::Parked,
                    })
                    .collect(),
                sort: match sort {
                    Sort::Address => FunctionSort::Address,
                    Sort::Callers => FunctionSort::Callers,
                    Sort::Size => FunctionSort::Size,
                },
                limit: limit.unwrap_or(if what == FindWhat::Similar {
                    DEFAULT_SIMILAR_LIMIT
                } else {
                    DEFAULT_LIMIT
                }),
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
        Command::Build {
            files,
            function,
            variant,
            function_source,
        } => match build(
            &cli.workspace,
            files,
            function,
            &variant,
            &function_source,
            cli.json,
        ) {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::from(1),
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(e.exit_code())
            }
        },
        Command::Link => match link(&cli.workspace, cli.json) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(e.exit_code())
            }
        },
        Command::History {
            function,
            limit,
            archive,
        } => finish(history(
            &cli.workspace,
            &function,
            limit,
            archive.as_deref(),
            cli.json,
        )),
        Command::Detail {
            handle,
            offset,
            limit,
        } => finish(detail(&cli.workspace, &handle, offset, limit, cli.json)),
        Command::Bench {
            what:
                BenchCommand::Run {
                    suite,
                    driver,
                    parallel,
                    seed,
                    repeat,
                    only,
                    max_total_tokens,
                    max_total_cost_usd,
                    resume,
                    keep,
                    no_exemplars,
                },
        } => {
            let mut options = match std::env::current_exe() {
                Ok(exe) => decovery_bench::RunOptions::new(driver, exe),
                Err(e) => {
                    eprintln!("error: cannot locate the decovery executable: {e}");
                    return ExitCode::from(2);
                }
            };
            options.parallel = parallel as usize;
            options.seed = seed;
            options.repeat = repeat;
            options.only = only;
            options.max_total_tokens = max_total_tokens;
            options.max_total_cost_usd = max_total_cost_usd;
            options.resume = resume;
            options.keep = keep;
            if no_exemplars {
                options.exemplars = Some(false);
            }
            bench_run(&suite, &options, cli.json)
        }
        Command::Bench {
            what: BenchCommand::Report { run, group_by },
        } => bench_report(&run, group_by, cli.json),
        Command::Bench {
            what: BenchCommand::Compare { a, b },
        } => bench_compare(&a, &b, cli.json),
        Command::Mcp { limits, max_jobs } => finish(decovery_mcp::serve_stdio_with_options(
            cli.workspace,
            limits,
            max_jobs,
        )),
        Command::Overlay { what } => {
            let answer = match what {
                OverlayCommand::Add { files, format, ds } => {
                    overlay::add(&cli.workspace, &files, &format, ds)
                }
                OverlayCommand::List => overlay::list(&cli.workspace),
                OverlayCommand::Remove { name } => overlay::remove(&cli.workspace, &name),
            };
            match answer {
                Ok(v) => {
                    if cli.json {
                        println!("{v:#}");
                    } else {
                        overlay::print(&v);
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::from(2)
                }
            }
        }
        Command::Job { what } => {
            let action = match what {
                JobCommand::List => decovery_facade::JobAction::List,
                JobCommand::Poll { id } => decovery_facade::JobAction::Poll(id),
                JobCommand::Cancel { id } => decovery_facade::JobAction::Cancel(id),
            };
            finish(job(&cli.workspace, action, cli.json))
        }
        Command::Setup {
            what:
                SetupCommand::Ghidra {
                    extern_dir,
                    ghidra_zip,
                    jdk_zip,
                    ghidra_dir,
                    jdk_dir,
                    plugins_dir,
                },
        } => finish(setup_ghidra(
            extern_dir,
            (ghidra_zip, jdk_zip),
            (ghidra_dir, jdk_dir),
            plugins_dir,
            cli.json,
        )),
        Command::Setup {
            what:
                SetupCommand::UnicornDos {
                    extern_dir,
                    python,
                    plugins_dir,
                },
        } => finish(setup_unicorn_dos(extern_dir, python, plugins_dir, cli.json)),
        Command::Setup {
            what:
                SetupCommand::DosboxLab {
                    package,
                    extern_dir,
                    python,
                    plugins_dir,
                },
        } => finish(setup_dosbox_lab(
            package,
            extern_dir,
            python,
            plugins_dir,
            cli.json,
        )),
        Command::Setup {
            what:
                SetupCommand::DecompLegacy {
                    decomp,
                    plugins_dir,
                },
        } => finish(setup_decomp_legacy(&decomp, plugins_dir, cli.json)),
        Command::Setup {
            what: SetupCommand::Toolchain { profile, dir },
        } => finish(setup_toolchain(&profile, &dir, cli.json)),
    }
}

/// Print the JSON or the text form of a result; errors exit 2.
fn bench_print(result: Result<(String, String), String>, json: bool) -> ExitCode {
    match result {
        Ok((j, t)) => {
            println!("{}", if json { &j } else { &t }.trim_end());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

/// `bench report`.
fn bench_report(run: &Path, group_by: Option<BenchGroupBy>, json: bool) -> ExitCode {
    let group = match group_by {
        None => decovery_bench::GroupBy::None,
        Some(BenchGroupBy::Workspace) => decovery_bench::GroupBy::Workspace,
        Some(BenchGroupBy::Profile) => decovery_bench::GroupBy::Profile,
        Some(BenchGroupBy::Tag) => decovery_bench::GroupBy::Tag,
    };
    let result = decovery_bench::RunRecord::read(run)
        .map_err(|e| e.to_string())
        .and_then(|record| {
            let report = decovery_bench::report(&record, group);
            let json = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
            Ok((json, report.to_text()))
        });
    bench_print(result, json)
}

/// `bench compare`.
fn bench_compare(a: &Path, b: &Path, json: bool) -> ExitCode {
    let result = (|| {
        let a = decovery_bench::RunRecord::read(a).map_err(|e| e.to_string())?;
        let b = decovery_bench::RunRecord::read(b).map_err(|e| e.to_string())?;
        let comparison = decovery_bench::compare(&a, &b);
        let json = serde_json::to_string_pretty(&comparison).map_err(|e| e.to_string())?;
        Ok((json, comparison.to_text()))
    })();
    bench_print(result, json)
}

/// `bench run`: the record as JSON or one line per task, exit 0 only for a finished run.
fn bench_run(suite: &Path, options: &decovery_bench::RunOptions, json: bool) -> ExitCode {
    let result = (|| -> Result<decovery_bench::RunRecord, String> {
        let suite = decovery_bench::read_suite(suite).map_err(|e| e.to_string())?;
        let user = decovery_core::read_user_config().map_err(|e| e.to_string())?;
        let driver = user.bench.drivers.get(&options.driver).ok_or_else(|| {
            format!(
                "unknown driver `{}`: add [bench.drivers.{}] to the user config",
                options.driver, options.driver
            )
        })?;
        decovery_bench::run_suite(&suite, driver, options, &|p: Progress| {
            if let Some(message) = &p.message {
                eprintln!("{} of {}: {message}", p.done, p.total.unwrap_or(0));
            }
        })
        .map_err(|e| e.to_string())
    })();
    let run = match result {
        Ok(run) => run,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    if json {
        match serde_json::to_string_pretty(&run) {
            Ok(text) => println!("{text}"),
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
        }
    } else {
        for t in &run.tasks {
            println!(
                "{} #{}: {} ({}), builds {}, calls {}, best distance {}",
                t.id,
                t.repeat,
                if t.solved { "solved" } else { "unsolved" },
                t.exit,
                t.builds,
                t.tool_calls,
                t.best_distance.map_or("-".into(), |d| d.to_string())
            );
        }
        println!(
            "run {}: {}, {} of {} solved",
            run.id, run.state, run.totals.solved, run.totals.tasks
        );
    }
    if run.state == "done" {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// Prints the failure on stderr and maps it to its exit code.
fn parse_hex_u16(text: &str) -> Result<u16, String> {
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    u16::from_str_radix(digits, 16).map_err(|e| format!("{text:?}: {e}"))
}

/// `--limit` of `find`: a row count or `all`.
fn parse_limit(text: &str) -> Result<usize, String> {
    if text.eq_ignore_ascii_case("all") {
        return Ok(usize::MAX);
    }
    text.parse::<usize>()
        .map_err(|_| format!("`{text}` is not a number or `all`"))
}

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
    print_attempt_counts(&report.attempt_memory);
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

fn print_attempt_counts(report: &decovery_core::AttemptMigrationReport) {
    println!(
        "Attempt memory: {} imported, {} archive entries, {} already present, {} lines and {} archives skipped",
        report.attempts,
        report.archive_entries,
        report.already_present,
        report.skipped_lines,
        report.skipped_archives
    );
    for issue in &report.skipped {
        println!("  {issue}");
    }
    for warning in &report.warnings {
        println!("  warning: {warning}");
    }
}

fn migrate_attempts(root: &Path, from: Option<&Path>, json: bool) -> Result<(), FacadeError> {
    let workspace = decovery_core::Workspace::open(root)?;
    let configured;
    let source = match from {
        Some(path) => path,
        None => {
            let legacy = workspace
                .config
                .legacy
                .as_ref()
                .and_then(|legacy| legacy.decomp_workspace.as_deref())
                .filter(|path| !path.is_empty())
                .ok_or_else(|| {
                    FacadeError::Invalid(
                        "no [legacy] decomp_workspace configured; pass --from".into(),
                    )
                })?;
            configured = workspace.root.join(legacy);
            &configured
        }
    };
    let report = decovery_core::migrate_attempts(source, root)
        .map_err(|e| FacadeError::Invalid(e.to_string()))?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|e| FacadeError::Invalid(e.to_string()))?
        );
    } else {
        print_attempt_counts(&report);
    }
    Ok(())
}

fn setup_ghidra(
    extern_dir: Option<PathBuf>,
    (ghidra_zip, jdk_zip): (Option<PathBuf>, Option<PathBuf>),
    (ghidra_dir, jdk_dir): (Option<PathBuf>, Option<PathBuf>),
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
        ghidra_dir: ghidra_dir.map(absolute),
        jdk_dir: jdk_dir.map(absolute),
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

fn setup_unicorn_dos(
    extern_dir: Option<PathBuf>,
    python: Option<String>,
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
    let options = setup::UnicornOptions {
        extern_dir: absolute(extern_dir),
        plugins_dir: absolute(plugins_dir),
        python: python
            .or_else(|| std::env::var("DECOVERY_PYTHON").ok())
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| "python".into()),
        config_path,
        platform,
    };
    let report = setup::run_unicorn_setup(&options, &setup::SystemRunner, &mut |line| {
        eprintln!("{line}")
    })
    .map_err(|e| invalid(e.to_string()))?;
    let response = Response::new(
        format!(
            "Plugin `unicorn-dos` installed in {}; registered in {}",
            report.venv_python.display(),
            report.config_path.display()
        ),
        serde_json::json!({
            "venv_python": report.venv_python.display().to_string(),
            "config": report.config_path.display().to_string(),
            "venv_kept": report.venv_kept,
        }),
    );
    print_summary(&response, json)
}

fn setup_dosbox_lab(
    package: PathBuf,
    extern_dir: Option<PathBuf>,
    python: Option<String>,
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
    let options = setup::DosboxLabOptions {
        extern_dir: absolute(extern_dir),
        plugins_dir: absolute(plugins_dir),
        package_dir: absolute(package),
        python: python
            .or_else(|| std::env::var("DECOVERY_PYTHON").ok())
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| "python".into()),
        config_path,
        platform,
    };
    let report = setup::run_dosbox_lab_setup(&options, &setup::SystemRunner, &mut |line| {
        eprintln!("{line}")
    })
    .map_err(|e| invalid(e.to_string()))?;
    let response = Response::new(
        format!(
            "Plugin `dosbox-lab` installed in {}; registered in {}. The DOSBox executable is not part of the package: build dosbox-lab or set DOSBOX_LAB_EXE",
            report.venv_python.display(),
            report.config_path.display()
        ),
        serde_json::json!({
            "venv_python": report.venv_python.display().to_string(),
            "config": report.config_path.display().to_string(),
            "venv_kept": report.venv_kept,
        }),
    );
    print_summary(&response, json)
}

fn setup_decomp_legacy(
    decomp: &Path,
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
    let absolute = |p: &Path| std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
    let options = setup::DecompLegacyOptions {
        decomp_dir: absolute(decomp),
        plugins_dir: absolute(&plugins_dir),
        config_path,
        platform,
    };
    let report = setup::run_decomp_legacy_setup(&options, &mut |line| eprintln!("{line}"))
        .map_err(|e| invalid(e.to_string()))?;
    let response = Response::new(
        format!(
            "Plugin `decomp-legacy` registered in {} (Python {})",
            report.config_path.display(),
            report.python.display()
        ),
        serde_json::json!({
            "python": report.python.display().to_string(),
            "pythonpath": report.pythonpath,
            "config": report.config_path.display().to_string(),
        }),
    );
    print_summary(&response, json)
}

fn setup_toolchain(profile: &str, dir: &Path, json: bool) -> Result<(), FacadeError> {
    let invalid = |e: String| FacadeError::Invalid(e);
    decovery_toolchain::profile(profile).map_err(|e| invalid(e.to_string()))?;
    if !dir.is_dir() {
        return Err(invalid(format!("{} is not a directory", dir.display())));
    }
    let dir = std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf());
    let config_path = decovery_facade::plugins::user_config_path().ok_or_else(|| {
        invalid("cannot locate the user config dir (APPDATA / HOME unset)".into())
    })?;
    setup::write_toolchain_entry(&config_path, profile, &dir)
        .map_err(|e| invalid(e.to_string()))?;
    let response = Response::new(
        format!(
            "Toolchain `{profile}` registered in {}",
            config_path.display()
        ),
        serde_json::json!({
            "profile": profile,
            "dir": dir.display().to_string(),
            "config": config_path.display().to_string(),
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

fn show(
    workspace: &Path,
    target: &str,
    lines: bool,
    asm: bool,
    json: bool,
) -> Result<(), FacadeError> {
    let session = Session::open(workspace)?;
    let run = |budget| {
        if asm {
            decovery_facade::show_with_asm(&session, target, budget, lines)
        } else if lines {
            decovery_facade::show_with_lines(&session, target, budget)
        } else {
            decovery_facade::show(&session, target, budget)
        }
    };
    if json {
        return print_json(&run(Budget::default())?);
    }
    let response = run(Budget { chars: usize::MAX })?;
    if let Some(signature) = response.data["signature"].as_str() {
        println!("/* decompiler signature: {signature} */");
    }
    if let Some(text) = response.data["text"].as_str() {
        print!("{text}");
    }
    if let Some(asm) = response.data["asm"].as_str().filter(|a| !a.is_empty()) {
        println!("
/* original disassembly */");
        print!("{asm}");
    }
    for warning in response.data["warnings"].as_array().into_iter().flatten() {
        if let Some(text) = warning.as_str() {
            eprintln!("note: {text}");
        }
    }
    Ok(())
}

fn diagnose(workspace: &Path, target: &str, json: bool) -> Result<(), FacadeError> {
    let session = Session::open(workspace)?;
    if json {
        return print_json(&decovery_facade::diagnose(
            &session,
            target,
            Budget::default(),
        )?);
    }
    let response = decovery_facade::diagnose(&session, target, Budget { chars: usize::MAX })?;
    let d = &response.data;
    println!("{}", response.summary);
    for warning in d["warnings"].as_array().into_iter().flatten() {
        if let Some(text) = warning.as_str() {
            eprintln!("note: {text}");
        }
    }
    for f in d["findings"].as_array().into_iter().flatten() {
        println!(
            "  [{}] {} → {}",
            f["rule"].as_str().unwrap_or(""),
            f["text"].as_str().unwrap_or(""),
            f["suggestion"].as_str().unwrap_or("")
        );
    }
    if let Some(text) = d["pairs_text"].as_str() {
        println!();
        print!("{text}");
    }
    Ok(())
}

/// Seconds between two "still running" lines while a legacy call's progress message stays the same.
const LEGACY_STILL_RUNNING_S: u64 = 60;

/// Runs a legacy bridge call (`diagnose --deep`, `search`, `verify`) and prints its result: the summary, Decomp's
/// report and what decovery adds.
fn legacy(workspace: &Path, call: &LegacyCall, json: bool) -> Result<(), FacadeError> {
    // The plugin sends a heartbeat every few seconds, mostly with an unchanged message: print a message when it
    // changes, otherwise a "still running" line once a minute.
    let last = std::cell::RefCell::new((String::new(), 0u64));
    let progress = |p: Progress| {
        let Some(message) = p.message.filter(|m| !m.trim().is_empty()) else {
            return;
        };
        let mut last = last.borrow_mut();
        if message != last.0 {
            eprintln!("{message}");
            *last = (message, p.done);
        } else if p.done >= last.1 + LEGACY_STILL_RUNNING_S {
            eprintln!("still running ({} s): {message}", p.done);
            last.1 = p.done;
        }
    };
    let mut call = call.clone();
    if !json {
        call.budget = Budget { chars: usize::MAX };
    }
    let response = decovery_facade::run_as_job(workspace, &JobOperation::legacy(call), &progress)?;
    if json {
        return print_json(&response);
    }
    let d = &response.data;
    println!("{}", response.summary);
    if let Some(report) = d["report"].as_str().filter(|r| !r.is_empty()) {
        println!();
        println!(
            "--- Decomp report ({}) ---",
            d["report_language"].as_str().unwrap_or("de")
        );
        print!("{report}");
        if !report.ends_with('\n') {
            println!();
        }
    }
    let own = &d["decovery"];
    if !own.is_null() {
        println!();
        println!("--- decovery diagnosis ---");
        match own["error"].as_str() {
            Some(error) => println!("{error}"),
            None => {
                println!("{}", own["summary"].as_str().unwrap_or(""));
                for f in own["data"]["findings"].as_array().into_iter().flatten() {
                    println!(
                        "  [{}] {} → {}",
                        f["rule"].as_str().unwrap_or(""),
                        f["text"].as_str().unwrap_or(""),
                        f["suggestion"].as_str().unwrap_or("")
                    );
                }
            }
        }
    }
    let candidate = &d["candidate"];
    if !candidate.is_null() {
        println!();
        println!(
            "candidate: {} ({}, judged as a {} attempt on {})",
            candidate["path"].as_str().unwrap_or(""),
            candidate["kind"].as_str().unwrap_or(""),
            candidate["evaluated_as"].as_str().unwrap_or(""),
            candidate["file"].as_str().unwrap_or("")
        );
        println!("{}", candidate["note"].as_str().unwrap_or(""));
    }
    Ok(())
}

fn annotate(workspace: &Path, request: &Annotation, json: bool) -> Result<(), FacadeError> {
    let response = decovery_facade::annotate(workspace, request)?;
    print_summary(&response, json)
}

fn analyze(workspace: &Path, options: &AnalyzeOptions, json: bool) -> Result<(), FacadeError> {
    let progress = |p: Progress| {
        if json {
            return;
        }
        let message = p
            .message
            .filter(|m| !m.trim().is_empty())
            .unwrap_or_else(|| "working …".to_string());
        match p.total {
            Some(total) => eprintln!("{}/{total} {message}", p.done),
            None => eprintln!("{message}"),
        }
    };
    let response = decovery_facade::run_as_job(
        workspace,
        &JobOperation::Analyze(options.clone()),
        &progress,
    )?;
    print_summary(&response, json)
}

/// Builds and prints the result; `true` when every built function is identical and no file failed.
fn build(
    workspace: &Path,
    files: Vec<String>,
    function: Option<String>,
    variants: &[PathBuf],
    function_sources: &[PathBuf],
    json: bool,
) -> Result<bool, FacadeError> {
    // with --json the output is the JSON alone, also when stdout and stderr are read together
    let progress = |p: Progress| {
        if json {
            return;
        }
        if let Some(message) = p.message.filter(|m| !m.trim().is_empty()) {
            eprintln!("{message}");
        }
    };
    let mut request = BuildRequest::default();
    request.files = files;
    request.function = function;
    // UTF-8 text, else code page 437 (what a DOS-era editor writes)
    let read = |path: &Path| {
        let bytes = std::fs::read(path).map_err(|e| {
            FacadeError::Invalid(format!("cannot read variant {}: {e}", path.display()))
        })?;
        Ok::<_, FacadeError>(
            String::from_utf8(bytes)
                .unwrap_or_else(|e| decovery_toolchain::from_cp437(e.as_bytes())),
        )
    };
    for path in variants {
        request
            .variants
            .push(Variant::new(read(path)?).with_label(path.display().to_string()));
    }
    for path in function_sources {
        request
            .variants
            .push(Variant::function(read(path)?).with_label(path.display().to_string()));
    }
    let has_variants = !request.variants.is_empty();
    let response =
        decovery_facade::run_as_job(workspace, &JobOperation::Build(request), &progress)?;
    if has_variants {
        return print_variants(&response, json);
    }
    let d = &response.data;
    let counts = &d["counts"];
    let complete = counts["failed_files"] == 0 && counts["identical"] == counts["functions"];
    if json {
        print_json(&response)?;
        return Ok(complete);
    }
    print_summary(&response, false)?;
    for file in d["files"].as_array().into_iter().flatten() {
        if file["status"] == "error" {
            println!(
                "{}: error: {}",
                file["file"].as_str().unwrap_or(""),
                file["message"].as_str().unwrap_or("").replace('\n', "\n  ")
            );
        }
    }
    for f in d["functions"].as_array().into_iter().flatten() {
        if f["verdict"] != "identical" {
            println!("{}", function_line(f));
            if let Some(near) = f["near"].as_str() {
                println!("  {near}");
            }
        }
    }
    for hint in d["hints"].as_array().into_iter().flatten() {
        if let Some(text) = hint.as_str() {
            eprintln!("hint: {text}");
        }
    }
    Ok(complete)
}

/// One differing function of a build: address, name, verdict, its blockers counted per kind (`kind ×n`), and
/// `(follow-on)` for a function behind the first real difference of a shifted overlay module.
fn function_line(f: &serde_json::Value) -> String {
    let blockers: Vec<String> = match f["blocker_counts"].as_object() {
        Some(counts) => counts
            .iter()
            .map(|(kind, n)| match n.as_u64() {
                Some(n) if n > 1 => format!("{kind} ×{n}"),
                _ => kind.clone(),
            })
            .collect(),
        None => f["blockers"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|b| b["kind"].as_str().map(str::to_string))
            .collect(),
    };
    let mut line = format!(
        "{}\t{}\t{}\t{}",
        f["address"].as_str().unwrap_or(""),
        f["name"].as_str().unwrap_or(""),
        f["verdict"].as_str().unwrap_or(""),
        blockers.join(", ")
    );
    if f["cause"] == true {
        line.push_str("\t(cause)");
    }
    if f["consequence"] == true {
        line.push_str("\t(follow-on)");
    }
    line
}

/// Links and prints the result; the exit code follows the result (0 identical, 1 differs, 2 error).
fn link(workspace: &Path, json: bool) -> Result<ExitCode, FacadeError> {
    // with --json the output is the JSON alone, also when stdout and stderr are read together
    let progress = |p: Progress| {
        if json {
            return;
        }
        if let Some(message) = p.message.filter(|m| !m.trim().is_empty()) {
            eprintln!("{message}");
        }
    };
    let response = decovery_facade::run_as_job(workspace, &JobOperation::Link, &progress)?;
    let d = &response.data;
    let code = match d["result"].as_str() {
        Some("identical") => ExitCode::SUCCESS,
        Some("differs") => ExitCode::from(1),
        _ => ExitCode::from(2),
    };
    if json {
        print_json(&response)?;
        return Ok(code);
    }
    print_summary(&response, false)?;
    // the summary carries the first line of the message
    for line in d["message"].as_str().unwrap_or("").lines().skip(1) {
        println!("  {line}");
    }
    for line in d["diagnosis"].as_array().into_iter().flatten() {
        println!("{}", line.as_str().unwrap_or(""));
    }
    if let Some(shares) = d["shares"].as_object() {
        let parts: Vec<String> = shares
            .iter()
            .filter(|(_, v)| v.as_u64().unwrap_or(0) > 0)
            .map(|(k, v)| format!("{k} {v}"))
            .collect();
        println!("shares (bytes): {}", parts.join(", "));
    }
    if let Some(used) = d["used"].as_object() {
        println!(
            "inserted: {} functions, {} bytes",
            used["functions"], used["bytes"]
        );
    }
    if let Some(n) = d["symbols_added"].as_u64().filter(|&n| n > 0) {
        println!("symbols added from the link map: {n}");
    }
    for hint in d["hints"].as_array().into_iter().flatten() {
        if let Some(text) = hint.as_str() {
            eprintln!("hint: {text}");
        }
    }
    Ok(code)
}

/// Prints the ranked variants (best first); `true` when the best one is identical.
fn print_variants(response: &Response, json: bool) -> Result<bool, FacadeError> {
    let best_identical =
        response.data["variants"][0]["verdict"] == "identical" && !response.data["best"].is_null();
    if json {
        print_json(response)?;
        return Ok(best_identical);
    }
    print_summary(response, false)?;
    for v in response.data["variants"].as_array().into_iter().flatten() {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            v["index"],
            v["verdict"].as_str().unwrap_or(""),
            v["instructions_differing"],
            v["differing"],
            v["refs_wrong"],
            v["label"].as_str().unwrap_or("")
        );
        if let Some(message) = v["message"].as_str() {
            println!("  {}", message.replace('\n', "\n  "));
        }
    }
    Ok(best_identical)
}

/// The JSON envelope, or the summary on stdout and `data.warnings` on stderr.
/// `job list | poll | cancel`: the summary, and for `list` one line per job.
fn job(
    workspace: &Path,
    action: decovery_facade::JobAction,
    json: bool,
) -> Result<(), FacadeError> {
    let response = decovery_facade::job_tool(workspace, action)?;
    if json {
        return print_json(&response);
    }
    println!("{}", response.summary);
    for j in response.data["jobs"].as_array().into_iter().flatten() {
        let text = |key: &str| j[key].as_str().unwrap_or("").to_string();
        let note = match j["state"].as_str() {
            Some("failed" | "interrupted") => text("error"),
            _ => text("summary"),
        };
        println!(
            "{}\t{}\t{}\t{}\t{note}",
            text("id"),
            text("kind"),
            text("state"),
            text("created")
        );
    }
    Ok(())
}

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

fn history(
    workspace: &Path,
    function: &str,
    limit: usize,
    archive: Option<&str>,
    json: bool,
) -> Result<(), FacadeError> {
    let budget = if json {
        Budget::default()
    } else {
        Budget { chars: usize::MAX }
    };
    let response = match archive {
        Some(id) => decovery_facade::history_archive(workspace, function, id, budget)?,
        None => decovery_facade::history(workspace, function, limit, budget)?,
    };
    if json {
        return print_json(&response);
    }
    let d = &response.data;
    println!("{}", response.summary);
    if archive.is_some() {
        for key in ["function_c", "comparison"] {
            if let Some(text) = d[key].as_str() {
                println!();
                print!("{text}");
            }
        }
        return Ok(());
    }
    for a in d["attempts"].as_array().into_iter().flatten() {
        println!(
            "{}",
            cells(
                a,
                &[
                    "time",
                    "origin",
                    "label",
                    "actor",
                    "verdict",
                    "instructions_differing",
                    "archive"
                ]
            )
        );
    }
    for f in d["failures"].as_array().into_iter().flatten() {
        println!(
            "failed {}x: {}",
            f["count"],
            f["message"].as_str().unwrap_or("")
        );
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
    if query.what == FindWhat::Similar {
        for item in d["items"].as_array().into_iter().flatten() {
            println!(
                "{}",
                cells(item, &["address", "name", "file", "flags", "reason"])
            );
            if let Some(source) = item["source"].as_str() {
                print!("{source}");
                if !source.ends_with('\n') {
                    println!();
                }
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

#[cfg(test)]
mod tests {
    use super::function_line;
    use serde_json::json;

    #[test]
    fn a_function_line_counts_blockers_and_marks_consequences() {
        let f = json!({
            "address": "ovl:A:0000:5400", "name": "later", "verdict": "differs",
            "blocker_counts": {"bytes-differ": 3, "data-layout": 1, "wrong-relative-ref": 20},
            "consequence": true,
        });
        assert_eq!(
            function_line(&f),
            "ovl:A:0000:5400\tlater\tdiffers\tbytes-differ ×3, data-layout, wrong-relative-ref ×20\t(follow-on)"
        );
    }
}
