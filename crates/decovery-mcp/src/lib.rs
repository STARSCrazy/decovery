//! MCP server of decovery: the thirteen facade tools (`status`, `find`, `show`, `annotate`, `analyze`, `build`,
//! `link`, `diagnose`, `search`, `verify`, `history`, `detail`, `job`) over stdio.
//!
//! Long calls (`analyze`, `build`, `link`, `diagnose` with `deep`, `search`, `verify`) are jobs (design 5.13,
//! ADR 0010). With `background` (default true for `search` and `verify`) they return at once with the job; the
//! server's [`JobRunner`] runs them and `job` polls or cancels them. In the foreground the call waits but is
//! registered as a job too, so `status` and `job` see it.
//!
//! `diagnose` with `deep`, `search` and `verify` run Decomp's tools through the `decomp-legacy` plugin (ADR 0007);
//! the server keeps that plugin running between calls, so its Decomp server and Ghidra project stay open.
//!
//! The server is a thin adapter. Every call re-opens the session from disk, so knowledge changed by another
//! writer between calls is seen. Results are the facade envelope as JSON text; facade errors become tool
//! results with `isError` and the facade message. stdout carries only MCP frames.
//!
//! Every tool call, also a refused or failed one, appends one line to the tool-call log (`cache/calls/`, actor
//! `mcp` or `DECOVERY_ACTOR`); no tool reads it.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use decovery_core::{CallRecord, ClaimSource, Confidence, append_call};
use decovery_facade::{
    AnalyzeOptions, AnnotateAction, Annotation, Budget, BuildRequest, DEFAULT_HISTORY_LIMIT,
    DEFAULT_LIMIT, DEFAULT_MAX_JOBS, DEFAULT_SIMILAR_LIMIT, FacadeError, FindQuery, FindWhat,
    FunctionFilter, FunctionSort, JobAction, JobOperation, JobRunner, LegacyCall, LegacyOperation,
    Progress, Response, Session, Variant, background_by_default,
};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::ToolCallContext;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    JsonObject, MetaObject, ProgressNotificationParam, RequestMetaObject, ServerCapabilities,
    ServerConfig,
};
use rmcp::schemars::JsonSchema;
use rmcp::service::RequestContext;
use rmcp::{
    ErrorData, Peer, RoleServer, ServerHandler, ServiceExt, tool, tool_handler, tool_router,
};
use serde::Deserialize;

const INSTRUCTIONS: &str = "Thirteen tools over one decovery workspace (a reverse-engineered executable). Rebuild \
verdicts (`build`, `link`) are tool findings; names, types and comments are claims with a source and confidence. \
`diagnose` with `deep`, `search` and `verify` use Decomp through the decomp-legacy bridge: its reports are German \
(`report_language`), its findings are evidence, and only decovery's own build sets verdicts. `history` lists what \
was tried on a function. Long calls take `background: true` (`search` and `verify` run in the background by \
default) and return a job id at once; `job` polls or cancels it and `detail` pages its result handle.";

/// The marker a handler puts into a tool error's `_meta` when it refused the call (bad parameters) instead of
/// running it; the call log records `refused` and the marker is removed before the answer goes out.
const REFUSED: &str = "decovery/refused";
/// How rmcp starts the tool error for arguments that do not deserialize into the tool's parameters.
const ARGUMENTS_REJECTED: &str = "failed to deserialize parameters:";

/// Serves the thirteen tools for the workspace at `root` on stdin/stdout until the client disconnects.
pub fn serve_stdio(root: PathBuf) -> Result<(), FacadeError> {
    serve_stdio_with_limits(root, None)
}

/// A benchmark endpoint optionally enforces schema-one limits before dispatching any tool.
pub fn serve_stdio_with_limits(
    root: PathBuf,
    limits_path: Option<PathBuf>,
) -> Result<(), FacadeError> {
    serve_stdio_with_options(root, limits_path, DEFAULT_MAX_JOBS)
}

/// [`serve_stdio_with_limits`] running at most `max_jobs` background jobs at once (`decovery mcp --max-jobs`).
pub fn serve_stdio_with_options(
    root: PathBuf,
    limits_path: Option<PathBuf>,
    max_jobs: usize,
) -> Result<(), FacadeError> {
    let bench = limits_path
        .map(|path| -> Result<_, FacadeError> {
            let limits = decovery_core::BenchLimits::read(&path)?;
            let usage = decovery_core::BenchUsage::load(&root)?;
            usage.save(&root)?;
            Ok(Arc::new(Mutex::new(LimitState { limits, usage })))
        })
        .transpose()?;
    decovery_facade::keep_legacy_plugin(true);
    decovery_facade::set_actor("mcp");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| FacadeError::Invalid(format!("cannot start the MCP server: {e}")))?;
    runtime.block_on(async move {
        let mut server = Server::new(root.clone());
        server.bench = bench;
        // jobs a stopped server left are resumed before the first call
        server.runner = Some(Arc::new(JobRunner::start(root, max_jobs)));
        let service = server
            .serve(rmcp::transport::stdio())
            .await
            .map_err(|e| FacadeError::Invalid(format!("MCP initialization failed: {e}")))?;
        service
            .waiting()
            .await
            .map_err(|e| FacadeError::Invalid(format!("MCP server stopped: {e}")))?;
        Ok(())
    })
}

#[derive(Clone)]
struct Server {
    root: PathBuf,
    tool_router: ToolRouter<Self>,
    bench: Option<Arc<Mutex<LimitState>>>,
    runner: Option<Arc<JobRunner>>,
}

struct LimitState {
    limits: decovery_core::BenchLimits,
    usage: decovery_core::BenchUsage,
}

/// Default inline budget of `show` and `find`.
const DEFAULT_BUDGET: usize = 8000;

#[derive(Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
#[serde(deny_unknown_fields)]
struct ShowParams {
    /// Function name, address (`flat:0001A2B0`) or file offset (`file:0x1A2B`).
    target: String,
    /// Characters of text returned inline (default 8000); the rest is stored as a handle.
    budget: Option<usize>,
}

#[derive(Clone, Copy, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
#[serde(rename_all = "kebab-case")]
enum What {
    Functions,
    Names,
    Strings,
    Code,
    Xrefs,
    Similar,
}

#[derive(Clone, Copy, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
#[serde(rename_all = "kebab-case")]
enum Filter {
    Named,
    Unnamed,
    Assumed,
    Confirmed,
    NotTried,
    Identical,
    Differs,
    Parked,
}

#[derive(Clone, Copy, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
#[serde(rename_all = "kebab-case")]
enum Sort {
    Address,
    Callers,
    Size,
}

#[derive(Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
#[serde(deny_unknown_fields)]
struct FindParams {
    /// What to search.
    what: What,
    /// Case-insensitive text, `*` matches any run; for `xrefs` and `similar` the target (name or address).
    pattern: Option<String>,
    /// Restrict the function list (all must hold); `functions` only. `parked`: the attempt budget is spent
    /// without reaching identical (see `history`).
    filter: Option<Vec<Filter>>,
    /// Order of the function list (default `address`); `functions` only.
    sort: Option<Sort>,
    /// Maximum number of rows (default 100; `similar`: 3); the rest is stored as a handle.
    limit: Option<usize>,
    /// Characters of rows returned inline (default 8000); the rest is stored as a handle.
    budget: Option<usize>,
}

#[derive(Clone, Copy, Default, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
#[serde(rename_all = "kebab-case")]
enum ClaimConfidence {
    Confirmed,
    #[default]
    Assumed,
}

#[derive(Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
#[serde(deny_unknown_fields)]
struct LocalParams {
    /// `param:1`, `stack:-0x10` or `reg:EAX`.
    place: String,
    /// Name of the local (a C identifier).
    name: String,
    /// C type of the local.
    #[serde(rename = "type")]
    data_type: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
#[serde(deny_unknown_fields)]
struct AnnotateParams {
    /// Function or symbol name, address or `file:0x…`; not needed for `add_type`.
    target: Option<String>,
    /// Action: name the target (a C identifier).
    name: Option<String>,
    /// Action: comment on the target; inside a function it becomes a line comment.
    comment: Option<String>,
    /// Action: C prototype of the function.
    signature: Option<String>,
    /// Action: C type of a global.
    #[serde(rename = "type")]
    data_type: Option<String>,
    /// Action: name a local of the target function.
    local: Option<LocalParams>,
    /// Action: withdraw the target's name; the value is the reason.
    refute: Option<String>,
    /// Action: append a C type definition to `types.h`.
    add_type: Option<String>,
    /// How sure the claim is (default `assumed`).
    confidence: Option<ClaimConfidence>,
    /// What the claim rests on.
    evidence: Option<String>,
    /// Replace a value held under a stronger claim (see the tool description).
    force: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
#[serde(deny_unknown_fields)]
struct AnalyzeParams {
    /// Plugin as configured in `[plugins.<name>]` (default `ghidra`).
    plugin: Option<String>,
    /// Decompile only these functions again (names, addresses or `file:0x…`); default: all.
    functions: Option<Vec<String>>,
    /// Run as a background job and return at once with its id (`job` polls it, `detail` pages its result);
    /// default false.
    background: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
#[serde(deny_unknown_fields)]
struct VariantParams {
    /// Name shown in the ranking (default: its position in the request).
    label: Option<String>,
    /// A whole replacement of the function's source file.
    source: Option<String>,
    /// A definition of `function` alone, spliced into its file.
    function_source: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
#[serde(deny_unknown_fields)]
struct BuildParams {
    /// Source files in `src/` (e.g. `ai.c`); default: all.
    files: Option<Vec<String>>,
    /// Report this function only (name or address); its file is built. Required with `variants`.
    function: Option<String>,
    /// Candidate sources for `function` (at most 64): compiled and ranked best first, nothing is recorded.
    /// Each has exactly one of `source` and `function_source`. A `function_source` variant may be compiled in a
    /// file shrunk to what the function needs (`shrunk: true`, for ranking); `identical` is only reported after
    /// the full file confirms it (`confirmed_on: "full"`). Variants are not diagnosed: call `diagnose` for a
    /// function that differs.
    variants: Option<Vec<VariantParams>>,
    /// Characters of the function list returned inline (default 8000); the rest is stored as a handle.
    /// Not used with `variants`.
    budget: Option<usize>,
    /// Run as a background job and return at once with its id (`job` polls it, `detail` pages its result);
    /// default false.
    background: Option<bool>,
}

#[derive(Clone, Copy, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
#[serde(rename_all = "kebab-case")]
enum Deep {
    Context,
    Structure,
    Registers,
    Slots,
    Joint,
}

#[derive(Clone, Copy, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
#[serde(rename_all = "kebab-case")]
enum Strategy {
    Chain,
    Permute,
    Beam,
    Forms,
}

#[derive(Clone, Copy, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
#[serde(rename_all = "kebab-case")]
enum Check {
    Equivalence,
    Behavior,
}

#[derive(Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
#[serde(deny_unknown_fields)]
struct DiagnoseParams {
    /// Rebuilt function: name or address.
    target: String,
    /// Characters of the instruction pairs (and of Decomp's report with `deep`) returned inline (default 8000);
    /// the rest is stored as a handle.
    budget: Option<usize>,
    /// Decomp's deeper analysis next to decovery's: `context` (context package), `structure` (structure comparison),
    /// `registers` (Watcom register allocation), `slots` (stack slots), `joint` (both together). Slow; German report.
    deep: Option<Deep>,
    /// With `deep` (`structure`, `registers`, `slots`, `joint`): path of a candidate source of the function to
    /// analyze instead of the current one.
    source: Option<String>,
    /// With `deep = registers`: the full report.
    all: Option<bool>,
    /// With `deep = slots`: time budget in minutes.
    minutes: Option<f64>,
    /// With `deep`: run as a background job and return at once with its id (`job` polls it, `detail` pages its
    /// result); default false.
    background: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
#[serde(deny_unknown_fields)]
struct SearchParams {
    /// Function: name or address.
    target: String,
    /// Decomp's search: `chain` (search chain), `permute` (permuter), `beam` (beam search), `forms` (form catalogue).
    strategy: Strategy,
    /// Time budget in minutes.
    minutes: Option<f64>,
    /// Search rounds.
    rounds: Option<u32>,
    /// With `strategy = permute`: path of a candidate source of the function to start from.
    source: Option<String>,
    /// Write the candidate's function into `src/` when decovery's verdict on it is better (identical, or fewer
    /// differing instructions), then record it with a normal build. Default false: nothing in `src/` changes.
    apply: Option<bool>,
    /// Characters of Decomp's report returned inline (default 8000); the rest is stored as a handle.
    budget: Option<usize>,
    /// Run as a background job and return at once with its id (`job` polls it, `detail` pages its result);
    /// default true: a search runs minutes to hours.
    background: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
#[serde(deny_unknown_fields)]
struct VerifyParams {
    /// Function: name or address.
    target: String,
    /// `equivalence` (static and dynamic equivalence evidence) or `behavior` (recorded and generated cases).
    check: Check,
    /// With `check = behavior`: the recorded runtime run to take cases from.
    run: Option<String>,
    /// With `check = equivalence`: time budget in minutes.
    minutes: Option<f64>,
    /// Characters of Decomp's report returned inline (default 8000); the rest is stored as a handle.
    budget: Option<usize>,
    /// Run as a background job and return at once with its id (`job` polls it, `detail` pages its result);
    /// default true: a check runs minutes to hours.
    background: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
#[serde(deny_unknown_fields)]
struct LinkParams {
    /// Run as a background job and return at once with its id (`job` polls it, `detail` pages its result);
    /// default false.
    background: Option<bool>,
}

#[derive(Clone, Copy, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
#[serde(rename_all = "kebab-case")]
enum JobVerb {
    List,
    Poll,
    Cancel,
}

#[derive(Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
#[serde(deny_unknown_fields)]
struct JobParams {
    /// `list` (every job, newest first), `poll` (one job's state, progress, summary and result handle) or
    /// `cancel` (ask it to stop at its next cancellation point; a cancel during recording lets it complete).
    action: JobVerb,
    /// Job id (`j_` plus 12 hex characters) for `poll` and `cancel`.
    id: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
#[serde(deny_unknown_fields)]
struct HistoryParams {
    /// Function: name or address.
    target: String,
    /// Most attempts listed, newest first (default 20); all of them are in a handle when there are more.
    limit: Option<usize>,
    /// Id of an archived attempt (`archive` of an attempt): returns its `function.c` and `comparison.txt` instead.
    archive: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
#[serde(deny_unknown_fields)]
struct DetailParams {
    /// Handle id (`h_` plus 12 hex characters) from another tool's `handles`.
    handle: String,
    /// First character to return (default 0).
    offset: Option<usize>,
    /// Number of characters to return (default 8000).
    limit: Option<usize>,
}

#[tool_router]
impl Server {
    fn new(root: PathBuf) -> Self {
        Server {
            root,
            tool_router: Self::tool_router(),
            bench: None,
            runner: None,
        }
    }

    #[tool(
        description = "Counts of named and rebuilt functions, the analysis in use and the suggested next step. Call it first to orient."
    )]
    async fn status(&self) -> CallToolResult {
        self.blocking(|root| decovery_facade::status(&Session::open(root)?))
            .await
    }

    #[tool(
        description = "Search functions (filter, sort), names, strings, generated pseudo-C (`code`), cross references (`xrefs`, pattern = target) or the most similar identical functions with their source (`similar`, pattern = target). Rows beyond the limit are stored as a handle."
    )]
    async fn find(&self, Parameters(p): Parameters<FindParams>) -> CallToolResult {
        let what = match p.what {
            What::Functions => FindWhat::Functions,
            What::Names => FindWhat::Names,
            What::Strings => FindWhat::Strings,
            What::Code => FindWhat::Code,
            What::Xrefs => FindWhat::Xrefs,
            What::Similar => FindWhat::Similar,
        };
        let query = FindQuery {
            what,
            pattern: p.pattern,
            filter: p
                .filter
                .unwrap_or_default()
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
            sort: match p.sort.unwrap_or(Sort::Address) {
                Sort::Address => FunctionSort::Address,
                Sort::Callers => FunctionSort::Callers,
                Sort::Size => FunctionSort::Size,
            },
            limit: p.limit.unwrap_or(if what == FindWhat::Similar {
                DEFAULT_SIMILAR_LIMIT
            } else {
                DEFAULT_LIMIT
            }),
        };
        let budget = budget(p.budget);
        self.blocking(move |root| decovery_facade::find(&Session::open(root)?, &query, budget))
            .await
    }

    #[tool(
        description = "Header and pseudo-C of one function. Header names, types and rebuild verdicts are recorded claims and tool findings, not proof."
    )]
    async fn show(&self, Parameters(p): Parameters<ShowParams>) -> CallToolResult {
        let budget = budget(p.budget);
        self.blocking(move |root| decovery_facade::show(&Session::open(root)?, &p.target, budget))
            .await
    }

    #[tool(
        description = "Record one claim (exactly one action field) with source `agent`; affected output files are regenerated. Ranks: human > confirmed > assumed. A claim ranked below the record it changes does not replace an existing name, comment, line comment, signature, type or local (no change, a warning instead) unless `force` is set; filling an empty field is always allowed. A human line comment counts as human. A refute below the record's rank needs `force` too."
    )]
    async fn annotate(&self, Parameters(p): Parameters<AnnotateParams>) -> CallToolResult {
        let request = match annotation(p) {
            Ok(request) => request,
            Err(message) => return refused(message),
        };
        self.blocking(move |root| decovery_facade::annotate(root, &request))
            .await
    }

    #[tool(
        description = "Run the analyzer plugin over the target and regenerate the output. Slow (minutes); call it when status reports no or a stale analysis."
    )]
    async fn analyze(
        &self,
        Parameters(p): Parameters<AnalyzeParams>,
        meta: RequestMetaObject,
        peer: Peer<RoleServer>,
    ) -> CallToolResult {
        let options = AnalyzeOptions {
            plugin: p.plugin.unwrap_or_else(|| "ghidra".into()),
            functions: p.functions,
        };
        self.long(meta, peer, JobOperation::Analyze(options), p.background)
            .await
    }

    #[tool(
        description = "Compile the rebuild sources in `src/`, compare their functions with the original and record the verdicts (identical, differs, error); decovery sets them, not the caller. Slow (minutes); reports progress. With `variants` (and `function`) it compiles candidate sources instead and ranks them best first without recording anything; those results are not diagnosed, so call `diagnose` for a function that differs. A variant compiled in a shrunk file (`shrunk: true`, for ranking) is reported `identical` only after confirmation on the full file (`confirmed_on: \"full\"`)."
    )]
    async fn build(
        &self,
        Parameters(p): Parameters<BuildParams>,
        meta: RequestMetaObject,
        peer: Peer<RoleServer>,
    ) -> CallToolResult {
        let mut request = BuildRequest::default();
        request.files = p.files.unwrap_or_default();
        request.function = p.function;
        request.budget = p.budget;
        for v in p.variants.unwrap_or_default() {
            let variant = match (v.source, v.function_source) {
                (Some(source), None) => Variant::new(source),
                (None, Some(source)) => Variant::function(source),
                _ => {
                    return refused("each variant needs exactly one of source and function_source");
                }
            };
            request.variants.push(match v.label {
                Some(label) => variant.with_label(label),
                None => variant,
            });
        }
        self.long(meta, peer, JobOperation::Build(request), p.background)
            .await
    }

    #[tool(
        description = "Link the whole program with the original linker and compare it with the original file (MZ: all rebuild sources are compiled and linked; LE: identical rebuilds are inserted into the original image). Records the result; `data.result` is identical, differs or a link failure. After an identical MZ link the public symbols the knowledge base lacks are recorded from the linker map (`data.symbols_added`). Slow; reports progress."
    )]
    async fn link(
        &self,
        Parameters(p): Parameters<LinkParams>,
        meta: RequestMetaObject,
        peer: Peer<RoleServer>,
    ) -> CallToolResult {
        self.long(meta, peer, JobOperation::Link, p.background)
            .await
    }

    #[tool(
        description = "Explain why a rebuilt function differs from the original: findings with a suggestion each, the kind of deviation and the instruction pairs side by side. Reads the object of the last `build` of its file; run `build` first. With `deep`, Decomp's register, stack-slot or structure model of the function comes too (`data.report`, German, `report_language: \"de\"`; decovery's own diagnosis under `data.decovery`); slow, reports progress, needs `decovery setup decomp-legacy`."
    )]
    async fn diagnose(
        &self,
        Parameters(p): Parameters<DiagnoseParams>,
        meta: RequestMetaObject,
        peer: Peer<RoleServer>,
    ) -> CallToolResult {
        let budget = budget(p.budget);
        let Some(deep) = p.deep else {
            if p.source.is_some()
                || p.all.is_some()
                || p.minutes.is_some()
                || p.background.is_some()
            {
                return refused("source, all, minutes and background need deep");
            }
            return self
                .blocking(move |root| {
                    decovery_facade::diagnose(&Session::open(root)?, &p.target, budget)
                })
                .await;
        };
        let operation = match deep {
            Deep::Context => LegacyOperation::Context,
            Deep::Structure => LegacyOperation::Structure,
            Deep::Registers => LegacyOperation::Registers,
            Deep::Slots => LegacyOperation::Slots,
            Deep::Joint => LegacyOperation::Joint,
        };
        let mut call = LegacyCall::new(p.target, operation);
        call.budget = budget;
        call.options.source = p.source.map(PathBuf::from);
        call.options.all = p.all.unwrap_or(false);
        call.options.minutes = p.minutes;
        self.long(meta, peer, JobOperation::DiagnoseDeep(call), p.background)
            .await
    }

    #[tool(
        description = "Search a better source for one function with Decomp's search (`chain`, `permute`, `beam`, `forms`; minutes to hours). A candidate it finds is built by decovery as a function-level attempt next to the current source; `data.candidate` has decovery's verdict on both and `improved`. With `apply`, an improved candidate is written into `src/` and recorded; otherwise nothing changes. Decomp's report is German (`report_language`). Reports progress; needs `decovery setup decomp-legacy`."
    )]
    async fn search(
        &self,
        Parameters(p): Parameters<SearchParams>,
        meta: RequestMetaObject,
        peer: Peer<RoleServer>,
    ) -> CallToolResult {
        let operation = match p.strategy {
            Strategy::Chain => LegacyOperation::Chain,
            Strategy::Permute => LegacyOperation::Permute,
            Strategy::Beam => LegacyOperation::Beam,
            Strategy::Forms => LegacyOperation::Forms,
        };
        let mut call = LegacyCall::new(p.target, operation);
        call.budget = budget(p.budget);
        call.options.minutes = p.minutes;
        call.options.rounds = p.rounds;
        call.options.source = p.source.map(PathBuf::from);
        call.apply = p.apply.unwrap_or(false);
        self.long(meta, peer, JobOperation::Search(call), p.background)
            .await
    }

    #[tool(
        description = "Check a rebuilt function's behaviour with Decomp: `equivalence` (static and dynamic evidence) or `behavior` (recorded runtime cases with `run`, and generated ones). The result is evidence with `source: \"decomp\"` (`data.evidence`), never a decovery verdict; nothing is recorded. German report. Slow; reports progress; needs `decovery setup decomp-legacy`."
    )]
    async fn verify(
        &self,
        Parameters(p): Parameters<VerifyParams>,
        meta: RequestMetaObject,
        peer: Peer<RoleServer>,
    ) -> CallToolResult {
        let operation = match p.check {
            Check::Equivalence => LegacyOperation::Equivalence,
            Check::Behavior => LegacyOperation::Behavior,
        };
        let mut call = LegacyCall::new(p.target, operation);
        call.budget = budget(p.budget);
        call.options.run = p.run;
        call.options.minutes = p.minutes;
        self.long(meta, peer, JobOperation::Verify(call), p.background)
            .await
    }

    #[tool(
        description = "What was tried on one function: every recorded attempt (builds, variants, search candidates) newest first with decovery's verdict, the best one, the attempt budget (`parked` when it is spent without reaching identical; `find` filter `parked`) and the failures grouped by message. With `archive` (the id an attempt names) the archived definition (`function_c`) and comparison of that attempt."
    )]
    async fn history(&self, Parameters(p): Parameters<HistoryParams>) -> CallToolResult {
        self.blocking(move |root| match &p.archive {
            Some(id) => decovery_facade::history_archive(root, &p.target, id, Budget::default()),
            None => decovery_facade::history(
                root,
                &p.target,
                p.limit.unwrap_or(DEFAULT_HISTORY_LIMIT),
                Budget::default(),
            ),
        })
        .await
    }

    #[tool(description = "Page the stored content of a handle returned by another tool.")]
    async fn detail(&self, Parameters(p): Parameters<DetailParams>) -> CallToolResult {
        self.blocking(move |root| {
            decovery_facade::detail(
                root,
                &p.handle,
                p.offset.unwrap_or(0),
                p.limit.unwrap_or(DEFAULT_BUDGET),
            )
        })
        .await
    }

    #[tool(
        description = "The workspace's jobs (long calls): `list` them, `poll` one (state queued, running, done, failed, cancelled or interrupted; progress; summary; `result`, a handle to page with `detail`) or `cancel` one."
    )]
    async fn job(&self, Parameters(p): Parameters<JobParams>) -> CallToolResult {
        let action = match (p.action, p.id) {
            (JobVerb::List, None) => JobAction::List,
            (JobVerb::Poll, Some(id)) => JobAction::Poll(id),
            (JobVerb::Cancel, Some(id)) => JobAction::Cancel(id),
            (JobVerb::List, Some(_)) => return refused("list takes no id"),
            (_, None) => return refused("poll and cancel need id"),
        };
        self.blocking(move |root| decovery_facade::job_tool(root, action))
            .await
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Server {
    /// Routes the call and logs it (also a refused or failed one) before the answer goes out.
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let started = Instant::now();
        let mut record = call_record(&request.name, request.arguments.as_ref());
        let requested = record.clone();
        let (charged, denial) = self.admit(&record);
        let mut result = if let Some(reason) = denial {
            Ok(CallToolResponse::Complete(refused(reason)))
        } else {
            self.tool_router
                .call(ToolCallContext::new(self, request, context))
                .await
        };
        record.seconds = started.elapsed().as_secs_f64();
        record.outcome = match &mut result {
            Err(_) => "refused".into(),
            Ok(CallToolResponse::Complete(r)) => {
                let marked = r
                    .meta
                    .as_mut()
                    .is_some_and(|m| m.0.remove(REFUSED).is_some());
                if r.meta.as_ref().is_some_and(|m| m.0.is_empty()) {
                    r.meta = None;
                }
                // rmcp answers arguments that do not fit the tool's parameters as a tool error with this prefix
                let bad_arguments = r
                    .content
                    .first()
                    .and_then(|c| c.as_text())
                    .is_some_and(|t| t.text.starts_with(ARGUMENTS_REJECTED));
                match (marked || bad_arguments, r.is_error == Some(true)) {
                    (true, _) => "refused".into(),
                    (false, true) => "error".into(),
                    (false, false) => "ok".into(),
                }
            }
            Ok(_) => "ok".into(),
        };
        if record.outcome == "refused" {
            record.builds = 0;
            record.searches = 0;
        }
        if let Err(e) = append_call(&self.root, &record) {
            eprintln!("decovery mcp: the call was not logged: {e}");
        }
        if let Some(bench) = &self.bench {
            let mut state = bench.lock().unwrap_or_else(|p| p.into_inner());
            if charged && record.outcome == "refused" {
                state.usage.builds = state.usage.builds.saturating_sub(requested.builds);
                state.usage.searches = state.usage.searches.saturating_sub(requested.searches);
            }
            if let Err(e) = state.usage.save(&self.root) {
                eprintln!("decovery mcp: usage was not saved: {e}");
            }
        }
        result
    }

    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("decovery", env!("CARGO_PKG_VERSION")))
            .with_instructions(INSTRUCTIONS)
    }
}

impl Server {
    fn admit(&self, record: &CallRecord) -> (bool, Option<String>) {
        let Some(bench) = &self.bench else {
            return (false, None);
        };
        let mut state = bench.lock().unwrap_or_else(|p| p.into_inner());
        let denial = state.limits.refusal(&state.usage, record);
        let mut cost = record.clone();
        if denial.is_some() {
            cost.builds = 0;
            cost.searches = 0;
        }
        state.usage.record(&cost);
        if let Err(e) = state.usage.save(&self.root) {
            state.usage.builds = state.usage.builds.saturating_sub(cost.builds);
            state.usage.searches = state.usage.searches.saturating_sub(cost.searches);
            return (false, Some(format!("cannot persist bench usage: {e}")));
        }
        (denial.is_none(), denial)
    }
    /// Runs the long operation `op`: in the background (`background`, default per kind) it is queued on the job
    /// runner and the answer is the job at once; otherwise it runs as a registered job on the blocking pool and
    /// its progress goes out as MCP progress notifications when the client sent a progress token.
    async fn long(
        &self,
        meta: RequestMetaObject,
        peer: Peer<RoleServer>,
        op: JobOperation,
        background: Option<bool>,
    ) -> CallToolResult {
        if background.unwrap_or_else(|| background_by_default(op.kind())) {
            let Some(runner) = self.runner.clone() else {
                return CallToolResult::error(vec![ContentBlock::text(
                    "this server runs no background jobs",
                )]);
            };
            return tool_result(
                tokio::task::spawn_blocking(move || {
                    let kind = op.kind();
                    let job = runner.submit(kind, op.spec())?;
                    Ok(Response::new(
                        format!("job {} started ({kind})", job.id),
                        serde_json::json!({ "job": {
                            "id": job.id,
                            "kind": job.kind,
                            "state": job.state.id(),
                            "created": job.created,
                        }}),
                    ))
                })
                .await,
            );
        }
        let root = self.root.clone();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Progress>();
        let forward = meta.get_progress_token().map(|token| {
            tokio::spawn(async move {
                while let Some(p) = rx.recv().await {
                    let mut note = ProgressNotificationParam::new(token.clone(), p.done as f64);
                    if let Some(total) = p.total {
                        note = note.with_total(total as f64);
                    }
                    if let Some(message) = p.message.filter(|m| !m.trim().is_empty()) {
                        note = note.with_message(message);
                    }
                    // a client that went away does not stop the call
                    let _ = peer.notify_progress(note).await;
                }
            })
        });
        let result = tokio::task::spawn_blocking(move || {
            let progress = |p: Progress| {
                let _ = tx.send(p);
            };
            decovery_facade::run_as_job(&root, &op, &progress)
        })
        .await;
        if let Some(forward) = forward {
            let _ = forward.await;
        }
        tool_result(result)
    }

    /// Runs `op` on the blocking pool (facade calls do file I/O and may wait for the workspace lock).
    async fn blocking<F>(&self, op: F) -> CallToolResult
    where
        F: FnOnce(&Path) -> Result<Response, FacadeError> + Send + 'static,
    {
        let root = self.root.clone();
        tool_result(tokio::task::spawn_blocking(move || op(&root)).await)
    }
}

fn budget(chars: Option<usize>) -> Budget {
    Budget {
        chars: chars.unwrap_or(DEFAULT_BUDGET),
    }
}

/// A tool error for a call that was not run (bad parameters); the call log records it as `refused`.
fn refused(message: impl Into<String>) -> CallToolResult {
    let mut result = CallToolResult::error(vec![ContentBlock::text(message.into())]);
    let mut meta = MetaObject::new();
    meta.0.insert(REFUSED.into(), serde_json::Value::Bool(true));
    result.meta = Some(meta);
    result
}

/// The log record of a call to `tool` with `arguments`: its target, operation and how many builds and searches it
/// asks for (counted unless it is refused).
fn call_record(tool: &str, arguments: Option<&JsonObject>) -> CallRecord {
    let mut record = CallRecord::new(tool);
    record.actor = Some(decovery_facade::actor());
    let text = |key: &str| {
        arguments
            .and_then(|a| a.get(key))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    };
    record.target = text("target").or_else(|| text("function"));
    record.operation = text("deep")
        .or_else(|| text("strategy"))
        .or_else(|| text("check"));
    match tool {
        "build" => {
            let variants = arguments
                .and_then(|a| a.get("variants"))
                .and_then(serde_json::Value::as_array)
                .map_or(0, Vec::len);
            record.builds = decovery_core::calls::requested_builds(variants);
        }
        "search" => record.searches = 1,
        _ => {}
    }
    record
}

/// The envelope as pretty JSON text, or the facade message as a tool error.
fn tool_result(
    result: Result<Result<Response, FacadeError>, tokio::task::JoinError>,
) -> CallToolResult {
    let text = match result {
        Ok(Ok(response)) => serde_json::to_string_pretty(&response),
        Ok(Err(e)) => return CallToolResult::error(vec![ContentBlock::text(e.to_string())]),
        Err(e) => {
            return CallToolResult::error(vec![ContentBlock::text(format!("tool failed: {e}"))]);
        }
    };
    match text {
        Ok(text) => CallToolResult::success(vec![ContentBlock::text(text)]),
        Err(e) => CallToolResult::error(vec![ContentBlock::text(e.to_string())]),
    }
}

/// The facade request for `p`, or "exactly one action required".
fn annotation(p: AnnotateParams) -> Result<Annotation, String> {
    let mut actions = Vec::new();
    if let Some(v) = p.name {
        actions.push(AnnotateAction::Name(v));
    }
    if let Some(v) = p.comment {
        actions.push(AnnotateAction::Comment(v));
    }
    if let Some(v) = p.signature {
        actions.push(AnnotateAction::Signature(v));
    }
    if let Some(v) = p.data_type {
        actions.push(AnnotateAction::DataType(v));
    }
    if let Some(v) = p.local {
        actions.push(AnnotateAction::Local {
            place: v.place,
            name: v.name,
            data_type: v.data_type,
        });
    }
    if let Some(reason) = p.refute {
        actions.push(AnnotateAction::Refute { reason });
    }
    if let Some(v) = p.add_type {
        actions.push(AnnotateAction::AddType(v));
    }
    let Some(action) = actions.pop().filter(|_| actions.is_empty()) else {
        return Err("exactly one action required".into());
    };
    Ok(Annotation {
        target: p.target.unwrap_or_default(),
        action,
        confidence: match p.confidence.unwrap_or_default() {
            ClaimConfidence::Confirmed => Confidence::Confirmed,
            ClaimConfidence::Assumed => Confidence::Assumed,
        },
        source: ClaimSource::Agent,
        evidence: p.evidence,
        force: p.force.unwrap_or(false),
    })
}
