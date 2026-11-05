//! MCP server of decovery: the six facade tools (`status`, `find`, `show`, `annotate`, `analyze`, `detail`)
//! over stdio.
//!
//! The server is a thin adapter. Every call re-opens the session from disk, so knowledge changed by another
//! writer between calls is seen. Results are the facade envelope as JSON text; facade errors become tool
//! results with `isError` and the facade message. stdout carries only MCP frames.

use std::path::{Path, PathBuf};

use decovery_core::{ClaimSource, Confidence};
use decovery_facade::{
    AnalyzeOptions, AnnotateAction, Annotation, Budget, DEFAULT_LIMIT, FacadeError, FindQuery,
    FindWhat, FunctionFilter, FunctionSort, Progress, Response, Session,
};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, ContentBlock, Implementation, ProgressNotificationParam, RequestMetaObject,
    ServerCapabilities, ServerConfig,
};
use rmcp::schemars::JsonSchema;
use rmcp::{Peer, RoleServer, ServerHandler, ServiceExt, tool, tool_handler, tool_router};
use serde::Deserialize;

const INSTRUCTIONS: &str = "Tools over one decovery workspace (a reverse-engineered executable). Rebuild \
verdicts are tool findings; names, types and comments are claims with a source and confidence.";

/// Serves the six tools for the workspace at `root` on stdin/stdout until the client disconnects.
pub fn serve_stdio(root: PathBuf) -> Result<(), FacadeError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| FacadeError::Invalid(format!("cannot start the MCP server: {e}")))?;
    runtime.block_on(async move {
        let service = Server::new(root)
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
    /// Case-insensitive text, `*` matches any run; for `xrefs` the target (name or address).
    pattern: Option<String>,
    /// Restrict the function list (all must hold); `functions` only.
    filter: Option<Vec<Filter>>,
    /// Order of the function list (default `address`); `functions` only.
    sort: Option<Sort>,
    /// Maximum number of rows (default 100); the rest is stored as a handle.
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
        description = "Search functions (filter, sort), names, strings, generated pseudo-C (`code`) or cross references (`xrefs`, pattern = target). Rows beyond the limit are stored as a handle."
    )]
    async fn find(&self, Parameters(p): Parameters<FindParams>) -> CallToolResult {
        let query = FindQuery {
            what: match p.what {
                What::Functions => FindWhat::Functions,
                What::Names => FindWhat::Names,
                What::Strings => FindWhat::Strings,
                What::Code => FindWhat::Code,
                What::Xrefs => FindWhat::Xrefs,
            },
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
                })
                .collect(),
            sort: match p.sort.unwrap_or(Sort::Address) {
                Sort::Address => FunctionSort::Address,
                Sort::Callers => FunctionSort::Callers,
                Sort::Size => FunctionSort::Size,
            },
            limit: p.limit.unwrap_or(DEFAULT_LIMIT),
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
            Err(message) => return CallToolResult::error(vec![ContentBlock::text(message)]),
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
                    // a client that went away does not stop the analysis
                    let _ = peer.notify_progress(note).await;
                }
            })
        });
        let result = tokio::task::spawn_blocking(move || {
            let progress = |p: Progress| {
                let _ = tx.send(p);
            };
            decovery_facade::analyze(&root, &options, &progress)
        })
        .await;
        if let Some(forward) = forward {
            let _ = forward.await;
        }
        tool_result(result)
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
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Server {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("decovery", env!("CARGO_PKG_VERSION")))
            .with_instructions(INSTRUCTIONS)
    }
}

impl Server {
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
