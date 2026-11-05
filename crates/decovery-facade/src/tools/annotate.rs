//! `annotate`: the one tool that writes knowledge (port of Decomp's write commands).

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use decovery_core::{
    Address, ClaimSource, Confidence, LineComment, LocalVariable, RefutedClaim, Symbol, SymbolKind,
    Workspace, WorkspaceLock,
};
use serde_json::json;

use crate::output::is_identifier;
use crate::resolve::{locate, segment_of};
use crate::session::default_name;
use crate::{Change, FacadeError, OutputReport, Response, Session, resolve, write_affected};

const LOCK_WAIT: Duration = Duration::from_secs(10);
const MAX_NAME: usize = 200;
const NO_ANALYSIS: &str = "no analysis; output not regenerated";
const C_KEYWORDS: &[&str] = &[
    "auto",
    "break",
    "case",
    "char",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extern",
    "float",
    "for",
    "goto",
    "if",
    "inline",
    "int",
    "long",
    "register",
    "restrict",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "struct",
    "switch",
    "typedef",
    "union",
    "unsigned",
    "void",
    "volatile",
    "while",
    "_Bool",
    "_Complex",
    "_Imaginary",
];

/// One knowledge change requested by a human or an agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Annotation {
    /// Name, address or `file:0x...`; ignored by `AddType`.
    pub target: String,
    pub action: AnnotateAction,
    pub confidence: Confidence,
    pub source: ClaimSource,
    pub evidence: Option<String>,
    /// Replace a stronger claim.
    pub force: bool,
}

/// What to record.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnnotateAction {
    Name(String),
    Comment(String),
    Signature(String),
    DataType(String),
    /// `place`: `param:1`, `stack:-0x10` or `reg:EAX`.
    Local {
        place: String,
        name: String,
        data_type: Option<String>,
    },
    Refute {
        reason: String,
    },
    /// Appended to `types.h`.
    AddType(String),
}

/// Records one claim in the workspace knowledge and regenerates the output it affects.
///
/// Takes the workspace lock for the whole operation. A claim weaker than the one it would replace
/// (`human` > `confirmed` > `assumed`) changes nothing and says why, unless `force` is set.
pub fn annotate(root: &Path, request: &Annotation) -> Result<Response, FacadeError> {
    check_request(request)?;
    let lock = Workspace::open(root)?.lock(LOCK_WAIT)?;
    let (mut session, analyzed) = match Session::open(root) {
        Ok(session) => (session, true),
        Err(FacadeError::NoAnalysis) => (Session::open_without_analysis(root)?, false),
        Err(e) => return Err(e),
    };
    let mut applied = apply(&mut session, request)?;
    let mut output = OutputReport::default();
    if applied.changed {
        match &applied.save {
            Save::Symbols => session.workspace.save_symbols(&lock)?,
            Save::Types(text) => session.workspace.save_types_h(text, &lock)?,
        }
        if analyzed {
            if let Some(change) = &applied.change {
                match regenerate(root, change, &lock) {
                    Ok(report) => output = report,
                    Err(e) => applied.warnings.push(format!(
                        "knowledge saved; output not regenerated: {e} (run `decovery analyze` or `decovery show`)"
                    )),
                }
            }
        } else {
            applied.warnings.push(NO_ANALYSIS.to_string());
        }
    }
    Ok(Response::new(
        applied.summary,
        json!({
            "changed": applied.changed,
            "target": applied.target,
            "action": applied.action,
            "warnings": applied.warnings,
            "output": { "written": output.written, "removed": output.removed },
        }),
    ))
}

/// Re-reads everything from disk, so the output shows exactly what was saved.
fn regenerate(
    root: &Path,
    change: &Change,
    lock: &WorkspaceLock,
) -> Result<OutputReport, FacadeError> {
    let session = Session::open(root)?;
    write_affected(&session, change, lock)
}

enum Save {
    Symbols,
    Types(String),
}

struct Applied {
    changed: bool,
    summary: String,
    target: String,
    action: &'static str,
    warnings: Vec<String>,
    change: Option<Change>,
    save: Save,
}

impl Applied {
    fn unchanged(target: impl ToString, action: &'static str, reason: String, warn: bool) -> Self {
        Applied {
            changed: false,
            summary: format!("no change: {reason}"),
            target: target.to_string(),
            action,
            warnings: if warn { vec![reason] } else { Vec::new() },
            change: None,
            save: Save::Symbols,
        }
    }

    fn changed(
        target: impl ToString,
        action: &'static str,
        summary: String,
        change: Change,
    ) -> Self {
        Applied {
            changed: true,
            summary,
            target: target.to_string(),
            action,
            warnings: Vec::new(),
            change: Some(change),
            save: Save::Symbols,
        }
    }
}

/// Checks that need neither the lock nor the workspace.
fn check_request(request: &Annotation) -> Result<(), FacadeError> {
    if request.source == ClaimSource::Other {
        return Err(FacadeError::Invalid("unknown claim source".into()));
    }
    if request.confidence == Confidence::Refuted {
        return Err(FacadeError::Invalid(
            "confidence must be confirmed or assumed; use a refute to withdraw a claim".into(),
        ));
    }
    match &request.action {
        AnnotateAction::Name(name) => check_name(name),
        AnnotateAction::Comment(text) => non_empty(text, "comment"),
        AnnotateAction::Signature(text) => check_signature(text).map(|_| ()),
        AnnotateAction::DataType(text) => check_type(text),
        AnnotateAction::Local {
            place,
            name,
            data_type,
        } => {
            if !valid_place(place) {
                return Err(FacadeError::Invalid(format!(
                    "invalid place {place:?} (stack:-0x10, param:1, reg:EAX)"
                )));
            }
            check_name(name)?;
            data_type.as_deref().map_or(Ok(()), check_type)
        }
        AnnotateAction::Refute { reason } => non_empty(reason, "refute reason"),
        AnnotateAction::AddType(text) => check_type_definition(text),
    }
}

fn non_empty(text: &str, what: &str) -> Result<(), FacadeError> {
    if text.trim().is_empty() {
        Err(FacadeError::Invalid(format!("empty {what}")))
    } else {
        Ok(())
    }
}

fn check_name(name: &str) -> Result<(), FacadeError> {
    if name.len() > MAX_NAME {
        return Err(FacadeError::Invalid(format!(
            "name is {} characters long; at most {MAX_NAME} are allowed",
            name.len()
        )));
    }
    if !is_identifier(name) {
        return Err(FacadeError::Invalid(format!(
            "'{name}' is not a valid C identifier (rule [A-Za-z_][A-Za-z0-9_]*; ASCII only)"
        )));
    }
    if C_KEYWORDS.contains(&name) {
        return Err(FacadeError::Invalid(format!(
            "'{name}' is a C keyword and cannot be a name"
        )));
    }
    Ok(())
}

/// Decomp's `^[^()]+\(.*\)\s*;?\s*$`; returns the prototype without the trailing `;`.
fn check_signature(text: &str) -> Result<String, FacadeError> {
    let sig = text.trim();
    let bad = || {
        FacadeError::Invalid(format!(
            "not a C prototype: {text:?} (example: int rate_item(Item *item))"
        ))
    };
    if sig.contains(['\n', '\r']) {
        return Err(bad());
    }
    let open = sig.find('(').ok_or_else(bad)?;
    if open == 0 || sig[..open].contains(')') {
        return Err(bad());
    }
    let sig = sig.trim_end_matches(|c: char| c.is_whitespace() || c == ';');
    if !sig.ends_with(')') || sig.len() <= open {
        return Err(bad());
    }
    Ok(sig.to_string())
}

fn check_type(text: &str) -> Result<(), FacadeError> {
    let t = text.trim();
    if t.is_empty() || t.contains(['\n', ';', '{', '}']) {
        return Err(FacadeError::Invalid(format!(
            "not a C type: {text:?} (a single type expression, for example unsigned short)"
        )));
    }
    Ok(())
}

fn check_type_definition(text: &str) -> Result<(), FacadeError> {
    non_empty(text, "type definition")?;
    let mut stack = Vec::new();
    for c in text.chars() {
        match c {
            '{' | '(' | '[' => stack.push(c),
            '}' | ')' | ']' => {
                let want = match c {
                    '}' => '{',
                    ')' => '(',
                    _ => '[',
                };
                if stack.pop() != Some(want) {
                    return Err(unbalanced());
                }
            }
            _ => {}
        }
    }
    if stack.is_empty() {
        Ok(())
    } else {
        Err(unbalanced())
    }
}

fn unbalanced() -> FacadeError {
    FacadeError::Invalid("type definition has unbalanced brackets".into())
}

/// `stack:[+-]?0x<hex>`, `param:<n>` (n >= 1) or `reg:<letters>`.
fn valid_place(place: &str) -> bool {
    let Some((kind, rest)) = place.split_once(':') else {
        return false;
    };
    match kind {
        "stack" => {
            let rest = rest.strip_prefix(['+', '-']).unwrap_or(rest);
            rest.strip_prefix("0x")
                .is_some_and(|h| !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit()))
        }
        "param" => {
            !rest.is_empty() && !rest.starts_with('0') && rest.bytes().all(|b| b.is_ascii_digit())
        }
        "reg" => !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_alphabetic()),
        _ => false,
    }
}

/// 3 for a human claim, else 2 confirmed, 1 assumed.
fn rank(source: ClaimSource, confidence: Confidence) -> u8 {
    if source == ClaimSource::Human {
        3
    } else if confidence == Confidence::Confirmed {
        2
    } else {
        1
    }
}

fn describe(source: ClaimSource, confidence: Confidence) -> String {
    format!("{}, {}", kebab(&source), kebab(&confidence))
}

fn kebab<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

struct Target {
    /// Where the claim is recorded.
    at: Address,
    /// Start of the analyzed function containing the target, if any.
    function: Option<Address>,
    kind: SymbolKind,
}

fn target_of(session: &Session, request: &Annotation) -> Result<Target, FacadeError> {
    let requested = locate(session, &request.target)?;
    let function = session
        .analysis
        .index()
        .function_containing(requested)
        .map(|f| f.start);
    let at = match (&request.action, function) {
        (AnnotateAction::Local { .. }, _) => resolve(session, &request.target)?.function,
        (AnnotateAction::Signature(_), Some(start)) => start,
        _ => requested,
    };
    let kind = match function {
        Some(start) if start == at => SymbolKind::Function,
        Some(_) => SymbolKind::Label,
        None if segment_of(session, at).is_some_and(|s| s.permissions.contains('x')) => {
            SymbolKind::Function
        }
        None => SymbolKind::Global,
    };
    Ok(Target { at, function, kind })
}

fn apply(session: &mut Session, request: &Annotation) -> Result<Applied, FacadeError> {
    if let AnnotateAction::AddType(definition) = &request.action {
        return add_type(session, definition);
    }
    let target = target_of(session, request)?;
    match &request.action {
        AnnotateAction::Name(name) => set_name(session, request, &target, name),
        AnnotateAction::Comment(text) => set_comment(session, request, &target, text),
        AnnotateAction::Signature(text) => {
            let sig = check_signature(text)?;
            set_claim_text(session, request, &target, Field::Signature, sig)
        }
        AnnotateAction::DataType(text) => set_claim_text(
            session,
            request,
            &target,
            Field::DataType,
            text.trim().into(),
        ),
        AnnotateAction::Local {
            place,
            name,
            data_type,
        } => set_local(session, request, &target, place, name, data_type.as_deref()),
        AnnotateAction::Refute { reason } => refute(session, request, &target, reason),
        _ => Err(FacadeError::Invalid("unsupported action".into())),
    }
}

/// The record for `at`: an active named one, else an active one, else any.
fn index_of(symbols: &[Symbol], at: Address) -> Option<usize> {
    symbols
        .iter()
        .enumerate()
        .filter(|(_, s)| s.address == at)
        .min_by_key(
            |(_, s)| match (s.confidence == Confidence::Refuted, s.name.is_empty()) {
                (false, false) => 0,
                (false, true) => 1,
                (true, _) => 2,
            },
        )
        .map(|(i, _)| i)
}

fn is_active(s: &Symbol) -> bool {
    s.confidence != Confidence::Refuted
}

/// The record to claim on at `at`: the existing active one, or a fresh one that keeps the history of a
/// refuted record. A new record always takes the request's source and confidence; with `restamp` an
/// existing unnamed record does too (Decomp: the claim goes with the name, an unnamed record has none).
/// Returns its index.
fn claim_slot(
    session: &mut Session,
    request: &Annotation,
    at: Address,
    kind: SymbolKind,
    restamp: bool,
) -> usize {
    let symbols = &mut session.workspace.symbols;
    match index_of(symbols, at) {
        Some(i) if is_active(&symbols[i]) => {
            // a restamp never lowers the record's stamp
            if restamp
                && symbols[i].name.is_empty()
                && rank(request.source, request.confidence)
                    >= rank(symbols[i].source, symbols[i].confidence)
            {
                symbols[i].source = request.source;
                symbols[i].confidence = request.confidence;
            }
            i
        }
        found => {
            let mut fresh = Symbol::new(at, kind, "");
            fresh.source = request.source;
            fresh.confidence = request.confidence;
            if let Some(i) = found {
                fresh.refuted = std::mem::take(&mut symbols[i].refuted);
                symbols[i] = fresh;
                i
            } else {
                symbols.push(fresh);
                symbols.len() - 1
            }
        }
    }
}

fn set_name(
    session: &mut Session,
    request: &Annotation,
    target: &Target,
    name: &str,
) -> Result<Applied, FacadeError> {
    let at = target.at;
    if let Some(other) = session
        .workspace
        .symbols
        .iter()
        .find(|s| is_active(s) && s.name == name && s.address != at)
    {
        return Err(FacadeError::Invalid(format!(
            "name '{name}' is already used at {}",
            other.address
        )));
    }
    let mine = rank(request.source, request.confidence);
    let old_display = session.name_of(at);
    let found = index_of(&session.workspace.symbols, at).filter(|&i| {
        let s = &session.workspace.symbols[i];
        is_active(s) && !s.name.is_empty()
    });
    if let Some(i) = found {
        let old = &session.workspace.symbols[i];
        let theirs = rank(old.source, old.confidence);
        if old.name == name {
            // same name: only a claim at least as strong may touch source, confidence and evidence
            let evidence = request.evidence.clone().or_else(|| old.evidence.clone());
            let differs = (old.source, old.confidence, &old.evidence)
                != (request.source, request.confidence, &evidence);
            if mine < theirs || !differs {
                return Ok(Applied::unchanged(
                    at,
                    "name",
                    format!("{at} is already named {name}"),
                    false,
                ));
            }
            let old = &mut session.workspace.symbols[i];
            old.source = request.source;
            old.confidence = request.confidence;
            old.evidence = evidence;
            return Ok(Applied::changed(
                at,
                "name",
                format!(
                    "named {at} {name} (claim now {})",
                    describe(request.source, request.confidence)
                ),
                Change::Symbol { at },
            ));
        }
        let outranked = mine < theirs;
        if outranked && !request.force {
            return Ok(Applied::unchanged(
                at,
                "name",
                format!(
                    "{at} keeps {} ({}), which outranks this claim ({}); use force to replace it",
                    old.name,
                    describe(old.source, old.confidence),
                    describe(request.source, request.confidence)
                ),
                true,
            ));
        }
        let keep_history =
            outranked || matches!(old.source, ClaimSource::Signature | ClaimSource::Similarity);
        let entry = keep_history.then(|| {
            let note = if outranked {
                format!("replaced by {name} (forced)")
            } else {
                format!("replaced by {name}")
            };
            history_entry(old, old.evidence.clone(), Some(note))
        });
        let old = &mut session.workspace.symbols[i];
        old.refuted.extend(entry);
        old.name = name.to_string();
        old.kind = target.kind;
        old.source = request.source;
        old.confidence = request.confidence;
        if request.evidence.is_some() {
            old.evidence = request.evidence.clone();
        }
    } else {
        let i = claim_slot(session, request, at, target.kind, false);
        let s = &mut session.workspace.symbols[i];
        s.name = name.to_string();
        s.kind = target.kind;
        s.source = request.source;
        s.confidence = request.confidence;
        if request.evidence.is_some() {
            s.evidence = request.evidence.clone();
        }
    }
    // R20: a first naming reports the old name as empty
    let old = if old_display.is_default {
        String::new()
    } else {
        old_display.name.clone()
    };
    Ok(Applied::changed(
        at,
        "name",
        format!("named {at} {name} (was {})", old_display.name),
        Change::Renamed { at, old },
    ))
}

fn set_comment(
    session: &mut Session,
    request: &Annotation,
    target: &Target,
    text: &str,
) -> Result<Applied, FacadeError> {
    let text = text.trim();
    let (owner, line_at) = match target.function {
        Some(start) if start != target.at => (start, Some(target.at)),
        _ => (target.at, None),
    };
    let kind = if line_at.is_some() {
        SymbolKind::Function
    } else {
        target.kind
    };
    let i = claim_slot(session, request, owner, kind, false);
    let symbols = &mut session.workspace.symbols;
    let s = &mut symbols[i];
    let changed = match line_at {
        Some(at) => {
            let new = LineComment::new(at, text, request.source);
            match s.line_comments.iter_mut().find(|c| c.address == at) {
                Some(c) if c.text == text => false,
                Some(c) => {
                    *c = new;
                    true
                }
                None => {
                    s.line_comments.push(new);
                    s.line_comments.sort_by_key(|c| c.address);
                    true
                }
            }
        }
        None => {
            let changed = s.comment.as_deref() != Some(text);
            s.comment = Some(text.to_string());
            changed
        }
    };
    let shown = line_at.unwrap_or(owner);
    if !changed {
        return Ok(Applied::unchanged(
            shown,
            "comment",
            format!("{shown} already has this comment"),
            false,
        ));
    }
    let what = if line_at.is_some() {
        "line comment"
    } else {
        "comment"
    };
    Ok(Applied::changed(
        shown,
        "comment",
        format!("set {what} at {shown}"),
        Change::Symbol { at: shown },
    ))
}

#[derive(Clone, Copy)]
enum Field {
    Signature,
    DataType,
}

impl Field {
    fn label(self) -> &'static str {
        match self {
            Field::Signature => "signature",
            Field::DataType => "type",
        }
    }

    fn get(self, s: &Symbol) -> Option<&String> {
        match self {
            Field::Signature => s.signature.as_ref(),
            Field::DataType => s.data_type.as_ref(),
        }
    }

    fn set(self, s: &mut Symbol, value: String) {
        match self {
            Field::Signature => s.signature = Some(value),
            Field::DataType => s.data_type = Some(value),
        }
    }
}

fn set_claim_text(
    session: &mut Session,
    request: &Annotation,
    target: &Target,
    field: Field,
    value: String,
) -> Result<Applied, FacadeError> {
    let at = target.at;
    let action = field.label();
    let mine = rank(request.source, request.confidence);
    if let Some(i) = index_of(&session.workspace.symbols, at)
        && is_active(&session.workspace.symbols[i])
    {
        let old = &session.workspace.symbols[i];
        match field.get(old) {
            Some(current) if *current == value => {
                return Ok(Applied::unchanged(
                    at,
                    action,
                    format!("{at} already has this {action}"),
                    false,
                ));
            }
            Some(current) if mine < rank(old.source, old.confidence) && !request.force => {
                return Ok(Applied::unchanged(
                    at,
                    action,
                    format!(
                        "{at} keeps its {action} {current} ({}), which outranks this claim ({}); use force to replace it",
                        describe(old.source, old.confidence),
                        describe(request.source, request.confidence)
                    ),
                    true,
                ));
            }
            _ => {}
        }
    }
    let i = claim_slot(session, request, at, target.kind, true);
    field.set(&mut session.workspace.symbols[i], value.clone());
    Ok(Applied::changed(
        at,
        action,
        format!("set {action} of {at}: {value}"),
        Change::Symbol { at },
    ))
}

fn set_local(
    session: &mut Session,
    request: &Annotation,
    target: &Target,
    place: &str,
    name: &str,
    data_type: Option<&str>,
) -> Result<Applied, FacadeError> {
    let at = target.at;
    let new = LocalVariable::new(place, name, data_type.map(|t| t.trim().to_string()));
    let i = claim_slot(session, request, at, SymbolKind::Function, true);
    let symbols = &mut session.workspace.symbols;
    let s = &mut symbols[i];
    if s.locals.contains(&new) {
        return Ok(Applied::unchanged(
            at,
            "local",
            format!("{at} already has this local"),
            false,
        ));
    }
    s.locals.retain(|l| l.place != place);
    s.locals.push(new);
    Ok(Applied::changed(
        at,
        "local",
        format!("named {place} of {at} {name}"),
        Change::Symbol { at },
    ))
}

fn refute(
    session: &mut Session,
    request: &Annotation,
    target: &Target,
    reason: &str,
) -> Result<Applied, FacadeError> {
    let at = target.at;
    let found = index_of(&session.workspace.symbols, at).filter(|&i| {
        let s = &session.workspace.symbols[i];
        is_active(s) && !s.name.is_empty()
    });
    let Some(i) = found else {
        return Err(FacadeError::Invalid(format!(
            "{at}: nothing to refute (no active named symbol)"
        )));
    };
    let old = &session.workspace.symbols[i];
    if rank(request.source, request.confidence) < rank(old.source, old.confidence) && !request.force
    {
        return Ok(Applied::unchanged(
            at,
            "refute",
            format!(
                "{at} keeps {} ({}), which outranks this refutation ({}); use force to refute it",
                old.name,
                describe(old.source, old.confidence),
                describe(request.source, request.confidence)
            ),
            true,
        ));
    }
    let name = old.name.clone();
    let entry = history_entry(old, Some(reason.trim().to_string()), None);
    let old = &mut session.workspace.symbols[i];
    old.refuted.push(entry);
    old.confidence = Confidence::Refuted;
    Ok(Applied::changed(
        at,
        "refute",
        format!(
            "refuted {name} at {at} (now {}): {}",
            default_name(at),
            reason.trim()
        ),
        Change::Renamed { at, old: name },
    ))
}

/// A history entry for the claim `old` holds now.
fn history_entry(old: &Symbol, evidence: Option<String>, note: Option<String>) -> RefutedClaim {
    let mut entry = RefutedClaim::new(old.name.clone());
    entry.source = Some(old.source);
    entry.confidence = Some(old.confidence);
    entry.evidence = evidence;
    entry.date = Some(today());
    entry.note = note;
    entry
}

fn add_type(session: &mut Session, definition: &str) -> Result<Applied, FacadeError> {
    let current = session.workspace.types_h()?;
    let definition = definition.trim();
    if current.contains(definition) {
        return Ok(Applied::unchanged(
            "types.h",
            "add-type",
            "types.h already contains this definition".into(),
            false,
        ));
    }
    let mut text = current.trim_end_matches('\n').to_string();
    if !text.is_empty() {
        text.push_str("\n\n");
    }
    text.push_str(definition);
    text.push('\n');
    Ok(Applied {
        changed: true,
        summary: "added a definition to types.h".into(),
        target: "types.h".into(),
        action: "add-type",
        warnings: Vec::new(),
        change: Some(Change::Types),
        save: Save::Types(text),
    })
}

/// Today's date (UTC) as `YYYY-MM-DD`.
fn today() -> String {
    let days = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() / 86_400) as i64;
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}
