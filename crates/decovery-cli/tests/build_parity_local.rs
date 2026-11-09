//! Phase-2 parity of `decovery build` against Decomp on the two local targets. Run with
//! `cargo test -p decovery-cli --test build_parity_local -- --ignored --nocapture` and
//!
//! - first target (LE, Watcom 9.5): `DECOVERY_LOCAL_WORKSPACE=<Decomp workspace>`; optional
//!   `DECOVERY_TOOLCHAIN_WATCOM95=<Watcom 9.5 directory>` (else the user config's toolchain entry);
//! - second target (MZ, Turbo C 2.0): `DECOVERY_LOCAL_WORKSPACE_MZ=<Decomp workspace>`,
//!   `DECOVERY_TARGET_MZ=<the original program>`; optional `DECOVERY_TOOLCHAIN_TC20=<Turbo C 2.0 directory>`;
//! - `DECOVERY_GOLDEN_DIR=<private dir>`: mismatches go to `parity-phase-2.md` there, and each must be listed in
//!   `phase-2-deviations.txt` there (one line per accepted blocker of a mismatch: the function's address as decovery writes it,
//!   e.g. `flat:00012340`, the blocker kind, e.g. `data-layout`, then the evidence that decovery's verdict is
//!   right; `#` starts a comment). A function with a verdict but no blocker is listed by the verdict, one that was
//!   not built as `not-built`. Entries that no longer mismatch are printed as stale warnings.
//!
//! The workspace is migrated into a temporary directory (the Decomp workspace is never touched) and built in full.
//! Every function Decomp records as identical must get `verdict = identical`. The byte-listing assembler sources are
//! built by the built-in assembler and compared like compiled ones; functions of sources the build still skips (an
//! assembler file outside its subset without an assembler) are counted, not compared. On the second target
//! `decovery link` runs first: an identical link records the addresses of the library publics (from the linker
//! map) that some functions reference and the migrated knowledge lacks.

#[path = "support/local.rs"]
mod local;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use serde_json::Value;

use local::{
    DECOMP_KEY_ADDRESS, DECOMP_KEY_FILE, DECOMP_KEY_RESULT, DECOMP_KNOWLEDGE_DIR,
    DECOMP_REBUILD_RECORDS_FILE, DECOMP_RECORD_TABLE, DECOMP_RESULT_IDENTICAL, decomp_commit,
    decovery, edit_config, env_path, lines, migrate, record_parity, response, set_tool_dir, table,
};

/// Decomp's address prefixes and decovery's.
const ADDRESS_PREFIXES: [(&str, &str); 2] = [("va:", "flat:"), ("rel:", "seg:")];

/// One function Decomp records as identical that decovery does not.
struct Mismatch {
    name: String,
    address: String,
    file: String,
    verdict: String,
    blockers: String,
    /// Blocker kinds (`not-built` when there is no record, the verdict when it has no blocker).
    kinds: Vec<String>,
    decomp: String,
}

/// decovery's form of a Decomp address (`va:X` → `flat:X`, `rel:S:O` → `seg:S:O`).
fn address(decomp: &str) -> String {
    for (theirs, ours) in ADDRESS_PREFIXES {
        if let Some(rest) = decomp.strip_prefix(theirs) {
            return format!("{ours}{}", rest.to_uppercase());
        }
    }
    decomp.to_string()
}

/// All built functions of a `build --json` response, paging the `build-functions` handle when the list was cut.
fn built_functions(response: &Value, ws: &Path) -> Vec<Value> {
    let Some(handle) = response["handles"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|h| h["kind"] == "build-functions")
        .and_then(|h| h["id"].as_str())
    else {
        return response["data"]["functions"]
            .as_array()
            .cloned()
            .unwrap_or_default();
    };
    let mut text = String::new();
    loop {
        let offset = text.chars().count().to_string();
        let (out, _) = decovery(&["detail", handle, "--json", "--offset", &offset], ws);
        let page = local::response(&out, "detail");
        let chunk = page["data"]["text"].as_str().unwrap_or("");
        text.push_str(chunk);
        let total = page["data"]["total"].as_u64().unwrap_or(0) as usize;
        if chunk.is_empty() || text.chars().count() >= total {
            break;
        }
    }
    text.lines()
        .map(|l| serde_json::from_str(l).expect("a function per line"))
        .collect()
}

/// The blocker kinds of a record; `not-built` without a record, the verdict when it names no blocker.
fn kinds(f: Option<&Value>, verdict: &str) -> Vec<String> {
    let Some(f) = f else {
        return vec!["not-built".to_string()];
    };
    let kinds: Vec<String> = f["blockers"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|b| b["kind"].as_str().unwrap_or("?").to_string())
        .collect();
    if kinds.is_empty() {
        vec![verdict.to_string()]
    } else {
        kinds
    }
}

/// `kind` or `kind@0x…` per blocker.
fn blockers(f: &Value) -> String {
    f["blockers"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|b| {
            let kind = b["kind"].as_str().unwrap_or("?");
            match (b["at"].as_u64(), b["count"].as_u64()) {
                (Some(at), _) => format!("{kind}@+{at:#x}"),
                (None, Some(n)) => format!("{kind} x{n}"),
                _ => kind.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// `(address, blocker kind)` pairs listed in `$DECOVERY_GOLDEN_DIR/phase-2-deviations.txt`
/// (`<address> <blocker kind> <evidence>` per line).
fn listed_deviations() -> BTreeSet<(String, String)> {
    let Some(dir) = std::env::var_os("DECOVERY_GOLDEN_DIR") else {
        return BTreeSet::new();
    };
    std::fs::read_to_string(Path::new(&dir).join("phase-2-deviations.txt"))
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let mut words = l.split_whitespace();
            Some((words.next()?.to_string(), words.next()?.to_string()))
        })
        .collect()
}

/// A mismatch is accepted when every one of its blocker kinds is listed for its address.
fn is_listed(listed: &BTreeSet<(String, String)>, m: &Mismatch) -> bool {
    !m.kinds.is_empty()
        && m.kinds
            .iter()
            .all(|k| listed.contains(&(m.address.clone(), k.clone())))
}

struct Target<'a> {
    title: &'a str,
    workspace_var: &'a str,
    tool_var: &'a str,
    /// `$DECOVERY_TARGET_MZ` for the MZ target (its migrated `target.file` names the owner's path).
    target_var: Option<&'a str>,
    link_first: bool,
}

fn parity(t: &Target) {
    let from = env_path(t.workspace_var);
    let to = tempfile::tempdir().unwrap();
    let ws = to.path().join("ws");
    migrate(&from, &ws);
    edit_config(&ws, |config| {
        set_tool_dir(config, t.tool_var);
        if let Some(var) = t.target_var {
            table(config, "target").insert(
                "file".into(),
                toml::Value::String(env_path(var).to_string_lossy().into_owned()),
            );
        }
    });

    let mut body = format!("Decomp commit: {}\n", decomp_commit(&from));
    if t.link_first {
        let (out, link_ms) = decovery(&["link", "--json"], &ws);
        let link = response(&out, "link");
        let summary = link["summary"].as_str().unwrap_or("");
        writeln!(
            body,
            "link before build: {summary}; {link_ms} ms wall; hints: {:?}",
            lines(&link["data"]["hints"])
        )
        .unwrap();
        assert_eq!(
            link["data"]["result"], "identical",
            "the link that supplies library addresses failed: {summary}"
        );
    }

    let (out, build_ms) = decovery(&["build", "--json"], &ws);
    assert!(
        out.status.code().is_some_and(|c| c <= 1),
        "build failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let build = response(&out, "build");
    let summary = build["summary"].as_str().unwrap_or("").to_string();
    println!("{summary}");
    println!(
        "build {build_ms} ms wall, timing {}",
        build["data"]["timing"]
    );
    writeln!(
        body,
        "build: {summary}\nbuild {build_ms} ms wall, timing {}",
        build["data"]["timing"]
    )
    .unwrap();
    let skipped: BTreeSet<String> = build["data"]["files"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|f| f["status"] == "skipped")
        .filter_map(|f| f["file"].as_str().map(str::to_string))
        .collect();
    let ours: BTreeMap<String, Value> = built_functions(&build, &ws)
        .into_iter()
        .filter_map(|f| Some((f["address"].as_str()?.to_string(), f)))
        .collect();

    let recorded: toml::Table = std::fs::read_to_string(
        from.join(DECOMP_KNOWLEDGE_DIR)
            .join(DECOMP_REBUILD_RECORDS_FILE),
    )
    .unwrap()
    .parse()
    .unwrap();
    let (mut identical, mut agree, mut not_built) = (0usize, 0usize, 0usize);
    let mut mismatches = Vec::new();
    let mut compared: BTreeSet<String> = BTreeSet::new();
    for e in recorded[DECOMP_RECORD_TABLE].as_array().unwrap() {
        let e = e.as_table().unwrap();
        let text = |key: &str| {
            e.get(key)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };
        if text(DECOMP_KEY_RESULT) != DECOMP_RESULT_IDENTICAL {
            continue;
        }
        identical += 1;
        if skipped.contains(&text(DECOMP_KEY_FILE)) {
            not_built += 1;
            continue;
        }
        let address = address(&text(DECOMP_KEY_ADDRESS));
        compared.insert(address.clone());
        let ours = ours.get(&address);
        let verdict = ours
            .and_then(|f| f["verdict"].as_str())
            .unwrap_or("not built");
        if verdict == "identical" {
            agree += 1;
            continue;
        }
        mismatches.push(Mismatch {
            name: text("name"),
            address,
            file: text(DECOMP_KEY_FILE),
            verdict: verdict.to_string(),
            blockers: ours.map(blockers).unwrap_or_default(),
            kinds: kinds(ours, verdict),
            decomp: format!(
                "{} ({} bytes, {} equal, refs ok {}, refs wrong {})",
                text(DECOMP_KEY_RESULT),
                e.get("bytes").and_then(|v| v.as_integer()).unwrap_or(0),
                e.get("gleich").and_then(|v| v.as_integer()).unwrap_or(0),
                e.get("verweise_passend")
                    .and_then(|v| v.as_integer())
                    .unwrap_or(0),
                e.get("verweise_falsch")
                    .and_then(|v| v.as_integer())
                    .unwrap_or(0),
            ),
        });
    }

    let listed = listed_deviations();
    writeln!(
        body,
        "Decomp identical: {identical}; decovery identical too: {agree}; in skipped sources (not built): \
         {not_built}; mismatches: {}",
        mismatches.len()
    )
    .unwrap();
    if !mismatches.is_empty() {
        body.push_str(
            "\n| function | address | file | decovery | blockers | Decomp | listed |\n|---|---|---|---|---|---|---|\n",
        );
    }
    for m in &mismatches {
        writeln!(
            body,
            "| {} | {} | {} | {} | {} | {} | {} |",
            m.name,
            m.address,
            m.file,
            m.verdict,
            m.blockers,
            m.decomp,
            if is_listed(&listed, m) { "yes" } else { "no" }
        )
        .unwrap();
    }
    println!("{body}");
    record_parity(t.title, &body);

    let unlisted: Vec<String> = mismatches
        .iter()
        .filter(|m| !is_listed(&listed, m))
        .map(|m| format!("{} {} {}: {}", m.address, m.name, m.verdict, m.blockers))
        .collect();
    // listed entries of this target that no longer mismatch: a warning, not a failure
    for (address, kind) in &listed {
        if compared.contains(address)
            && !mismatches
                .iter()
                .any(|m| &m.address == address && m.kinds.contains(kind))
        {
            eprintln!(
                "warning: stale entry in phase-2-deviations.txt (no longer mismatches): {address} {kind}"
            );
        }
    }
    assert!(
        unlisted.is_empty(),
        "not in phase-2-deviations.txt: {unlisted:#?}"
    );
    assert!(agree > 0, "no function compared");
}

#[test]
#[ignore = "local: first target + Watcom 9.5"]
fn first_target_identical_functions() {
    parity(&Target {
        title: "build: first target (LE)",
        workspace_var: "DECOVERY_LOCAL_WORKSPACE",
        tool_var: "DECOVERY_TOOLCHAIN_WATCOM95",
        target_var: None,
        link_first: false,
    });
}

#[test]
#[ignore = "local: second target + Turbo C"]
fn second_target_identical_functions() {
    parity(&Target {
        title: "build: second target (MZ)",
        workspace_var: "DECOVERY_LOCAL_WORKSPACE_MZ",
        tool_var: "DECOVERY_TOOLCHAIN_TC20",
        target_var: Some("DECOVERY_TARGET_MZ"),
        link_first: true,
    });
}
