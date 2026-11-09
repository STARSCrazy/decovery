//! `decovery link` on both local targets against their private Decomp workspaces. Run with
//! `cargo test -p decovery-cli --test link_local -- --ignored --nocapture` and
//!
//! - first target (LE, Watcom): `DECOVERY_LOCAL_WORKSPACE=<Decomp workspace>`; optional
//!   `DECOVERY_TOOLCHAIN_WATCOM95=<Watcom 9.5 directory>` (else the user config's toolchain entry);
//! - second target (MZ, Turbo C): `DECOVERY_LOCAL_WORKSPACE_MZ=<Decomp workspace>`,
//!   `DECOVERY_TARGET_MZ=<the original program>`; optional `DECOVERY_TOOLCHAIN_TC20=<Turbo C 2.0 directory>`;
//! - optional `DECOVERY_GOLDEN_DIR=<private dir>` (the outcomes go to `parity-phase-2.md` there).
//!
//! The workspaces are migrated into temporary directories (the Decomp workspaces are never touched).
//!
//! First target: links with WLINK 9.5 (`[rebuild.link] profile = "watcom-9.5"`) after a full `decovery build`
//! (which keeps the objects the inserts come from, those of the assembler sources included), and checks that every inserted rebuild reproduces the original's
//! pages: no page and no fixup content may differ. WLINK 9.5 differs from the original's linker in the order of the
//! fixup records (and possibly object flags), so `differs` is accepted. When WLINK does not run at all, its message
//! goes to the parity document instead of failing.
//!
//! Second target: compiles and links all rebuild sources with TCC/TLINK; `REBUILD.EXE` must equal the original byte
//! for byte.

#[path = "support/local.rs"]
mod local;

use local::{
    decovery, edit_config, env_path, lines, migrate, record_parity, response, set_tool_dir, table,
};

#[test]
#[ignore = "local: first target + Watcom"]
fn first_target_le_link() {
    let from = env_path("DECOVERY_LOCAL_WORKSPACE");
    let to = tempfile::tempdir().unwrap();
    let ws = to.path().join("ws");
    migrate(&from, &ws);
    edit_config(&ws, |config| {
        set_tool_dir(config, "DECOVERY_TOOLCHAIN_WATCOM95");
        table(table(config, "rebuild"), "link")
            .insert("profile".into(), toml::Value::String("watcom-9.5".into()));
    });

    let (out, build_ms) = decovery(&["build", "--json"], &ws);
    assert!(
        out.status.code().is_some_and(|c| c <= 1),
        "build failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let (out, link_ms) = decovery(&["link", "--json"], &ws);
    let response = response(&out, "link");
    let d = &response["data"];
    let diagnosis = lines(&d["diagnosis"]);
    let hints = lines(&d["hints"]);
    println!(
        "build {build_ms} ms, link {link_ms} ms wall, timing {}",
        d["timing"]
    );
    println!("{}", response["summary"].as_str().unwrap_or(""));
    for line in &diagnosis {
        println!("  {line}");
    }
    let program = std::fs::read_to_string(ws.join("knowledge/rebuild-program.toml")).unwrap();
    let record: toml::Table = program.parse().unwrap();
    let used = &record["program"]["used"];
    let (functions, bytes) = (
        used["functions"].as_integer().unwrap_or(0),
        used["bytes"].as_integer().unwrap_or(0),
    );
    println!(
        "inserted {functions} functions, {bytes} bytes; {} hints",
        hints.len()
    );

    let result = d["result"].as_str().unwrap_or("");
    let mut body = format!(
        "WLINK 9.5 (`[rebuild.link] profile = \"watcom-9.5\"`): {result}; inserted {functions} functions, \
         {bytes} bytes; link {link_ms} ms wall, timing {}\n",
        d["timing"]
    );
    for line in &diagnosis {
        body.push_str(&format!("- {line}\n"));
    }
    record_parity("link: first target (LE)", &body);
    assert!(
        result == "differs" || result == "identical",
        "link result {result}: {}",
        d["message"].as_str().unwrap_or("")
    );
    assert!(functions > 0 && bytes > 0, "nothing inserted: {hints:?}");
    // every inserted rebuild reproduces the original: no page and no fixup content differs
    assert!(
        !diagnosis
            .iter()
            .any(|l| l.contains("pages differ") || l.starts_with("fixup page")),
        "{diagnosis:?}"
    );
    assert!(
        diagnosis
            .iter()
            .all(|l| !l.starts_with("fixups:")
                || l.starts_with("fixups: 0 pages with other content")),
        "{diagnosis:?}"
    );
}

#[test]
#[ignore = "local: second target + Turbo C"]
fn second_target_links_identically() {
    let from = env_path("DECOVERY_LOCAL_WORKSPACE_MZ");
    let original = env_path("DECOVERY_TARGET_MZ");
    let to = tempfile::tempdir().unwrap();
    let ws = to.path().join("ws");
    migrate(&from, &ws);
    edit_config(&ws, |config| {
        set_tool_dir(config, "DECOVERY_TOOLCHAIN_TC20");
        table(config, "target").insert(
            "file".into(),
            toml::Value::String(original.to_string_lossy().into_owned()),
        );
    });

    let (out, link_ms) = decovery(&["link", "--json"], &ws);
    let response = response(&out, "link");
    let d = &response["data"];
    let summary = response["summary"].as_str().unwrap_or("");
    let result = d["result"].as_str().unwrap_or("");
    println!("{summary}; link {link_ms} ms wall, timing {}", d["timing"]);
    let rebuilt = std::fs::read(ws.join("cache/rebuild/REBUILD.EXE")).unwrap_or_default();
    let program = std::fs::read(&original).unwrap();
    let hints = lines(&d["hints"]);
    let mut body = format!(
        "TCC 2.0 + TLINK: {result} ({summary}); REBUILD.EXE {} bytes, original {} bytes, byte-equal: {}; \
         link {link_ms} ms wall, timing {}; {} hints\n",
        rebuilt.len(),
        program.len(),
        rebuilt == program,
        d["timing"],
        hints.len()
    );
    for line in lines(&d["diagnosis"]) {
        body.push_str(&format!("- {line}\n"));
    }
    record_parity("link: second target (MZ)", &body);
    assert_eq!(
        result,
        "identical",
        "{summary}: {:?} {}",
        lines(&d["diagnosis"]),
        d["message"]
    );
    assert_eq!(out.status.code(), Some(0));
    assert!(rebuilt == program, "REBUILD.EXE differs from the original");
}
