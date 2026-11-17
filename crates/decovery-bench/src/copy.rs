//! Construct an isolated task workspace. Only the start point is written, never the hidden definition.
use super::{BenchError, StartPoint, SuiteTask, ToolSet, io};
use decovery_core::{Address, Analysis, address_key};
use decovery_toolchain::{definitions, from_cp437};
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

#[derive(Debug)]
#[non_exhaustive]
pub struct TaskCopy {
    pub root: PathBuf,
    pub address: Address,
    pub name: String,
    pub file: String,
    pub profile: String,
    /// Evaluation only: never serialize this into a task directory.
    pub solution: String,
    pub legacy_view: Option<PathBuf>,
    pub warnings: Vec<String>,
}

pub fn copies_dir() -> PathBuf {
    #[cfg(windows)]
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    #[cfg(not(windows))]
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(std::env::temp_dir);
    base.join("decovery/bench")
}

pub(crate) fn copy_error(task: &SuiteTask, reason: impl Into<String>) -> BenchError {
    BenchError::Copy {
        task: task.id.clone(),
        reason: reason.into(),
    }
}

/// Resolve existing ancestors without creating anything, and reject inherited agent instructions/repositories.
fn destination(task: &SuiteTask, into: &Path) -> Result<PathBuf, BenchError> {
    let absolute = std::path::absolute(into).map_err(|e| io(into, e))?;
    if absolute
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(copy_error(task, "destination must not contain .."));
    }
    for ancestor in absolute.ancestors() {
        clean_ancestor(task, ancestor)?;
    }
    let mut anchor = absolute.clone();
    let mut suffix = Vec::new();
    while !anchor.exists() {
        suffix.push(
            anchor
                .file_name()
                .ok_or_else(|| copy_error(task, "invalid destination"))?
                .to_os_string(),
        );
        if !anchor.pop() {
            return Err(copy_error(task, "invalid destination"));
        }
    }
    let mut resolved = super::canonical(&anchor)?;
    for ancestor in resolved.ancestors() {
        clean_ancestor(task, ancestor)?;
    }
    for segment in suffix.into_iter().rev() {
        resolved.push(segment);
    }
    Ok(resolved)
}

fn clean_ancestor(task: &SuiteTask, path: &Path) -> Result<(), BenchError> {
    if path.join("CLAUDE.md").exists() {
        return Err(copy_error(
            task,
            format!("destination inherits {}", path.join("CLAUDE.md").display()),
        ));
    }
    if path.join(".git").exists() {
        return Err(copy_error(
            task,
            format!("destination is inside a repository: {}", path.display()),
        ));
    }
    Ok(())
}

pub fn prepare_copy(
    task: &SuiteTask,
    start: StartPoint,
    tools: ToolSet,
    into: &Path,
) -> Result<TaskCopy, BenchError> {
    let selected = super::suite::selected(task)?;
    let root = destination(task, into)?;
    if root.starts_with(&selected.workspace.root) {
        return Err(copy_error(
            task,
            "destination must be outside the source workspace",
        ));
    }
    if root.exists() {
        return Err(copy_error(
            task,
            format!("destination already exists: {}", root.display()),
        ));
    }
    let parent = root
        .parent()
        .ok_or_else(|| copy_error(task, "destination has no parent"))?;
    let view = parent.join("legacy-view");
    if tools == ToolSet::CoreLegacy && view.exists() {
        return Err(copy_error(
            task,
            "task legacy-view already exists; use a separate task directory",
        ));
    }
    let legacy_source = if tools == ToolSet::CoreLegacy {
        let configured = selected
            .workspace
            .config
            .legacy
            .as_ref()
            .and_then(|l| l.decomp_workspace.as_ref())
            .ok_or_else(|| copy_error(task, "core-legacy needs [legacy] decomp_workspace"))?;
        let source = super::canonical(&selected.workspace.root.join(configured))?;
        if root.starts_with(&source) || view.starts_with(&source) {
            return Err(copy_error(
                task,
                "task directories must be outside the original Decomp workspace",
            ));
        }
        Some(source)
    } else {
        None
    };
    let definition = definitions(&selected.text)
        .into_iter()
        .find(|d| d.name == selected.record.name)
        .ok_or_else(|| copy_error(task, "source definition disappeared"))?;
    let solution = selected.text[definition.start..definition.end].to_string();
    let mut warnings = Vec::new();
    let pseudo = if start == StartPoint::PseudoC {
        Analysis::decompiled(&selected.workspace.root, selected.record.address)?
    } else {
        None
    };
    let pseudo_body = pseudo.as_deref().and_then(|text| {
        let spans = definitions(text);
        match spans.as_slice() {
            [one] => Some(text[one.brace..one.end].to_string()),
            _ => None,
        }
    });
    if start == StartPoint::PseudoC && pseudo_body.is_none() {
        warnings.push("no usable decompiled definition; starting from a stub".into());
    }
    let body = pseudo_body.as_deref().unwrap_or("{\n}\n");
    let start_definition = format!(
        "{}{body}",
        &selected.text[definition.start..definition.brace]
    );
    let object = original_object(&selected.workspace.root, &selected.file)?;
    let secrets = Secrets {
        definition: solution.clone(),
        code_hash: selected.record.code_hash.clone().filter(|h| !h.is_empty()),
        object,
    };
    let module = format!(
        "{}{}{}",
        secrets.redact(&selected.text[..definition.start]),
        start_definition,
        secrets.redact(&selected.text[definition.end..])
    );
    let profile = selected
        .record
        .compiler
        .clone()
        .or_else(|| {
            selected
                .workspace
                .config
                .rebuild
                .as_ref()
                .and_then(|r| r.compiler.clone())
        })
        .ok_or_else(|| copy_error(task, "no compiler profile recorded or configured"))?;
    std::fs::create_dir_all(parent).map_err(|e| io(parent, e))?;
    std::fs::create_dir(&root).map_err(|e| io(&root, e))?;
    let result = (|| {
        let source = &selected.workspace.root;
        copy_tree(
            &source.join("knowledge"),
            &root.join("knowledge"),
            &secrets,
            &|relative| relative != Path::new("rebuild.toml"),
        )?;
        let mut rebuild = read_toml(&source.join("knowledge/rebuild.toml"))?;
        remove_record(
            &mut rebuild,
            "function",
            "address",
            &selected.record.address.to_string(),
        );
        secrets.sanitize_toml(&mut rebuild);
        write_toml(&root.join("knowledge/rebuild.toml"), &rebuild)?;
        let own_relative = selected
            .path
            .strip_prefix(source.join("src"))
            .map_err(|_| copy_error(task, "source is outside src/"))?;
        copy_tree(
            &source.join("src"),
            &root.join("src"),
            &secrets,
            &|relative| relative != own_relative,
        )?;
        write(&root.join("src").join(own_relative), module.as_bytes())?;
        let own_stem = stem(&selected.file);
        copy_tree(
            &source.join("cache/rebuild/obj"),
            &root.join("cache/rebuild/obj"),
            &secrets,
            &|relative| stem(&relative.to_string_lossy()) != own_stem,
        )?;
        let shard = format!("{}.jsonl", address_key(selected.record.address));
        copy_tree(
            &source.join("cache/attempts"),
            &root.join("cache/attempts"),
            &secrets,
            &|relative| {
                relative
                    .file_name()
                    .is_some_and(|name| name != std::ffi::OsStr::new(&shard) && name != ".lock")
            },
        )?;
        // No archive entries: a sibling entry may hold the entire module or migrated input files.
        let mut config = read_toml(&source.join("decovery.toml"))?;
        if let Some(file) = config.get_mut("target").and_then(|t| t.get_mut("file")) {
            absolutize(file, source);
        }
        if let Some(dir) = config
            .get_mut("rebuild")
            .and_then(|r| r.get_mut("tool_dir"))
        {
            absolutize(dir, source);
        }
        let legacy_view = if tools == ToolSet::CoreLegacy {
            let legacy = legacy_source
                .as_ref()
                .ok_or_else(|| copy_error(task, "legacy source is missing"))?;
            super::legacy_view::prepare(task, legacy, &view, selected.record.address, &secrets)?;
            config["legacy"]["decomp_workspace"] =
                toml::Value::String(view.to_string_lossy().into_owned());
            Some(view.clone())
        } else {
            if let Some(table) = config.as_table_mut() {
                table.remove("legacy");
            }
            None
        };
        secrets.sanitize_toml(&mut config);
        write_toml(&root.join("decovery.toml"), &config)?;
        // A generated stub/pseudo-C may itself equal a trivial known solution. Only its generated span is exempt.
        scan(
            task,
            &root,
            &secrets,
            Some(&root.join("src").join(own_relative)),
            true,
        )?;
        if let Some(view) = &legacy_view {
            scan(task, view, &secrets, None, false)?;
        }
        Ok(TaskCopy {
            root: root.clone(),
            address: selected.record.address,
            name: selected.record.name.clone(),
            file: selected.file.clone(),
            profile,
            solution,
            legacy_view,
            warnings,
        })
    })();
    if result.is_err() {
        // Both paths were absent before this call and were resolved outside the source workspace.
        let _ = std::fs::remove_dir_all(&root);
        if tools == ToolSet::CoreLegacy && view.exists() {
            let _ = std::fs::remove_dir_all(&view);
        }
    }
    result
}

fn stem(file: &str) -> String {
    Path::new(file)
        .with_extension("")
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase()
}

fn original_object(root: &Path, file: &str) -> Result<Option<Vec<u8>>, BenchError> {
    let mut found = Vec::new();
    let base = root.join("cache/rebuild/obj");
    visit(
        &base,
        Path::new(""),
        &mut BTreeSet::new(),
        &mut |path, relative| {
            if path
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("obj"))
                && stem(&relative.to_string_lossy()) == stem(file)
            {
                found.push(std::fs::read(path).map_err(|e| io(path, e))?);
            }
            Ok(())
        },
    )?;
    if found.len() > 1 {
        return Err(BenchError::Io {
            path: base,
            source: std::io::Error::other("ambiguous kept objects for source file"),
        });
    }
    Ok(found.pop().filter(|o| !o.is_empty()))
}

pub(crate) fn write(path: &Path, bytes: &[u8]) -> Result<(), BenchError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| io(parent, e))?;
    }
    decovery_core::write_atomic(path, bytes).map_err(|e| io(path, e))
}
pub(crate) fn read_toml(path: &Path) -> Result<toml::Value, BenchError> {
    let text = std::fs::read_to_string(path).map_err(|e| io(path, e))?;
    toml::from_str(&text).map_err(|e| BenchError::Suite {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })
}
pub(crate) fn write_toml(path: &Path, value: &toml::Value) -> Result<(), BenchError> {
    let text = toml::to_string(value).map_err(|e| BenchError::Suite {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })?;
    write(path, text.as_bytes())
}
pub(crate) fn absolutize(value: &mut toml::Value, root: &Path) {
    if let Some(path) = value.as_str() {
        *value = toml::Value::String(root.join(path).to_string_lossy().into_owned());
    }
}
pub(crate) fn remove_record(value: &mut toml::Value, table: &str, field: &str, address: &str) {
    if let Some(records) = value.get_mut(table).and_then(toml::Value::as_array_mut) {
        records.retain(|r| {
            let actual = r.get(field).and_then(toml::Value::as_str);
            actual != Some(address)
                && !actual.is_some_and(|actual| {
                    super::legacy_view::parse_address(actual)
                        .is_some_and(|a| Some(a) == super::legacy_view::parse_address(address))
                })
        });
    }
}

/// Walk regular files without following links. A linked knowledge/source directory would defeat sanitization.
pub(crate) fn visit(
    root: &Path,
    prefix: &Path,
    seen: &mut BTreeSet<PathBuf>,
    callback: &mut impl FnMut(&Path, &Path) -> Result<(), BenchError>,
) -> Result<(), BenchError> {
    let metadata = match std::fs::symlink_metadata(root) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(io(root, e)),
    };
    if metadata.file_type().is_symlink() || std::fs::read_link(root).is_ok() {
        return Err(io(
            root,
            std::io::Error::other("links are not allowed in copied trees"),
        ));
    }
    if !metadata.is_dir() {
        return callback(root, prefix);
    }
    let canonical = root.canonicalize().map_err(|e| io(root, e))?;
    if !seen.insert(canonical.clone()) || seen.len() > 128 {
        return Err(io(
            root,
            std::io::Error::other("directory cycle or nesting exceeds 128"),
        ));
    }
    let mut entries = std::fs::read_dir(root)
        .map_err(|e| io(root, e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| io(root, e))?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        visit(
            &entry.path(),
            &prefix.join(entry.file_name()),
            seen,
            callback,
        )?;
    }
    seen.remove(&canonical);
    Ok(())
}

pub(crate) fn copy_tree(
    source: &Path,
    destination: &Path,
    secrets: &Secrets,
    keep: &impl Fn(&Path) -> bool,
) -> Result<(), BenchError> {
    visit(
        source,
        Path::new(""),
        &mut BTreeSet::new(),
        &mut |path, relative| {
            if !keep(relative) {
                return Ok(());
            }
            let bytes = std::fs::read(path).map_err(|e| io(path, e))?;
            let bytes = secrets.sanitize_file(path, &bytes)?;
            write(&destination.join(relative), &bytes)
        },
    )
}

pub(crate) struct Secrets {
    pub definition: String,
    pub code_hash: Option<String>,
    pub object: Option<Vec<u8>>,
}

fn normalized(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

impl Secrets {
    fn scan_reader(
        &self,
        reader: &mut impl std::io::Read,
        include_definition: bool,
        include_bytes: bool,
    ) -> std::io::Result<Option<&'static str>> {
        let definition: Vec<_> = if include_definition {
            self.definition
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect()
        } else {
            Vec::new()
        };
        let mut utf8 = Matcher::new(definition.clone());
        let mut cp437 = Matcher::new(definition);
        let mut hash = Matcher::new(if include_bytes {
            self.code_hash.as_deref().unwrap_or("").as_bytes().to_vec()
        } else {
            Vec::new()
        });
        let mut object = Matcher::new(if include_bytes {
            self.object.clone().unwrap_or_default()
        } else {
            Vec::new()
        });
        let cp437_table: Vec<_> = from_cp437(&(0..=255).collect::<Vec<u8>>())
            .chars()
            .collect();
        let mut buffer = [0; 65_536];
        let mut pending = Vec::new();
        loop {
            let size = reader.read(&mut buffer)?;
            if size == 0 {
                break;
            }
            for byte in &buffer[..size] {
                if hash.feed(*byte) || object.feed(*byte) {
                    return Ok(Some("object or code hash"));
                }
                if include_definition {
                    let c = cp437_table[usize::from(*byte)];
                    if !c.is_whitespace() && cp437.feed(c) {
                        return Ok(Some("definition"));
                    }
                }
            }
            if !include_definition {
                continue;
            }
            pending.extend_from_slice(&buffer[..size]);
            let mut consumed = 0;
            while consumed < pending.len() {
                let (valid, invalid) = match std::str::from_utf8(&pending[consumed..]) {
                    Ok(_) => (pending.len() - consumed, None),
                    Err(error) => (error.valid_up_to(), Some(error.error_len())),
                };
                if let Ok(text) = std::str::from_utf8(&pending[consumed..consumed + valid]) {
                    for c in text.chars().filter(|c| !c.is_whitespace()) {
                        if utf8.feed(c) {
                            return Ok(Some("definition"));
                        }
                    }
                }
                consumed += valid;
                match invalid {
                    None => break,
                    Some(None) => break, // Up to three bytes of an incomplete UTF-8 character.
                    Some(Some(size)) => {
                        if utf8.feed('\u{FFFD}') {
                            return Ok(Some("definition"));
                        }
                        consumed += size;
                    }
                }
            }
            pending.drain(..consumed);
        }
        Ok(None)
    }
    pub(crate) fn redact(&self, text: &str) -> String {
        let needle = normalized(&self.definition);
        let mut compact = String::new();
        let mut positions = Vec::new();
        for (index, c) in text.char_indices().filter(|(_, c)| !c.is_whitespace()) {
            compact.push(c);
            positions.extend(std::iter::repeat_n(
                (index, index + c.len_utf8()),
                c.len_utf8(),
            ));
        }
        let mut output = String::new();
        let mut written = 0;
        let mut offset = 0;
        if !needle.is_empty() {
            while let Some(at) = compact[offset..].find(&needle) {
                let start = offset + at;
                let end = start + needle.len();
                output.push_str(&text[written..positions[start].0]);
                written = positions[end - 1].1;
                offset = end;
            }
        }
        output.push_str(&text[written..]);
        if let Some(hash) = &self.code_hash {
            output = output.replace(hash, "");
        }
        output
    }

    pub(crate) fn sanitize_toml(&self, value: &mut toml::Value) {
        match value {
            toml::Value::String(s) => *s = self.redact(s),
            toml::Value::Array(a) => {
                for v in a {
                    self.sanitize_toml(v);
                }
            }
            toml::Value::Table(t) => {
                for (_, v) in t.iter_mut() {
                    self.sanitize_toml(v);
                }
            }
            _ => {}
        }
    }
    fn sanitize_json(&self, value: &mut serde_json::Value) {
        match value {
            serde_json::Value::String(s) => *s = self.redact(s),
            serde_json::Value::Array(a) => {
                for v in a {
                    self.sanitize_json(v);
                }
            }
            serde_json::Value::Object(t) => {
                for v in t.values_mut() {
                    self.sanitize_json(v);
                }
            }
            _ => {}
        }
    }
    fn sanitize_file(&self, path: &Path, bytes: &[u8]) -> Result<Vec<u8>, BenchError> {
        let extension = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !matches!(
            extension.as_str(),
            "c" | "h" | "s" | "asm" | "inc" | "toml" | "json" | "jsonl" | "md" | "txt"
        ) {
            return Ok(bytes.to_vec());
        }
        let text = String::from_utf8(bytes.to_vec()).unwrap_or_else(|_| from_cp437(bytes));
        if extension == "toml" {
            let mut value: toml::Value = toml::from_str(&text).map_err(|e| BenchError::Suite {
                path: path.to_path_buf(),
                reason: e.to_string(),
            })?;
            self.sanitize_toml(&mut value);
            return toml::to_string(&value)
                .map(String::into_bytes)
                .map_err(|e| BenchError::Suite {
                    path: path.to_path_buf(),
                    reason: e.to_string(),
                });
        }
        if extension == "json" || extension == "jsonl" {
            let mut lines = Vec::new();
            let entries: Vec<&str> = if extension == "json" {
                vec![text.as_str()]
            } else {
                text.lines().filter(|l| !l.trim().is_empty()).collect()
            };
            for entry in entries {
                let mut value = serde_json::from_str(entry).map_err(|e| BenchError::Suite {
                    path: path.to_path_buf(),
                    reason: e.to_string(),
                })?;
                self.sanitize_json(&mut value);
                lines.push(
                    serde_json::to_string(&value).map_err(|e| BenchError::Suite {
                        path: path.to_path_buf(),
                        reason: e.to_string(),
                    })?,
                );
            }
            return Ok((lines.join("\n") + "\n").into_bytes());
        }
        Ok(self.redact(&text).into_bytes())
    }
}

/// Linear matching keeps scan memory independent of the size of linked backend databases.
struct Matcher<T> {
    pattern: Vec<T>,
    prefix: Vec<usize>,
    matched: usize,
}
impl<T: Copy + Eq> Matcher<T> {
    fn new(pattern: Vec<T>) -> Self {
        let mut prefix = vec![0; pattern.len()];
        let mut matched = 0;
        for i in 1..pattern.len() {
            while matched > 0 && pattern[i] != pattern[matched] {
                matched = prefix[matched - 1];
            }
            if pattern[i] == pattern[matched] {
                matched += 1;
            }
            prefix[i] = matched;
        }
        Self {
            pattern,
            prefix,
            matched: 0,
        }
    }
    fn feed(&mut self, next: T) -> bool {
        if self.pattern.is_empty() {
            return false;
        }
        while self.matched > 0 && self.pattern[self.matched] != next {
            self.matched = self.prefix[self.matched - 1];
        }
        if self.pattern[self.matched] == next {
            self.matched += 1;
        }
        if self.matched == self.pattern.len() {
            self.matched = self.prefix[self.matched - 1];
            return true;
        }
        false
    }
}

/// Check even linked backend resources, but never modify their targets.
fn scan(
    task: &SuiteTask,
    root: &Path,
    secrets: &Secrets,
    generated: Option<&Path>,
    analysis_exempt: bool,
) -> Result<(), BenchError> {
    fn walk(
        task: &SuiteTask,
        path: &Path,
        root: &Path,
        secrets: &Secrets,
        generated: Option<&Path>,
        exempt: bool,
        seen: &mut BTreeSet<PathBuf>,
    ) -> Result<(), BenchError> {
        if path.is_dir() {
            let canonical = path.canonicalize().map_err(|e| io(path, e))?;
            if !seen.insert(canonical.clone()) || seen.len() > 128 {
                return Err(copy_error(
                    task,
                    "cycle or excessive nesting in linked resources",
                ));
            }
            for entry in std::fs::read_dir(path).map_err(|e| io(path, e))? {
                walk(
                    task,
                    &entry.map_err(|e| io(path, e))?.path(),
                    root,
                    secrets,
                    generated,
                    exempt,
                    seen,
                )?;
            }
            seen.remove(&canonical);
            return Ok(());
        }
        let mut file = std::fs::File::open(path).map_err(|e| io(path, e))?;
        let include_bytes = !(exempt && path.starts_with(root.join("knowledge/analysis")));
        if let Some(kind) = secrets
            .scan_reader(&mut file, Some(path) != generated, include_bytes)
            .map_err(|e| io(path, e))?
        {
            return Err(copy_error(
                task,
                format!("known {kind} remains in {}", path.display()),
            ));
        }
        Ok(())
    }
    walk(
        task,
        root,
        root,
        secrets,
        generated,
        analysis_exempt,
        &mut BTreeSet::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::Secrets;
    use std::io::Cursor;

    #[test]
    fn streamed_scan_keeps_matches_across_buffer_and_utf8_boundaries() {
        let secrets = Secrets {
            definition: "int f() { /* ☺ */ return 7; }".into(),
            code_hash: Some("secret-hash-17".into()),
            object: Some(b"object-blob-29".to_vec()),
        };
        for (payload, expected) in [
            ("int\nf() { /* ☺ */ return 7; }".as_bytes(), "definition"),
            (b"secret-hash-17".as_slice(), "object or code hash"),
            (b"object-blob-29".as_slice(), "object or code hash"),
        ] {
            for prefix in [65_520, 65_525, 65_530, 65_535] {
                let mut input = vec![b'x'; prefix];
                input.extend_from_slice(payload);
                input.extend_from_slice(b" harmless tail");
                assert_eq!(
                    secrets
                        .scan_reader(&mut Cursor::new(input), true, true)
                        .unwrap(),
                    Some(expected)
                );
            }
        }
        assert_eq!(
            secrets
                .scan_reader(&mut Cursor::new(b"unrelated"), true, true)
                .unwrap(),
            None
        );
        assert_eq!(
            secrets
                .scan_reader(&mut Cursor::new(b"object-blob-29"), true, false)
                .unwrap(),
            None
        );
    }
}
