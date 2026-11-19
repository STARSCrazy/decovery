//! Source staging: finds the sources of a rebuild and writes them the way DOS compilers read them
//! (upper-case 8.3 names, code page 437, CRLF line ends).

use std::fs;
use std::path::{Path, PathBuf};

use crate::{ToolchainError, cp437};

/// The files of a rebuild: translatable sources (`.c`, `.s`, `.asm`) and headers (`.h`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SourceSet {
    pub sources: Vec<PathBuf>,
    pub headers: Vec<PathBuf>,
}

fn io(path: &Path, source: std::io::Error) -> ToolchainError {
    ToolchainError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Checks `[a-z0-9_-]{1,8}\.(c|h|s|asm)`, case-insensitive; returns the lower-case stem and extension.
fn split_name(name: &str) -> Result<(String, String), ToolchainError> {
    let invalid = || ToolchainError::InvalidSourceName {
        name: name.to_string(),
    };
    let lower = name.to_ascii_lowercase();
    let (stem, ext) = lower.rsplit_once('.').ok_or_else(invalid)?;
    let stem_ok = (1..=8).contains(&stem.len())
        && stem
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
    if !stem_ok || !matches!(ext, "c" | "h" | "s" | "asm") {
        return Err(invalid());
    }
    Ok((stem.to_string(), ext.to_string()))
}

/// First-line markers of a build-only assembler file: data, library and stand-in code a standalone build of the
/// whole program needs, which is not part of the rebuild (never compiled or compared). `decomp:` is the marker of
/// workspaces migrated from Decomp.
pub const BUILD_ONLY_MARKERS: [&str; 2] = ["decovery: build only", "decomp: build only"];

/// Whether `path` is an assembler file whose first line carries a [`BUILD_ONLY_MARKERS`] marker.
pub fn is_build_only(path: &Path) -> Result<bool, ToolchainError> {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let lower = name.to_ascii_lowercase();
    if !(lower.ends_with(".asm") || lower.ends_with(".s")) {
        return Ok(false);
    }
    let bytes = fs::read(path).map_err(|e| io(path, e))?;
    let end = bytes
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(bytes.len());
    let first = String::from_utf8_lossy(&bytes[..end]);
    Ok(BUILD_ONLY_MARKERS.iter().any(|m| first.contains(m)))
}

/// Finds the sources and headers in `src_dir` and its direct subdirectories (not those whose name starts with a
/// dot); `only` (file names) restricts the sources. All files are staged into one flat directory, so a file name
/// may occur only once. Assembler files marked build-only ([`is_build_only`]) are left out.
pub fn find_sources(src_dir: &Path, only: &[String]) -> Result<SourceSet, ToolchainError> {
    if !src_dir.is_dir() {
        return Err(ToolchainError::Invalid(format!(
            "source directory is missing: {}",
            src_dir.display()
        )));
    }
    let mut dirs = vec![src_dir.to_path_buf()];
    let mut subdirs = Vec::new();
    for entry in fs::read_dir(src_dir).map_err(|e| io(src_dir, e))? {
        let path = entry.map_err(|e| io(src_dir, e))?.path();
        let hidden = path
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with('.'));
        if path.is_dir() && !hidden {
            subdirs.push(path);
        }
    }
    subdirs.sort();
    dirs.extend(subdirs);
    let mut files = Vec::new();
    for dir in &dirs {
        for entry in fs::read_dir(dir).map_err(|e| io(dir, e))? {
            let path = entry.map_err(|e| io(dir, e))?.path();
            if !path.is_file() {
                continue;
            }
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());
            if matches!(ext.as_deref(), Some("c" | "h" | "cpp" | "s" | "asm"))
                && !is_build_only(&path)?
            {
                files.push(path);
            }
        }
    }
    let mut names: Vec<String> = files
        .iter()
        .map(|p| {
            p.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_ascii_lowercase()
        })
        .collect();
    names.sort();
    let mut same: Vec<&String> = names
        .windows(2)
        .filter(|w| w[0] == w[1])
        .map(|w| &w[0])
        .collect();
    same.dedup();
    if !same.is_empty() {
        // every file lands in the same staging directory
        return Err(ToolchainError::Invalid(format!(
            "same file name in several directories of {}: {}",
            src_dir.display(),
            same.iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    files.sort_by_key(|p| p.file_name().map(|n| n.to_ascii_lowercase()));
    let mut sources = Vec::new();
    let mut headers = Vec::new();
    let mut stems: Vec<String> = Vec::new();
    for path in files {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let (stem, ext) = split_name(&name)?;
        if ext == "h" {
            headers.push(path);
        } else {
            stems.push(stem);
            sources.push(path);
        }
    }
    let mut duplicates: Vec<&str> = stems
        .iter()
        .filter(|s| stems.iter().filter(|t| t == s).count() > 1)
        .map(String::as_str)
        .collect();
    duplicates.sort();
    duplicates.dedup();
    if !duplicates.is_empty() {
        // MAG.C and MAG.S would produce the same object file
        return Err(ToolchainError::Invalid(format!(
            "same name with different extensions in {}: {} (rename the assembler file, e.g. asmpart.s)",
            src_dir.display(),
            duplicates.join(", ")
        )));
    }
    if !only.is_empty() {
        let mut chosen: Vec<PathBuf> = Vec::new();
        let mut missing = Vec::new();
        for name in only {
            let found = sources
                .iter()
                .find(|p| p.file_name().is_some_and(|n| n == name.as_str()));
            match found {
                Some(p) if !chosen.contains(p) => chosen.push(p.clone()),
                Some(_) => {}
                None => missing.push(name.as_str()),
            }
        }
        if !missing.is_empty() {
            return Err(ToolchainError::Invalid(format!(
                "source missing in {}: {}",
                src_dir.display(),
                missing.join(", ")
            )));
        }
        sources = chosen;
    }
    if sources.is_empty() {
        return Err(ToolchainError::Invalid(format!(
            "{} contains no .c, .s or .asm files",
            src_dir.display()
        )));
    }
    Ok(SourceSet { sources, headers })
}

/// UTF-8 text to code page 437 with CRLF line ends (Turbo C silently compiles LF sources to empty code).
/// A trailing empty line is dropped. `name` only labels errors.
pub fn to_dos_bytes(name: &str, text: &str) -> Result<Vec<u8>, ToolchainError> {
    let text = text.replace("\r\n", "\n");
    let mut lines: Vec<&str> = text.split('\n').collect();
    if lines.last() == Some(&"") {
        lines.pop();
    }
    let mut out = Vec::with_capacity(text.len() + lines.len());
    for (i, line) in lines.iter().enumerate() {
        for c in line.chars() {
            let byte = cp437::encode(c).ok_or_else(|| ToolchainError::NotCp437 {
                file: name.to_string(),
                line: i as u32 + 1,
                ch: c as u32,
            })?;
            out.push(byte);
        }
        out.extend_from_slice(b"\r\n");
    }
    Ok(out)
}

/// Writes one source text into `build_dir` under its upper-case DOS name and returns that name.
pub fn stage_text(name: &str, text: &str, build_dir: &Path) -> Result<String, ToolchainError> {
    split_name(name)?;
    let bytes = to_dos_bytes(name, text)?;
    fs::create_dir_all(build_dir).map_err(|e| io(build_dir, e))?;
    let dos_name = name.to_ascii_uppercase();
    let target = build_dir.join(&dos_name);
    fs::write(&target, bytes).map_err(|e| io(&target, e))?;
    Ok(dos_name)
}

/// Empties `build_dir` and writes all sources and headers into it; returns the DOS names written.
pub fn stage(set: &SourceSet, build_dir: &Path) -> Result<Vec<String>, ToolchainError> {
    if build_dir.exists() {
        fs::remove_dir_all(build_dir).map_err(|e| io(build_dir, e))?;
    }
    fs::create_dir_all(build_dir).map_err(|e| io(build_dir, e))?;
    let mut names = Vec::new();
    for path in set.sources.iter().chain(&set.headers) {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let text = fs::read_to_string(path).map_err(|e| io(path, e))?;
        names.push(stage_text(&name, &text, build_dir)?);
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lf_source_is_staged_with_crlf() {
        let dir = tempfile::tempdir().unwrap();
        let name = stage_text("mag.c", "int a;\nint b;\n", dir.path()).unwrap();
        assert_eq!(name, "MAG.C");
        assert_eq!(
            fs::read(dir.path().join("MAG.C")).unwrap(),
            b"int a;\r\nint b;\r\n"
        );
        assert_eq!(to_dos_bytes("x.c", "a\r\nb").unwrap(), b"a\r\nb\r\n");
        assert_eq!(to_dos_bytes("x.c", "a\n\n").unwrap(), b"a\r\n\r\n");
    }

    #[test]
    fn umlaut_becomes_cp437() {
        assert_eq!(to_dos_bytes("x.c", "ä").unwrap(), b"\x84\r\n");
    }

    #[test]
    fn non_cp437_character_names_line() {
        let err = to_dos_bytes("mag.c", "int a;\nchar *s = \"€\";\n").unwrap_err();
        assert_eq!(
            err.to_string(),
            "mag.c:2: character U+20AC does not exist in code page 437"
        );
    }

    #[test]
    fn long_name_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let err = stage_text("toolongname.c", "", dir.path()).unwrap_err();
        assert!(err.to_string().contains("[a-z0-9_-]{1,8}.(c|h|s|asm)"));
        assert!(err.to_string().contains("8.3 names"), "{err}");
        fs::write(dir.path().join("toolongname.c"), "").unwrap();
        assert!(find_sources(dir.path(), &[]).is_err());
        assert!(stage_text("a.txt", "", dir.path()).is_err());
        assert!(stage_text("a b.c", "", dir.path()).is_err());
    }

    #[test]
    fn same_stem_twice_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("mag.c"), "").unwrap();
        fs::write(dir.path().join("mag.s"), "").unwrap();
        let err = find_sources(dir.path(), &[]).unwrap_err();
        assert!(err.to_string().contains("mag"));
    }

    #[test]
    fn stage_empties_build_dir() {
        let src = tempfile::tempdir().unwrap();
        fs::write(src.path().join("a.c"), "int a;\n").unwrap();
        fs::write(src.path().join("a.h"), "extern int a;\n").unwrap();
        fs::write(src.path().join("notes.txt"), "x").unwrap();
        let set = find_sources(src.path(), &[]).unwrap();
        assert_eq!(set.sources.len(), 1);
        assert_eq!(set.headers.len(), 1);
        let build = tempfile::tempdir().unwrap();
        fs::write(build.path().join("OLD.OBJ"), "x").unwrap();
        let names = stage(&set, build.path()).unwrap();
        assert_eq!(names, ["A.C", "A.H"]);
        assert!(!build.path().join("OLD.OBJ").exists());
        assert!(build.path().join("A.H").exists());
    }

    #[test]
    fn only_selects_sources() {
        let src = tempfile::tempdir().unwrap();
        fs::write(src.path().join("a.c"), "").unwrap();
        fs::write(src.path().join("b.c"), "").unwrap();
        let set = find_sources(src.path(), &["b.c".to_string()]).unwrap();
        assert_eq!(set.sources, [src.path().join("b.c")]);
        assert!(find_sources(src.path(), &["c.c".to_string()]).is_err());
        assert!(find_sources(&src.path().join("none"), &[]).is_err());
    }

    #[test]
    fn subdirectories_are_searched_and_build_only_files_left_out() {
        let src = tempfile::tempdir().unwrap();
        let dir = src.path();
        for sub in ["lib", "data", ".hidden"] {
            fs::create_dir(dir.join(sub)).unwrap();
        }
        fs::write(dir.join("main.c"), "").unwrap();
        fs::write(
            dir.join("lib/clib.asm"),
            "; clib.asm - run-time parts
",
        )
        .unwrap();
        fs::write(dir.join("lib/libdefs.h"), "").unwrap();
        fs::write(
            dir.join("lib/rest.asm"),
            "; rest.asm (decomp: build only) - library bytes
",
        )
        .unwrap();
        fs::write(
            dir.join("data/dconst.asm"),
            "; dconst.asm (decovery: build only) - data
",
        )
        .unwrap();
        // the marker counts only on the first line
        fs::write(
            dir.join("data/later.asm"),
            "; later.asm
; (decovery: build only)
",
        )
        .unwrap();
        fs::write(dir.join(".hidden/x.c"), "").unwrap();
        let set = find_sources(dir, &[]).unwrap();
        let names = |paths: &[PathBuf]| -> Vec<String> {
            paths
                .iter()
                .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
                .collect()
        };
        assert_eq!(names(&set.sources), ["clib.asm", "later.asm", "main.c"]);
        assert_eq!(names(&set.headers), ["libdefs.h"]);
        assert!(is_build_only(&dir.join("lib/rest.asm")).unwrap());
        assert!(!is_build_only(&dir.join("main.c")).unwrap());
        let set = find_sources(dir, &["clib.asm".to_string()]).unwrap();
        assert_eq!(set.sources, [dir.join("lib").join("clib.asm")]);

        // one staging directory: a name may occur only once
        fs::write(dir.join("data/main.c"), "").unwrap();
        let err = find_sources(dir, &[]).unwrap_err().to_string();
        assert!(
            err.contains("same file name") && err.contains("main.c"),
            "{err}"
        );
    }
}
