//! Compiler flags per source file: `[rebuild.file_flags]` in `decovery.toml`, and a header comment in the source
//! itself (`/* decovery: flags = +b +c */` in the first lines), which wins when both are there and differ.

use std::path::Path;

use decovery_core::RebuildConfig;

use super::build::SOURCE_DIR;

/// How many lines at the top of a source are searched for the comment.
const HEADER_LINES: usize = 10;

/// The flags a source's header comment gives: `Ok(None)` without a `decovery:` comment, an error text for one that
/// cannot be read.
pub(super) fn header_flags(text: &str) -> Result<Option<String>, String> {
    for line in text.lines().take(HEADER_LINES) {
        let Some((before, rest)) = line.split_once("decovery:") else {
            continue;
        };
        let before = before.trim();
        if !(before.ends_with("/*") || before.ends_with("//") || before.ends_with('*')) {
            continue;
        }
        let rest = rest.trim();
        let rest = rest.strip_suffix("*/").unwrap_or(rest).trim();
        let Some(value) = rest
            .strip_prefix("flags")
            .map(str::trim_start)
            .and_then(|r| r.strip_prefix('='))
        else {
            return Err(format!(
                "unreadable comment `decovery:{rest}` (expected `decovery: flags = <flags>`)"
            ));
        };
        return Ok(Some(value.trim().to_string()));
    }
    Ok(None)
}

/// Puts the header-comment flags of the sources in `src/` into `rebuild.file_flags` (the comment wins over a
/// different table entry) and returns warnings: differing entries, unreadable comments, and table entries that
/// name no file in `src/`.
pub(super) fn apply_source_flags(root: &Path, rebuild: &mut RebuildConfig) -> Vec<String> {
    let mut warnings = Vec::new();
    let mut names: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root.join(SOURCE_DIR)) {
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|t| t.is_file()) {
                names.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
    }
    names.sort();
    for key in rebuild.file_flags.keys() {
        if !names.iter().any(|n| n.eq_ignore_ascii_case(key)) {
            warnings.push(format!(
                "[rebuild.file_flags] names {key}, which is not in {SOURCE_DIR}/"
            ));
        }
    }
    for name in names.iter().filter(|n| super::build::is_c(n)) {
        let Ok(bytes) = std::fs::read(root.join(SOURCE_DIR).join(name)) else {
            continue;
        };
        let flags = match header_flags(&String::from_utf8_lossy(&bytes)) {
            Ok(Some(flags)) => flags,
            Ok(None) => continue,
            Err(e) => {
                warnings.push(format!("{name}: {e}"));
                continue;
            }
        };
        let keys: Vec<String> = rebuild
            .file_flags
            .keys()
            .filter(|k| k.eq_ignore_ascii_case(name))
            .cloned()
            .collect();
        for key in keys {
            if let Some(old) = rebuild.file_flags.remove(&key)
                && old != flags
            {
                warnings.push(format!(
                    "{name}: flags in the source comment ({flags}) differ from [rebuild.file_flags] ({old}); the comment wins"
                ));
            }
        }
        rebuild.file_flags.insert(name.clone(), flags);
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_comment_in_the_first_lines() {
        for text in [
            "/* decovery: flags = +b +c */\nint x;\n",
            "\n// decovery: flags = +b +c\nint x;\n",
            "/*\n * decovery:flags=+b +c\n */\n",
        ] {
            assert_eq!(header_flags(text), Ok(Some("+b +c".to_string())), "{text}");
        }
    }

    #[test]
    fn no_comment_or_too_late_means_none() {
        assert_eq!(header_flags("int x;\n"), Ok(None));
        let late = format!("{}/* decovery: flags = +b */\n", "int x;\n".repeat(20));
        assert_eq!(header_flags(&late), Ok(None));
        // the word inside code is not a comment
        assert_eq!(
            header_flags("char *s = \"decovery: flags = x\";\n"),
            Ok(None)
        );
    }

    #[test]
    fn a_broken_comment_is_an_error() {
        assert!(header_flags("/* decovery: flag +b */\n").is_err());
    }

    fn rebuild(table: &[(&str, &str)]) -> RebuildConfig {
        let mut r = RebuildConfig::default();
        for (k, v) in table {
            r.file_flags.insert(k.to_string(), v.to_string());
        }
        r
    }

    fn workspace(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(SOURCE_DIR)).unwrap();
        for (name, text) in files {
            std::fs::write(dir.path().join(SOURCE_DIR).join(name), text).unwrap();
        }
        dir
    }

    #[test]
    fn the_comment_alone_sets_the_flags() {
        let dir = workspace(&[("a.c", "/* decovery: flags = +b */\n"), ("b.c", "int x;\n")]);
        let mut r = rebuild(&[]);
        let warnings = apply_source_flags(dir.path(), &mut r);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(r.file_flags.get("a.c").map(String::as_str), Some("+b"));
        assert_eq!(r.file_flags.len(), 1);
    }

    #[test]
    fn a_differing_table_entry_loses_with_a_warning() {
        let dir = workspace(&[("a.c", "/* decovery: flags = +b */\n")]);
        let mut r = rebuild(&[("A.C", "+c")]);
        let warnings = apply_source_flags(dir.path(), &mut r);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("the comment wins"), "{warnings:?}");
        assert_eq!(r.file_flags.get("a.c").map(String::as_str), Some("+b"));
        assert!(!r.file_flags.contains_key("A.C"));
    }

    #[test]
    fn an_equal_table_entry_is_silent() {
        let dir = workspace(&[("a.c", "/* decovery: flags = +b */\n")]);
        let mut r = rebuild(&[("a.c", "+b")]);
        assert!(apply_source_flags(dir.path(), &mut r).is_empty());
    }

    #[test]
    fn orphan_table_entries_are_warned_about() {
        let dir = workspace(&[("a.c", "int x;\n")]);
        let mut r = rebuild(&[("A.C", "+b"), ("gone.c", "+c")]);
        let warnings = apply_source_flags(dir.path(), &mut r);
        assert_eq!(
            warnings,
            vec!["[rebuild.file_flags] names gone.c, which is not in src/".to_string()]
        );
        assert_eq!(r.file_flags.len(), 2);
    }
}
