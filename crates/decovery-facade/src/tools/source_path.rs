//! Source arguments of `build`: a file name in `src/`, or a path to it relative to the workspace or to `src/`
//! (or absolute inside `src/`), normalised to the file name.

use std::path::{Component, Path, PathBuf};

use crate::FacadeError;

use super::build::SOURCE_DIR;

/// `path` without `.` and `..` components (no file system access).
fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// The part of `path` below `base`, compared without regard to ASCII case (DOS names, Windows paths).
fn below<'a>(path: &'a Path, base: &Path) -> Option<Vec<&'a std::ffi::OsStr>> {
    let mut p = path.components();
    for b in base.components() {
        let a = p.next()?;
        if !a
            .as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(&b.as_os_str().to_string_lossy())
        {
            return None;
        }
    }
    Some(p.map(Component::as_os_str).collect())
}

/// The file name in `src/` that `arg` stands for.
pub(super) fn source_file_name(root: &Path, arg: &str) -> Result<String, FacadeError> {
    let arg = arg.trim();
    let path = Path::new(arg);
    let src = lexical(&root.join(SOURCE_DIR));
    let is_name = path.components().count() == 1
        && matches!(path.components().next(), Some(Component::Normal(_)));
    if is_name {
        return Ok(arg.to_string());
    }
    let mut candidates = vec![lexical(&root.join(path))];
    if path.is_relative() {
        candidates.push(lexical(&src.join(path)));
    }
    for candidate in &candidates {
        if let Some(rest) = below(candidate, &src)
            && let Some(name) = rest.last()
        {
            return Ok(name.to_string_lossy().into_owned());
        }
    }
    Err(FacadeError::Invalid(format!(
        "{arg} is not a source in {} (give a file name in src/, or a path inside it)",
        src.display()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(arg: &str) -> Result<String, String> {
        let root = Path::new("work").join("ws");
        source_file_name(&root, arg).map_err(|e| e.to_string())
    }

    #[test]
    fn bare_name_stays() {
        assert_eq!(name("x.c").unwrap(), "x.c");
    }

    #[test]
    fn paths_relative_to_the_workspace_or_to_src() {
        for arg in ["src/x.c", "./src/x.c", "./x.c", "SRC/x.c"] {
            assert_eq!(name(arg).unwrap(), "x.c", "{arg}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn backslash_paths_on_windows() {
        assert_eq!(name("src\\x.c").unwrap(), "x.c");
    }

    #[test]
    fn absolute_path_inside_src() {
        let root = std::env::current_dir().unwrap().join("ws");
        let abs = root.join("src").join("x.c");
        assert_eq!(
            source_file_name(&root, &abs.to_string_lossy()).unwrap(),
            "x.c"
        );
    }

    #[test]
    fn paths_outside_src_are_rejected() {
        for arg in ["../x.c", "../ws/x.c"] {
            let m = name(arg).unwrap_err();
            assert!(m.contains("not a source in"), "{arg}: {m}");
        }
        let root = std::env::current_dir().unwrap().join("ws");
        let abs = root.join("elsewhere").join("x.c");
        assert!(source_file_name(&root, &abs.to_string_lossy()).is_err());
    }
}
