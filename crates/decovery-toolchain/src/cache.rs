//! Content-addressed cache of compiled objects (design 5.13): the key is the blake3 hash of everything the object
//! depends on, so a repeated compile is free and results do not depend on order.

use std::io;
use std::path::{Path, PathBuf};

use decovery_core::write_atomic;

use crate::Profile;

/// Directory of the cached objects, relative to the workspace root.
pub const OBJECT_CACHE_DIR: &str = "cache/rebuild/objects";

/// Objects by key under `cache/rebuild/objects/<key>.obj`.
#[derive(Debug, Clone)]
pub struct ObjectCache {
    dir: PathBuf,
}

/// Feeds a length-prefixed field, so that no two different inputs hash the same.
fn field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

impl ObjectCache {
    /// The cache of the workspace at `root`.
    pub fn open(root: &Path) -> Self {
        ObjectCache {
            dir: root.join(OBJECT_CACHE_DIR),
        }
    }

    /// The key of one compile: profile id, `flags` (the rendered compile line, so the source name counts too),
    /// prelude, source bytes, headers sorted by name with their bytes, and the fingerprint of the tool files.
    pub fn key(
        profile: &Profile,
        flags: &str,
        source: &[u8],
        headers: &[(String, Vec<u8>)],
        tool_fingerprint: &str,
    ) -> String {
        let mut hasher = blake3::Hasher::new();
        field(&mut hasher, b"decovery-object/1");
        field(&mut hasher, profile.id.as_bytes());
        field(&mut hasher, flags.as_bytes());
        field(&mut hasher, profile.prelude.join("\n").as_bytes());
        field(&mut hasher, source);
        let mut sorted: Vec<&(String, Vec<u8>)> = headers.iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        hasher.update(&(sorted.len() as u64).to_le_bytes());
        for (name, bytes) in sorted {
            field(&mut hasher, name.as_bytes());
            field(&mut hasher, bytes);
        }
        field(&mut hasher, tool_fingerprint.as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    fn path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.obj"))
    }

    /// The cached object, if any.
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        std::fs::read(self.path(key)).ok()
    }

    /// Stores `object` under `key` (atomically).
    pub fn put(&self, key: &str, object: &[u8]) -> io::Result<()> {
        write_atomic(&self.path(key), object)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(items: &[(&str, &[u8])]) -> Vec<(String, Vec<u8>)> {
        items
            .iter()
            .map(|(n, b)| (n.to_string(), b.to_vec()))
            .collect()
    }

    #[test]
    fn key_depends_on_every_input_and_not_on_header_order() {
        let p = crate::profile("turbo-c-2.0").unwrap();
        let w = crate::profile("watcom-9.5").unwrap();
        let h = headers(&[("A.H", b"a"), ("B.H", b"b")]);
        let base = ObjectCache::key(&p, "TCC A.C", b"int a;", &h, "f1");
        let reordered = headers(&[("B.H", b"b"), ("A.H", b"a")]);
        assert_eq!(
            base,
            ObjectCache::key(&p, "TCC A.C", b"int a;", &reordered, "f1")
        );
        let others = [
            ObjectCache::key(&w, "TCC A.C", b"int a;", &h, "f1"),
            ObjectCache::key(&p, "TCC B.C", b"int a;", &h, "f1"),
            ObjectCache::key(&p, "TCC A.C", b"int b;", &h, "f1"),
            ObjectCache::key(&p, "TCC A.C", b"int a;", &headers(&[("A.H", b"a")]), "f1"),
            ObjectCache::key(
                &p,
                "TCC A.C",
                b"int a;",
                &headers(&[("A.H", b"a"), ("B.H", b"c")]),
                "f1",
            ),
            ObjectCache::key(&p, "TCC A.C", b"int a;", &h, "f2"),
        ];
        for other in others {
            assert_ne!(base, other);
        }
        assert_eq!(base.len(), 64);
    }

    #[test]
    fn put_then_get() {
        let dir = tempfile::tempdir().unwrap();
        let cache = ObjectCache::open(dir.path());
        assert_eq!(cache.get("k"), None);
        cache.put("k", b"obj").unwrap();
        assert_eq!(cache.get("k").unwrap(), b"obj");
        assert!(dir.path().join(OBJECT_CACHE_DIR).join("k.obj").is_file());
    }
}
