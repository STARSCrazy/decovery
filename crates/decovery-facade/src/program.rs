//! Loading the target program of a workspace.

use std::path::{Path, PathBuf};

use decovery_core::{
    ArchMode, OverlayConfig, Permissions, Program, Region, TargetFormat, Workspace,
};

use crate::FacadeError;

/// Path as given when it exists, otherwise relative to the workspace root.
fn locate(path: &Path, root: &Path) -> PathBuf {
    if path.is_absolute() || path.exists() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

/// The file of the target of `ws`.
pub fn target_path(ws: &Workspace) -> PathBuf {
    locate(Path::new(&ws.config.target.file), &ws.root)
}

/// The bytes of overlay `o` from its file (`file_offset`, `size`; a file of its own is read whole).
pub fn overlay_bytes(ws: &Workspace, o: &OverlayConfig) -> Result<Vec<u8>, String> {
    let path = locate(Path::new(&o.file), &ws.root);
    let bytes = std::fs::read(&path)
        .map_err(|e| format!("cannot read overlay {} ({}): {e}", o.name, path.display()))?;
    if o.file_offset == 0 {
        return Ok(bytes);
    }
    let start = usize::try_from(o.file_offset).unwrap_or(usize::MAX);
    let end = start.saturating_add(usize::try_from(o.size).unwrap_or(usize::MAX));
    bytes
        .get(start..end.min(bytes.len()))
        .map(<[u8]>::to_vec)
        .ok_or_else(|| {
            format!(
                "overlay {}: file offset {start} past the end of {}",
                o.name,
                path.display()
            )
        })
}

/// Loads the target of `ws`, dispatching on its format.
pub fn load(ws: &Workspace) -> Result<Program, FacadeError> {
    let format = ws.config.target.format;
    let file = target_path(ws);
    let bytes = std::fs::read(&file)
        .map_err(|e| FacadeError::Invalid(format!("cannot read target {}: {e}", file.display())))?;
    let loaded = match format {
        TargetFormat::Le => decovery_loaders::load_le(&bytes).map(|image| image.program),
        TargetFormat::Mz => decovery_loaders::load_mz(&bytes).map(|image| image.program),
        TargetFormat::Com => decovery_loaders::load_com(&bytes),
        _ => {
            return Err(FacadeError::Invalid(format!(
                "target format {format:?} is not supported yet"
            )));
        }
    };
    let mut program = loaded
        .map_err(|e| FacadeError::Invalid(format!("cannot load target {}: {e}", file.display())))?;
    let (regions, _warnings) = overlay_regions(ws);
    program.regions.extend(regions);
    for o in &ws.config.overlays {
        if let Some(entry) = o.entry
            && program.region_at(entry).is_some()
        {
            program.entry_points.push(entry);
        }
    }
    Ok(program)
}

/// Regions of the configured overlays (ADR 0011): one per `[[target.segment]]` with an `ovl:` start, bytes from the
/// overlay's file. An overlay whose file cannot be read gives a warning and no regions; the others still load.
pub fn overlay_regions(ws: &Workspace) -> (Vec<Region>, Vec<String>) {
    let mut regions = Vec::new();
    let mut warnings = Vec::new();
    for o in &ws.config.overlays {
        let path = locate(Path::new(&o.file), &ws.root);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                warnings.push(format!(
                    "overlay {}: cannot read {}: {e}",
                    o.name,
                    path.display()
                ));
                continue;
            }
        };
        let file = bytes
            .get(usize::try_from(o.file_offset).unwrap_or(usize::MAX)..)
            .unwrap_or(&[]);
        for seg in ws
            .config
            .target
            .segments
            .iter()
            .filter(|s| s.start.overlay() == Some(o.name))
        {
            let len = seg.file_length.unwrap_or(seg.length).min(seg.length);
            let data = match seg.file_offset {
                Some(off) => {
                    let start = usize::try_from(off).unwrap_or(usize::MAX);
                    let end = start.saturating_add(usize::try_from(len).unwrap_or(usize::MAX));
                    match file.get(start..end) {
                        Some(d) => d.to_vec(),
                        None => {
                            warnings.push(format!(
                                "overlay {}: segment {} ({len} bytes at file offset {off:#x}) runs past the file end",
                                o.name, seg.name
                            ));
                            continue;
                        }
                    }
                }
                None => Vec::new(),
            };
            let permissions = Permissions {
                read: seg.permissions.contains('r'),
                write: seg.permissions.contains('w'),
                execute: seg.permissions.contains('x'),
            };
            let mut region = Region::new(
                seg.name.clone(),
                seg.start,
                seg.length,
                data,
                permissions,
                ArchMode::X86Real16,
            );
            region.file_offset = seg.file_offset.map(|f| f + o.file_offset);
            regions.push(region);
        }
    }
    (regions, warnings)
}

/// Reads and checks the file of overlay `o` (Aztec C86 layout); the error names the file.
pub fn read_overlay_of(
    ws: &Workspace,
    o: &decovery_core::OverlayConfig,
) -> Result<decovery_loaders::Overlay, String> {
    let path = locate(Path::new(&o.file), &ws.root);
    let bytes = std::fs::read(&path)
        .map_err(|e| format!("overlay {}: cannot read {}: {e}", o.name, path.display()))?;
    let file = bytes
        .get(usize::try_from(o.file_offset).unwrap_or(usize::MAX)..)
        .unwrap_or(&[]);
    decovery_loaders::read_overlay(file, o.name.as_str())
        .map_err(|e| format!("overlay {}: {e}", o.name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_segments_become_readable_regions() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("t.com"), [0xC3u8]).unwrap();
        let mut ovr = vec![0u8; 14];
        ovr.extend_from_slice(&[0x55, 0x8B, 0xEC, 0xC3, 7, 8]);
        std::fs::write(dir.path().join("A.OVR"), &ovr).unwrap();
        std::fs::write(
            dir.path().join("decovery.toml"),
            "schema = 1

[target]
file = \"t.com\"
sha256 = \"aa\"
format = \"com\"
processor = \"x86\"

[[target.segment]]
name = \"A.code\"
start = \"ovl:A:0000:5000\"
length = 4
file_offset = 14
permissions = \"rwx\"

[[target.segment]]
name = \"A.data\"
start = \"ovl:A:0FF6:9000\"
length = 8
file_offset = 18
file_length = 2
permissions = \"rw\"

[[overlay]]
name = \"A\"
file = \"A.OVR\"
sha256 = \"bb\"
format = \"aztec-c86\"
size = 20
entry = \"ovl:A:0000:5000\"

[[overlay]]
name = \"MISSING\"
file = \"MISSING.OVR\"
sha256 = \"cc\"
format = \"aztec-c86\"
size = 20
",
        )
        .unwrap();
        let ws = Workspace::open(dir.path()).unwrap();
        let (regions, warnings) = overlay_regions(&ws);
        assert_eq!(regions.len(), 2);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("MISSING"));
        let program = load(&ws).unwrap();
        let at: decovery_core::Address = "ovl:A:0000:5001".parse().unwrap();
        assert_eq!(program.read(at, 3), Some(&[0x8B, 0xEC, 0xC3][..]));
        let data: decovery_core::Address = "ovl:A:0FF6:9000".parse().unwrap();
        assert_eq!(program.read(data, 2), Some(&[7, 8][..]));
        assert!(
            program
                .entry_points
                .contains(&"ovl:A:0000:5000".parse().unwrap())
        );
    }
}
