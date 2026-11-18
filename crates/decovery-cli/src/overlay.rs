//! `decovery overlay add|list|remove`: the `[[overlay]]` entries of `decovery.toml` (ADR 0011).

use std::path::{Path, PathBuf};
use std::time::Duration;

use decovery_core::{Address, OverlayConfig, OverlayName, SegmentConfig, TargetFormat, Workspace};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Overlay formats `overlay add` knows.
pub const FORMATS: &[&str] = &["aztec-c86"];

const LOCK_WAIT: Duration = Duration::from_secs(10);

fn open(root: &Path) -> Result<Workspace, String> {
    Workspace::open(root).map_err(|e| format!("cannot open workspace: {e}"))
}

fn save(ws: &Workspace) -> Result<(), String> {
    let lock = ws.lock(LOCK_WAIT).map_err(|e| e.to_string())?;
    ws.save_config(&lock).map_err(|e| e.to_string())
}

fn entry_json(o: &OverlayConfig, ws: &Workspace) -> Value {
    let segments: Vec<String> = ws
        .config
        .target
        .segments
        .iter()
        .filter(|s| s.start.overlay() == Some(o.name))
        .map(|s| format!("{} {} +{:#x}", s.name, s.start, s.length))
        .collect();
    json!({
        "name": o.name.as_str(),
        "file": o.file,
        "format": o.format,
        "size": o.size,
        "entry": o.entry.map(|a| a.to_string()),
        "segments": segments,
    })
}

/// Code and data segment of the main program an Aztec overlay is loaded into: CS from the MZ header, DS from the
/// startup code's `mov bp, <segment>` (or `ds`), plus the offset of `ovloader_` when found once.
fn main_segments(ws: &Workspace, ds: Option<u16>) -> Result<(u16, u16, Option<u32>), String> {
    if ws.config.target.format != TargetFormat::Mz {
        return Err("Aztec overlays need an MZ main program".into());
    }
    let path = decovery_facade::program::target_path(ws);
    let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mz = decovery_loaders::load_mz(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    let image = bytes
        .get(usize::try_from(mz.image_offset).unwrap_or(usize::MAX)..)
        .unwrap_or(&[]);
    let cs = mz.header.cs;
    let ds = match ds {
        Some(ds) => ds,
        None => decovery_loaders::aztec_data_segment(image, cs, mz.header.ip).ok_or(
            "data segment not found in the startup code (no `mov bp, <segment>` at the entry); give --ds SSSS",
        )?,
    };
    let code_start = usize::from(cs) * 16;
    let code = image
        .get(code_start..image.len().min(code_start + 0x1_0000))
        .unwrap_or(&[]);
    Ok((cs, ds, decovery_loaders::find_overlay_loader(code)))
}

/// Adds (or replaces, by name) one overlay per file; the name is the file stem, upper case. The header is
/// checked and the overlay's code and data segments are written as `[[target.segment]]` entries.
pub fn add(root: &Path, files: &[PathBuf], format: &str, ds: Option<u16>) -> Result<Value, String> {
    if !FORMATS.contains(&format) {
        return Err(format!(
            "unknown overlay format {format:?} (known: {})",
            FORMATS.join(", ")
        ));
    }
    if files.is_empty() {
        return Err("no overlay file given".into());
    }
    let mut ws = open(root)?;
    let (cs, ds, loader) = main_segments(&ws, ds)?;
    let mut added = Vec::new();
    let mut segments = Vec::new();
    for file in files {
        let path = if file.is_absolute() || file.exists() {
            file.clone()
        } else {
            root.join(file)
        };
        let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| format!("{}: no file name", path.display()))?;
        let name = OverlayName::new(stem).map_err(|e| format!("{}: {e}", path.display()))?;
        if added.iter().any(|o: &OverlayConfig| o.name == name) {
            return Err(format!("two overlay files named {name}"));
        }
        let overlay = decovery_loaders::read_overlay(&bytes, name.as_str())
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let h = overlay.header;
        let at = |seg: u16, off: u16| Address::Ovl {
            overlay: name,
            seg,
            off,
        };
        segments.push(SegmentConfig::new(
            format!("{name}.code"),
            at(cs, h.corg),
            u64::from(h.csize),
            Some(h.code_offset()),
            None,
            "rwx",
        ));
        if u32::from(h.dsize) + u32::from(h.bss) > 0 {
            segments.push(SegmentConfig::new(
                format!("{name}.data"),
                at(ds, h.dorg),
                u64::from(h.dsize) + u64::from(h.bss),
                Some(h.data_offset()),
                Some(u64::from(h.dsize)),
                "rw",
            ));
        }
        let sha = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let file_text = std::path::absolute(&path)
            .unwrap_or(path.clone())
            .to_string_lossy()
            .replace('\\', "/");
        let mut config = OverlayConfig::new(name, file_text, sha, format, bytes.len() as u64);
        config.entry = Some(at(cs, h.entry));
        added.push(config);
    }
    for o in &added {
        ws.config.overlays.retain(|x| x.name != o.name);
        ws.config
            .target
            .segments
            .retain(|s| s.start.overlay() != Some(o.name));
    }
    ws.config.overlays.extend(added.iter().cloned());
    ws.config.target.segments.extend(segments);
    save(&ws)?;
    let entries: Vec<Value> = added.iter().map(|o| entry_json(o, &ws)).collect();
    Ok(json!({
        "overlays": entries,
        "loader": loader.map(|off| Address::Seg { seg: cs, off: off as u16 }.to_string()),
    }))
}

/// Every configured overlay.
pub fn list(root: &Path) -> Result<Value, String> {
    let ws = open(root)?;
    let entries: Vec<Value> = ws
        .config
        .overlays
        .iter()
        .map(|o| entry_json(o, &ws))
        .collect();
    Ok(json!({ "overlays": entries }))
}

/// Removes an overlay and its memory segments.
pub fn remove(root: &Path, name: &str) -> Result<Value, String> {
    let mut ws = open(root)?;
    let wanted = OverlayName::new(name).map_err(|e| e.to_string())?;
    if ws.config.overlay(wanted).is_none() {
        let known: Vec<&str> = ws.config.overlays.iter().map(|o| o.name.as_str()).collect();
        return Err(format!(
            "no overlay {wanted} (known overlays: {})",
            if known.is_empty() {
                "none".to_string()
            } else {
                known.join(", ")
            }
        ));
    }
    ws.config.overlays.retain(|o| o.name != wanted);
    let before = ws.config.target.segments.len();
    ws.config
        .target
        .segments
        .retain(|s| s.start.overlay() != Some(wanted));
    let segments = before - ws.config.target.segments.len();
    save(&ws)?;
    Ok(json!({ "removed": wanted.as_str(), "segments": segments }))
}

/// Text form of an `add`/`list` answer.
pub fn print(answer: &Value) {
    if let Some(name) = answer["removed"].as_str() {
        println!(
            "removed overlay {name} ({} segments)",
            answer["segments"].as_u64().unwrap_or(0)
        );
        return;
    }
    let entries = answer["overlays"].as_array().cloned().unwrap_or_default();
    if entries.is_empty() {
        println!("no overlays");
    }
    for o in entries {
        println!(
            "{} {} ({}, {} bytes){}",
            o["name"].as_str().unwrap_or(""),
            o["file"].as_str().unwrap_or(""),
            o["format"].as_str().unwrap_or(""),
            o["size"].as_u64().unwrap_or(0),
            o["entry"]
                .as_str()
                .map(|e| format!(", entry {e}"))
                .unwrap_or_default()
        );
        for s in o["segments"].as_array().into_iter().flatten() {
            println!("  {}", s.as_str().unwrap_or(""));
        }
    }
}
