//! Benchmark endpoint limits and usage. Call records are the single source of completed-call accounting.
use crate::{CallRecord, WorkspaceError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct BenchLimits {
    pub schema: u32,
    pub max_builds: u32,
    pub max_tool_calls: u32,
    pub max_searches: u32,
    pub tools: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}
impl BenchLimits {
    pub fn read(path: &Path) -> Result<Self, WorkspaceError> {
        let bytes = std::fs::read(path).map_err(|source| WorkspaceError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let mut limits: Self =
            serde_json::from_slice(&bytes).map_err(|source| WorkspaceError::Json {
                path: path.to_path_buf(),
                source: Box::new(source),
            })?;
        if limits.schema != 1 {
            return Err(WorkspaceError::Schema {
                path: path.to_path_buf(),
                found: limits.schema,
            });
        }
        if limits.tools == "core+legacy" {
            limits.tools = "core-legacy".into();
        }
        if !matches!(limits.tools.as_str(), "core" | "core-legacy") {
            return Err(WorkspaceError::UnknownValue {
                file: path.to_path_buf(),
                detail: "byte 0: tools must be core or core-legacy".into(),
            });
        }
        Ok(limits)
    }
    pub fn refusal(&self, usage: &BenchUsage, call: &CallRecord) -> Option<String> {
        if usage.tool_calls >= self.max_tool_calls {
            return Some(format!(
                "limit reached: {} of {} tool calls used",
                usage.tool_calls, self.max_tool_calls
            ));
        }
        if self.tools == "core"
            && (matches!(call.tool.as_str(), "search" | "verify")
                || (call.tool == "diagnose" && call.operation.is_some()))
        {
            return Some("not available in this bench run (tools = core)".into());
        }
        if call.builds > self.max_builds.saturating_sub(usage.builds) {
            return Some(format!(
                "limit reached: {} of {} builds used",
                usage.builds, self.max_builds
            ));
        }
        if call.searches > self.max_searches.saturating_sub(usage.searches) {
            return Some(format!(
                "limit reached: {} of {} searches used",
                usage.searches, self.max_searches
            ));
        }
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct BenchUsage {
    pub schema: u32,
    pub builds: u32,
    pub searches: u32,
    pub tool_calls: u32,
    pub calls_by_tool: BTreeMap<String, u32>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}
impl Default for BenchUsage {
    fn default() -> Self {
        Self {
            schema: 1,
            builds: 0,
            searches: 0,
            tool_calls: 0,
            calls_by_tool: BTreeMap::new(),
            warnings: Vec::new(),
            extra: serde_json::Map::new(),
        }
    }
}
impl BenchUsage {
    pub fn record(&mut self, call: &CallRecord) {
        if call.actor.as_deref() == Some("bench-harness") {
            return;
        }
        self.tool_calls = self.tool_calls.saturating_add(1);
        self.builds = self.builds.saturating_add(call.builds);
        self.searches = self.searches.saturating_add(call.searches);
        let count = self.calls_by_tool.entry(call.tool.clone()).or_default();
        *count = count.saturating_add(1);
    }
    pub fn load(root: &Path) -> Result<Self, WorkspaceError> {
        let (calls, warnings) = crate::calls::read_calls(root)?;
        let mut usage = Self {
            warnings,
            ..Self::default()
        };
        for call in &calls {
            usage.record(call);
        }
        let path = root.join("cache/bench/usage.json");
        match std::fs::read(&path) {
            Ok(bytes) => {
                let previous: Self =
                    serde_json::from_slice(&bytes).map_err(|source| WorkspaceError::Json {
                        path: path.clone(),
                        source: Box::new(source),
                    })?;
                if previous.schema != 1 {
                    return Err(WorkspaceError::Schema {
                        path,
                        found: previous.schema,
                    });
                }
                usage.extra = previous.extra;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(WorkspaceError::Io { path, source }),
        }
        Ok(usage)
    }
    pub fn save(&self, root: &Path) -> Result<(), WorkspaceError> {
        let path = root.join("cache/bench/usage.json");
        let bytes = serde_json::to_vec_pretty(self).map_err(|source| WorkspaceError::Json {
            path: path.clone(),
            source: Box::new(source),
        })?;
        crate::write_atomic(&path, &bytes).map_err(|source| WorkspaceError::Io { path, source })
    }
}
