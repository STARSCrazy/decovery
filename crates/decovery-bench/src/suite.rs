//! Suite records and validation against native identical rebuilds.
use super::{BenchError, io};
use decovery_core::{RebuildRecord, VerdictId, Workspace, read_rebuild};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum StartPoint {
    #[default]
    Stub,
    PseudoC,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ToolSet {
    #[default]
    Core,
    #[serde(alias = "core+legacy")]
    CoreLegacy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct TaskDefaults {
    pub start: StartPoint,
    pub tools: ToolSet,
    pub max_builds: u32,
    pub max_tool_calls: u32,
    pub max_searches: u32,
    pub wall_minutes: u32,
    pub max_tokens: Option<u64>,
    pub max_cost_usd: Option<f64>,
    pub prompt: Option<PathBuf>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, toml::Value>,
}
impl Default for TaskDefaults {
    fn default() -> Self {
        Self {
            start: StartPoint::Stub,
            tools: ToolSet::Core,
            max_builds: 40,
            max_tool_calls: 120,
            max_searches: 0,
            wall_minutes: 15,
            max_tokens: None,
            max_cost_usd: Some(3.0),
            prompt: None,
            extra: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SuiteTask {
    #[serde(default)]
    pub id: String,
    pub workspace: PathBuf,
    pub function: String,
    #[serde(default)]
    pub start: Option<StartPoint>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, toml::Value>,
}
impl SuiteTask {
    pub fn new(workspace: PathBuf, function: impl Into<String>) -> Self {
        let function = function.into();
        let name = workspace
            .file_name()
            .unwrap_or(workspace.as_os_str())
            .to_string_lossy();
        Self {
            id: format!("{name}/{function}"),
            workspace,
            function,
            start: None,
            tags: Vec::new(),
            extra: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Suite {
    pub schema: u32,
    pub name: String,
    #[serde(default)]
    pub defaults: TaskDefaults,
    #[serde(rename = "task")]
    pub tasks: Vec<SuiteTask>,
    #[serde(skip)]
    pub dir: PathBuf,
    #[serde(flatten)]
    pub extra: BTreeMap<String, toml::Value>,
}

pub fn read_suite(path: &Path) -> Result<Suite, BenchError> {
    let path = super::canonical(path)?;
    let invalid = |reason: String| BenchError::Suite {
        path: path.clone(),
        reason,
    };
    let text = std::fs::read_to_string(&path).map_err(|e| io(&path, e))?;
    let value: toml::Value = toml::from_str(&text).map_err(|e| invalid(e.to_string()))?;
    let mut suite: Suite = value
        .clone()
        .try_into()
        .map_err(|e: toml::de::Error| invalid(e.to_string()))?;
    if suite.schema != 1 {
        return Err(invalid(format!(
            "unsupported schema {} (expected 1)",
            suite.schema
        )));
    }
    if suite.name.trim().is_empty() {
        return Err(invalid("name must not be empty".into()));
    }
    if suite
        .defaults
        .max_cost_usd
        .is_some_and(|cost| !cost.is_finite() || cost < 0.0)
    {
        return Err(invalid(
            "max_cost_usd must be finite and nonnegative".into(),
        ));
    }
    suite.dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();
    if value
        .get("defaults")
        .and_then(|d| d.get("max_searches"))
        .is_none()
    {
        suite.defaults.max_searches = if suite.defaults.tools == ToolSet::CoreLegacy {
            2
        } else {
            0
        };
    }
    if let Some(prompt) = &mut suite.defaults.prompt {
        *prompt = suite.dir.join(&*prompt);
    }
    let mut ids = BTreeSet::new();
    for task in &mut suite.tasks {
        task.workspace = super::canonical(&suite.dir.join(&task.workspace))
            .map_err(|e| invalid(format!("task {}: workspace: {e}", task.function)))?;
        if task.id.is_empty() {
            task.id = SuiteTask::new(task.workspace.clone(), &task.function).id;
        }
        if !ids.insert(task.id.clone()) {
            return Err(invalid(format!("duplicate task id {:?}", task.id)));
        }
        selected(task).map_err(|e| invalid(e.to_string()))?;
    }
    Ok(suite)
}

pub(crate) struct Selected {
    pub workspace: Workspace,
    pub record: RebuildRecord,
    pub file: String,
    pub path: PathBuf,
    pub text: String,
}

pub(crate) fn selected(task: &SuiteTask) -> Result<Selected, BenchError> {
    let invalid = |reason: String| BenchError::Copy {
        task: task.id.clone(),
        reason,
    };
    let root = super::canonical(&task.workspace)?;
    let workspace = Workspace::open(&root)?;
    let address = task
        .function
        .parse::<decovery_core::Address>()
        .ok()
        .or_else(|| {
            workspace
                .symbols
                .iter()
                .find(|s| {
                    s.name == task.function && s.confidence != decovery_core::Confidence::Refuted
                })
                .map(|s| s.address)
        });
    let records: Vec<_> = read_rebuild(&root)?
        .into_iter()
        .filter(|r| r.name == task.function || Some(r.address) == address)
        .collect();
    let record = match records.as_slice() {
        [r] if r.verdict == Some(VerdictId::Identical) => r.clone(),
        _ => {
            return Err(invalid(format!(
                "{} must have exactly one native identical rebuild record",
                task.function
            )));
        }
    };
    let file = record
        .file
        .clone()
        .ok_or_else(|| invalid("the rebuild record has no source file".into()))?;
    let relative = Path::new(&file);
    if relative
        .components()
        .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        return Err(invalid(format!("invalid source path {file:?}")));
    }
    let src = root.join("src");
    let path = super::canonical(&src.join(&file))?;
    if !path.starts_with(super::canonical(&src)?) {
        return Err(invalid("source path escapes src/".into()));
    }
    let bytes = std::fs::read(&path).map_err(|e| io(&path, e))?;
    let text = String::from_utf8(bytes.clone())
        .unwrap_or_else(|_| decovery_toolchain::from_cp437(&bytes))
        .replace("\r\n", "\n");
    if decovery_toolchain::definitions(&text)
        .iter()
        .filter(|d| d.name == record.name)
        .count()
        != 1
    {
        return Err(invalid(format!(
            "{file} must define {} exactly once",
            record.name
        )));
    }
    Ok(Selected {
        workspace,
        record,
        file,
        path,
        text,
    })
}
