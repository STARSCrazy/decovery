//! Run reports and run-to-run comparison.

use crate::run::{RunRecord, TaskResult};
use crate::stats::{
    bootstrap_mean_difference, bootstrap_paired_difference, mean_of, median, newcombe_difference,
    wilson,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

const RESAMPLES: u32 = 2000;
const SEED: u64 = 0x5eed;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GroupBy {
    None,
    Workspace,
    Profile,
    Tag,
}

/// Mean and median of one metric over the tasks that have a value for it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MetricSummary {
    pub n: u32,
    pub mean: f64,
    pub median: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GroupReport {
    pub name: String,
    pub tasks: u32,
    pub solved: u32,
    pub success_rate: f64,
    pub success_low: f64,
    pub success_high: f64,
    pub builds: Option<MetricSummary>,
    pub tool_calls: Option<MetricSummary>,
    pub input_tokens: Option<MetricSummary>,
    pub output_tokens: Option<MetricSummary>,
    pub cost_usd: Option<MetricSummary>,
    pub wall_s: Option<MetricSummary>,
    /// Best distance of the unsolved tasks only.
    pub best_distance_unsolved: Option<MetricSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Report {
    pub run: String,
    pub suite: String,
    pub state: String,
    pub driver: String,
    pub model: Option<String>,
    pub tools: String,
    /// Tasks never started (`not-run`), left out of every statistic.
    pub not_run: u32,
    /// Tasks stopped by the subscription's usage limit (`quota`), left out of every statistic.
    pub quota: u32,
    pub groups: Vec<GroupReport>,
    /// Calls per tool over the included tasks (information only).
    pub calls_by_tool: BTreeMap<String, u32>,
}

fn included(task: &TaskResult) -> bool {
    !matches!(task.exit.as_str(), "not-run" | "quota")
}

type Getter = fn(&TaskResult) -> Option<f64>;

const METRICS: [(&str, Getter); 8] = [
    ("solved", |t| Some(if t.solved { 1.0 } else { 0.0 })),
    ("builds", |t| Some(f64::from(t.builds))),
    ("tool_calls", |t| Some(f64::from(t.tool_calls))),
    ("input_tokens", |t| t.input_tokens.map(|v| v as f64)),
    ("output_tokens", |t| t.output_tokens.map(|v| v as f64)),
    ("cost_usd", |t| t.cost_usd),
    ("wall_s", |t| Some(t.wall_s)),
    ("best_distance_unsolved", |t| {
        if t.solved {
            None
        } else {
            t.best_distance.map(|v| v as f64)
        }
    }),
];

fn summary(tasks: &[&TaskResult], get: Getter) -> Option<MetricSummary> {
    let values: Vec<f64> = tasks.iter().filter_map(|t| get(t)).collect();
    (!values.is_empty()).then(|| MetricSummary {
        n: values.len() as u32,
        mean: mean_of(&values),
        median: median(&values),
    })
}

fn group_report(name: String, tasks: &[&TaskResult]) -> GroupReport {
    let solved = tasks.iter().filter(|t| t.solved).count() as u32;
    let n = tasks.len() as u32;
    let (success_low, success_high) = wilson(solved, n);
    GroupReport {
        name,
        tasks: n,
        solved,
        success_rate: if n == 0 {
            0.0
        } else {
            f64::from(solved) / f64::from(n)
        },
        success_low,
        success_high,
        builds: summary(tasks, METRICS[1].1),
        tool_calls: summary(tasks, METRICS[2].1),
        input_tokens: summary(tasks, METRICS[3].1),
        output_tokens: summary(tasks, METRICS[4].1),
        cost_usd: summary(tasks, METRICS[5].1),
        wall_s: summary(tasks, METRICS[6].1),
        best_distance_unsolved: summary(tasks, METRICS[7].1),
    }
}

/// Success rate with a Wilson interval and medians/means of the cost metrics, per group. A task is counted in
/// each of its tags (or `(untagged)`); groups are sorted by name. `not-run` and `quota` tasks are left out.
pub fn report(run: &RunRecord, group_by: GroupBy) -> Report {
    let tasks: Vec<&TaskResult> = run.tasks.iter().filter(|t| included(t)).collect();
    let mut groups: BTreeMap<String, Vec<&TaskResult>> = BTreeMap::new();
    for task in &tasks {
        let keys: Vec<String> = match group_by {
            GroupBy::None => vec!["all".into()],
            GroupBy::Workspace => vec![task.workspace.clone()],
            GroupBy::Profile => vec![task.profile.clone()],
            GroupBy::Tag if task.tags.is_empty() => vec!["(untagged)".into()],
            GroupBy::Tag => task
                .tags
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        };
        for key in keys {
            groups.entry(key).or_default().push(task);
        }
    }
    if groups.is_empty() && group_by == GroupBy::None {
        groups.insert("all".into(), Vec::new());
    }
    let mut calls_by_tool = BTreeMap::new();
    for task in &tasks {
        for (tool, count) in &task.calls_by_tool {
            *calls_by_tool.entry(tool.clone()).or_insert(0) += count;
        }
    }
    Report {
        run: run.id.clone(),
        suite: run.suite.clone(),
        state: run.state.clone(),
        driver: run.driver.clone(),
        model: run.model.clone(),
        tools: run.tools.clone(),
        not_run: run.tasks.iter().filter(|t| t.exit == "not-run").count() as u32,
        quota: run.tasks.iter().filter(|t| t.exit == "quota").count() as u32,
        groups: groups
            .into_iter()
            .map(|(name, tasks)| group_report(name, &tasks))
            .collect(),
        calls_by_tool,
    }
}

fn cell(m: &Option<MetricSummary>, precision: usize) -> String {
    m.as_ref().map_or("-".into(), |m| {
        format!("{:.p$}/{:.p$}", m.median, m.mean, p = precision)
    })
}

impl Report {
    /// A table (cells are `median/mean`) plus the left-out counts and the calls per tool.
    pub fn to_text(&self) -> String {
        let mut out = format!(
            "run {} of suite {} ({}), driver {}, model {}, tools {}\n",
            self.run,
            self.suite,
            self.state,
            self.driver,
            self.model.as_deref().unwrap_or("-"),
            self.tools
        );
        let _ = writeln!(
            out,
            "{:<20} {:>7} {:>22} {:>9} {:>9} {:>13} {:>11} {:>9} {:>9}",
            "group",
            "solved",
            "rate [95 % CI]",
            "builds",
            "calls",
            "tokens in",
            "tokens out",
            "cost $",
            "wall s"
        );
        for g in &self.groups {
            let _ = writeln!(
                out,
                "{:<20} {:>7} {:>22} {:>9} {:>9} {:>13} {:>11} {:>9} {:>9}",
                g.name,
                format!("{}/{}", g.solved, g.tasks),
                format!(
                    "{:.3} [{:.3}, {:.3}]",
                    g.success_rate, g.success_low, g.success_high
                ),
                cell(&g.builds, 1),
                cell(&g.tool_calls, 1),
                cell(&g.input_tokens, 0),
                cell(&g.output_tokens, 0),
                cell(&g.cost_usd, 2),
                cell(&g.wall_s, 1),
            );
        }
        out.push_str("cells: median/mean\n");
        if self.not_run > 0 || self.quota > 0 {
            let _ = writeln!(
                out,
                "left out: {} not run, {} stopped by the usage limit",
                self.not_run, self.quota
            );
        }
        if !self.calls_by_tool.is_empty() {
            let calls: Vec<String> = self
                .calls_by_tool
                .iter()
                .map(|(tool, n)| format!("{tool} {n}"))
                .collect();
            let _ = writeln!(out, "calls per tool: {}", calls.join(", "));
        }
        out
    }
}

/// One metric's change from run A to run B (`difference` = B minus A) with a 95 % interval.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MetricComparison {
    pub name: String,
    pub n_a: u32,
    pub n_b: u32,
    pub mean_a: f64,
    pub mean_b: f64,
    pub difference: f64,
    pub low: f64,
    pub high: f64,
    /// The interval does not contain 0.
    pub excludes_zero: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RunComparison {
    pub a: String,
    pub b: String,
    /// Both runs hold the same (task, repeat) pairs, so differences are taken per task.
    pub paired: bool,
    /// The exemplar setting of run A and run B.
    #[serde(default = "default_true")]
    pub exemplars_a: bool,
    #[serde(default = "default_true")]
    pub exemplars_b: bool,
    pub warnings: Vec<String>,
    pub metrics: Vec<MetricComparison>,
    /// Names of the metrics whose interval excludes 0.
    pub differing: Vec<String>,
    /// Every interval contains 0.
    pub consistent: bool,
}

fn on_off(enabled: bool) -> &'static str {
    if enabled { "on" } else { "off" }
}

fn default_true() -> bool {
    true
}

type TaskKey<'a> = (&'a str, u32);
type Keyed<'a> = BTreeMap<TaskKey<'a>, &'a TaskResult>;

fn keyed(run: &RunRecord) -> Keyed<'_> {
    run.tasks
        .iter()
        .filter(|t| included(t))
        .map(|t| ((t.id.as_str(), t.repeat), t))
        .collect()
}

fn mean_or_zero(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        mean_of(values)
    }
}

/// Compare two runs metric by metric (solved: Newcombe interval, or the paired bootstrap when paired; the rest:
/// bootstrap, 2 000 resamples, splitmix64 seeded with 0x5eed, 2.5 / 97.5 percentiles). `not-run` and `quota`
/// tasks are left out; a metric one run has no values for is skipped.
pub fn compare(a: &RunRecord, b: &RunRecord) -> RunComparison {
    let (ka, kb) = (keyed(a), keyed(b));
    let paired = !ka.is_empty() && ka.keys().eq(kb.keys());
    let mut warnings = Vec::new();
    if a.tools != b.tools {
        warnings.push(format!("tools differ: {} vs {}", a.tools, b.tools));
    }
    if a.exemplars != b.exemplars {
        warnings.push(format!(
            "exemplars differ: {} vs {}",
            on_off(a.exemplars),
            on_off(b.exemplars)
        ));
    }
    if a.driver != b.driver {
        warnings.push(format!("driver differs: {} vs {}", a.driver, b.driver));
    }
    if a.model != b.model {
        warnings.push(format!(
            "model differs: {} vs {}",
            a.model.as_deref().unwrap_or("-"),
            b.model.as_deref().unwrap_or("-")
        ));
    }
    if a.suite != b.suite {
        warnings.push(format!("suite differs: {} vs {}", a.suite, b.suite));
    }
    if !paired {
        warnings.push("the runs hold different tasks: unpaired comparison".into());
    }
    let mut metrics = Vec::new();
    for (name, get) in METRICS {
        let values = |m: &Keyed| -> Vec<f64> { m.values().filter_map(|t| get(t)).collect() };
        let (va, vb) = (values(&ka), values(&kb));
        if va.is_empty() || vb.is_empty() {
            continue;
        }
        // The `bootstrap_*` functions give first minus second, so B goes first for B minus A.
        let (difference, low, high) = if paired {
            let (pa, pb): (Vec<f64>, Vec<f64>) = ka
                .iter()
                .filter_map(|(key, ta)| Some((get(ta)?, get(kb.get(key)?)?)))
                .unzip();
            bootstrap_paired_difference(&pb, &pa, RESAMPLES, SEED)
        } else if name == "solved" {
            let solved = |m: &Keyed| m.values().filter(|t| t.solved).count() as u32;
            newcombe_difference(solved(&kb), kb.len() as u32, solved(&ka), ka.len() as u32)
        } else {
            bootstrap_mean_difference(&vb, &va, RESAMPLES, SEED)
        };
        metrics.push(MetricComparison {
            name: name.into(),
            n_a: va.len() as u32,
            n_b: vb.len() as u32,
            mean_a: mean_or_zero(&va),
            mean_b: mean_or_zero(&vb),
            difference,
            low,
            high,
            excludes_zero: low > 0.0 || high < 0.0,
        });
    }
    let differing: Vec<String> = metrics
        .iter()
        .filter(|m| m.excludes_zero)
        .map(|m| m.name.clone())
        .collect();
    RunComparison {
        a: a.id.clone(),
        b: b.id.clone(),
        exemplars_a: a.exemplars,
        exemplars_b: b.exemplars,
        paired,
        warnings,
        metrics,
        consistent: differing.is_empty(),
        differing,
    }
}

impl RunComparison {
    /// Warnings, one table row per metric and the verdict line.
    pub fn to_text(&self) -> String {
        let mut out = format!(
            "compare {} (A) with {} (B), {}; difference = B minus A\n",
            self.a,
            self.b,
            if self.paired {
                "paired by task"
            } else {
                "unpaired"
            }
        );
        let _ = writeln!(
            out,
            "exemplars: A {}, B {}",
            on_off(self.exemplars_a),
            on_off(self.exemplars_b)
        );
        for w in &self.warnings {
            let _ = writeln!(out, "warning: {w}");
        }
        let _ = writeln!(
            out,
            "{:<24} {:>12} {:>12} {:>12} {:>24}",
            "metric", "mean A", "mean B", "difference", "95 % interval"
        );
        for m in &self.metrics {
            let _ = writeln!(
                out,
                "{:<24} {:>12.3} {:>12.3} {:>+12.3} {:>24}{}",
                m.name,
                m.mean_a,
                m.mean_b,
                m.difference,
                format!("[{:+.3}, {:+.3}]", m.low, m.high),
                if m.excludes_zero { "  *" } else { "" }
            );
        }
        if self.consistent {
            out.push_str("consistent within noise\n");
        } else {
            let _ = writeln!(
                out,
                "interval excludes 0 for: {}",
                self.differing.join(", ")
            );
        }
        out
    }
}
