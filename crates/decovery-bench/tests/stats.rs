//! Statistics, reports and run comparison (no driver, no workspace: run records are built from JSON).

use decovery_bench::{
    GroupBy, RunRecord, bootstrap_mean_difference, bootstrap_paired_difference, compare,
    newcombe_difference, report, wilson,
};
use serde_json::{Value, json};

fn close(a: f64, b: f64) -> bool {
    (a - b).abs() < 5e-5
}

#[test]
fn wilson_matches_reference_values() {
    for (s, n, lo, hi) in [
        (0, 10, 0.0, 0.2775),
        (5, 10, 0.2366, 0.7634),
        (10, 10, 0.7225, 1.0),
        (37, 50, 0.6045, 0.8413),
    ] {
        let (l, h) = wilson(s, n);
        assert!(close(l, lo) && close(h, hi), "{s}/{n}: {l} {h}");
    }
}

#[test]
fn wilson_of_nothing_is_the_whole_range() {
    assert_eq!(wilson(0, 0), (0.0, 1.0));
    assert_eq!(wilson(5, 3), wilson(3, 3), "successes are capped at n");
}

#[test]
fn newcombe_matches_reference_values() {
    let (d, lo, hi) = newcombe_difference(56, 70, 48, 80);
    assert!(
        close(d, 0.2) && close(lo, 0.0524) && close(hi, 0.3339),
        "{d} {lo} {hi}"
    );
    let (d, lo, hi) = newcombe_difference(0, 0, 3, 4);
    assert!(d.is_finite() && lo.is_finite() && hi.is_finite());
}

#[test]
fn bootstrap_is_deterministic() {
    let a = [1.0, 2.0, 3.0, 4.0, 10.0];
    let b = [2.0, 2.5, 3.5, 9.0];
    let first = bootstrap_mean_difference(&a, &b, 2000, 0x5eed);
    assert_eq!(first, bootstrap_mean_difference(&a, &b, 2000, 0x5eed));
    assert_ne!(first, bootstrap_mean_difference(&a, &b, 2000, 7));
    assert!(close(first.0, 4.0 - 4.25), "observed difference of means");
    assert!(first.1 <= first.0 && first.0 <= first.2);
    assert_eq!(bootstrap_mean_difference(&[], &b, 100, 1), (0.0, 0.0, 0.0));
}

fn task(id: &str, repeat: u32, solved: bool, builds: u32, tags: &[&str], exit: &str) -> Value {
    json!({
        "id": id, "repeat": repeat, "workspace": "ws", "profile": "p1", "tags": tags,
        "solved": solved, "verdict": if solved { "identical" } else { "differs" },
        "start_distance": 9, "best_distance": if solved { 0 } else { 4 },
        "builds": builds, "tool_calls": builds * 2, "searches": 0, "calls_by_tool": {"build": builds},
        "input_tokens": 100 * u64::from(builds), "output_tokens": 10, "cost_usd": 0.5 * f64::from(builds),
        "wall_s": 10.0 * f64::from(builds), "exit": exit, "log": null
    })
}

fn run(id: &str, tools: &str, tasks: Vec<Value>) -> RunRecord {
    serde_json::from_value(json!({
        "schema": 1, "id": id, "suite": "s", "started": "2026-11-17T08:00:00Z", "finished": null,
        "state": "done", "tool_version": "0", "config_hash": "h", "driver": "d", "model": "m",
        "tools": tools, "seed": 0,
        "totals": {"tasks": 0, "solved": 0, "builds": 0, "tool_calls": 0, "searches": 0, "wall_s": 0.0},
        "tasks": tasks
    }))
    .expect("run record")
}

fn sample(tools: &str, solved: [bool; 4]) -> RunRecord {
    run(
        "r",
        tools,
        (0..4)
            .map(|i| {
                task(
                    &format!("t{i}"),
                    0,
                    solved[i],
                    3 + i as u32,
                    if i < 2 { &["small"] } else { &["big", "odd"] },
                    "ok",
                )
            })
            .collect(),
    )
}

#[test]
fn paired_compare_uses_matching_tasks() {
    let a = sample("core", [true, true, false, false]);
    let b = sample("core", [true, true, true, false]);
    let c = compare(&a, &b);
    assert!(c.paired);
    let solved = c.metrics.iter().find(|m| m.name == "solved").unwrap();
    assert!(
        close(solved.difference, 0.25),
        "b - a: {}",
        solved.difference
    );
    let mut other = sample("core", [true, true, true, false]);
    other = run("r2", "core", {
        let mut t: Vec<Value> = serde_json::to_value(&other.tasks)
            .unwrap()
            .as_array()
            .unwrap()
            .clone();
        t.pop();
        t
    });
    assert!(
        !compare(&a, &other).paired,
        "different task sets are unpaired"
    );
}

#[test]
fn identical_runs_are_consistent() {
    let a = sample("core", [true, false, true, false]);
    let c = compare(&a, &a);
    assert!(c.consistent);
    assert!(c.differing.is_empty());
    assert!(c.to_text().contains("consistent within noise"));
}

#[test]
fn different_runs_name_the_metric() {
    let a = run(
        "a",
        "core",
        (0..12)
            .map(|i| task(&format!("t{i}"), 0, false, 10, &[], "ok"))
            .collect(),
    );
    let b = run(
        "b",
        "core+legacy",
        (0..12)
            .map(|i| task(&format!("t{i}"), 0, true, 2, &[], "ok"))
            .collect(),
    );
    let c = compare(&a, &b);
    assert!(!c.consistent);
    for name in ["solved", "builds", "wall_s"] {
        assert!(
            c.differing.iter().any(|d| d == name),
            "{name} in {:?}",
            c.differing
        );
    }
    let text = c.to_text();
    assert!(text.contains("builds") && !text.contains("consistent within noise"));
    assert!(
        c.warnings.iter().any(|w| w.contains("tools")),
        "{:?}",
        c.warnings
    );
}

#[test]
fn report_groups_by_tag() {
    let r = sample("core", [true, false, true, true]);
    let rep = report(&r, GroupBy::Tag);
    let names: Vec<_> = rep.groups.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, ["big", "odd", "small"]);
    let small = &rep.groups[2];
    assert_eq!((small.tasks, small.solved), (2, 1));
    assert!(close(small.success_rate, 0.5));
    assert!(small.success_low < 0.5 && small.success_high > 0.5);
    assert_eq!(
        rep.groups[0].tasks, 2,
        "a task counts in every one of its tags"
    );
    let all = report(&r, GroupBy::None);
    assert_eq!(all.groups.len(), 1);
    assert_eq!((all.groups[0].tasks, all.groups[0].solved), (4, 3));
    assert_eq!(report(&r, GroupBy::Profile).groups[0].name, "p1");
    assert_eq!(report(&r, GroupBy::Workspace).groups[0].name, "ws");
    assert!(all.to_text().contains("3/4"));
}

#[test]
fn not_run_tasks_are_left_out() {
    let r = run(
        "r",
        "core",
        vec![
            task("a", 0, true, 2, &[], "ok"),
            task("b", 0, false, 0, &[], "not-run"),
            task("c", 0, false, 0, &[], "quota"),
            task("d", 0, false, 4, &[], "timeout"),
        ],
    );
    let rep = report(&r, GroupBy::None);
    assert_eq!((rep.not_run, rep.quota), (1, 1));
    assert_eq!((rep.groups[0].tasks, rep.groups[0].solved), (2, 1));
    let builds = rep.groups[0].builds.as_ref().unwrap();
    assert_eq!(builds.n, 2);
    assert!(close(builds.mean, 3.0) && close(builds.median, 3.0));
    assert_eq!(rep.calls_by_tool.get("build"), Some(&6));
    let none = report(&run("e", "core", vec![]), GroupBy::None);
    assert_eq!(none.groups[0].success_rate, 0.0);
}

#[test]
fn run_comparison_round_trips_as_json() {
    let a = sample("core", [true, false, true, false]);
    let c = compare(&a, &a);
    let text = serde_json::to_string(&c).unwrap();
    assert!(text.contains("\"metrics\""));
    serde_json::to_string(&report(&a, GroupBy::None)).unwrap();
    let _ = bootstrap_paired_difference(&[1.0], &[2.0], 10, 1);
}

#[test]
fn run_record_carries_exemplar_setting() {
    // an old record without the field loads with exemplars on
    let old = sample("core", [true, false, true, false]);
    assert!(old.exemplars);
    let mut value = serde_json::to_value(&old).unwrap();
    assert_eq!(value["exemplars"], true);
    value["exemplars"] = json!(false);
    value["id"] = json!("hidden");
    let hidden: RunRecord = serde_json::from_value(value).unwrap();
    assert!(!hidden.exemplars);
    assert!(!hidden.extra.contains_key("exemplars"));
    let comparison = compare(&old, &hidden);
    assert!(
        comparison
            .warnings
            .iter()
            .any(|w| w == "exemplars differ: on vs off"),
        "{:?}",
        comparison.warnings
    );
    let text = comparison.to_text();
    assert!(text.contains("exemplars: A on, B off"), "{text}");
}
