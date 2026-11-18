//! The global limit on jobs in flight (design 5.13): every runner request takes its share of `--jobs` slots before
//! it runs and returns them afterwards, so the jobs of all requests together never exceed the limit, and each
//! request stays within its provider's declared `max_parallel`.

use std::sync::{Arc, Condvar, Mutex, OnceLock};

/// A fixed number of job slots shared by all runner requests of the process.
#[derive(Debug)]
pub struct JobSlots {
    total: u32,
    free: Mutex<u32>,
    freed: Condvar,
}

impl JobSlots {
    /// `total` slots (at least 1).
    pub fn new(total: u32) -> Arc<Self> {
        let total = total.max(1);
        Arc::new(JobSlots {
            total,
            free: Mutex::new(total),
            freed: Condvar::new(),
        })
    }

    pub fn total(&self) -> u32 {
        self.total
    }

    /// Takes up to `wanted` slots (at least 1): waits until one is free, then takes as many as are free.
    pub fn acquire(&self, wanted: u32) -> SlotGuard<'_> {
        let wanted = wanted.max(1);
        let mut free = self.free.lock().unwrap_or_else(|p| p.into_inner());
        while *free == 0 {
            free = self.freed.wait(free).unwrap_or_else(|p| p.into_inner());
        }
        let count = wanted.min(*free);
        *free -= count;
        SlotGuard { slots: self, count }
    }

    fn release(&self, count: u32) {
        let mut free = self.free.lock().unwrap_or_else(|p| p.into_inner());
        *free = (*free + count).min(self.total);
        self.freed.notify_all();
    }
}

/// Slots taken by one request; returned when dropped.
#[derive(Debug)]
pub struct SlotGuard<'a> {
    slots: &'a JobSlots,
    count: u32,
}

impl SlotGuard<'_> {
    /// How many jobs the request may run at once.
    pub fn count(&self) -> u32 {
        self.count
    }
}

impl Drop for SlotGuard<'_> {
    fn drop(&mut self) {
        self.slots.release(self.count);
    }
}

/// One compile job on the build's clock (milliseconds since the build started): runnable from `queued_ms` (its
/// request was sent), running from `start_ms` to `end_ms`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobSpan {
    pub queued_ms: u64,
    pub start_ms: u64,
    pub end_ms: u64,
}

/// How well a build used its job slots (plan decision 5).
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct Throughput {
    /// Serial time (wall outside the compile phase) plus the larger of the longest job and the jobs' wall time
    /// spread over the slots.
    pub lower_bound_ms: u64,
    /// Busy job time over `slots` x time, counted only while at least `slots` jobs are runnable (queued or
    /// running) and from the first job start on (worker start-up is excluded); `None` when that never happens.
    pub saturation: Option<f64>,
    /// `lower_bound_ms` / wall time (1 when the wall time is 0).
    pub efficiency: f64,
}

/// The throughput of a build of `wall_ms` whose compile phase took `compile_ms`, with `slots` jobs at once.
pub fn throughput(jobs: &[JobSpan], slots: u32, wall_ms: u64, compile_ms: u64) -> Throughput {
    let slots = u64::from(slots.max(1));
    let serial = wall_ms.saturating_sub(compile_ms);
    let length = |j: &JobSpan| j.end_ms.saturating_sub(j.start_ms);
    let longest = jobs.iter().map(length).max().unwrap_or(0);
    let spread = jobs.iter().map(length).sum::<u64>().div_ceil(slots);
    let lower_bound_ms = serial + longest.max(spread);

    let mut edges: Vec<u64> = jobs
        .iter()
        .flat_map(|j| [j.queued_ms, j.start_ms, j.end_ms])
        .collect();
    edges.sort_unstable();
    edges.dedup();
    // Worker start-up (request sent until the first job starts) is not counted (owner decision 5, 2026-11-18).
    let first_start = jobs.iter().map(|j| j.start_ms).min().unwrap_or(0);
    let (mut busy, mut offered) = (0u64, 0u64);
    for pair in edges.windows(2) {
        let (from, to) = (pair[0], pair[1]);
        if from < first_start {
            continue;
        }
        let alive = |j: &&JobSpan| j.end_ms > from;
        let runnable = jobs
            .iter()
            .filter(alive)
            .filter(|j| j.queued_ms <= from)
            .count() as u64;
        if runnable < slots {
            continue;
        }
        let running = jobs
            .iter()
            .filter(alive)
            .filter(|j| j.start_ms <= from)
            .count() as u64;
        busy += running.min(slots) * (to - from);
        offered += slots * (to - from);
    }
    Throughput {
        lower_bound_ms,
        saturation: (offered > 0).then(|| busy as f64 / offered as f64),
        efficiency: if wall_ms == 0 {
            1.0
        } else {
            lower_bound_ms as f64 / wall_ms as f64
        },
    }
}

static GLOBAL: OnceLock<Arc<JobSlots>> = OnceLock::new();

/// The number of logical cores (1 when unknown): the default of `--jobs`.
pub fn default_jobs() -> u32 {
    std::thread::available_parallelism()
        .map(|n| u32::try_from(n.get()).unwrap_or(u32::MAX))
        .unwrap_or(1)
}

/// Sets the process-wide limit (`--jobs`). Only the first call before any runner request counts; returns whether
/// this one did.
pub fn set_global_jobs(jobs: u32) -> bool {
    GLOBAL.set(JobSlots::new(jobs)).is_ok()
}

/// The process-wide slots: `--jobs` when set, else [`default_jobs`].
pub fn global_slots() -> Arc<JobSlots> {
    GLOBAL.get_or_init(|| JobSlots::new(default_jobs())).clone()
}
