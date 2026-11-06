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
