//! Confidence intervals written out by hand (ADR 0003: no statistics crate).

const Z: f64 = 1.959_964;

/// 95 % Wilson score interval for `successes` of `n`; `(0, 1)` for `n = 0`; successes above `n` are capped.
pub fn wilson(successes: u32, n: u32) -> (f64, f64) {
    if n == 0 {
        return (0.0, 1.0);
    }
    let n = f64::from(n);
    let p = f64::from(successes).min(n) / n;
    let z2 = Z * Z;
    let denominator = 1.0 + z2 / n;
    let centre = (p + z2 / (2.0 * n)) / denominator;
    let half = Z * (p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt() / denominator;
    ((centre - half).max(0.0), (centre + half).min(1.0))
}

/// Difference of two proportions `p1 - p2` with Newcombe's hybrid score interval (method 10 of Newcombe 1998,
/// without continuity correction): `(difference, low, high)`. An empty sample contributes the full range.
pub fn newcombe_difference(s1: u32, n1: u32, s2: u32, n2: u32) -> (f64, f64, f64) {
    let rate = |s: u32, n: u32| {
        if n == 0 {
            0.5
        } else {
            f64::from(s.min(n)) / f64::from(n)
        }
    };
    let (p1, p2) = (rate(s1, n1), rate(s2, n2));
    let (l1, u1) = wilson(s1, n1);
    let (l2, u2) = wilson(s2, n2);
    let difference = p1 - p2;
    let low = difference - ((p1 - l1).powi(2) + (u2 - p2).powi(2)).sqrt();
    let high = difference + ((u1 - p1).powi(2) + (p2 - l2).powi(2)).sqrt();
    (difference, low.max(-1.0), high.min(1.0))
}

/// splitmix64, so a seed gives the same resamples on every platform.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn index(&mut self, len: usize) -> usize {
        (self.next() % len as u64) as usize
    }
}

fn mean(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len() as f64
}

fn resampled_mean(values: &[f64], rng: &mut SplitMix64) -> f64 {
    (0..values.len())
        .map(|_| values[rng.index(values.len())])
        .sum::<f64>()
        / values.len() as f64
}

/// 2.5 / 97.5 percentile interval of the sorted resample statistics.
fn percentile_interval(mut samples: Vec<f64>) -> (f64, f64) {
    samples.sort_by(f64::total_cmp);
    let n = samples.len();
    let low = samples[(n as f64 * 0.025) as usize];
    let high = samples[((n as f64 * 0.975).ceil() as usize).clamp(1, n) - 1];
    (low, high)
}

/// Mean of `a` minus mean of `b` with a bootstrap percentile interval over independent samples:
/// `(difference, low, high)`. Empty input gives `(0, 0, 0)`.
pub fn bootstrap_mean_difference(
    a: &[f64],
    b: &[f64],
    resamples: u32,
    seed: u64,
) -> (f64, f64, f64) {
    if a.is_empty() || b.is_empty() || resamples == 0 {
        return (0.0, 0.0, 0.0);
    }
    let mut rng = SplitMix64(seed);
    let samples = (0..resamples)
        .map(|_| resampled_mean(a, &mut rng) - resampled_mean(b, &mut rng))
        .collect();
    let (low, high) = percentile_interval(samples);
    (mean(a) - mean(b), low, high)
}

/// Like [`bootstrap_mean_difference`] for paired samples (`a[i]` and `b[i]` belong together): the pairs are
/// resampled, not the two sides. Samples of different length give `(0, 0, 0)`.
pub fn bootstrap_paired_difference(
    a: &[f64],
    b: &[f64],
    resamples: u32,
    seed: u64,
) -> (f64, f64, f64) {
    if a.is_empty() || a.len() != b.len() || resamples == 0 {
        return (0.0, 0.0, 0.0);
    }
    let differences: Vec<f64> = a.iter().zip(b).map(|(x, y)| x - y).collect();
    let mut rng = SplitMix64(seed);
    let samples = (0..resamples)
        .map(|_| resampled_mean(&differences, &mut rng))
        .collect();
    let (low, high) = percentile_interval(samples);
    (mean(&differences), low, high)
}

pub(crate) fn median(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let n = sorted.len();
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    }
}

pub(crate) fn mean_of(values: &[f64]) -> f64 {
    mean(values)
}
