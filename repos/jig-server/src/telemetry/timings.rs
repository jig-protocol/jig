//! Timings histograms for runtime phases (feature: telemetry_v0_2).
//! Records queue_wait, init, exec, total (milliseconds) into HDR histograms
//! and provides percentile snapshots for observability and metrics.

use hdrhistogram::Histogram;
use std::sync::Mutex;

/// Common percentile set for dashboards/alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Percentiles {
    pub p50: u64,
    pub p95: u64,
    pub p99: u64,
}

impl Default for TimingsRecorder {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of all phase histograms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimingsSnapshot {
    pub samples: u64,
    pub queue_wait: Percentiles,
    pub init: Percentiles,
    pub exec: Percentiles,
    pub total: Percentiles,
}

/// Recorder for timing phases using HDR histograms.
pub struct TimingsRecorder {
    queue_wait: Mutex<Histogram<u64>>,
    init: Mutex<Histogram<u64>>,
    exec: Mutex<Histogram<u64>>,
    total: Mutex<Histogram<u64>>,
}

impl TimingsRecorder {
    /// Create recorder with sensible bounds (1ms..=10m), 3 significant digits.
    pub fn new() -> Self {
        let make_hist = || Histogram::<u64>::new_with_bounds(1, 10 * 60 * 1000, 3).expect("hist");
        Self {
            queue_wait: Mutex::new(make_hist()),
            init: Mutex::new(make_hist()),
            exec: Mutex::new(make_hist()),
            total: Mutex::new(make_hist()),
        }
    }

    /// Record a single execution timing sample (milliseconds).
    /// `total` will be computed as saturating `init + exec`.
    pub fn record(&self, queue_wait_ms: u32, init_ms: u32, exec_ms: u32) {
        let qw = queue_wait_ms as u64;
        let init = init_ms as u64;
        let exec = exec_ms as u64;
        let total = init.saturating_add(exec);

        if qw > 0 {
            // 0s are noise for queue wait; skip to keep signal crisp
            let _ = self.queue_wait.lock().unwrap().record(qw);
        }
        let _ = self.init.lock().unwrap().record(init);
        let _ = self.exec.lock().unwrap().record(exec);
        let _ = self.total.lock().unwrap().record(total);
    }

    /// Return latest percentile snapshot across all phases.
    pub fn snapshot(&self) -> TimingsSnapshot {
        let q = self.queue_wait.lock().unwrap();
        let i = self.init.lock().unwrap();
        let e = self.exec.lock().unwrap();
        let t = self.total.lock().unwrap();

        // Use exec histogram as sample count proxy (others should be identical cardinality)
        let samples = e.len();

        TimingsSnapshot {
            samples,
            queue_wait: pset(&q),
            init: pset(&i),
            exec: pset(&e),
            total: pset(&t),
        }
    }
}

fn pset(h: &Histogram<u64>) -> Percentiles {
    if h.is_empty() {
        return Percentiles {
            p50: 0,
            p95: 0,
            p99: 0,
        };
    }
    Percentiles {
        p50: h.value_at_quantile(0.50),
        p95: h.value_at_quantile(0.95),
        p99: h.value_at_quantile(0.99),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_exec_distribution_and_reports_percentiles() {
        let r = TimingsRecorder::new();
        // Heavily skewed: majority fast, few slow
        for _ in 0..20 {
            r.record(0, 5, 10);
        }
        for _ in 0..3 {
            r.record(0, 5, 1000);
        }

        let snap = r.snapshot();
        assert!(snap.samples >= 23);
        // p50 stays low
        assert!(snap.exec.p50 <= 15);
        // High tail reflected in p95/p99
        assert!(snap.exec.p95 >= 900);
        assert!(snap.exec.p99 >= 900);
        // total ~= init + exec at percentiles
        assert!(snap.total.p50 >= snap.exec.p50);
    }

    #[test]
    fn zero_snapshot_when_empty() {
        let r = TimingsRecorder::new();
        let snap = r.snapshot();
        assert_eq!(snap.samples, 0);
        assert_eq!(
            snap.exec,
            Percentiles {
                p50: 0,
                p95: 0,
                p99: 0
            }
        );
    }
}
