//! Rough time remaining based on completed objects, not allocated bytes.
//! Waiting for a human lock decision is excluded from the rate estimate.
use std::time::{Duration, Instant};

pub(super) struct DeleteEta {
    started: Instant,
    last_sample: Option<(Instant, u64)>,
    last_progress: Option<Instant>,
    recent_rate: Option<f64>,
    paused_at: Option<Instant>,
    paused_total: Duration,
}

impl DeleteEta {
    pub(super) fn new(now: Instant) -> Self {
        Self {
            started: now,
            last_sample: None,
            last_progress: None,
            recent_rate: None,
            paused_at: None,
            paused_total: Duration::ZERO,
        }
    }

    fn active_elapsed(&self, now: Instant) -> Duration {
        let until = self.paused_at.unwrap_or(now);
        until
            .duration_since(self.started)
            .saturating_sub(self.paused_total)
    }

    pub(super) fn pause(&mut self, now: Instant) {
        if self.paused_at.is_none() {
            self.paused_at = Some(now);
        }
    }

    pub(super) fn resume(&mut self, now: Instant) {
        if let Some(paused) = self.paused_at.take() {
            self.paused_total += now.duration_since(paused);
            self.last_sample = None; // Never count a human decision as slow file processing.
            self.last_progress = Some(now);
        }
    }

    pub(super) fn is_stalled(&self, now: Instant) -> bool {
        self.paused_at.is_none()
            && self
                .last_progress
                .is_some_and(|last| now.duration_since(last) > Duration::from_secs(5))
    }

    pub(super) fn observe(&mut self, now: Instant, done: u64, total: u64) -> String {
        if self.paused_at.is_some() {
            return String::new();
        }
        if total == 0 || done >= total {
            return String::new();
        }
        let active = self.active_elapsed(now).as_secs_f64();
        if let Some((previous, previous_done)) = self.last_sample
            && done > previous_done
        {
            let seconds = now.duration_since(previous).as_secs_f64();
            if seconds >= 0.4 {
                let sample = (done - previous_done) as f64 / seconds;
                self.recent_rate = Some(match self.recent_rate {
                    Some(rate) => 0.7 * rate + 0.3 * sample,
                    None => sample,
                });
            }
        }
        if self
            .last_sample
            .is_none_or(|(_, previous_done)| done > previous_done)
        {
            self.last_sample = Some((now, done));
        }
        self.last_progress = Some(now);
        if done == 0 || active < 1.0 {
            return String::new();
        }
        let average = done as f64 / active;
        let rate = match self.recent_rate {
            Some(recent) => 0.7 * average + 0.3 * recent.clamp(average / 3.0, average * 3.0),
            None => average,
        };
        let seconds = (total - done) as f64 / rate;
        format_duration(seconds)
    }
}

fn format_duration(seconds: f64) -> String {
    if !seconds.is_finite() || seconds <= 0.0 {
        return String::new();
    }
    if seconds < 10.0 {
        return "<10s".into();
    }
    // An estimate, not a clock: round up rather than imply second-level accuracy.
    let rounded = (seconds / 5.0).ceil() as u64 * 5;
    if rounded >= 86_400 {
        format!(">{}d", rounded / 86_400)
    } else if rounded >= 3_600 {
        format!("{}h {}m", rounded / 3_600, (rounded % 3_600) / 60)
    } else if rounded >= 60 {
        format!("{}m {}s", rounded / 60, rounded % 60)
    } else {
        format!("{rounded}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_after_progress() {
        let start = Instant::now();
        let mut eta = DeleteEta::new(start);
        assert_eq!(eta.observe(start, 0, 100), "");
        assert_eq!(eta.observe(start + Duration::from_secs(2), 10, 100), "20s");
        assert_eq!(eta.observe(start + Duration::from_secs(4), 20, 100), "20s");
    }

    #[test]
    fn lock_wait_does_not_extend_eta() {
        let start = Instant::now();
        let mut eta = DeleteEta::new(start);
        eta.observe(start + Duration::from_secs(2), 10, 100);
        eta.pause(start + Duration::from_secs(2));
        assert_eq!(eta.observe(start + Duration::from_secs(62), 10, 100), "");
        eta.resume(start + Duration::from_secs(62));
        let label = eta.observe(start + Duration::from_secs(64), 20, 100);
        assert_eq!(label, "20s");
    }

    #[test]
    fn stalled_and_short_jobs_do_not_promise_a_countdown() {
        let start = Instant::now();
        let mut eta = DeleteEta::new(start);
        assert!(!eta.is_stalled(start + Duration::from_secs(10)));
        eta.observe(start + Duration::from_secs(1), 1, 2);
        assert!(eta.is_stalled(start + Duration::from_secs(7)));
        eta.pause(start + Duration::from_secs(7));
        assert!(!eta.is_stalled(start + Duration::from_secs(8)));
    }
}
