//! Rate pacing: turning `--rate` into a schedule the loop can actually keep.
//!
//! `--rate` is a safety control, not a knob, so pacing has two obligations that
//! pull against each other: never exceed the cap, and actually *deliver* it. The
//! second one is not free — `thread::sleep` cannot resolve the intervals that
//! high rates imply — which is what [`batch_for`] exists to resolve.

use std::time::Duration;

use jinrai_core::RunPlan;

/// The shortest tick worth sleeping on.
///
/// `thread::sleep` cannot resolve arbitrarily small durations: the syscall plus
/// the scheduler round-trip costs tens of microseconds, so asking for a 5 µs nap
/// yields something nearer 50 µs. One millisecond is comfortably above that floor
/// on every platform jinrai targets, while still being a fine enough quantum that
/// a batch is a millisecond of traffic rather than a visible slug.
pub(crate) const MIN_TICK: Duration = Duration::from_millis(1);

/// How many units to emit per tick, and how long that tick lasts, for a given
/// per-unit interval.
///
/// One unit per sleep works while the interval is longer than a sleep can
/// resolve. Below that the sleep, not `--rate`, sets the pace: at `--rate 200000`
/// the interval is 5 µs, every nap overshoots by an order of magnitude, and the
/// run tops out near 29 k/s while the summary reports "14% of the 200000/s cap" —
/// a shortfall the operator can easily read as absorbed load.
///
/// So below [`MIN_TICK`] the *tick*, not the unit, becomes the scheduling
/// quantum: emit `batch` units back-to-back, then sleep off the rest of the tick.
/// The ceiling stays exact — `batch / tick` is the requested rate by
/// construction, and no window of one tick or longer ever carries more than the
/// cap allows.
///
/// The trade is deliberate and bounded: within a tick the units leave as fast as
/// the syscalls go. That burst is at most one millisecond of traffic, it is
/// declared rather than accidental, and it is the same shape any rate-limited
/// generator produces once the requested rate exceeds what per-unit pacing can
/// deliver.
pub(crate) fn batch_for(interval: Duration) -> (u64, Duration) {
    if interval >= MIN_TICK {
        return (1, interval);
    }
    // interval > 0 here: a zero rate never reaches this code (`min_interval`
    // returns `None` and the run ends before a socket is opened).
    let batch = MIN_TICK.as_nanos().div_ceil(interval.as_nanos()).max(1);
    let batch = u64::try_from(batch).unwrap_or(u64::MAX);
    // Derive the tick from the batch rather than reusing MIN_TICK, so
    // `batch / tick` is exactly the requested rate even when the division above
    // rounded up.
    (batch, interval * u32::try_from(batch).unwrap_or(u32::MAX))
}

/// Sleep for `dur` but wake early (and return `true`) if the kill switch trips,
/// so a large inter-packet interval never delays an abort by more than ~50ms.
pub(crate) fn interruptible_sleep(dur: Duration, plan: &RunPlan) -> bool {
    let end = std::time::Instant::now() + dur;
    let chunk = Duration::from_millis(50);
    loop {
        if plan.kill.is_tripped() {
            return true;
        }
        let now = std::time::Instant::now();
        if now >= end {
            return false;
        }
        std::thread::sleep((end - now).min(chunk));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jinrai_core::RateCap;

    /// The batching arithmetic, which is what keeps `--rate` a hard ceiling.
    #[test]
    fn batching_holds_the_requested_rate_exactly() {
        // Rates a sleep can pace one unit at a time are left alone.
        for per_sec in [1u64, 10, 100, 1000] {
            let interval = RateCap::new(per_sec).min_interval().unwrap();
            let (batch, tick) = batch_for(interval);
            assert_eq!(batch, 1, "{per_sec}/s should not batch");
            assert_eq!(tick, interval, "{per_sec}/s tick should be the interval");
        }

        // Above that, the tick becomes the quantum — and `batch / tick` must
        // still be the requested rate, or the cap would be a lie in either
        // direction.
        for per_sec in [2_000u64, 20_000, 200_000, 1_000_000] {
            let interval = RateCap::new(per_sec).min_interval().unwrap();
            let (batch, tick) = batch_for(interval);
            assert!(batch > 1, "{per_sec}/s should batch");
            assert!(tick >= MIN_TICK, "{per_sec}/s tick {tick:?} must be sleepable");
            let effective = batch as f64 / tick.as_secs_f64();
            let drift = (effective - per_sec as f64).abs() / per_sec as f64;
            assert!(
                drift < 0.001,
                "{per_sec}/s batches to {batch} per {tick:?} = {effective:.1}/s"
            );
        }
    }

    /// Rates that do not divide a second evenly cannot be paced exactly, because
    /// the interval is a whole number of nanoseconds. What must still hold is the
    /// *direction* of the residual error: the cap is approached from below and
    /// never breached. (Float division rounded to nearest instead, so 3M/s paced
    /// at 333ns and delivered 3.003M/s — above the ceiling the operator set.)
    #[test]
    fn awkward_rates_stay_under_the_ceiling() {
        // Rates chosen where one nanosecond of rounding is still well under 1%;
        // past ~10M/s the quantum itself dominates and only the ceiling holds.
        for per_sec in [999_999u64, 3_000_000, 7_000_000] {
            let interval = RateCap::new(per_sec).min_interval().unwrap();
            let (batch, tick) = batch_for(interval);
            let effective = batch as f64 / tick.as_secs_f64();
            assert!(
                effective <= per_sec as f64,
                "{per_sec}/s batches to {batch} per {tick:?} = {effective:.1}/s, over the cap"
            );
            assert!(
                effective > per_sec as f64 * 0.99,
                "{per_sec}/s delivers only {effective:.1}/s — the shortfall is not rounding"
            );
        }
    }

    /// A `--rate` far above anything a machine can emit must still produce a
    /// runnable schedule. Before the interval was floored at 1ns this divided by
    /// zero, killing the process after the raw socket was already open.
    #[test]
    fn an_absurd_rate_paces_instead_of_panicking() {
        for per_sec in [2_000_000_001u64, 10_000_000_000, u64::MAX] {
            let interval = RateCap::new(per_sec).min_interval().unwrap();
            let (batch, tick) = batch_for(interval);
            assert!(batch > 0 && tick >= MIN_TICK, "{per_sec}/s must yield a sleepable tick");
        }
    }

    /// A tripped kill-switch must be noticed without waiting out the sleep.
    #[test]
    fn a_tripped_kill_switch_cuts_the_sleep_short() {
        use jinrai_safety::KillSwitch;
        let kill = KillSwitch::new();
        kill.trip();
        let plan = RunPlan {
            targets: vec![],
            rate_cap: RateCap::new(1),
            duration: Duration::from_secs(1),
            kill,
        };
        let started = std::time::Instant::now();
        assert!(interruptible_sleep(Duration::from_secs(30), &plan), "must report the abort");
        assert!(started.elapsed() < Duration::from_secs(1), "must not wait out the sleep");
    }
}
