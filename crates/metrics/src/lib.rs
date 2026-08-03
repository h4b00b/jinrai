//! # jinrai-metrics — reporting and the audit log (Phase 4)
//!
//! Renders a [`RunReport`] either as a compact one-line summary ([`render`], for
//! logs and scripts) or as a human-readable end-of-run block ([`render_summary`],
//! what an operator reads), and provides the append-only, tamper-evident
//! [`AuditLog`] (see [`mod@audit`]) that records every authorized / completed /
//! refused run.

#![forbid(unsafe_code)]

mod audit;

pub use audit::{verify, verify_and_read, AuditError, AuditEvent, AuditLog, AuditRecord};

use std::time::Duration;

use jinrai_core::{ErrnoBucket, RunReport, SloVerdict};

/// Render a run report as a plain-text summary line.
///
/// A status-class breakdown is appended when any response was classified, and
/// latency percentiles when at least one unit completed (stub / slow layers
/// report `units_sent == 0` or all-zero status counts and have neither to show).
pub fn render(report: &RunReport) -> String {
    let mut line = format!(
        "[{}] sent={} errors={} aborted_early={}",
        report.layer_label, report.units_sent, report.errors, report.aborted_early
    );
    let classified =
        report.status_2xx + report.status_3xx + report.status_4xx + report.status_5xx;
    if classified > 0 || report.timeouts > 0 {
        line.push_str(&format!(
            " status(2xx={} 3xx={} 4xx={} 5xx={} timeout={})",
            report.status_2xx,
            report.status_3xx,
            report.status_4xx,
            report.status_5xx,
            report.timeouts,
        ));
    }
    // Which HTTP version the responses actually came back on — an https run can
    // negotiate h2 without the operator asking for it (see `--http-version`).
    if !report.http_versions.is_empty() {
        let protos: Vec<String> =
            report.http_versions.iter().map(|(v, n)| format!("{v}={n}")).collect();
        line.push_str(&format!(" proto({})", protos.join(" ")));
    }
    // Per-errno breakdown of `errors`, for layers that classify failures. Without
    // it, a local descriptor ceiling (EMFILE) and the target refusing every
    // connection (ECONNREFUSED) are the same number — see `ErrnoBucket`.
    if !report.errno.is_empty() {
        let buckets: Vec<String> =
            report.errno.iter().map(|(b, n)| format!("{b}={n}")).collect();
        line.push_str(&format!(" errno({})", buckets.join(" ")));
    }
    if report.aborted_by_watchdog {
        line.push_str(" watchdog=ABORTED");
    }
    if report.units_sent > 0 {
        line.push_str(&format!(
            " latency_us(p50={} p90={} p99={} max={})",
            report.p50_micros, report.p90_micros, report.p99_micros, report.max_micros
        ));
    }
    // Breaking-point discovery result, when a ramp found the capacity knee.
    if let Some(k) = report.knee {
        line.push_str(&format!(
            " knee(sustained={}/s broke_at={}/s)",
            k.sustained_per_sec, k.breached_at_per_sec
        ));
    }
    line
}

/// Render an SLO verdict as a one-line `SLO: PASS` / `SLO: FAIL (...)` summary.
pub fn render_verdict(verdict: &SloVerdict) -> String {
    format!("SLO: {verdict}")
}

/// Whether the summary block is painted with ANSI colour, and in which sense
/// each row is painted.
///
/// The block states several numbers of *opposite meaning* in the same column —
/// `completed` next to `failed`, `2xx` next to `5xx`, "ran to completion" next
/// to "ABORTED" — and in a terminal they all arrive as the same grey text, so
/// the reader has to parse the labels to find the one that matters. Colour is
/// carried here rather than decided inside the renderer because a report is also
/// piped, redirected and pasted, and escape codes in a file are worse than no
/// colour at all: the caller owns that decision (see the CLI's `--color`).
///
/// Deliberately three senses, not a palette of nine: **good** (the run did what
/// it set out to do), **warn** (a caveat about *our* side — a ceiling we hit, a
/// shortfall that is not the target's doing) and **bad** (failure, and the
/// target's own error responses). Anything finer would be decoration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    on: bool,
}

impl Palette {
    /// No escape codes at all — for files, pipes and `NO_COLOR`.
    pub const PLAIN: Palette = Palette { on: false };
    /// Painted with ANSI SGR codes — for an interactive terminal.
    pub const ANSI: Palette = Palette { on: true };

    /// `Palette::ANSI` when `color` is true, otherwise `Palette::PLAIN`.
    pub fn new(color: bool) -> Palette {
        if color { Palette::ANSI } else { Palette::PLAIN }
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.on {
            format!("\u{1b}[{code}m{text}\u{1b}[0m")
        } else {
            text.to_string()
        }
    }

    fn good(&self, text: &str) -> String {
        self.paint(GREEN, text)
    }
    fn warn(&self, text: &str) -> String {
        self.paint(YELLOW, text)
    }
    fn bad(&self, text: &str) -> String {
        self.paint(RED, text)
    }
}

const GREEN: &str = "32";
const YELLOW: &str = "33";
const RED: &str = "31";
const DIM: &str = "2";
const BOLD: &str = "1";
const ALERT: &str = "1;31";

/// What the report itself cannot know: which module ran, against what, with which
/// operator settings, and how long it actually took.
///
/// A [`RunReport`] carries counters only, so on its own it cannot say whether
/// `sent=600` over a 30 s window was the requested load or a fifth of it. The
/// caller (the CLI) has that context and passes it here so the summary can state
/// the *offered vs. achieved* load instead of leaving the reader to do the
/// division.
#[derive(Debug, Clone)]
pub struct RunContext {
    /// Layer label, e.g. `"L7"` / `"L4"`.
    pub layer: String,
    /// Module / primitive name, e.g. `"l7-http-get"`.
    pub mode: String,
    /// What was targeted: a URL, or the target list for L3/L4.
    pub target: String,
    /// The operator's `--rate` ceiling (units/sec).
    pub rate_per_sec: u64,
    /// The requested `--duration`.
    pub planned: Duration,
    /// Wall-clock time the run actually took (shorter when aborted early).
    pub elapsed: Duration,
    /// Unix time (UTC seconds) at which the first unit was emitted, or `None`
    /// when the caller cannot say.
    ///
    /// `elapsed` alone answers "how long", never "when" — and "when" is what a
    /// reader needs to line the run up against the target's own logs, graphs and
    /// alerts. The finish time is derived from this plus `elapsed`, so the two
    /// timestamps can never disagree with the window they bracket.
    pub started_unix: Option<u64>,
    /// Extra operator-relevant settings worth restating, e.g. `"HTTP/1.1 forced"`
    /// or `"max 50 concurrent connections"`.
    pub notes: Vec<String>,
    /// In-flight ceiling for the modes that have one (`--concurrency` /
    /// `--max-connections`), or `None` for the stateless floods.
    ///
    /// Present so the summary can tell an operator *why* a run fell short of its
    /// rate cap. Offered load is bounded by `concurrency / latency` (Little's
    /// law), and when that product lands below the cap the run was never capable
    /// of reaching it — a fact no counter in the report can express on its own,
    /// and one that otherwise reads as "the target absorbed it".
    pub concurrency: Option<usize>,
}

/// Render the end-of-run block an operator reads: what was fired, what came back,
/// and what it means.
///
/// Deliberately verbose where the one-line [`render`] is terse. A test is only
/// useful if the person reading the output can tell "the target absorbed 6000
/// requests and stayed healthy" from "6000 attempts all failed locally and the
/// target never saw a packet" — both of which the compact line reports as two
/// numbers. Sections that do not apply to a layer (status classes, latency, HTTP
/// version) are omitted rather than printed as zeros.
pub fn render_summary(
    report: &RunReport,
    ctx: &RunContext,
    verdict: Option<&SloVerdict>,
    p: &Palette,
) -> String {
    const WIDTH: usize = 74;
    let attempts = report.attempts();
    let secs = ctx.elapsed.as_secs_f64();
    let mut out = String::new();

    out.push_str(&format!("{}\n", p.paint(BOLD, &header_rule("run summary", WIDTH))));
    out.push_str(&row(p, "target", &ctx.target));
    let mut module = format!("{} / {}", ctx.layer, ctx.mode);
    if !ctx.notes.is_empty() {
        module.push_str(&format!("  ({})", ctx.notes.join(", ")));
    }
    out.push_str(&row(p, "module", &module));
    out.push_str(&row(
        p,
        "window",
        &format!(
            "{} elapsed of {} planned, rate cap {}/s",
            fmt_secs(ctx.elapsed),
            fmt_secs(ctx.planned),
            ctx.rate_per_sec
        ),
    ));
    // When the window was, not just how long it was — without this the block
    // cannot be lined up against the target's own logs or dashboards. Derived
    // from one instant plus `elapsed` so the pair always brackets the window
    // above it.
    if let Some(started) = ctx.started_unix {
        out.push_str(&row(p, "started", &audit::format_rfc3339(started)));
        out.push_str(&row(
            p,
            "finished",
            // Rounded, not truncated: a 1.9 s run finished at +2 s, and reporting
            // +1 s would put the finish inside the window it closes.
            &audit::format_rfc3339(
                started.saturating_add(ctx.elapsed.as_secs_f64().round() as u64),
            ),
        ));
    }

    // Offered load: what actually left the tool, against what was asked for.
    let effective = if secs > 0.0 { attempts as f64 / secs } else { 0.0 };
    out.push_str(&row(
        p,
        "attempts",
        &format!("{attempts} total, {effective:.1}/s achieved{}", achieved_hint(effective, ctx)),
    ));
    // Load the generator never offered, because its own in-flight budget was
    // full. Not an attempt and not an error — but without it, "the target
    // absorbed everything" and "we never sent it" print identically.
    if report.not_offered > 0 {
        out.push_str(&row(
            p,
            "  not offered",
            &p.warn(&format!(
                "{} attempt{} skipped — our in-flight budget was saturated, not the \
                 target's capacity (raise --concurrency to offer more)",
                report.not_offered,
                if report.not_offered == 1 { "" } else { "s" }
            )),
        ));
    }
    // `completed` and `failed` are the pair a reader looks for first, and they
    // mean opposite things — so they are the pair that must not arrive in the
    // same colour. A completion count of zero is not good news, whatever the row
    // is called.
    let completed = format!("{} {}", report.units_sent, share(report.units_sent, attempts));
    out.push_str(&row(
        p,
        "completed",
        &if report.units_sent > 0 { p.good(&completed) } else { p.bad(&completed) },
    ));

    // What those completions were made of, for the primitives where "completed"
    // covers outcomes that mean opposite things. See `RunReport::detail`: without
    // this row the finding lives only in the audit log, and the operator reading
    // the screen sees a clean run with no result in it.
    if let Some(detail) = &report.detail {
        out.push_str(&row(p, "  of which", detail));
    }

    // Response classification (fast L7 only; other layers get no response).
    // Painted per class rather than per row: this row is the one place where a
    // good number and a bad number sit side by side in the same line, which is
    // exactly where a uniform colour helps least.
    let classified =
        report.status_2xx + report.status_3xx + report.status_4xx + report.status_5xx;
    if classified > 0 {
        let class = |n: u64, name: &str, paint: fn(&Palette, &str) -> String| {
            let text = format!("{name} {n} {}", share(n, classified));
            // A class with no responses in it is not a finding; painting a bare
            // `5xx 0 (0.0%)` red would put alarm on the healthiest possible line.
            if n > 0 { paint(p, &text) } else { text }
        };
        out.push_str(&row(
            p,
            "  status",
            &format!(
                "{}   {}   {}   {}",
                class(report.status_2xx, "2xx", Palette::good),
                class(report.status_3xx, "3xx", |_, s| s.to_string()),
                class(report.status_4xx, "4xx", Palette::warn),
                class(report.status_5xx, "5xx", Palette::bad),
            ),
        ));
    }
    if !report.http_versions.is_empty() {
        let protos: Vec<String> =
            report.http_versions.iter().map(|(v, n)| format!("{v} {n}")).collect();
        out.push_str(&row(p, "  protocol", &protos.join("   ")));
    }

    // Failures, and — crucially — whose fault they are.
    if report.errors > 0 {
        let mut failed = format!("{} {}", report.errors, share(report.errors, attempts));
        if report.timeouts > 0 {
            failed.push_str(&format!(", of which {} timed out", report.timeouts));
        }
        out.push_str(&row(p, "failed", &p.bad(&failed)));
        for (bucket, n) in report.errno.iter() {
            let line = format!("{n} x {bucket} — {}", errno_meaning(bucket));
            // Our ceiling vs. the target's behaviour, in colour: a local bucket
            // is a caveat about the run (fix the host and run it again), a
            // remote one is the result the run went looking for.
            out.push_str(&row(
                p,
                "",
                &if is_local_ceiling(bucket) { p.warn(&line) } else { p.bad(&line) },
            ));
        }
    } else {
        out.push_str(&row(p, "failed", &p.good("0")));
    }

    if report.units_sent > 0 {
        let mut latency = format!(
            "p50 {}   p90 {}   p99 {}   max {}",
            fmt_micros(report.p50_micros),
            fmt_micros(report.p90_micros),
            fmt_micros(report.p99_micros),
            fmt_micros(report.max_micros),
        );
        // These percentiles cover attempts that COMPLETED. With failures in the
        // mix that is a materially different population, and an unqualified
        // "p99 7.7ms" next to "26% failed" reads as a healthy target when a
        // quarter of the attempts in fact took the timeout in full.
        if report.errors > 0 {
            latency.push_str(&format!(
                " (completed attempts only — the {} that failed are not in these percentiles)",
                report.errors
            ));
        }
        out.push_str(&row(p, "latency", &latency));
        // The residency that the concurrency budget actually paid for, shown
        // whenever it diverges from the completed-only view above.
        if report.mean_micros > report.p50_micros.saturating_mul(2) {
            out.push_str(&row(
                p,
                "  per-slot",
                &format!(
                    "{} mean per attempt across all {attempts} — what one in-flight \
                     slot cost, failures included",
                    fmt_micros(report.mean_micros)
                ),
            ));
        }
    }
    // Why the run fell short of its cap, when it did. The two notes are mutually
    // exclusive by construction: the first applies only where there is an
    // in-flight ceiling to blame, the second only where there is not.
    if let Some(note) =
        concurrency_bound_note(effective, report, ctx).or_else(|| generator_bound_note(effective, report, ctx))
    {
        // A shortfall that is ours, not the target's — the whole point of the
        // note is that the reader must not read it as absorbed load.
        out.push_str(&row(p, "bound by", &p.warn(&note)));
    }
    if let Some(k) = report.knee {
        out.push_str(&row(
            p,
            "knee",
            &format!(
                "held {}/s within SLO, first breached at {}/s",
                k.sustained_per_sec, k.breached_at_per_sec
            ),
        ));
    }

    let outcome = outcome_line(report);
    out.push_str(&row(p, "outcome", &p.paint(outcome_color(report), outcome)));
    if let Some(v) = verdict {
        let text = v.to_string();
        out.push_str(&row(
            p,
            "SLO",
            &if v.passed() { p.good(&text) } else { p.bad(&text) },
        ));
    }
    // The one reading an operator must not miss: a run that exercised nothing.
    if report.units_sent == 0 && report.errors > 0 {
        out.push_str(&row_with(
            p,
            ALERT,
            "WARNING",
            &p.bad(
                "no unit completed — nothing was actually stress-tested \
                 (target unreachable/filtered, or the tool was blocked locally: \
                 check the failure breakdown above)",
            ),
        ));
    }
    out.push_str(&p.paint(BOLD, &"=".repeat(WIDTH)));
    out
}

/// The sense in which a run ended: green for a run that did its job, red for a
/// target that failed under the load, yellow for one the operator cut short.
fn outcome_color(report: &RunReport) -> &'static str {
    if report.aborted_by_watchdog {
        RED
    } else if report.knee.is_some() {
        GREEN
    } else if report.aborted_early {
        YELLOW
    } else if report.units_sent == 0 && report.errors > 0 {
        // A hollow run "ran to completion" in the narrowest possible sense. The
        // WARNING below says so, but a green line above a red warning is the
        // confidently-wrong green this whole block exists to prevent.
        YELLOW
    } else {
        GREEN
    }
}

/// Whether an errno bucket describes **our** ceiling rather than the target's
/// behaviour — the same split [`errno_meaning`] spells out in words.
fn is_local_ceiling(bucket: ErrnoBucket) -> bool {
    matches!(
        bucket,
        ErrnoBucket::Emfile
            | ErrnoBucket::Enfile
            | ErrnoBucket::Enobufs
            | ErrnoBucket::Eaddrnotavail
            | ErrnoBucket::Timeout
            | ErrnoBucket::Abandoned
            | ErrnoBucket::Internal
    )
}

/// A plain-language statement of how the run ended, replacing the bare
/// `aborted_early=true|false` pair (which does not say *who* stopped it).
fn outcome_line(report: &RunReport) -> &'static str {
    if report.aborted_by_watchdog {
        "ABORTED by the SLO health-watchdog (sustained breach — the target was \
         failing, so traffic was stopped)"
    } else if report.knee.is_some() {
        "stopped at the capacity knee (breaking-point discovery — this is a \
         successful outcome)"
    } else if report.aborted_early {
        "ABORTED before the planned duration (operator Ctrl-C, or the run could \
         not be started)"
    } else {
        "ran to completion"
    }
}

/// What one errno bucket tells the operator to do about it: the local buckets are
/// the tool's own ceiling (fix the host), the rest are target behaviour (the
/// result you came for).
fn errno_meaning(bucket: ErrnoBucket) -> &'static str {
    match bucket {
        ErrnoBucket::Emfile => "we hit our OWN open-file limit — local ceiling, not the target",
        ErrnoBucket::Enfile => "the host's system-wide file table is full — local, not the target",
        ErrnoBucket::Enobufs => "the local kernel ran out of socket buffers — local, not the target",
        ErrnoBucket::Eaddrnotavail => {
            "no local ephemeral port left — local exhaustion, not the target"
        }
        ErrnoBucket::Econnrefused => "the TARGET actively refused the connection (RST)",
        ErrnoBucket::Etimedout => "the TARGET never answered (kernel connect timeout)",
        ErrnoBucket::Econnreset => "the TARGET reset the connection mid-handshake",
        ErrnoBucket::Eunreach => "no route to the target — routing/firewall, nothing was delivered",
        ErrnoBucket::Timeout => {
            "our own attempt timeout expired first (tune --request-timeout-ms for \
             l7, --connect-timeout-ms for l4)"
        }
        ErrnoBucket::Abandoned => {
            "still in flight when the run's window closed, so we cancelled it — \
             the target was answering slower than the offered load (raise --duration \
             or lower --rate; --drain-timeout-ms sets the grace)"
        }
        ErrnoBucket::Protocol => {
            "the socket worked but the protocol exchange failed (most often the \
             target does not speak the forced --http-version)"
        }
        ErrnoBucket::Other(_) => "OS error — see the code",
        ErrnoBucket::Internal => "refused before the OS (structural mismatch, e.g. IPv6 vs IPv4-only)",
    }
}

/// `" (98% of the 200/s cap)"`, or empty when there is no meaningful cap to
/// compare against. This is what turns a raw rate into "did we offer the load we
/// asked for?".
fn achieved_hint(effective: f64, ctx: &RunContext) -> String {
    if ctx.rate_per_sec == 0 || effective <= 0.0 {
        return String::new();
    }
    let pct = effective / ctx.rate_per_sec as f64 * 100.0;
    format!(" ({pct:.0}% of the {}/s cap)", ctx.rate_per_sec)
}

/// Explain a run that fell short of its rate cap because it could not have
/// reached it, rather than because the target pushed back.
///
/// Offered load is bounded by Little's law: with `N` attempts in flight and an
/// attempt occupying its slot for `W`, the most a run can offer is `N / W` per
/// second. If that product is below the cap, the cap was unreachable from the
/// start and the achieved percentage says nothing about the target — the
/// operator needs to raise the concurrency ceiling, not read the result as
/// absorbed load. Silent when the run got near its cap, when no per-attempt
/// duration was measured (the stateless floods), or when the ceiling was not the
/// binding constraint.
///
/// ## `W` is the mean residency, not the median latency
///
/// This note used to divide by `p50_micros`, and that made it misfire in the one
/// scenario it was written for. The percentiles describe attempts that
/// *completed*; an attempt that times out completes nothing but holds its slot
/// for the entire timeout. A connect flood that lands 72% of its handshakes in
/// ~3 ms and times the rest out at 500 ms has a median of 3 ms and a mean
/// residency of ~130 ms — a factor of 40. Dividing by the median put the ceiling
/// at 190k/s, well above any cap, so the note stayed silent and the operator was
/// left reading "32% of the 10000/s cap" as load the target had absorbed. It was
/// nothing of the kind: two thirds of that load was never offered.
///
/// So `W` is [`RunReport::mean_micros`] when the layer measured it, and the
/// median only as a fallback for layers that do not.
fn concurrency_bound_note(effective: f64, report: &RunReport, ctx: &RunContext) -> Option<String> {
    let concurrency = ctx.concurrency?;
    // Prefer true mean residency; fall back to the completed-only median for
    // layers that do not measure it.
    let (residency_micros, basis) = match report.mean_micros {
        0 => (report.p50_micros, "median"),
        mean => (mean, "mean"),
    };
    if ctx.rate_per_sec == 0 || residency_micros == 0 || concurrency == 0 {
        return None;
    }
    let cap = ctx.rate_per_sec as f64;
    // Within reach of the cap: the pacer was in charge, which is the healthy case.
    if effective >= cap * 0.9 {
        return None;
    }
    let residency = residency_micros as f64 / 1_000_000.0;
    let ceiling = concurrency as f64 / residency;
    if ceiling >= cap {
        // The run had the headroom to reach the cap and did not — that is a
        // finding about the target, not about this knob. Say nothing.
        return None;
    }
    let mut note = format!(
        "concurrency, not the target: {concurrency} in flight at a {} {basis} \
         attempt tops out near {ceiling:.0}/s, below the {}/s cap — only \
         {effective:.0}/s was ever offered, so the shortfall is NOT load the \
         target absorbed",
        fmt_micros(residency_micros),
        ctx.rate_per_sec
    );
    // Where the budget went. A slot spent on an attempt that never completes is
    // the usual reason the ceiling is this low, and it points at a different
    // knob than "raise --concurrency" does.
    if basis == "mean" && report.errors > 0 && residency_micros > report.p50_micros.saturating_mul(2)
    {
        note.push_str(&format!(
            ". Failed attempts hold a slot far longer than the {} median completion, \
             so they dominate that budget — lowering the attempt timeout buys more \
             offered load than raising --concurrency",
            fmt_micros(report.p50_micros)
        ));
    } else {
        note.push_str(" — raise --concurrency to offer more load");
    }
    Some(note)
}

/// Explain a run that fell short of its rate cap because **this host** could not
/// emit any faster — the case where the low percentage says nothing whatsoever
/// about the target.
///
/// This is the counterpart to [`concurrency_bound_note`], for the modes that have
/// no in-flight ceiling to blame. A stateless flood paces itself one unit at a
/// time and tops out well below what `--rate` will accept: ask for 200 000
/// packets/s and the summary reports `14% of the 200000/s cap`, with **zero
/// failures**. Read without help, that is the most dangerous line the tool can
/// print — it looks exactly like a target absorbing 86% of the offered load,
/// when in fact the load was never offered.
///
/// The inference is deliberately narrow. Nothing failed, so nothing was refused,
/// reset or timed out; there is no concurrency ceiling that could have throttled
/// dispatch; and the run was not cut short. With every external explanation
/// eliminated, what remains is the generator's own pacing limit — so the note
/// states the achieved rate as the *real* offered load and tells the operator not
/// to credit the target with the difference.
fn generator_bound_note(effective: f64, report: &RunReport, ctx: &RunContext) -> Option<String> {
    // An in-flight ceiling is a better explanation, and `concurrency_bound_note`
    // owns that case.
    if ctx.concurrency.is_some() || ctx.rate_per_sec == 0 || effective <= 0.0 {
        return None;
    }
    // Any failure at all means the breakdown above is the story; do not talk over
    // it with an inference that assumes a clean run.
    if report.errors > 0 {
        return None;
    }
    // A run stopped early is short for a reason the outcome line already gives.
    if report.aborted_early || report.knee.is_some() {
        return None;
    }
    let cap = ctx.rate_per_sec as f64;
    // Within reach of the cap: the pacer delivered what was asked, which is the
    // healthy case and needs no explanation.
    if effective >= cap * 0.9 {
        return None;
    }
    Some(format!(
        "the generator, not the target: nothing failed and there was no in-flight \
         ceiling, so {effective:.0}/s is what this host could emit — the shortfall \
         against the {}/s cap is jinrai's own limit, NOT load the target absorbed. \
         Treat {effective:.0}/s as the load actually offered",
        ctx.rate_per_sec
    ))
}

/// `"(99.9%)"` of a total, or empty when the total is zero.
fn share(n: u64, total: u64) -> String {
    if total == 0 {
        return String::new();
    }
    format!("({:.1}%)", n as f64 / total as f64 * 100.0)
}

/// One `label  value` line, wrapped to the block width so long values stay
/// readable in a terminal.
///
/// Whitespace *runs* inside the value are preserved rather than collapsed: the
/// wide gaps are what separate the groups within a line (`2xx 5900   3xx 0`), so
/// squashing them to single spaces would undo the readability this block exists
/// for. A run of spaces at a wrap point becomes the line break instead.
fn row(p: &Palette, label: &str, value: &str) -> String {
    row_with(p, DIM, label, value)
}

/// [`row`] with an explicit SGR code for the label column, for the one row
/// (`WARNING`) whose label is itself the message.
fn row_with(p: &Palette, label_code: &str, label: &str, value: &str) -> String {
    const LABEL_W: usize = 11;
    const WRAP: usize = 74;
    // The padding is the only thing separating label from value, so a label that
    // fills the column renders as `slot time132.0ms`. Caught here rather than in
    // a summary someone has to read.
    debug_assert!(
        label.chars().count() < LABEL_W,
        "label {label:?} fills the {LABEL_W}-char column and would run into the value"
    );
    let indent = " ".repeat(LABEL_W + 1);
    // The label is padded *before* it is painted, so the escape codes sit outside
    // the column and cannot be mistaken for part of its width.
    let mut out = format!(" {}", p.paint(label_code, &format!("{label:<LABEL_W$}")));
    let mut col = 1 + LABEL_W;

    let mut rest = value.trim_start();
    let mut gap = String::new();
    while !rest.is_empty() {
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let (word, tail) = rest.split_at(end);
        let w = visible_width(word);
        if !gap.is_empty() && col + gap.chars().count() + w > WRAP {
            out.push('\n');
            out.push_str(&indent);
            col = indent.chars().count();
        } else {
            out.push_str(&gap);
            col += gap.chars().count();
        }
        out.push_str(word);
        col += w;
        let ws_end = tail
            .find(|c: char| !c.is_whitespace())
            .unwrap_or(tail.len());
        gap = tail[..ws_end].replace(['\n', '\t'], " ");
        rest = &tail[ws_end..];
    }
    out.push('\n');
    out
}

/// How many terminal cells a word occupies, ignoring any ANSI SGR escapes in it.
///
/// The wrapper counts characters to decide where to break, and a painted word
/// carries five to nine characters no terminal ever shows. Counting those would
/// wrap the block early and unevenly — the layout would depend on whether colour
/// happened to be on, which is the one thing colour must not change.
fn visible_width(s: &str) -> usize {
    let mut width = 0;
    let mut in_escape = false;
    for c in s.chars() {
        if in_escape {
            // SGR sequences end at `m`; nothing else is emitted here.
            in_escape = c != 'm';
        } else if c == '\u{1b}' {
            in_escape = true;
        } else {
            width += 1;
        }
    }
    width
}

/// `==== run summary ==========` — a titled rule so consecutive runs in one log
/// are visually separable.
fn header_rule(title: &str, width: usize) -> String {
    let left = 4;
    let used = left + 2 + title.chars().count();
    format!("{} {title} {}", "=".repeat(left), "=".repeat(width.saturating_sub(used)))
}

/// Microseconds as the unit an operator thinks in: `840us` / `12.4ms` / `1.20s`.
fn fmt_micros(micros: u64) -> String {
    if micros < 1_000 {
        format!("{micros}us")
    } else if micros < 1_000_000 {
        format!("{:.1}ms", micros as f64 / 1_000.0)
    } else {
        format!("{:.2}s", micros as f64 / 1_000_000.0)
    }
}

/// A duration in seconds with one decimal (`30.0s`), or `m:ss` past a minute.
fn fmt_secs(d: Duration) -> String {
    let s = d.as_secs_f64();
    if s < 60.0 {
        format!("{s:.1}s")
    } else {
        format!("{}m{:02}s", (s / 60.0) as u64, (s % 60.0) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_summary() {
        let r = RunReport {
            layer_label: "L7".into(),
            units_sent: 42,
            errors: 1,
            aborted_early: false,
            status_2xx: 40,
            status_5xx: 2,
            p50_micros: 1200,
            p90_micros: 3400,
            p99_micros: 9800,
            max_micros: 15000,
            ..Default::default()
        };
        assert_eq!(
            render(&r),
            "[L7] sent=42 errors=1 aborted_early=false \
             status(2xx=40 3xx=0 4xx=0 5xx=2 timeout=0) \
             latency_us(p50=1200 p90=3400 p99=9800 max=15000)"
        );
    }

    #[test]
    fn omits_latency_and_status_when_nothing_sent() {
        let r = RunReport {
            layer_label: "L4 (stub)".into(),
            ..Default::default()
        };
        assert_eq!(render(&r), "[L4 (stub)] sent=0 errors=0 aborted_early=false");
    }

    #[test]
    fn renders_errno_breakdown_when_failures_are_classified() {
        use jinrai_core::{ErrnoBucket, ErrnoTally};
        let mut errno = ErrnoTally::default();
        for _ in 0..957 {
            errno.record(ErrnoBucket::Emfile);
        }
        errno.record(ErrnoBucket::Econnrefused);
        errno.record(ErrnoBucket::Timeout);
        let r = RunReport {
            layer_label: "L4 tcp-connect-flood".into(),
            units_sent: 1021,
            errors: errno.total(),
            errno,
            ..Default::default()
        };
        let out = render(&r);
        assert!(
            out.contains("errno(EMFILE=957 ECONNREFUSED=1 timeout=1)"),
            "rendered: {out}"
        );
    }

    #[test]
    fn omits_errno_breakdown_when_layer_does_not_classify() {
        // An unclassified layer must not grow an empty `errno()` group.
        let r = RunReport { layer_label: "L4".into(), errors: 3, ..Default::default() };
        assert_eq!(render(&r), "[L4] sent=0 errors=3 aborted_early=false");
    }

    #[test]
    fn renders_knee_when_present() {
        use jinrai_core::Knee;
        let r = RunReport {
            layer_label: "L7 knee".into(),
            units_sent: 30,
            status_2xx: 20,
            status_5xx: 10,
            knee: Some(Knee { sustained_per_sec: 40, breached_at_per_sec: 60 }),
            ..Default::default()
        };
        assert!(
            render(&r).contains("knee(sustained=40/s broke_at=60/s)"),
            "rendered: {}",
            render(&r)
        );
    }

    #[test]
    fn renders_negotiated_http_version() {
        let mut r = RunReport { layer_label: "L7".into(), units_sent: 3, ..Default::default() };
        r.http_versions.insert("HTTP/1.1".into(), 1);
        r.http_versions.insert("HTTP/2.0".into(), 2);
        assert!(
            render(&r).contains("proto(HTTP/1.1=1 HTTP/2.0=2)"),
            "rendered: {}",
            render(&r)
        );
    }

    #[test]
    fn renders_verdict_pass_and_fail() {
        use jinrai_core::{SloBreach, SloVerdict};
        assert_eq!(render_verdict(&SloVerdict::default()), "SLO: PASS");
        let fail = SloVerdict {
            breaches: vec![SloBreach::ServerErrorRate { observed: 0.2, limit: 0.1 }],
        };
        assert_eq!(render_verdict(&fail), "SLO: FAIL (5xx-rate 20.0% > 10.0%)");
    }

    fn ctx() -> RunContext {
        RunContext {
            layer: "L7".into(),
            mode: "l7-http-get".into(),
            target: "http://api.staging.internal/health".into(),
            rate_per_sec: 200,
            planned: Duration::from_secs(30),
            elapsed: Duration::from_secs(30),
            notes: vec!["HTTP/1.1 forced".into()],
            concurrency: None,
            // 2026-07-10T00:00:00Z
            started_unix: Some(1_783_641_600),
        }
    }

    #[test]
    fn summary_states_offered_load_and_outcome() {
        let mut r = RunReport {
            layer_label: "L7 get".into(),
            units_sent: 5994,
            errors: 6,
            timeouts: 6,
            status_2xx: 5900,
            status_4xx: 40,
            status_5xx: 54,
            p50_micros: 12_400,
            p99_micros: 210_000,
            max_micros: 1_200_000,
            ..Default::default()
        };
        r.http_versions.insert("HTTP/1.1".into(), 5994);
        let out = render_summary(&r, &ctx(), None, &Palette::PLAIN);
        assert!(out.contains("6000 total"), "{out}");
        assert!(out.contains("200.0/s achieved (100% of the 200/s cap)"), "{out}");
        assert!(out.contains("HTTP/1.1 forced"), "{out}");
        assert!(out.contains("HTTP/1.1 5994"), "{out}");
        assert!(out.contains("p99 210.0ms"), "{out}");
        assert!(out.contains("ran to completion"), "{out}");
        // Percentages, not just counts — the point of the block.
        assert!(out.contains("2xx 5900 (98.4%)"), "{out}");
    }

    /// The reading that used to be a mystery: "320/s achieved (3% of the 10000/s
    /// cap)" with zero failures. The block must say the ceiling was ours.
    #[test]
    fn summary_attributes_a_short_run_to_the_concurrency_ceiling() {
        let r = RunReport {
            layer_label: "L4 tcp-connect-flood".into(),
            units_sent: 3204,
            p50_micros: 3_000,
            ..Default::default()
        };
        let c = RunContext {
            layer: "L4".into(),
            mode: "tcp-connect-flood".into(),
            target: "198.51.100.7".into(),
            rate_per_sec: 10_000,
            planned: Duration::from_secs(10),
            elapsed: Duration::from_secs(10),
            notes: vec![],
            concurrency: Some(1),
            started_unix: Some(1_783_641_600),
        };
        let out = render_summary(&r, &c, None, &Palette::PLAIN);
        assert!(out.contains("bound by"), "{out}");
        assert!(out.contains("concurrency, not the target"), "{out}");
        // The arithmetic, so the operator can see where the number came from.
        // (Assert on fragments that survive the block's line wrapping.)
        assert!(out.contains("tops out near 333/s"), "{out}");
        assert!(out.contains("--concurrency to offer more load"), "{out}");
    }

    /// The same shortfall with headroom to spare is a finding about the target,
    /// so the note must stay quiet rather than blame the wrong thing.
    #[test]
    fn summary_stays_quiet_when_concurrency_had_the_headroom() {
        let r = RunReport {
            units_sent: 3204,
            p50_micros: 3_000,
            ..Default::default()
        };
        let c = RunContext {
            // 256 in flight at a 3ms median is ~85k/s — far above the cap, so
            // falling short is not this knob's fault.
            concurrency: Some(256),
            ..ctx_l4()
        };
        let out = render_summary(&r, &c, None, &Palette::PLAIN);
        assert!(!out.contains("bound by"), "{out}");
    }

    /// REGRESSION: the note used to divide by the completed-only median, and so
    /// stayed silent on exactly the run it exists to explain.
    ///
    /// Real numbers from a `--concurrency 512 --connect-timeout-ms 500` connect
    /// flood: 33470 attempts in 10.5 s, 26% of them timing out at the full
    /// 500 ms. The median *completion* is 2.7 ms, which puts the false ceiling at
    /// 190k/s — comfortably above the 10k cap, so the old note said nothing and
    /// "32% of the 10000/s cap" read as 68% absorbed by the target. Mean
    /// residency is ~132 ms: the real ceiling is ~3.9k/s and the cap was never
    /// reachable.
    #[test]
    fn summary_uses_mean_residency_so_timeouts_cannot_hide_the_ceiling() {
        let r = RunReport {
            layer_label: "L4 tcp-connect-flood".into(),
            units_sent: 24_737,
            errors: 8_733,
            timeouts: 8_733,
            p50_micros: 2_700,
            p90_micros: 5_700,
            p99_micros: 7_700,
            max_micros: 94_700,
            mean_micros: 132_000,
            ..Default::default()
        };
        let c = RunContext {
            rate_per_sec: 10_000,
            elapsed: Duration::from_millis(10_500),
            concurrency: Some(512),
            ..ctx_l4()
        };
        let out = render_summary(&r, &c, None, &Palette::PLAIN);
        assert!(out.contains("bound by"), "the ceiling must be named: {out}");
        assert!(out.contains("concurrency, not the target"), "{out}");
        // 512 / 0.132s ~= 3879/s, not the 190k/s the median implied.
        assert!(out.contains("tops out near 3879/s"), "{out}");
        // The operator must not credit the target with the shortfall.
        assert!(out.contains("NOT load the"), "{out}");
        // ...and must be pointed at the knob that actually helps here.
        assert!(out.contains("lowering the attempt timeout"), "{out}");
        // The percentiles must not silently claim to cover the failures.
        // (Fragments short enough to survive the block's line wrapping.)
        assert!(out.contains("attempts only"), "{out}");
        assert!(out.contains("not in these"), "{out}");
        assert!(out.contains("132.0ms mean per"), "{out}");
    }

    /// A stateless flood measures no latency, so there is no bound to compute
    /// and the summary must not invent one.
    #[test]
    fn summary_omits_the_bound_without_measured_latency() {
        let r = RunReport { units_sent: 900, p50_micros: 0, ..Default::default() };
        let out = render_summary(&r, &RunContext { concurrency: Some(4), ..ctx_l4() }, None, &Palette::PLAIN);
        assert!(!out.contains("bound by"), "{out}");
    }

    /// The most dangerous line the tool can print: a huge cap, a low percentage
    /// and **zero failures**, which reads exactly like a target absorbing the
    /// difference. Real numbers from a UDP flood on loopback: 200 000/s asked
    /// for, ~27 800/s delivered, nothing failed.
    #[test]
    fn summary_names_the_generator_when_nothing_else_can_explain_the_shortfall() {
        let r = RunReport {
            layer_label: "L4 udp-flood".into(),
            units_sent: 83_304,
            ..Default::default()
        };
        let c = RunContext {
            mode: "udp-flood".into(),
            rate_per_sec: 200_000,
            planned: Duration::from_secs(3),
            elapsed: Duration::from_secs(3),
            ..ctx_l4()
        };
        let out = render_summary(&r, &c, None, &Palette::PLAIN);
        assert!(out.contains("bound by"), "{out}");
        assert!(out.contains("the generator, not the target"), "{out}");
        // The achieved rate restated as the real offered load, and the explicit
        // instruction not to credit the target with the gap.
        assert!(out.contains("27768/s is what this host could emit"), "{out}");
        assert!(out.contains("NOT load the target absorbed"), "{out}");
    }

    /// A run that delivered its cap needs no explaining.
    #[test]
    fn summary_stays_quiet_when_the_generator_kept_up() {
        let r = RunReport { units_sent: 100_000, ..Default::default() };
        let c = RunContext { rate_per_sec: 10_000, ..ctx_l4() };
        let out = render_summary(&r, &c, None, &Palette::PLAIN);
        assert!(!out.contains("bound by"), "{out}");
    }

    /// With failures on the board the errno breakdown is the story. The
    /// generator note assumes a clean run, so it must not talk over it.
    #[test]
    fn generator_note_defers_to_the_failure_breakdown() {
        use jinrai_core::{ErrnoBucket, ErrnoTally};
        let mut errno = ErrnoTally::default();
        errno.record(ErrnoBucket::Econnrefused);
        let r = RunReport {
            units_sent: 900,
            errors: errno.total(),
            errno,
            ..Default::default()
        };
        let out = render_summary(&r, &ctx_l4(), None, &Palette::PLAIN);
        assert!(!out.contains("the generator, not the target"), "{out}");
    }

    /// An aborted run is short for a reason the outcome line already gives.
    #[test]
    fn generator_note_stays_quiet_on_an_aborted_run() {
        let r = RunReport { units_sent: 900, aborted_early: true, ..Default::default() };
        let out = render_summary(&r, &ctx_l4(), None, &Palette::PLAIN);
        assert!(!out.contains("the generator, not the target"), "{out}");
    }

    /// Where there *is* an in-flight ceiling, that is the better explanation and
    /// the two notes must not both fire.
    #[test]
    fn concurrency_note_wins_over_the_generator_note() {
        let r = RunReport { units_sent: 3204, p50_micros: 3_000, ..Default::default() };
        let c = RunContext { concurrency: Some(1), ..ctx_l4() };
        let out = render_summary(&r, &c, None, &Palette::PLAIN);
        assert!(out.contains("concurrency, not the target"), "{out}");
        assert!(!out.contains("the generator, not the target"), "{out}");
    }

    /// A run whose completions mean opposite things must say so on screen. A TLS
    /// hello the target *parsed* and one it *refused with an alert* were both
    /// delivered; reporting only "30 completed" hands the operator a clean-looking
    /// run with the actual result of the test missing from it.
    #[test]
    fn the_module_breakdown_reaches_the_summary_not_just_the_audit_log() {
        let r = RunReport {
            layer_label: "L7 l7-tls-big-hello".into(),
            units_sent: 30,
            detail: Some("12 parsed by the target, 18 refused with an alert".into()),
            ..Default::default()
        };
        let out = render_summary(&r, &ctx_l4(), None, &Palette::PLAIN);
        assert!(out.contains("of which"), "{out}");
        assert!(out.contains("18 refused with an alert"), "{out}");
    }

    /// The layers whose units have one meaning get no row at all — an empty
    /// breakdown printed as zeros is the noise this block exists to avoid.
    #[test]
    fn a_module_with_nothing_to_break_down_gets_no_row() {
        let r = RunReport { units_sent: 30, ..Default::default() };
        let out = render_summary(&r, &ctx_l4(), None, &Palette::PLAIN);
        assert!(!out.contains("of which"), "{out}");
    }

    /// A connection-holding run (slowloris, websocket, sse) opens up to its
    /// ceiling and then stops opening, so it *always* sits far below the rate
    /// cap with zero failures — the exact shape the generator note fires on, and
    /// the one case where its conclusion is wrong: this host could have opened
    /// far more, the operator asked it not to. Declaring the ceiling is what
    /// keeps the note quiet, and it measures no per-attempt latency, so the
    /// concurrency note has nothing to say either.
    #[test]
    fn a_declared_connection_ceiling_silences_both_shortfall_notes() {
        let r = RunReport {
            layer_label: "L7 l7-websocket".into(),
            units_sent: 25,
            ..Default::default() // no errors, no latency, not aborted
        };
        let c = RunContext {
            layer: "L7".into(),
            mode: "l7-websocket".into(),
            rate_per_sec: 50,
            planned: Duration::from_secs(5),
            elapsed: Duration::from_secs(5),
            concurrency: Some(25),
            ..ctx_l4()
        };
        let out = render_summary(&r, &c, None, &Palette::PLAIN);
        assert!(!out.contains("bound by"), "{out}");
    }

    /// `elapsed` says how long the run was, never *when* it was — and "when" is
    /// what lines the block up against the target's own logs. Both ends must be
    /// on screen, and the finish must bracket the window rather than fall inside
    /// it (a 10.4 s run that started at :00 finished at :10, not at :00).
    #[test]
    fn summary_brackets_the_run_with_wall_clock_timestamps() {
        let r = RunReport { units_sent: 100, ..Default::default() };
        let c = RunContext {
            elapsed: Duration::from_millis(10_400),
            started_unix: Some(1_783_641_600), // 2026-07-10T00:00:00Z
            ..ctx_l4()
        };
        let out = render_summary(&r, &c, None, &Palette::PLAIN);
        assert!(out.contains("started"), "{out}");
        assert!(out.contains("2026-07-10T00:00:00Z"), "{out}");
        assert!(out.contains("finished"), "{out}");
        assert!(out.contains("2026-07-10T00:00:10Z"), "{out}");
    }

    /// A caller that cannot say when the run began must get no timestamps at all
    /// rather than a confident 1970.
    #[test]
    fn summary_omits_timestamps_when_the_caller_has_none() {
        let r = RunReport { units_sent: 100, ..Default::default() };
        let out = render_summary(&r, &RunContext { started_unix: None, ..ctx_l4() }, None, &Palette::PLAIN);
        assert!(!out.contains("1970"), "{out}");
        assert!(!out.contains("finished"), "{out}");
    }

    fn ctx_l4() -> RunContext {
        RunContext {
            layer: "L4".into(),
            mode: "tcp-connect-flood".into(),
            target: "198.51.100.7".into(),
            rate_per_sec: 10_000,
            planned: Duration::from_secs(10),
            elapsed: Duration::from_secs(10),
            notes: vec![],
            concurrency: None,
            started_unix: Some(1_783_641_600),
        }
    }

    #[test]
    fn summary_warns_when_nothing_completed() {
        use jinrai_core::{ErrnoBucket, ErrnoTally};
        let mut errno = ErrnoTally::default();
        for _ in 0..12 {
            errno.record(ErrnoBucket::Econnrefused);
        }
        let r = RunReport {
            layer_label: "L4 tcp".into(),
            units_sent: 0,
            errors: 12,
            errno,
            ..Default::default()
        };
        let out = render_summary(&r, &ctx(), None, &Palette::PLAIN);
        assert!(out.contains("nothing was actually stress-tested"), "{out}");
        assert!(out.contains("actively refused"), "{out}");
    }

    #[test]
    fn summary_names_the_watchdog_as_the_aborter() {
        let r = RunReport {
            layer_label: "L7 get".into(),
            units_sent: 100,
            aborted_early: true,
            aborted_by_watchdog: true,
            status_5xx: 100,
            ..Default::default()
        };
        let out = render_summary(&r, &ctx(), None, &Palette::PLAIN);
        assert!(out.contains("ABORTED by the SLO health-watchdog"), "{out}");
    }

    /// The pair a reader looks for first must not arrive in the same colour.
    #[test]
    fn colour_separates_completed_from_failed() {
        use jinrai_core::{ErrnoBucket, ErrnoTally};
        let mut errno = ErrnoTally::default();
        errno.record(ErrnoBucket::Econnrefused);
        let r = RunReport {
            units_sent: 99,
            errors: errno.total(),
            errno,
            status_2xx: 99,
            status_5xx: 1,
            ..Default::default()
        };
        let out = render_summary(&r, &ctx(), None, &Palette::ANSI);
        assert!(out.contains("\u{1b}[32m99 (99.0%)\u{1b}[0m"), "completed must be green: {out}");
        assert!(out.contains("\u{1b}[31m1 (1.0%)\u{1b}[0m"), "failed must be red: {out}");
        assert!(out.contains("\u{1b}[32m2xx 99"), "{out}");
        assert!(out.contains("\u{1b}[31m5xx 1"), "{out}");
        // A class with nothing in it is not an alarm.
        assert!(out.contains("4xx 0 (0.0%)   \u{1b}[31m5xx"), "an empty class stays plain: {out}");
    }

    /// A zero completion count is not good news, whatever the row is called.
    #[test]
    fn colour_does_not_congratulate_a_hollow_run() {
        use jinrai_core::{ErrnoBucket, ErrnoTally};
        let mut errno = ErrnoTally::default();
        errno.record(ErrnoBucket::Emfile);
        let r = RunReport { units_sent: 0, errors: 1, errno, ..Default::default() };
        let out = render_summary(&r, &ctx_l4(), None, &Palette::ANSI);
        assert!(out.contains("\u{1b}[31m0 (0.0%)\u{1b}[0m"), "completed 0 must be red: {out}");
        // Our own ceiling is a caveat about the run, not the target's answer.
        assert!(out.contains("\u{1b}[33m1 x EMFILE"), "a local ceiling is yellow: {out}");
        assert!(out.contains("\u{1b}[1;31mWARNING"), "{out}");
        assert!(
            out.contains("\u{1b}[33mran to completion"),
            "a hollow run must not print a green outcome: {out}"
        );
    }

    /// Colour must never move a line break: the block is the same shape painted
    /// or plain, or a report changes meaning depending on where it is read.
    #[test]
    fn colour_does_not_change_the_layout() {
        let r = RunReport {
            units_sent: 24_737,
            errors: 8_733,
            timeouts: 8_733,
            p50_micros: 2_700,
            mean_micros: 132_000,
            status_2xx: 24_000,
            status_5xx: 737,
            detail: Some("a breakdown long enough to need wrapping across lines".into()),
            ..Default::default()
        };
        let c = RunContext { rate_per_sec: 10_000, concurrency: Some(512), ..ctx_l4() };
        let plain = render_summary(&r, &c, None, &Palette::PLAIN);
        let painted = render_summary(&r, &c, None, &Palette::ANSI);
        assert!(painted.contains('\u{1b}'), "the painted block must actually be painted");
        assert_eq!(
            plain.lines().count(),
            painted.lines().count(),
            "colour changed the wrapping:\n{plain}\n---\n{painted}"
        );
        let stripped: Vec<usize> = painted.lines().map(visible_width).collect();
        let widths: Vec<usize> = plain.lines().map(|l| l.chars().count()).collect();
        assert_eq!(widths, stripped, "colour changed the visible widths");
    }

    /// The plain palette is byte-for-byte the block that existed before colour.
    #[test]
    fn the_plain_palette_emits_no_escapes() {
        let r = RunReport {
            units_sent: 10,
            errors: 2,
            status_2xx: 10,
            aborted_early: true,
            ..Default::default()
        };
        let out = render_summary(&r, &ctx(), Some(&SloVerdict::default()), &Palette::PLAIN);
        assert!(!out.contains('\u{1b}'), "{out}");
    }

    #[test]
    fn visible_width_ignores_escapes() {
        assert_eq!(visible_width("2xx"), 3);
        assert_eq!(visible_width("\u{1b}[32m2xx\u{1b}[0m"), 3);
        assert_eq!(visible_width("\u{1b}[1;31mWARNING\u{1b}[0m"), 7);
        assert_eq!(visible_width(""), 0);
    }

    #[test]
    fn formats_durations_in_operator_units() {
        assert_eq!(fmt_micros(840), "840us");
        assert_eq!(fmt_micros(12_400), "12.4ms");
        assert_eq!(fmt_micros(1_200_000), "1.20s");
        assert_eq!(fmt_secs(Duration::from_secs(30)), "30.0s");
        assert_eq!(fmt_secs(Duration::from_secs(125)), "2m05s");
    }
}
