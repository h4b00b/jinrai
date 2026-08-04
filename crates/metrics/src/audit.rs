//! Append-only, tamper-evident audit log for jinrai runs.
//!
//! Every consequential action — a run being authorized, completing, or being
//! refused — is appended as one JSON object per line (JSONL). For an authorized
//! dual-use traffic generator, an accountable trail of *what was fired at whom,
//! by whom, and with what outcome* is a compliance requirement, not a nicety.
//!
//! ## Tamper-evidence (hash chain)
//!
//! Each record carries the SHA-256 hash of the previous record (`prev`) and its
//! own hash (`hash`), computed over the record's entire serialized body
//! *including* `prev`. Any edit to any field breaks that record's `hash`; any
//! deletion, reordering, or insertion breaks the `prev` linkage of the
//! neighbouring record. [`verify`] walks the file and reports the first break.
//!
//! This gives **tamper-evidence**, not cryptographic non-repudiation: an actor
//! who can rewrite the whole file can recompute a fresh consistent chain. Closing
//! that gap needs a secret key (HMAC) or external anchoring and is out of scope
//! here; the chain defeats casual edits, mid-file deletion, reordering and
//! insertion, which is what an on-host audit log is realistically up against.
//!
//! ## What it does *not* catch: a truncated tail
//!
//! Deleting the last *k* records leaves a chain that still verifies perfectly,
//! and this is unavoidable in a self-contained file: a record can only link
//! *backwards*, so nothing in what remains says how much came after it. Worse,
//! [`AuditLog::open`] resumes from whatever record it finds last, chaining new
//! entries onto the truncated tail — after which the gap is invisible even to a
//! careful reader.
//!
//! So the property to rely on is precise: **the records still present are
//! trustworthy and in order; their absence is not proven.** Detecting a truncated
//! tail needs an anchor the local file cannot supply — shipping each record to
//! syslog / a remote collector, or recording the high-water `seq` somewhere the
//! same actor cannot reach. `--verify-audit` therefore reports the sequence range
//! it found rather than only "INTACT", so an operator with an expectation about
//! how many runs happened can notice the difference.
//!
//! The format is deliberately plain JSONL so it stays greppable / `jq`-able and
//! needs no bespoke reader.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use jinrai_core::{RunReport, SloVerdict};
use sha2::{Digest, Sha256};

/// The `prev` value of the very first record — a chain "genesis" anchor.
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One auditable event. Serialized as the tail fields of a JSONL record; the
/// common envelope (seq, timestamps, operator, prev/hash) is added by
/// [`AuditLog`].
#[derive(Debug, Clone)]
pub enum AuditEvent {
    /// Targets passed the gate and a run is about to start.
    RunAuthorized {
        layer: String,
        mode: String,
        rate_per_sec: u64,
        duration_secs: u64,
        /// Authorized target descriptors (IP literals or host names).
        targets: Vec<String>,
        /// The operator-supplied allowlist rules in effect for this run.
        allow_rules: Vec<String>,
    },
    /// A run finished; carries the outcome metrics and the SLO verdict.
    RunCompleted {
        layer_label: String,
        /// Completions plus failures — the denominator every rate is read against.
        attempts: u64,
        units_sent: u64,
        /// How many of `units_sent` nothing observed past the local stack
        /// accepting them — see [`RunReport::unobserved_units`]. Recorded because
        /// the distinction survives worse than the count does: months later,
        /// "2497693 completed" reads as a delivered flood, and for a datagram
        /// primitive nobody ever established that.
        unobserved_units: u64,
        errors: u64,
        aborted_early: bool,
        aborted_by_watchdog: bool,
        status_2xx: u64,
        status_3xx: u64,
        status_4xx: u64,
        status_5xx: u64,
        timeouts: u64,
        /// `errors` broken down by OS cause, as `(bucket, count)` pairs. Empty for
        /// layers that do not classify failures. Recorded because "12 errors" and
        /// "12 ECONNREFUSED from the target" are different findings after the fact.
        errno: Vec<(String, u64)>,
        /// Completions by the HTTP version actually used on the wire — so a
        /// reviewer can tell months later whether a run was HTTP/1.1 or HTTP/2.
        http_versions: Vec<(String, u64)>,
        /// Completions by **exact** status code, as `(code, count)` pairs. The
        /// `status_*` classes above cannot distinguish "the target rate-limited
        /// us" (429) from "our request was malformed" (400), and after the fact
        /// nobody can re-run the traffic to find out which it was.
        status_codes: Vec<(u16, u64)>,
        p50_micros: u64,
        p90_micros: u64,
        p99_micros: u64,
        max_micros: u64,
        /// SLO verdict rendered as `PASS` / `FAIL (...)`, or `n/a` when no SLO
        /// was declared for the run.
        slo: String,
    },
    /// A run was refused (fail-closed) before or during execution.
    RunRefused {
        /// Where it was refused: e.g. "authorization", "preflight", "outcome".
        stage: String,
        reason: String,
    },
}

impl AuditEvent {
    /// Build a `RunCompleted` event from a [`RunReport`] and the run's SLO
    /// verdict (`None` when no SLO was declared).
    pub fn completed(report: &RunReport, verdict: Option<&SloVerdict>) -> Self {
        AuditEvent::RunCompleted {
            layer_label: report.layer_label.clone(),
            attempts: report.attempts(),
            units_sent: report.units_sent,
            unobserved_units: report.unobserved_units,
            errors: report.errors,
            errno: report.errno.iter().map(|(b, n)| (b.to_string(), n)).collect(),
            http_versions: report
                .http_versions
                .iter()
                .map(|(v, n)| (v.clone(), *n))
                .collect(),
            status_codes: report.status_codes.iter().map(|(c, n)| (*c, *n)).collect(),
            aborted_early: report.aborted_early,
            aborted_by_watchdog: report.aborted_by_watchdog,
            status_2xx: report.status_2xx,
            status_3xx: report.status_3xx,
            status_4xx: report.status_4xx,
            status_5xx: report.status_5xx,
            timeouts: report.timeouts,
            p50_micros: report.p50_micros,
            p90_micros: report.p90_micros,
            p99_micros: report.p99_micros,
            max_micros: report.max_micros,
            slo: match verdict {
                Some(v) => v.to_string(),
                None => "n/a".to_string(),
            },
        }
    }

    /// One human-readable line describing this event.
    ///
    /// Stored in the record as `summary` and printed by `--verify-audit`. A JSONL
    /// log is machine-readable by construction, but "readable by `jq`" is not the
    /// same as "readable by the engineer reviewing what was fired at production
    /// last Tuesday" — this field is what makes the log answer that question
    /// without a query. It is inside the hashed body, so it cannot be edited to
    /// disagree with the structured fields next to it.
    pub fn human(&self) -> String {
        match self {
            AuditEvent::RunAuthorized {
                layer,
                mode,
                rate_per_sec,
                duration_secs,
                targets,
                allow_rules,
            } => format!(
                "AUTHORIZED {layer}/{mode} at up to {rate_per_sec}/s for {duration_secs}s \
                 -> {} [allowed by: {}]",
                join_or(targets, "no target"),
                join_or(allow_rules, "no rule"),
            ),
            AuditEvent::RunCompleted {
                layer_label,
                attempts,
                units_sent,
                errors,
                aborted_early,
                aborted_by_watchdog,
                status_2xx,
                status_3xx,
                status_4xx,
                status_5xx,
                timeouts,
                errno,
                http_versions,
                status_codes,
                unobserved_units,
                p99_micros,
                slo,
                ..
            } => {
                // A datagram or raw unit was never observed past the local stack
                // taking it, so the record must not say it completed. The trail
                // outlives everyone's memory of which primitive this was, and
                // "2497693 completed" is exactly the sentence a reader would take
                // at face value years later.
                let verb = if *unobserved_units >= *units_sent && *units_sent > 0 {
                    "emitted (unacknowledged: no completion is observable at this layer)"
                } else {
                    "completed"
                };
                let mut s = format!(
                    "COMPLETED {layer_label} — {attempts} attempts: {units_sent} {verb}, \
                     {errors} failed"
                );
                if *timeouts > 0 {
                    s.push_str(&format!(" ({timeouts} timed out)"));
                }
                if status_2xx + status_3xx + status_4xx + status_5xx > 0 {
                    s.push_str(&format!(
                        "; status 2xx={status_2xx} 3xx={status_3xx} 4xx={status_4xx} \
                         5xx={status_5xx}"
                    ));
                }
                // The classes cannot answer "was that 4xx a rate limit?", and by
                // the time anyone reads the log the traffic is long gone.
                if !status_codes.is_empty() {
                    let v: Vec<String> =
                        status_codes.iter().map(|(c, n)| format!("{c}={n}")).collect();
                    s.push_str(&format!("; codes {}", v.join(" ")));
                }
                if !http_versions.is_empty() {
                    let v: Vec<String> =
                        http_versions.iter().map(|(k, n)| format!("{k}={n}")).collect();
                    s.push_str(&format!("; proto {}", v.join(" ")));
                }
                if !errno.is_empty() {
                    let v: Vec<String> = errno.iter().map(|(k, n)| format!("{k}={n}")).collect();
                    s.push_str(&format!("; errno {}", v.join(" ")));
                }
                // Only when something was actually timed. A packet flood has no
                // completion to measure, so `p99 0us` in a permanent record is a
                // measurement nobody took — and the reader years later has no way
                // left to tell it from a very fast one.
                if *units_sent > 0 && *p99_micros > 0 {
                    s.push_str(&format!("; p99 {}us", p99_micros));
                }
                if *aborted_by_watchdog {
                    s.push_str("; ABORTED by SLO watchdog");
                } else if *aborted_early {
                    s.push_str("; ABORTED early");
                }
                s.push_str(&format!("; SLO {slo}"));
                s
            }
            AuditEvent::RunRefused { stage, reason } => {
                format!("REFUSED at {stage} — {reason} (no traffic was emitted)")
            }
        }
    }

    /// Serialize just this event's fields (no leading/trailing comma or braces),
    /// with the human [`summary`](AuditEvent::human) appended as the last field.
    fn fields_json(&self) -> String {
        let structured = match self {
            AuditEvent::RunAuthorized {
                layer,
                mode,
                rate_per_sec,
                duration_secs,
                targets,
                allow_rules,
            } => format!(
                "\"event\":\"run_authorized\",\"layer\":\"{}\",\"mode\":\"{}\",\
                 \"rate_per_sec\":{},\"duration_secs\":{},\"targets\":{},\"allow_rules\":{}",
                json_escape(layer),
                json_escape(mode),
                rate_per_sec,
                duration_secs,
                json_str_array(targets),
                json_str_array(allow_rules),
            ),
            AuditEvent::RunCompleted {
                layer_label,
                attempts,
                units_sent,
                unobserved_units,
                errors,
                aborted_early,
                aborted_by_watchdog,
                status_2xx,
                status_3xx,
                status_4xx,
                status_5xx,
                timeouts,
                errno,
                http_versions,
                status_codes,
                p50_micros,
                p90_micros,
                p99_micros,
                max_micros,
                slo,
            } => format!(
                "\"event\":\"run_completed\",\"layer\":\"{}\",\"attempts\":{},\
                 \"units_sent\":{},\"unobserved_units\":{},\"errors\":{},\
                 \"aborted_early\":{},\"aborted_by_watchdog\":{},\
                 \"status\":{{\"c2xx\":{},\"c3xx\":{},\"c4xx\":{},\"c5xx\":{},\"timeout\":{}}},\
                 \"errno\":{},\"http_versions\":{},\"status_codes\":{},\
                 \"latency_us\":{{\"p50\":{},\"p90\":{},\"p99\":{},\"max\":{}}},\"slo\":\"{}\"",
                json_escape(layer_label),
                attempts,
                units_sent,
                unobserved_units,
                errors,
                aborted_early,
                aborted_by_watchdog,
                status_2xx,
                status_3xx,
                status_4xx,
                status_5xx,
                timeouts,
                json_count_object(errno),
                json_count_object(http_versions),
                json_code_object(status_codes),
                p50_micros,
                p90_micros,
                p99_micros,
                max_micros,
                json_escape(slo),
            ),
            AuditEvent::RunRefused { stage, reason } => format!(
                "\"event\":\"run_refused\",\"stage\":\"{}\",\"reason\":\"{}\"",
                json_escape(stage),
                json_escape(reason),
            ),
        };
        format!("{structured},\"summary\":\"{}\"", json_escape(&self.human()))
    }
}

/// An append-only, hash-chained audit log backed by a file.
///
/// Opening an existing log recovers the last record's hash and sequence number
/// so new records continue the *same* chain across process runs — that
/// cross-run continuity is what lets [`verify`] detect a whole run being deleted
/// from the middle of the file.
pub struct AuditLog {
    file: File,
    path: PathBuf,
    operator: String,
    seq: u64,
    prev_hash: String,
}

impl AuditLog {
    /// Open (creating if absent) the log at `path`, attributing records to
    /// `operator`. Verifies the **entire** existing chain and refuses to open a
    /// log with any unparsable record, any record whose hash does not recompute,
    /// or any break in the `prev` linkage — so we never append onto a broken
    /// chain (fail-closed). Equivalent to what [`verify`] checks.
    ///
    /// Takes an **exclusive advisory lock** for the lifetime of the log. Reading
    /// the tail and appending to it is a read-modify-write on shared state: two
    /// jinrai processes opening the same log would both recover the same
    /// `(seq, prev)` and each write a record claiming that position. Neither is
    /// tampering, but the chain forks — and `verify` reports a forked chain as
    /// `Tampered`, which is the worst possible failure mode for this file. An
    /// operator who ran two floods at once would find their evidence declared
    /// forged. So: one writer at a time, and a clear error for the second.
    pub fn open(path: impl AsRef<Path>, operator: impl Into<String>) -> Result<Self, AuditError> {
        let path = path.as_ref().to_path_buf();

        let mut opts = OpenOptions::new();
        // `read` as well as `append`: the tail is recovered through this same
        // handle, *after* the lock is held, so nobody can append between the read
        // and the first write. O_APPEND writes go to the end regardless of where
        // reading left the cursor.
        opts.create(true).append(true).read(true);
        // The log names every target a run was pointed at, and who pointed it.
        // On a shared host the default umask would leave that world-readable; a
        // file created for accountability should not be one anybody can read.
        // (Only applies at creation — an existing log keeps its own mode.)
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(&path).map_err(|e| AuditError::io(&path, e))?;

        if let Err(e) = file.try_lock() {
            let detail = match e {
                fs::TryLockError::WouldBlock => {
                    "another jinrai process is writing to this audit log; \
                     concurrent writers would fork the hash chain"
                        .to_string()
                }
                fs::TryLockError::Error(e) => {
                    format!("could not lock the audit log for exclusive append: {e}")
                }
            };
            return Err(AuditError::Locked { path, detail });
        }

        // Recover chain state from any existing content, now that the lock makes
        // "what the file ends with" a stable answer.
        //
        // The WHOLE chain is verified here, not just the tail. Recomputing the
        // tail's hash was already necessary — trusting the stored value would mean
        // a log whose last record had been edited still accepted new, correctly
        // chained records, and the forgery would then sit *below* verified history,
        // exactly the shape a reviewer is least likely to question. But the tail
        // alone left the same hole one line further up: a record edited in the
        // MIDDLE of the file, with the last line intact, opened cleanly and honest
        // records were chained onto poisoned history — discoverable only if
        // somebody later happened to run `--verify-audit`.
        //
        // Finding the end of the file already reads every line, so full
        // verification costs one SHA-256 per record and nothing else. Opening the
        // log is the natural checkpoint for it.
        let mut expected_prev = GENESIS.to_string();
        let mut last: Option<(u64, String)> = None;
        for (idx, line) in BufReader::new(&file).lines().enumerate() {
            let lineno = idx + 1;
            let line = line.map_err(|e| AuditError::io(&path, e))?;
            if line.trim().is_empty() {
                continue;
            }
            let (body, stored) = split_body_hash(&line).ok_or_else(|| AuditError::Corrupt {
                path: path.clone(),
                line: lineno,
                detail: "record is not a well-formed audit line (no hash field)".into(),
            })?;
            if sha256_hex(body.as_bytes()) != stored {
                return Err(AuditError::Tampered {
                    path: path.clone(),
                    line: lineno,
                    detail: "record hash does not match its contents (edited in place); \
                             refusing to append to a broken chain (run --verify-audit)"
                        .into(),
                });
            }
            let prev = extract_prev(body).ok_or_else(|| AuditError::Corrupt {
                path: path.clone(),
                line: lineno,
                detail: "record has no readable prev field".into(),
            })?;
            if prev != expected_prev {
                return Err(AuditError::Tampered {
                    path: path.clone(),
                    line: lineno,
                    detail: "record's prev hash breaks the chain (a record was removed, \
                             reordered, or inserted); refusing to append to a broken \
                             chain (run --verify-audit)"
                        .into(),
                });
            }
            let seq = extract_seq(&line).ok_or_else(|| AuditError::Corrupt {
                path: path.clone(),
                line: lineno,
                detail: "record has no readable seq".into(),
            })?;
            expected_prev = stored.to_string();
            last = Some((seq, expected_prev.clone()));
        }
        let (seq, prev_hash) = match last {
            Some((seq, hash)) => {
                let next = seq.checked_add(1).ok_or_else(|| AuditError::Corrupt {
                    path: path.clone(),
                    line: 0,
                    detail: "existing log's sequence number is at the maximum".into(),
                })?;
                (next, hash)
            }
            None => (0, GENESIS.to_string()),
        };

        Ok(Self {
            file,
            path,
            operator: operator.into(),
            seq,
            prev_hash,
        })
    }

    /// The path this log writes to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one record for `event`, extending the hash chain, and get it onto
    /// the disk before returning. A failure here is surfaced to the caller so an
    /// operator can treat "could not record the audit trail" as a reason to
    /// abort rather than emit untracked traffic.
    ///
    /// The `sync_data` is the point: `flush` only pushes the bytes out of the
    /// process's buffer into the OS page cache, which a crash or a power loss
    /// still discards — and the records worth having are exactly the ones written
    /// just before a machine went down mid-run. Audit volume is a handful of lines
    /// per run, so paying for durability per record costs nothing that matters.
    pub fn record(&mut self, event: &AuditEvent) -> Result<(), AuditError> {
        let ts_unix = now_unix();
        // Body = everything except the trailing hash field. The hash is computed
        // over exactly this string, so any later edit to any field is detectable.
        let body = format!(
            "{{\"seq\":{},\"ts_unix\":{},\"ts\":\"{}\",\"operator\":\"{}\",{},\"prev\":\"{}\"",
            self.seq,
            ts_unix,
            format_rfc3339(ts_unix),
            json_escape(&self.operator),
            event.fields_json(),
            self.prev_hash,
        );
        let hash = sha256_hex(body.as_bytes());
        let line = format!("{body},\"hash\":\"{hash}\"}}\n");

        // Where the file ended before this record. A `write_all` that fails
        // partway — ENOSPC is the realistic one — leaves half a line behind, and
        // half a line is not a recoverable state for this file: every subsequent
        // `verify` reports it corrupt and `open` refuses to append, so one full
        // disk permanently retires the log. Rolling back to this length turns
        // that into "the record did not happen", which is both true and something
        // the caller can act on (the run aborts, fail-closed).
        let before = self
            .file
            .metadata()
            .map_err(|e| AuditError::io(&self.path, e))?
            .len();

        if let Err(e) = self
            .file
            .write_all(line.as_bytes())
            .and_then(|()| self.file.flush())
            .and_then(|()| self.file.sync_data())
        {
            // Best-effort: if the rollback itself fails there is nothing further
            // to try, and the original I/O error is the one worth reporting.
            let _ = self.file.set_len(before);
            let _ = self.file.sync_data();
            return Err(AuditError::io(&self.path, e));
        }

        // Unreachable short of ~1.8e19 records, but `seq` is recovered from the
        // file at `open`, so it is not purely internal — and this is the crate
        // that must not panic.
        self.seq = self.seq.checked_add(1).ok_or_else(|| AuditError::Corrupt {
            path: self.path.clone(),
            line: 0,
            detail: "sequence number is at the maximum".into(),
        })?;
        self.prev_hash = hash;
        Ok(())
    }
}

/// One verified record, reduced to what a human needs to read it.
///
/// Produced by [`verify_and_read`] so `--verify-audit` can *show the log* rather
/// than only assert that its hash chain adds up.
#[derive(Debug, Clone)]
pub struct AuditRecord {
    /// Position in the chain.
    pub seq: u64,
    /// RFC 3339 UTC timestamp as recorded.
    pub ts: String,
    /// Who the run was attributed to.
    pub operator: String,
    /// Machine event name: `run_authorized` / `run_completed` / `run_refused`.
    pub event: String,
    /// The record's human-readable one-line summary.
    pub summary: String,
}

/// Walk the log at `path`, confirm the hash chain is intact, and return every
/// record in readable form.
///
/// On the first inconsistency (a record whose recomputed hash differs, or whose
/// `prev` does not match the preceding record's hash) it returns an
/// [`AuditError::Tampered`] naming the offending line — the records read so far
/// are discarded, because a broken chain makes the whole file untrustworthy.
pub fn verify_and_read(path: impl AsRef<Path>) -> Result<Vec<AuditRecord>, AuditError> {
    let path = path.as_ref();
    let file = File::open(path).map_err(|e| AuditError::io(path, e))?;

    let mut expected_prev = GENESIS.to_string();
    let mut records = Vec::new();

    for (idx, line) in BufReader::new(file).lines().enumerate() {
        let lineno = idx + 1;
        let line = line.map_err(|e| AuditError::io(path, e))?;
        if line.trim().is_empty() {
            continue;
        }

        let (body, stored_hash) = split_body_hash(&line).ok_or_else(|| AuditError::Corrupt {
            path: path.to_path_buf(),
            line: lineno,
            detail: "record is not a well-formed audit line (no hash field)".into(),
        })?;

        let recomputed = sha256_hex(body.as_bytes());
        if recomputed != stored_hash {
            return Err(AuditError::Tampered {
                path: path.to_path_buf(),
                line: lineno,
                detail: "record hash does not match its contents (edited in place)".into(),
            });
        }

        let prev = extract_prev(body).ok_or_else(|| AuditError::Corrupt {
            path: path.to_path_buf(),
            line: lineno,
            detail: "record has no readable prev field".into(),
        })?;
        if prev != expected_prev {
            return Err(AuditError::Tampered {
                path: path.to_path_buf(),
                line: lineno,
                detail: "record's prev hash breaks the chain (a record was removed, \
                         reordered, or inserted)"
                    .into(),
            });
        }

        expected_prev = stored_hash.to_string();
        // Read-back is best-effort per field: a record whose chain is intact is
        // trustworthy, so a missing display field is a gap in the view, never a
        // reason to call the log tampered.
        records.push(AuditRecord {
            seq: extract_seq(body).unwrap_or(records.len() as u64),
            ts: extract_json_str(body, "ts").unwrap_or_else(|| "?".into()),
            operator: extract_json_str(body, "operator").unwrap_or_else(|| "?".into()),
            event: extract_json_str(body, "event").unwrap_or_else(|| "?".into()),
            summary: extract_json_str(body, "summary").unwrap_or_else(|| {
                // Pre-0.22 records have no summary field; show the raw body tail
                // rather than nothing.
                format!("(no summary field) {body}")
            }),
        });
    }

    Ok(records)
}

/// Walk the log at `path` and confirm the hash chain is intact, returning the
/// number of records verified. See [`verify_and_read`] to also read them back.
pub fn verify(path: impl AsRef<Path>) -> Result<usize, AuditError> {
    verify_and_read(path).map(|r| r.len())
}

/// Errors from opening, writing, or verifying an audit log.
#[derive(Debug)]
pub enum AuditError {
    /// Underlying filesystem error.
    Io { path: PathBuf, source: io::Error },
    /// The file exists but a record could not be parsed as an audit line.
    Corrupt {
        path: PathBuf,
        line: usize,
        detail: String,
    },
    /// The chain is internally inconsistent — evidence of tampering.
    Tampered {
        path: PathBuf,
        line: usize,
        detail: String,
    },
    /// The log could not be taken for exclusive append. Distinct from `Corrupt`
    /// because nothing is wrong with the file: somebody else is using it, and
    /// the operator's next move is to wait or pick another path, not to
    /// investigate an integrity failure.
    Locked { path: PathBuf, detail: String },
}

impl AuditError {
    fn io(path: &Path, source: io::Error) -> Self {
        AuditError::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditError::Io { path, source } => {
                write!(f, "audit log I/O error on {}: {source}", path.display())
            }
            AuditError::Corrupt { path, line, detail } => write!(
                f,
                "audit log {} is corrupt at line {line}: {detail}",
                path.display()
            ),
            AuditError::Tampered { path, line, detail } => write!(
                f,
                "audit log {} FAILED integrity check at line {line}: {detail}",
                path.display()
            ),
            AuditError::Locked { path, detail } => {
                write!(f, "audit log {} is in use: {detail}", path.display())
            }
        }
    }
}

impl std::error::Error for AuditError {}

// --- serialization / parsing helpers -------------------------------------

/// Split an audit line into (body, stored_hash), where `body` is exactly the
/// string that was hashed. Because every `"` inside a JSON *value* is escaped to
/// `\"`, the structural `,"hash":"` separator cannot occur inside any field
/// value, so locating it (from the right, to be safe) is unambiguous.
fn split_body_hash(line: &str) -> Option<(&str, &str)> {
    let line = line.trim_end();
    let marker = ",\"hash\":\"";
    let at = line.rfind(marker)?;
    let body = &line[..at];
    let rest = &line[at + marker.len()..]; // `<hex>"}`
    let hex = rest.strip_suffix("\"}")?;
    if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some((body, hex))
    } else {
        None
    }
}

/// Read the `prev` value out of a record body (or full line).
fn extract_prev(s: &str) -> Option<&str> {
    let marker = "\"prev\":\"";
    let at = s.rfind(marker)?;
    let rest = &s[at + marker.len()..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

/// Read the string value of `"<key>":"…"` out of a record body, undoing the
/// escaping [`json_escape`] applied. Stops at the first *unescaped* closing quote,
/// so a value containing `\"` is read whole.
fn extract_json_str(s: &str, key: &str) -> Option<String> {
    let marker = format!("\"{key}\":\"");
    let at = s.find(&marker)?;
    let rest = &s[at + marker.len()..];
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => match chars.next()? {
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'u' => {
                    // `\uXXXX` is only emitted for control characters, which have
                    // no display value — consume the digits and drop it.
                    for _ in 0..4 {
                        chars.next()?;
                    }
                }
                other => out.push(other), // `\"` and `\\`
            },
            c => out.push(c),
        }
    }
    None // unterminated string
}

/// Read the leading `seq` integer out of a record line.
fn extract_seq(line: &str) -> Option<u64> {
    let marker = "\"seq\":";
    let at = line.find(marker)?;
    let rest = &line[at + marker.len()..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// `"a, b"` — or `empty` when the list is empty, so a summary never reads as a
/// dangling `-> `.
fn join_or(items: &[String], empty: &str) -> String {
    if items.is_empty() {
        return empty.to_string();
    }
    items.join(", ")
}

/// Minimal JSON string escaping for the field values we emit.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// `(name, count)` pairs as a JSON object: `{"EMFILE":957,"ECONNREFUSED":1}`.
fn json_count_object(items: &[(String, u64)]) -> String {
    let mut out = String::from("{");
    for (i, (k, n)) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(&json_escape(k));
        out.push_str("\":");
        out.push_str(&n.to_string());
    }
    out.push('}');
    out
}

/// `(code, count)` pairs as a JSON object: `{"200":875,"429":118}`. Keys are
/// strings because JSON objects have no other kind, and a numeric status is
/// still the natural key to `jq` on.
fn json_code_object(items: &[(u16, u64)]) -> String {
    let mut out = String::from("{");
    for (i, (c, n)) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!("\"{c}\":{n}"));
    }
    out.push('}');
    out
}

fn json_str_array(items: &[String]) -> String {
    let mut out = String::from("[");
    for (i, s) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(&json_escape(s));
        out.push('"');
    }
    out.push(']');
    out
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Format a Unix timestamp (seconds) as an RFC 3339 UTC string, e.g.
/// `2026-07-08T12:34:56Z`. Uses the standard days-from-civil algorithm so the
/// audit log carries a human-readable time without pulling in a date crate.
pub(crate) fn format_rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hour, min, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Convert a count of days since the Unix epoch (1970-01-01) to a (year, month,
/// day) civil date. Howard Hinnant's public-domain algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorized_event() -> AuditEvent {
        AuditEvent::RunAuthorized {
            layer: "L4".into(),
            mode: "udp-flood".into(),
            rate_per_sec: 100,
            duration_secs: 10,
            targets: vec!["10.0.0.9".into()],
            allow_rules: vec!["10.0.0.0/8".into()],
        }
    }

    fn tmp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("jinrai-audit-test-{}-{}.jsonl", std::process::id(), name));
        let _ = std::fs::remove_file(&p);
        p
    }

    /// Two processes appending to one log both recover the same `(seq, prev)`
    /// and fork the chain — after which `verify` calls an untampered log
    /// tampered. The lock makes the second opener fail loudly instead.
    #[test]
    fn a_second_writer_is_refused_rather_than_forking_the_chain() {
        let path = tmp_path("concurrent");
        let mut first = AuditLog::open(&path, "operator-a").unwrap();
        first.record(&authorized_event()).unwrap();

        let err = match AuditLog::open(&path, "operator-b") { Err(e) => e, Ok(_) => panic!("a second writer must not get the log") };
        assert!(
            err.to_string().contains("another jinrai process"),
            "expected a concurrent-writer refusal, got: {err}"
        );

        // Once the first writer is done the log is available again, and the
        // chain it left behind is intact and continuable.
        drop(first);
        let mut second = AuditLog::open(&path, "operator-b").unwrap();
        second.record(&authorized_event()).unwrap();
        drop(second);
        let records = verify_and_read(&path).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].seq, 1, "the chain continued rather than forking");
        let _ = std::fs::remove_file(&path);
    }

    /// `open` used to take the tail's stored hash on faith. A forged tail would
    /// then get honest, correctly-chained records appended below it — putting the
    /// forgery in the part of the file a reviewer scrolls past.
    #[test]
    fn appending_onto_an_edited_tail_is_refused() {
        let path = tmp_path("edited-tail");
        let mut log = AuditLog::open(&path, "operator").unwrap();
        log.record(&authorized_event()).unwrap();
        drop(log);

        // Edit a field of the (only, and therefore last) record, leaving its
        // stored hash untouched — the tamper the chain exists to catch.
        let contents = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, contents.replace("10.0.0.9", "10.0.0.1")).unwrap();

        let err = match AuditLog::open(&path, "operator") { Err(e) => e, Ok(_) => panic!("an edited tail must not be appendable") };
        assert!(
            matches!(err, AuditError::Tampered { .. }),
            "expected a tamper refusal, got: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The same hole one line further up: `open` verified only the tail, so a
    /// record edited in the MIDDLE of the file with an intact last line opened
    /// cleanly and got honest records chained onto poisoned history. `open` reads
    /// every line anyway, so it verifies every line.
    #[test]
    fn appending_onto_an_edited_middle_record_is_refused() {
        let path = tmp_path("edited-middle");
        let mut log = AuditLog::open(&path, "operator").unwrap();
        log.record(&authorized_event()).unwrap();
        log.record(&authorized_event()).unwrap();
        log.record(&authorized_event()).unwrap();
        drop(log);

        // Edit the middle record only; the tail record is untouched and still
        // recomputes to its own stored hash.
        let lines: Vec<String> =
            std::fs::read_to_string(&path).unwrap().lines().map(String::from).collect();
        assert_eq!(lines.len(), 3);
        let edited = lines[1].replace("10.0.0.9", "10.0.0.1");
        assert_ne!(edited, lines[1], "the test must actually change the record");
        std::fs::write(&path, format!("{}\n{}\n{}\n", lines[0], edited, lines[2])).unwrap();

        let err = match AuditLog::open(&path, "operator") {
            Err(e) => e,
            Ok(_) => panic!("a log with an edited middle record must not be appendable"),
        };
        match err {
            AuditError::Tampered { line, .. } => assert_eq!(line, 2, "names the edited record"),
            other => panic!("expected a tamper refusal, got: {other}"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn civil_from_days_known_dates() {
        // Epoch and a couple of anchored dates.
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339(1_000_000_000), "2001-09-09T01:46:40Z");
        // A midnight in 2026 (1_783_641_600 = 20644 whole days since the epoch).
        assert_eq!(format_rfc3339(1_783_641_600), "2026-07-10T00:00:00Z");
    }

    #[test]
    fn append_then_verify_ok() {
        let path = tmp_path("ok");
        {
            let mut log = AuditLog::open(&path, "tester@example.com").unwrap();
            log.record(&authorized_event()).unwrap();
            let r = RunReport {
                layer_label: "L4 (udp-flood)".into(),
                units_sent: 42,
                ..Default::default()
            };
            log.record(&AuditEvent::completed(&r, None)).unwrap();
        }
        assert_eq!(verify(&path).unwrap(), 2);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn chain_continues_across_reopen() {
        // Deleting a record from the middle must be detectable *because* the
        // second session chained onto the first.
        let path = tmp_path("reopen");
        {
            let mut log = AuditLog::open(&path, "op").unwrap();
            log.record(&authorized_event()).unwrap();
        }
        {
            let mut log = AuditLog::open(&path, "op").unwrap();
            log.record(&AuditEvent::RunRefused {
                stage: "outcome".into(),
                reason: "target unreachable".into(),
            })
            .unwrap();
        }
        assert_eq!(verify(&path).unwrap(), 2);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn in_place_edit_is_detected() {
        let path = tmp_path("edit");
        {
            let mut log = AuditLog::open(&path, "op").unwrap();
            log.record(&authorized_event()).unwrap();
        }
        // Flip a byte inside a field value without touching the hash.
        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replace("10.0.0.9", "10.0.0.1");
        assert_ne!(content, tampered);
        std::fs::write(&path, tampered).unwrap();

        match verify(&path) {
            Err(AuditError::Tampered { line, .. }) => assert_eq!(line, 1),
            other => panic!("expected Tampered, got {other:?}"),
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn deleting_a_record_breaks_the_chain() {
        let path = tmp_path("delete");
        {
            let mut log = AuditLog::open(&path, "op").unwrap();
            log.record(&authorized_event()).unwrap();
            log.record(&AuditEvent::RunRefused {
                stage: "preflight".into(),
                reason: "no CAP_NET_RAW".into(),
            })
            .unwrap();
            log.record(&AuditEvent::completed(&RunReport::default(), None)).unwrap();
        }
        // Remove the middle record; the third's prev now dangles.
        let lines: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(lines.len(), 3);
        let mut f = File::create(&path).unwrap();
        writeln!(f, "{}", lines[0]).unwrap();
        writeln!(f, "{}", lines[2]).unwrap();
        drop(f);

        match verify(&path) {
            Err(AuditError::Tampered { line, .. }) => assert_eq!(line, 2),
            other => panic!("expected Tampered on the second surviving line, got {other:?}"),
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn records_carry_a_readable_summary() {
        let path = tmp_path("summary");
        {
            let mut log = AuditLog::open(&path, "tester").unwrap();
            log.record(&authorized_event()).unwrap();
            let mut r = RunReport {
                layer_label: "L7 l7-http-get http://api.internal/ (HTTP/1.1 forced)".into(),
                units_sent: 990,
                errors: 10,
                timeouts: 4,
                status_2xx: 900,
                status_5xx: 90,
                p99_micros: 210_000,
                ..Default::default()
            };
            r.http_versions.insert("HTTP/1.1".into(), 990);
            log.record(&AuditEvent::completed(&r, None)).unwrap();
        }

        let records = verify_and_read(&path).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].operator, "tester");
        assert_eq!(records[0].event, "run_authorized");
        assert!(
            records[0].summary.contains("AUTHORIZED L4/udp-flood at up to 100/s for 10s")
                && records[0].summary.contains("10.0.0.9")
                && records[0].summary.contains("10.0.0.0/8"),
            "{}",
            records[0].summary
        );
        let done = &records[1].summary;
        assert!(done.starts_with("COMPLETED"), "{done}");
        assert!(done.contains("1000 attempts: 990 completed, 10 failed"), "{done}");
        assert!(done.contains("(4 timed out)"), "{done}");
        assert!(done.contains("proto HTTP/1.1=990"), "{done}");
        assert!(done.contains("SLO n/a"), "{done}");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn summary_field_survives_quotes_and_stays_in_the_hash() {
        // The summary is inside the hashed body: editing it must break the chain,
        // and reading it back must survive escaped quotes in the reason.
        let path = tmp_path("summary-escape");
        {
            let mut log = AuditLog::open(&path, "op").unwrap();
            log.record(&AuditEvent::RunRefused {
                stage: "authorization".into(),
                reason: "host \"evil.example\" not in allowlist".into(),
            })
            .unwrap();
        }
        let records = verify_and_read(&path).unwrap();
        assert!(
            records[0].summary.contains("host \"evil.example\" not in allowlist"),
            "{}",
            records[0].summary
        );

        let content = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, content.replace("not in allowlist", "was in allowlist")).unwrap();
        assert!(matches!(verify(&path), Err(AuditError::Tampered { .. })));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn split_body_hash_is_unambiguous_with_tricky_values() {
        // A reason string containing the literal characters of the hash marker
        // must not confuse the splitter (the real one has an unescaped quote).
        let path = tmp_path("tricky");
        {
            let mut log = AuditLog::open(&path, "op").unwrap();
            log.record(&AuditEvent::RunRefused {
                stage: "authorization".into(),
                reason: "weird \",\\\"hash\\\":\\\" value".into(),
            })
            .unwrap();
        }
        assert_eq!(verify(&path).unwrap(), 1);
        std::fs::remove_file(&path).ok();
    }
}
