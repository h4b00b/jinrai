//! # TLS handshake flood (THC-SSL-DoS class) — isolated-lab / authorized use.
//!
//! Repeatedly opens a TCP connection, completes a **full** TLS handshake, and
//! immediately drops it — over and over, concurrently. A TLS handshake is
//! deeply **asymmetric**: the server spends far more CPU (key exchange, signing
//! with its private key) than the client does to request one. Flooding fresh
//! handshakes therefore drives the server's CPU hard at little cost to the
//! client — the resource asymmetry THC-SSL-DoS exploited. jinrai exposes it as a
//! resilience self-test so an operator can measure whether their own TLS
//! termination (server, proxy, load-balancer) is rate-limited / offloaded / sized
//! for it.
//!
//! Session resumption is disabled in the shared [`crate::tls`] config, so every
//! connection is a full handshake — a resumed one would be cheap for the server
//! and defeat the test.
//!
//! ## Same safety boundary as the other L7 engines
//!
//! The URL host is authorized as a **datum** ([`crate::authorize_datum`]) and
//! resolved **once** to a pinned connect address ([`crate::resolve_addrs`]); every
//! connection only ever goes there. This primitive is `https`-only (there is no
//! TLS handshake to flood on a plaintext target). The run is bounded by
//! `duration`, capped by the rate cap (reinterpreted as *handshakes per second*),
//! and aborts promptly on the kill switch. It is a **direct** self-test — no
//! spoofing, no reflection/amplification.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

use jinrai_core::{Layer, ModuleError, RunPlan, RunReport, StressModule};
use jinrai_safety::{Authorization, AuthorizedTarget};

use crate::{authorize_datum, resolve_addrs, wait_for_kill, L7Error};

/// The TLS handshake-flood engine. Holds a clone of the gate (the sole authority)
/// and the target URL.
#[derive(Debug, Clone)]
pub struct TlsHandshakeEngine {
    gate: Authorization,
    url: String,
}

impl TlsHandshakeEngine {
    pub fn new(gate: Authorization, url: impl Into<String>) -> Self {
        Self { gate, url: url.into() }
    }

    /// Authorize the datum (public so the CLI can fail-closed before any run).
    pub fn authorize_target(&self) -> Result<Vec<AuthorizedTarget>, L7Error> {
        Ok(vec![authorize_datum(&self.gate, &self.url)?.target])
    }

    fn prepare(&self) -> Result<Prepared, L7Error> {
        let datum = authorize_datum(&self.gate, &self.url)?;
        // https-only: a plaintext target has no handshake to flood. Fail-closed.
        if datum.url.scheme() != "https" {
            // A scheme refusal, not a client-build failure: this is jinrai
            // declining what was asked for, and the audit log records the two
            // under different stages.
            return Err(L7Error::UnsupportedScheme(format!(
                "{} — the tls-handshake flood needs https (there is no TLS handshake on http)",
                datum.url.scheme()
            )));
        }
        let addr = *resolve_addrs(&datum)?.first().expect("resolve_addrs is non-empty");
        let connector = TlsConnector::from(crate::tls::client_config(vec![])?);
        let server_name = crate::tls::server_name(&datum)?;
        Ok(Prepared { addr, connector, server_name })
    }

    /// This primitive could not start. See [`crate::module_error`] for why the
    /// distinction between a refusal and a setup failure is kept.
    fn refusal(&self, e: L7Error) -> ModuleError {
        crate::module_error("L7 tls-handshake".to_string(), e)
    }
}

struct Prepared {
    addr: SocketAddr,
    connector: TlsConnector,
    server_name: ServerName<'static>,
}

impl StressModule for TlsHandshakeEngine {
    fn layer(&self) -> Layer {
        Layer::L7
    }

    fn name(&self) -> &str {
        "l7-tls-handshake"
    }

    fn execute(&mut self, plan: &RunPlan) -> Result<RunReport, ModuleError> {
        let Prepared { addr, connector, server_name } = match self.prepare() {
            Ok(p) => p,
            Err(e) => return Err(self.refusal(e)),
        };

        // Rate cap: min spacing between handshake attempts. `None` => send nothing.
        let Some(interval) = plan.rate_cap.min_interval() else {
            return Ok(RunReport {
                layer_label: format!("L7 tls-handshake {} (rate cap 0 — sent nothing)", self.url),
                aborted_early: false,
                ..Default::default()
            });
        };

        let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => return Err(self.refusal(L7Error::Client(e.to_string()))),
        };

        let sent = Arc::new(AtomicU64::new(0));
        let errors = Arc::new(AtomicU64::new(0));
        let sent_w = sent.clone();
        let errors_w = errors.clone();
        let kill = plan.kill.clone();
        let duration = plan.duration;

        rt.block_on(async move {
            let deadline = crate::deadline_in(duration);
            let mut ticker = tokio::time::interval(interval);
            // Never exceed the cap: on a missed tick, delay rather than burst.
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            // Each handshake runs as its own task so a slow server does not stall
            // the dispatch rate — this is the concurrency that makes it a flood.
            let mut tasks: JoinSet<()> = JoinSet::new();

            loop {
                tokio::select! {
                    _ = ticker.tick() => {}
                    _ = wait_for_kill(kill.clone()) => break,
                }
                if kill.is_tripped() || Instant::now() >= deadline {
                    break;
                }

                let connector = connector.clone();
                let server_name = server_name.clone();
                let sent = sent_w.clone();
                let errors = errors_w.clone();
                tasks.spawn(async move {
                    match one_handshake(addr, &connector, server_name).await {
                        Ok(()) => sent.fetch_add(1, Ordering::Relaxed),
                        Err(()) => errors.fetch_add(1, Ordering::Relaxed),
                    };
                });
            }

            // Kill/deadline reached: stop in-flight handshakes rather than waiting.
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        });

        let aborted = plan.kill.is_tripped();
        let n = sent.load(Ordering::Relaxed);
        Ok(RunReport {
            layer_label: format!(
                "L7 tls-handshake {} ({} handshake{})",
                self.url,
                n,
                if n == 1 { "" } else { "s" }
            ),
            units_sent: n,
            errors: errors.load(Ordering::Relaxed),
            aborted_early: aborted,
            ..Default::default()
        })
    }
}

/// Open a TCP connection to `addr`, complete one full TLS handshake, then drop
/// both. `Ok(())` means the handshake completed (the server did the expensive
/// work); `Err(())` means connect or handshake failed. A 10s ceiling on each
/// stage keeps a black-holed target from pinning a task forever.
async fn one_handshake(
    addr: SocketAddr,
    connector: &TlsConnector,
    server_name: ServerName<'static>,
) -> Result<(), ()> {
    let tcp = match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return Err(()),
    };
    match tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, tcp)).await {
        Ok(Ok(_stream)) => Ok(()), // handshake done — drop immediately
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jinrai_core::RateCap;
    use jinrai_safety::{Allowlist, KillSwitch};

    fn gate_cidrs(cidrs: &[&str]) -> Authorization {
        Authorization::new(Allowlist::from_cidrs(cidrs).unwrap(), KillSwitch::new())
    }

    #[test]
    fn authorizes_https_datum() {
        let engine = TlsHandshakeEngine::new(gate_cidrs(&["127.0.0.0/8"]), "https://127.0.0.1:9/");
        assert!(engine.authorize_target().is_ok());
    }

    #[test]
    fn unauthorized_target_refused() {
        let engine = TlsHandshakeEngine::new(gate_cidrs(&["10.0.0.0/8"]), "https://127.0.0.1:9/");
        assert!(engine.authorize_target().is_err());
    }

    #[test]
    fn name_and_layer() {
        let engine = TlsHandshakeEngine::new(gate_cidrs(&["127.0.0.0/8"]), "https://127.0.0.1:9/");
        assert_eq!(engine.name(), "l7-tls-handshake");
        assert_eq!(engine.layer(), Layer::L7);
    }

    #[test]
    fn http_url_refused_no_handshake_to_flood() {
        // A plaintext target authorizes as a datum but has no TLS handshake, so
        // the run is refused fail-closed rather than doing plaintext work.
        let mut engine =
            TlsHandshakeEngine::new(gate_cidrs(&["127.0.0.0/8"]), "http://127.0.0.1:9/");
        let plan = RunPlan {
            targets: engine.authorize_target().unwrap(),
            rate_cap: RateCap::new(50),
            duration: Duration::from_millis(100),
            kill: KillSwitch::new(),
        };
        match engine.execute(&plan) {
            Err(ModuleError::Refused(msg)) => {
                assert!(msg.contains("needs https"), "got: {msg}")
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn rate_cap_zero_sends_nothing() {
        let mut engine =
            TlsHandshakeEngine::new(gate_cidrs(&["127.0.0.0/8"]), "https://127.0.0.1:9/");
        let plan = RunPlan {
            targets: engine.authorize_target().unwrap(),
            rate_cap: RateCap::new(0),
            duration: Duration::from_millis(50),
            kill: KillSwitch::new(),
        };
        let report = engine.execute(&plan).expect("the run should execute");
        assert_eq!(report.units_sent, 0);
        assert!(!report.aborted_early);
        assert!(report.layer_label.contains("sent nothing"));
    }
}
