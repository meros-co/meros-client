//! The event emitter, conforming to the Meros Event Envelope v1
//! (`meros-co/meros-event-spec` v0.1.1).
//!
//! Emission is never required and never in a critical path: [`Emitter::emit`]
//! doesn't block on the network, a full queue drops its oldest events (and
//! reports how many in the next delivery), and an offline collector is
//! normal. Every event goes to a capped local NDJSON log (one previous
//! generation kept) that exports as is. Collectors get batches of at most
//! 500 through `POST {collector}/v1/events`; the Meros Cloud collector takes
//! the user's token with `events:write`.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::Error;
use crate::auth::AccessTokenSource;
use crate::http::{HttpRequest, Transport};

/// The envelope format version.
pub const ENVELOPE: u32 = 1;
/// The most events in one delivery (the collector contract's cap).
pub const BATCH: usize = 500;
/// How many events wait for collectors before the oldest are dropped.
const PENDING_CAP: usize = 10_000;
/// The local log's size before it rolls over to its previous generation.
const LOG_CAP: u64 = 10 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Debug,
    Info,
    Notice,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    pub product: String,
    pub version: String,
    pub instance: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    /// `desktop`, `server` or `appliance`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edition: Option<String>,
}

/// What an event is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    pub kind: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Who caused it: `user`, `system`, `device` or `external`. Absent means
/// unknown, which is not `system`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// One event as it goes on the wire and in the log.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    pub envelope: u32,
    pub id: String,
    pub occurred_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    pub source: Source,
    #[serde(rename = "type")]
    pub kind: String,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<Subject>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<Actor>,
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub attrs: Map<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<String>,
}

/// What the app reports; the emitter adds the id, time, sequence and source.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    /// `product.subject.verb`, lowercase, past tense.
    pub kind: String,
    pub severity: Severity,
    pub subject: Option<Subject>,
    pub actor: Option<Actor>,
    pub attrs: Map<String, Value>,
    pub trace: Option<String>,
}

impl Event {
    pub fn new(kind: &str, severity: Severity) -> Event {
        Event {
            kind: kind.to_string(),
            severity,
            subject: None,
            actor: None,
            attrs: Map::new(),
            trace: None,
        }
    }

    pub fn about(mut self, kind: &str, id: &str, name: Option<&str>) -> Event {
        self.subject = Some(Subject {
            kind: kind.to_string(),
            id: id.to_string(),
            name: name.map(str::to_string),
        });
        self
    }

    pub fn by(mut self, kind: &str, id: Option<&str>, name: Option<&str>) -> Event {
        self.actor = Some(Actor {
            kind: kind.to_string(),
            id: id.map(str::to_string),
            name: name.map(str::to_string),
        });
        self
    }

    pub fn attr(mut self, key: &str, value: impl Into<Value>) -> Event {
        self.attrs.insert(key.to_string(), value.into());
        self
    }

    pub fn traced(mut self, trace: &str) -> Event {
        self.trace = Some(trace.to_string());
        self
    }
}

/// A collector: its base URL (events go to `{url}/v1/events`) and where its
/// bearer token comes from, if it wants one.
#[derive(Clone)]
pub struct Collector {
    pub url: String,
    pub token: Option<Arc<dyn AccessTokenSource>>,
}

/// What the events say about their source, and where the log lives.
#[derive(Debug, Clone)]
pub struct EmitterConfig {
    /// The local log, the sequence and the install's identity live here.
    pub dir: PathBuf,
    pub product: String,
    pub version: String,
    pub edition: Option<String>,
    pub site: Option<String>,
}

/// How a delivery went.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlushReport {
    /// Events every collector took (accepted, duplicates or rejected:
    /// inside a 202 all three are final).
    pub delivered: usize,
    pub accepted: u64,
    pub duplicates: u64,
    pub rejected: u64,
    /// Collectors that didn't take the batch; it stays queued.
    pub failed: usize,
}

struct Inner {
    source: Source,
    seq: u64,
    log: Option<File>,
    log_size: u64,
    dir: PathBuf,
    pending: VecDeque<Envelope>,
    dropped: u64,
    collectors: Vec<Collector>,
}

/// Emits events. Cloning shares it.
#[derive(Clone)]
pub struct Emitter {
    inner: Arc<Mutex<Inner>>,
    transport: Arc<dyn Transport>,
    flushing: Arc<tokio::sync::Mutex<()>>,
}

impl Emitter {
    /// Opens the local log, creating the install's identity on first run.
    /// Deliver with [`flush`](Self::flush), or [`spawn`](Self::spawn) a
    /// periodic delivery.
    pub fn open(
        config: EmitterConfig,
        collectors: Vec<Collector>,
        transport: Arc<dyn Transport>,
    ) -> std::io::Result<Emitter> {
        std::fs::create_dir_all(&config.dir)?;
        let instance = instance_id(&config.dir)?;
        let seq = last_seq(&config.dir);
        let log_path = config.dir.join("events.ndjson");
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;
        let log_size = log.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Emitter {
            inner: Arc::new(Mutex::new(Inner {
                source: Source {
                    product: config.product,
                    version: config.version,
                    instance,
                    site: config.site,
                    edition: config.edition,
                },
                seq,
                log: Some(log),
                log_size,
                dir: config.dir,
                pending: VecDeque::new(),
                dropped: 0,
                collectors,
            })),
            transport,
            flushing: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    /// Records an event: to the local log at once, and queued for the
    /// collectors. Never blocks on the network, never fails.
    pub fn emit(&self, event: Event) {
        let mut inner = self.inner.lock().unwrap();
        inner.seq += 1;
        let envelope = Envelope {
            envelope: ENVELOPE,
            id: ulid(),
            occurred_at: now_rfc3339(),
            seq: Some(inner.seq),
            source: inner.source.clone(),
            kind: event.kind,
            severity: event.severity,
            subject: event.subject,
            actor: event.actor,
            attrs: event.attrs,
            trace: event.trace,
        };
        if let Ok(mut line) = serde_json::to_string(&envelope) {
            line.push('\n');
            inner.write_log(line.as_bytes());
        }
        if !inner.collectors.is_empty() {
            if inner.pending.len() >= PENDING_CAP {
                inner.pending.pop_front();
                inner.dropped += 1;
            }
            inner.pending.push_back(envelope);
        }
    }

    /// Changes where events go (and the site they say they come from).
    /// With no collectors, nothing is queued.
    pub fn configure(&self, site: Option<String>, collectors: Vec<Collector>) {
        let mut inner = self.inner.lock().unwrap();
        inner.source.site = site;
        if collectors.is_empty() {
            inner.pending.clear();
        }
        inner.collectors = collectors;
    }

    /// The local log, previous generation first, as newline-delimited JSON.
    pub fn export(&self) -> Vec<u8> {
        let dir = self.inner.lock().unwrap().dir.clone();
        let mut out = std::fs::read(dir.join("events.1.ndjson")).unwrap_or_default();
        out.extend(std::fs::read(dir.join("events.ndjson")).unwrap_or_default());
        out
    }

    /// The install's stable identity.
    pub fn instance(&self) -> String {
        self.inner.lock().unwrap().source.instance.clone()
    }

    /// Events waiting for collectors.
    pub fn pending(&self) -> usize {
        self.inner.lock().unwrap().pending.len()
    }

    /// Delivers what's waiting to every collector, a batch at a time, until
    /// the queue is empty or a collector doesn't take a batch (that batch
    /// stays queued for next time). Inside a 202, rejected and duplicate
    /// events are final; any other answer resends the whole batch later. A
    /// `413 batch_too_large` splits the batch to the collector's `max`.
    pub async fn flush(&self) -> FlushReport {
        let _one = self.flushing.lock().await;
        let mut report = FlushReport::default();
        let mut limit = BATCH;
        loop {
            let (collectors, batch) = {
                let mut inner = self.inner.lock().unwrap();
                if inner.collectors.is_empty() || (inner.pending.is_empty() && inner.dropped == 0) {
                    return report;
                }
                if inner.dropped > 0 {
                    // Loss is reported, so a collector knows a gap is real.
                    let count = std::mem::take(&mut inner.dropped);
                    let product = inner.source.product.clone();
                    drop(inner);
                    self.emit(
                        Event::new(&format!("{product}.events.dropped"), Severity::Warning)
                            .by("system", None, None)
                            .attr("count", count),
                    );
                    inner = self.inner.lock().unwrap();
                }
                let n = inner.pending.len().min(limit);
                let batch: Vec<Envelope> = inner.pending.iter().take(n).cloned().collect();
                (inner.collectors.clone(), batch)
            };
            let mut all_took = true;
            for collector in &collectors {
                match self.deliver(collector, &batch).await {
                    Ok((a, d, r)) => {
                        report.accepted += a;
                        report.duplicates += d;
                        report.rejected += r;
                    }
                    Err(e) if e.code == "batch_too_large" && batch.len() > 1 => {
                        limit = e.max.unwrap_or(batch.len() / 2).clamp(1, batch.len() - 1);
                        all_took = false;
                        break;
                    }
                    Err(_) => {
                        report.failed += 1;
                        all_took = false;
                    }
                }
            }
            if !all_took {
                if report.failed > 0 {
                    return report;
                }
                continue; // resend smaller
            }
            let mut inner = self.inner.lock().unwrap();
            // Only what was sent: new events may have arrived meanwhile.
            let sent: std::collections::HashSet<&str> =
                batch.iter().map(|e| e.id.as_str()).collect();
            inner.pending.retain(|e| !sent.contains(e.id.as_str()));
            report.delivered += batch.len();
        }
    }

    async fn deliver(
        &self,
        collector: &Collector,
        batch: &[Envelope],
    ) -> Result<(u64, u64, u64), Error> {
        let url = format!("{}/v1/events", collector.url.trim_end_matches('/'));
        let send = |token: Option<String>| {
            let mut r = HttpRequest::new("POST", url.clone()).json(&batch);
            if let Some(t) = token {
                r = r.header("Authorization", format!("Bearer {t}"));
            }
            self.transport.send(r)
        };
        let token = match &collector.token {
            Some(t) => Some(t.access_token(false).await?),
            None => None,
        };
        let mut r = send(token).await?;
        if r.status == 401
            && let Some(t) = &collector.token
        {
            r = send(Some(t.access_token(true).await?)).await?;
        }
        if !r.ok() {
            return Err(Error::from_response(&r));
        }
        let j = r.value();
        let n = |k: &str| j.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
        if j.get("accepted").is_some()
            && n("accepted") == 0
            && n("duplicates") == 0
            && n("rejected") == 0
        {
            // An old collector's 202 for an oversized batch takes nothing.
            if let Some(err) = j
                .get("errors")
                .and_then(|e| e.as_array())
                .and_then(|e| e.first())
                && err.as_str().is_some_and(|s| s.contains("exceeds"))
            {
                let mut e = Error::new(Some(r.status), "batch_too_large", "Batch too large.");
                e.max = Some(BATCH);
                return Err(e);
            }
        }
        Ok((n("accepted"), n("duplicates"), n("rejected")))
    }

    /// Delivers every `every` (plus up to a quarter of jitter) on the current
    /// Tokio runtime, until the returned handle is aborted.
    #[cfg(feature = "events-runtime")]
    pub fn spawn(&self, every: std::time::Duration) -> tokio::task::JoinHandle<()> {
        let emitter = self.clone();
        tokio::spawn(async move {
            loop {
                let jitter = every.mul_f64(rand::random::<f64>() * 0.25);
                tokio::time::sleep(every + jitter).await;
                emitter.flush().await;
            }
        })
    }
}

impl Inner {
    /// Appends to the log, rolling over to its previous generation when full.
    fn write_log(&mut self, line: &[u8]) {
        if self.log_size + line.len() as u64 > LOG_CAP {
            self.log = None;
            let current = self.dir.join("events.ndjson");
            let _ = std::fs::rename(&current, self.dir.join("events.1.ndjson"));
            self.log = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&current)
                .ok();
            self.log_size = 0;
        }
        if let Some(log) = self.log.as_mut()
            && log.write_all(line).is_ok()
        {
            self.log_size += line.len() as u64;
        }
    }
}

/// The install's identity: made on first run, kept beside the log. Never a
/// MAC address.
fn instance_id(dir: &Path) -> std::io::Result<String> {
    let path = dir.join("instance");
    if let Ok(id) = std::fs::read_to_string(&path) {
        let id = id.trim().to_string();
        if !id.is_empty() {
            return Ok(id);
        }
    }
    let id: String = (0..8)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect();
    std::fs::write(&path, &id)?;
    Ok(id)
}

/// The last sequence number written, so it carries on across restarts.
fn last_seq(dir: &Path) -> u64 {
    ["events.ndjson", "events.1.ndjson"]
        .iter()
        .find_map(|name| {
            let file = File::open(dir.join(name)).ok()?;
            BufReader::new(file)
                .lines()
                .map_while(Result::ok)
                .filter_map(|line| serde_json::from_str::<Value>(&line).ok()?["seq"].as_u64())
                .last()
        })
        .unwrap_or(0)
}

/// RFC 3339, UTC, to the millisecond, ending in `Z`.
pub fn now_rfc3339() -> String {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    rfc3339_ms(ms)
}

/// Formats unix milliseconds as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub fn rfc3339_ms(unix_ms: i64) -> String {
    let secs = unix_ms.div_euclid(1000);
    let ms = unix_ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    // Civil from days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{ms:03}Z",
        sod / 3600,
        sod % 3600 / 60,
        sod % 60
    )
}

/// A ULID: 48 bits of milliseconds and 80 random bits, in Crockford base32.
pub fn ulid() -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
        & ((1u128 << 48) - 1);
    let random = rand::random::<u128>() & ((1u128 << 80) - 1);
    let mut value = (ms << 80) | random;
    let mut out = [0u8; 26];
    for slot in out.iter_mut().rev() {
        *slot = ALPHABET[(value & 31) as usize];
        value >>= 5;
    }
    String::from_utf8(out.to_vec()).expect("ASCII")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_format_as_rfc_3339_milliseconds() {
        assert_eq!(rfc3339_ms(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339_ms(1_790_000_000_123), "2026-09-21T14:13:20.123Z");
        assert_eq!(rfc3339_ms(951_782_400_000), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn ulids_match_the_schema_pattern_and_sort_by_time() {
        let a = ulid();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = ulid();
        assert_eq!(a.len(), 26);
        assert!(a.as_bytes()[0] <= b'7');
        assert!(
            a.bytes()
                .all(|c| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&c))
        );
        assert!(a < b);
    }
}
