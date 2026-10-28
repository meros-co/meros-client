//! Support tickets over the device-signed support API, push-token
//! registration, the unread inbox, the new-reply tracker for platforms
//! without push, and support deep links. Screens stay in the app.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::Error;
use crate::device::DeviceSigner;
use crate::http::{HttpRequest, HttpResponse, Transport, segment, unix_now};

/// A ticket's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TicketStatus {
    /// Waiting on support.
    Open,
    /// Support replied: show "Answered" and badge it.
    Pending,
    /// Resolved; a reply from the device reopens it.
    Closed,
}

impl TicketStatus {
    pub fn parse(s: &str) -> TicketStatus {
        match s {
            "pending" => TicketStatus::Pending,
            "closed" => TicketStatus::Closed,
            _ => TicketStatus::Open,
        }
    }

    /// The label to show.
    pub fn label(self) -> &'static str {
        match self {
            TicketStatus::Open => "Open",
            TicketStatus::Pending => "Answered",
            TicketStatus::Closed => "Closed",
        }
    }

    /// Support has replied and the user should look.
    pub fn needs_attention(self) -> bool {
        self == TicketStatus::Pending
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportTicket {
    pub id: String,
    pub subject: String,
    pub status: TicketStatus,
    /// Unix seconds.
    pub created_at: i64,
    pub last_message_at: i64,
}

impl SupportTicket {
    pub fn from_json(j: &Value) -> Option<SupportTicket> {
        let created = j.get("created_at").and_then(|v| v.as_i64()).unwrap_or(0);
        Some(SupportTicket {
            id: j.get("id")?.as_str()?.to_string(),
            subject: j
                .get("subject")
                .and_then(|v| v.as_str())
                .unwrap_or("(no subject)")
                .to_string(),
            status: TicketStatus::parse(j.get("status").and_then(|v| v.as_str()).unwrap_or("open")),
            created_at: created,
            last_message_at: j
                .get("last_message_at")
                .and_then(|v| v.as_i64())
                .unwrap_or(created),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportMessage {
    /// `author` is exactly `you` or `support`.
    pub from_support: bool,
    pub body: String,
    /// Unix seconds.
    pub at: i64,
}

/// A ticket and its messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportThread {
    pub ticket: SupportTicket,
    pub messages: Vec<SupportMessage>,
}

type RejectHook = Arc<dyn Fn(&str) + Send + Sync>;

/// The support API client. Only activated devices may call it: an
/// unlicensed app sends users to its web form instead.
pub struct SupportApi {
    /// The product's device base, such as `https://<host>/app/<product>`.
    pub base_url: String,
    /// Sent with the push-token registration.
    pub app_version: String,
    transport: Arc<dyn Transport>,
    signer: Arc<dyn DeviceSigner>,
    now: Arc<dyn Fn() -> i64 + Send + Sync>,
    on_device_rejected: Option<RejectHook>,
}

impl SupportApi {
    pub fn new(
        base_url: impl Into<String>,
        app_version: impl Into<String>,
        transport: Arc<dyn Transport>,
        signer: Arc<dyn DeviceSigner>,
    ) -> Self {
        SupportApi {
            base_url: base_url.into(),
            app_version: app_version.into(),
            transport,
            signer,
            now: Arc::new(unix_now),
            on_device_rejected: None,
        }
    }

    /// Called with the server's code when a request is refused, so the app
    /// can drop a stale entitlement on `unknown_device`.
    pub fn on_device_rejected(mut self, hook: impl Fn(&str) + Send + Sync + 'static) -> Self {
        self.on_device_rejected = Some(Arc::new(hook));
        self
    }

    pub fn with_clock(mut self, now: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.now = Arc::new(now);
        self
    }

    fn sign(&self, method: &str, path: &str, ts: i64) -> Result<(String, String), Error> {
        let id = self.signer.identity().ok_or_else(Error::no_identity)?;
        let sig = self
            .signer
            .sign(method, path, ts)
            .ok_or_else(Error::no_identity)?;
        Ok((id.id, sig))
    }

    fn refused(&self, r: &HttpResponse) -> Error {
        let e = Error::from_response(r);
        if let Some(h) = &self.on_device_rejected {
            h(&e.code);
        }
        e
    }

    async fn post(&self, path: &str, mut body: Value) -> Result<HttpResponse, Error> {
        let ts = (self.now)();
        let (id, sig) = self.sign("POST", path, ts)?;
        body["device_id"] = json!(id);
        body["ts"] = json!(ts);
        body["sig"] = json!(sig);
        let r = self
            .transport
            .send(HttpRequest::new("POST", format!("{}{path}", self.base_url)).json(&body))
            .await?;
        if r.status != 200 {
            return Err(self.refused(&r));
        }
        Ok(r)
    }

    async fn get(&self, path: &str) -> Result<HttpResponse, Error> {
        let ts = (self.now)();
        let (id, sig) = self.sign("GET", path, ts)?;
        let r = self
            .transport
            .send(
                HttpRequest::new("GET", format!("{}{path}", self.base_url))
                    .header("X-Device-Id", id)
                    .header("X-Ts", ts.to_string())
                    .header("X-Sig", sig),
            )
            .await?;
        if r.status != 200 {
            return Err(self.refused(&r));
        }
        Ok(r)
    }

    fn ticket_of(r: &HttpResponse) -> Result<SupportTicket, Error> {
        r.value()
            .get("ticket")
            .and_then(SupportTicket::from_json)
            .ok_or_else(|| Error::new(Some(r.status), "bad_response", "No ticket returned."))
    }

    /// Files a ticket. `diagnostics` (optional) goes with the first message.
    pub async fn create(
        &self,
        subject: &str,
        message: &str,
        diagnostics: Option<&str>,
    ) -> Result<SupportTicket, Error> {
        let mut body = json!({"subject": subject, "message": message});
        if let Some(d) = diagnostics.filter(|d| !d.is_empty()) {
            body["app_diagnostics"] = json!(d);
        }
        Self::ticket_of(&self.post("/v1/support/tickets", body).await?)
    }

    /// The device's tickets.
    pub async fn list(&self) -> Result<Vec<SupportTicket>, Error> {
        let j = self.get("/v1/support/tickets").await?.value();
        Ok(j.get("tickets")
            .and_then(|t| t.as_array())
            .map(|a| a.iter().filter_map(SupportTicket::from_json).collect())
            .unwrap_or_default())
    }

    /// A ticket and its messages.
    pub async fn thread(&self, id: &str) -> Result<SupportThread, Error> {
        let r = self
            .get(&format!("/v1/support/tickets/{}", segment(id)))
            .await?;
        let j = r.value();
        #[derive(Deserialize)]
        struct M {
            #[serde(default)]
            author: Option<String>,
            #[serde(default)]
            body: Option<String>,
            #[serde(default)]
            at: Option<i64>,
        }
        let messages = j
            .get("messages")
            .cloned()
            .and_then(|m| serde_json::from_value::<Vec<M>>(m).ok())
            .unwrap_or_default()
            .into_iter()
            .map(|m| SupportMessage {
                from_support: m.author.as_deref().unwrap_or("support") == "support",
                body: m.body.unwrap_or_default(),
                at: m.at.unwrap_or(0),
            })
            .collect();
        Ok(SupportThread {
            ticket: Self::ticket_of(&r)?,
            messages,
        })
    }

    /// Replies on a ticket (reopening a closed one).
    pub async fn reply(&self, id: &str, message: &str) -> Result<SupportTicket, Error> {
        let path = format!("/v1/support/tickets/{}/messages", segment(id));
        Self::ticket_of(&self.post(&path, json!({"message": message})).await?)
    }

    /// Registers the device's push token for support-reply notifications;
    /// `platform` is `android` or `ios`. A device with no identity yet has
    /// nothing to register and returns quietly.
    pub async fn register_push_token(&self, token: &str, platform: &str) -> Result<(), Error> {
        if self.signer.identity().is_none() {
            return Ok(());
        }
        let body = json!({"platform": platform, "token": token, "app_version": self.app_version});
        self.post("/v1/device/push-token", body).await.map(|_| ())
    }
}

/// Where the user's last-seen time per ticket lives (unix seconds of the
/// latest message they viewed). The app persists it however it likes.
pub trait TicketSeenStore: Send + Sync {
    fn seen_at(&self, ticket_id: &str) -> Option<i64>;
    fn set_seen_at(&self, ticket_id: &str, unix_seconds: i64);
}

/// A [`TicketSeenStore`] in memory.
#[derive(Default)]
pub struct MemoryTicketSeenStore {
    pub values: Mutex<std::collections::HashMap<String, i64>>,
}

impl TicketSeenStore for MemoryTicketSeenStore {
    fn seen_at(&self, ticket_id: &str) -> Option<i64> {
        self.values.lock().unwrap().get(ticket_id).copied()
    }

    fn set_seen_at(&self, ticket_id: &str, unix_seconds: i64) {
        self.values
            .lock()
            .unwrap()
            .insert(ticket_id.to_string(), unix_seconds);
    }
}

/// The ticket list and its unread count. A ticket is unread when support
/// has replied (`pending`) after the user last looked.
pub struct SupportInbox {
    seen: Arc<dyn TicketSeenStore>,
    tickets: Mutex<Vec<SupportTicket>>,
}

impl SupportInbox {
    pub fn new(seen: Arc<dyn TicketSeenStore>) -> Self {
        SupportInbox {
            seen,
            tickets: Mutex::new(Vec::new()),
        }
    }

    pub fn tickets(&self) -> Vec<SupportTicket> {
        self.tickets.lock().unwrap().clone()
    }

    pub fn is_unread(&self, t: &SupportTicket) -> bool {
        t.status.needs_attention()
            && self
                .seen
                .seen_at(&t.id)
                .is_none_or(|seen| t.last_message_at > seen)
    }

    pub fn unread_count(&self) -> usize {
        self.tickets
            .lock()
            .unwrap()
            .iter()
            .filter(|t| self.is_unread(t))
            .count()
    }

    /// Re-fetches the list. An unlicensed device has no tickets. Errors keep
    /// the previous list.
    pub async fn refresh(&self, api: &SupportApi, licensed: bool) -> Result<(), Error> {
        if !licensed {
            self.adopt(Vec::new());
            return Ok(());
        }
        let tickets = api.list().await?;
        self.adopt(tickets);
        Ok(())
    }

    /// Takes a list fetched elsewhere (a screen's own load).
    pub fn adopt(&self, tickets: Vec<SupportTicket>) {
        *self.tickets.lock().unwrap() = tickets;
    }

    /// The user opened `t`: it's read up to its latest message.
    pub fn mark_seen(&self, t: &SupportTicket) {
        self.seen.set_seen_at(&t.id, t.last_message_at);
    }
}

/// Reports each new support reply once, for platforms without push (the
/// app runs [`check`](Self::check) on its own timer and raises its own
/// notification). The first check only records what was already unread.
#[derive(Default)]
pub struct ReplyTracker {
    known: Mutex<Option<HashSet<(String, i64)>>>,
}

impl ReplyTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Refreshes the inbox and returns the replies not reported before.
    pub async fn check(
        &self,
        inbox: &SupportInbox,
        api: &SupportApi,
        licensed: bool,
    ) -> Vec<SupportTicket> {
        if inbox.refresh(api, licensed).await.is_err() {
            return Vec::new();
        }
        self.observe(inbox)
    }

    /// Like [`check`](Self::check), over the inbox as it stands.
    pub fn observe(&self, inbox: &SupportInbox) -> Vec<SupportTicket> {
        let unread: Vec<SupportTicket> = inbox
            .tickets()
            .into_iter()
            .filter(|t| inbox.is_unread(t))
            .collect();
        let keys: HashSet<(String, i64)> = unread
            .iter()
            .map(|t| (t.id.clone(), t.last_message_at))
            .collect();
        let mut known = self.known.lock().unwrap();
        let fresh = match known.as_ref() {
            None => Vec::new(),
            Some(k) => unread
                .into_iter()
                .filter(|t| !k.contains(&(t.id.clone(), t.last_message_at)))
                .collect(),
        };
        let mut all = known.take().unwrap_or_default();
        all.extend(keys);
        *known = Some(all);
        fresh
    }
}

/// The ticket id in a support deep link: `{scheme}://support/ticket/{id}`
/// or `{scheme}://support?ticket={id}` (`support` as host or a path segment).
pub fn support_ticket_id_from_uri(uri: &str, scheme: &str) -> Option<String> {
    let u = url::Url::parse(uri).ok()?;
    if u.scheme() != scheme {
        return None;
    }
    let mut segs: Vec<String> = u
        .path_segments()
        .map(|s| s.map(str::to_string).collect())
        .unwrap_or_default();
    segs.retain(|s| !s.is_empty());
    if let Some(h) = u.host_str() {
        segs.insert(0, h.to_string());
    }
    let at = segs.iter().position(|s| s == "support")?;
    if segs.get(at + 1).map(String::as_str) == Some("ticket")
        && let Some(id) = segs.get(at + 2)
    {
        return Some(id.clone());
    }
    u.query_pairs()
        .find(|(k, _)| k == "ticket")
        .map(|(_, v)| v.into_owned())
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn support_deep_links_carry_the_ticket_id() {
        let id = |s: &str| support_ticket_id_from_uri(s, "demoapp");
        assert_eq!(
            id("demoapp://support/ticket/tkt_9").as_deref(),
            Some("tkt_9")
        );
        assert_eq!(
            id("demoapp://support?ticket=tkt_9").as_deref(),
            Some("tkt_9")
        );
        assert_eq!(
            id("demoapp://x/support/ticket/tkt_9").as_deref(),
            Some("tkt_9")
        );
        assert_eq!(id("otherapp://support/ticket/tkt_9"), None);
        assert_eq!(id("demoapp://activate?key=k"), None);
        assert_eq!(id("demoapp://support"), None);
    }

    fn t(id: &str, status: &str, last: i64) -> SupportTicket {
        SupportTicket::from_json(&json!({"id": id, "subject": "S", "status": status, "created_at": 900, "last_message_at": last}))
            .unwrap()
    }

    #[test]
    fn unread_counts_answered_tickets_newer_than_last_seen() {
        let seen = Arc::new(MemoryTicketSeenStore::default());
        seen.set_seen_at("c", 1500);
        let inbox = SupportInbox::new(seen.clone());
        inbox.adopt(vec![
            t("a", "pending", 2000),
            t("b", "open", 2000),
            t("c", "pending", 1500),
        ]);
        assert_eq!(inbox.unread_count(), 1);
        inbox.mark_seen(&inbox.tickets()[0]);
        assert_eq!(seen.seen_at("a"), Some(2000));
        assert_eq!(inbox.unread_count(), 0);
    }

    #[test]
    fn the_tracker_reports_each_new_reply_once_not_what_was_unread_at_start() {
        let inbox = SupportInbox::new(Arc::new(MemoryTicketSeenStore::default()));
        let tracker = ReplyTracker::new();
        inbox.adopt(vec![t("a", "pending", 100)]);
        assert!(tracker.observe(&inbox).is_empty());
        inbox.adopt(vec![t("a", "pending", 100), t("b", "pending", 200)]);
        assert_eq!(tracker.observe(&inbox)[0].id, "b");
        assert!(tracker.observe(&inbox).is_empty());
        inbox.adopt(vec![t("a", "pending", 300), t("b", "pending", 200)]);
        assert_eq!(tracker.observe(&inbox)[0].id, "a");
    }
}
