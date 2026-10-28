//! A fake of the Meros services, in memory, as a [`Transport`]: hand it to
//! the clients in an app's tests and nothing leaves the process.
//!
//! It answers OAuth with PKCE and rotating refresh tokens, the device license
//! API (activate, renew, release, offline activate, App Store redeem, sign-in
//! claim with TOTP, claim with the app's sign-in, seats and seat release),
//! profiles, versioned documents, files through a signed-URL bucket, accounts,
//! entitlements, support tickets, push tokens and event ingest. Device
//! signatures are checked for real. Knobs on [`FakeState`] make it refuse:
//! no free seats, a claim refusal, expired access tokens, a full file quota,
//! damaged uploads, a revoked seat.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::Error;
use crate::cloud::file_hash;
use crate::events::rfc3339_ms;
use crate::http::{BoxFuture, HttpRequest, HttpResponse, Transport};

/// Where the fake's signed upload and download URLs point.
pub const BUCKET_HOST: &str = "bucket.test";
/// The personal account's id.
pub const PERSONAL: &str = "acct-personal";

/// One stored document version.
#[derive(Debug, Clone, PartialEq)]
pub struct DocVersion {
    pub version: i64,
    pub body: Value,
}

/// A support ticket in the fake.
#[derive(Debug, Clone, PartialEq)]
pub struct FakeTicket {
    pub id: String,
    pub device_id: String,
    pub subject: String,
    pub status: String,
    pub created_at: i64,
    pub last_message_at: i64,
    /// `(author, body, at)`, author `you` or `support`.
    pub messages: Vec<(String, String, i64)>,
    pub diagnostics: Option<String>,
}

/// Makes an entitlement token for a device id.
pub type Mint = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// Everything the fake knows, and the knobs that change its answers.
pub struct FakeState {
    /// Feature flags `/v1/entitlements` reports.
    pub features: BTreeSet<String>,
    /// A team the user belongs to, if any.
    pub team: Option<String>,
    /// Licenses free for devices to claim.
    pub free_seats: i64,
    /// Whether the user may release seats.
    pub can_release: bool,
    /// Devices holding licenses, as `GET …/v1/account/seats` lists them.
    pub seats: Vec<Value>,
    /// Device ids whose seats were released or revoked; they get
    /// `410 seat_revoked` at their next renewal, once. Activating or
    /// claiming again is allowed.
    pub released: HashSet<String>,
    /// License keys that activate.
    pub license_keys: HashSet<String>,
    /// The account each key belongs to; unlisted keys are the personal
    /// account's.
    pub key_accounts: HashMap<String, String>,
    /// Suspended keys (reversible): activation and renewal are refused with
    /// `403 license_key_disabled`, and a device keeps its token.
    pub suspended_keys: HashSet<String>,
    /// Revoked or refunded keys: activation is refused with
    /// `403 license_key_disabled`; renewal answers `410 seat_revoked`.
    pub revoked_keys: HashSet<String>,
    /// The key each device activated with.
    pub device_keys: HashMap<String, String>,
    /// Activated devices: id → public key.
    pub devices: HashMap<String, String>,
    /// `(email, password)` that sign in for the seat claim.
    pub credentials: Option<(String, String)>,
    /// Whether that sign-in asks for a TOTP, and the code that passes.
    pub totp: Option<String>,
    /// Refuses the next claims with this status and code, such as
    /// `(403, "email_not_verified")`.
    pub claim_refusal: Option<(u16, String)>,
    /// Makes entitlement tokens for a device id; default `ent-{id}-{n}`.
    pub mint: Option<Mint>,
    /// Stored files, by `account/product/collection/sha256`.
    pub files: BTreeMap<String, Vec<u8>>,
    /// The largest file accepted.
    pub file_cap: usize,
    /// The most an account may store in files, in all.
    pub file_quota: usize,
    /// Damages every upload in the bucket.
    pub damage_uploads: bool,
    /// Collections that take files.
    pub file_collections: BTreeSet<String>,
    pub profiles: BTreeMap<String, Map<String, Value>>,
    pub profile_times: BTreeMap<String, i64>,
    /// `account/product/collection/key` → versions, oldest first.
    pub docs: BTreeMap<String, Vec<DocVersion>>,
    pub deleted: BTreeSet<String>,
    pub tickets: Vec<FakeTicket>,
    /// `(device_id, platform, token)`.
    pub push_tokens: Vec<(String, String, String)>,
    /// Refuses support requests with `429 rate_limited`.
    pub support_rate_limited: bool,
    /// Products the signed-in ticket API refuses as `unknown_product`.
    pub unknown_products: BTreeSet<String>,
    /// Whether signed-in tokens carry `support:write`; without it the
    /// signed-in ticket API answers `403 insufficient_scope`.
    pub support_scope: bool,
    /// Tickets a device may have open (not closed).
    pub open_ticket_cap: usize,
    /// Events ingested, as received.
    pub events: Vec<Value>,
    /// The batch cap event ingest enforces.
    pub event_batch_cap: usize,
    /// Every request, in order.
    pub requests: Vec<HttpRequest>,
    /// The fake's clock, unix seconds.
    pub clock: i64,
    codes: HashMap<String, (String, String)>,
    refresh: HashSet<String>,
    access: HashSet<String>,
    sessions: HashMap<String, (String, bool)>,
    pending_files: HashMap<String, usize>,
    bucket: HashMap<String, Vec<u8>>,
    n: u64,
}

impl Default for FakeState {
    fn default() -> Self {
        FakeState {
            features: BTreeSet::new(),
            team: None,
            free_seats: 0,
            can_release: true,
            seats: Vec::new(),
            released: HashSet::new(),
            license_keys: HashSet::new(),
            key_accounts: HashMap::new(),
            suspended_keys: HashSet::new(),
            revoked_keys: HashSet::new(),
            device_keys: HashMap::new(),
            devices: HashMap::new(),
            credentials: None,
            totp: None,
            claim_refusal: None,
            mint: None,
            files: BTreeMap::new(),
            file_cap: 16 * 1024 * 1024,
            file_quota: 500 * 1024 * 1024,
            damage_uploads: false,
            file_collections: ["luts".to_string()].into(),
            profiles: BTreeMap::new(),
            profile_times: BTreeMap::new(),
            docs: BTreeMap::new(),
            deleted: BTreeSet::new(),
            tickets: Vec::new(),
            push_tokens: Vec::new(),
            support_rate_limited: false,
            unknown_products: BTreeSet::new(),
            support_scope: true,
            open_ticket_cap: 10,
            events: Vec::new(),
            event_batch_cap: 500,
            requests: Vec::new(),
            clock: 1_792_238_400, // 2026-10-17 12:00 UTC
            codes: HashMap::new(),
            refresh: HashSet::new(),
            access: HashSet::new(),
            sessions: HashMap::new(),
            pending_files: HashMap::new(),
            bucket: HashMap::new(),
            n: 0,
        }
    }
}

impl FakeState {
    fn next(&mut self) -> u64 {
        self.n += 1;
        self.n
    }

    fn time(&self) -> String {
        rfc3339_ms(self.clock * 1000)
    }

    /// Makes every live access token stale, as when they expire.
    pub fn expire_access_tokens(&mut self) {
        self.access.clear();
    }

    /// Revokes every token, as a sign-out elsewhere or a reuse detection.
    pub fn revoke_session(&mut self) {
        self.access.clear();
        self.refresh.clear();
    }

    fn version_cap(&self, product: &str) -> usize {
        if self.features.contains(&format!("{product}.backup.history")) {
            100
        } else {
            1
        }
    }

    fn mint_token(&mut self, device_id: &str) -> String {
        match &self.mint {
            Some(m) => m(device_id),
            None => {
                let n = self.next();
                format!("ent-{device_id}-{n}")
            }
        }
    }

    fn tokens(&mut self) -> Value {
        let a = format!("at{}", self.next());
        let r = format!("rt{}", self.next());
        self.access.insert(a.clone());
        self.refresh.insert(r.clone());
        json!({"access_token": a, "token_type": "Bearer", "expires_in": 3600, "refresh_token": r})
    }
}

/// The fake. Share it with `Arc` and pass it as the clients' transport.
#[derive(Default)]
pub struct FakeMeros {
    state: Mutex<FakeState>,
}

fn reply(status: u16, body: Value) -> HttpResponse {
    HttpResponse::json(status, &body)
}

fn err(status: u16, code: &str) -> HttpResponse {
    reply(
        status,
        json!({"error": code, "message": format!("Refused: {code}.")}),
    )
}

fn s(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

impl FakeMeros {
    pub fn new() -> Arc<FakeMeros> {
        Arc::new(FakeMeros::default())
    }

    /// The fake's state, to set knobs and inspect what happened.
    pub fn state(&self) -> MutexGuard<'_, FakeState> {
        self.state.lock().unwrap()
    }

    /// What the browser does on the authorize page: approve, and redirect
    /// back with a code.
    pub fn approve(&self, authorize_url: &str) -> String {
        let u = url::Url::parse(authorize_url).expect("an authorize URL");
        let q: HashMap<String, String> = u.query_pairs().into_owned().collect();
        let mut st = self.state();
        let code = format!("code{}", st.next());
        st.codes.insert(
            code.clone(),
            (q["code_challenge"].clone(), q["redirect_uri"].clone()),
        );
        let mut back = url::Url::parse(&q["redirect_uri"]).expect("a redirect URI");
        back.query_pairs_mut()
            .append_pair("code", &code)
            .append_pair("state", &q["state"]);
        back.to_string()
    }

    /// Support answers a ticket: it becomes `pending` (answered).
    pub fn support_replies(&self, ticket_id: &str, body: &str) {
        let mut st = self.state();
        let clock = st.clock;
        if let Some(t) = st.tickets.iter_mut().find(|t| t.id == ticket_id) {
            t.status = "pending".into();
            t.last_message_at = clock;
            t.messages.push(("support".into(), body.into(), clock));
        }
    }

    /// Requests whose path ends with `suffix`.
    pub fn requests_to(&self, suffix: &str) -> Vec<HttpRequest> {
        self.state()
            .requests
            .iter()
            .filter(|r| {
                url::Url::parse(&r.url)
                    .map(|u| u.path().ends_with(suffix))
                    .unwrap_or(false)
            })
            .cloned()
            .collect()
    }

    fn handle(&self, r: HttpRequest) -> HttpResponse {
        let mut st = self.state();
        st.requests.push(r.clone());
        let Ok(u) = url::Url::parse(&r.url) else {
            return err(400, "bad_url");
        };
        if u.host_str() == Some(BUCKET_HOST) {
            return bucket(&mut st, &r, &u);
        }
        let segs: Vec<String> = u
            .path_segments()
            .map(|s| {
                s.map(|p| {
                    url::form_urlencoded::parse(p.as_bytes())
                        .map(|(k, v)| {
                            if v.is_empty() {
                                k.into_owned()
                            } else {
                                format!("{k}={v}")
                            }
                        })
                        .collect::<String>()
                })
                .collect()
            })
            .unwrap_or_default();
        let segs: Vec<&str> = segs.iter().map(String::as_str).collect();
        let query: HashMap<String, String> = u.query_pairs().into_owned().collect();
        match segs.as_slice() {
            ["oauth", "token"] => oauth_token(&mut st, &r),
            ["oauth", "revoke"] => {
                st.revoke_session();
                HttpResponse::new(200, Vec::new())
            }
            // The device API, at `/app/{product}/v1/…` or a service's own
            // root.
            ["app", _, "v1", rest @ ..] | ["v1", rest @ ..]
                if matches!(
                    rest.first(),
                    Some(&("device" | "offline" | "apple" | "account"))
                ) || rest.starts_with(&["support", "tickets"]) =>
            {
                device_api(&mut st, &r, rest)
            }
            _ => {
                let token = r
                    .header_value("Authorization")
                    .unwrap_or("")
                    .trim_start_matches("Bearer ")
                    .to_string();
                if !st.access.contains(&token) {
                    return err(401, "invalid_token");
                }
                let account = r
                    .header_value("X-Meros-Account")
                    .unwrap_or(PERSONAL)
                    .to_string();
                cloud(&mut st, &r, &segs, &query, &account)
            }
        }
    }
}

impl Transport for FakeMeros {
    fn send(&self, request: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, Error>> {
        let response = self.handle(request);
        Box::pin(async move { Ok(response) })
    }
}

fn oauth_token(st: &mut FakeState, r: &HttpRequest) -> HttpResponse {
    let f: HashMap<String, String> = r.form_fields().into_iter().collect();
    match f.get("grant_type").map(String::as_str) {
        Some("authorization_code") => {
            let Some((challenge, redirect)) = f.get("code").and_then(|c| st.codes.remove(c)) else {
                return err(400, "invalid_grant");
            };
            let verifier = f.get("code_verifier").cloned().unwrap_or_default();
            let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
            if expected != challenge || f.get("redirect_uri") != Some(&redirect) {
                return err(400, "invalid_grant");
            }
            let t = st.tokens();
            reply(200, t)
        }
        Some("refresh_token") => {
            // Rotation: each refresh token works once.
            if !f.get("refresh_token").is_some_and(|t| st.refresh.remove(t)) {
                return err(400, "invalid_grant");
            }
            let t = st.tokens();
            reply(200, t)
        }
        _ => err(400, "unsupported_grant_type"),
    }
}

fn bucket(st: &mut FakeState, r: &HttpRequest, u: &url::Url) -> HttpResponse {
    let id = u.path().trim_start_matches('/').to_string();
    if r.method == "PUT" {
        let mut bytes = r.body.clone();
        if st.damage_uploads && !bytes.is_empty() {
            bytes[0] ^= 0xff;
        }
        st.bucket.insert(id, bytes);
        return HttpResponse::new(200, Vec::new());
    }
    match st.files.get(&id) {
        Some(b) => HttpResponse::new(200, b.clone()),
        None => HttpResponse::new(404, Vec::new()),
    }
}

/// Checks a device signature: `"{method}|{path}|{device_id}|{ts}"`.
fn signed(pubkey: &str, method: &str, path: &str, device_id: &str, ts: i64, sig: &str) -> bool {
    let (Ok(key), Ok(sig)) = (URL_SAFE_NO_PAD.decode(pubkey), URL_SAFE_NO_PAD.decode(sig)) else {
        return false;
    };
    let (Ok(key), Ok(sig)) = (
        <[u8; 32]>::try_from(key.as_slice()),
        Signature::from_slice(&sig),
    ) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&key) else {
        return false;
    };
    key.verify(format!("{method}|{path}|{device_id}|{ts}").as_bytes(), &sig)
        .is_ok()
}

/// The account a sign-in claim lands on: the user's team, else their own.
fn claim_account(st: &FakeState) -> String {
    st.team.clone().unwrap_or_else(|| PERSONAL.into())
}

/// Gives the device a seat on `account`. A device holding a seat on another
/// account moves here (that seat is freed and its push tokens dropped),
/// unless the request is signed with a different key than the device
/// registered: then `409 device_id_in_use`.
fn seat_for(st: &mut FakeState, device: &Value, account: &str) -> Result<(), HttpResponse> {
    let id = s(device, "id");
    let pubkey = s(device, "pubkey");
    let held = st.seats.iter().position(|x| x["device_id"] == id);
    if let Some(i) = held {
        if st.seats[i]["account_id"] == account {
            return Ok(());
        }
        let registered = st.devices.get(&id).cloned().unwrap_or_default();
        if !pubkey.is_empty() && pubkey != registered {
            return Err(reply(
                409,
                json!({
                    "error": "device_id_in_use",
                    "message": "This device is licensed on another account. Release it there first.",
                }),
            ));
        }
    }
    if st.free_seats <= 0 {
        return Err(err(409, "no_seats_available"));
    }
    if let Some(i) = held {
        st.seats.remove(i);
        st.free_seats += 1;
        st.push_tokens.retain(|(d, _, _)| *d != id);
    }
    st.free_seats -= 1;
    let seat_id = (st.seats.len() + st.released.len() + 1) as i64;
    let (account_name, account_type) = if account == PERSONAL {
        ("Pat".to_string(), "person")
    } else if st.team.as_deref() == Some(account) {
        ("Crew".to_string(), "org")
    } else {
        (account.to_string(), "org")
    };
    let time = st.time();
    st.seats.push(json!({
        "seat_id": seat_id,
        "device_id": id,
        "name": device.get("name"),
        "model": device.get("model"),
        "activated_at": time,
        "last_seen_at": time,
        "account_id": account,
        "account_name": account_name,
        "account_type": account_type,
        "can_release": st.can_release,
    }));
    if !pubkey.is_empty() {
        st.devices.entry(id.clone()).or_insert(pubkey);
    }
    st.released.remove(&id);
    Ok(())
}

fn entitlement(st: &mut FakeState, device_id: &str) -> HttpResponse {
    let token = st.mint_token(device_id);
    reply(200, json!({"token": token, "entitlement_token": token}))
}

/// `/app/{product}/v1/…`: the device license API, seats with the app's
/// sign-in, and support.
fn device_api(st: &mut FakeState, r: &HttpRequest, rest: &[&str]) -> HttpResponse {
    let path = format!("/v1/{}", rest.join("/"));
    let body = r.json_body().unwrap_or(Value::Null);
    let ts = body.get("ts").and_then(|v| v.as_i64()).unwrap_or(0);
    let sig = s(&body, "sig");
    let bearer = r
        .header_value("Authorization")
        .map(|a| a.trim_start_matches("Bearer ").to_string());

    // Self-signed requests carry their public key.
    let self_signed = |sign_path: &str| {
        let d = body.get("device").cloned().unwrap_or(Value::Null);
        signed(&s(&d, "pubkey"), "POST", sign_path, &s(&d, "id"), ts, &sig)
    };
    // The rest are checked against the key stored at activation.
    let known = |st: &FakeState, method: &str, id: &str, ts: i64, sig: &str| {
        st.devices
            .get(id)
            .is_some_and(|k| signed(k, method, &path, id, ts, sig))
    };

    match (r.method.as_str(), rest) {
        ("POST", ["device", "activate"]) | ("POST", ["offline", "activate"]) => {
            let key = s(&body, "license_key");
            if !st.license_keys.contains(&key) {
                return err(404, "unknown_license_key");
            }
            if st.suspended_keys.contains(&key) || st.revoked_keys.contains(&key) {
                return err(403, "license_key_disabled");
            }
            if !self_signed("/v1/device/activate") {
                return err(401, "bad_signature");
            }
            let d = body["device"].clone();
            st.free_seats += 1; // a key always has room
            let account = st
                .key_accounts
                .get(&s(&body, "license_key"))
                .cloned()
                .unwrap_or_else(|| PERSONAL.into());
            if let Err(e) = seat_for(st, &d, &account) {
                return e;
            }
            st.device_keys.insert(s(&d, "id"), key);
            entitlement(st, &s(&d, "id"))
        }
        ("POST", ["apple", "redeem"]) => {
            if s(&body, "signed_transaction").is_empty() {
                return err(422, "invalid_transaction");
            }
            if !self_signed(&path) {
                return err(401, "bad_signature");
            }
            let d = body["device"].clone();
            st.free_seats += 1;
            if let Err(e) = seat_for(st, &d, PERSONAL) {
                return e;
            }
            entitlement(st, &s(&d, "id"))
        }
        ("POST", ["device", "renew"]) | ("POST", ["device", "release"]) => {
            let id = s(&body, "device_id");
            if !st.devices.contains_key(&id) {
                return err(404, "unknown_device");
            }
            if !known(st, "POST", &id, ts, &sig) {
                return err(401, "bad_signature");
            }
            if rest[1] == "release" {
                st.seats.retain(|x| x["device_id"] != id);
                st.devices.remove(&id);
                return reply(200, json!({"released": true}));
            }
            if st.released.remove(&id) || !st.seats.iter().any(|x| x["device_id"] == id) {
                return err(410, "seat_revoked");
            }
            let key = st.device_keys.get(&id).cloned().unwrap_or_default();
            if st.revoked_keys.contains(&key) {
                st.seats.retain(|x| x["device_id"] != id);
                return err(410, "seat_revoked");
            }
            if st.suspended_keys.contains(&key) {
                return err(403, "license_key_disabled");
            }
            entitlement(st, &id)
        }
        ("POST", ["account", "authenticate"]) => {
            if !self_signed(&path) {
                return err(401, "bad_signature");
            }
            let ok = st
                .credentials
                .as_ref()
                .is_some_and(|(e, p)| *e == s(&body, "email") && *p == s(&body, "password"));
            if !ok {
                return err(401, "bad_credentials");
            }
            let d = body["device"].clone();
            let session = format!("sess{}", st.next());
            let needs_totp = st.totp.is_some();
            st.sessions
                .insert(session.clone(), (s(&d, "id"), !needs_totp));
            st.devices
                .entry(s(&d, "id"))
                .or_insert_with(|| s(&d, "pubkey"));
            reply(
                200,
                json!({
                    "status": if needs_totp { "totp_required" } else { "authenticated" },
                    "session": session,
                    "account_name": "Pat",
                    "account_type": "person",
                    "seats_available": st.free_seats,
                }),
            )
        }
        ("POST", ["account", "authenticate", "totp"]) => {
            let id = s(&body, "device_id");
            if !known(st, "POST", &id, ts, &sig) {
                return err(401, "bad_signature");
            }
            let session = s(&body, "session");
            if st.sessions.get(&session).is_none_or(|(d, _)| *d != id) {
                return err(401, "session_expired");
            }
            if st.totp.as_deref() != Some(s(&body, "code").as_str()) {
                return err(401, "bad_totp");
            }
            st.sessions.insert(session.clone(), (id, true));
            reply(200, json!({"status": "authenticated", "session": session}))
        }
        ("POST", ["account", "claim"]) if bearer.is_none() => {
            let id = s(&body, "device_id");
            if !known(st, "POST", &id, ts, &sig) {
                return err(401, "bad_signature");
            }
            let session = s(&body, "session");
            if st
                .sessions
                .remove(&session)
                .is_none_or(|(d, ok)| d != id || !ok)
            {
                return err(401, "session_expired");
            }
            let pubkey = st.devices.get(&id).cloned().unwrap_or_default();
            let account = claim_account(st);
            if let Err(e) = seat_for(st, &json!({"id": id, "pubkey": pubkey}), &account) {
                return e;
            }
            entitlement(st, &id)
        }
        (_, ["account", ..]) => {
            if !bearer.as_ref().is_some_and(|b| st.access.contains(b)) {
                // The claim answers in licensing's words; the seats API's
                // guard, as Laravel's, with only a message.
                if rest.last() != Some(&"claim") {
                    return reply(401, json!({"message": "Unauthenticated."}));
                }
                return err(401, "unauthenticated");
            }
            account_api(st, r, rest, &body, ts, &sig)
        }
        ("POST", ["device", "push-token"]) => {
            let id = s(&body, "device_id");
            if !known(st, "POST", &id, ts, &sig) {
                return err(401, "unknown_device");
            }
            st.push_tokens
                .push((id, s(&body, "platform"), s(&body, "token")));
            reply(200, json!({"registered": true}))
        }
        (method, ["support", "tickets", ..]) => support_api(st, r, method, rest, &body, &path),
        _ => err(404, "not_found"),
    }
}

fn account_api(
    st: &mut FakeState,
    r: &HttpRequest,
    rest: &[&str],
    body: &Value,
    ts: i64,
    sig: &str,
) -> HttpResponse {
    match (r.method.as_str(), rest) {
        ("POST", ["account", "claim"]) => {
            let d = body.get("device").cloned().unwrap_or(Value::Null);
            let id = s(&d, "id");
            if id.is_empty() || !signed(&s(&d, "pubkey"), "POST", "/v1/account/claim", &id, ts, sig)
            {
                return err(401, "bad_signature");
            }
            if let Some((status, code)) = st.claim_refusal.clone() {
                return err(status, &code);
            }
            let account = claim_account(st);
            if let Err(e) = seat_for(st, &d, &account) {
                return e;
            }
            entitlement(st, &id)
        }
        ("GET", ["account", "seats"]) => reply(200, json!({"seats": st.seats})),
        ("POST", ["account", "seats", id, "release"]) => {
            let id: i64 = id.parse().unwrap_or(-1);
            let Some(i) = st.seats.iter().position(|x| x["seat_id"] == id) else {
                return err(404, "not_found");
            };
            if st.seats[i]["can_release"] != true {
                return err(403, "forbidden");
            }
            let seat = st.seats.remove(i);
            st.released.insert(s(&seat, "device_id"));
            st.free_seats += 1;
            reply(200, json!({"seat_id": id, "released": true}))
        }
        _ => err(404, "not_found"),
    }
}

fn ticket_json(t: &FakeTicket) -> Value {
    json!({
        "id": t.id, "subject": t.subject, "status": t.status,
        "created_at": t.created_at, "last_message_at": t.last_message_at,
    })
}

fn support_api(
    st: &mut FakeState,
    r: &HttpRequest,
    method: &str,
    rest: &[&str],
    body: &Value,
    path: &str,
) -> HttpResponse {
    let (id, ts, sig) = if method == "GET" {
        (
            r.header_value("X-Device-Id").unwrap_or("").to_string(),
            r.header_value("X-Ts")
                .and_then(|t| t.parse().ok())
                .unwrap_or(0),
            r.header_value("X-Sig").unwrap_or("").to_string(),
        )
    } else {
        (
            s(body, "device_id"),
            body.get("ts").and_then(|v| v.as_i64()).unwrap_or(0),
            s(body, "sig"),
        )
    };
    let Some(key) = st.devices.get(&id).cloned() else {
        return err(401, "unknown_device");
    };
    if !signed(&key, method, path, &id, ts, &sig) {
        return err(401, "bad_signature");
    }
    tickets(st, &id, method, &rest[2..], body)
}

/// The ticket store both support APIs share; `owner` is the device id or,
/// for the signed-in API, the user and product.
fn tickets(
    st: &mut FakeState,
    owner: &str,
    method: &str,
    rest: &[&str],
    body: &Value,
) -> HttpResponse {
    let id = owner.to_string();
    let clock = st.clock;
    match (method, rest) {
        _ if st.support_rate_limited => reply(
            429,
            json!({"error": "rate_limited", "message": "Too many requests. Try again later."}),
        ),
        ("POST", []) => {
            let subject = s(body, "subject");
            let message = s(body, "message");
            if subject.chars().any(char::is_control) {
                return err(422, "invalid_subject");
            }
            // An identical resend returns the first ticket.
            if let Some(t) = st.tickets.iter().find(|t| {
                t.device_id == id
                    && t.subject == subject
                    && t.messages.first().map(|m| &m.1) == Some(&message)
            }) {
                return reply(200, json!({"ticket": ticket_json(t)}));
            }
            let open = st
                .tickets
                .iter()
                .filter(|t| t.device_id == id && t.status != "closed")
                .count();
            if open >= st.open_ticket_cap {
                return err(429, "too_many_open_tickets");
            }
            let n = st.next();
            let t = FakeTicket {
                id: format!("tkt_{n}"),
                device_id: id,
                subject: s(body, "subject"),
                status: "open".into(),
                created_at: clock,
                last_message_at: clock,
                messages: vec![("you".into(), s(body, "message"), clock)],
                diagnostics: body
                    .get("app_diagnostics")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
            };
            let j = ticket_json(&t);
            st.tickets.push(t);
            reply(200, json!({"ticket": j}))
        }
        ("GET", []) => {
            let list: Vec<Value> = st
                .tickets
                .iter()
                .filter(|t| t.device_id == id)
                .map(ticket_json)
                .collect();
            reply(200, json!({"tickets": list}))
        }
        ("GET", [tid]) => match st
            .tickets
            .iter()
            .find(|t| t.id == *tid && t.device_id == id)
        {
            Some(t) => reply(
                200,
                json!({
                    "ticket": ticket_json(t),
                    "messages": t.messages.iter().map(|(a, b, at)| json!({"author": a, "body": b, "at": at})).collect::<Vec<_>>(),
                }),
            ),
            None => err(404, "unknown_ticket"),
        },
        ("POST", [tid, "messages"]) => match st
            .tickets
            .iter_mut()
            .find(|t| t.id == *tid && t.device_id == id)
        {
            Some(t) => {
                t.status = "open".into();
                t.last_message_at = clock;
                t.messages.push(("you".into(), s(body, "message"), clock));
                let j = ticket_json(t);
                reply(200, json!({"ticket": j}))
            }
            None => err(404, "unknown_ticket"),
        },
        _ => err(404, "not_found"),
    }
}

fn cloud(
    st: &mut FakeState,
    r: &HttpRequest,
    segs: &[&str],
    query: &HashMap<String, String>,
    account: &str,
) -> HttpResponse {
    let body = r.json_body().unwrap_or(Value::Null);
    match (r.method.as_str(), segs) {
        ("GET", ["oauth", "userinfo"]) => reply(
            200,
            json!({"sub": "u1", "name": "Pat", "email": "pat@example.com"}),
        ),
        ("GET", ["v1", "accounts"]) => {
            let mut list = vec![
                json!({"id": PERSONAL, "type": "person", "name": "Pat", "role": "owner", "default": st.team.is_none()}),
            ];
            if let Some(t) = &st.team {
                list.push(json!({"id": t, "type": "org", "name": "Crew", "role": "member", "default": true}));
            }
            reply(200, json!({"accounts": list}))
        }
        ("GET", ["v1", "entitlements"]) => {
            if let Some(a) = query.get("account_id")
                && a != PERSONAL
                && Some(a) != st.team.as_ref()
            {
                return err(403, "forbidden");
            }
            let mut f: Map<String, Value> = st
                .features
                .iter()
                .map(|k| (k.clone(), json!(true)))
                .collect();
            f.insert(
                "tier".into(),
                json!(if st.features.is_empty() {
                    "free"
                } else {
                    "pro"
                }),
            );
            reply(200, json!({"product": query.get("product"), "features": f}))
        }
        (_, ["v1", "profiles", ns]) => profiles(st, &r.method, ns, &body),
        (_, ["v1", "docs", product, collection, rest @ ..]) => {
            if account != PERSONAL && Some(account) != st.team.as_deref() {
                return err(403, "forbidden");
            }
            docs(
                st,
                &r.method,
                &format!("{account}/{product}/{collection}"),
                product,
                rest,
                query,
                &body,
            )
        }
        (_, ["v1", "files", product, collection, rest @ ..]) => {
            if !st.file_collections.contains(*collection) {
                return err(404, "not_found");
            }
            files(
                st,
                &r.method,
                account,
                &format!("{account}/{product}/{collection}"),
                rest,
                &body,
            )
        }
        ("POST", ["v1", "events"]) => ingest(st, &body),
        (method, ["v1", "support", product, "tickets", rest @ ..]) => {
            if !st.support_scope {
                return err(403, "insufficient_scope");
            }
            if st.unknown_products.contains(*product) {
                return err(404, "unknown_product");
            }
            tickets(st, &format!("user:u1/{product}"), method, rest, &body)
        }
        _ => err(404, "not_found"),
    }
}

fn profiles(st: &mut FakeState, method: &str, ns: &str, body: &Value) -> HttpResponse {
    if method == "DELETE" {
        st.profiles.remove(ns);
        return reply(200, json!({"deleted": true}));
    }
    let clock = st.clock;
    let mut p = st.profiles.get(ns).cloned().unwrap_or_default();
    if method == "PUT" {
        let keys = body
            .get("keys")
            .and_then(|k| k.as_object())
            .cloned()
            .unwrap_or_default();
        let mut merged = p.clone();
        merged.extend(keys.clone());
        if serde_json::to_vec(&merged).map(|v| v.len()).unwrap_or(0) > 256 * 1024 {
            return err(413, "profile_too_large");
        }
        for (k, v) in keys {
            if v.is_null() {
                p.remove(&k);
            } else {
                p.insert(k.clone(), v);
            }
            st.profile_times.insert(format!("{ns}/{k}"), clock);
        }
        st.profiles.insert(ns.to_string(), p.clone());
    }
    let meta: Map<String, Value> = p
        .keys()
        .map(|k| {
            let t = st
                .profile_times
                .get(&format!("{ns}/{k}"))
                .copied()
                .unwrap_or(clock);
            (k.clone(), json!(rfc3339_ms(t * 1000)))
        })
        .collect();
    reply(
        200,
        json!({"namespace": ns, "keys": p, "key_meta": meta, "updated_at": st.time()}),
    )
}

fn docs(
    st: &mut FakeState,
    method: &str,
    base: &str,
    product: &str,
    rest: &[&str],
    query: &HashMap<String, String>,
    body: &Value,
) -> HttpResponse {
    let time = st.time();
    if rest.is_empty() {
        let list: Vec<Value> = st
            .docs
            .iter()
            .filter(|(k, _)| k.starts_with(&format!("{base}/")) && !st.deleted.contains(*k))
            .map(|(k, v)| json!({"key": &k[base.len() + 1..], "head_version": v.last().map(|d| d.version), "updated_at": time}))
            .collect();
        return reply(200, json!({"documents": list}));
    }
    let key = rest[0];
    let id = format!("{base}/{key}");
    if rest.get(1) == Some(&"versions") {
        let Some(v) = st.docs.get(&id) else {
            return err(404, "not_found");
        };
        let list: Vec<Value> = v
            .iter()
            .rev()
            .map(|d| json!({"version": d.version, "created_at": time, "size_bytes": 10}))
            .collect();
        return reply(200, json!({"versions": list}));
    }
    match method {
        "GET" => {
            let Some(versions) = st.docs.get(&id).filter(|_| !st.deleted.contains(&id)) else {
                return err(404, "not_found");
            };
            let want: Option<i64> = query.get("version").and_then(|v| v.parse().ok());
            let found = match want {
                None => versions.last(),
                Some(w) => versions.iter().find(|d| d.version == w),
            };
            match found {
                Some(d) => reply(
                    200,
                    json!({"key": key, "version": d.version, "head_version": versions.last().unwrap().version, "body": d.body}),
                ),
                None => err(404, "not_found"),
            }
        }
        "PUT" => {
            let head = st
                .docs
                .get(&id)
                .and_then(|v| v.last())
                .map(|d| d.version)
                .unwrap_or(0);
            if let Some(b) = body.get("base_version").and_then(|v| v.as_i64())
                && b != head
            {
                return reply(
                    409,
                    json!({"error": "version_conflict", "message": "Stale.", "head": {"version": head}}),
                );
            }
            let cap = st.version_cap(product);
            let list = st.docs.entry(id.clone()).or_default();
            list.push(DocVersion {
                version: head + 1,
                body: body.get("body").cloned().unwrap_or(json!({})),
            });
            while list.len() > cap {
                list.remove(0);
            }
            st.deleted.remove(&id);
            reply(
                201,
                json!({"key": key, "version": head + 1, "head_version": head + 1}),
            )
        }
        "DELETE" => {
            if !st.docs.contains_key(&id) {
                return err(404, "not_found");
            }
            st.deleted.insert(id);
            HttpResponse::new(204, Vec::new())
        }
        _ => err(405, "method_not_allowed"),
    }
}

fn describe(sha: &str, size: usize, status: &str, time: &str) -> Value {
    json!({"sha256": sha, "size": size, "status": status, "created_at": time})
}

fn files(
    st: &mut FakeState,
    method: &str,
    account: &str,
    base: &str,
    rest: &[&str],
    body: &Value,
) -> HttpResponse {
    let time = st.time();
    if rest.is_empty() {
        if method == "GET" {
            let list: Vec<Value> = st
                .files
                .iter()
                .filter(|(k, _)| k.starts_with(&format!("{base}/")))
                .map(|(k, v)| {
                    describe(k.rsplit('/').next().unwrap_or(""), v.len(), "stored", &time)
                })
                .collect();
            return reply(200, json!({"files": list}));
        }
        let sha = s(body, "sha256");
        let size = body.get("size").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let id = format!("{base}/{sha}");
        if st.files.contains_key(&id) {
            let mut d = describe(&sha, size, "stored", &time);
            d["upload"] = Value::Null;
            return reply(200, d);
        }
        if size > st.file_cap {
            return err(413, "file_too_large");
        }
        let used: usize = st
            .files
            .iter()
            .filter(|(k, _)| k.starts_with(&format!("{account}/")))
            .map(|(_, v)| v.len())
            .sum();
        if used + size > st.file_quota {
            return err(413, "quota_exceeded");
        }
        st.pending_files.insert(id.clone(), size);
        let mut d = describe(&sha, size, "pending", &time);
        d["upload"] = json!({
            "url": format!("https://{BUCKET_HOST}/{id}"),
            "headers": {"Content-Type": "application/octet-stream"},
            "expires_at": rfc3339_ms((st.clock + 900) * 1000),
        });
        return reply(201, d);
    }
    let sha = rest[0];
    let id = format!("{base}/{sha}");
    if rest.get(1) == Some(&"complete") {
        let (Some(bytes), Some(size)) = (st.bucket.remove(&id), st.pending_files.get(&id).copied())
        else {
            return err(409, "not_uploaded");
        };
        st.pending_files.remove(&id);
        if bytes.len() != size || file_hash(&bytes) != sha {
            return err(422, "file_mismatch");
        }
        st.files.insert(id, bytes);
        return reply(200, describe(sha, size, "stored", &time));
    }
    let Some(len) = st.files.get(&id).map(Vec::len) else {
        return err(404, "not_found");
    };
    if method == "DELETE" {
        st.files.remove(&id);
        return reply(200, json!({"sha256": sha, "deleted": true}));
    }
    let mut d = describe(sha, len, "stored", &time);
    d["download"] = json!({"url": format!("https://{BUCKET_HOST}/{id}"), "expires_at": rfc3339_ms((st.clock + 900) * 1000)});
    reply(200, d)
}

fn ingest(st: &mut FakeState, body: &Value) -> HttpResponse {
    let events: Vec<Value> = match body {
        Value::Array(a) => a.clone(),
        Value::Object(_) => vec![body.clone()],
        _ => return err(422, "invalid_body"),
    };
    if events.len() > st.event_batch_cap {
        return reply(
            413,
            json!({"error": "batch_too_large", "max": st.event_batch_cap}),
        );
    }
    let (mut accepted, mut duplicates, mut rejected) = (0, 0, 0);
    let mut errors = Vec::new();
    for e in events {
        let ok = e.get("envelope") == Some(&json!(1))
            && ["id", "occurred_at", "type", "severity"]
                .iter()
                .all(|k| e.get(*k).is_some_and(|v| v.is_string()))
            && e.pointer("/source/instance").is_some_and(|v| v.is_string());
        if !ok {
            rejected += 1;
            errors.push(json!("invalid envelope"));
            continue;
        }
        let dup = st
            .events
            .iter()
            .any(|x| x["id"] == e["id"] && x["source"]["instance"] == e["source"]["instance"]);
        if dup {
            duplicates += 1;
        } else {
            accepted += 1;
            st.events.push(e);
        }
    }
    reply(
        202,
        json!({"accepted": accepted, "duplicates": duplicates, "rejected": rejected, "errors": errors}),
    )
}
