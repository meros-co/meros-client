//! The device license API: activate with a key, renew, release, claim a seat
//! by signing in (with TOTP) or with the app's Meros sign-in, App Store
//! redeem, "manage online" and browser-claim links, offline activation, and
//! license deep links.
//!
//! Requests are signed by the app's [`LicenseDevice`]; returned entitlement
//! tokens go straight back to it to verify and store.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::Error;
use crate::auth::AccessTokenSource;
use crate::device::LicenseDevice;
use crate::http::{HttpRequest, HttpResponse, Transport, unix_now};

/// Which license service and app this client speaks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseConfig {
    /// The product's device base, such as `https://<host>/app/<product>`
    /// (paths start at `/v1/…`). The app supplies it.
    pub base_url: String,
    /// Used in the default device name: "{app_name} {os} ({model})".
    pub app_name: String,
    /// Reported to the service as `device.app_version`.
    pub app_version: String,
}

/// Result of `POST /v1/account/authenticate[/totp]`: `authenticated`
/// (claim next) or `totp_required` (send the code). The opaque `session`
/// threads the steps together (10 minutes, single use).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AuthResult {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub session: String,
    pub account_name: Option<String>,
    pub account_type: Option<String>,
    pub seats_available: Option<i64>,
}

impl AuthResult {
    pub fn needs_totp(&self) -> bool {
        self.status == "totp_required"
    }
}

/// A device holding one of the product's licenses on the signed-in user's
/// team or personal account, from `GET /v1/account/seats`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct LicenseSeat {
    pub seat_id: i64,
    #[serde(default)]
    pub device_id: String,
    #[serde(default, deserialize_with = "or_empty")]
    pub name: String,
    #[serde(default, deserialize_with = "or_empty")]
    pub model: String,
    /// ISO 8601.
    pub activated_at: Option<String>,
    pub last_seen_at: Option<String>,
    #[serde(default)]
    pub account_id: String,
    #[serde(default)]
    pub account_name: String,
    /// `org` for a team, `person` for the user's own account.
    #[serde(default)]
    pub account_type: String,
    /// Whether the user may release it: a team's owners, admins and billing
    /// managers, and a personal account's owner.
    #[serde(default)]
    pub can_release: bool,
}

fn or_empty<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    Ok(Option::<String>::deserialize(d)?.unwrap_or_default())
}

/// What [`LicenseClient::adopt_after_sign_in`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignInClaim {
    /// The service answered with a token for this device's seat, now
    /// applied: an unowned license (a guest or App Store purchase) adopted by
    /// the account, or an owned one refreshed.
    Claimed,
    /// The license belongs to an account the user can't claim a seat on
    /// (`no_seats_available`): the current license is kept, and nothing
    /// needs showing.
    KeptCurrent,
    /// The device holds no license, so nothing was sent. Claiming one is
    /// the user's choice ([`LicenseClient::claim_with_account`]).
    NotLicensed,
}

type Hook = Arc<dyn Fn() + Send + Sync>;

/// The licensing client.
pub struct LicenseClient {
    pub config: LicenseConfig,
    transport: Arc<dyn Transport>,
    device: Arc<dyn LicenseDevice>,
    now: Arc<dyn Fn() -> i64 + Send + Sync>,
    on_changed: Option<Hook>,
    on_activated: Option<Hook>,
}

impl LicenseClient {
    pub fn new(
        config: LicenseConfig,
        transport: Arc<dyn Transport>,
        device: Arc<dyn LicenseDevice>,
    ) -> Self {
        LicenseClient {
            config,
            transport,
            device,
            now: Arc::new(unix_now),
            on_changed: None,
            on_activated: None,
        }
    }

    /// Called whenever the device's entitlement changes (activated, claimed,
    /// imported, renewed, released, dropped), so license UIs refresh.
    pub fn on_changed(mut self, hook: impl Fn() + Send + Sync + 'static) -> Self {
        self.on_changed = Some(Arc::new(hook));
        self
    }

    /// Called once the device is known to the service (activation, claim,
    /// App Store redeem, offline import), such as to register a push token
    /// the service refused while the device was unknown. A device that moved
    /// to another account loses its push tokens there, so register again
    /// every time.
    pub fn on_activated(mut self, hook: impl Fn() + Send + Sync + 'static) -> Self {
        self.on_activated = Some(Arc::new(hook));
        self
    }

    /// Replaces the clock (unix seconds), for tests.
    pub fn with_clock(mut self, now: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.now = Arc::new(now);
        self
    }

    fn changed(&self) {
        if let Some(h) = &self.on_changed {
            h();
        }
    }

    fn activated(&self) {
        if let Some(h) = &self.on_activated {
            h();
        }
    }

    /// Drops the stored entitlement and reports the change. Use this rather
    /// than clearing the token directly, so open license screens refresh.
    pub fn drop_entitlement(&self) {
        self.device.clear_token();
        self.changed();
    }

    /// The server answered `unknown_device` to a device-signed request: a
    /// token we hold can't be genuine for this server (stale data from
    /// another environment, a deregistered device). Drop it.
    fn drop_if_unknown(&self, code: &str) {
        if code == "unknown_device" {
            self.drop_entitlement();
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.config.base_url)
    }

    fn identity(&self) -> Result<crate::DeviceIdentity, Error> {
        self.device.identity().ok_or_else(Error::no_identity)
    }

    fn sig(&self, method: &str, path: &str, ts: i64) -> Result<String, Error> {
        self.device
            .sign(method, path, ts)
            .ok_or_else(Error::no_identity)
    }

    /// The `device{…}` block sent in self-signed requests.
    fn device_block(&self, device_name: Option<&str>) -> Result<Value, Error> {
        let id = self.identity()?;
        let model = self.device.model();
        let mut name = device_name.unwrap_or("").trim().to_string();
        if name.is_empty() {
            name = self.device.name().unwrap_or_default().trim().to_string();
        }
        if name.is_empty() {
            name = format!(
                "{} {} ({model})",
                self.config.app_name,
                std::env::consts::OS
            );
        }
        Ok(json!({
            "id": id.id,
            "pubkey": id.pubkey,
            "name": name,
            "model": model,
            "app_version": self.config.app_version,
        }))
    }

    fn activate_body(&self, license_key: &str, device_name: Option<&str>) -> Result<Value, Error> {
        let ts = (self.now)();
        Ok(json!({
            "license_key": license_key.trim(),
            "device": self.device_block(device_name)?,
            "ts": ts,
            "sig": self.sig("POST", "/v1/device/activate", ts)?,
        }))
    }

    async fn post(&self, path: &str, body: &Value) -> Result<HttpResponse, Error> {
        self.transport
            .send(HttpRequest::new("POST", self.url(path)).json(body))
            .await
    }

    /// Fails with the server's code, dropping a foreign entitlement.
    fn refused(&self, r: &HttpResponse) -> Error {
        let e = Error::from_response(r);
        self.drop_if_unknown(&e.code);
        e
    }

    fn apply_token(&self, r: &HttpResponse) -> Result<(), Error> {
        let body = r.value();
        let token = body
            .get("entitlement_token")
            .or_else(|| body.get("token"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                Error::new(
                    Some(r.status),
                    "bad_response",
                    "No entitlement token returned.",
                )
            })?;
        self.device
            .apply_token(token)
            .map_err(|e| Error::new(None, "token_rejected", format!("Token rejected: {e}")))?;
        self.changed();
        Ok(())
    }

    /// Activates this device with a license key, then verifies and stores
    /// the entitlement. A revoked seat doesn't stop it: the device may
    /// activate again with any key, the same one included. A suspended,
    /// revoked or refunded key is refused with `license_key_disabled`. A key of another
    /// account moves the device there; a
    /// device whose seat elsewhere was taken with a different key gets
    /// `device_id_in_use` (show its message).
    pub async fn activate(
        &self,
        license_key: &str,
        device_name: Option<&str>,
    ) -> Result<(), Error> {
        let body = self.activate_body(license_key, device_name)?;
        let r = self.post("/v1/device/activate", &body).await?;
        if r.status != 200 {
            return Err(self.refused(&r));
        }
        self.apply_token(&r)?;
        self.activated();
        Ok(())
    }

    /// Redeems an App Store purchase: the StoreKit 2 signed transaction goes
    /// to the server, which verifies it with Apple and activates this
    /// device on the purchase's account. Redeeming again moves the seat.
    pub async fn redeem_app_store(
        &self,
        signed_transaction: &str,
        device_name: Option<&str>,
    ) -> Result<(), Error> {
        let path = "/v1/apple/redeem";
        let ts = (self.now)();
        let body = json!({
            "signed_transaction": signed_transaction,
            "device": self.device_block(device_name)?,
            "ts": ts,
            "sig": self.sig("POST", path, ts)?,
        });
        let r = self.post(path, &body).await?;
        if r.status != 200 {
            return Err(self.refused(&r));
        }
        self.apply_token(&r)?;
        self.activated();
        Ok(())
    }

    /// "Manage online": the website for the account this device holds a
    /// seat on, as a device-signed link (virtual path `/manage`).
    pub fn manage_url(&self) -> Result<String, Error> {
        let ts = (self.now)();
        let blob = json!({
            "device_id": self.identity()?.id,
            "ts": ts,
            "sig": self.sig("GET", "/manage", ts)?,
        });
        Ok(format!(
            "{}?request={}",
            self.url("/manage"),
            unpadded(&blob)
        ))
    }

    /// Browser sign-in claim: a device-signed claim the website redeems once
    /// the user signs in there (virtual path `/claim`). The site answers with
    /// a [`LicenseLink::Claim`] deep link.
    pub fn browser_claim_url(&self) -> Result<String, Error> {
        let ts = (self.now)();
        let blob = json!({
            "device": self.device_block(None)?,
            "ts": ts,
            "sig": self.sig("GET", "/claim", ts)?,
        });
        Ok(format!(
            "{}?request={}",
            self.url("/claim"),
            unpadded(&blob)
        ))
    }

    /// Offline activation: the `request_blob` the user pastes into the
    /// browser activation page.
    pub fn offline_request_blob(
        &self,
        license_key: &str,
        device_name: Option<&str>,
    ) -> Result<String, Error> {
        let body = self.activate_body(license_key, device_name)?;
        Ok(URL_SAFE.encode(serde_json::to_vec(&body).unwrap_or_default()))
    }

    /// Imports the `token_blob` from the offline activation page, or a claim
    /// deep link's token.
    pub fn import_offline_token(&self, token_blob: &str) -> Result<(), Error> {
        self.device
            .apply_token(token_blob.trim())
            .map_err(|e| Error::new(None, "token_rejected", format!("Token rejected: {e}")))?;
        self.changed();
        self.activated();
        Ok(())
    }

    /// Renews the entitlement. Quiet on failure, since grace covers outages;
    /// true when a new token was applied. `device_info` adds fields after
    /// `app_version` (optional compliance signals). A suspended key
    /// (`403 license_key_disabled`) keeps the token. A `seat_revoked` (an
    /// admin released the seat) or `unknown_device` drops the entitlement.
    pub async fn renew(&self, device_info: Map<String, Value>) -> bool {
        let path = "/v1/device/renew";
        let (Ok(id), ts) = (self.identity(), (self.now)()) else {
            return false;
        };
        let Ok(sig) = self.sig("POST", path, ts) else {
            return false;
        };
        let mut info = Map::new();
        info.insert(
            "app_version".into(),
            Value::String(self.config.app_version.clone()),
        );
        info.extend(device_info);
        let body = json!({"device_id": id.id, "ts": ts, "sig": sig, "device_info": info});
        let Ok(r) = self.post(path, &body).await else {
            return false; // offline: grace covers it
        };
        if r.status == 410 {
            self.drop_entitlement();
            return false;
        }
        if r.status != 200 {
            self.drop_if_unknown(&r.error_code().unwrap_or_default());
            return false;
        }
        self.apply_token(&r).is_ok()
    }

    /// Releases this device's seat and clears the local entitlement.
    pub async fn release(&self) -> Result<(), Error> {
        let path = "/v1/device/release";
        let id = self.identity()?;
        let ts = (self.now)();
        let body = json!({"device_id": id.id, "ts": ts, "sig": self.sig("POST", path, ts)?});
        let r = self.post(path, &body).await?;
        if r.status != 200 {
            return Err(self.refused(&r));
        }
        self.drop_entitlement();
        Ok(())
    }

    // Claim a seat by signing in:
    // authenticate ─(2FA?)─► authenticate_totp ─► claim ─► entitlement.

    /// Signs in with account credentials: `authenticated` (go to
    /// [`claim`](Self::claim)) or `totp_required` (go to
    /// [`authenticate_totp`](Self::authenticate_totp)).
    pub async fn authenticate(
        &self,
        email: &str,
        password: &str,
        device_name: Option<&str>,
    ) -> Result<AuthResult, Error> {
        let path = "/v1/account/authenticate";
        let ts = (self.now)();
        let body = json!({
            "device": self.device_block(device_name)?,
            "email": email.trim(),
            "password": password,
            "ts": ts,
            "sig": self.sig("POST", path, ts)?,
        });
        let r = self.post(path, &body).await?;
        if r.status != 200 {
            return Err(self.refused(&r));
        }
        r.parse()
    }

    /// Completes 2FA with a 6-digit TOTP or a recovery code.
    pub async fn authenticate_totp(&self, session: &str, code: &str) -> Result<AuthResult, Error> {
        let path = "/v1/account/authenticate/totp";
        let id = self.identity()?;
        let ts = (self.now)();
        let body = json!({
            "device_id": id.id,
            "session": session,
            "code": code.trim(),
            "ts": ts,
            "sig": self.sig("POST", path, ts)?,
        });
        let r = self.post(path, &body).await?;
        if r.status != 200 {
            return Err(self.refused(&r));
        }
        r.parse()
    }

    /// Claims a seat for the authenticated `session` and stores the
    /// entitlement. A device already holding a seat gets a fresh token.
    pub async fn claim(&self, session: &str) -> Result<(), Error> {
        let path = "/v1/account/claim";
        let id = self.identity()?;
        let ts = (self.now)();
        let body = json!({"device_id": id.id, "session": session, "ts": ts, "sig": self.sig("POST", path, ts)?});
        let r = self.post(path, &body).await?;
        if r.status != 200 {
            return Err(self.refused(&r));
        }
        self.apply_token(&r)?;
        self.activated();
        Ok(())
    }

    // With the app's own Sign in with Meros token.

    /// A bearer request to the license base, retried once with a fresh
    /// token on any 401.
    async fn with_account(
        &self,
        token: &dyn AccessTokenSource,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<HttpResponse, Error> {
        let request = |access: String| {
            let mut r = HttpRequest::new(method, self.url(path))
                .header("Authorization", format!("Bearer {access}"))
                .header("Accept", "application/json");
            if let Some(b) = body {
                r = r.json(b);
            }
            r
        };
        let r = self
            .transport
            .send(request(token.access_token(false).await?))
            .await?;
        if r.status != 401 {
            return Ok(r);
        }
        self.transport
            .send(request(token.access_token(true).await?))
            .await
    }

    /// Fails with the server's code; a bare 401 (Laravel's guard says only
    /// "Unauthenticated.") becomes `unauthenticated`.
    fn refused_account(&self, r: &HttpResponse) -> Error {
        if r.status == 401 && r.error_code().is_none() {
            return Error::new(
                Some(401),
                "unauthenticated",
                "Sign in with Meros again to continue.",
            );
        }
        self.refused(r)
    }

    /// Claims a license for this device with the user's Meros sign-in, in
    /// one step: a free license of their team first, then of their personal
    /// account. Codes include `no_seats_available`, `email_not_verified`,
    /// `two_factor_required`, `device_id_in_use`, `bad_signature` and
    /// `unauthenticated`.
    pub async fn claim_with_account(
        &self,
        token: &dyn AccessTokenSource,
        device_name: Option<&str>,
    ) -> Result<(), Error> {
        let path = "/v1/account/claim";
        let device = self.device_block(device_name)?;
        let ts = (self.now)();
        let body = json!({"device": device, "ts": ts, "sig": self.sig("POST", path, ts)?});
        let r = self.with_account(token, "POST", path, Some(&body)).await?;
        if r.status != 200 {
            return Err(self.refused_account(&r));
        }
        self.apply_token(&r)?;
        self.activated();
        Ok(())
    }

    /// The step after Sign in with Meros on a licensed device: the account
    /// claim, which adopts an unowned license (a guest or App Store
    /// purchase) into the signed-in account and otherwise refreshes the
    /// token. Call it after every sign-in. A license owned elsewhere that
    /// the account has no seat for is kept quietly
    /// ([`SignInClaim::KeptCurrent`]). Other refusals, such as
    /// `device_id_in_use` and the sign-in errors, are returned to show.
    pub async fn adopt_after_sign_in(
        &self,
        token: &dyn AccessTokenSource,
        device_name: Option<&str>,
    ) -> Result<SignInClaim, Error> {
        if !self.device.has_entitlement() {
            return Ok(SignInClaim::NotLicensed);
        }
        match self.claim_with_account(token, device_name).await {
            Ok(()) => Ok(SignInClaim::Claimed),
            Err(e) if e.no_seats() => Ok(SignInClaim::KeptCurrent),
            Err(e) => Err(e),
        }
    }

    /// The devices holding the product's licenses on the user's team and
    /// personal account.
    pub async fn seats(&self, token: &dyn AccessTokenSource) -> Result<Vec<LicenseSeat>, Error> {
        let r = self
            .with_account(token, "GET", "/v1/account/seats", None)
            .await?;
        if r.status != 200 {
            return Err(self.refused_account(&r));
        }
        #[derive(Deserialize)]
        struct Seats {
            seats: Vec<LicenseSeat>,
        }
        Ok(r.parse::<Seats>()?.seats)
    }

    /// Releases another device's license (a lost or replaced device); it gets
    /// `seat_revoked` at its next renewal. Needs
    /// [`LicenseSeat::can_release`], else `forbidden`.
    pub async fn release_seat(
        &self,
        token: &dyn AccessTokenSource,
        seat_id: i64,
    ) -> Result<(), Error> {
        let path = format!("/v1/account/seats/{seat_id}/release");
        let r = self.with_account(token, "POST", &path, None).await?;
        if r.status != 200 {
            return Err(self.refused_account(&r));
        }
        Ok(())
    }
}

fn unpadded(v: &Value) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap_or_default())
}

/// A license deep link the app was opened with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseLink {
    /// `…://activate?key=…`: a license email's "Activate on this device".
    /// Confirm, then [`LicenseClient::activate`].
    Activate { key: String },
    /// `…://claim?token=…` or `?error=…`: the return of the browser claim.
    /// Apply the token with [`LicenseClient::import_offline_token`]; `error`
    /// is `cancelled`, `no_seats`, `not_allowed` or another code, empty when
    /// there's a token.
    Claim { token: String, error: String },
}

impl LicenseLink {
    /// Parses `{scheme}://activate?key=…` and `{scheme}://claim?…`;
    /// `activate`/`claim` may be the host or the first path segment.
    pub fn parse(uri: &str, scheme: &str) -> Option<LicenseLink> {
        let u = url::Url::parse(uri).ok()?;
        if u.scheme() != scheme {
            return None;
        }
        let first = u.path_segments().and_then(|mut s| s.next()).unwrap_or("");
        let is = |name: &str| u.host_str() == Some(name) || first == name;
        let q = |k: &str| {
            u.query_pairs()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.into_owned())
                .unwrap_or_default()
        };
        if is("activate") {
            let key = q("key");
            return (!key.is_empty()).then_some(LicenseLink::Activate { key });
        }
        if is("claim") {
            return Some(LicenseLink::Claim {
                token: q("token"),
                error: q("error"),
            });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn license_links_parse() {
        assert_eq!(
            LicenseLink::parse("demo://activate?key=K-1", "demo"),
            Some(LicenseLink::Activate { key: "K-1".into() })
        );
        assert_eq!(
            LicenseLink::parse("demo://x/activate?key=K-2", "demo"),
            Some(LicenseLink::Activate { key: "K-2".into() })
        );
        assert_eq!(LicenseLink::parse("demo://activate", "demo"), None);
        assert_eq!(
            LicenseLink::parse("demo://claim?error=no_seats", "demo"),
            Some(LicenseLink::Claim {
                token: String::new(),
                error: "no_seats".into()
            })
        );
        assert_eq!(LicenseLink::parse("other://claim?token=t", "demo"), None);
        assert_eq!(LicenseLink::parse("demo://support", "demo"), None);
    }
}
