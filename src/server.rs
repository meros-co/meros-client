//! Server licenses: perpetual, online-only activation for Pro and Server
//! editions. An instance activates with a license key, or with a Meros login
//! (which also adopts an unowned key into the signed-in account), renews at
//! least daily while online, and can be released and moved.
//!
//! Every Server route is at the service root with `product` in the body.
//! Activation and renewal return the 30-day feature token and a signed
//! Server statement (`licence`), which never expires: an instance never stops
//! working because a token lapsed. Only `410 seat_revoked` at renewal ends
//! it. Server keys can't be activated offline.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::Error;
use crate::auth::AccessTokenSource;
use crate::device::DeviceSigner;
use crate::http::{HttpRequest, HttpResponse, Transport, unix_now};

/// The instance as the license service sees it. The key stays with
/// whatever already holds it; the client only asks for an id, a public key
/// and signatures.
pub trait ServerDevice: DeviceSigner {
    /// Verifies and stores a Server statement and its feature token (see
    /// [`verify_licence`]); the reason on refusal.
    fn apply(&self, licence: &str, token: &str) -> Result<(), String>;

    /// Drops the stored statement and token: the instance is deactivated.
    fn clear(&self);

    /// A short model string ("Linux x86_64", an appliance model).
    fn model(&self) -> String {
        "Server".into()
    }

    /// The instance's own name; None or empty uses "{app} ({model})".
    fn name(&self) -> Option<String> {
        None
    }
}

/// Which service and product this client speaks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    /// The service root (the issuer origin), no trailing slash. The app
    /// supplies it.
    pub base_url: String,
    /// The product's id, sent in every body.
    pub product: String,
    /// Used in the default instance name.
    pub app_name: String,
    /// Reported as `device.app_version`.
    pub app_version: String,
}

/// How a renewal went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerRenewal {
    /// A fresh statement and token were applied.
    Renewed,
    /// `410 seat_revoked`: the key was revoked or refunded, or the seat was
    /// released, revoked or moved elsewhere. The instance is deactivated and
    /// may activate again with any key, the same one included.
    Revoked,
    /// `403 license_key_disabled`: the key is suspended. Keep running on the
    /// statement already held, and show the message.
    Suspended(Error),
    /// Any other failure (offline included): keep running.
    Kept(Error),
}

/// The Server license client.
pub struct ServerLicenseClient {
    pub config: ServerConfig,
    transport: Arc<dyn Transport>,
    device: Arc<dyn ServerDevice>,
    now: Arc<dyn Fn() -> i64 + Send + Sync>,
    on_changed: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl ServerLicenseClient {
    pub fn new(
        config: ServerConfig,
        transport: Arc<dyn Transport>,
        device: Arc<dyn ServerDevice>,
    ) -> Self {
        ServerLicenseClient {
            config,
            transport,
            device,
            now: Arc::new(unix_now),
            on_changed: None,
        }
    }

    /// Called whenever the activation changes (activated, renewed,
    /// released, revoked).
    pub fn on_changed(mut self, hook: impl Fn() + Send + Sync + 'static) -> Self {
        self.on_changed = Some(Arc::new(hook));
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

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.config.base_url)
    }

    fn signed(&self, path: &str, ts: i64) -> Result<(crate::DeviceIdentity, String), Error> {
        let id = self.device.identity().ok_or_else(Error::no_identity)?;
        let sig = self
            .device
            .sign("POST", path, ts)
            .ok_or_else(Error::no_identity)?;
        Ok((id, sig))
    }

    fn device_block(&self, id: &crate::DeviceIdentity, device_name: Option<&str>) -> Value {
        let model = self.device.model();
        let mut name = device_name.unwrap_or("").trim().to_string();
        if name.is_empty() {
            name = self.device.name().unwrap_or_default().trim().to_string();
        }
        if name.is_empty() {
            name = format!("{} ({model})", self.config.app_name);
        }
        json!({
            "id": id.id,
            "pubkey": id.pubkey,
            "name": name,
            "model": model,
            "app_version": self.config.app_version,
        })
    }

    fn apply(&self, r: &HttpResponse) -> Result<(), Error> {
        let body = r.value();
        let text = |k: &str| body.get(k).and_then(|v| v.as_str());
        let (Some(licence), Some(token)) = (
            text("licence"),
            text("entitlement_token").or_else(|| text("token")),
        ) else {
            return Err(Error::new(
                Some(r.status),
                "bad_response",
                "No Server statement returned.",
            ));
        };
        self.device
            .apply(licence, token)
            .map_err(|e| Error::new(None, "token_rejected", format!("Statement rejected: {e}")))?;
        self.changed();
        Ok(())
    }

    /// Activates the instance with a Server key. Codes include
    /// `unknown_license_key`, `license_key_disabled`, `no_seats_available`
    /// (another instance holds the key; its message names it),
    /// `device_id_in_use` and `bad_signature`.
    pub async fn activate(
        &self,
        license_key: &str,
        device_name: Option<&str>,
    ) -> Result<(), Error> {
        let path = "/v1/device/activate";
        let ts = (self.now)();
        let (id, sig) = self.signed(path, ts)?;
        let body = json!({
            "product": self.config.product,
            "license_key": license_key.trim(),
            "device": self.device_block(&id, device_name),
            "ts": ts,
            "sig": sig,
        });
        let r = self
            .transport
            .send(HttpRequest::new("POST", self.url(path)).json(&body))
            .await?;
        if r.status != 200 {
            return Err(Error::from_response(&r));
        }
        self.apply(&r)
    }

    /// Activates the instance with the signed-in user's license (Sign in
    /// with Meros, scope `licenses:activate`): the license the instance
    /// already holds if it's on that account, else the account's first free
    /// Server key. `account_id` picks a team; None uses the user's team if
    /// they're on one, else their own account.
    ///
    /// Call it after every login on an activated instance too: a key no
    /// account owns (a guest purchase) is adopted into the account, the same
    /// seat. Codes include `no_licence` (none free on the account; the
    /// message has the buy link), `device_id_in_use` (another account's
    /// license, a different key; show its message), `forbidden`,
    /// `insufficient_scope`, `unknown_product` and `unauthenticated`.
    pub async fn activate_with_login(
        &self,
        token: &dyn AccessTokenSource,
        account_id: Option<&str>,
        device_name: Option<&str>,
    ) -> Result<(), Error> {
        let path = "/v1/server/activate";
        let ts = (self.now)();
        let (id, sig) = self.signed(path, ts)?;
        let mut body = json!({
            "product": self.config.product,
            "device": self.device_block(&id, device_name),
            "ts": ts,
            "sig": sig,
        });
        if let Some(a) = account_id {
            body["account_id"] = json!(a);
        }
        let request = |access: String| {
            HttpRequest::new("POST", self.url(path))
                .header("Authorization", format!("Bearer {access}"))
                .header("Accept", "application/json")
                .json(&body)
        };
        let mut r = self
            .transport
            .send(request(token.access_token(false).await?))
            .await?;
        if r.status == 401 && r.error_code().is_none() {
            r = self
                .transport
                .send(request(token.access_token(true).await?))
                .await?;
        }
        if r.status == 401 && r.error_code().is_none() {
            return Err(Error::new(
                Some(401),
                "unauthenticated",
                "Sign in with Meros again to continue.",
            ));
        }
        if r.status != 200 {
            return Err(Error::from_response(&r));
        }
        self.apply(&r)
    }

    /// Renews at least daily while online. `device_info` adds optional
    /// fields reported with the renewal.
    pub async fn renew(&self, device_info: Map<String, Value>) -> ServerRenewal {
        let path = "/v1/device/renew";
        let ts = (self.now)();
        let (id, sig) = match self.signed(path, ts) {
            Ok(v) => v,
            Err(e) => return ServerRenewal::Kept(e),
        };
        let mut info = Map::new();
        info.insert("app_version".into(), json!(self.config.app_version));
        info.extend(device_info);
        let body = json!({
            "product": self.config.product,
            "device_id": id.id,
            "ts": ts,
            "sig": sig,
            "device_info": info,
        });
        let r = match self
            .transport
            .send(HttpRequest::new("POST", self.url(path)).json(&body))
            .await
        {
            Ok(r) => r,
            Err(e) => return ServerRenewal::Kept(e),
        };
        match r.status {
            200 => match self.apply(&r) {
                Ok(()) => ServerRenewal::Renewed,
                Err(e) => ServerRenewal::Kept(e),
            },
            410 => {
                self.device.clear();
                self.changed();
                ServerRenewal::Revoked
            }
            _ => {
                let e = Error::from_response(&r);
                if e.license_key_disabled() {
                    ServerRenewal::Suspended(e)
                } else {
                    ServerRenewal::Kept(e)
                }
            }
        }
    }

    /// Releases the instance's seat (idempotent) and deactivates it, so the
    /// license can move to another instance.
    pub async fn release(&self) -> Result<(), Error> {
        let path = "/v1/device/release";
        let ts = (self.now)();
        let (id, sig) = self.signed(path, ts)?;
        let body =
            json!({"product": self.config.product, "device_id": id.id, "ts": ts, "sig": sig});
        let r = self
            .transport
            .send(HttpRequest::new("POST", self.url(path)).json(&body))
            .await?;
        if r.status != 200 {
            return Err(Error::from_response(&r));
        }
        self.device.clear();
        self.changed();
        Ok(())
    }
}

/// A verified Server statement.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ServerLicence {
    pub v: u32,
    pub typ: String,
    pub kid: String,
    pub jti: String,
    pub product: String,
    #[serde(default)]
    pub edition: String,
    #[serde(default)]
    pub account_id: String,
    #[serde(default)]
    pub account_type: String,
    #[serde(default)]
    pub account_name: String,
    /// The key's id, never the key itself.
    #[serde(default, deserialize_with = "string_or_number")]
    pub license_id: String,
    #[serde(default, deserialize_with = "string_or_number")]
    pub seat_id: String,
    pub device_id: String,
    pub device_pubkey: String,
    pub iat: i64,
    /// `perpetual`.
    pub licence: String,
    /// `YYYY-MM-DD`: only builds released after this date are refused.
    pub updates_until: String,
    #[serde(default)]
    pub features: Map<String, Value>,
}

fn string_or_number<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    Ok(match Value::deserialize(d)? {
        Value::String(s) => s,
        Value::Null => String::new(),
        other => other.to_string(),
    })
}

impl ServerLicence {
    /// Whether a build released on `build_date` (`YYYY-MM-DD`) may be
    /// installed under this statement.
    pub fn covers_build(&self, build_date: &str) -> bool {
        build_date <= self.updates_until.as_str()
    }
}

/// Verifies a Server statement (`base64url(payload).base64url(signature)`,
/// Ed25519 over the exact payload bytes) against the product's
/// `(kid, base64url public key)` table, and checks that it is a Server
/// statement for this product, device and key. There is no expiry.
pub fn verify_licence(
    keys: &[(&str, &str)],
    statement: &str,
    product: &str,
    device_id: &str,
    device_pubkey: &str,
) -> Result<ServerLicence, String> {
    let (payload_b64, sig_b64) = statement
        .trim()
        .split_once('.')
        .ok_or("malformed statement")?;
    let payload = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| "payload not base64url")?;
    let sig = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| "signature not base64url")?;
    let sig = Signature::from_slice(&sig).map_err(|_| "signature must be 64 bytes")?;
    let l: ServerLicence =
        serde_json::from_slice(&payload).map_err(|e| format!("invalid payload: {e}"))?;
    let key = keys
        .iter()
        .find(|(kid, _)| *kid == l.kid)
        .map(|(_, k)| *k)
        .ok_or_else(|| format!("unknown signing key: {}", l.kid))?;
    let key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(key)
        .ok()
        .and_then(|k| k.try_into().ok())
        .ok_or("product key must be 32 bytes of base64url")?;
    VerifyingKey::from_bytes(&key)
        .map_err(|_| "product key is not a valid Ed25519 point")?
        .verify_strict(&payload, &sig)
        .map_err(|_| "signature verification failed")?;
    if l.v != 1 || l.typ != "server_licence" {
        return Err("not a Server statement".into());
    }
    if l.product != product || l.device_id != device_id || l.device_pubkey != device_pubkey {
        return Err("statement is for another product or device".into());
    }
    Ok(l)
}
