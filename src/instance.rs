//! Cloud-managed users: an instance asks meros.co, as itself, which members
//! of its owning team may use it and with which role
//! (`POST /v1/instance/members`, signed with the device key). The answer
//! carries a members statement signed with the product key, which lasts
//! seven days and is enough on its own offline: sessions keep running on the
//! last good statement while meros.co can't be reached.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::Error;
use crate::device::DeviceSigner;
use crate::http::{Transport, unix_now};

/// A role a product declares on meros.co.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberRole {
    pub id: String,
    #[serde(default)]
    pub name: String,
}

/// A member of the owning team, and their role here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub sub: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub email: String,
    /// Their role in the team: `owner`, `admin`, `billing` or `member`.
    #[serde(default)]
    pub team_role: String,
    /// Their role in this product; `None` is no access.
    pub role: Option<String>,
}

/// A verified members statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembersStatement {
    pub v: u32,
    pub typ: String,
    pub kid: String,
    pub product: String,
    pub device_id: String,
    pub device_pubkey: String,
    pub account_id: String,
    #[serde(default)]
    pub account_name: String,
    /// Whether cloud-managed users may be used here now.
    pub enabled: bool,
    /// Why not, when `enabled` is false: `personal_account`,
    /// `no_team_addon`, `gate_lapsed`.
    #[serde(default)]
    pub reason: Option<String>,
    /// Opaque; sent back to ask whether anything changed.
    pub version: String,
    #[serde(default)]
    pub roles: Vec<MemberRole>,
    #[serde(default)]
    pub default_role: Option<String>,
    #[serde(default)]
    pub admin_role: Option<String>,
    #[serde(default)]
    pub members: Vec<Member>,
    pub iat: i64,
    pub exp: i64,
}

impl MembersStatement {
    /// Past its seven days: no session should run on it any more.
    pub fn expired(&self, now: i64) -> bool {
        now >= self.exp
    }

    /// The member with `sub` who has a role here, if any.
    pub fn member(&self, sub: &str) -> Option<&Member> {
        self.members
            .iter()
            .find(|m| m.sub == sub && m.role.is_some())
    }
}

/// Verifies a members statement: the product key's Ed25519 signature over
/// the exact payload bytes, the type, and that it was issued to this product
/// and device. Whether it has expired is the caller's to decide (see
/// [`MembersStatement::expired`]).
pub fn verify_members(
    keys: &[(&str, &str)],
    statement: &str,
    product: &str,
    device_id: &str,
    device_pubkey: &str,
) -> Result<MembersStatement, String> {
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
    let s: MembersStatement =
        serde_json::from_slice(&payload).map_err(|e| format!("invalid payload: {e}"))?;
    let key = keys
        .iter()
        .find(|(kid, _)| *kid == s.kid)
        .map(|(_, k)| *k)
        .ok_or_else(|| format!("unknown signing key: {}", s.kid))?;
    let key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(key)
        .ok()
        .and_then(|k| k.try_into().ok())
        .ok_or("product key must be 32 bytes of base64url")?;
    VerifyingKey::from_bytes(&key)
        .map_err(|_| "product key is not a valid Ed25519 point")?
        .verify_strict(&payload, &sig)
        .map_err(|_| "signature verification failed")?;
    if s.v != 1 || s.typ != "instance_members" {
        return Err("not a members statement".into());
    }
    if s.product != product || s.device_id != device_id || s.device_pubkey != device_pubkey {
        return Err("statement is for another product or device".into());
    }
    Ok(s)
}

/// What a members fetch returned: the statement as issued and verified, and
/// whether the version was unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembersAnswer {
    pub statement: String,
    pub members: MembersStatement,
    pub unchanged: bool,
}

/// Asks meros.co for the instance's members, as the instance.
pub struct InstanceClient {
    /// The issuer, such as the staging or production meros.co origin.
    pub base_url: String,
    pub product: String,
    keys: Vec<(String, String)>,
    transport: Arc<dyn Transport>,
    device: Arc<dyn DeviceSigner>,
}

impl InstanceClient {
    /// `keys` are the product's statement keys (kid → base64url key).
    pub fn new(
        base_url: impl Into<String>,
        product: impl Into<String>,
        keys: Vec<(String, String)>,
        transport: Arc<dyn Transport>,
        device: Arc<dyn DeviceSigner>,
    ) -> Self {
        InstanceClient {
            base_url: base_url.into(),
            product: product.into(),
            keys,
            transport,
            device,
        }
    }

    /// `POST /v1/instance/members`, device-signed. With `version` (the last
    /// one seen), an unchanged list comes back as a fresh statement for the
    /// same version. The statement is verified before it is returned; one
    /// that doesn't verify is `verify_failed`. Refusals include
    /// `unknown_device` (not activated or registered for the product),
    /// `bad_signature` and `rate_limited`.
    pub async fn members(&self, version: Option<&str>) -> Result<MembersAnswer, Error> {
        let nonce = crate::device::nonce();
        let mut fields = vec![("product", self.product.as_str()), ("nonce", &nonce)];
        if let Some(v) = version.filter(|v| !v.is_empty()) {
            fields.push(("version", v));
        }
        let url = format!(
            "{}/v1/instance/members",
            self.base_url.trim_end_matches('/')
        );
        let request = crate::device::signed_form(self.device.as_ref(), &url, &fields, unix_now())?
            .header("Accept", "application/json");
        let r = self.transport.send(request).await?;
        if !r.ok() {
            return Err(Error::from_response(&r));
        }
        let body = r.value();
        let statement = body["statement"]
            .as_str()
            .ok_or_else(|| {
                Error::new(
                    Some(r.status),
                    "bad_response",
                    "The members answer has no statement.",
                )
            })?
            .to_string();
        let id = self.device.identity().ok_or_else(Error::no_identity)?;
        let keys: Vec<(&str, &str)> = self
            .keys
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let members = verify_members(&keys, &statement, &self.product, &id.id, &id.pubkey)
            .map_err(|e| {
                Error::new(
                    None,
                    "verify_failed",
                    format!("The members statement: {e}."),
                )
            })?;
        Ok(MembersAnswer {
            statement,
            members,
            unchanged: body["unchanged"].as_bool() == Some(true),
        })
    }
}
