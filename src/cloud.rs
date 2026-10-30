//! The Meros Cloud services (`/v1/…`), authorized as the signed-in user:
//! profiles, versioned documents (backups), files, accounts, entitlements,
//! device inventory and login tokens for connected services, plus signed
//! data-pack feeds (public packs need no sign-in). Every request retries
//! once with a fresh token on 401.

use std::collections::BTreeSet;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::Error;
use crate::auth::AccessTokenSource;
use crate::http::{HttpRequest, HttpResponse, Transport, segment, with_query};

/// A synced profile: its top-level keys, and when each was last written.
#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
pub struct MerosProfile {
    #[serde(default)]
    pub keys: Map<String, Value>,
    /// Key → ISO 8601 time of its last write.
    #[serde(default, rename = "key_meta")]
    pub updated: Map<String, Value>,
}

/// One document in a collection listing.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MerosDocInfo {
    pub key: String,
    pub head_version: i64,
    /// ISO 8601.
    #[serde(default, rename = "updated_at")]
    pub updated: String,
}

/// A document at one version.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct MerosDoc {
    pub key: String,
    pub version: i64,
    pub head_version: i64,
    pub body: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MerosDocVersion {
    pub version: i64,
    #[serde(default, rename = "created_at")]
    pub created: String,
    #[serde(default)]
    pub size_bytes: i64,
}

/// A personal or team account the user may act in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerosAccount {
    pub id: String,
    pub name: String,
    /// An organization (team), not the personal account.
    pub team: bool,
    pub role: String,
    pub is_default: bool,
}

/// A file in an account's file storage (such as a LUT), named by the
/// sha256 of its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerosFile {
    /// Lowercase hex.
    pub sha256: String,
    pub size: i64,
    /// `pending` until its upload is confirmed, then `stored`.
    pub status: String,
    pub created: Option<String>,
    /// A signed URL, valid for 15 minutes, from [`MerosCloud::file`].
    pub download_url: Option<String>,
}

impl MerosFile {
    pub fn stored(&self) -> bool {
        self.status == "stored"
    }

    fn from_json(j: &Value) -> MerosFile {
        let s = |k: &str| j.get(k).and_then(|v| v.as_str()).map(str::to_string);
        MerosFile {
            sha256: s("sha256").unwrap_or_default(),
            size: j.get("size").and_then(|v| v.as_i64()).unwrap_or(0),
            status: s("status").unwrap_or_default(),
            created: s("created_at"),
            download_url: j
                .pointer("/download/url")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        }
    }
}

/// A document body as Meros hashes it: object keys sorted recursively,
/// array order kept, no whitespace, `/` and non-ASCII unescaped.
pub fn canonical_json(value: &Value) -> String {
    fn sorted(v: &Value) -> Value {
        match v {
            Value::Object(m) => {
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort();
                let mut out = Map::new();
                for k in keys {
                    out.insert(k.clone(), sorted(&m[k]));
                }
                Value::Object(out)
            }
            Value::Array(a) => Value::Array(a.iter().map(sorted).collect()),
            other => other.clone(),
        }
    }
    // Keys are inserted in order, so the output follows it whether or not
    // serde_json keeps insertion order.
    serde_json::to_string(&sorted(value)).unwrap_or_default()
}

/// A document's `content_hash`: the sha256 (lowercase hex) of its
/// [`canonical_json`]. Equal hashes mean an identical copy, which is not a
/// conflict worth asking anyone about.
pub fn content_hash(body: &Value) -> String {
    Sha256::digest(canonical_json(body).as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The sha256 (lowercase hex) that names `bytes` in file storage.
pub fn file_hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The Meros Cloud client.
pub struct MerosCloud {
    /// The issuer, such as the staging or production meros.co origin.
    pub base_url: String,
    transport: Arc<dyn Transport>,
    token: Arc<dyn AccessTokenSource>,
}

impl MerosCloud {
    pub fn new(
        base_url: impl Into<String>,
        transport: Arc<dyn Transport>,
        token: Arc<dyn AccessTokenSource>,
    ) -> Self {
        MerosCloud {
            base_url: base_url.into(),
            transport,
            token,
        }
    }

    fn url(&self, path: &str, query: &[(&str, &str)]) -> String {
        with_query(&format!("{}{path}", self.base_url), query)
    }

    async fn send(
        &self,
        method: &str,
        url: String,
        body: Option<&Value>,
        account: Option<&str>,
    ) -> Result<HttpResponse, Error> {
        let request = |token: String| {
            let mut r = HttpRequest::new(method, url.clone())
                .header("Authorization", format!("Bearer {token}"))
                .header("Accept", "application/json");
            if let Some(a) = account {
                r = r.header("X-Meros-Account", a);
            }
            if let Some(b) = body {
                r = r.json(b);
            }
            r
        };
        let mut r = self
            .transport
            .send(request(self.token.access_token(false).await?))
            .await?;
        if r.status == 401 {
            r = self
                .transport
                .send(request(self.token.access_token(true).await?))
                .await?;
        }
        if r.status >= 400 {
            return Err(Error::from_response(&r));
        }
        Ok(r)
    }

    // Profiles: person-scoped, partial merge, last write wins per key.

    pub async fn profile(&self, namespace: &str) -> Result<MerosProfile, Error> {
        let url = self.url(&format!("/v1/profiles/{}", segment(namespace)), &[]);
        self.send("GET", url, None, None).await?.parse()
    }

    /// Merges `keys` into the profile; a null value deletes that key.
    pub async fn put_profile(
        &self,
        namespace: &str,
        keys: Map<String, Value>,
    ) -> Result<MerosProfile, Error> {
        let url = self.url(&format!("/v1/profiles/{}", segment(namespace)), &[]);
        self.send("PUT", url, Some(&json!({"keys": keys})), None)
            .await?
            .parse()
    }

    /// Forgets a namespace.
    pub async fn delete_profile(&self, namespace: &str) -> Result<(), Error> {
        let url = self.url(&format!("/v1/profiles/{}", segment(namespace)), &[]);
        self.send("DELETE", url, None, None).await.map(|_| ())
    }

    // Documents: account-scoped, versioned JSON. `account` is the account's
    // id; None is the user's personal account.

    fn doc_path(product: &str, collection: &str, key: Option<&str>) -> String {
        let mut p = format!("/v1/docs/{}/{}", segment(product), segment(collection));
        if let Some(k) = key {
            p.push('/');
            p.push_str(&segment(k));
        }
        p
    }

    pub async fn list_docs(
        &self,
        product: &str,
        collection: &str,
        account: Option<&str>,
    ) -> Result<Vec<MerosDocInfo>, Error> {
        #[derive(Deserialize)]
        struct List {
            #[serde(default)]
            documents: Vec<MerosDocInfo>,
        }
        let url = self.url(&Self::doc_path(product, collection, None), &[]);
        Ok(self
            .send("GET", url, None, account)
            .await?
            .parse::<List>()?
            .documents)
    }

    /// The head, or `version`.
    pub async fn get_doc(
        &self,
        product: &str,
        collection: &str,
        key: &str,
        version: Option<i64>,
        account: Option<&str>,
    ) -> Result<MerosDoc, Error> {
        let v = version.map(|v| v.to_string());
        let query: Vec<(&str, &str)> = v.as_deref().map(|v| ("version", v)).into_iter().collect();
        let url = self.url(&Self::doc_path(product, collection, Some(key)), &query);
        self.send("GET", url, None, account).await?.parse()
    }

    /// Writes a new version and returns its number. With `base_version`, a
    /// newer version on the server fails with `version_conflict`, carrying
    /// the current head in [`Error::head_version`].
    pub async fn put_doc(
        &self,
        product: &str,
        collection: &str,
        key: &str,
        body: Map<String, Value>,
        base_version: Option<i64>,
        account: Option<&str>,
    ) -> Result<i64, Error> {
        let mut payload = json!({"body": body});
        if let Some(b) = base_version {
            payload["base_version"] = json!(b);
        }
        let url = self.url(&Self::doc_path(product, collection, Some(key)), &[]);
        let j = self
            .send("PUT", url, Some(&payload), account)
            .await?
            .value();
        j.get("version")
            .or_else(|| j.get("head_version"))
            .and_then(|v| v.as_i64())
            .ok_or_else(|| Error::new(None, "bad_response", "No version returned."))
    }

    /// Deletes a document (soft: history is kept). One already gone is not
    /// an error.
    pub async fn delete_doc(
        &self,
        product: &str,
        collection: &str,
        key: &str,
        account: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.url(&Self::doc_path(product, collection, Some(key)), &[]);
        match self.send("DELETE", url, None, account).await {
            Err(e) if !e.not_found() => Err(e),
            _ => Ok(()),
        }
    }

    pub async fn doc_versions(
        &self,
        product: &str,
        collection: &str,
        key: &str,
        account: Option<&str>,
    ) -> Result<Vec<MerosDocVersion>, Error> {
        #[derive(Deserialize)]
        struct List {
            #[serde(default)]
            versions: Vec<MerosDocVersion>,
        }
        let url = self.url(
            &format!(
                "{}/versions",
                Self::doc_path(product, collection, Some(key))
            ),
            &[],
        );
        Ok(self
            .send("GET", url, None, account)
            .await?
            .parse::<List>()?
            .versions)
    }

    // Files: account-scoped, named by sha256, moved through signed URLs.
    // File bodies never go in documents: a backup names its files by sha256.

    fn file_path(product: &str, collection: &str, sha256: Option<&str>) -> String {
        let mut p = format!("/v1/files/{}/{}", segment(product), segment(collection));
        if let Some(s) = sha256 {
            p.push('/');
            p.push_str(&segment(s));
        }
        p
    }

    /// Stores `bytes` in `collection` (such as `luts`) and returns the stored
    /// file. Bytes the account already has are not sent again. Codes:
    /// `file_too_large` (413, one file over the cap), `quota_exceeded` (413,
    /// the account's storage is full), `file_mismatch` (422, the upload
    /// arrived damaged and was discarded), `not_uploaded` (409),
    /// `upload_failed` (the bucket refused it).
    pub async fn put_file(
        &self,
        product: &str,
        collection: &str,
        bytes: &[u8],
        account: Option<&str>,
    ) -> Result<MerosFile, Error> {
        let hash = file_hash(bytes);
        let url = self.url(&Self::file_path(product, collection, None), &[]);
        let j = self
            .send(
                "POST",
                url,
                Some(&json!({"sha256": hash, "size": bytes.len()})),
                account,
            )
            .await?
            .value();
        let Some(upload) = j.get("upload").filter(|u| u.is_object()) else {
            return Ok(MerosFile::from_json(&j));
        };
        let target = upload
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let mut put = HttpRequest::new("PUT", target);
        if let Some(headers) = upload.get("headers").and_then(|h| h.as_object()) {
            for (k, v) in headers {
                let value = match v {
                    Value::Array(items) => items
                        .iter()
                        .map(|i| {
                            i.as_str()
                                .map(str::to_string)
                                .unwrap_or_else(|| i.to_string())
                        })
                        .collect::<Vec<_>>()
                        .join(","),
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                put = put.header(k, value);
            }
        }
        put.body = bytes.to_vec();
        let r = self.transport.send(put).await?;
        if r.status >= 300 {
            return Err(Error::new(
                Some(r.status),
                "upload_failed",
                "The upload was refused.",
            ));
        }
        let url = self.url(
            &format!(
                "{}/complete",
                Self::file_path(product, collection, Some(&hash))
            ),
            &[],
        );
        Ok(MerosFile::from_json(
            &self.send("POST", url, None, account).await?.value(),
        ))
    }

    /// The stored files in `collection`.
    pub async fn list_files(
        &self,
        product: &str,
        collection: &str,
        account: Option<&str>,
    ) -> Result<Vec<MerosFile>, Error> {
        let url = self.url(&Self::file_path(product, collection, None), &[]);
        let j = self.send("GET", url, None, account).await?.value();
        Ok(j.get("files")
            .and_then(|f| f.as_array())
            .map(|a| a.iter().map(MerosFile::from_json).collect())
            .unwrap_or_default())
    }

    /// One stored file, with a signed download URL; 404 when not stored.
    pub async fn file(
        &self,
        product: &str,
        collection: &str,
        sha256: &str,
        account: Option<&str>,
    ) -> Result<MerosFile, Error> {
        let url = self.url(&Self::file_path(product, collection, Some(sha256)), &[]);
        Ok(MerosFile::from_json(
            &self.send("GET", url, None, account).await?.value(),
        ))
    }

    /// The bytes of a stored file, checked against its sha256 (else
    /// `file_mismatch`).
    pub async fn download_file(
        &self,
        product: &str,
        collection: &str,
        sha256: &str,
        account: Option<&str>,
    ) -> Result<Vec<u8>, Error> {
        let f = self.file(product, collection, sha256, account).await?;
        let url = f
            .download_url
            .ok_or_else(|| Error::new(Some(404), "not_found", "That file is not stored."))?;
        let r = self.transport.send(HttpRequest::new("GET", url)).await?;
        if r.status != 200 {
            return Err(Error::new(
                Some(r.status),
                "download_failed",
                "The download failed.",
            ));
        }
        if file_hash(&r.body) != sha256 {
            return Err(Error::new(
                Some(422),
                "file_mismatch",
                "The file arrived damaged. Try again.",
            ));
        }
        Ok(r.body)
    }

    /// Deletes a file; one already gone is not an error.
    pub async fn delete_file(
        &self,
        product: &str,
        collection: &str,
        sha256: &str,
        account: Option<&str>,
    ) -> Result<(), Error> {
        let url = self.url(&Self::file_path(product, collection, Some(sha256)), &[]);
        match self.send("DELETE", url, None, account).await {
            Err(e) if !e.not_found() => Err(e),
            _ => Ok(()),
        }
    }

    // Accounts and entitlements.

    pub async fn accounts(&self) -> Result<Vec<MerosAccount>, Error> {
        let j = self
            .send("GET", self.url("/v1/accounts", &[]), None, None)
            .await?
            .value();
        let s = |a: &Value, k: &str| {
            a.get(k)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string()
        };
        Ok(j.get("accounts")
            .and_then(|a| a.as_array())
            .map(|list| {
                list.iter()
                    .map(|a| MerosAccount {
                        id: s(a, "id"),
                        name: s(a, "name"),
                        team: a.get("type").and_then(|v| v.as_str()) == Some("org"),
                        role: s(a, "role"),
                        is_default: a.get("default").and_then(|v| v.as_bool()) == Some(true),
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Enabled feature flags for `product`, such as `myapp.backup.history`.
    pub async fn features(
        &self,
        product: &str,
        account: Option<&str>,
    ) -> Result<BTreeSet<String>, Error> {
        let mut query = vec![("product", product)];
        if let Some(a) = account {
            query.push(("account_id", a));
        }
        let j = self
            .send("GET", self.url("/v1/entitlements", &query), None, None)
            .await?
            .value();
        Ok(j.get("features")
            .and_then(|f| f.as_object())
            .map(|f| {
                f.iter()
                    .filter(|(_, v)| v.as_bool() == Some(true))
                    .map(|(k, _)| k.clone())
                    .collect()
            })
            .unwrap_or_default())
    }

    /// The whole entitlements answer for `product`: `{product, account_id,
    /// features: {flag: true, tier}, entitlements: [{sku, kind, status,
    /// expires_at}]}`.
    pub async fn entitlements(&self, product: &str, account: Option<&str>) -> Result<Value, Error> {
        let mut query = vec![("product", product)];
        if let Some(a) = account {
            query.push(("account_id", a));
        }
        Ok(self
            .send("GET", self.url("/v1/entitlements", &query), None, None)
            .await?
            .value())
    }

    /// The account's tier for `product` (`free` or `pro`).
    pub async fn tier(&self, product: &str, account: Option<&str>) -> Result<String, Error> {
        let mut query = vec![("product", product)];
        if let Some(a) = account {
            query.push(("account_id", a));
        }
        let j = self
            .send("GET", self.url("/v1/entitlements", &query), None, None)
            .await?
            .value();
        Ok(j.pointer("/features/tier")
            .and_then(|v| v.as_str())
            .unwrap_or("free")
            .to_string())
    }

    // Inventory: a product's device list for the account, replaced whole.

    /// The account's device inventory for `product`:
    /// `{product, count, updated_at, devices}`.
    pub async fn inventory(&self, product: &str, account: Option<&str>) -> Result<Value, Error> {
        let url = self.url(&format!("/v1/inventory/{}", segment(product)), &[]);
        Ok(self.send("GET", url, None, account).await?.value())
    }

    /// Replaces the inventory with `devices` (upserted by `id`; devices left
    /// out are deleted, `[]` clears it). Returns `{product, count,
    /// updated_at}`. Refusals include `invalid_inventory` (naming the
    /// field), `inventory_too_large` and `insufficient_scope`.
    pub async fn put_inventory(
        &self,
        product: &str,
        devices: Vec<Value>,
        account: Option<&str>,
    ) -> Result<Value, Error> {
        let url = self.url(&format!("/v1/inventory/{}", segment(product)), &[]);
        Ok(self
            .send("PUT", url, Some(&json!({"devices": devices})), account)
            .await?
            .value())
    }

    /// Mints a single-use login token for a connected service (`audience`)
    /// from this user's session, so that service can sign the same user in
    /// as its own client (`POST /oauth/sso/ticket`). `code_challenge` is the
    /// service's S256 challenge where it uses PKCE; `acr_values` such as
    /// `urn:meros:acr:mfa` asks for a two-factor sign-in. Returns
    /// `{login_token, token_type, expires_in, audience, client_id}`.
    /// Refusals include `invalid_target` and `mfa_required`.
    pub async fn login_token(
        &self,
        audience: &str,
        code_challenge: Option<&str>,
        nonce: Option<&str>,
        acr_values: Option<&str>,
    ) -> Result<Value, Error> {
        let mut body = json!({"audience": audience});
        if let Some(c) = code_challenge {
            body["code_challenge"] = json!(c);
            body["code_challenge_method"] = json!("S256");
        }
        if let Some(n) = nonce {
            body["nonce"] = json!(n);
        }
        if let Some(a) = acr_values {
            body["acr_values"] = json!(a);
        }
        let url = self.url("/oauth/sso/ticket", &[]);
        Ok(self.send("POST", url, Some(&body), None).await?.value())
    }
}

/// A signed data pack as a feed serves it, before verification.
#[derive(Debug, Clone, PartialEq)]
pub struct MerosPack {
    pub product: String,
    pub pack: String,
    pub version: i64,
    pub kid: String,
    pub issued_at: String,
    /// `MEROSPACK1.<base64url header>.<base64url payload>`, the signed bytes.
    pub signed: String,
    /// base64url Ed25519 signature over `signed`.
    pub signature: String,
}

/// What a feed request returned.
#[derive(Debug, Clone, PartialEq)]
pub enum FeedResponse {
    /// The pack, and its `ETag` for the next request.
    Pack(MerosPack, Option<String>),
    /// `304`: the copy matching the `ETag` sent is current.
    NotModified,
}

/// Signed data-pack feeds (`/v1/feeds/{product}/{pack}`). Public packs
/// need no `token`; entitled ones answer `401` without one and
/// `403 not_entitled` without the product's entitlement. Verify what comes
/// back with [`verify_pack`] before using it.
pub struct MerosFeeds {
    /// The issuer, such as the staging or production meros.co origin.
    pub base_url: String,
    transport: Arc<dyn Transport>,
    token: Option<Arc<dyn AccessTokenSource>>,
}

impl MerosFeeds {
    pub fn new(
        base_url: impl Into<String>,
        transport: Arc<dyn Transport>,
        token: Option<Arc<dyn AccessTokenSource>>,
    ) -> Self {
        MerosFeeds {
            base_url: base_url.into(),
            transport,
            token,
        }
    }

    /// A pack, latest or `version`. Pass the last `etag` to get
    /// [`FeedResponse::NotModified`] cheaply.
    pub async fn fetch(
        &self,
        product: &str,
        pack: &str,
        version: Option<i64>,
        etag: Option<&str>,
        account: Option<&str>,
    ) -> Result<FeedResponse, Error> {
        let v = version.map(|v| v.to_string());
        let mut query = Vec::new();
        if let Some(v) = &v {
            query.push(("version", v.as_str()));
        }
        let url = with_query(
            &format!(
                "{}/v1/feeds/{}/{}",
                self.base_url,
                segment(product),
                segment(pack)
            ),
            &query,
        );
        let r = self.get(&url, etag, account).await?;
        if r.status == 304 {
            return Ok(FeedResponse::NotModified);
        }
        let j = r.value();
        let text = |k: &str| {
            j.get(k)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string()
        };
        let pack = MerosPack {
            product: text("product"),
            pack: text("pack"),
            version: j.get("version").and_then(|v| v.as_i64()).unwrap_or(0),
            kid: text("kid"),
            issued_at: text("issued_at"),
            signed: text("signed"),
            signature: text("signature"),
        };
        Ok(FeedResponse::Pack(
            pack,
            r.header_value("etag").map(str::to_string),
        ))
    }

    /// The versions a pack offers, as the service lists them.
    pub async fn versions(
        &self,
        product: &str,
        pack: &str,
        account: Option<&str>,
    ) -> Result<Value, Error> {
        let url = format!(
            "{}/v1/feeds/{}/{}/versions",
            self.base_url,
            segment(product),
            segment(pack)
        );
        Ok(self.get(&url, None, account).await?.value())
    }

    async fn get(
        &self,
        url: &str,
        etag: Option<&str>,
        account: Option<&str>,
    ) -> Result<HttpResponse, Error> {
        let request = |access: Option<String>| {
            let mut r =
                HttpRequest::new("GET", url.to_string()).header("Accept", "application/json");
            if let Some(a) = access {
                r = r.header("Authorization", format!("Bearer {a}"));
            }
            if let Some(e) = etag {
                r = r.header("If-None-Match", e);
            }
            if let Some(a) = account {
                r = r.header("X-Meros-Account", a);
            }
            r
        };
        let access = match &self.token {
            Some(t) => Some(t.access_token(false).await?),
            None => None,
        };
        let mut r = self.transport.send(request(access)).await?;
        if r.status == 401
            && let Some(t) = &self.token
        {
            r = self
                .transport
                .send(request(Some(t.access_token(true).await?)))
                .await?;
        }
        if r.status >= 400 {
            return Err(Error::from_response(&r));
        }
        Ok(r)
    }
}

/// Verifies a pack offline against the product's `(kid, base64url public
/// key)` table: Ed25519 over the exact `signed` bytes, with no
/// re-serialization. Returns the decoded header (`product`, `pack`,
/// `version`, `kid`, `issued_at`) and the pack's payload, read from the
/// signed bytes rather than any convenience copy.
pub fn verify_pack(
    keys: &[(&str, &str)],
    signed: &str,
    signature: &str,
) -> Result<(Value, Value), String> {
    let mut parts = signed.split('.');
    let (Some("MEROSPACK1"), Some(header), Some(payload), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("not a MEROSPACK1 pack".into());
    };
    let decode = |s: &str| -> Result<Value, String> {
        let bytes = URL_SAFE_NO_PAD.decode(s).map_err(|_| "not base64url")?;
        serde_json::from_slice(&bytes).map_err(|e| format!("invalid JSON: {e}"))
    };
    let header = decode(header)?;
    let payload = decode(payload)?;
    let kid = header["kid"].as_str().unwrap_or_default();
    let key = keys
        .iter()
        .find(|(k, _)| *k == kid)
        .map(|(_, v)| *v)
        .ok_or_else(|| format!("unknown signing key: {kid}"))?;
    let key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(key)
        .ok()
        .and_then(|k| k.try_into().ok())
        .ok_or("product key must be 32 bytes of base64url")?;
    let sig = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| "signature not base64url")?;
    let sig =
        ed25519_dalek::Signature::from_slice(&sig).map_err(|_| "signature must be 64 bytes")?;
    ed25519_dalek::VerifyingKey::from_bytes(&key)
        .map_err(|_| "product key is not a valid Ed25519 point")?
        .verify_strict(signed.as_bytes(), &sig)
        .map_err(|_| "signature verification failed")?;
    Ok((header, payload))
}

#[cfg(test)]
mod tests {
    #[test]
    fn file_hashes_are_lowercase_hex_sha256() {
        assert_eq!(
            super::file_hash(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
