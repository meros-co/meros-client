//! "Sign in with Meros": OAuth 2.0 authorization code with PKCE (S256), a
//! rotating refresh token kept in the app's [`TokenStore`], and sign-out by
//! revocation. Mobile apps redirect to their own scheme; desktop apps use a
//! loopback redirect (RFC 8252, see [`crate::loopback`]).

use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Error;
use crate::http::{BoxFuture, HttpRequest, Transport, unix_now, with_query};

/// Where an app signs in and what it asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthConfig {
    /// The issuer, such as the staging or production meros.co origin, with
    /// no trailing slash. The app supplies it (see [`crate::Environment`]).
    pub issuer: String,
    /// The app's public OAuth client.
    pub client_id: String,
    /// The registered app-scheme redirect, such as `myapp://oauth/callback`.
    /// Desktop apps signing in through a loopback redirect pass theirs to
    /// [`MerosAuth::begin_sign_in_with`] instead and may leave this empty.
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

/// Where tokens are kept between runs: the app backs it with the platform's
/// secure storage (Keystore, Keychain, its own channel). Values are strings;
/// `None` deletes.
pub trait TokenStore: Send + Sync {
    fn read(&self, key: &str) -> BoxFuture<'_, Option<String>>;
    fn write(&self, key: &str, value: Option<String>) -> BoxFuture<'_, ()>;
}

/// A [`TokenStore`] in memory, for tests and apps that don't persist.
#[derive(Default)]
pub struct MemoryTokenStore {
    pub values: Mutex<std::collections::HashMap<String, String>>,
}

impl TokenStore for MemoryTokenStore {
    fn read(&self, key: &str) -> BoxFuture<'_, Option<String>> {
        let v = self.values.lock().unwrap().get(key).cloned();
        Box::pin(async move { v })
    }

    fn write(&self, key: &str, value: Option<String>) -> BoxFuture<'_, ()> {
        let mut values = self.values.lock().unwrap();
        match value {
            Some(v) => values.insert(key.to_string(), v),
            None => values.remove(key),
        };
        Box::pin(async {})
    }
}

/// Gives out bearer tokens for the user's requests. [`MerosAuth`] is one;
/// `force` asks for a new one after the server refused the last.
pub trait AccessTokenSource: Send + Sync {
    fn access_token(&self, force: bool) -> BoxFuture<'_, Result<String, Error>>;
}

/// A PKCE verifier and its S256 challenge (RFC 7636).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

const UNRESERVED: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

impl Pkce {
    pub fn from_verifier(verifier: &str) -> Pkce {
        Pkce {
            verifier: verifier.to_string(),
            challenge: URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
        }
    }

    /// 64 random characters from the unreserved set.
    pub fn generate() -> Pkce {
        Pkce::from_verifier(&random_unreserved(64))
    }
}

fn random_unreserved(n: usize) -> String {
    let mut rng = rand::rng();
    (0..n)
        .map(|_| UNRESERVED[rng.random_range(0..UNRESERVED.len())] as char)
        .collect()
}

/// Who is signed in.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MerosUser {
    #[serde(rename = "sub", deserialize_with = "string_or_number")]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub email: String,
}

impl MerosUser {
    /// How to show the account: its name, else its email.
    pub fn label(&self) -> &str {
        if self.name.is_empty() {
            &self.email
        } else {
            &self.name
        }
    }
}

fn string_or_number<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    Ok(match serde_json::Value::deserialize(d)? {
        serde_json::Value::String(s) => s,
        other => other.to_string(),
    })
}

#[derive(Serialize, Deserialize)]
struct Pending {
    state: String,
    verifier: String,
    #[serde(default)]
    redirect_uri: Option<String>,
}

#[derive(Default)]
struct Session {
    access: Option<String>,
    expires: i64,
    user: Option<MerosUser>,
    loaded: bool,
    /// Bumped by every refresh, so callers that waited on one share it.
    generation: u64,
}

type UserHook = Arc<dyn Fn(Option<MerosUser>) + Send + Sync>;

// The same keys the Dart client used, so a stored session carries over.
const REFRESH_KEY: &str = "meros.refresh_token";
const USER_KEY: &str = "meros.user";
const PENDING_KEY: &str = "meros.pending";

/// Sign in with Meros. Share one per app (it is `Send + Sync`); refresh
/// tokens rotate, so two instances must not share one store.
pub struct MerosAuth {
    pub config: AuthConfig,
    transport: Arc<dyn Transport>,
    store: Arc<dyn TokenStore>,
    now: Arc<dyn Fn() -> i64 + Send + Sync>,
    session: Mutex<Session>,
    refreshing: tokio::sync::Mutex<()>,
    on_user_changed: Option<UserHook>,
}

impl MerosAuth {
    pub fn new(
        config: AuthConfig,
        transport: Arc<dyn Transport>,
        store: Arc<dyn TokenStore>,
    ) -> Self {
        MerosAuth {
            config,
            transport,
            store,
            now: Arc::new(unix_now),
            session: Mutex::new(Session::default()),
            refreshing: tokio::sync::Mutex::new(()),
            on_user_changed: None,
        }
    }

    /// Replaces the clock (unix seconds), for tests.
    /// Called with the new user (None when signed out) whenever the session
    /// changes: a sign-in, a sign-out, or a refresh the issuer refused.
    pub fn on_user_changed(
        mut self,
        hook: impl Fn(Option<MerosUser>) + Send + Sync + 'static,
    ) -> Self {
        self.on_user_changed = Some(Arc::new(hook));
        self
    }

    fn user_changed(&self, user: Option<MerosUser>) {
        if let Some(h) = &self.on_user_changed {
            h(user);
        }
    }

    pub fn with_clock(mut self, now: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.now = Arc::new(now);
        self
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.config.issuer)
    }

    /// Reads the stored session. The other calls do it on first use; call it
    /// at startup to know [`user`](Self::user) before any request.
    pub async fn load(&self) {
        if self.session.lock().unwrap().loaded {
            return;
        }
        let user = self.store.read(USER_KEY).await;
        let refresh = self.store.read(REFRESH_KEY).await;
        let mut s = self.session.lock().unwrap();
        if s.loaded {
            return;
        }
        s.loaded = true;
        if refresh.is_some() {
            s.user = user.and_then(|u| serde_json::from_str(&u).ok());
        }
    }

    /// Who is signed in, once [`load`](Self::load)ed.
    pub fn user(&self) -> Option<MerosUser> {
        self.session.lock().unwrap().user.clone()
    }

    pub fn signed_in(&self) -> bool {
        self.user().is_some()
    }

    /// The page to open in the browser, redirecting to the configured
    /// app-scheme redirect.
    pub async fn begin_sign_in(&self) -> String {
        let redirect = self.config.redirect_uri.clone();
        self.begin_sign_in_with(&redirect).await
    }

    /// The page to open in the browser, redirecting to `redirect_uri` (a
    /// loopback `http://127.0.0.1:{port}/…` on desktop). The state, verifier
    /// and redirect are stored, so the callback completes even if the app
    /// was closed meanwhile.
    pub async fn begin_sign_in_with(&self, redirect_uri: &str) -> String {
        let pkce = Pkce::generate();
        let state = random_unreserved(32);
        let pending = Pending {
            state: state.clone(),
            verifier: pkce.verifier.clone(),
            redirect_uri: Some(redirect_uri.to_string()),
        };
        self.store
            .write(PENDING_KEY, serde_json::to_string(&pending).ok())
            .await;
        let scope = self.config.scopes.join(" ");
        with_query(
            &self.endpoint("/oauth/authorize"),
            &[
                ("response_type", "code"),
                ("client_id", &self.config.client_id),
                ("redirect_uri", redirect_uri),
                ("scope", &scope),
                ("state", &state),
                ("code_challenge", &pkce.challenge),
                ("code_challenge_method", "S256"),
            ],
        )
    }

    /// Whether `uri` is this app's sign-in callback (its scheme, host and
    /// path match the configured redirect).
    pub fn is_callback(&self, uri: &str) -> bool {
        let (Ok(u), Ok(r)) = (
            url::Url::parse(uri),
            url::Url::parse(&self.config.redirect_uri),
        ) else {
            return false;
        };
        u.scheme() == r.scheme() && u.host_str() == r.host_str() && u.path() == r.path()
    }

    /// Finishes signing in from the redirect back to the app.
    pub async fn complete_sign_in(&self, callback: &str) -> Result<MerosUser, Error> {
        let pending = self.store.read(PENDING_KEY).await;
        self.store.write(PENDING_KEY, None).await;
        let url = url::Url::parse(callback)
            .map_err(|_| Error::new(None, "state_mismatch", "That sign-in link is not valid."))?;
        let q = |k: &str| {
            url.query_pairs()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.into_owned())
        };
        if let Some(error) = q("error") {
            let message = if error == "access_denied" {
                "Sign-in was canceled.".to_string()
            } else {
                format!("Sign-in failed ({error}).")
            };
            return Err(Error::new(None, error, message));
        }
        let pending: Pending = pending
            .and_then(|p| serde_json::from_str(&p).ok())
            .ok_or_else(|| {
                Error::new(
                    None,
                    "no_pending",
                    "Sign-in was not started here. Try again.",
                )
            })?;
        let code = q("code");
        if q("state").as_deref() != Some(pending.state.as_str()) || code.is_none() {
            return Err(Error::new(
                None,
                "state_mismatch",
                "That sign-in link does not match. Try again.",
            ));
        }
        let redirect = pending
            .redirect_uri
            .unwrap_or_else(|| self.config.redirect_uri.clone());
        let access = self
            .token(&[
                ("grant_type", "authorization_code"),
                ("code", &code.unwrap()),
                ("redirect_uri", &redirect),
                ("client_id", &self.config.client_id),
                ("code_verifier", &pending.verifier),
            ])
            .await?;
        let info = self
            .transport
            .send(
                HttpRequest::new("GET", self.endpoint("/oauth/userinfo"))
                    .header("Authorization", format!("Bearer {access}"))
                    .header("Accept", "application/json"),
            )
            .await?;
        if info.status != 200 {
            return Err(Error::new(
                Some(info.status),
                "userinfo",
                "Could not read the account.",
            ));
        }
        let user: MerosUser = info.parse()?;
        self.store
            .write(USER_KEY, serde_json::to_string(&user).ok())
            .await;
        let mut s = self.session.lock().unwrap();
        s.user = Some(user.clone());
        s.loaded = true;
        drop(s);
        self.user_changed(Some(user.clone()));
        Ok(user)
    }

    /// A valid access token, refreshed when it is within a minute of running
    /// out (or when `force`d). Concurrent callers share one refresh, since
    /// refresh tokens rotate.
    pub async fn access_token(&self, force: bool) -> Result<String, Error> {
        self.load().await;
        let seen = {
            let s = self.session.lock().unwrap();
            if !force
                && let Some(a) = &s.access
                && (self.now)() < s.expires - 60
            {
                return Ok(a.clone());
            }
            s.generation
        };
        let _guard = self.refreshing.lock().await;
        {
            // Someone refreshed while we waited: theirs is ours.
            let s = self.session.lock().unwrap();
            if s.generation != seen
                && let Some(a) = &s.access
            {
                return Ok(a.clone());
            }
        }
        self.refresh().await
    }

    async fn refresh(&self) -> Result<String, Error> {
        let Some(refresh) = self.store.read(REFRESH_KEY).await else {
            return Err(Error::new(None, "signed_out", "Not signed in."));
        };
        let result = self
            .token(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh),
                ("client_id", &self.config.client_id),
            ])
            .await;
        if let Err(e) = &result {
            // The refresh token was revoked or expired: the session is over.
            if e.code == "invalid_grant" {
                self.clear().await;
            }
        }
        result
    }

    async fn token(&self, form: &[(&str, &str)]) -> Result<String, Error> {
        let r = self
            .transport
            .send(HttpRequest::new("POST", self.endpoint("/oauth/token")).form(form))
            .await?;
        if r.status != 200 {
            let mut e = Error::from_response(&r);
            if e.code.starts_with("http_") {
                e.code = format!("token_{}", r.status);
            }
            if e.message.starts_with("Request failed") {
                e.message = "Sign-in failed.".into();
            }
            return Err(e);
        }
        #[derive(Deserialize)]
        struct Tokens {
            access_token: String,
            expires_in: Option<i64>,
            refresh_token: Option<String>,
        }
        let t: Tokens = r.parse()?;
        if let Some(refresh) = t.refresh_token {
            self.store.write(REFRESH_KEY, Some(refresh)).await;
        }
        let mut s = self.session.lock().unwrap();
        s.access = Some(t.access_token.clone());
        s.expires = (self.now)() + t.expires_in.unwrap_or(3600);
        s.generation += 1;
        Ok(t.access_token)
    }

    /// Signs out here and revokes the session on the issuer. Offline, the
    /// local session ends anyway.
    pub async fn sign_out(&self) {
        let access = self.session.lock().unwrap().access.clone();
        let token = match access {
            Some(a) => Some(a),
            None => self.store.read(REFRESH_KEY).await,
        };
        if let Some(token) = token {
            let _ = self
                .transport
                .send(
                    HttpRequest::new("POST", self.endpoint("/oauth/revoke"))
                        .form(&[("token", &token), ("client_id", &self.config.client_id)]),
                )
                .await;
        }
        self.clear().await;
    }

    async fn clear(&self) {
        let had_user = {
            let mut s = self.session.lock().unwrap();
            s.access = None;
            s.user.take().is_some()
        };
        self.store.write(REFRESH_KEY, None).await;
        self.store.write(USER_KEY, None).await;
        if had_user {
            self.user_changed(None);
        }
    }
}

impl AccessTokenSource for MerosAuth {
    fn access_token(&self, force: bool) -> BoxFuture<'_, Result<String, Error>> {
        Box::pin(MerosAuth::access_token(self, force))
    }
}

/// A fixed bearer token, such as a collector's static token.
pub struct StaticToken(pub String);

impl AccessTokenSource for StaticToken {
    fn access_token(&self, _force: bool) -> BoxFuture<'_, Result<String, Error>> {
        let t = self.0.clone();
        Box::pin(async move { Ok(t) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_matches_the_rfc_7636_example() {
        let p = Pkce::from_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        assert_eq!(p.challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        let g = Pkce::generate();
        assert_eq!(g.verifier.len(), 64);
        assert!(g.verifier.bytes().all(|b| UNRESERVED.contains(&b)));
    }

    #[test]
    fn users_parse_numeric_and_string_subjects() {
        let u: MerosUser = serde_json::from_str(r#"{"sub":42,"email":"a@b.test"}"#).unwrap();
        assert_eq!((u.id.as_str(), u.label()), ("42", "a@b.test"));
        let u: MerosUser = serde_json::from_str(r#"{"sub":"u1","name":"Pat"}"#).unwrap();
        assert_eq!(u.label(), "Pat");
    }
}
