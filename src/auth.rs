//! "Sign in with Meros": OAuth 2.0 authorization code with PKCE (S256), a
//! nonce and a checked id_token, a rotating refresh token kept in the app's
//! [`TokenStore`], and sign-out by revocation. Mobile apps redirect to their
//! own scheme; desktop apps use a loopback redirect (RFC 8252, see
//! [`crate::loopback`]); servers push the request signed with their device
//! key (RFC 9126) and redirect to their own https address. Consoles sign in
//! with an email and password ([`MerosAuth::password_sign_in`]), or as the
//! alternative where typing is hard, with the device authorization grant
//! (RFC 8628): they show a code and a link, and the person approves it on
//! another device. A service whose user signed in elsewhere redeems the
//! login token minted there ([`MerosAuth::begin_login_token_sign_in`]).

use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Error;
use crate::device::DeviceSigner;
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

/// The single pending sign-in older versions kept; still read once so a
/// sign-in begun before an upgrade can finish.
#[derive(Serialize, Deserialize)]
struct Pending {
    state: String,
    verifier: String,
    #[serde(default)]
    redirect_uri: Option<String>,
}

/// A browser sign-in waiting for its callback, by state.
#[derive(Serialize, Deserialize, Clone)]
struct BrowserPending {
    verifier: String,
    /// Empty for a sign-in begun before nonces were sent.
    #[serde(default)]
    nonce: String,
    redirect_uri: String,
    client_id: String,
    expires_at: i64,
    #[serde(default)]
    acr_values: Option<String>,
    #[serde(default)]
    context: Option<String>,
}

/// How long a browser sign-in waits for its callback, and how many may
/// wait at once.
const BROWSER_PENDING_SECS: i64 = 600;
const BROWSER_PENDING_MAX: usize = 32;

/// What a browser sign-in asks for ([`MerosAuth::begin_browser_sign_in`]).
#[derive(Clone, Default)]
pub struct BrowserSignInOptions {
    /// Where meros.co sends the browser back: a loopback
    /// `http://127.0.0.1:{port}/callback` on desktop, a server's own https
    /// callback, or empty for the configured app-scheme redirect.
    pub redirect_uri: String,
    /// Such as `urn:meros:acr:mfa`, to require a two-factor sign-in.
    pub acr_values: Option<String>,
    /// The email to fill in on the sign-in page.
    pub login_hint: Option<String>,
    /// Such as `login`, to ask for the password even when the browser is
    /// already signed in to meros.co.
    pub prompt: Option<String>,
    /// Pushes the request to the issuer's PAR endpoint, signed with this
    /// device's key (RFC 9126), and leaves only its `request_uri` on the
    /// authorize URL. Server products' clients require it.
    pub device: Option<Arc<dyn DeviceSigner>>,
    /// Kept with the pending sign-in and handed back when it finishes.
    pub context: Option<String>,
}

/// A browser sign-in begun: send the browser to [`authorize_url`] and
/// finish with the callback within [`expires_at`].
///
/// [`authorize_url`]: Self::authorize_url
/// [`expires_at`]: Self::expires_at
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserSignIn {
    pub authorize_url: String,
    pub state: String,
    /// When the pending sign-in is forgotten, unix seconds.
    pub expires_at: i64,
}

/// A completed sign-in not yet kept in any session: hand it to
/// [`MerosAuth::adopt`] on the session it belongs to.
pub struct NewSession {
    pub user: MerosUser,
    /// The client the tokens belong to; the session refreshes and revokes
    /// with it.
    pub client_id: String,
    /// The id_token's `acr`, such as `urn:meros:acr:mfa`.
    pub acr: Option<String>,
    /// The id_token's `amr`, such as `["pwd", "otp", "mfa"]`.
    pub amr: Vec<String>,
    /// What the sign-in was begun with in
    /// [`BrowserSignInOptions::context`].
    pub context: Option<String>,
    tokens: Tokens,
}

impl std::fmt::Debug for NewSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewSession")
            .field("user", &self.user)
            .field("client_id", &self.client_id)
            .field("acr", &self.acr)
            .field("amr", &self.amr)
            .finish_non_exhaustive()
    }
}

/// A sign-in kept in a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedIn {
    pub user: MerosUser,
    /// Whether a different user was signed in to the session before (they
    /// were signed out on the service first).
    pub replaced_previous: bool,
    pub acr: Option<String>,
    pub amr: Vec<String>,
}

/// The first answer to a password sign-in.
#[derive(Debug)]
pub enum PasswordStep {
    SignedIn(NewSession),
    /// The account has two-factor on: ask for a code and finish with
    /// [`MerosAuth::two_factor_sign_in`].
    TwoFactor(TwoFactorChallenge),
}

/// A two-factor step waiting for its code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwoFactorChallenge {
    pub challenge: String,
    /// What the code may be: `totp`, `recovery`.
    pub methods: Vec<String>,
    /// When the challenge runs out, unix seconds.
    pub expires_at: i64,
}

const PASSWORD_GRANT: &str = "urn:meros:params:oauth:grant-type:password";

/// The issuer's endpoints, from its discovery document
/// (`{issuer}/.well-known/openid-configuration`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
    #[serde(default)]
    pub device_authorization_endpoint: Option<String>,
    /// Where signed pushed authorization requests go (RFC 9126).
    #[serde(default)]
    pub pushed_authorization_request_endpoint: Option<String>,
    /// Whether the issuer puts `iss` on its authorization responses (RFC
    /// 9207); a callback without it is then refused.
    #[serde(default)]
    pub authorization_response_iss_parameter_supported: bool,
}

/// A device sign-in in progress (RFC 8628): show [`user_code`] and
/// [`verification_uri`] (or [`verification_uri_complete`] as a link or QR
/// code), then call [`MerosAuth::poll_device_sign_in`] every [`interval`]
/// seconds until it returns the user or fails.
///
/// [`user_code`]: Self::user_code
/// [`verification_uri`]: Self::verification_uri
/// [`verification_uri_complete`]: Self::verification_uri_complete
/// [`interval`]: Self::interval
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSignIn {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    /// Seconds to wait between polls; raised when the issuer says
    /// `slow_down`.
    pub interval: u64,
    /// When the codes stop working, unix seconds.
    pub expires_at: i64,
}

const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const LOGIN_TOKEN_GRANT: &str = "urn:meros:params:oauth:grant-type:sso-ticket";

/// A login-token sign-in waiting for its token: hand `code_challenge`
/// (S256) and `nonce` to whoever mints the login token, then redeem it with
/// [`MerosAuth::complete_login_token_sign_in`] and this `request_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginTokenRequest {
    pub request_id: String,
    pub code_challenge: String,
    pub nonce: String,
    /// When the request is forgotten, unix seconds.
    pub expires_at: i64,
}

/// How long a login-token request waits, and how many may wait at once.
const LOGIN_PENDING_SECS: i64 = 300;
const LOGIN_PENDING_MAX: usize = 16;

#[derive(Serialize, Deserialize, Clone)]
struct LoginPending {
    verifier: String,
    nonce: String,
    expires_at: i64,
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
const ACCESS_KEY: &str = "meros.access_token";
const LOGIN_PENDING_KEY: &str = "meros.login_pending";
const BROWSER_PENDING_KEY: &str = "meros.browser_pending";
/// The client a session's tokens belong to.
const CLIENT_KEY: &str = "meros.client_id";

#[derive(Serialize, Deserialize)]
struct KeptAccess {
    token: String,
    expires: i64,
}

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
    discovery: Mutex<Endpoints>,
    keep_access: bool,
}

/// What discovery found: nothing yet, the document, or that the issuer has
/// none (then the issuer's standard `/oauth/*` paths stand in).
#[derive(Default, Clone)]
enum Endpoints {
    #[default]
    Unknown,
    Found(Discovery),
    Missing,
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
            discovery: Mutex::new(Endpoints::Unknown),
            keep_access: false,
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

    /// Keeps the access token in the store too, so a process that runs
    /// briefly (a command-line call) reuses it until it runs out instead of
    /// refreshing on every start.
    pub fn keep_access_token(mut self) -> Self {
        self.keep_access = true;
        self
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.config.issuer)
    }

    /// One of the issuer's endpoints, from discovery; the issuer's standard
    /// path when it publishes no discovery document, or while it can't be
    /// reached (that request then fails offline anyway).
    async fn endpoint_for(
        &self,
        pick: impl Fn(&Discovery) -> Option<String>,
        standard: &str,
    ) -> String {
        match self.discover().await {
            Ok(d) => pick(&d).unwrap_or_else(|| self.endpoint(standard)),
            Err(_) => self.endpoint(standard),
        }
    }

    /// The issuer's discovery document, read once and kept. An issuer
    /// without one is remembered too, so it is asked only once.
    pub async fn discover(&self) -> Result<Discovery, Error> {
        match self.discovery.lock().unwrap().clone() {
            Endpoints::Found(d) => return Ok(d),
            Endpoints::Missing => return Err(no_discovery(None)),
            Endpoints::Unknown => {}
        }
        let r = self
            .transport
            .send(
                HttpRequest::new("GET", self.endpoint("/.well-known/openid-configuration"))
                    .header("Accept", "application/json"),
            )
            .await?;
        if r.status != 200 {
            if r.status == 404 {
                *self.discovery.lock().unwrap() = Endpoints::Missing;
            }
            return Err(no_discovery(Some(r.status)));
        }
        let d: Discovery = r.parse()?;
        *self.discovery.lock().unwrap() = Endpoints::Found(d.clone());
        Ok(d)
    }

    /// Starts a device sign-in (RFC 8628) at the issuer's
    /// `device_authorization_endpoint`, asking for the configured scopes.
    pub async fn begin_device_sign_in(&self) -> Result<DeviceSignIn, Error> {
        self.begin_device_sign_in_with(None).await
    }

    /// [`begin_device_sign_in`](Self::begin_device_sign_in) with
    /// `acr_values`, such as `urn:meros:acr:mfa` to require a two-factor
    /// sign-in (a step-up after `mfa_required`). Completing it on a session
    /// already signed in as the same user upgrades that session.
    pub async fn begin_device_sign_in_with(
        &self,
        acr_values: Option<&str>,
    ) -> Result<DeviceSignIn, Error> {
        let d = self.discover().await?;
        let Some(endpoint) = d.device_authorization_endpoint else {
            return Err(Error::new(
                None,
                "device_grant_unsupported",
                "This sign-in service does not support signing in with a code.",
            ));
        };
        let scope = self.config.scopes.join(" ");
        let mut form = vec![
            ("client_id", self.config.client_id.as_str()),
            ("scope", scope.as_str()),
        ];
        if let Some(a) = acr_values.filter(|a| !a.is_empty()) {
            form.push(("acr_values", a));
        }
        let r = self
            .transport
            .send(HttpRequest::new("POST", endpoint).form(&form))
            .await?;
        if r.status != 200 {
            return Err(Error::from_response(&r));
        }
        #[derive(Deserialize)]
        struct Codes {
            device_code: String,
            user_code: String,
            verification_uri: String,
            verification_uri_complete: Option<String>,
            interval: Option<u64>,
            expires_in: i64,
        }
        let c: Codes = r.parse()?;
        Ok(DeviceSignIn {
            device_code: c.device_code,
            user_code: c.user_code,
            verification_uri: c.verification_uri,
            verification_uri_complete: c.verification_uri_complete,
            // RFC 8628 section 3.2: 5 seconds when the issuer leaves it out.
            interval: c.interval.unwrap_or(5).max(1),
            expires_at: (self.now)() + c.expires_in,
        })
    }

    /// Asks once whether the person has approved `sign_in`. `Ok(None)`
    /// means not yet: wait `sign_in.interval` seconds (raised here when the
    /// issuer says `slow_down`) and ask again. Fails with `expired_token`
    /// once the codes run out and `access_denied` when the person declines;
    /// start over with [`begin_device_sign_in`](Self::begin_device_sign_in)
    /// either way. On approval the session is stored as for any sign-in.
    pub async fn poll_device_sign_in(
        &self,
        sign_in: &mut DeviceSignIn,
    ) -> Result<Option<MerosUser>, Error> {
        if (self.now)() >= sign_in.expires_at {
            return Err(expired(None));
        }
        match self
            .token(&[
                ("grant_type", DEVICE_CODE_GRANT),
                ("device_code", &sign_in.device_code),
                ("client_id", &self.config.client_id),
            ])
            .await
        {
            Ok(access) => self.signed_in_with(&access).await.map(Some),
            Err(e) => match e.code.as_str() {
                "authorization_pending" => Ok(None),
                // RFC 8628 section 3.5: 5 seconds more from now on.
                "slow_down" => {
                    sign_in.interval += 5;
                    Ok(None)
                }
                "expired_token" => Err(expired(e.status)),
                "access_denied" => Err(Error::new(
                    e.status,
                    "access_denied",
                    "Sign-in was declined.",
                )),
                _ => Err(e),
            },
        }
    }

    async fn login_pending(&self) -> std::collections::BTreeMap<String, LoginPending> {
        let now = (self.now)();
        let mut all: std::collections::BTreeMap<String, LoginPending> = self
            .store
            .read(LOGIN_PENDING_KEY)
            .await
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        all.retain(|_, p| p.expires_at > now);
        all
    }

    async fn keep_login_pending(&self, all: &std::collections::BTreeMap<String, LoginPending>) {
        let value = if all.is_empty() {
            None
        } else {
            serde_json::to_string(all).ok()
        };
        self.store.write(LOGIN_PENDING_KEY, value).await;
    }

    /// Starts redeeming a login token minted for this client elsewhere (a
    /// user who signed in on another product's console). Up to 16 requests
    /// wait at once, each for five minutes; the oldest goes first.
    pub async fn begin_login_token_sign_in(&self) -> LoginTokenRequest {
        let pkce = Pkce::generate();
        let nonce = random_unreserved(22);
        let request_id = random_unreserved(22);
        let expires_at = (self.now)() + LOGIN_PENDING_SECS;
        let mut all = self.login_pending().await;
        while all.len() >= LOGIN_PENDING_MAX {
            let oldest = all
                .iter()
                .min_by_key(|(_, p)| p.expires_at)
                .map(|(k, _)| k.clone())
                .unwrap_or_default();
            all.remove(&oldest);
        }
        all.insert(
            request_id.clone(),
            LoginPending {
                verifier: pkce.verifier.clone(),
                nonce: nonce.clone(),
                expires_at,
            },
        );
        self.keep_login_pending(&all).await;
        LoginTokenRequest {
            request_id,
            code_challenge: pkce.challenge,
            nonce,
            expires_at,
        }
    }

    /// Redeems `login_token` for request `request_id` as this client, with
    /// the configured scopes. The id_token must be for this client, carry
    /// the request's nonce and a subject, be unexpired and come from this
    /// issuer, and a refresh token must come with it; otherwise the tokens
    /// are revoked and the sign-in fails with `invalid_response`. A different
    /// user already signed in here is signed out on the service first; the
    /// result says whether that happened. Fails with `unknown_request` for a
    /// request not begun here or expired, and the service's `invalid_grant`
    /// for a token it won't take. Offline, the request is kept for a retry.
    pub async fn complete_login_token_sign_in(
        &self,
        request_id: &str,
        login_token: &str,
    ) -> Result<(MerosUser, bool), Error> {
        let mut all = self.login_pending().await;
        let Some(pending) = all.get(request_id).cloned() else {
            return Err(unknown_request());
        };
        let scope = self.config.scopes.join(" ");
        let result = self
            .token_response(&[
                ("grant_type", LOGIN_TOKEN_GRANT),
                ("login_token", login_token),
                ("client_id", &self.config.client_id),
                ("code_verifier", &pending.verifier),
                ("scope", &scope),
            ])
            .await;
        if !matches!(&result, Err(e) if e.offline()) {
            all.remove(request_id);
            self.keep_login_pending(&all).await;
        }
        let session = self
            .accept(result?, &self.config.client_id, &pending.nonce, None)
            .await?;
        let s = self.adopt(session).await;
        Ok((s.user, s.replaced_previous))
    }

    /// Checks a token response from a sign-in and reads who signed in. The
    /// id_token must be for `client_id`, carry `nonce` and a subject, be
    /// unexpired and come from this issuer, and a refresh token must come
    /// with it; otherwise the tokens are revoked and it fails with
    /// `invalid_response`.
    async fn accept(
        &self,
        t: Tokens,
        client_id: &str,
        nonce: &str,
        context: Option<String>,
    ) -> Result<NewSession, Error> {
        let issuer = self
            .discover()
            .await
            .ok()
            .map(|d| d.issuer)
            .unwrap_or_else(|| self.config.issuer.clone());
        let claims = t
            .id_token
            .as_deref()
            .and_then(jwt_claims)
            .unwrap_or(serde_json::Value::Null);
        let problem = id_token_problem(&claims, client_id, nonce, Some(&issuer), (self.now)())
            .or_else(|| {
                t.refresh_token
                    .is_none()
                    .then_some("no refresh token was returned")
            });
        if let Some(why) = problem {
            self.revoke_as(&t.access_token, client_id).await;
            return Err(Error::new(
                None,
                "invalid_response",
                format!("The sign-in could not be accepted: {why}."),
            ));
        }
        let text = |k: &str| claims[k].as_str().unwrap_or_default().to_string();
        let mut user = MerosUser {
            id: text("sub"),
            name: text("name"),
            email: text("email"),
        };
        if user.name.is_empty() && user.email.is_empty() {
            // An id_token without profile claims: the profile is at userinfo.
            if let Ok(u) = self.userinfo(&t.access_token).await
                && u.id == user.id
            {
                user = u;
            }
        }
        Ok(NewSession {
            user,
            client_id: client_id.to_string(),
            acr: claims["acr"].as_str().map(str::to_string),
            amr: claims["amr"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
            context,
            tokens: t,
        })
    }

    /// Keeps a completed sign-in as this session. A different user signed in
    /// here before is signed out on the service first.
    pub async fn adopt(&self, session: NewSession) -> SignedIn {
        self.load().await;
        let previous = self.user();
        let replaced = previous.as_ref().is_some_and(|p| p.id != session.user.id);
        if replaced {
            let access = self.session.lock().unwrap().access.clone();
            let token = match access {
                Some(a) => Some(a),
                None => self.store.read(REFRESH_KEY).await,
            };
            if let Some(token) = token {
                self.revoke(&token).await;
            }
        }
        self.store
            .write(CLIENT_KEY, Some(session.client_id.clone()))
            .await;
        self.keep(session.tokens).await;
        let user = session.user;
        self.store
            .write(USER_KEY, serde_json::to_string(&user).ok())
            .await;
        {
            let mut s = self.session.lock().unwrap();
            s.user = Some(user.clone());
            s.loaded = true;
        }
        self.user_changed(Some(user.clone()));
        SignedIn {
            user,
            replaced_previous: replaced,
            acr: session.acr,
            amr: session.amr,
        }
    }

    /// The client this session's tokens belong to.
    async fn session_client(&self) -> String {
        self.store
            .read(CLIENT_KEY)
            .await
            .unwrap_or_else(|| self.config.client_id.clone())
    }

    /// Revokes `token` (RFC 7009) with this session's client id; Meros revokes
    /// nothing without it. Best effort: true when the service answered
    /// (it always answers 200), false when it couldn't be reached.
    async fn revoke(&self, token: &str) -> bool {
        let client = self.session_client().await;
        self.revoke_as(token, &client).await
    }

    async fn revoke_as(&self, token: &str, client_id: &str) -> bool {
        let revoke = self
            .endpoint_for(|d| d.revocation_endpoint.clone(), "/oauth/revoke")
            .await;
        self.transport
            .send(
                HttpRequest::new("POST", revoke)
                    .form(&[("token", token), ("client_id", client_id)]),
            )
            .await
            .is_ok_and(|r| r.ok())
    }

    /// Reads the stored session. The other calls do it on first use; call it
    /// at startup to know [`user`](Self::user) before any request.
    pub async fn load(&self) {
        if self.session.lock().unwrap().loaded {
            return;
        }
        let user = self.store.read(USER_KEY).await;
        let refresh = self.store.read(REFRESH_KEY).await;
        let access = if self.keep_access {
            self.store.read(ACCESS_KEY).await
        } else {
            None
        };
        let mut s = self.session.lock().unwrap();
        if s.loaded {
            return;
        }
        s.loaded = true;
        if refresh.is_some() {
            s.user = user.and_then(|u| serde_json::from_str(&u).ok());
            if let Some(kept) = access.and_then(|a| serde_json::from_str::<KeptAccess>(&a).ok()) {
                s.access = Some(kept.token);
                s.expires = kept.expires;
            }
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
    /// loopback `http://127.0.0.1:{port}/…` on desktop). The sign-in waits,
    /// stored, so the callback completes even if the app was closed
    /// meanwhile. [`begin_browser_sign_in`](Self::begin_browser_sign_in)
    /// takes more options.
    pub async fn begin_sign_in_with(&self, redirect_uri: &str) -> String {
        let options = BrowserSignInOptions {
            redirect_uri: redirect_uri.to_string(),
            ..Default::default()
        };
        // Without a device the authorize URL is made here; nothing can fail.
        self.begin_browser_sign_in(&options)
            .await
            .map(|b| b.authorize_url)
            .unwrap_or_default()
    }

    /// Begins a browser sign-in (authorization code with PKCE S256, a nonce
    /// and state). Up to 32 wait at once, each for ten minutes; the oldest
    /// goes first. With [`BrowserSignInOptions::device`], the request is
    /// pushed to the issuer signed with the device key, and fails with the
    /// issuer's refusal (`invalid_redirect_uri`, `unauthorized_client`,
    /// `bad_signature`, `rate_limited`) or `par_unsupported`.
    pub async fn begin_browser_sign_in(
        &self,
        options: &BrowserSignInOptions,
    ) -> Result<BrowserSignIn, Error> {
        let redirect_uri = if options.redirect_uri.is_empty() {
            self.config.redirect_uri.clone()
        } else {
            options.redirect_uri.clone()
        };
        let pkce = Pkce::generate();
        let state = random_unreserved(32);
        let nonce = random_unreserved(22);
        let scope = self.config.scopes.join(" ");
        let mut params: Vec<(&str, &str)> = vec![
            ("client_id", &self.config.client_id),
            ("response_type", "code"),
            ("redirect_uri", &redirect_uri),
            ("scope", &scope),
            ("state", &state),
            ("nonce", &nonce),
            ("code_challenge", &pkce.challenge),
            ("code_challenge_method", "S256"),
        ];
        for (k, v) in [
            ("acr_values", &options.acr_values),
            ("login_hint", &options.login_hint),
            ("prompt", &options.prompt),
        ] {
            if let Some(v) = v.as_deref().filter(|v| !v.is_empty()) {
                params.push((k, v));
            }
        }
        let authorize = self
            .endpoint_for(
                |d| Some(d.authorization_endpoint.clone()),
                "/oauth/authorize",
            )
            .await;
        let authorize_url = match &options.device {
            None => with_query(&authorize, &params),
            Some(device) => {
                let endpoint = self
                    .discover()
                    .await?
                    .pushed_authorization_request_endpoint
                    .ok_or_else(|| {
                        Error::new(
                            None,
                            "par_unsupported",
                            "This sign-in service does not take pushed sign-in requests.",
                        )
                    })?;
                let r = self
                    .transport
                    .send(self.signed_form(device.as_ref(), &endpoint, &params)?)
                    .await?;
                if !r.ok() {
                    return Err(Error::from_response(&r));
                }
                #[derive(Deserialize)]
                struct Pushed {
                    request_uri: String,
                }
                let p: Pushed = r.parse()?;
                with_query(
                    &authorize,
                    &[
                        ("client_id", &self.config.client_id),
                        ("request_uri", &p.request_uri),
                    ],
                )
            }
        };
        let expires_at = (self.now)() + BROWSER_PENDING_SECS;
        let mut all = self.browser_pending().await;
        while all.len() >= BROWSER_PENDING_MAX {
            let oldest = all
                .iter()
                .min_by_key(|(_, p)| p.expires_at)
                .map(|(k, _)| k.clone())
                .unwrap_or_default();
            all.remove(&oldest);
        }
        all.insert(
            state.clone(),
            BrowserPending {
                verifier: pkce.verifier,
                nonce,
                redirect_uri,
                client_id: self.config.client_id.clone(),
                expires_at,
                acr_values: options.acr_values.clone(),
                context: options.context.clone(),
            },
        );
        self.keep_browser_pending(&all).await;
        Ok(BrowserSignIn {
            authorize_url,
            state,
            expires_at,
        })
    }

    fn signed_form(
        &self,
        device: &dyn DeviceSigner,
        endpoint: &str,
        fields: &[(&str, &str)],
    ) -> Result<HttpRequest, Error> {
        crate::device::signed_form(device, endpoint, fields, (self.now)())
    }

    async fn browser_pending(&self) -> std::collections::BTreeMap<String, BrowserPending> {
        let now = (self.now)();
        let mut all: std::collections::BTreeMap<String, BrowserPending> = self
            .store
            .read(BROWSER_PENDING_KEY)
            .await
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        all.retain(|_, p| p.expires_at > now);
        all
    }

    async fn keep_browser_pending(&self, all: &std::collections::BTreeMap<String, BrowserPending>) {
        let value = if all.is_empty() {
            None
        } else {
            serde_json::to_string(all).ok()
        };
        self.store.write(BROWSER_PENDING_KEY, value).await;
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

    /// Finishes signing in from the redirect back to the app, and keeps the
    /// session here.
    pub async fn complete_sign_in(&self, callback: &str) -> Result<MerosUser, Error> {
        Ok(self.complete_browser_sign_in(callback).await?.user)
    }

    /// [`finish_browser_sign_in`](Self::finish_browser_sign_in), then
    /// [`adopt`](Self::adopt) here.
    pub async fn complete_browser_sign_in(&self, callback: &str) -> Result<SignedIn, Error> {
        let session = self.finish_browser_sign_in(callback).await?;
        Ok(self.adopt(session).await)
    }

    /// Checks the redirect back from the sign-in page and exchanges its code,
    /// without keeping the session anywhere yet. The state must be one
    /// waiting here (each finishes once), `iss` must be this issuer, the
    /// code is exchanged with the stored verifier and redirect, and the
    /// id_token is checked (for this client, with the nonce, unexpired, from
    /// this issuer, with a refresh token). Refusals:
    /// the issuer's `error` (`access_denied` when the person canceled),
    /// `unknown_request`, `state_mismatch`, `issuer_mismatch`,
    /// `invalid_grant`, `invalid_response`. Offline, the sign-in keeps
    /// waiting for a retry.
    pub async fn finish_browser_sign_in(&self, callback: &str) -> Result<NewSession, Error> {
        let url = url::Url::parse(callback)
            .map_err(|_| Error::new(None, "state_mismatch", "That sign-in link is not valid."))?;
        let q = |k: &str| {
            url.query_pairs()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.into_owned())
        };
        let state = q("state").unwrap_or_default();
        let mut all = self.browser_pending().await;
        let pending = match all.remove(&state) {
            Some(p) => Some(p),
            None => self.legacy_pending(&state).await,
        };
        self.keep_browser_pending(&all).await;
        if let Some(error) = q("error") {
            let message = if error == "access_denied" {
                "Sign-in was canceled.".to_string()
            } else {
                q("error_description").unwrap_or_else(|| format!("Sign-in failed ({error})."))
            };
            return Err(Error::new(None, error, message));
        }
        let Some(pending) = pending else {
            return Err(unknown_request());
        };
        let discovery = self.discover().await.ok();
        let issuer = discovery
            .as_ref()
            .map(|d| d.issuer.clone())
            .unwrap_or_else(|| self.config.issuer.clone());
        let iss_required = discovery
            .as_ref()
            .is_some_and(|d| d.authorization_response_iss_parameter_supported);
        match q("iss") {
            Some(iss) if iss != issuer => return Err(issuer_mismatch()),
            None if iss_required => return Err(issuer_mismatch()),
            _ => {}
        }
        let Some(code) = q("code") else {
            return Err(Error::new(
                None,
                "state_mismatch",
                "That sign-in link does not match. Try again.",
            ));
        };
        let result = self
            .token_response(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", &pending.redirect_uri),
                ("client_id", &pending.client_id),
                ("code_verifier", &pending.verifier),
            ])
            .await;
        if matches!(&result, Err(e) if e.offline()) {
            let mut all = self.browser_pending().await;
            all.insert(state, pending.clone());
            self.keep_browser_pending(&all).await;
        }
        let t = result?;
        if pending.nonce.is_empty() {
            // Begun before nonces were sent: the profile comes from userinfo.
            let user = self.userinfo(&t.access_token).await?;
            return Ok(NewSession {
                user,
                client_id: pending.client_id,
                acr: None,
                amr: Vec::new(),
                context: pending.context,
                tokens: t,
            });
        }
        self.accept(t, &pending.client_id, &pending.nonce, pending.context)
            .await
    }

    /// The single pending sign-in older versions kept, if it has `state`.
    async fn legacy_pending(&self, state: &str) -> Option<BrowserPending> {
        let raw = self.store.read(PENDING_KEY).await?;
        self.store.write(PENDING_KEY, None).await;
        let p: Pending = serde_json::from_str(&raw).ok()?;
        (p.state == state).then(|| BrowserPending {
            verifier: p.verifier,
            nonce: String::new(),
            redirect_uri: p
                .redirect_uri
                .unwrap_or_else(|| self.config.redirect_uri.clone()),
            client_id: self.config.client_id.clone(),
            expires_at: 0,
            acr_values: None,
            context: None,
        })
    }

    /// Signs in with an email and password, for consoles: the device grant's
    /// alternative where typing is possible. The request is signed with the
    /// device key, and the client must be allowed the password grant. The
    /// password is sent once and kept nowhere. Refusals: `bad_credentials`,
    /// `email_not_verified`, `team_requires_two_factor`, `account_locked`,
    /// `rate_limited`, `unauthorized_client`, `bad_signature`.
    pub async fn password_sign_in(
        &self,
        device: &dyn DeviceSigner,
        email: &str,
        password: &str,
    ) -> Result<PasswordStep, Error> {
        let scope = self.config.scopes.join(" ");
        self.password_grant(
            device,
            &[
                ("email", email),
                ("password", password),
                ("scope", scope.as_str()),
            ],
        )
        .await
    }

    /// Finishes a password sign-in's two-factor step with the person's code
    /// (an authenticator code or a recovery code). Refusals: `bad_code`
    /// (try again; the challenge allows five tries), `invalid_challenge`
    /// (start over), `account_locked`, `rate_limited`.
    pub async fn two_factor_sign_in(
        &self,
        device: &dyn DeviceSigner,
        challenge: &str,
        code: &str,
    ) -> Result<NewSession, Error> {
        let code = code.trim().replace(' ', "");
        match self
            .password_grant(device, &[("challenge", challenge), ("code", &code)])
            .await?
        {
            PasswordStep::SignedIn(s) => Ok(s),
            PasswordStep::TwoFactor(_) => Err(Error::new(
                None,
                "invalid_response",
                "The sign-in service asked for a second code again.",
            )),
        }
    }

    async fn password_grant(
        &self,
        device: &dyn DeviceSigner,
        fields: &[(&str, &str)],
    ) -> Result<PasswordStep, Error> {
        let nonce = random_unreserved(22);
        let mut form = vec![
            ("grant_type", PASSWORD_GRANT),
            ("client_id", self.config.client_id.as_str()),
        ];
        form.extend_from_slice(fields);
        form.push(("nonce", &nonce));
        let endpoint = self
            .endpoint_for(|d| Some(d.token_endpoint.clone()), "/oauth/token")
            .await;
        let r = self
            .transport
            .send(self.signed_form(device, &endpoint, &form)?)
            .await?;
        if r.status != 200 {
            let body = r.value();
            if r.error_code().as_deref() == Some("two_factor_required")
                && let Some(challenge) = body["challenge"].as_str()
            {
                return Ok(PasswordStep::TwoFactor(TwoFactorChallenge {
                    challenge: challenge.to_string(),
                    methods: body["methods"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default(),
                    expires_at: (self.now)() + body["expires_in"].as_i64().unwrap_or(300),
                }));
            }
            return Err(Error::from_response(&r));
        }
        let t: Tokens = r.parse()?;
        let client = self.config.client_id.clone();
        Ok(PasswordStep::SignedIn(
            self.accept(t, &client, &nonce, None).await?,
        ))
    }

    /// The account behind an access token.
    async fn userinfo(&self, access: &str) -> Result<MerosUser, Error> {
        let userinfo = self
            .endpoint_for(|d| d.userinfo_endpoint.clone(), "/oauth/userinfo")
            .await;
        let info = self
            .transport
            .send(
                HttpRequest::new("GET", userinfo)
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
        info.parse()
    }

    /// Reads the account behind a new access token from the device grant
    /// (the configured client) and stores the session.
    async fn signed_in_with(&self, access: &str) -> Result<MerosUser, Error> {
        let user = self.userinfo(access).await?;
        self.store
            .write(CLIENT_KEY, Some(self.config.client_id.clone()))
            .await;
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
        let client = self.session_client().await;
        let result = self
            .token(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh),
                ("client_id", &client),
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
        let t = self.token_response(form).await?;
        Ok(self.keep(t).await)
    }

    async fn token_response(&self, form: &[(&str, &str)]) -> Result<Tokens, Error> {
        let endpoint = self
            .endpoint_for(|d| Some(d.token_endpoint.clone()), "/oauth/token")
            .await;
        let r = self
            .transport
            .send(HttpRequest::new("POST", endpoint).form(form))
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
        r.parse()
    }

    /// Stores a token response: the rotated refresh token first, then the
    /// access token.
    async fn keep(&self, t: Tokens) -> String {
        if let Some(refresh) = t.refresh_token {
            self.store.write(REFRESH_KEY, Some(refresh)).await;
        }
        let expires = (self.now)() + t.expires_in.unwrap_or(3600);
        if self.keep_access {
            let kept = KeptAccess {
                token: t.access_token.clone(),
                expires,
            };
            self.store
                .write(ACCESS_KEY, serde_json::to_string(&kept).ok())
                .await;
        }
        let mut s = self.session.lock().unwrap();
        s.access = Some(t.access_token.clone());
        s.expires = expires;
        s.generation += 1;
        t.access_token
    }

    /// Signs out here and revokes the session on the issuer. Returns whether
    /// the service revoked it: false when it couldn't be reached (the local
    /// session ends anyway, and the refresh token stays valid on the service
    /// until it idles out) or when there was no session.
    pub async fn sign_out(&self) -> bool {
        self.load().await;
        let access = self.session.lock().unwrap().access.clone();
        let token = match access {
            Some(a) => Some(a),
            None => self.store.read(REFRESH_KEY).await,
        };
        let revoked = match token {
            Some(token) => self.revoke(&token).await,
            None => false,
        };
        self.clear().await;
        revoked
    }

    async fn clear(&self) {
        let had_user = {
            let mut s = self.session.lock().unwrap();
            s.access = None;
            s.user.take().is_some()
        };
        self.store.write(REFRESH_KEY, None).await;
        self.store.write(USER_KEY, None).await;
        self.store.write(CLIENT_KEY, None).await;
        if self.keep_access {
            self.store.write(ACCESS_KEY, None).await;
        }
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

#[derive(Deserialize)]
struct Tokens {
    access_token: String,
    expires_in: Option<i64>,
    refresh_token: Option<String>,
    id_token: Option<String>,
}

/// The claims of a JWT, unverified: an id_token taken straight from the
/// token endpoint over TLS needs no signature check (OIDC Core 3.1.3.7).
fn jwt_claims(token: &str) -> Option<serde_json::Value> {
    let payload = token.split('.').nth(1)?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()
}

/// Why an id_token can't be accepted, if it can't.
fn id_token_problem(
    claims: &serde_json::Value,
    client_id: &str,
    nonce: &str,
    issuer: Option<&str>,
    now: i64,
) -> Option<&'static str> {
    if !claims.is_object() {
        return Some("no readable id_token");
    }
    let aud_ok = match &claims["aud"] {
        serde_json::Value::String(a) => a == client_id,
        serde_json::Value::Array(a) => a.iter().any(|x| x == client_id),
        _ => false,
    };
    if !aud_ok {
        return Some("the id_token is for a different client");
    }
    if claims["sub"].as_str().is_none_or(|s| s.trim().is_empty()) {
        return Some("the id_token has no subject");
    }
    if claims["nonce"].as_str() != Some(nonce) {
        return Some("the id_token belongs to another sign-in (nonce)");
    }
    if claims["exp"].as_i64().is_some_and(|exp| exp < now - 60) {
        return Some("the id_token has expired");
    }
    if let (Some(want), Some(got)) = (issuer, claims["iss"].as_str())
        && want != got
    {
        return Some("the id_token is from a different issuer");
    }
    None
}

fn unknown_request() -> Error {
    Error::new(
        None,
        "unknown_request",
        "This sign-in was not begun here, or it expired. Begin it again.",
    )
}

fn issuer_mismatch() -> Error {
    Error::new(
        None,
        "issuer_mismatch",
        "That sign-in came back from a different sign-in service.",
    )
}

fn no_discovery(status: Option<u16>) -> Error {
    Error::new(
        status,
        "discovery",
        "Could not read the sign-in service's settings.",
    )
}

fn expired(status: Option<u16>) -> Error {
    Error::new(
        status,
        "expired_token",
        "The sign-in code expired. Get a new one.",
    )
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
