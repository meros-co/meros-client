//! The `meros-client` command-line helper (feature `cli`): every client in
//! this crate behind one JSON-in, JSON-out command, for apps not written in
//! Rust. See `docs/cli.md` for the commands and their output.
//!
//! Each call reads one JSON object (the command's input) and writes one JSON
//! object: `{"ok": true, ...}` or `{"ok": false, "error": {...}}`, with the
//! exit code in [`exit`]. Everything kept between calls (the device key, the
//! sign-in session, the license statement and token, undelivered events)
//! lives in the caller's state directory, which only the calling user can
//! read. A call holds a lock on that directory, so concurrent calls run one
//! after another and a rotating refresh token is never used twice.
//!
//! Several identities can be signed in at once, each under a `session`
//! handle the caller picks (its own client id, scopes and rotating refresh
//! token), and with `key_file` every stored secret is sealed with a key kept
//! outside the state directory.
//!
//! The [`READ_ONLY`] commands change nothing: they create no directory, key
//! or lock file and take only a shared lock, so a privileged process can ask
//! about another user's state directory without leaving files there. They
//! verify what is stored on every call and trust no cached answer.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::{Map, Value, json};

use crate::events::{Actor, Collector, Emitter, EmitterConfig, Envelope, Event, Severity, Subject};
use crate::http::{BoxFuture, unix_now};
use crate::{
    AccessTokenSource, AccountSupportApi, AuthConfig, DeviceIdentity, DeviceSignIn, DeviceSigner,
    Error, FeedResponse, LicenseClient, LicenseConfig, LicenseDevice, MerosAuth, MerosCloud,
    MerosFeeds, MerosUser, ServerConfig, ServerDevice, ServerLicenseClient, ServerRenewal,
    SignInClaim, SupportApi, SupportThread, SupportTicket, TokenStore, Transport, verify_licence,
    verify_pack,
};

/// Exit codes.
pub mod exit {
    /// Done; the output has `"ok": true`.
    pub const OK: i32 = 0;
    /// The service refused: `error.code` is its code, unchanged.
    pub const REFUSED: i32 = 1;
    /// No connection to the service.
    pub const OFFLINE: i32 = 2;
    /// The command or its input is wrong (`unknown_command`, `bad_input`).
    pub const USAGE: i32 = 3;
    /// The state directory or a stored statement or token is unusable
    /// (`state_error`, `verify_failed`, `no_device_identity`,
    /// `token_rejected`, `not_activated`, `no_sign_in`).
    pub const LOCAL: i32 = 4;
}

/// What a call produced: the JSON to print and the process exit code.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub exit: i32,
    pub output: Value,
}

/// Every command, for `meros-client commands`.
pub const COMMANDS: &[&str] = &[
    "device.identity",
    "signin.start",
    "signin.poll",
    "signin.status",
    "signin.token",
    "signin.signout",
    "signin.list",
    "signin.cancel",
    "signin.redeem.begin",
    "signin.redeem.complete",
    "signin.login_token",
    "server.activate",
    "server.activate_login",
    "server.renew",
    "server.release",
    "server.status",
    "server.verify",
    "license.activate",
    "license.renew",
    "license.release",
    "license.status",
    "license.offline_request",
    "license.offline_import",
    "license.manage_url",
    "license.claim",
    "license.adopt",
    "license.seats",
    "license.release_seat",
    "cloud.accounts",
    "cloud.entitlements",
    "cloud.feed",
    "cloud.feed_versions",
    "cloud.inventory.get",
    "cloud.inventory.put",
    "cloud.profile.get",
    "cloud.profile.put",
    "cloud.profile.delete",
    "cloud.docs.list",
    "cloud.docs.get",
    "cloud.docs.put",
    "cloud.docs.delete",
    "cloud.docs.versions",
    "cloud.files.list",
    "cloud.files.put",
    "cloud.files.get",
    "cloud.files.delete",
    "support.create",
    "support.list",
    "support.thread",
    "support.reply",
    "events.send",
    "events.relay",
    "events.flush",
    "events.clear",
    "fake.keys",
    "fake.state",
    "fake.set",
    "fake.approve_device",
    "fake.deny_device",
    "fake.publish_pack",
    "fake.support_reply",
    "fake.advance",
];

/// Commands that only read the state directory.
pub const READ_ONLY: &[&str] = &[
    "server.status",
    "server.verify",
    "license.status",
    "signin.status",
    "signin.list",
];

const LOCAL_CODES: &[&str] = &[
    "unknown_request",
    "not_cached",
    "state_error",
    "verify_failed",
    "no_device_identity",
    "token_rejected",
    "not_activated",
    "no_sign_in",
    "signed_out",
];

/// Runs one command against `transport`.
pub async fn run(command: &str, input: Value, transport: Arc<dyn Transport>) -> Outcome {
    let Value::Object(input) = input else {
        return failure(bad_input("The input must be a JSON object."));
    };
    if !COMMANDS.contains(&command) {
        return failure(Error::new(
            None,
            "unknown_command",
            format!("Unknown command: {command}. Run `meros-client commands` for the list."),
        ));
    }
    let mut input = input;
    let fake = match fake_mode(&mut input) {
        Ok(f) => f,
        Err(e) => return failure(e),
    };
    if command.starts_with("fake.") {
        let Some((fake, path)) = &fake else {
            return failure(bad_input("fake.* commands need `\"issuer\": \"fake:\"`."));
        };
        let result = fake_command(command, &input, fake);
        if let Err(e) = save_fake(fake, path) {
            return failure(e);
        }
        return match result {
            Ok(v) => success(v),
            Err(e) => failure(e),
        };
    }
    let transport: Arc<dyn Transport> = match &fake {
        Some((f, _)) => f.clone(),
        None => transport,
    };
    let ctx = match Ctx::open(input, transport, READ_ONLY.contains(&command)) {
        Ok(c) => c,
        Err(e) => return failure(e),
    };
    let result = ctx.dispatch(command).await;
    drop(ctx);
    if let Some((f, path)) = &fake
        && let Err(e) = save_fake(f, path)
    {
        return failure(e);
    }
    match result {
        Ok(v) => success(v),
        Err(e) => failure(e),
    }
}

fn success(v: Value) -> Outcome {
    match v {
        Value::Object(mut out) => {
            out.insert("ok".into(), json!(true));
            Outcome {
                exit: exit::OK,
                output: Value::Object(out),
            }
        }
        other => Outcome {
            exit: exit::OK,
            output: json!({"ok": true, "result": other}),
        },
    }
}

// ───────────────────────────── Fake mode ─────────────────────────────

/// The issuer that selects fake mode, and the origin the fake answers as.
pub const FAKE_ISSUER: &str = "fake:";
const FAKE_ORIGIN: &str = "https://fake.meros.test";

/// With `"issuer": "fake:"`, the service is a [`FakeMeros`] kept in
/// `{state_dir}/fake.json`, so products can test the real binary with no
/// network. Its issuer becomes [`FAKE_ORIGIN`].
fn fake_mode(
    input: &mut Map<String, Value>,
) -> Result<Option<(Arc<crate::fake::FakeMeros>, PathBuf)>, Error> {
    if input.get("issuer").and_then(|v| v.as_str()) != Some(FAKE_ISSUER) {
        return Ok(None);
    }
    let dir = input
        .get("state_dir")
        .and_then(|v| v.as_str())
        .filter(|d| !d.is_empty())
        .ok_or_else(|| bad_input("Fake mode keeps its service in `state_dir`; give one."))?;
    create_private_dir(Path::new(dir)).map_err(state_error)?;
    let path = Path::new(dir).join("fake.json");
    let state = match fs::read(&path) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).map_err(|e| state_error(format!("fake.json: {e}")))?
        }
        Err(_) => {
            // Seeded for the helper: real signed tokens, so they verify
            // against `fake.keys`.
            let mut s = crate::fake::FakeState::default();
            s.signed_tokens = true;
            s
        }
    };
    input.insert("issuer".into(), json!(FAKE_ORIGIN));
    Ok(Some((crate::fake::FakeMeros::with_state(state), path)))
}

fn save_fake(fake: &crate::fake::FakeMeros, path: &Path) -> Result<(), Error> {
    let bytes = serde_json::to_vec_pretty(&*fake.state()).map_err(state_error)?;
    write_private(path, &bytes).map_err(state_error)
}

/// The fake's controls, for tests driving the binary.
fn fake_command(
    command: &str,
    input: &Map<String, Value>,
    fake: &crate::fake::FakeMeros,
) -> Result<Value, Error> {
    let text = |k: &str| {
        input
            .get(k)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| bad_input(format!("Missing input field `{k}`.")))
    };
    let table = |keys: Vec<(&str, String)>| -> Value {
        keys.into_iter()
            .map(|(k, v)| (k.to_string(), json!(v)))
            .collect::<Map<_, _>>()
            .into()
    };
    match command {
        "fake.keys" => Ok(json!({
            "server": table(crate::fake::server_keys()),
            "entitlement": table(crate::fake::entitlement_keys()),
            "issuer": FAKE_ORIGIN,
        })),
        "fake.state" => {
            Ok(json!({"state": serde_json::to_value(&*fake.state()).map_err(state_error)?}))
        }
        "fake.set" => {
            let Some(Value::Object(patch)) = input.get("patch") else {
                return Err(bad_input("`patch` must be an object of state fields."));
            };
            let mut st = fake.state();
            let mut current = serde_json::to_value(&*st).map_err(state_error)?;
            for (k, v) in patch {
                if current.get(k).is_none() {
                    return Err(bad_input(format!("The fake has no field `{k}`.")));
                }
                current[k] = v.clone();
            }
            let mint = st.mint.take();
            let requests = std::mem::take(&mut st.requests);
            *st = serde_json::from_value(current)
                .map_err(|e| bad_input(format!("The patch doesn't fit the fake: {e}")))?;
            st.mint = mint;
            st.requests = requests;
            Ok(json!({}))
        }
        "fake.approve_device" | "fake.deny_device" => {
            let code = text("user_code")?;
            if !fake
                .state()
                .device_sign_ins
                .values()
                .any(|d| d.user_code == code)
            {
                return Err(bad_input(format!("No device sign-in shows {code}.")));
            }
            if command == "fake.approve_device" {
                fake.approve_device(&code);
            } else {
                fake.deny_device(&code);
            }
            Ok(json!({}))
        }
        "fake.publish_pack" => {
            let entitled = input.get("entitled").and_then(|v| v.as_bool()) == Some(true);
            fake.publish_pack(
                &text("product")?,
                &text("pack")?,
                input.get("payload").cloned().unwrap_or(json!({})),
                entitled,
            );
            Ok(json!({}))
        }
        "fake.support_reply" => {
            fake.support_replies(&text("ticket_id")?, &text("message")?);
            Ok(json!({}))
        }
        "fake.advance" => {
            let secs = input
                .get("seconds")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| bad_input("`seconds` must be an integer."))?;
            fake.state().clock += secs;
            Ok(json!({"clock": fake.state().clock}))
        }
        _ => unreachable!("checked against COMMANDS"),
    }
}

fn failure(e: Error) -> Outcome {
    let exit = if e.code == "network" {
        exit::OFFLINE
    } else if e.code == "unknown_command" || e.code == "bad_input" {
        exit::USAGE
    } else if LOCAL_CODES.contains(&e.code.as_str()) {
        exit::LOCAL
    } else {
        exit::REFUSED
    };
    let mut error = json!({"code": e.code, "message": e.message});
    if let Some(s) = e.status {
        error["status"] = json!(s);
    }
    if let Some(r) = e.retry_after {
        error["retry_after"] = json!(r);
    }
    if let Some(v) = e.head_version {
        error["head_version"] = json!(v);
    }
    if let Some(h) = &e.head {
        if let Some(c) = &h.content_hash {
            error["head_content_hash"] = json!(c);
        }
        if let Some(t) = &h.updated_at {
            error["head_updated_at"] = json!(t);
        }
    }
    Outcome {
        exit,
        output: json!({"ok": false, "error": error}),
    }
}

fn bad_input(message: impl Into<String>) -> Error {
    Error::new(None, "bad_input", message)
}

fn state_error(e: impl std::fmt::Display) -> Error {
    Error::new(None, "state_error", format!("State directory: {e}"))
}

// ───────────────────────────── State directory ─────────────────────────────

/// The caller's state directory, locked for the call.
struct State {
    dir: PathBuf,
    read_only: bool,
    /// Seals every file written, when the caller gives a key file.
    key: Option<chacha20poly1305::Key>,
    _lock: Option<File>,
}

/// The key in `key_file`: 32 random bytes as hex, made on first use.
fn load_key(path: &str, dir: &Path, create: bool) -> Result<chacha20poly1305::Key, Error> {
    let path = PathBuf::from(path);
    let within = |p: &Path| {
        let canon = |q: &Path| q.canonicalize().unwrap_or_else(|_| q.to_path_buf());
        p.parent()
            .is_some_and(|parent| canon(parent).starts_with(canon(dir)))
    };
    if within(&path) {
        return Err(bad_input(
            "Keep `key_file` outside the state directory, or it protects nothing.",
        ));
    }
    let parse = |text: &str| -> Option<chacha20poly1305::Key> {
        let text = text.trim();
        if text.len() != 64 {
            return None;
        }
        let bytes: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16))
            .collect::<Result<_, _>>()
            .ok()?;
        Some(*chacha20poly1305::Key::from_slice(&bytes))
    };
    match fs::read_to_string(&path) {
        Ok(text) => parse(&text).ok_or_else(|| state_error("key_file is not 64 hex digits")),
        Err(_) if create => {
            let bytes: [u8; 32] = rand::random();
            write_private(&path, hex(&bytes).as_bytes()).map_err(state_error)?;
            Ok(*chacha20poly1305::Key::from_slice(&bytes))
        }
        Err(e) => Err(state_error(format!("key_file: {e}"))),
    }
}

impl State {
    fn open(dir: &str, key_file: Option<&str>) -> Result<State, Error> {
        let dir = PathBuf::from(dir);
        create_private_dir(&dir).map_err(state_error)?;
        let key = key_file.map(|k| load_key(k, &dir, true)).transpose()?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join("lock"))
            .map_err(state_error)?;
        lock.lock().map_err(state_error)?;
        Ok(State {
            dir,
            read_only: false,
            key,
            _lock: Some(lock),
        })
    }

    /// Opens without creating anything: a shared lock when a writer has
    /// made the lock file, so a read never sees a half-finished call.
    fn open_read_only(dir: &str, key_file: Option<&str>) -> Result<State, Error> {
        let dir = PathBuf::from(dir);
        // No key file yet means nothing was ever sealed with it: read on
        // without one rather than fail.
        let key = key_file
            .filter(|k| Path::new(k).exists())
            .map(|k| load_key(k, &dir, false))
            .transpose()?;
        let lock = match File::open(dir.join("lock")) {
            Ok(f) => {
                f.lock_shared().map_err(state_error)?;
                Some(f)
            }
            Err(_) => None,
        };
        Ok(State {
            dir,
            read_only: true,
            key,
            _lock: lock,
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// A stored JSON file, unsealed if it was sealed. A sealed file without
    /// the right key reads as missing.
    fn read_json(&self, name: &str) -> Option<Value> {
        let bytes = fs::read(self.path(name)).ok()?;
        let value: Value = serde_json::from_slice(&bytes).ok()?;
        if value.get("sealed").is_none() {
            return Some(value);
        }
        use chacha20poly1305::aead::{Aead, KeyInit};
        let key = self.key.as_ref()?;
        let nonce = URL_SAFE_NO_PAD.decode(value["nonce"].as_str()?).ok()?;
        let data = URL_SAFE_NO_PAD.decode(value["data"].as_str()?).ok()?;
        if nonce.len() != 12 {
            return None;
        }
        let plain = chacha20poly1305::ChaCha20Poly1305::new(key)
            .decrypt(chacha20poly1305::Nonce::from_slice(&nonce), data.as_slice())
            .ok()?;
        serde_json::from_slice(&plain).ok()
    }

    /// Like [`read_json`](Self::read_json), but a file that exists and
    /// can't be read (sealed without the right key, damaged) is an error
    /// rather than missing, so it is never replaced by a fresh one.
    fn read_json_strict(&self, name: &str) -> Result<Option<Value>, Error> {
        if !self.path(name).exists() {
            return Ok(None);
        }
        self.read_json(name).map(Some).ok_or_else(|| {
            state_error(format!(
                "{name} can't be read: it is sealed with another key_file, or damaged"
            ))
        })
    }

    fn write_json(&self, name: &str, value: &Value) -> Result<(), Error> {
        if self.read_only {
            return Err(state_error("this command only reads the state directory"));
        }
        let bytes = serde_json::to_vec_pretty(value).map_err(state_error)?;
        let bytes = match &self.key {
            None => bytes,
            Some(key) => {
                use chacha20poly1305::aead::{Aead, KeyInit};
                let nonce: [u8; 12] = rand::random();
                let data = chacha20poly1305::ChaCha20Poly1305::new(key)
                    .encrypt(
                        chacha20poly1305::Nonce::from_slice(&nonce),
                        bytes.as_slice(),
                    )
                    .map_err(|_| state_error("sealing failed"))?;
                serde_json::to_vec(&json!({
                    "sealed": 1,
                    "nonce": URL_SAFE_NO_PAD.encode(nonce),
                    "data": URL_SAFE_NO_PAD.encode(data),
                }))
                .map_err(state_error)?
            }
        };
        write_private(&self.path(name), &bytes).map_err(state_error)
    }

    fn remove(&self, name: &str) {
        if !self.read_only {
            let _ = fs::remove_file(self.path(name));
        }
    }
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        if !dir.exists() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)?;
        }
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    {
        // Elsewhere the directory inherits the caller's profile ACLs.
        fs::create_dir_all(dir)
    }
}

/// Writes `bytes` to `path` readable by the owner only, replacing it
/// atomically.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut f = options.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

/// One identity's session in `sessions/{handle}.json`.
struct FileTokenStore {
    state: Arc<State>,
    name: String,
    values: Mutex<HashMap<String, String>>,
}

impl FileTokenStore {
    fn open(state: Arc<State>, name: String) -> Result<FileTokenStore, Error> {
        let values = state
            .read_json_strict(&name)?
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();
        Ok(FileTokenStore {
            state,
            name,
            values: Mutex::new(values),
        })
    }
}

impl TokenStore for FileTokenStore {
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
        if !self.state.read_only
            && let Ok(v) = serde_json::to_value(&*values)
        {
            let _ = self.state.write_json(&self.name, &v);
        }
        Box::pin(async {})
    }
}

// ───────────────────────────── Device ─────────────────────────────

/// The device key in `device.json`, made on first use, plus the statement
/// and token files. Statements and tokens are verified against `keys`
/// before they are stored.
struct FileDevice {
    state: Arc<State>,
    id: String,
    key: SigningKey,
    keys: Vec<(String, String)>,
    product: String,
    model: String,
    name: Option<String>,
    now: i64,
}

impl FileDevice {
    fn open(
        state: Arc<State>,
        keys: Vec<(String, String)>,
        product: String,
        model: String,
        name: Option<String>,
    ) -> Result<FileDevice, Error> {
        let (id, key) = match state.read_json_strict("device.json")? {
            Some(d) => {
                let id = d["id"].as_str().unwrap_or_default().to_string();
                let seed: [u8; 32] = d["seed"]
                    .as_str()
                    .and_then(|s| URL_SAFE_NO_PAD.decode(s).ok())
                    .and_then(|s| s.try_into().ok())
                    .ok_or_else(|| state_error("device.json has no usable key"))?;
                if id.is_empty() {
                    return Err(state_error("device.json has no device id"));
                }
                (id, SigningKey::from_bytes(&seed))
            }
            None if state.read_only => {
                return Err(Error::new(
                    None,
                    "not_activated",
                    "This state directory has no device key yet.",
                ));
            }
            None => {
                let seed: [u8; 32] = rand::random();
                let b: [u8; 16] = rand::random();
                let id = format!(
                    "{}-{}-{}-{}-{}",
                    hex(&b[0..4]),
                    hex(&b[4..6]),
                    hex(&b[6..8]),
                    hex(&b[8..10]),
                    hex(&b[10..16])
                );
                state.write_json(
                    "device.json",
                    &json!({"id": id, "seed": URL_SAFE_NO_PAD.encode(seed)}),
                )?;
                (id, SigningKey::from_bytes(&seed))
            }
        };
        Ok(FileDevice {
            state,
            id,
            key,
            keys,
            product,
            model,
            name,
            now: unix_now(),
        })
    }

    fn pubkey(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.key.verifying_key().to_bytes())
    }

    fn key_table(&self) -> Vec<(&str, &str)> {
        self.keys
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    }

    fn need_keys(&self) -> Result<(), String> {
        if self.keys.is_empty() {
            Err("no product keys given (input `keys`)".into())
        } else {
            Ok(())
        }
    }

    /// The stored Server statement, verified, and its feature token.
    fn server(&self) -> Option<(Value, String)> {
        let s = self.state.read_json("server.json")?;
        let licence = s["licence"].as_str()?;
        verify_licence(
            &self.key_table(),
            licence,
            &self.product,
            &self.id,
            &self.pubkey(),
        )
        .ok()?;
        Some((payload_of(licence)?, s["token"].as_str()?.to_string()))
    }

    /// The stored entitlement token, verified, and its payload.
    fn entitlement(&self) -> Option<(Value, String)> {
        let token = self.state.read_json("license.json")?["token"]
            .as_str()?
            .to_string();
        let payload =
            verify_entitlement(&self.key_table(), &token, &self.id, &self.pubkey()).ok()?;
        Some((payload, token))
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The JSON payload of a `base64url(payload).base64url(signature)` token.
fn payload_of(token: &str) -> Option<Value> {
    let (p, _) = token.trim().split_once('.')?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p).ok()?).ok()
}

/// Verifies an entitlement token (Ed25519 over the exact payload bytes,
/// signed by a key in `keys`) and that it was issued to this device.
fn verify_entitlement(
    keys: &[(&str, &str)],
    token: &str,
    device_id: &str,
    device_pubkey: &str,
) -> Result<Value, String> {
    let (p, s) = token.trim().split_once('.').ok_or("malformed token")?;
    let payload = URL_SAFE_NO_PAD
        .decode(p)
        .map_err(|_| "payload not base64url")?;
    let sig = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| "signature not base64url")?;
    let sig = Signature::from_slice(&sig).map_err(|_| "signature must be 64 bytes")?;
    let body: Value =
        serde_json::from_slice(&payload).map_err(|e| format!("invalid payload: {e}"))?;
    let kid = body["kid"].as_str().unwrap_or_default();
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
    VerifyingKey::from_bytes(&key)
        .map_err(|_| "product key is not a valid Ed25519 point")?
        .verify_strict(&payload, &sig)
        .map_err(|_| "signature verification failed")?;
    if body["device_id"] != device_id || body["device_pubkey"] != device_pubkey {
        return Err("token is for another device".into());
    }
    Ok(body)
}

impl DeviceSigner for FileDevice {
    fn identity(&self) -> Option<DeviceIdentity> {
        Some(DeviceIdentity {
            id: self.id.clone(),
            pubkey: self.pubkey(),
        })
    }

    fn sign(&self, method: &str, path: &str, ts: i64) -> Option<String> {
        let input = format!("{method}|{path}|{}|{ts}", self.id);
        Some(URL_SAFE_NO_PAD.encode(self.key.sign(input.as_bytes()).to_bytes()))
    }
}

impl ServerDevice for FileDevice {
    fn apply(&self, licence: &str, token: &str) -> Result<(), String> {
        self.need_keys()?;
        verify_licence(
            &self.key_table(),
            licence,
            &self.product,
            &self.id,
            &self.pubkey(),
        )?;
        self.state
            .write_json("server.json", &json!({"licence": licence, "token": token}))
            .map_err(|e| e.message)
    }

    fn clear(&self) {
        self.state.remove("server.json");
    }

    fn model(&self) -> String {
        self.model.clone()
    }

    fn name(&self) -> Option<String> {
        self.name.clone()
    }
}

impl LicenseDevice for FileDevice {
    fn apply_token(&self, token: &str) -> Result<(), String> {
        self.need_keys()?;
        verify_entitlement(&self.key_table(), token, &self.id, &self.pubkey())?;
        self.state
            .write_json("license.json", &json!({"token": token}))
            .map_err(|e| e.message)
    }

    fn clear_token(&self) {
        self.state.remove("license.json");
    }

    fn has_entitlement(&self) -> bool {
        self.entitlement()
            .is_some_and(|(p, _)| p["exp"].as_i64().is_none_or(|exp| self.now < exp))
    }

    fn model(&self) -> String {
        self.model.clone()
    }

    fn name(&self) -> Option<String> {
        self.name.clone()
    }
}

// ───────────────────────────── Commands ─────────────────────────────

struct Ctx {
    input: Map<String, Value>,
    transport: Arc<dyn Transport>,
    state: Option<Arc<State>>,
}

impl Ctx {
    fn open(
        input: Map<String, Value>,
        transport: Arc<dyn Transport>,
        read_only: bool,
    ) -> Result<Ctx, Error> {
        let key_file = input
            .get("key_file")
            .and_then(|v| v.as_str())
            .filter(|k| !k.is_empty());
        let state = match input.get("state_dir").and_then(|v| v.as_str()) {
            Some(d) if !d.is_empty() && read_only => {
                Some(Arc::new(State::open_read_only(d, key_file)?))
            }
            Some(d) if !d.is_empty() => Some(Arc::new(State::open(d, key_file)?)),
            _ => None,
        };
        Ok(Ctx {
            input,
            transport,
            state,
        })
    }

    fn opt(&self, k: &str) -> Option<String> {
        match self.input.get(k) {
            Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
            Some(Value::Number(n)) => Some(n.to_string()),
            _ => None,
        }
    }

    fn req(&self, k: &str) -> Result<String, Error> {
        self.opt(k)
            .ok_or_else(|| bad_input(format!("Missing input field `{k}`.")))
    }

    fn opt_i64(&self, k: &str) -> Result<Option<i64>, Error> {
        match self.input.get(k) {
            None | Some(Value::Null) => Ok(None),
            Some(v) => v
                .as_i64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
                .map(Some)
                .ok_or_else(|| bad_input(format!("`{k}` must be an integer."))),
        }
    }

    fn object(&self, k: &str) -> Result<Map<String, Value>, Error> {
        match self.input.get(k) {
            Some(Value::Object(m)) => Ok(m.clone()),
            None | Some(Value::Null) => Ok(Map::new()),
            _ => Err(bad_input(format!("`{k}` must be an object."))),
        }
    }

    fn state(&self) -> Result<Arc<State>, Error> {
        self.state
            .clone()
            .ok_or_else(|| bad_input("Missing input field `state_dir`."))
    }

    fn issuer(&self) -> Result<String, Error> {
        Ok(self.req("issuer")?.trim_end_matches('/').to_string())
    }

    fn keys(&self) -> Result<Vec<(String, String)>, Error> {
        match self.input.get("keys") {
            None | Some(Value::Null) => Ok(Vec::new()),
            Some(Value::Object(m)) => m
                .iter()
                .map(|(k, v)| {
                    v.as_str()
                        .map(|v| (k.clone(), v.to_string()))
                        .ok_or_else(|| bad_input("`keys` maps each kid to a base64url key."))
                })
                .collect(),
            _ => Err(bad_input("`keys` must be an object of kid → key.")),
        }
    }

    fn device(&self) -> Result<Arc<FileDevice>, Error> {
        let model = self
            .opt("model")
            .unwrap_or_else(|| format!("{} {}", std::env::consts::OS, std::env::consts::ARCH));
        Ok(Arc::new(FileDevice::open(
            self.state()?,
            self.keys()?,
            self.opt("product").unwrap_or_default(),
            model,
            self.opt("device_name"),
        )?))
    }

    /// The identity this call acts as: `session` (a handle the caller
    /// picks), else the session signed in as `sub`, else `default`.
    fn session(&self) -> Result<String, Error> {
        if let Some(h) = self.opt("session") {
            return Ok(file_safe(&h).replace('.', "_"));
        }
        let Some(sub) = self.opt("sub") else {
            return Ok("default".into());
        };
        self.sessions()?
            .into_iter()
            .find(|(_, u)| u.as_ref().is_some_and(|u| u.id == sub))
            .map(|(h, _)| h)
            .ok_or_else(|| {
                Error::new(
                    None,
                    "no_sign_in",
                    format!("No session is signed in as {sub}."),
                )
            })
    }

    /// Every stored session and who is signed in to it.
    fn sessions(&self) -> Result<Vec<(String, Option<MerosUser>)>, Error> {
        let state = self.state()?;
        let mut out = Vec::new();
        let Ok(entries) = fs::read_dir(state.path("sessions")) else {
            return Ok(out);
        };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let Some(handle) = name.strip_suffix(".json") else {
                continue;
            };
            if handle.contains('.') {
                continue; // a pending grant, not a session
            }
            let user = state.read_json(&format!("sessions/{name}")).and_then(|v| {
                let s = v.get("meros.user")?.as_str()?.to_string();
                v.get("meros.refresh_token")?;
                serde_json::from_str::<MerosUser>(&s).ok()
            });
            out.push((handle.to_string(), user));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    fn auth(&self) -> Result<Arc<MerosAuth>, Error> {
        let state = self.state()?;
        let handle = self.session()?;
        if !state.read_only {
            create_private_dir(&state.path("sessions")).map_err(state_error)?;
        }
        let scopes = match self.input.get("scopes") {
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(|s| s.as_str().map(str::to_string))
                .collect(),
            Some(Value::String(s)) => s.split_whitespace().map(str::to_string).collect(),
            _ => Vec::new(),
        };
        let config = AuthConfig {
            issuer: self.issuer()?,
            client_id: self.opt("client_id").unwrap_or_default(),
            redirect_uri: String::new(),
            scopes,
        };
        let store = Arc::new(FileTokenStore::open(
            state.clone(),
            format!("sessions/{handle}.json"),
        )?);
        Ok(Arc::new(
            MerosAuth::new(config, self.transport.clone(), store).keep_access_token(),
        ))
    }

    /// The signed-in session, or `no_sign_in`.
    async fn signed_in(&self) -> Result<Arc<MerosAuth>, Error> {
        let auth = self.auth()?;
        auth.load().await;
        if !auth.signed_in() {
            return Err(Error::new(
                None,
                "no_sign_in",
                "Not signed in. Run signin.start, then signin.poll.",
            ));
        }
        Ok(auth)
    }

    fn server_client(&self, device: Arc<FileDevice>) -> Result<ServerLicenseClient, Error> {
        Ok(ServerLicenseClient::new(
            ServerConfig {
                base_url: self.issuer()?,
                product: self.req("product")?,
                app_name: self.opt("app_name").unwrap_or_else(|| "App".into()),
                app_version: self.opt("app_version").unwrap_or_default(),
            },
            self.transport.clone(),
            device,
        ))
    }

    /// The product's device base: `device_base_url`, else
    /// `{issuer}/app/{product}`, where Meros serves device licensing and
    /// device-signed support.
    fn device_base(&self) -> Result<String, Error> {
        Ok(match self.opt("device_base_url") {
            Some(b) => b.trim_end_matches('/').to_string(),
            None => format!("{}/app/{}", self.issuer()?, self.req("product")?),
        })
    }

    fn license_client(&self, device: Arc<FileDevice>) -> Result<LicenseClient, Error> {
        let base = self.device_base()?;
        Ok(LicenseClient::new(
            LicenseConfig {
                base_url: base,
                app_name: self.opt("app_name").unwrap_or_else(|| "App".into()),
                app_version: self.opt("app_version").unwrap_or_default(),
            },
            self.transport.clone(),
            device,
        ))
    }

    async fn cloud(&self) -> Result<MerosCloud, Error> {
        let auth = self.signed_in().await?;
        Ok(MerosCloud::new(
            self.issuer()?,
            self.transport.clone(),
            auth,
        ))
    }

    async fn dispatch(&self, command: &str) -> Result<Value, Error> {
        match command {
            "device.identity" => {
                let d = self.device()?;
                Ok(json!({"device_id": d.id, "pubkey": d.pubkey()}))
            }
            c if c.starts_with("signin.") => self.signin(&c[7..]).await,
            c if c.starts_with("server.") => self.server(&c[7..]).await,
            c if c.starts_with("license.") => self.license(&c[8..]).await,
            c if c.starts_with("cloud.") => self.cloud_command(&c[6..]).await,
            c if c.starts_with("support.") => self.support(&c[8..]).await,
            c if c.starts_with("events.") => self.events(&c[7..]).await,
            _ => unreachable!("checked against COMMANDS"),
        }
    }

    // ── Sign in with Meros (device grant) ──

    async fn signin(&self, op: &str) -> Result<Value, Error> {
        let state = self.state()?;
        let pending = format!("sessions/{}.signin.json", self.session()?);
        let pending = pending.as_str();
        match op {
            "start" => {
                let auth = self.auth()?;
                let acr = self.opt("acr_values");
                let s = auth.begin_device_sign_in_with(acr.as_deref()).await?;
                state.write_json(
                    pending,
                    &json!({
                        "acr_values": acr,
                        "device_code": s.device_code,
                        "user_code": s.user_code,
                        "verification_uri": s.verification_uri,
                        "verification_uri_complete": s.verification_uri_complete,
                        "interval": s.interval,
                        "expires_at": s.expires_at,
                    }),
                )?;
                Ok(json!({
                    "user_code": s.user_code,
                    "verification_uri": s.verification_uri,
                    "verification_uri_complete": s.verification_uri_complete,
                    "interval": s.interval,
                    "expires_at": s.expires_at,
                }))
            }
            "poll" => {
                let p = state.read_json(pending).ok_or_else(|| {
                    Error::new(None, "no_sign_in", "No sign-in started. Run signin.start.")
                })?;
                let text = |k: &str| p[k].as_str().unwrap_or_default().to_string();
                let mut s = DeviceSignIn {
                    device_code: text("device_code"),
                    user_code: text("user_code"),
                    verification_uri: text("verification_uri"),
                    verification_uri_complete: p["verification_uri_complete"]
                        .as_str()
                        .map(str::to_string),
                    interval: p["interval"].as_u64().unwrap_or(5),
                    expires_at: p["expires_at"].as_i64().unwrap_or(0),
                };
                let auth = self.auth()?;
                match auth.poll_device_sign_in(&mut s).await {
                    Ok(None) => {
                        let mut kept = p.clone();
                        kept["interval"] = json!(s.interval);
                        state.write_json(pending, &kept)?;
                        Ok(json!({"status": "pending", "interval": s.interval}))
                    }
                    Ok(Some(user)) => {
                        state.remove(pending);
                        let mut out = json!({"status": "signed_in", "user": user_json(&user)});
                        if !p["acr_values"].is_null() {
                            out["acr_values"] = p["acr_values"].clone();
                        }
                        Ok(out)
                    }
                    Err(e) => {
                        if e.code == "expired_token" || e.code == "access_denied" {
                            state.remove(pending);
                        }
                        Err(e)
                    }
                }
            }
            "status" => {
                let auth = self.auth()?;
                auth.load().await;
                Ok(match auth.user() {
                    Some(u) => json!({"signed_in": true, "user": user_json(&u)}),
                    None => json!({"signed_in": false}),
                })
            }
            "token" => {
                let auth = self.signed_in().await?;
                let force = self.input.get("force").and_then(|v| v.as_bool()) == Some(true);
                Ok(json!({"access_token": auth.access_token(force).await?}))
            }
            "signout" => {
                let auth = self.auth()?;
                let revoked = auth.sign_out().await;
                state.remove(pending);
                let prefix = format!("{}-", self.session()?);
                if let Ok(entries) = fs::read_dir(state.path("cache")) {
                    for e in entries.flatten() {
                        if e.file_name().to_string_lossy().starts_with(&prefix) {
                            let _ = fs::remove_file(e.path());
                        }
                    }
                }
                Ok(json!({"revoked": revoked}))
            }
            "list" => Ok(
                json!({"sessions": self.sessions()?.into_iter().map(|(h, u)| json!({
                "session": h,
                "signed_in": u.is_some(),
                "user": u.as_ref().map(user_json),
            })).collect::<Vec<_>>()}),
            ),
            "cancel" => {
                state.remove(pending);
                Ok(json!({}))
            }
            "redeem.begin" => {
                let r = self.auth()?.begin_login_token_sign_in().await;
                Ok(json!({
                    "request_id": r.request_id,
                    "code_challenge": r.code_challenge,
                    "code_challenge_method": "S256",
                    "nonce": r.nonce,
                    "expires_at": r.expires_at,
                }))
            }
            "redeem.complete" => {
                let (user, replaced) = self
                    .auth()?
                    .complete_login_token_sign_in(
                        &self.req("request_id")?,
                        &self.req("login_token")?,
                    )
                    .await?;
                Ok(json!({"user": user_json(&user), "replaced_previous": replaced}))
            }
            "login_token" => {
                let cloud = self.cloud().await?;
                cloud
                    .login_token(
                        &self.req("audience")?,
                        self.opt("code_challenge").as_deref(),
                        self.opt("nonce").as_deref(),
                        self.opt("acr_values").as_deref(),
                    )
                    .await
            }
            _ => unreachable!(),
        }
    }

    // ── Server licenses ──

    async fn server(&self, op: &str) -> Result<Value, Error> {
        let device = match self.device() {
            Err(e) if e.code == "not_activated" && op == "status" => {
                return Ok(json!({"active": false}));
            }
            other => other?,
        };
        let activated = |device: &FileDevice| -> Result<Value, Error> {
            let (licence, token) = device.server().ok_or_else(|| {
                Error::new(
                    None,
                    "verify_failed",
                    "The stored statement doesn't verify.",
                )
            })?;
            Ok(json!({"licence": licence, "token": token}))
        };
        match op {
            "activate" => {
                let key = self.req("license_key")?;
                self.server_client(device.clone())?
                    .activate(&key, self.opt("device_name").as_deref())
                    .await?;
                activated(&device)
            }
            "activate_login" => {
                let auth = self.signed_in().await?;
                self.server_client(device.clone())?
                    .activate_with_login(
                        auth.as_ref(),
                        self.opt("account_id").as_deref(),
                        self.opt("device_name").as_deref(),
                    )
                    .await?;
                activated(&device)
            }
            "renew" => {
                let info = self.object("device_info")?;
                let r = self.server_client(device.clone())?.renew(info).await;
                Ok(match r {
                    ServerRenewal::Renewed => {
                        let mut out = activated(&device)?;
                        out["result"] = json!("renewed");
                        out
                    }
                    ServerRenewal::Revoked => json!({"result": "revoked"}),
                    ServerRenewal::Suspended(e) => {
                        json!({"result": "suspended", "error": failure(e).output["error"]})
                    }
                    ServerRenewal::Kept(e) => {
                        json!({"result": "kept", "error": failure(e).output["error"]})
                    }
                })
            }
            "release" => {
                self.server_client(device)?.release().await?;
                Ok(json!({}))
            }
            "status" => {
                let Some((licence, token)) = device.server() else {
                    return Ok(json!({"active": false}));
                };
                let mut out = json!({"active": true, "licence": licence, "token": token});
                if let Some(build) = self.opt("build_date") {
                    let until = licence["updates_until"].as_str().unwrap_or_default();
                    out["covers_build"] = json!(build.as_str() <= until);
                }
                Ok(out)
            }
            "verify" => {
                let statement = self.req("statement")?;
                let device_id = self.opt("device_id").unwrap_or_else(|| device.id.clone());
                let pubkey = self.opt("device_pubkey").unwrap_or_else(|| device.pubkey());
                verify_licence(
                    &device.key_table(),
                    &statement,
                    &self.req("product")?,
                    &device_id,
                    &pubkey,
                )
                .map_err(|e| Error::new(None, "verify_failed", e))?;
                Ok(json!({"licence": payload_of(&statement)}))
            }
            _ => unreachable!(),
        }
    }

    // ── Device licenses ──

    async fn license(&self, op: &str) -> Result<Value, Error> {
        let device = match self.device() {
            Err(e) if e.code == "not_activated" && op == "status" => {
                return Ok(json!({"active": false}));
            }
            other => other?,
        };
        let entitled = |device: &FileDevice| -> Result<Value, Error> {
            let (payload, token) = device.entitlement().ok_or_else(|| {
                Error::new(None, "verify_failed", "The stored token doesn't verify.")
            })?;
            Ok(json!({"entitlement": payload, "token": token}))
        };
        let client = self.license_client(device.clone())?;
        match op {
            "activate" => {
                client
                    .activate(
                        &self.req("license_key")?,
                        self.opt("device_name").as_deref(),
                    )
                    .await?;
                entitled(&device)
            }
            "renew" => {
                let renewed = client.renew(self.object("device_info")?).await;
                let mut out = json!({"renewed": renewed});
                if let Some((payload, token)) = device.entitlement() {
                    out["entitlement"] = payload;
                    out["token"] = json!(token);
                }
                Ok(out)
            }
            "release" => {
                client.release().await?;
                Ok(json!({}))
            }
            "status" => Ok(match device.entitlement() {
                Some((payload, token)) => {
                    let valid = payload["exp"].as_i64().is_none_or(|exp| unix_now() < exp);
                    json!({"active": true, "valid": valid, "entitlement": payload, "token": token})
                }
                None => json!({"active": false}),
            }),
            "offline_request" => Ok(json!({
                "blob": client.offline_request_blob(
                    &self.req("license_key")?,
                    self.opt("device_name").as_deref(),
                )?
            })),
            "offline_import" => {
                client.import_offline_token(&self.req("blob")?)?;
                entitled(&device)
            }
            "manage_url" => Ok(json!({"url": client.manage_url()?})),
            "claim" => {
                let auth = self.signed_in().await?;
                client
                    .claim_with_account(auth.as_ref(), self.opt("device_name").as_deref())
                    .await?;
                entitled(&device)
            }
            "adopt" => {
                let auth = self.signed_in().await?;
                let r = client
                    .adopt_after_sign_in(auth.as_ref(), self.opt("device_name").as_deref())
                    .await?;
                Ok(json!({"result": match r {
                    SignInClaim::Claimed => "claimed",
                    SignInClaim::KeptCurrent => "kept_current",
                    SignInClaim::NotLicensed => "not_licensed",
                }}))
            }
            "seats" => {
                let auth = self.signed_in().await?;
                let seats = client.seats(auth.as_ref()).await?;
                Ok(json!({"seats": seats.iter().map(|s| json!({
                    "seat_id": s.seat_id,
                    "device_id": s.device_id,
                    "name": s.name,
                    "model": s.model,
                    "activated_at": s.activated_at,
                    "last_seen_at": s.last_seen_at,
                    "account_id": s.account_id,
                    "account_name": s.account_name,
                    "account_type": s.account_type,
                    "can_release": s.can_release,
                })).collect::<Vec<_>>()}))
            }
            "release_seat" => {
                let auth = self.signed_in().await?;
                let seat = self
                    .opt_i64("seat_id")?
                    .ok_or_else(|| bad_input("Missing input field `seat_id`."))?;
                client.release_seat(auth.as_ref(), seat).await?;
                Ok(json!({}))
            }
            _ => unreachable!(),
        }
    }

    // ── Meros Cloud ──

    async fn cloud_command(&self, op: &str) -> Result<Value, Error> {
        if op == "feed" || op == "feed_versions" {
            return self.feed(op).await;
        }
        let cloud = self.cloud().await?;
        let account = self.opt("account_id");
        let account = account.as_deref();
        match op {
            "accounts" => Ok(
                json!({"accounts": cloud.accounts().await?.iter().map(|a| json!({
                "id": a.id, "name": a.name, "team": a.team, "role": a.role, "is_default": a.is_default,
            })).collect::<Vec<_>>()}),
            ),
            "entitlements" => {
                let product = self.req("product")?;
                let state = self.state()?;
                let cache = format!(
                    "cache/{}-entitlements-{}-{}.json",
                    self.session()?,
                    file_safe(&product),
                    file_safe(account.unwrap_or("default"))
                );
                let (answer, cached) = match cloud.entitlements(&product, account).await {
                    Ok(raw) => {
                        let features: Vec<String> = raw["features"]
                            .as_object()
                            .map(|f| {
                                f.iter()
                                    .filter(|(_, v)| v.as_bool() == Some(true))
                                    .map(|(k, _)| k.clone())
                                    .collect()
                            })
                            .unwrap_or_default();
                        // The soonest expiry across the product's entitlements.
                        let expires_at = raw["entitlements"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .filter_map(|e| e["expires_at"].as_str())
                            .filter_map(|t| parse_rfc3339(t).map(|u| (u, t.to_string())))
                            .min()
                            .map(|(_, t)| t);
                        let answer = json!({
                            "account_id": raw["account_id"],
                            "features": features,
                            "tier": raw.pointer("/features/tier").and_then(|t| t.as_str()).unwrap_or("free"),
                            "expires_at": expires_at,
                            "fetched_at": unix_now(),
                        });
                        create_private_dir(&state.path("cache")).map_err(state_error)?;
                        state.write_json(&cache, &answer)?;
                        (answer, false)
                    }
                    // Offline, the last answer stands, within its grace.
                    Err(e) if e.offline() => match state.read_json(&cache) {
                        Some(answer) => (answer, true),
                        None => return Err(e),
                    },
                    Err(e) => return Err(e),
                };
                let now = unix_now();
                let expiry = answer["expires_at"].as_str().and_then(parse_rfc3339);
                let in_grace = expiry.is_some_and(|x| now > x && now < x + ENTITLEMENT_GRACE_SECS);
                let lapsed = expiry.is_some_and(|x| now >= x + ENTITLEMENT_GRACE_SECS);
                let mut out = answer.clone();
                out["held"] = if lapsed {
                    json!([])
                } else {
                    answer["features"].clone()
                };
                out["in_grace"] = json!(in_grace);
                out["lapsed"] = json!(lapsed);
                out["cached"] = json!(cached);
                Ok(out)
            }
            "inventory.get" => cloud.inventory(&self.req("product")?, account).await,
            "inventory.put" => {
                let devices = match self.input.get("devices") {
                    Some(Value::Array(a)) => a.clone(),
                    _ => return Err(bad_input("`devices` must be an array.")),
                };
                cloud
                    .put_inventory(&self.req("product")?, devices, account)
                    .await
            }
            "profile.get" => {
                let p = cloud.profile(&self.req("namespace")?).await?;
                Ok(json!({"keys": p.keys, "updated": p.updated}))
            }
            "profile.put" => {
                let p = cloud
                    .put_profile(&self.req("namespace")?, self.object("keys")?)
                    .await?;
                Ok(json!({"keys": p.keys, "updated": p.updated}))
            }
            "profile.delete" => {
                cloud.delete_profile(&self.req("namespace")?).await?;
                Ok(json!({}))
            }
            "docs.list" => {
                let docs = cloud
                    .list_docs(&self.req("product")?, &self.req("collection")?, account)
                    .await?;
                Ok(json!({"docs": docs.iter().map(|d| json!({
                    "key": d.key, "head_version": d.head_version, "updated": d.updated,
                })).collect::<Vec<_>>()}))
            }
            "docs.get" => {
                let d = cloud
                    .get_doc(
                        &self.req("product")?,
                        &self.req("collection")?,
                        &self.req("key")?,
                        self.opt_i64("version")?,
                        account,
                    )
                    .await?;
                let hash = crate::content_hash(&Value::Object(d.body.clone()));
                Ok(json!({
                    "key": d.key, "version": d.version, "head_version": d.head_version,
                    "body": d.body, "content_hash": hash,
                }))
            }
            "docs.put" => {
                let body = self.object("body")?;
                let hash = crate::content_hash(&Value::Object(body.clone()));
                match cloud
                    .put_doc(
                        &self.req("product")?,
                        &self.req("collection")?,
                        &self.req("key")?,
                        body,
                        self.opt_i64("base_version")?,
                        account,
                    )
                    .await
                {
                    Ok(version) => {
                        Ok(json!({"version": version, "content_hash": hash, "unchanged": false}))
                    }
                    // The head moved, but to exactly this content: already
                    // current, and nothing for anyone to resolve.
                    Err(e)
                        if e.code == "version_conflict"
                            && e.head.as_ref().and_then(|h| h.content_hash.as_deref())
                                == Some(hash.as_str()) =>
                    {
                        Ok(
                            json!({"version": e.head_version, "content_hash": hash, "unchanged": true}),
                        )
                    }
                    Err(e) => Err(e),
                }
            }
            "docs.delete" => {
                cloud
                    .delete_doc(
                        &self.req("product")?,
                        &self.req("collection")?,
                        &self.req("key")?,
                        account,
                    )
                    .await?;
                Ok(json!({}))
            }
            "docs.versions" => {
                let v = cloud
                    .doc_versions(
                        &self.req("product")?,
                        &self.req("collection")?,
                        &self.req("key")?,
                        account,
                    )
                    .await?;
                Ok(json!({"versions": v.iter().map(|v| json!({
                    "version": v.version, "created": v.created, "size_bytes": v.size_bytes,
                })).collect::<Vec<_>>()}))
            }
            "files.list" => {
                let files = cloud
                    .list_files(&self.req("product")?, &self.req("collection")?, account)
                    .await?;
                Ok(json!({"files": files.iter().map(file_json).collect::<Vec<_>>()}))
            }
            "files.put" => {
                let bytes = match (self.opt("content_base64"), self.opt("path")) {
                    (Some(b), _) => STANDARD
                        .decode(b.as_bytes())
                        .map_err(|_| bad_input("`content_base64` is not base64."))?,
                    (None, Some(p)) => {
                        fs::read(&p).map_err(|e| bad_input(format!("Can't read `path`: {e}")))?
                    }
                    (None, None) => {
                        return Err(bad_input("Give `content_base64` or `path`."));
                    }
                };
                let f = cloud
                    .put_file(
                        &self.req("product")?,
                        &self.req("collection")?,
                        &bytes,
                        account,
                    )
                    .await?;
                Ok(json!({"file": file_json(&f)}))
            }
            "files.get" => {
                let (product, collection, sha) = (
                    self.req("product")?,
                    self.req("collection")?,
                    self.req("sha256")?,
                );
                let bytes = cloud
                    .download_file(&product, &collection, &sha, account)
                    .await?;
                match self.opt("path") {
                    Some(p) => {
                        fs::write(&p, &bytes)
                            .map_err(|e| bad_input(format!("Can't write `path`: {e}")))?;
                        Ok(json!({"sha256": sha, "size": bytes.len(), "path": p}))
                    }
                    None => Ok(json!({
                        "sha256": sha, "size": bytes.len(), "content_base64": STANDARD.encode(&bytes),
                    })),
                }
            }
            "files.delete" => {
                cloud
                    .delete_file(
                        &self.req("product")?,
                        &self.req("collection")?,
                        &self.req("sha256")?,
                        account,
                    )
                    .await?;
                Ok(json!({}))
            }
            _ => unreachable!(),
        }
    }

    // ── Signed data packs ──

    /// A pack verified against `keys`, cached with its `ETag`: a current
    /// cached copy answers `304`, and offline the cached copy stands.
    async fn feed(&self, op: &str) -> Result<Value, Error> {
        let (product, pack) = (self.req("product")?, self.req("pack")?);
        let cache_only = self.input.get("cache_only").and_then(|v| v.as_bool()) == Some(true);
        if cache_only && op == "feed" {
            return self.cached_feed(&product, &pack);
        }
        let issuer = self.issuer()?;
        let account = self.opt("account_id");
        let auth = match &self.state {
            Some(_) => {
                let a = self.auth()?;
                a.load().await;
                a.signed_in().then_some(a)
            }
            None => None,
        };
        let token = auth.map(|a| a as Arc<dyn AccessTokenSource>);
        let feeds = MerosFeeds::new(issuer, self.transport.clone(), token);
        if op == "feed_versions" {
            return feeds.versions(&product, &pack, account.as_deref()).await;
        }
        let keys = self.keys()?;
        let table: Vec<(&str, &str)> = keys.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        if table.is_empty() {
            return Err(bad_input("Give the product's `keys` to verify packs."));
        }
        let version = self.opt_i64("version")?;
        let state = self.state()?;
        let cache = format!(
            "cache/feed-{}-{}.json",
            file_safe(&product),
            file_safe(&pack)
        );
        // Only the latest version is cached.
        let cached = if version.is_none() {
            state.read_json(&cache)
        } else {
            None
        };
        let answer = |c: &Value, from_cache: bool| -> Result<Value, Error> {
            let signed = c["signed"].as_str().unwrap_or_default();
            let signature = c["signature"].as_str().unwrap_or_default();
            let (header, payload) = verify_pack(&table, signed, signature)
                .map_err(|e| Error::new(None, "verify_failed", format!("Pack: {e}")))?;
            Ok(json!({
                "product": header["product"], "pack": header["pack"],
                "version": header["version"], "kid": header["kid"],
                "issued_at": header["issued_at"], "payload": payload,
                "from_cache": from_cache, "fetched_at": c["fetched_at"],
            }))
        };
        let etag = cached
            .as_ref()
            .and_then(|c| c["etag"].as_str())
            .map(str::to_string);
        match feeds
            .fetch(
                &product,
                &pack,
                version,
                etag.as_deref(),
                account.as_deref(),
            )
            .await
        {
            Ok(FeedResponse::NotModified) => match &cached {
                Some(c) => answer(c, true),
                None => Err(Error::new(
                    Some(304),
                    "bad_response",
                    "Not modified, but nothing cached.",
                )),
            },
            Ok(FeedResponse::Pack(p, etag)) => {
                let c = json!({
                    "signed": p.signed, "signature": p.signature, "etag": etag,
                    "fetched_at": unix_now(),
                });
                let out = answer(&c, false)?;
                if version.is_none() {
                    create_private_dir(&state.path("cache")).map_err(state_error)?;
                    state.write_json(&cache, &c)?;
                }
                Ok(out)
            }
            Err(e) if e.offline() => match &cached {
                Some(c) => answer(c, true),
                None => Err(e),
            },
            Err(e) => Err(e),
        }
    }

    /// The cached latest pack, verified, with no network at all; exit 4
    /// `not_cached` when there is none.
    fn cached_feed(&self, product: &str, pack: &str) -> Result<Value, Error> {
        let keys = self.keys()?;
        let table: Vec<(&str, &str)> = keys.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        if table.is_empty() {
            return Err(bad_input("Give the product's `keys` to verify packs."));
        }
        let state = self.state()?;
        let cache = format!("cache/feed-{}-{}.json", file_safe(product), file_safe(pack));
        let c = state.read_json(&cache).ok_or_else(|| {
            Error::new(
                None,
                "not_cached",
                format!("No copy of {product}/{pack} is cached."),
            )
        })?;
        let (header, payload) = verify_pack(
            &table,
            c["signed"].as_str().unwrap_or_default(),
            c["signature"].as_str().unwrap_or_default(),
        )
        .map_err(|e| Error::new(None, "verify_failed", format!("Pack: {e}")))?;
        Ok(json!({
            "product": header["product"], "pack": header["pack"],
            "version": header["version"], "kid": header["kid"],
            "issued_at": header["issued_at"], "payload": payload,
            "from_cache": true, "fetched_at": c["fetched_at"],
        }))
    }

    // ── Support ──

    async fn support(&self, op: &str) -> Result<Value, Error> {
        enum Api {
            Device(SupportApi),
            Account(AccountSupportApi),
        }
        let api = match self.opt("via").as_deref().unwrap_or("device") {
            "device" => {
                let device = self.device()?;
                let base = self.device_base()?;
                Api::Device(SupportApi::new(
                    base,
                    self.opt("app_version").unwrap_or_default(),
                    self.transport.clone(),
                    device,
                ))
            }
            "account" => {
                let auth: Arc<dyn AccessTokenSource> = self.signed_in().await?;
                Api::Account(AccountSupportApi::new(
                    self.issuer()?,
                    self.req("product")?,
                    self.transport.clone(),
                    auth,
                ))
            }
            other => {
                return Err(bad_input(format!(
                    "`via` is `device` or `account`, not `{other}`."
                )));
            }
        };
        match op {
            "create" => {
                let (subject, message) = (self.req("subject")?, self.req("message")?);
                let diag = self.opt("diagnostics");
                let t = match &api {
                    Api::Device(a) => a.create(&subject, &message, diag.as_deref()).await?,
                    Api::Account(a) => a.create(&subject, &message, diag.as_deref()).await?,
                };
                Ok(json!({"ticket": ticket_json(&t)}))
            }
            "list" => {
                let t = match &api {
                    Api::Device(a) => a.list().await?,
                    Api::Account(a) => a.list().await?,
                };
                Ok(json!({"tickets": t.iter().map(ticket_json).collect::<Vec<_>>()}))
            }
            "thread" => {
                let id = self.req("ticket_id")?;
                let t = match &api {
                    Api::Device(a) => a.thread(&id).await?,
                    Api::Account(a) => a.thread(&id).await?,
                };
                Ok(thread_json(&t))
            }
            "reply" => {
                let (id, message) = (self.req("ticket_id")?, self.req("message")?);
                let t = match &api {
                    Api::Device(a) => a.reply(&id, &message).await?,
                    Api::Account(a) => a.reply(&id, &message).await?,
                };
                Ok(json!({"ticket": ticket_json(&t)}))
            }
            _ => unreachable!(),
        }
    }

    // ── Events ──

    async fn events(&self, op: &str) -> Result<Value, Error> {
        let state = self.state()?;
        let outbox = state.path("events").join("outbox.json");
        if op == "clear" {
            // Drops what's waiting without sending it: nothing leaves.
            let waiting = fs::read(&outbox)
                .ok()
                .and_then(|b| serde_json::from_slice::<Vec<Value>>(&b).ok())
                .map_or(0, |v| v.len());
            if outbox.exists() {
                write_private(&outbox, b"[]").map_err(state_error)?;
            }
            return Ok(json!({"cleared": waiting, "pending": 0}));
        }
        let collectors = self.collectors().await?;
        let emitter = Emitter::open(
            EmitterConfig {
                dir: state.path("events"),
                product: self.req("product")?,
                version: self.opt("app_version").unwrap_or_default(),
                edition: self.opt("edition"),
                site: self.opt("site"),
            },
            collectors,
            self.transport.clone(),
        )
        .map_err(state_error)?;
        let kept: Vec<Envelope> = fs::read(&outbox)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        emitter.requeue(kept);
        if op == "relay" {
            let events = match self.input.get("events") {
                Some(Value::Array(a)) => a.clone(),
                _ => return Err(bad_input("`events` must be an array of envelopes.")),
            };
            for (i, e) in events.into_iter().enumerate() {
                let envelope: Envelope = serde_json::from_value(e).map_err(|err| {
                    bad_input(format!("events[{i}] is not an Envelope v1 event: {err}"))
                })?;
                emitter
                    .relay(envelope)
                    .map_err(|err| bad_input(format!("events[{i}]: {err}")))?;
            }
        }
        if op == "send" {
            let events = match self.input.get("events") {
                Some(Value::Array(a)) => a.clone(),
                _ => return Err(bad_input("`events` must be an array.")),
            };
            for e in &events {
                emitter.emit(event_from(e)?);
            }
        }
        let flush =
            op == "flush" || self.input.get("flush").and_then(|v| v.as_bool()) != Some(false);
        let report = if flush {
            Some(emitter.flush().await)
        } else {
            None
        };
        let left = emitter.pending_events();
        let bytes = serde_json::to_vec(&left).map_err(state_error)?;
        write_private(&outbox, &bytes).map_err(state_error)?;
        let mut out = json!({"instance": emitter.instance(), "pending": left.len()});
        if let Some(r) = report {
            out["delivered"] = json!(r.delivered);
            out["accepted"] = json!(r.accepted);
            out["duplicates"] = json!(r.duplicates);
            out["rejected"] = json!(r.rejected);
            out["failed"] = json!(r.failed);
        }
        Ok(out)
    }

    /// `collectors`: `[{"url": ..., "auth": "signin" | "none"}]`; default
    /// the issuer with the signed-in session.
    async fn collectors(&self) -> Result<Vec<Collector>, Error> {
        let list = match self.input.get("collectors") {
            Some(Value::Array(a)) => a.clone(),
            None | Some(Value::Null) => vec![json!({"url": self.issuer()?, "auth": "signin"})],
            _ => return Err(bad_input("`collectors` must be an array.")),
        };
        let mut out = Vec::new();
        for c in list {
            let url = c["url"]
                .as_str()
                .ok_or_else(|| bad_input("Each collector needs a `url`."))?
                .to_string();
            let token: Option<Arc<dyn AccessTokenSource>> =
                match c["auth"].as_str().unwrap_or("signin") {
                    "signin" => Some(self.signed_in().await?),
                    "none" => None,
                    other => {
                        return Err(bad_input(format!(
                            "Collector `auth` is `signin` or `none`, not `{other}`."
                        )));
                    }
                };
            out.push(Collector { url, token });
        }
        Ok(out)
    }
}

/// How long a cached entitlement is honored offline after it expires.
pub const ENTITLEMENT_GRACE_SECS: i64 = 30 * 86_400;

/// Unix seconds of an RFC 3339 time (`2026-10-30T12:00:00Z`, fractions and
/// offsets allowed).
fn parse_rfc3339(t: &str) -> Option<i64> {
    let b = t.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    let n = |r: std::ops::Range<usize>| t.get(r)?.parse::<i64>().ok();
    let (y, mo, d) = (n(0..4)?, n(5..7)?, n(8..10)?);
    let (h, mi, s) = (n(11..13)?, n(14..16)?, n(17..19)?);
    let mut rest = &t[19..];
    if let Some(r) = rest.strip_prefix('.') {
        rest = r.trim_start_matches(|c: char| c.is_ascii_digit());
    }
    let offset = match rest {
        "Z" | "z" | "" => 0,
        o if o.len() == 6 && (o.starts_with('+') || o.starts_with('-')) => {
            let sign = if o.starts_with('-') { -1 } else { 1 };
            sign * (o[1..3].parse::<i64>().ok()? * 3600 + o[4..6].parse::<i64>().ok()? * 60)
        }
        _ => return None,
    };
    // Days from the civil date (Howard Hinnant's algorithm).
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + s - offset)
}

/// `s` as a file-name part: anything but letters, digits, `.`, `_` and `-`
/// becomes `_`.
fn file_safe(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_start_matches('.')
        .to_string()
}

fn user_json(u: &MerosUser) -> Value {
    json!({"id": u.id, "name": u.name, "email": u.email})
}

fn file_json(f: &crate::MerosFile) -> Value {
    json!({
        "sha256": f.sha256, "size": f.size, "status": f.status,
        "created": f.created, "download_url": f.download_url,
    })
}

fn ticket_json(t: &SupportTicket) -> Value {
    let status = match t.status {
        crate::support::TicketStatus::Open => "open",
        crate::support::TicketStatus::Pending => "pending",
        crate::support::TicketStatus::Closed => "closed",
    };
    json!({
        "id": t.id, "subject": t.subject, "status": status,
        "created_at": t.created_at, "last_message_at": t.last_message_at,
    })
}

fn thread_json(t: &SupportThread) -> Value {
    json!({
        "ticket": ticket_json(&t.ticket),
        "messages": t.messages.iter().map(|m| json!({
            "author": if m.from_support { "support" } else { "you" },
            "body": m.body,
            "at": m.at,
        })).collect::<Vec<_>>(),
    })
}

fn event_from(e: &Value) -> Result<Event, Error> {
    let kind = e["type"]
        .as_str()
        .ok_or_else(|| bad_input("Each event needs a `type`."))?;
    let severity: Severity = serde_json::from_value(
        e.get("severity").cloned().unwrap_or(json!("info")),
    )
    .map_err(|_| bad_input("`severity` is debug, info, notice, warning, error or critical."))?;
    let mut event = Event::new(kind, severity);
    if let Some(s) = e.get("subject").filter(|v| !v.is_null()) {
        event.subject = Some(
            serde_json::from_value::<Subject>(s.clone())
                .map_err(|_| bad_input("`subject` needs `kind` and `id`."))?,
        );
    }
    if let Some(a) = e.get("actor").filter(|v| !v.is_null()) {
        event.actor = Some(
            serde_json::from_value::<Actor>(a.clone())
                .map_err(|_| bad_input("`actor` needs `kind`."))?,
        );
    }
    if let Some(Value::Object(attrs)) = e.get("attrs") {
        event.attrs = attrs.clone();
    }
    event.trace = e["trace"].as_str().map(str::to_string);
    if let Some(t) = e.get("occurred_at").filter(|v| !v.is_null()) {
        let t = t
            .as_str()
            .filter(|t| parse_rfc3339(t).is_some())
            .ok_or_else(|| bad_input("`occurred_at` must be an RFC 3339 time."))?;
        event.occurred_at = Some(t.to_string());
    }
    Ok(event)
}
