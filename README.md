# meros-client

Rust clients for the Meros services, so every app shares one
implementation whatever its language. Desktop apps use the crate directly.
Flutter apps call it from their Rust core through flutter_rust_bridge.

| Module | What it does |
|---|---|
| `license` | The device license API: activate with a key, renew, release, claim a seat by signing in (with TOTP), claim and list or release seats with the app's own sign-in, adopt an unowned license (guest or App Store purchase) into the account after sign-in (`adopt_after_sign_in`), App Store redeem, "manage online" and browser-claim links, offline activation blobs, and `activate`/`claim` deep links |
| `auth` | Sign in with Meros: authorization code with PKCE (S256), the device authorization grant (RFC 8628), rotating refresh tokens kept in the app's `TokenStore`, and sign-out by revocation. Endpoints come from the issuer's discovery document |
| `server` | Server licenses: activate an instance with a key or a Meros login (which adopts an unowned key), renew daily with `410` vs `403` told apart, release and move, and verify the perpetual Server statement (`verify_licence`). No offline activation |
| `loopback` | The desktop loopback redirect (RFC 8252). Feature `loopback` |
| `cloud` | Meros Cloud: profiles, versioned documents, files (signed-URL upload and checked download), accounts and entitlements |
| `support` | Support tickets over the device API (`SupportApi`) or as the signed-in user for apps without a device license (`AccountSupportApi`), push-token registration, the unread inbox, a new-reply tracker for platforms without push, and support deep links |
| `events` | The Meros Event Envelope v1 (`meros-co/meros-event-spec` v0.1.1): a capped local NDJSON log, and batched delivery to collectors. Feature `events-runtime` adds periodic delivery on Tokio |
| `device` | `EntitlementDevice`: a `LicenseDevice` over a meros-entitlement `Store`, keeping its device id, key and seat. Feature `entitlement` |
| `fake` | `FakeMeros`: all of the services in memory as a `Transport`, for app tests with no network. Feature `fake` |

## Principles

- **The crate has no built-in host or client id.** The app passes its issuer,
  device base URL and OAuth client id. `Environment::for_build(release,
  testing)` picks production only for a release build that isn't a test
  build. Tests use `FakeMeros`, so they reach no server at all.
- **Keys stay where they are.** The clients never hold a device key. The app
  implements `DeviceSigner` and `LicenseDevice` over whatever already holds
  the key, so an existing device keeps its id, key and seat.
- **Storage is the app's.** `TokenStore` (OAuth tokens) and `TicketSeenStore`
  (unread state) are traits. The app backs them with the Keystore, the
  Keychain or its own channel.
- **Errors keep the server's code.** `Error::code` is exactly what the server
  sent, such as `no_seats_available`, `email_not_verified`,
  `two_factor_required`, `device_id_in_use`, `seat_revoked`,
  `file_too_large`, `quota_exceeded`, `file_mismatch` or `version_conflict`.
  `Error::head_version` holds the head version on a conflict, and
  `Error::retry_after` holds the wait on a 429. A bare 401 on a seat request
  becomes `unauthenticated`.
- **Renewal refusals differ.** `410 seat_revoked` means the seat or its key
  was revoked (by an admin or a refund). The client drops the token, and the
  device may activate or claim again. `403 license_key_disabled` means a
  suspended key, which is reversible. The device keeps its token until it
  expires, resumes when the key is reactivated, and shows the message.
- **Every request goes through a `Transport`.** The default is
  `ReqwestTransport` (rustls). An app may supply its own.

## Use

```rust,ignore
use std::sync::Arc;
use meros_client::*;

// The device, over whatever holds its key.
struct Device { /* the app's key store */ }
impl DeviceSigner for Device {
    fn identity(&self) -> Option<DeviceIdentity> { todo!() }
    fn sign(&self, method: &str, path: &str, ts: i64) -> Option<String> { todo!() }
}
impl LicenseDevice for Device {
    fn apply_token(&self, token: &str) -> Result<(), String> { todo!() }
    fn clear_token(&self) { todo!() }
    fn model(&self) -> String { "Model".into() }
    fn name(&self) -> Option<String> { None }
}

# async fn run(device: Arc<Device>, store: Arc<dyn TokenStore>, release: bool) -> Result<(), Error> {
let host = Environment::for_build(release, false)
    .pick("https://production.example", "https://staging.example");
let transport: Arc<dyn Transport> = Arc::new(ReqwestTransport::new());

let license = LicenseClient::new(
    LicenseConfig {
        base_url: format!("{host}/app/example-app"),
        app_name: "Example".into(),
        app_version: "1.0.0".into(),
    },
    transport.clone(),
    device.clone(),
)
.on_changed(|| { /* refresh the license screen */ });

let auth = Arc::new(MerosAuth::new(
    AuthConfig {
        issuer: host.into(),
        client_id: "the app's client id".into(),
        redirect_uri: "exampleapp://oauth/callback".into(),
        scopes: vec!["openid".into(), "offline_access".into()],
    },
    transport.clone(),
    store,
));
// Open `begin_sign_in()` in the browser, then pass the redirect back.
let page = auth.begin_sign_in().await;
# let callback = page;
auth.complete_sign_in(&callback).await?;
license.claim_with_account(auth.as_ref(), None).await?;

let cloud = MerosCloud::new(host, transport.clone(), auth.clone());
let backup = cloud.get_doc("example-app", "backups", "main", None, None).await?;
# Ok(()) }
```

On desktop, sign in through a loopback redirect:

```rust,ignore
# async fn run(auth: &meros_client::MerosAuth) -> Result<(), meros_client::Error> {
let redirect = meros_client::loopback::LoopbackRedirect::bind().await?;
let page = auth.begin_sign_in_with(redirect.redirect_uri()).await;
// open `page` in the browser
let callback = redirect.wait(std::time::Duration::from_secs(300)).await?;
auth.complete_sign_in(&callback).await?;
# Ok(()) }
```

On a device with no browser, sign in with a code approved on another device
(RFC 8628):

```rust,ignore
# async fn run(auth: &meros_client::MerosAuth) -> Result<(), meros_client::Error> {
let mut sign_in = auth.begin_device_sign_in().await?;
// show `sign_in.user_code` and `sign_in.verification_uri`
// (or `verification_uri_complete` as a QR code)
let user = loop {
    tokio::time::sleep(std::time::Duration::from_secs(sign_in.interval)).await;
    if let Some(user) = auth.poll_device_sign_in(&mut sign_in).await? {
        break user;
    }
};
# Ok(()) }
```

The poll fails with `expired_token` or `access_denied`; start again with a new
code either way.

## Tests

`cargo test --all-features` runs everything against `FakeMeros`. It checks
device signatures for real, and the tests cover:

- PKCE, the device grant and refresh rotation;
- seats, claim refusals, token expiry and the file quota;
- damaged uploads;
- document conflicts;
- support threads;
- event batches and splitting.

App tests can use the same fake. Turn on the `fake` feature in
dev-dependencies, pass `FakeMeros::new()` as the transport, and set its knobs
through `fake.state()`.

## License

MIT. See [LICENSE](LICENSE).
