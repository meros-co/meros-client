//! Browser sign-in (authorization code with PKCE, pushed and device-signed
//! for server products) and the console password sign-in, against the fake.

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use common::*;
use meros_client::fake::FakeMeros;
use meros_client::testing::TestDevice;
use meros_client::{
    AuthConfig, BrowserSignInOptions, DeviceSigner, MemoryTokenStore, MerosAuth, PasswordStep,
    Pkce, TokenStore,
};
use serde_json::json;

const SERVER_CALLBACK: &str = "https://rack.lan:8443/auth/meros/callback";

fn query(url: &str) -> HashMap<String, String> {
    url::Url::parse(url)
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect()
}

fn server_options(device: &Arc<TestDevice>, redirect: &str) -> BrowserSignInOptions {
    BrowserSignInOptions {
        redirect_uri: redirect.into(),
        device: Some(device.clone()),
        ..Default::default()
    }
}

#[tokio::test]
async fn a_server_pushes_a_signed_request_and_finishes_with_its_verifier() {
    let fake = FakeMeros::new();
    let a = auth(&fake);
    let device = Arc::new(TestDevice::new("d1"));
    let b = a
        .begin_browser_sign_in(&server_options(&device, SERVER_CALLBACK))
        .await
        .unwrap();
    // Only the client and the pushed request travel through the browser.
    let q = query(&b.authorize_url);
    assert_eq!(
        q.keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        ["client_id", "request_uri"].into()
    );
    let pushed = &fake.requests_to("/oauth/par")[0];
    let body = String::from_utf8(pushed.body.clone()).unwrap();
    assert!(body.contains("&sig=") && !body.contains("code_verifier"));
    let f: HashMap<String, String> = pushed.form_fields().into_iter().collect();
    assert_eq!(f["redirect_uri"], SERVER_CALLBACK);
    assert_eq!(f["state"], b.state);
    assert_eq!(f["device_id"], "d1");

    let callback = fake.approve(&b.authorize_url);
    assert!(query(&callback).contains_key("iss"));
    let s = a.complete_browser_sign_in(&callback).await.unwrap();
    assert_eq!((s.user.id.as_str(), s.user.label()), ("u1", "Pat"));
    assert_eq!(
        (s.amr, s.replaced_previous),
        (vec!["pwd".to_string()], false)
    );
    assert!(a.access_token(false).await.unwrap().starts_with("at"));
    // Each state finishes once.
    let e = a.complete_browser_sign_in(&callback).await.unwrap_err();
    assert_eq!(e.code, "unknown_request");
}

#[tokio::test]
async fn an_unknown_device_may_redirect_only_to_the_local_network() {
    let fake = FakeMeros::new();
    let a = auth(&fake);
    let device = Arc::new(TestDevice::new("d1"));
    for local in [
        SERVER_CALLBACK,
        "https://192.168.1.20/cb",
        "https://rack.local/cb",
        "https://rack/cb",
    ] {
        a.begin_browser_sign_in(&server_options(&device, local))
            .await
            .unwrap();
    }
    let public = "https://rack.example.com/cb";
    let e = a
        .begin_browser_sign_in(&server_options(&device, public))
        .await
        .unwrap_err();
    assert_eq!(
        (e.status, e.code.as_str()),
        (Some(400), "invalid_redirect_uri")
    );
    // Activated, the device may use its public name, never a public address.
    let pubkey = device.identity().unwrap().pubkey;
    fake.state().devices.insert("d1".into(), pubkey);
    a.begin_browser_sign_in(&server_options(&device, public))
        .await
        .unwrap();
    let e = a
        .begin_browser_sign_in(&server_options(&device, "https://203.0.113.9/cb"))
        .await
        .unwrap_err();
    assert_eq!(e.code, "invalid_redirect_uri");
    let e = a
        .begin_browser_sign_in(&server_options(&device, "http://rack.lan/cb"))
        .await
        .unwrap_err();
    assert_eq!(e.code, "invalid_redirect_uri");
}

#[tokio::test]
async fn a_known_device_id_signed_with_another_key_is_refused() {
    let fake = FakeMeros::new();
    fake.state().devices.insert(
        "d1".into(),
        TestDevice::new("other").identity().unwrap().pubkey,
    );
    let device = Arc::new(TestDevice::new("d1"));
    let e = auth(&fake)
        .begin_browser_sign_in(&server_options(&device, SERVER_CALLBACK))
        .await
        .unwrap_err();
    assert_eq!((e.status, e.code.as_str()), (Some(401), "bad_signature"));
}

#[tokio::test]
async fn an_issuer_without_par_says_so() {
    let fake = FakeMeros::new();
    fake.state().par = false;
    let device = Arc::new(TestDevice::new("d1"));
    let e = auth(&fake)
        .begin_browser_sign_in(&server_options(&device, SERVER_CALLBACK))
        .await
        .unwrap_err();
    assert_eq!(e.code, "par_unsupported");
}

#[tokio::test]
async fn several_sign_ins_wait_at_once_and_the_oldest_goes_first() {
    let fake = FakeMeros::new();
    let clock = Arc::new(std::sync::atomic::AtomicI64::new(1_000));
    let c = clock.clone();
    let a = MerosAuth::new(
        AuthConfig {
            issuer: ISSUER.into(),
            client_id: "client-1".into(),
            redirect_uri: "exampleapp://oauth/callback".into(),
            scopes: vec!["openid".into(), "offline_access".into()],
        },
        fake.clone(),
        Arc::new(MemoryTokenStore::default()),
    )
    .with_clock(move || c.fetch_add(1, std::sync::atomic::Ordering::SeqCst));
    let first = a.begin_sign_in().await;
    let second = a.begin_sign_in().await;
    // Finished in any order.
    a.complete_sign_in(&fake.approve(&second)).await.unwrap();
    a.complete_sign_in(&fake.approve(&first)).await.unwrap();
    // The 33rd pushes out the oldest.
    let oldest = a.begin_sign_in().await;
    for _ in 0..32 {
        a.begin_sign_in().await;
    }
    let e = a
        .complete_sign_in(&fake.approve(&oldest))
        .await
        .unwrap_err();
    assert_eq!(e.code, "unknown_request");
    // Ten minutes later they are all gone.
    let last = a.begin_sign_in().await;
    clock.fetch_add(601, std::sync::atomic::Ordering::SeqCst);
    let e = a.complete_sign_in(&fake.approve(&last)).await.unwrap_err();
    assert_eq!(e.code, "unknown_request");
}

#[tokio::test]
async fn the_id_token_must_be_this_clients_and_this_sign_ins() {
    for (claim, value) in [
        ("aud", json!("someone-else")),
        ("nonce", json!("another-sign-in")),
        ("iss", json!("https://elsewhere.test")),
        ("exp", json!(1_000)),
        ("sub", json!("")),
    ] {
        let fake = FakeMeros::new();
        fake.state().id_token_overrides.insert(claim.into(), value);
        let a = auth(&fake);
        let page = a.begin_sign_in().await;
        let e = a.complete_sign_in(&fake.approve(&page)).await.unwrap_err();
        assert_eq!(e.code, "invalid_response", "{claim}");
        assert!(!a.signed_in());
        // The tokens it got were revoked.
        assert_eq!(fake.requests_to("/oauth/revoke").len(), 1, "{claim}");
    }
}

#[tokio::test]
async fn iss_is_required_when_the_issuer_sends_it() {
    let fake = FakeMeros::new();
    let a = auth(&fake);
    let page = a.begin_sign_in().await;
    let callback = fake.approve(&page);
    let without: String = {
        let mut u = url::Url::parse(&callback).unwrap();
        let kept: Vec<(String, String)> = u
            .query_pairs()
            .into_owned()
            .filter(|(k, _)| k != "iss")
            .collect();
        u.query_pairs_mut().clear().extend_pairs(kept);
        u.to_string()
    };
    let e = a.complete_sign_in(&without).await.unwrap_err();
    assert_eq!(e.code, "issuer_mismatch");

    // An issuer that doesn't send it isn't asked for it.
    let fake = FakeMeros::new();
    fake.state().authorize_iss = false;
    let a = auth(&fake);
    let page = a.begin_sign_in().await;
    a.complete_sign_in(&fake.approve(&page)).await.unwrap();
}

#[tokio::test]
async fn a_canceled_sign_in_reports_it_and_is_forgotten() {
    let fake = FakeMeros::new();
    let a = auth(&fake);
    let page = a.begin_sign_in().await;
    let callback = fake.deny(&page);
    let e = a.complete_sign_in(&callback).await.unwrap_err();
    assert_eq!(
        (e.code.as_str(), e.message.as_str()),
        ("access_denied", "Sign-in was canceled.")
    );
    let state = query(&page)["state"].clone();
    let e = a
        .complete_sign_in(&format!(
            "exampleapp://oauth/callback?code=c&state={state}&iss={ISSUER}"
        ))
        .await
        .unwrap_err();
    assert_eq!(e.code, "unknown_request");
}

#[tokio::test]
async fn acr_values_login_hint_and_prompt_reach_the_issuer() {
    let fake = FakeMeros::new();
    let a = auth(&fake);
    let b = a
        .begin_browser_sign_in(&BrowserSignInOptions {
            acr_values: Some("urn:meros:acr:mfa".into()),
            login_hint: Some("pat@example.com".into()),
            prompt: Some("login".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    let q = query(&b.authorize_url);
    assert_eq!(q["acr_values"], "urn:meros:acr:mfa");
    assert_eq!(q["login_hint"], "pat@example.com");
    assert_eq!(q["prompt"], "login");
    assert_eq!(q["redirect_uri"], "exampleapp://oauth/callback");
    assert!(!q["nonce"].is_empty());
    let s = a
        .complete_browser_sign_in(&fake.approve(&b.authorize_url))
        .await
        .unwrap();
    assert_eq!(s.acr.as_deref(), Some("urn:meros:acr:mfa"));
    assert!(s.amr.contains(&"mfa".to_string()));

    // Pushed, they go in the signed request.
    let device = Arc::new(TestDevice::new("d1"));
    let mut options = server_options(&device, SERVER_CALLBACK);
    options.login_hint = Some("pat@example.com".into());
    a.begin_browser_sign_in(&options).await.unwrap();
    let f: HashMap<String, String> = fake.requests_to("/oauth/par")[0]
        .form_fields()
        .into_iter()
        .collect();
    assert_eq!(f["login_hint"], "pat@example.com");
}

#[tokio::test]
async fn a_session_refreshes_and_revokes_with_the_client_its_tokens_belong_to() {
    let fake = FakeMeros::new();
    let store = Arc::new(MemoryTokenStore::default());
    let config = |client: &str| AuthConfig {
        issuer: ISSUER.into(),
        client_id: client.into(),
        redirect_uri: String::new(),
        scopes: vec!["openid".into(), "licenses:activate".into()],
    };
    // Signed in as the server client, kept in a session configured with
    // the browser client.
    let server = MerosAuth::new(
        config("server-client"),
        fake.clone(),
        Arc::new(MemoryTokenStore::default()),
    );
    let device = Arc::new(TestDevice::new("d1"));
    let b = server
        .begin_browser_sign_in(&server_options(&device, SERVER_CALLBACK))
        .await
        .unwrap();
    let new = server
        .finish_browser_sign_in(&fake.approve(&b.authorize_url))
        .await
        .unwrap();
    assert_eq!(new.client_id, "server-client");
    let session = MerosAuth::new(config("browser-client"), fake.clone(), store.clone());
    session.adopt(new).await;
    session.access_token(true).await.unwrap();
    let refresh = fake.requests_to("/oauth/token").pop().unwrap();
    let f: HashMap<String, String> = refresh.form_fields().into_iter().collect();
    assert_eq!(
        (f["grant_type"].as_str(), f["client_id"].as_str()),
        ("refresh_token", "server-client")
    );
    assert!(session.sign_out().await);
    let revoke = fake.requests_to("/oauth/revoke").pop().unwrap();
    let f: HashMap<String, String> = revoke.form_fields().into_iter().collect();
    assert_eq!(f["client_id"], "server-client");
    assert!(store.read("meros.client_id").await.is_none());
}

#[tokio::test]
async fn a_sign_in_begun_before_an_upgrade_still_finishes() {
    let fake = FakeMeros::new();
    let store = Arc::new(MemoryTokenStore::default());
    let pkce = Pkce::generate();
    store
        .write(
            "meros.pending",
            Some(
                json!({"state": "s-old", "verifier": pkce.verifier, "redirect_uri": "exampleapp://oauth/callback"})
                    .to_string(),
            ),
        )
        .await;
    let a = MerosAuth::new(
        AuthConfig {
            issuer: ISSUER.into(),
            client_id: "client-1".into(),
            redirect_uri: "exampleapp://oauth/callback".into(),
            scopes: vec!["openid".into()],
        },
        fake.clone(),
        store,
    );
    let page = format!(
        "{ISSUER}/oauth/authorize?client_id=client-1&redirect_uri=exampleapp%3A%2F%2Foauth%2Fcallback&state=s-old&code_challenge={}",
        pkce.challenge
    );
    let user = a.complete_sign_in(&fake.approve(&page)).await.unwrap();
    assert_eq!(user.id, "u1");
}

// ── Console password sign-in ──

fn console(fake: &Arc<FakeMeros>) -> (Arc<MerosAuth>, Arc<TestDevice>) {
    fake.state().credentials = Some(("pat@example.com".into(), "correct horse".into()));
    (auth(fake), Arc::new(TestDevice::new("console-1")))
}

#[tokio::test]
async fn a_console_signs_in_with_an_email_and_password() {
    let fake = FakeMeros::new();
    let (a, device) = console(&fake);
    let step = a
        .password_sign_in(device.as_ref(), "Pat@Example.com", "correct horse")
        .await
        .unwrap();
    let PasswordStep::SignedIn(new) = step else {
        panic!("no two-factor here");
    };
    assert_eq!(new.amr, ["pwd"]);
    let s = a.adopt(new).await;
    assert_eq!(s.user.id, "u1");
    assert!(a.signed_in());
    // Signed with the device key; the password went once, to the token
    // endpoint, and nowhere else.
    let sent = &fake.requests_to("/oauth/token")[0];
    let f: HashMap<String, String> = sent.form_fields().into_iter().collect();
    assert_eq!(
        f["grant_type"],
        "urn:meros:params:oauth:grant-type:password"
    );
    assert_eq!(f["device_id"], "console-1");
    assert!(f.contains_key("sig") && f.contains_key("nonce"));
}

#[tokio::test]
async fn two_factor_takes_a_code_and_allows_a_retry() {
    let fake = FakeMeros::new();
    let (a, device) = console(&fake);
    fake.state().totp = Some("123456".into());
    let PasswordStep::TwoFactor(c) = a
        .password_sign_in(device.as_ref(), "pat@example.com", "correct horse")
        .await
        .unwrap()
    else {
        panic!("two-factor is on");
    };
    assert_eq!(c.methods, ["totp", "recovery"]);
    let e = a
        .two_factor_sign_in(device.as_ref(), &c.challenge, "000000")
        .await
        .unwrap_err();
    assert_eq!(e.code, "bad_code");
    let new = a
        .two_factor_sign_in(device.as_ref(), &c.challenge, "123 456")
        .await
        .unwrap();
    assert_eq!(new.amr, ["pwd", "otp", "mfa"]);
    assert_eq!(new.acr.as_deref(), Some("urn:meros:acr:mfa"));
    // The challenge is spent.
    let e = a
        .two_factor_sign_in(device.as_ref(), &c.challenge, "123456")
        .await
        .unwrap_err();
    assert_eq!(e.code, "invalid_challenge");
}

#[tokio::test]
async fn password_refusals_come_through_unchanged() {
    let fake = FakeMeros::new();
    let (a, device) = console(&fake);
    let e = a
        .password_sign_in(device.as_ref(), "pat@example.com", "wrong")
        .await
        .unwrap_err();
    assert_eq!((e.status, e.code.as_str()), (Some(400), "bad_credentials"));
    for _ in 0..9 {
        let _ = a
            .password_sign_in(device.as_ref(), "pat@example.com", "wrong")
            .await;
    }
    let e = a
        .password_sign_in(device.as_ref(), "pat@example.com", "correct horse")
        .await
        .unwrap_err();
    assert_eq!((e.status, e.code.as_str()), (Some(423), "account_locked"));

    let fake = FakeMeros::new();
    let (a, device) = console(&fake);
    fake.state()
        .password_clients
        .insert("console-client".into());
    let e = a
        .password_sign_in(device.as_ref(), "pat@example.com", "correct horse")
        .await
        .unwrap_err();
    assert_eq!(e.code, "unauthorized_client");

    let fake = FakeMeros::new();
    let (a, device) = console(&fake);
    fake.state().password_refusal = Some((403, "email_not_verified".into()));
    let e = a
        .password_sign_in(device.as_ref(), "pat@example.com", "correct horse")
        .await
        .unwrap_err();
    assert_eq!(e.code, "email_not_verified");
}

// ── Devices registered without a seat ──

#[tokio::test]
async fn a_registered_device_counts_as_known_until_it_unregisters() {
    let fake = FakeMeros::new();
    let a = signed_in(&fake).await;
    let cloud = cloud(&fake, &a);
    let device = Arc::new(TestDevice::new("panel-1"));
    let public = "https://panel.example.com/cb";
    let e = a
        .begin_browser_sign_in(&server_options(&device, public))
        .await
        .unwrap_err();
    assert_eq!(e.code, "invalid_redirect_uri");

    let r = cloud
        .register_device(
            "example-app",
            device.as_ref(),
            Some("Booth"),
            Some("x86_64"),
        )
        .await
        .unwrap();
    assert_eq!(
        (
            r.product.as_str(),
            r.device_id.as_str(),
            r.account_id.as_str()
        ),
        ("example-app", "panel-1", "acct-personal")
    );
    // Form-encoded and signed like a pushed sign-in: a nonce, the bearer
    // token, and sig last.
    let sent = fake.requests_to("/v1/device/register").pop().unwrap();
    assert!(
        sent.header_value("Authorization")
            .is_some_and(|a| a.starts_with("Bearer "))
    );
    let body = String::from_utf8(sent.body.clone()).unwrap();
    let (_, sig) = body.rsplit_once("&sig=").unwrap();
    assert_eq!(sig.len(), 86);
    let f: HashMap<String, String> = sent.form_fields().into_iter().collect();
    assert_eq!(f["product"], "example-app");
    assert_eq!(
        (f["name"].as_str(), f["model"].as_str()),
        ("Booth", "x86_64")
    );
    assert_eq!(f["device_id"], "panel-1");
    assert!((16..=64).contains(&f["nonce"].len()));
    a.begin_browser_sign_in(&server_options(&device, public))
        .await
        .unwrap();

    // Again, twice in the same second, updates it: each body is different.
    for _ in 0..2 {
        cloud
            .register_device("example-app", device.as_ref(), Some("Booth 2"), None)
            .await
            .unwrap();
    }
    // Another key can't take the id.
    let impostor = TestDevice::with_key("panel-1", "impostor");
    let e = cloud
        .register_device("example-app", &impostor, None, None)
        .await
        .unwrap_err();
    assert_eq!((e.status, e.code.as_str()), (Some(401), "bad_signature"));
    // Nor can another account.
    fake.state().team = Some("acct-team".into());
    let e = cloud
        .register_device("example-app", device.as_ref(), None, None)
        .await
        .unwrap_err();
    assert_eq!((e.status, e.code.as_str()), (Some(409), "device_id_in_use"));
    fake.state().team = None;

    assert!(
        cloud
            .unregister_device("example-app", device.as_ref())
            .await
            .unwrap()
    );
    assert!(
        !cloud
            .unregister_device("example-app", device.as_ref())
            .await
            .unwrap()
    );
    let e = a
        .begin_browser_sign_in(&server_options(&device, public))
        .await
        .unwrap_err();
    assert_eq!(e.code, "invalid_redirect_uri");
}

#[tokio::test]
async fn registering_needs_the_scope() {
    let fake = FakeMeros::new();
    fake.state().devices_scope = false;
    let a = signed_in(&fake).await;
    let e = cloud(&fake, &a)
        .register_device("example-app", &TestDevice::new("p"), None, None)
        .await
        .unwrap_err();
    assert_eq!(
        (e.status, e.code.as_str()),
        (Some(403), "insufficient_scope")
    );
}

#[tokio::test]
async fn a_device_holding_a_seat_isnt_registered_too() {
    let fake = FakeMeros::new();
    let a = signed_in(&fake).await;
    let device = TestDevice::new("seated");
    fake.state()
        .devices
        .insert("seated".into(), device.identity().unwrap().pubkey);
    let e = cloud(&fake, &a)
        .register_device("example-app", &device, None, None)
        .await
        .unwrap_err();
    assert_eq!((e.status, e.code.as_str()), (Some(409), "device_id_in_use"));
}
