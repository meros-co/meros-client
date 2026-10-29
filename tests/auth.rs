mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use common::*;
use meros_client::fake::FakeMeros;
use meros_client::{AuthConfig, MemoryTokenStore, MerosAuth, TokenStore};

#[tokio::test]
async fn signs_in_with_pkce_and_keeps_the_session_across_runs() {
    let fake = FakeMeros::new();
    let store = Arc::new(MemoryTokenStore::default());
    let config = AuthConfig {
        issuer: ISSUER.into(),
        client_id: "client-1".into(),
        redirect_uri: "exampleapp://oauth/callback".into(),
        scopes: vec!["openid".into(), "profiles:read".into()],
    };
    let a = MerosAuth::new(config.clone(), fake.clone(), store.clone());
    let page = a.begin_sign_in().await;
    let u = url::Url::parse(&page).unwrap();
    let q: std::collections::HashMap<_, _> = u.query_pairs().into_owned().collect();
    assert_eq!(u.path(), "/oauth/authorize");
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(q["scope"], "openid profiles:read");
    let callback = fake.approve(&page);
    assert!(a.is_callback(&callback));
    let user = a.complete_sign_in(&callback).await.unwrap();
    assert_eq!(user.label(), "Pat");

    // A new run reads the stored session.
    let again = MerosAuth::new(config, fake.clone(), store.clone());
    again.load().await;
    assert_eq!(again.user().unwrap().id, "u1");
    assert!(again.access_token(false).await.unwrap().starts_with("at"));
}

#[tokio::test]
async fn a_tampered_or_foreign_callback_is_refused() {
    let fake = FakeMeros::new();
    let a = auth(&fake);
    let page = a.begin_sign_in().await;
    let callback = fake.approve(&page).replace("state=", "state=x");
    assert_eq!(
        a.complete_sign_in(&callback).await.unwrap_err().code,
        "state_mismatch"
    );
    // The pending sign-in is used up.
    let e = a
        .complete_sign_in("exampleapp://oauth/callback?code=c&state=s")
        .await
        .unwrap_err();
    assert_eq!(e.code, "no_pending");
    let e = a
        .complete_sign_in("exampleapp://oauth/callback?error=access_denied")
        .await
        .unwrap_err();
    assert_eq!(
        (e.code.as_str(), e.message.as_str()),
        ("access_denied", "Sign-in was canceled.")
    );
}

#[tokio::test]
async fn tokens_refresh_near_expiry_and_rotate() {
    let fake = FakeMeros::new();
    let clock = Arc::new(AtomicI64::new(1_000));
    let c = clock.clone();
    let a = auth(&fake);
    let a = Arc::new(
        Arc::try_unwrap(a)
            .ok()
            .unwrap()
            .with_clock(move || c.load(Ordering::SeqCst)),
    );
    let page = a.begin_sign_in().await;
    a.complete_sign_in(&fake.approve(&page)).await.unwrap();
    let first = a.access_token(false).await.unwrap();
    assert_eq!(a.access_token(false).await.unwrap(), first, "still fresh");
    clock.store(1_000 + 3600 - 30, Ordering::SeqCst);
    let second = a.access_token(false).await.unwrap();
    assert_ne!(second, first, "refreshed within a minute of expiry");
    assert_eq!(fake.requests_to("/oauth/token").len(), 2);
}

/// The fake answers at once; a real network takes a while.
struct Slow(Arc<FakeMeros>);

impl meros_client::Transport for Slow {
    fn send(
        &self,
        r: meros_client::HttpRequest,
    ) -> meros_client::BoxFuture<'_, Result<meros_client::HttpResponse, meros_client::Error>> {
        Box::pin(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            self.0.send(r).await
        })
    }
}

#[tokio::test]
async fn concurrent_callers_share_one_refresh() {
    let fake = FakeMeros::new();
    let config = auth(&fake).config.clone();
    let a = MerosAuth::new(
        config,
        Arc::new(Slow(fake.clone())),
        Arc::new(MemoryTokenStore::default()),
    );
    let page = a.begin_sign_in().await;
    a.complete_sign_in(&fake.approve(&page)).await.unwrap();
    let before = fake.requests_to("/oauth/token").len();
    let (x, y, z) = tokio::join!(
        a.access_token(true),
        a.access_token(true),
        a.access_token(true)
    );
    let (x, y, z) = (x.unwrap(), y.unwrap(), z.unwrap());
    assert_eq!(fake.requests_to("/oauth/token").len(), before + 1);
    assert!(x == y && y == z);
}

#[tokio::test]
async fn a_revoked_session_signs_out_and_sign_out_revokes() {
    let fake = FakeMeros::new();
    let a = signed_in(&fake).await;
    fake.state().revoke_session();
    let e = a.access_token(true).await.unwrap_err();
    assert_eq!(e.code, "invalid_grant");
    assert!(!a.signed_in());
    assert_eq!(a.access_token(false).await.unwrap_err().code, "signed_out");

    let store = Arc::new(MemoryTokenStore::default());
    let b = MerosAuth::new(a.config.clone(), fake.clone(), store.clone());
    let page = b.begin_sign_in().await;
    b.complete_sign_in(&fake.approve(&page)).await.unwrap();
    b.sign_out().await;
    assert!(!b.signed_in());
    assert_eq!(store.read("meros.refresh_token").await, None);
    assert_eq!(fake.requests_to("/oauth/revoke").len(), 1);
}

#[tokio::test]
async fn a_loopback_redirect_completes_a_desktop_sign_in() {
    let fake = FakeMeros::new();
    let a = auth(&fake);
    let lb = meros_client::loopback::LoopbackRedirect::bind()
        .await
        .unwrap();
    let page = a.begin_sign_in_with(lb.redirect_uri()).await;
    // What the browser does after approval: load the loopback redirect.
    let back = fake.approve(&page);
    let target = back.trim_start_matches("http://").to_string();
    let (addr, path) = target.split_at(target.find('/').unwrap());
    let (addr, path) = (addr.to_string(), path.to_string());
    let waiting = tokio::spawn(lb.wait(std::time::Duration::from_secs(5)));
    let browser = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(&addr).await.unwrap();
        s.write_all(format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out
    });
    let callback = waiting.await.unwrap().unwrap();
    assert!(browser.await.unwrap().starts_with("HTTP/1.1 200"));
    let user = a.complete_sign_in(&callback).await.unwrap();
    assert_eq!(user.id, "u1");
    // The code was exchanged with the loopback redirect it was issued for.
    let token = &fake.requests_to("/oauth/token")[0];
    let fields: std::collections::HashMap<_, _> = token.form_fields().into_iter().collect();
    assert!(fields["redirect_uri"].starts_with("http://127.0.0.1:"));
}

#[tokio::test]
async fn user_changes_are_reported_on_sign_in_sign_out_and_a_refused_refresh() {
    let fake = FakeMeros::new();
    let seen: Arc<std::sync::Mutex<Vec<Option<String>>>> = Arc::default();
    let s = seen.clone();
    let a = MerosAuth::new(
        auth(&fake).config.clone(),
        fake.clone(),
        Arc::new(MemoryTokenStore::default()),
    )
    .on_user_changed(move |u| s.lock().unwrap().push(u.map(|u| u.id)));
    let page = a.begin_sign_in().await;
    a.complete_sign_in(&fake.approve(&page)).await.unwrap();
    fake.state().revoke_session();
    assert!(a.access_token(true).await.is_err());
    a.sign_out().await; // already signed out: no second report
    assert_eq!(*seen.lock().unwrap(), [Some("u1".to_string()), None]);
}

#[tokio::test]
async fn a_device_signs_in_with_a_code_approved_elsewhere() {
    let fake = FakeMeros::new();
    let store = Arc::new(MemoryTokenStore::default());
    let config = auth(&fake).config.clone();
    let a = MerosAuth::new(config.clone(), fake.clone(), store.clone());
    let mut d = a.begin_device_sign_in().await.unwrap();
    assert_eq!(d.verification_uri, format!("{ISSUER}/link"));
    assert_eq!(
        d.verification_uri_complete.as_deref(),
        Some(format!("{ISSUER}/link?user_code={}", d.user_code).as_str())
    );
    assert_eq!(d.interval, 5);
    let start = &fake.requests_to("/oauth/device/code")[0];
    let fields: std::collections::HashMap<_, _> = start.form_fields().into_iter().collect();
    assert_eq!(
        (fields["client_id"].as_str(), fields["scope"].as_str()),
        ("client-1", "openid offline_access")
    );

    // Not approved yet.
    assert_eq!(a.poll_device_sign_in(&mut d).await.unwrap(), None);
    assert!(!a.signed_in());
    fake.state().clock += 5;
    fake.approve_device(&d.user_code);
    let user = a.poll_device_sign_in(&mut d).await.unwrap().unwrap();
    assert_eq!(user.id, "u1");
    assert!(a.signed_in());
    let token = &fake.requests_to("/oauth/token")[1];
    let fields: std::collections::HashMap<_, _> = token.form_fields().into_iter().collect();
    assert_eq!(
        fields["grant_type"],
        "urn:ietf:params:oauth:grant-type:device_code"
    );

    // The refresh token is stored and rotates as for any sign-in.
    let first = a.access_token(false).await.unwrap();
    let second = a.access_token(true).await.unwrap();
    assert_ne!(first, second);
    let again = MerosAuth::new(config, fake.clone(), store);
    again.load().await;
    assert_eq!(again.user().unwrap().id, "u1");
    assert!(again.access_token(true).await.is_ok());
    // Each client read discovery once and kept it.
    assert_eq!(
        fake.requests_to("/.well-known/openid-configuration").len(),
        2
    );
}

#[tokio::test]
async fn polling_too_fast_slows_the_device_down() {
    let fake = FakeMeros::new();
    let a = auth(&fake);
    let mut d = a.begin_device_sign_in().await.unwrap();
    assert_eq!(a.poll_device_sign_in(&mut d).await.unwrap(), None);
    assert_eq!(a.poll_device_sign_in(&mut d).await.unwrap(), None);
    assert_eq!(d.interval, 10);
    fake.state().clock += 10;
    assert_eq!(a.poll_device_sign_in(&mut d).await.unwrap(), None);
    assert_eq!(d.interval, 10);
}

#[tokio::test]
async fn a_declined_or_expired_device_sign_in_fails() {
    let fake = FakeMeros::new();
    let a = auth(&fake);
    let mut d = a.begin_device_sign_in().await.unwrap();
    fake.deny_device(&d.user_code);
    let e = a.poll_device_sign_in(&mut d).await.unwrap_err();
    assert_eq!(e.code, "access_denied");
    assert!(!a.signed_in());

    let mut d = a.begin_device_sign_in().await.unwrap();
    fake.state().clock += 600;
    let e = a.poll_device_sign_in(&mut d).await.unwrap_err();
    assert_eq!(e.code, "expired_token");

    // Past its own expiry the client stops asking.
    let clock = Arc::new(AtomicI64::new(1_000));
    let c = clock.clone();
    let b = MerosAuth::new(
        auth(&fake).config.clone(),
        fake.clone(),
        Arc::new(MemoryTokenStore::default()),
    )
    .with_clock(move || c.load(Ordering::SeqCst));
    let mut d = b.begin_device_sign_in().await.unwrap();
    assert_eq!(d.expires_at, 1_600);
    clock.store(1_600, Ordering::SeqCst);
    let asked = fake.requests_to("/oauth/token").len();
    let e = b.poll_device_sign_in(&mut d).await.unwrap_err();
    assert_eq!(e.code, "expired_token");
    assert_eq!(fake.requests_to("/oauth/token").len(), asked);
}

#[tokio::test]
async fn an_issuer_without_the_device_grant_says_so() {
    let fake = FakeMeros::new();
    fake.state().device_grant = false;
    let e = auth(&fake).begin_device_sign_in().await.unwrap_err();
    assert_eq!(e.code, "device_grant_unsupported");
}

#[tokio::test]
async fn endpoints_come_from_discovery() {
    let fake = FakeMeros::new();
    let a = signed_in(&fake).await;
    a.access_token(true).await.unwrap();
    a.sign_out().await;
    assert_eq!(
        fake.requests_to("/.well-known/openid-configuration").len(),
        1
    );
    assert_eq!(fake.requests_to("/oauth/token").len(), 2);
    assert_eq!(fake.requests_to("/oauth/userinfo").len(), 1);
    assert_eq!(fake.requests_to("/oauth/revoke").len(), 1);
}

#[tokio::test]
async fn an_issuer_without_discovery_signs_in_at_its_standard_paths() {
    let fake = FakeMeros::new();
    fake.state().discovery = false;
    let a = signed_in(&fake).await;
    assert!(a.access_token(true).await.is_ok());
    // Asked once, then remembered.
    assert_eq!(
        fake.requests_to("/.well-known/openid-configuration").len(),
        1
    );
    // The device grant needs discovery.
    let e = a.begin_device_sign_in().await.unwrap_err();
    assert_eq!(e.code, "discovery");
}
