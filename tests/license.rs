mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use common::*;
use meros_client::fake::FakeMeros;
use meros_client::testing::TestDevice;
use meros_client::{DeviceSigner, LicenseLink};
use serde_json::{Map, Value, json};

fn device(id: &str) -> Arc<TestDevice> {
    Arc::new(TestDevice::new(id))
}

#[tokio::test]
async fn activates_with_a_key_renews_and_releases() {
    let fake = FakeMeros::new();
    fake.state().license_keys.insert("KEY-1".into());
    let d = device("dev-a");
    let changes = Arc::new(AtomicUsize::new(0));
    let activations = Arc::new(AtomicUsize::new(0));
    let (c, a) = (changes.clone(), activations.clone());
    let client = license(&fake, &d)
        .on_changed(move || {
            c.fetch_add(1, Ordering::SeqCst);
        })
        .on_activated(move || {
            a.fetch_add(1, Ordering::SeqCst);
        });

    client.activate("  KEY-1 ", None).await.unwrap();
    assert!(d.token().unwrap().starts_with("ent-dev-a"));
    let sent = fake.requests_to("/v1/device/activate")[0]
        .json_body()
        .unwrap();
    assert_eq!(sent["license_key"], "KEY-1");
    assert_eq!(sent["device"]["model"], "SM-X518U");
    assert_eq!(sent["device"]["app_version"], "2.0.1");
    assert_eq!(
        sent["device"]["name"],
        format!("Example {} (SM-X518U)", std::env::consts::OS)
    );
    assert_eq!(activations.load(Ordering::SeqCst), 1);

    let before = d.token();
    let mut info = Map::new();
    info.insert("rooted".into(), json!(false));
    assert!(client.renew(info).await);
    assert_ne!(d.token(), before);
    let renew = fake.requests_to("/v1/device/renew")[0].json_body().unwrap();
    assert_eq!(
        renew["device_info"],
        json!({"app_version": "2.0.1", "rooted": false})
    );

    client.release().await.unwrap();
    assert_eq!(d.token(), None);
    assert_eq!(changes.load(Ordering::SeqCst), 3);
    assert!(fake.state().seats.is_empty());
}

#[tokio::test]
async fn refusals_carry_the_server_code() {
    let fake = FakeMeros::new();
    let d = device("dev-b");
    let client = license(&fake, &d);
    let e = client.activate("NOPE", None).await.unwrap_err();
    assert_eq!(
        (e.status, e.code.as_str()),
        (Some(404), "unknown_license_key")
    );

    // A token the device won't take.
    fake.state().license_keys.insert("K".into());
    *d.refuse.lock().unwrap() = Some("bad signature".into());
    let e = client.activate("K", None).await.unwrap_err();
    assert_eq!(e.code, "token_rejected");
}

#[tokio::test]
async fn a_revoked_seat_or_unknown_device_drops_the_entitlement() {
    let fake = FakeMeros::new();
    fake.state().license_keys.insert("K".into());
    let d = device("dev-c");
    let client = license(&fake, &d);
    client.activate("K", None).await.unwrap();
    fake.state().released.insert("dev-c".into());
    assert!(!client.renew(Map::new()).await);
    assert_eq!(d.token(), None, "seat_revoked drops it");

    // Unknown to the server (another environment's token): dropped too.
    let other = device("dev-x");
    *other.token.lock().unwrap() = Some("stale".into());
    assert!(!license(&fake, &other).renew(Map::new()).await);
    assert_eq!(other.token(), None);
}

#[tokio::test]
async fn an_offline_renewal_keeps_the_entitlement() {
    struct Offline;
    impl meros_client::Transport for Offline {
        fn send(
            &self,
            _: meros_client::HttpRequest,
        ) -> meros_client::BoxFuture<'_, Result<meros_client::HttpResponse, meros_client::Error>>
        {
            Box::pin(async { Err(meros_client::Error::new(None, "network", "offline")) })
        }
    }
    let d = device("dev-d");
    *d.token.lock().unwrap() = Some("kept".into());
    let client = meros_client::LicenseClient::new(
        meros_client::LicenseConfig {
            base_url: BASE.into(),
            app_name: "Example".into(),
            app_version: "1".into(),
        },
        Arc::new(Offline),
        d.clone(),
    );
    assert!(!client.renew(Map::new()).await);
    assert_eq!(d.token().as_deref(), Some("kept"));
    let e = client.release().await.unwrap_err();
    assert!(e.offline());
}

#[tokio::test]
async fn claims_a_seat_by_signing_in_with_totp() {
    let fake = FakeMeros::new();
    {
        let mut st = fake.state();
        st.credentials = Some(("pat@example.com".into(), "pw".into()));
        st.totp = Some("123456".into());
        st.free_seats = 1;
    }
    let d = device("dev-e");
    let client = license(&fake, &d);
    let e = client
        .authenticate("pat@example.com", "wrong", None)
        .await
        .unwrap_err();
    assert_eq!(e.code, "bad_credentials");
    let first = client
        .authenticate(" pat@example.com ", "pw", Some("Stage iPad"))
        .await
        .unwrap();
    assert!(first.needs_totp());
    let e = client
        .authenticate_totp(&first.session, "000000")
        .await
        .unwrap_err();
    assert_eq!(e.code, "bad_totp");
    let ok = client
        .authenticate_totp(&first.session, " 123456 ")
        .await
        .unwrap();
    assert_eq!(ok.status, "authenticated");
    client.claim(&ok.session).await.unwrap();
    assert!(d.token().is_some());
    assert_eq!(fake.state().free_seats, 0);
}

#[tokio::test]
async fn claims_seats_and_releases_with_the_apps_sign_in() {
    let fake = FakeMeros::new();
    fake.state().free_seats = 1;
    let a = signed_in(&fake).await;
    let d = device("dev-f");
    let client = license(&fake, &d);
    client
        .claim_with_account(a.as_ref(), Some("Booth"))
        .await
        .unwrap();
    assert!(d.token().is_some());

    let other = device("dev-g");
    let e = license(&fake, &other)
        .claim_with_account(a.as_ref(), None)
        .await
        .unwrap_err();
    assert_eq!(e.code, "no_seats_available");

    let seats = client.seats(a.as_ref()).await.unwrap();
    assert_eq!(seats.len(), 1);
    let s = &seats[0];
    assert_eq!(
        (
            s.device_id.as_str(),
            s.name.as_str(),
            s.account_name.as_str()
        ),
        ("dev-f", "Booth", "Pat")
    );
    assert!(s.can_release && s.activated_at.is_some());
    client.release_seat(a.as_ref(), s.seat_id).await.unwrap();
    // The released device learns at its next renewal.
    assert!(!client.renew(Map::new()).await);
    assert_eq!(d.token(), None);
}

#[tokio::test]
async fn claim_refusals_and_forbidden_releases_pass_through() {
    let fake = FakeMeros::new();
    fake.state().free_seats = 2;
    let a = signed_in(&fake).await;
    let d = device("dev-h");
    let client = license(&fake, &d);
    for code in [
        "email_not_verified",
        "two_factor_required",
        "device_id_in_use",
    ] {
        fake.state().claim_refusal = Some((403, code.into()));
        let e = client
            .claim_with_account(a.as_ref(), None)
            .await
            .unwrap_err();
        assert_eq!(e.code, code);
    }
    fake.state().claim_refusal = None;
    fake.state().can_release = false;
    client.claim_with_account(a.as_ref(), None).await.unwrap();
    let seat = client.seats(a.as_ref()).await.unwrap()[0].seat_id;
    assert_eq!(
        client
            .release_seat(a.as_ref(), seat)
            .await
            .unwrap_err()
            .code,
        "forbidden"
    );
}

#[tokio::test]
async fn a_stale_token_is_renewed_once_and_a_bare_401_is_unauthenticated() {
    let fake = FakeMeros::new();
    let a = signed_in(&fake).await;
    let d = device("dev-i");
    let client = license(&fake, &d);
    fake.state().expire_access_tokens();
    assert!(client.seats(a.as_ref()).await.unwrap().is_empty());
    assert_eq!(fake.requests_to("/v1/account/seats").len(), 2);

    // Signed out on the server: the guard's bare 401 gets a code.
    fake.state().revoke_session();
    let e = client.seats(a.as_ref()).await.unwrap_err();
    assert_eq!(e.code, "invalid_grant", "the refresh itself is refused");
    let e = client
        .seats(&meros_client::StaticToken("gone".into()))
        .await
        .unwrap_err();
    assert_eq!((e.status, e.code.as_str()), (Some(401), "unauthenticated"));
}

#[tokio::test]
async fn redeems_an_app_store_purchase() {
    let fake = FakeMeros::new();
    let d = device("dev-j");
    license(&fake, &d)
        .redeem_app_store("signed-jws", None)
        .await
        .unwrap();
    assert!(d.token().is_some());
    let sent = fake.requests_to("/v1/apple/redeem")[0].json_body().unwrap();
    assert_eq!(sent["signed_transaction"], "signed-jws");
}

#[tokio::test]
async fn builds_signed_manage_claim_and_offline_blobs() {
    let fake = FakeMeros::new();
    let d = device("dev-k");
    let client = license(&fake, &d).with_clock(|| 1_790_000_000);
    let decode = |url: &str| -> Value {
        let blob = url.split("request=").nth(1).unwrap();
        assert!(!blob.contains('='), "unpadded");
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(blob).unwrap()).unwrap()
    };
    let manage = client.manage_url().unwrap();
    assert!(manage.starts_with(&format!("{BASE}/manage?request=")));
    let m = decode(&manage);
    assert_eq!(m["device_id"], "dev-k");
    assert_eq!(m["sig"], d.sign("GET", "/manage", 1_790_000_000).unwrap());

    let claim = decode(&client.browser_claim_url().unwrap());
    assert_eq!(claim["device"]["id"], "dev-k");
    assert_eq!(
        claim["sig"],
        d.sign("GET", "/claim", 1_790_000_000).unwrap()
    );

    let blob = client.offline_request_blob("KEY-9", None).unwrap();
    let body: Value = serde_json::from_slice(&URL_SAFE.decode(blob).unwrap()).unwrap();
    assert_eq!(body["license_key"], "KEY-9");
    assert_eq!(
        body["sig"],
        d.sign("POST", "/v1/device/activate", 1_790_000_000)
            .unwrap()
    );

    // The token the page returns (or a claim link carries) is applied.
    client.import_offline_token(" ent-offline ").unwrap();
    assert_eq!(d.token().as_deref(), Some("ent-offline"));
    assert_eq!(
        LicenseLink::parse("exampleapp://claim?token=ent-x", "exampleapp"),
        Some(LicenseLink::Claim {
            token: "ent-x".into(),
            error: String::new()
        })
    );
}

#[tokio::test]
async fn a_device_without_identity_fails_before_any_request() {
    struct NoIdentity;
    impl meros_client::DeviceSigner for NoIdentity {
        fn identity(&self) -> Option<meros_client::DeviceIdentity> {
            None
        }
        fn sign(&self, _: &str, _: &str, _: i64) -> Option<String> {
            None
        }
    }
    impl meros_client::LicenseDevice for NoIdentity {
        fn apply_token(&self, _: &str) -> Result<(), String> {
            Ok(())
        }
        fn clear_token(&self) {}
    }
    let fake = FakeMeros::new();
    let client = meros_client::LicenseClient::new(
        meros_client::LicenseConfig {
            base_url: BASE.into(),
            app_name: "Example".into(),
            app_version: "1".into(),
        },
        fake.clone(),
        Arc::new(NoIdentity),
    );
    assert_eq!(
        client.activate("K", None).await.unwrap_err().code,
        "no_device_identity"
    );
    assert!(fake.state().requests.is_empty());
}

#[tokio::test]
async fn a_device_moves_between_accounts_and_must_register_push_again() {
    let fake = FakeMeros::new();
    {
        let mut st = fake.state();
        st.license_keys.insert("KEY-PERSONAL".into());
        st.license_keys.insert("KEY-OTHER".into());
        st.key_accounts
            .insert("KEY-OTHER".into(), "acct-other".into());
    }
    let d = device("dev-move");
    let activated = Arc::new(AtomicUsize::new(0));
    let a = activated.clone();
    let client = license(&fake, &d).on_activated(move || {
        a.fetch_add(1, Ordering::SeqCst);
    });
    client.activate("KEY-PERSONAL", None).await.unwrap();
    let support = meros_client::SupportApi::new(BASE, "1", fake.clone(), d.clone());
    support
        .register_push_token("fcm-1", "android")
        .await
        .unwrap();

    // Another account's key moves it: no release first.
    client.activate("KEY-OTHER", None).await.unwrap();
    let seats = fake.state().seats.clone();
    assert_eq!(seats.len(), 1);
    assert_eq!(seats[0]["account_id"], "acct-other");
    assert!(
        fake.state().push_tokens.is_empty(),
        "a move drops push tokens"
    );
    assert_eq!(
        activated.load(Ordering::SeqCst),
        2,
        "the app re-registers each time"
    );
    assert!(client.renew(Map::new()).await);

    // The same device id signed with a different key is refused.
    let impostor = Arc::new(TestDevice::with_key("dev-move", "another key"));
    let e = license(&fake, &impostor)
        .activate("KEY-PERSONAL", None)
        .await
        .unwrap_err();
    assert_eq!((e.status, e.code.as_str()), (Some(409), "device_id_in_use"));
    assert!(e.message.contains("Release it there first"));
    assert_eq!(fake.state().seats[0]["account_id"], "acct-other");
}

#[tokio::test]
async fn a_sign_in_claim_moves_the_device_too() {
    let fake = FakeMeros::new();
    {
        let mut st = fake.state();
        st.license_keys.insert("KEY-OTHER".into());
        st.key_accounts
            .insert("KEY-OTHER".into(), "acct-other".into());
        st.free_seats = 1;
    }
    let a = signed_in(&fake).await;
    let d = device("dev-claim-move");
    let client = license(&fake, &d);
    client.activate("KEY-OTHER", None).await.unwrap();
    // The app's sign-in claims it onto the personal account: a move.
    client.claim_with_account(a.as_ref(), None).await.unwrap();
    let st = fake.state();
    assert_eq!(st.seats.len(), 1);
    assert_eq!(st.seats[0]["account_id"], meros_client::fake::PERSONAL);
    assert_eq!(st.free_seats, 1, "the other account's seat was freed");
}
