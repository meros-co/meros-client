mod common;

use std::sync::{Arc, Mutex};

use common::*;
use meros_client::fake::FakeMeros;
use meros_client::testing::TestDevice;
use meros_client::{MemoryTicketSeenStore, ReplyTracker, SupportApi, SupportInbox, TicketStatus};

/// An activated device and its support client.
async fn setup() -> (Arc<FakeMeros>, Arc<TestDevice>, SupportApi) {
    let fake = FakeMeros::new();
    fake.state().license_keys.insert("K".into());
    let d = Arc::new(TestDevice::new("dev-s"));
    license(&fake, &d).activate("K", None).await.unwrap();
    let api = SupportApi::new(BASE, "2.0.1", fake.clone(), d.clone());
    (fake, d, api)
}

#[tokio::test]
async fn files_lists_and_replies_on_tickets() {
    let (fake, _, api) = setup().await;
    let t = api
        .create("Recording stops", "After a few minutes.", Some("os: test"))
        .await
        .unwrap();
    assert_eq!(t.status, TicketStatus::Open);
    assert_eq!(
        fake.state().tickets[0].diagnostics.as_deref(),
        Some("os: test")
    );
    // Empty diagnostics are left out.
    api.create("Second", "Body", Some("")).await.unwrap();
    let sent = fake
        .requests_to("/v1/support/tickets")
        .last()
        .unwrap()
        .json_body()
        .unwrap();
    assert!(sent.get("app_diagnostics").is_none());

    // GETs are signed in headers.
    let list = api.list().await.unwrap();
    assert_eq!(list.len(), 2);
    let get = fake
        .requests_to("/v1/support/tickets")
        .into_iter()
        .find(|r| r.method == "GET")
        .unwrap();
    assert_eq!(get.header_value("X-Device-Id"), Some("dev-s"));
    assert!(get.header_value("X-Sig").is_some());

    fake.support_replies(&t.id, "Try this.");
    let thread = api.thread(&t.id).await.unwrap();
    assert_eq!(thread.ticket.status, TicketStatus::Pending);
    assert_eq!(
        thread
            .messages
            .iter()
            .map(|m| m.from_support)
            .collect::<Vec<_>>(),
        [false, true]
    );
    let reopened = api.reply(&t.id, "Thanks").await.unwrap();
    assert_eq!(reopened.status, TicketStatus::Open);
    assert_eq!(
        api.thread("tkt_none").await.unwrap_err().code,
        "unknown_ticket"
    );
}

#[tokio::test]
async fn an_unknown_device_is_refused_and_the_app_told() {
    let fake = FakeMeros::new();
    let d = Arc::new(TestDevice::new("dev-unknown"));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = seen.clone();
    let api = SupportApi::new(BASE, "1", fake.clone(), d)
        .on_device_rejected(move |c| s.lock().unwrap().push(c.to_string()));
    let e = api.list().await.unwrap_err();
    assert!(e.device_not_activated());
    assert_eq!(*seen.lock().unwrap(), ["unknown_device"]);
}

#[tokio::test]
async fn registers_push_tokens_and_skips_without_identity() {
    let (fake, _, api) = setup().await;
    api.register_push_token("fcm-1", "android").await.unwrap();
    assert_eq!(
        fake.state().push_tokens,
        [(
            "dev-s".to_string(),
            "android".to_string(),
            "fcm-1".to_string()
        )]
    );
    let body = fake.requests_to("/v1/device/push-token")[0]
        .json_body()
        .unwrap();
    assert_eq!(body["app_version"], "2.0.1");
}

#[tokio::test]
async fn the_inbox_and_tracker_follow_replies() {
    let (fake, _, api) = setup().await;
    let inbox = SupportInbox::new(Arc::new(MemoryTicketSeenStore::default()));
    let tracker = ReplyTracker::new();
    let t = api.create("A", "a", None).await.unwrap();
    assert!(tracker.check(&inbox, &api, true).await.is_empty());
    fake.support_replies(&t.id, "Answer");
    fake.state().clock += 10;
    let fresh = tracker.check(&inbox, &api, true).await;
    assert_eq!(fresh.len(), 1);
    assert_eq!(inbox.unread_count(), 1);
    inbox.mark_seen(&inbox.tickets()[0]);
    assert_eq!(inbox.unread_count(), 0);
    assert!(tracker.check(&inbox, &api, true).await.is_empty());
    // Unlicensed: no tickets, nothing unread.
    inbox.refresh(&api, false).await.unwrap();
    assert!(inbox.tickets().is_empty());
}

#[tokio::test]
async fn the_service_safeguards_reach_the_app_and_bad_text_is_never_sent() {
    let (fake, _, api) = setup().await;
    // Checked here first: nothing is sent.
    let sent = || fake.requests_to("/v1/support/tickets").len();
    let before = sent();
    assert_eq!(
        api.create("Two\nlines", "m", None).await.unwrap_err().code,
        "invalid_subject"
    );
    assert_eq!(
        api.create("", "m", None).await.unwrap_err().code,
        "invalid_subject"
    );
    assert_eq!(
        api.create("S", "bell\u{7}", None).await.unwrap_err().code,
        "invalid_message"
    );
    assert_eq!(sent(), before);
    // A resend is the same ticket.
    let a = api
        .create("Audio drops", "Line one\nline two", None)
        .await
        .unwrap();
    let again = api
        .create("Audio drops", "Line one\nline two", None)
        .await
        .unwrap();
    assert_eq!(a.id, again.id);
    assert_eq!(fake.state().tickets.len(), 1);
    // The open-ticket cap and the rate limit keep their codes.
    fake.state().open_ticket_cap = 1;
    let e = api.create("Another", "m", None).await.unwrap_err();
    assert!(e.too_many_open_tickets() && e.status == Some(429));
    fake.state().support_rate_limited = true;
    let e = api.list().await.unwrap_err();
    assert!(e.rate_limited());
    assert_eq!(e.message, "Too many requests. Try again later.");
}

#[tokio::test]
async fn a_service_at_its_own_root_works_too() {
    let fake = FakeMeros::new();
    fake.state().license_keys.insert("K".into());
    let d = Arc::new(TestDevice::new("dev-root"));
    let lc = meros_client::LicenseClient::new(
        meros_client::LicenseConfig {
            base_url: "https://service.example.test".into(),
            app_name: "Example".into(),
            app_version: "1".into(),
        },
        fake.clone(),
        d.clone(),
    );
    lc.activate("K", None).await.unwrap();
    let api = SupportApi::new("https://service.example.test", "1", fake.clone(), d);
    api.create("S", "m", None).await.unwrap();
    assert_eq!(api.list().await.unwrap().len(), 1);
}

mod signed_in {
    use super::*;
    use meros_client::AccountSupportApi;

    async fn api(fake: &Arc<FakeMeros>) -> AccountSupportApi {
        let a = signed_in(fake).await;
        AccountSupportApi::new(ISSUER, "example-app", fake.clone(), a)
    }

    #[tokio::test]
    async fn files_lists_and_replies_as_the_signed_in_user() {
        let fake = FakeMeros::new();
        let api = api(&fake).await;
        let t = api
            .create("Crash on export", "Steps…", Some("os: test"))
            .await
            .unwrap();
        assert!(t.id.starts_with("tkt_"));
        // A resend is the same ticket.
        assert_eq!(
            api.create("Crash on export", "Steps…", None)
                .await
                .unwrap()
                .id,
            t.id
        );
        let r = &fake.requests_to("/v1/support/example-app/tickets")[0];
        assert!(
            r.header_value("Authorization")
                .unwrap()
                .starts_with("Bearer at")
        );
        assert_eq!(r.json_body().unwrap()["app_diagnostics"], "os: test");

        fake.support_replies(&t.id, "Fixed in the next build.");
        let thread = api.thread(&t.id).await.unwrap();
        assert_eq!(thread.ticket.status, TicketStatus::Pending);
        assert_eq!(
            thread
                .messages
                .iter()
                .map(|m| m.from_support)
                .collect::<Vec<_>>(),
            [false, true]
        );
        assert_eq!(
            api.reply(&t.id, "Thanks").await.unwrap().status,
            TicketStatus::Open
        );
        assert_eq!(api.list().await.unwrap().len(), 1);
        assert_eq!(
            api.thread("tkt_none").await.unwrap_err().code,
            "unknown_ticket"
        );
    }

    #[tokio::test]
    async fn refusals_keep_their_codes_and_a_stale_token_is_renewed_once() {
        let fake = FakeMeros::new();
        let api = api(&fake).await;
        fake.state().expire_access_tokens();
        assert!(api.list().await.unwrap().is_empty());
        assert_eq!(fake.requests_to("/v1/support/example-app/tickets").len(), 2);

        assert_eq!(
            api.create("Two\nlines", "m", None).await.unwrap_err().code,
            "invalid_subject"
        );
        let long = "x".repeat(meros_client::support::SUBJECT_MAX + 1);
        assert_eq!(
            api.create(&long, "m", None).await.unwrap_err().code,
            "invalid_subject"
        );

        fake.state().support_rate_limited = true;
        assert!(api.list().await.unwrap_err().rate_limited());
        fake.state().support_rate_limited = false;
        fake.state().unknown_products.insert("example-app".into());
        assert_eq!(api.list().await.unwrap_err().code, "unknown_product");
        fake.state().unknown_products.clear();
        fake.state().support_scope = false;
        let e = api.list().await.unwrap_err();
        assert_eq!(
            (e.status, e.code.as_str()),
            (Some(403), "insufficient_scope")
        );
    }

    #[tokio::test]
    async fn signed_out_users_get_signed_out_not_a_request() {
        let fake = FakeMeros::new();
        let api = AccountSupportApi::new(ISSUER, "example-app", fake.clone(), auth(&fake));
        assert_eq!(api.list().await.unwrap_err().code, "signed_out");
        assert!(fake.requests_to("/tickets").is_empty());
    }
}
