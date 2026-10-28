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
