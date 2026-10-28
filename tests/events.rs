mod common;

use std::sync::Arc;

use common::*;
use meros_client::fake::FakeMeros;
use meros_client::{Collector, Emitter, EmitterConfig, Event, Severity};
use serde_json::Value;

fn config(dir: &std::path::Path) -> EmitterConfig {
    EmitterConfig {
        dir: dir.to_path_buf(),
        product: "example-app".into(),
        version: "0.1.0".into(),
        edition: Some("desktop".into()),
        site: Some("hall".into()),
    }
}

/// Checks an event against event-envelope-1.json's rules.
fn conforms(e: &Value) {
    let s = |p: &str| {
        e.pointer(p)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string()
    };
    assert_eq!(e["envelope"], 1);
    let id = s("/id");
    assert!(id.len() == 26 && id.as_bytes()[0] <= b'7');
    let at = s("/occurred_at");
    assert!(at.ends_with('Z') && at.len() == 24, "{at}");
    let kind = s("/type");
    assert!(kind.split('.').count() >= 3 && kind == kind.to_lowercase());
    assert!(
        ["debug", "info", "notice", "warning", "error", "critical"]
            .contains(&s("/severity").as_str())
    );
    assert!(
        !s("/source/product").is_empty()
            && !s("/source/version").is_empty()
            && !s("/source/instance").is_empty()
    );
    let allowed = [
        "envelope",
        "id",
        "occurred_at",
        "seq",
        "source",
        "type",
        "severity",
        "subject",
        "actor",
        "attrs",
        "trace",
    ];
    assert!(
        e.as_object()
            .unwrap()
            .keys()
            .all(|k| allowed.contains(&k.as_str()))
    );
}

#[tokio::test]
async fn logs_locally_with_a_sequence_that_survives_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeMeros::new();
    let emitter = Emitter::open(config(dir.path()), vec![], fake.clone()).unwrap();
    emitter.emit(
        Event::new("example-app.output.started", Severity::Info)
            .about("output", "rec", Some("Recording"))
            .by("user", Some("u1"), None)
            .attr("transport", "record")
            .traced("t-1"),
    );
    emitter.emit(Event::new("example-app.output.stopped", Severity::Notice));
    let log = String::from_utf8(emitter.export()).unwrap();
    let lines: Vec<Value> = log
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    lines.iter().for_each(conforms);
    assert_eq!(
        (lines[0]["seq"].as_u64(), lines[1]["seq"].as_u64()),
        (Some(1), Some(2))
    );
    assert_eq!(lines[0]["subject"]["name"], "Recording");
    assert_eq!(lines[0]["trace"], "t-1");
    assert!(lines[1].get("attrs").is_none() && lines[1].get("actor").is_none());
    // No collectors: nothing queued, no network.
    assert_eq!(emitter.pending(), 0);
    assert_eq!(emitter.flush().await.delivered, 0);
    assert!(fake.state().requests.is_empty());
    let instance = emitter.instance();
    drop(emitter);

    let again = Emitter::open(config(dir.path()), vec![], fake.clone()).unwrap();
    assert_eq!(again.instance(), instance);
    again.emit(Event::new("example-app.engine.started", Severity::Info));
    let last: Value = serde_json::from_str(
        String::from_utf8(again.export())
            .unwrap()
            .lines()
            .last()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(last["seq"], 3);
}

#[tokio::test]
async fn delivers_batches_to_the_cloud_with_the_users_token() {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeMeros::new();
    let a = signed_in(&fake).await;
    let emitter = Emitter::open(
        config(dir.path()),
        vec![Collector {
            url: ISSUER.into(),
            token: Some(a.clone()),
        }],
        fake.clone(),
    )
    .unwrap();
    for i in 0..1203 {
        emitter.emit(Event::new("example-app.device.connected", Severity::Info).attr("i", i));
    }
    fake.state().expire_access_tokens();
    let report = emitter.flush().await;
    assert_eq!(
        (report.delivered, report.accepted, report.failed),
        (1203, 1203, 0)
    );
    assert_eq!(emitter.pending(), 0);
    let batches = fake.requests_to("/v1/events");
    // Three batches of at most 500, plus one retry after the stale token.
    assert_eq!(batches.len(), 4);
    assert!(
        batches
            .iter()
            .all(|b| b.json_body().unwrap().as_array().unwrap().len() <= 500)
    );
    fake.state().events.iter().for_each(conforms);
}

#[tokio::test]
async fn an_unreachable_collector_keeps_events_and_a_smaller_cap_splits_batches() {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeMeros::new();
    let emitter = Emitter::open(
        config(dir.path()),
        vec![Collector {
            url: ISSUER.into(),
            token: Some(Arc::new(meros_client::StaticToken("nope".into()))),
        }],
        fake.clone(),
    )
    .unwrap();
    for _ in 0..30 {
        emitter.emit(Event::new("example-app.device.lost", Severity::Warning));
    }
    let report = emitter.flush().await;
    assert_eq!((report.delivered, report.failed), (0, 1));
    assert_eq!(emitter.pending(), 30, "refused: kept for next time");

    let a = signed_in(&fake).await;
    emitter.configure(
        None,
        vec![Collector {
            url: ISSUER.into(),
            token: Some(a),
        }],
    );
    fake.state().event_batch_cap = 8;
    let report = emitter.flush().await;
    assert_eq!(report.delivered, 30);
    assert_eq!(fake.state().events.len(), 30);
    // After the 413, every batch fit the collector's cap.
    let sizes: Vec<usize> = fake
        .requests_to("/v1/events")
        .iter()
        .filter_map(|r| r.json_body()?.as_array().map(Vec::len))
        .collect();
    assert!(
        sizes.iter().skip_while(|n| **n > 8).all(|n| *n <= 8),
        "{sizes:?}"
    );
    // Events keep the site they were emitted with.
    assert_eq!(fake.state().events[0]["source"]["site"], "hall");
}
