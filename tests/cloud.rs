mod common;

use common::*;
use meros_client::fake::{FakeMeros, PERSONAL};
use serde_json::{Map, Value, json};

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

#[tokio::test]
async fn profiles_merge_per_key_and_null_deletes() {
    let fake = FakeMeros::new();
    let a = signed_in(&fake).await;
    let c = cloud(&fake, &a);
    assert!(c.profile("example-app").await.unwrap().keys.is_empty());
    c.put_profile("example-app", obj(json!({"theme": "dark", "zoom": 2})))
        .await
        .unwrap();
    let p = c
        .put_profile("example-app", obj(json!({"zoom": null, "lang": "en"})))
        .await
        .unwrap();
    assert_eq!(
        Value::Object(p.keys),
        json!({"theme": "dark", "lang": "en"})
    );
    assert!(p.updated.contains_key("theme"));
    c.delete_profile("example-app").await.unwrap();
    assert!(c.profile("example-app").await.unwrap().keys.is_empty());
}

#[tokio::test]
async fn documents_version_conflict_and_delete() {
    let fake = FakeMeros::new();
    let a = signed_in(&fake).await;
    let c = cloud(&fake, &a);
    let v1 = c
        .put_doc(
            "example-app",
            "settings",
            "main",
            obj(json!({"a": 1})),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(v1, 1);
    let v2 = c
        .put_doc(
            "example-app",
            "settings",
            "main",
            obj(json!({"a": 2})),
            Some(1),
            None,
        )
        .await
        .unwrap();
    assert_eq!(v2, 2);
    let e = c
        .put_doc(
            "example-app",
            "settings",
            "main",
            obj(json!({"a": 3})),
            Some(1),
            None,
        )
        .await
        .unwrap_err();
    assert!(e.conflict());
    assert_eq!((e.status, e.head_version), (Some(409), Some(2)));

    let doc = c
        .get_doc("example-app", "settings", "main", None, None)
        .await
        .unwrap();
    assert_eq!((doc.version, doc.head_version), (2, 2));
    assert_eq!(Value::Object(doc.body), json!({"a": 2}));
    let list = c.list_docs("example-app", "settings", None).await.unwrap();
    assert_eq!((list[0].key.as_str(), list[0].head_version), ("main", 2));
    // Free accounts keep only the latest version.
    assert_eq!(
        c.doc_versions("example-app", "settings", "main", None)
            .await
            .unwrap()
            .len(),
        1
    );

    c.delete_doc("example-app", "settings", "main", None)
        .await
        .unwrap();
    c.delete_doc("example-app", "settings", "main", None)
        .await
        .unwrap();
    c.delete_doc("example-app", "settings", "never", None)
        .await
        .unwrap();
    assert!(
        c.get_doc("example-app", "settings", "main", None, None)
            .await
            .unwrap_err()
            .not_found()
    );
}

#[tokio::test]
async fn paid_history_keeps_versions_and_team_accounts_are_checked() {
    let fake = FakeMeros::new();
    {
        let mut st = fake.state();
        st.features.insert("example-app.backup.history".into());
        st.team = Some("acct-team".into());
    }
    let a = signed_in(&fake).await;
    let c = cloud(&fake, &a);
    for i in 0..3 {
        c.put_doc(
            "example-app",
            "backups",
            "b",
            obj(json!({"i": i})),
            None,
            Some("acct-team"),
        )
        .await
        .unwrap();
    }
    assert_eq!(
        c.doc_versions("example-app", "backups", "b", Some("acct-team"))
            .await
            .unwrap()
            .len(),
        3
    );
    let old = c
        .get_doc("example-app", "backups", "b", Some(1), Some("acct-team"))
        .await
        .unwrap();
    assert_eq!(Value::Object(old.body), json!({"i": 0}));
    let e = c
        .list_docs("example-app", "backups", Some("acct-other"))
        .await
        .unwrap_err();
    assert_eq!(e.code, "forbidden");

    let accounts = c.accounts().await.unwrap();
    assert_eq!(accounts.len(), 2);
    assert!(accounts[1].team && accounts[1].is_default);
    assert_eq!(accounts[0].id, PERSONAL);
    let f = c.features("example-app", None).await.unwrap();
    assert!(f.contains("example-app.backup.history") && !f.contains("tier"));
    assert_eq!(
        c.tier("example-app", Some("acct-team")).await.unwrap(),
        "pro"
    );
    assert_eq!(
        c.features("example-app", Some("acct-other"))
            .await
            .unwrap_err()
            .code,
        "forbidden"
    );
}

#[tokio::test]
async fn files_upload_once_download_checked_and_refuse_with_distinct_codes() {
    let fake = FakeMeros::new();
    let a = signed_in(&fake).await;
    let c = cloud(&fake, &a);
    let lut = b"LUT_3D_SIZE 2\n0 0 0\n".to_vec();
    let f = c.put_file("example-app", "luts", &lut, None).await.unwrap();
    assert!(f.stored());
    assert_eq!(f.sha256, meros_client::file_hash(&lut));
    // The same bytes again: nothing is uploaded.
    let puts = || {
        fake.state()
            .requests
            .iter()
            .filter(|r| r.method == "PUT")
            .count()
    };
    let before = puts();
    c.put_file("example-app", "luts", &lut, None).await.unwrap();
    assert_eq!(puts(), before);

    assert_eq!(
        c.list_files("example-app", "luts", None)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        c.file("example-app", "luts", &f.sha256, None)
            .await
            .unwrap()
            .download_url
            .is_some()
    );
    assert_eq!(
        c.download_file("example-app", "luts", &f.sha256, None)
            .await
            .unwrap(),
        lut
    );

    fake.state().file_cap = 4;
    assert_eq!(
        c.put_file("example-app", "luts", b"too big", None)
            .await
            .unwrap_err()
            .code,
        "file_too_large"
    );
    {
        let mut st = fake.state();
        st.file_cap = 1 << 20;
        st.file_quota = lut.len() + 3;
    }
    assert_eq!(
        c.put_file("example-app", "luts", b"four", None)
            .await
            .unwrap_err()
            .code,
        "quota_exceeded"
    );
    {
        let mut st = fake.state();
        st.file_quota = 1 << 20;
        st.damage_uploads = true;
    }
    let e = c
        .put_file("example-app", "luts", b"damaged", None)
        .await
        .unwrap_err();
    assert_eq!((e.status, e.code.as_str()), (Some(422), "file_mismatch"));

    c.delete_file("example-app", "luts", &f.sha256, None)
        .await
        .unwrap();
    c.delete_file("example-app", "luts", &f.sha256, None)
        .await
        .unwrap();
    assert!(
        c.file("example-app", "luts", &f.sha256, None)
            .await
            .unwrap_err()
            .not_found()
    );
}

#[tokio::test]
async fn an_expired_token_is_refreshed_and_the_request_retried_once() {
    let fake = FakeMeros::new();
    let a = signed_in(&fake).await;
    let c = cloud(&fake, &a);
    fake.state().expire_access_tokens();
    c.profile("example-app").await.unwrap();
    assert_eq!(fake.requests_to("/v1/profiles/example-app").len(), 2);
    assert_eq!(fake.requests_to("/oauth/token").len(), 2);
}

#[tokio::test]
async fn a_signed_out_user_gets_signed_out_not_a_network_call() {
    let fake = FakeMeros::new();
    let a = auth(&fake);
    let c = cloud(&fake, &a);
    assert_eq!(c.accounts().await.unwrap_err().code, "signed_out");
    assert!(fake.state().requests.is_empty());
}
