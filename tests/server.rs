mod common;

use std::sync::{Arc, Mutex};

use common::*;
use meros_client::fake::{FakeMeros, PERSONAL, UNOWNED, server_keys};
use meros_client::testing::TestDevice;
use meros_client::{
    DeviceIdentity, DeviceSigner, ServerConfig, ServerDevice, ServerLicence, ServerLicenseClient,
    ServerRenewal, Transport, verify_licence,
};
use serde_json::Map;

/// An instance that verifies statements against the fake's key table.
struct Instance {
    key: TestDevice,
    held: Mutex<Option<ServerLicence>>,
}

impl Instance {
    fn new(id: &str) -> Arc<Instance> {
        Arc::new(Instance {
            key: TestDevice::new(id),
            held: Mutex::new(None),
        })
    }
    fn licence(&self) -> Option<ServerLicence> {
        self.held.lock().unwrap().clone()
    }
}

impl DeviceSigner for Instance {
    fn identity(&self) -> Option<DeviceIdentity> {
        self.key.identity()
    }
    fn sign(&self, method: &str, path: &str, ts: i64) -> Option<String> {
        self.key.sign(method, path, ts)
    }
}

impl ServerDevice for Instance {
    fn apply(&self, licence: &str, _token: &str) -> Result<(), String> {
        let keys = server_keys();
        let table: Vec<(&str, &str)> = keys.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let me = self.identity().unwrap();
        let l = verify_licence(&table, licence, "example-app", &me.id, &me.pubkey)?;
        *self.held.lock().unwrap() = Some(l);
        Ok(())
    }
    fn clear(&self) {
        *self.held.lock().unwrap() = None;
    }
}

fn client(fake: &Arc<FakeMeros>, i: &Arc<Instance>) -> ServerLicenseClient {
    ServerLicenseClient::new(
        ServerConfig {
            base_url: ISSUER.into(),
            product: "example-app".into(),
            app_name: "Example Server".into(),
            app_version: "1.0.0".into(),
        },
        fake.clone(),
        i.clone(),
    )
}

#[tokio::test]
async fn a_key_activates_one_instance_renews_and_releases() {
    let fake = FakeMeros::new();
    fake.state()
        .server_keys
        .insert("SRV-1".into(), PERSONAL.into());
    let a = Instance::new("srv-a");
    let c = client(&fake, &a);
    c.activate("SRV-1", None).await.unwrap();
    let l = a.licence().unwrap();
    assert_eq!(
        (l.licence.as_str(), l.edition.as_str()),
        ("perpetual", "server")
    );
    assert!(l.covers_build("2027-01-01") && !l.covers_build("2028-01-01"));
    let sent = fake.requests_to("/v1/device/activate")[0]
        .json_body()
        .unwrap();
    assert_eq!(sent["product"], "example-app");

    // One instance at a time.
    let b = Instance::new("srv-b");
    let e = client(&fake, &b).activate("SRV-1", None).await.unwrap_err();
    assert_eq!(e.code, "no_seats_available");

    // A later updates_until arrives at renewal.
    fake.state().updates_until = "2028-10-17".into();
    assert_eq!(c.renew(Map::new()).await, ServerRenewal::Renewed);
    assert_eq!(a.licence().unwrap().updates_until, "2028-10-17");

    // Release, then move.
    c.release().await.unwrap();
    assert!(a.licence().is_none());
    client(&fake, &b).activate("SRV-1", None).await.unwrap();
    assert!(b.licence().is_some());
}

#[tokio::test]
async fn offline_is_refused_for_server_keys() {
    let fake = FakeMeros::new();
    fake.state()
        .server_keys
        .insert("SRV-1".into(), PERSONAL.into());
    let r = fake
        .send(
            meros_client::HttpRequest::new("POST", format!("{ISSUER}/v1/offline/activate"))
                .json(&serde_json::json!({"license_key": "SRV-1", "product": "example-app"})),
        )
        .await
        .unwrap();
    assert_eq!(
        (r.status, r.error_code().as_deref()),
        (403, Some("offline_not_allowed"))
    );
}

#[tokio::test]
async fn a_login_activates_from_the_accounts_free_keys() {
    let fake = FakeMeros::new();
    let a = signed_in(&fake).await;
    let i = Instance::new("srv-login");
    let c = client(&fake, &i);
    let e = c
        .activate_with_login(a.as_ref(), None, None)
        .await
        .unwrap_err();
    assert_eq!(e.code, "no_licence");
    fake.state()
        .server_keys
        .insert("SRV-P".into(), PERSONAL.into());
    c.activate_with_login(a.as_ref(), None, None).await.unwrap();
    assert_eq!(i.licence().unwrap().account_id, PERSONAL);
    let sent = fake
        .requests_to("/v1/server/activate")
        .last()
        .unwrap()
        .clone();
    assert!(
        sent.header_value("Authorization")
            .unwrap()
            .starts_with("Bearer ")
    );
    // Again: the same key, refreshed.
    c.activate_with_login(a.as_ref(), None, None).await.unwrap();
    assert_eq!(fake.state().server_key_holders.len(), 1);

    let e = c
        .activate_with_login(a.as_ref(), Some("acct-not-mine"), None)
        .await
        .unwrap_err();
    assert_eq!(e.code, "forbidden");
    fake.state().licenses_scope = false;
    let e = c
        .activate_with_login(a.as_ref(), None, None)
        .await
        .unwrap_err();
    assert_eq!(
        (e.status, e.code.as_str()),
        (Some(403), "insufficient_scope")
    );
}

#[tokio::test]
async fn a_login_adopts_an_unowned_key_and_refuses_another_install() {
    let fake = FakeMeros::new();
    fake.state()
        .server_keys
        .insert("GUEST".into(), UNOWNED.into());
    let i = Instance::new("srv-guest");
    let c = client(&fake, &i);
    c.activate("GUEST", None).await.unwrap();
    assert_eq!(i.licence().unwrap().account_id, "");

    let a = signed_in(&fake).await;
    c.activate_with_login(a.as_ref(), None, None).await.unwrap();
    assert_eq!(
        i.licence().unwrap().account_id,
        PERSONAL,
        "adopted, the same seat"
    );
    assert_eq!(fake.state().server_keys["GUEST"], PERSONAL);

    // Another install claiming the same id with its own key.
    fake.state()
        .server_keys
        .insert("OTHER".into(), "acct-other".into());
    fake.state()
        .server_keys
        .insert("GUEST".into(), "acct-other".into());
    let impostor = Arc::new(Instance {
        key: TestDevice::with_key("srv-guest", "a different key"),
        held: Mutex::new(None),
    });
    let e = client(&fake, &impostor)
        .activate_with_login(a.as_ref(), None, None)
        .await
        .unwrap_err();
    assert_eq!(e.code, "device_id_in_use");
    assert!(e.message.contains("Release it there first"));
}

#[tokio::test]
async fn renewal_tells_revoked_from_suspended() {
    let fake = FakeMeros::new();
    fake.state()
        .server_keys
        .insert("SRV-R".into(), PERSONAL.into());
    let i = Instance::new("srv-r");
    let c = client(&fake, &i);
    c.activate("SRV-R", None).await.unwrap();

    fake.state().suspended_keys.insert("SRV-R".into());
    let r = c.renew(Map::new()).await;
    assert!(
        matches!(r, ServerRenewal::Suspended(ref e) if e.license_key_disabled()),
        "{r:?}"
    );
    assert!(i.licence().is_some(), "keeps running");
    fake.state().suspended_keys.clear();

    fake.state().revoked_keys.insert("SRV-R".into());
    assert_eq!(c.renew(Map::new()).await, ServerRenewal::Revoked);
    assert!(i.licence().is_none(), "deactivated");
}

#[test]
fn statements_from_another_key_or_device_are_refused() {
    let keys = server_keys();
    let table: Vec<(&str, &str)> = keys.iter().map(|(k, v)| (*k, v.as_str())).collect();
    assert!(verify_licence(&table, "garbage", "example-app", "d", "k").is_err());
    assert!(verify_licence(&[], "e30.AAAA", "example-app", "d", "k").is_err());
}
