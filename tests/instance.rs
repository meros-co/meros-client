//! Cloud-managed users: the instance's members, asked as the instance and
//! verified against the product key, against the fake.

mod common;

use std::sync::Arc;

use common::*;
use meros_client::fake::{FakeMeros, server_keys};
use meros_client::testing::TestDevice;
use meros_client::{DeviceSigner, InstanceClient, verify_members};
use serde_json::json;

fn keys() -> Vec<(String, String)> {
    server_keys()
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect()
}

/// An instance meros.co knows (its device activated).
fn known(fake: &Arc<FakeMeros>, id: &str) -> Arc<TestDevice> {
    let device = Arc::new(TestDevice::new(id));
    fake.state()
        .devices
        .insert(id.into(), device.identity().unwrap().pubkey);
    device
}

fn client(fake: &Arc<FakeMeros>, device: &Arc<TestDevice>) -> InstanceClient {
    InstanceClient::new(ISSUER, "example-app", keys(), fake.clone(), device.clone())
}

#[tokio::test]
async fn an_instance_gets_its_members_as_itself_and_a_signed_statement() {
    let fake = FakeMeros::new();
    let device = known(&fake, "rack-1");
    let c = client(&fake, &device);
    let a = c.members(None).await.unwrap();
    assert!(!a.unchanged);
    let m = &a.members;
    assert!(m.enabled && m.reason.is_none());
    assert_eq!(
        (m.product.as_str(), m.device_id.as_str()),
        ("example-app", "rack-1")
    );
    assert_eq!(m.exp - m.iat, 7 * 86_400);
    assert_eq!(m.member("u1").unwrap().role.as_deref(), Some("admin"));
    assert!(m.member("nobody").is_none());
    // Signed with the device key, no person's token.
    let sent = fake.requests_to("/v1/instance/members").pop().unwrap();
    assert!(sent.header_value("Authorization").is_none());
    let body = String::from_utf8(sent.body.clone()).unwrap();
    assert!(body.contains("&sig=") && body.contains("nonce="));

    // The same version: unchanged, with a fresh statement.
    let again = c.members(Some(&m.version)).await.unwrap();
    assert!(again.unchanged);
    assert_eq!(again.members.version, m.version);

    // A change on meros.co: a new version, and a member without access.
    fake.state().instance_members.push(json!({
        "sub": "u2", "name": "Sam", "email": "sam@example.com", "team_role": "billing", "role": null
    }));
    let changed = c.members(Some(&m.version)).await.unwrap();
    assert!(!changed.unchanged);
    assert_ne!(changed.members.version, m.version);
    assert!(changed.members.member("u2").is_none(), "no role, no access");
    assert_eq!(changed.members.members.len(), 2);
}

#[tokio::test]
async fn a_gate_that_is_off_says_why() {
    let fake = FakeMeros::new();
    let device = known(&fake, "rack-1");
    {
        let mut st = fake.state();
        st.members_enabled = false;
        st.members_reason = Some("no_team_addon".into());
    }
    let m = client(&fake, &device).members(None).await.unwrap().members;
    assert!(!m.enabled);
    assert_eq!(m.reason.as_deref(), Some("no_team_addon"));
}

#[tokio::test]
async fn an_unknown_instance_is_refused() {
    let fake = FakeMeros::new();
    let device = Arc::new(TestDevice::new("stranger"));
    let e = client(&fake, &device).members(None).await.unwrap_err();
    assert_eq!((e.status, e.code.as_str()), (Some(404), "unknown_device"));
}

#[tokio::test]
async fn statements_verify_only_for_their_product_device_and_key() {
    let fake = FakeMeros::new();
    let device = known(&fake, "rack-1");
    let token = client(&fake, &device)
        .members(None)
        .await
        .unwrap()
        .statement;
    let pubkey = device.identity().unwrap().pubkey;
    let k = keys();
    let table: Vec<(&str, &str)> = k.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    assert!(verify_members(&table, &token, "example-app", "rack-1", &pubkey).is_ok());
    assert!(verify_members(&table, &token, "other-app", "rack-1", &pubkey).is_err());
    assert!(verify_members(&table, &token, "example-app", "rack-2", &pubkey).is_err());
    let (payload, sig) = token.split_once('.').unwrap();
    let tampered = format!("{}x.{sig}", &payload[..payload.len() - 1]);
    assert!(verify_members(&table, &tampered, "example-app", "rack-1", &pubkey).is_err());
    assert!(
        verify_members(
            &[("other-kid", &k[0].1)],
            &token,
            "example-app",
            "rack-1",
            &pubkey
        )
        .is_err()
    );
    let s = verify_members(&table, &token, "example-app", "rack-1", &pubkey).unwrap();
    assert!(!s.expired(s.iat) && s.expired(s.exp));
}
