#![allow(dead_code)]

use std::sync::Arc;

use meros_client::fake::FakeMeros;
use meros_client::testing::TestDevice;
use meros_client::{
    AuthConfig, LicenseClient, LicenseConfig, MemoryTokenStore, MerosAuth, MerosCloud,
};

pub const ISSUER: &str = "https://id.example.test";
pub const BASE: &str = "https://id.example.test/app/example-app";

pub fn auth(fake: &Arc<FakeMeros>) -> Arc<MerosAuth> {
    Arc::new(MerosAuth::new(
        AuthConfig {
            issuer: ISSUER.into(),
            client_id: "client-1".into(),
            redirect_uri: "exampleapp://oauth/callback".into(),
            scopes: vec!["openid".into(), "offline_access".into()],
        },
        fake.clone(),
        Arc::new(MemoryTokenStore::default()),
    ))
}

/// A signed-in session.
pub async fn signed_in(fake: &Arc<FakeMeros>) -> Arc<MerosAuth> {
    let a = auth(fake);
    let page = a.begin_sign_in().await;
    a.complete_sign_in(&fake.approve(&page)).await.unwrap();
    a
}

pub fn cloud(fake: &Arc<FakeMeros>, auth: &Arc<MerosAuth>) -> MerosCloud {
    MerosCloud::new(ISSUER, fake.clone(), auth.clone())
}

pub fn license(fake: &Arc<FakeMeros>, device: &Arc<TestDevice>) -> LicenseClient {
    LicenseClient::new(
        LicenseConfig {
            base_url: BASE.into(),
            app_name: "Example".into(),
            app_version: "2.0.1".into(),
        },
        fake.clone(),
        device.clone(),
    )
}
