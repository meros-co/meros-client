//! Real requests to a staging service, through the reqwest transport, that
//! change nothing there: refusals only. Skipped unless the host is given in
//! `MEROS_STAGING_DEVICE_BASE`: a product's staging device base
//! (`<host>/app/<product>`, or a service's own root).
//!
//! Never point it at production. No test here sends a deliberately bad
//! bearer token: those raise alerts on the service.

use std::sync::Arc;

use meros_client::testing::TestDevice;
use meros_client::{LicenseClient, LicenseConfig, ReqwestTransport, SupportApi, Transport};

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

#[tokio::test]
async fn the_device_api_refuses_an_unknown_key_and_device() {
    let Some(base) = env("MEROS_STAGING_DEVICE_BASE") else {
        eprintln!("skipped: MEROS_STAGING_DEVICE_BASE is not set");
        return;
    };
    let transport: Arc<dyn Transport> = Arc::new(ReqwestTransport::new());
    let device = Arc::new(TestDevice::new("d_meros_client_staging_check"));
    let license = LicenseClient::new(
        LicenseConfig {
            base_url: base.clone(),
            app_name: "Staging check".into(),
            app_version: "0.0.0".into(),
        },
        transport.clone(),
        device.clone(),
    );
    let e = license.activate("NOT-A-REAL-KEY", None).await.unwrap_err();
    assert_eq!(
        (e.status, e.code.as_str()),
        (Some(404), "unknown_license_key"),
        "{e:?}"
    );
    assert!(!license.renew(Default::default()).await);

    let support = SupportApi::new(base, "0.0.0", transport, device);
    let e = support.list().await.unwrap_err();
    // Services answer an unknown device with 401 or 404.
    assert!(matches!(e.status, Some(401 | 404)), "{e:?}");
    assert!(
        ["unknown_device", "bad_signature"].contains(&e.code.as_str()),
        "{e:?}"
    );
}
