//! Real requests to a staging service, through the reqwest transport, that
//! change nothing there: refusals only. Skipped unless the hosts are given:
//!
//! - `MEROS_STAGING_ISSUER`: the staging issuer origin;
//! - `MEROS_STAGING_DEVICE_BASE`: a product's staging device base
//!   (`<host>/app/<product>`, or a service's own root).
//!
//! Never point these at production.

use std::sync::Arc;

use meros_client::testing::TestDevice;
use meros_client::{
    Collector, Emitter, EmitterConfig, Event, LicenseClient, LicenseConfig, MerosCloud,
    ReqwestTransport, Severity, StaticToken, SupportApi, Transport,
};

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

#[tokio::test]
async fn the_cloud_and_event_ingest_refuse_a_bad_token() {
    let Some(issuer) = env("MEROS_STAGING_ISSUER") else {
        eprintln!("skipped: MEROS_STAGING_ISSUER is not set");
        return;
    };
    let transport: Arc<dyn Transport> = Arc::new(ReqwestTransport::new());
    let cloud = MerosCloud::new(
        issuer.clone(),
        transport.clone(),
        Arc::new(StaticToken("not-a-token".into())),
    );
    let e = cloud.accounts().await.unwrap_err();
    assert_eq!(e.status, Some(401), "{e:?}");

    let dir = tempfile::tempdir().unwrap();
    let emitter = Emitter::open(
        EmitterConfig {
            dir: dir.path().to_path_buf(),
            product: "example-app".into(),
            version: "0.0.0".into(),
            edition: None,
            site: None,
        },
        vec![Collector {
            url: issuer,
            token: Some(Arc::new(StaticToken("not-a-token".into()))),
        }],
        transport,
    )
    .unwrap();
    emitter.emit(Event::new("example-app.check.ran", Severity::Debug));
    let report = emitter.flush().await;
    assert_eq!((report.delivered, report.failed), (0, 1));
    assert_eq!(emitter.pending(), 1, "refused events stay queued");
}
