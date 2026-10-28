//! The device's side of licensing and support: who it is, how it signs, and
//! where its entitlement goes. The key stays with whatever already holds it
//! (the app's own crate, or an entitlement store); the clients only ask for
//! an id, a public key and signatures, so an existing device keeps its id,
//! key and seat.

/// The device's identity: its id and its base64url Ed25519 public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub id: String,
    pub pubkey: String,
}

/// Signs device API requests. Implemented by whatever holds the key.
pub trait DeviceSigner: Send + Sync {
    /// The identity, created on first use; None when it's unavailable.
    fn identity(&self) -> Option<DeviceIdentity>;

    /// base64url Ed25519 signature over `"{method}|{path}|{device_id}|{ts}"`,
    /// or None when the identity is unavailable.
    fn sign(&self, method: &str, path: &str, ts: i64) -> Option<String>;
}

/// A [`DeviceSigner`] that also keeps the entitlement and describes the
/// device for its record on the service.
pub trait LicenseDevice: DeviceSigner {
    /// Verifies and stores an entitlement token; the reason on refusal.
    fn apply_token(&self, token: &str) -> Result<(), String>;

    /// Drops the stored entitlement.
    fn clear_token(&self);

    /// A short model string from the platform ("SM-X518U", "iPad13,1").
    fn model(&self) -> String {
        "Device".into()
    }

    /// The device's own name from the platform ("Galaxy S24+"); None or
    /// empty uses the default "{app} {os} ({model})".
    fn name(&self) -> Option<String> {
        None
    }
}

/// A device for tests: a fixed Ed25519 key, tokens kept in memory.
#[cfg(any(test, feature = "fake"))]
pub mod testing {
    use std::sync::Mutex;

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    pub struct TestDevice {
        pub id: String,
        key: SigningKey,
        /// The applied token, if any.
        pub token: Mutex<Option<String>>,
        /// Tokens [`apply_token`](LicenseDevice::apply_token) refuses.
        pub refuse: Mutex<Option<String>>,
        pub model: String,
        pub name: Option<String>,
    }

    impl TestDevice {
        pub fn new(id: &str) -> TestDevice {
            let mut seed = [0u8; 32];
            for (i, b) in id.bytes().enumerate() {
                seed[i % 32] ^= b;
            }
            TestDevice {
                id: id.to_string(),
                key: SigningKey::from_bytes(&seed),
                token: Mutex::new(None),
                refuse: Mutex::new(None),
                model: "SM-X518U".into(),
                name: None,
            }
        }

        pub fn token(&self) -> Option<String> {
            self.token.lock().unwrap().clone()
        }
    }

    impl DeviceSigner for TestDevice {
        fn identity(&self) -> Option<DeviceIdentity> {
            Some(DeviceIdentity {
                id: self.id.clone(),
                pubkey: URL_SAFE_NO_PAD.encode(self.key.verifying_key().to_bytes()),
            })
        }

        fn sign(&self, method: &str, path: &str, ts: i64) -> Option<String> {
            let input = format!("{method}|{path}|{}|{ts}", self.id);
            Some(URL_SAFE_NO_PAD.encode(self.key.sign(input.as_bytes()).to_bytes()))
        }
    }

    impl LicenseDevice for TestDevice {
        fn apply_token(&self, token: &str) -> Result<(), String> {
            if let Some(reason) = self.refuse.lock().unwrap().clone() {
                return Err(reason);
            }
            *self.token.lock().unwrap() = Some(token.to_string());
            Ok(())
        }

        fn clear_token(&self) {
            *self.token.lock().unwrap() = None;
        }

        fn model(&self) -> String {
            self.model.clone()
        }

        fn name(&self) -> Option<String> {
            self.name.clone()
        }
    }
}
