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

/// A [`LicenseDevice`] over a meros-entitlement [`Store`]: the Store's own
/// device id, seed and token file, so a device already activated through it
/// keeps its id, key and seat.
///
/// [`Store`]: meros_entitlement::Store
#[cfg(feature = "entitlement")]
pub struct EntitlementDevice<F: 'static> {
    store: &'static meros_entitlement::Store<F>,
    model: String,
    name: Option<String>,
}

#[cfg(feature = "entitlement")]
impl<F> EntitlementDevice<F>
where
    F: serde::de::DeserializeOwned + Clone + 'static,
{
    /// `model` and `name` come from the platform.
    pub fn new(
        store: &'static meros_entitlement::Store<F>,
        model: impl Into<String>,
        name: Option<String>,
    ) -> Self {
        EntitlementDevice {
            store,
            model: model.into(),
            name,
        }
    }
}

#[cfg(feature = "entitlement")]
impl<F> DeviceSigner for EntitlementDevice<F>
where
    F: serde::de::DeserializeOwned + Clone + 'static,
{
    fn identity(&self) -> Option<DeviceIdentity> {
        let (id, _) = self.store.device_identity()?;
        Some(DeviceIdentity {
            id,
            pubkey: self.store.device_pubkey()?,
        })
    }

    fn sign(&self, method: &str, path: &str, ts: i64) -> Option<String> {
        self.store
            .sign_request(method, path, ts)
            .map(|(_, sig)| sig)
    }
}

#[cfg(feature = "entitlement")]
impl<F> LicenseDevice for EntitlementDevice<F>
where
    F: serde::de::DeserializeOwned + Clone + 'static,
{
    fn apply_token(&self, token: &str) -> Result<(), String> {
        self.store.apply_token(token)
    }

    fn clear_token(&self) {
        self.store.clear_token();
    }

    fn model(&self) -> String {
        self.model.clone()
    }

    fn name(&self) -> Option<String> {
        self.name.clone()
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

        /// A device with id `id` but a key made from `key`, as a second
        /// install claiming the same id would have.
        pub fn with_key(id: &str, key: &str) -> TestDevice {
            let mut d = TestDevice::new(key);
            d.id = id.to_string();
            d
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

#[cfg(all(test, feature = "entitlement"))]
mod entitlement_tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    #[derive(Clone, serde::Deserialize)]
    struct Features {}

    static STORE: meros_entitlement::Store<Features> =
        meros_entitlement::Store::new(&[], || Features {});

    #[test]
    fn an_entitlement_store_keeps_its_device_id_and_key() {
        let dir = tempfile::tempdir().unwrap();
        STORE.init(dir.path().to_str().unwrap());
        let device = EntitlementDevice::new(&STORE, "Model-1", Some("Desk".into()));
        let id = device.identity().unwrap();
        // The id and key the Store made are the ones the client signs with.
        assert_eq!(id.id, STORE.device_identity().unwrap().0);
        let again = EntitlementDevice::new(&STORE, "Model-1", None)
            .identity()
            .unwrap();
        assert_eq!(again, id);
        let sig = device
            .sign("POST", "/v1/device/renew", 1_790_000_000)
            .unwrap();
        let key: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&id.pubkey)
            .unwrap()
            .try_into()
            .unwrap();
        let sig = Signature::from_slice(&URL_SAFE_NO_PAD.decode(sig).unwrap()).unwrap();
        VerifyingKey::from_bytes(&key)
            .unwrap()
            .verify(
                format!("POST|/v1/device/renew|{}|1790000000", id.id).as_bytes(),
                &sig,
            )
            .unwrap();
        assert_eq!(
            (device.model(), device.name()),
            ("Model-1".to_string(), Some("Desk".to_string()))
        );
        // A token that doesn't verify is refused with the Store's reason.
        assert!(device.apply_token("not-a-token").is_err());
    }
}
