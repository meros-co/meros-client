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

    /// base64url Ed25519 signature over `message` itself, for requests whose
    /// signed string carries more than those four fields (the sign-in
    /// requests add a body hash). None when the key's holder signs only the
    /// four-field form; those requests then fail with `device_unavailable`.
    fn sign_message(&self, message: &str) -> Option<String> {
        let _ = message;
        None
    }
}

/// 22 random URL-safe characters: the fresh value every signed form carries,
/// since meros.co takes each signature once.
pub(crate) fn nonce() -> String {
    use rand::Rng;
    const ABC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut rng = rand::rng();
    (0..22)
        .map(|_| ABC[rng.random_range(0..ABC.len())] as char)
        .collect()
}

/// A form-encoded request signed with the device key, as meros.co's
/// sign-in and device-registration endpoints take them: `fields`, then
/// `device_id`, `device_pubkey` and `ts`, then `sig` last, over
/// `POST|{path}|{device_id}|{ts}|{hex sha256 of the body before &sig=}`.
/// Callers put a fresh random value in `fields` (a nonce or state): the
/// issuer takes each signature once, and Ed25519 signatures are
/// deterministic.
pub(crate) fn signed_form(
    device: &dyn DeviceSigner,
    endpoint: &str,
    fields: &[(&str, &str)],
    ts: i64,
) -> Result<crate::HttpRequest, crate::Error> {
    use sha2::{Digest, Sha256};
    let id = device.identity().ok_or_else(crate::Error::no_identity)?;
    let ts = ts.to_string();
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(fields)
        .append_pair("device_id", &id.id)
        .append_pair("device_pubkey", &id.pubkey)
        .append_pair("ts", &ts)
        .finish();
    let path = url::Url::parse(endpoint)
        .map(|u| u.path().to_string())
        .unwrap_or_default();
    let hash: String = Sha256::digest(body.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let sig = device
        .sign_message(&format!("POST|{path}|{}|{ts}|{hash}", id.id))
        .ok_or_else(|| {
            crate::Error::new(
                None,
                "device_unavailable",
                "This device's key can't sign these requests.",
            )
        })?;
    // base64url needs no escaping.
    let mut r = crate::HttpRequest::new("POST", endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded");
    r.body = format!("{body}&sig={sig}").into_bytes();
    Ok(r)
}

/// A [`DeviceSigner`] that also keeps the entitlement and describes the
/// device for its record on the service.
pub trait LicenseDevice: DeviceSigner {
    /// Verifies and stores an entitlement token; the reason on refusal.
    fn apply_token(&self, token: &str) -> Result<(), String>;

    /// Drops the stored entitlement.
    fn clear_token(&self);

    /// Whether the device holds an entitlement now (valid or in grace).
    /// [`LicenseClient::adopt_after_sign_in`](crate::LicenseClient::adopt_after_sign_in)
    /// claims only for a licensed device; the default says it doesn't.
    fn has_entitlement(&self) -> bool {
        false
    }

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

    fn has_entitlement(&self) -> bool {
        matches!(
            self.store.current(),
            Some((
                meros_entitlement::Validity::Valid | meros_entitlement::Validity::Grace,
                _
            ))
        )
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

        fn sign_message(&self, message: &str) -> Option<String> {
            Some(URL_SAFE_NO_PAD.encode(self.key.sign(message.as_bytes()).to_bytes()))
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

        fn has_entitlement(&self) -> bool {
            self.token.lock().unwrap().is_some()
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
