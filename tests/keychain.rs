//! The helper's sealing key in the OS keychain (`key_source: "keychain"`):
//! Windows Credential Manager, the macOS Keychain, or the Secret Service on
//! Linux, with a key file beside the state directory when the machine has
//! none. The real-keychain test makes one entry under a unique service and
//! deletes it; it skips where no keychain answers (a headless Linux box).

use meros_client::cli::{self, exit};
use meros_client::fake::FakeMeros;
use serde_json::{Value, json};

/// `MEROS_CLIENT_KEYCHAIN` is process-wide: run these one at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct KeychainOff;

impl KeychainOff {
    fn new() -> KeychainOff {
        // SAFETY: the tests touching the environment hold SERIAL.
        unsafe { std::env::set_var("MEROS_CLIENT_KEYCHAIN", "off") };
        KeychainOff
    }
}

impl Drop for KeychainOff {
    fn drop(&mut self) {
        // SAFETY: as above.
        unsafe { std::env::remove_var("MEROS_CLIENT_KEYCHAIN") };
    }
}

async fn run(dir: &std::path::Path, command: &str, extra: Value) -> cli::Outcome {
    let mut input = json!({
        "state_dir": dir.join("state").to_str().unwrap(),
        "issuer": "https://id.example.test",
        "client_id": "client-1",
    });
    for (k, v) in extra.as_object().unwrap() {
        input[k] = v.clone();
    }
    cli::run(command, input, FakeMeros::new()).await
}

fn unique_service() -> String {
    format!("meros-client-test-{}-{}", std::process::id(), rand_suffix())
}

fn rand_suffix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

#[tokio::test]
async fn the_key_lives_in_the_os_keychain_and_seals_the_state() {
    let _one = SERIAL.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let service = unique_service();
    let source = json!({"key_source": "keychain", "keychain_service": service, "keychain_account": "state-1"});
    let first = run(dir.path(), "device.identity", source.clone()).await;
    assert_eq!(first.exit, exit::OK, "{}", first.output);
    if first.output["key_source"] != "keychain" {
        eprintln!(
            "SKIPPED: no OS keychain here ({})",
            first.output["key_source"]
        );
        return;
    }
    let entry = keyring::Entry::new(&service, "state-1").unwrap();
    let stored = entry.get_password().unwrap();
    assert_eq!(stored.len(), 64);
    // Sealed: the device key isn't readable on disk, and no key file was made.
    let device = std::fs::read_to_string(dir.path().join("state/device.json")).unwrap();
    assert!(device.contains("\"sealed\"") && !device.contains("seed"));
    assert!(!dir.path().join("state.key").exists());
    let marker = std::fs::read_to_string(dir.path().join("state/key-source.json")).unwrap();
    assert!(marker.contains("keychain") && !marker.contains(&stored));

    // The same key next time; read-only commands report it too.
    let again = run(dir.path(), "device.identity", source.clone()).await;
    assert_eq!(again.output["device_id"], first.output["device_id"]);
    let status = run(dir.path(), "signin.status", source.clone()).await;
    assert_eq!(status.output["key_source"], "keychain");

    // Without the key the files are refused, never replaced.
    let without = run(dir.path(), "device.identity", json!({})).await;
    assert_eq!(without.exit, exit::LOCAL, "{}", without.output);

    // A state set up on the keychain never falls back to a file.
    {
        let _off = KeychainOff::new();
        let off = run(dir.path(), "device.identity", source.clone()).await;
        assert_eq!(off.exit, exit::LOCAL, "{}", off.output);
        assert_eq!(off.output["error"]["code"], "state_error");
        assert!(!dir.path().join("state.key").exists());
    }
    entry.delete_credential().unwrap();
}

#[tokio::test]
async fn without_a_keychain_the_key_goes_in_a_file_beside_the_state() {
    let _one = SERIAL.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let source = json!({"key_source": "keychain", "keychain_service": unique_service()});
    let first = {
        let _off = KeychainOff::new();
        let first = run(dir.path(), "device.identity", source.clone()).await;
        assert_eq!(first.exit, exit::OK, "{}", first.output);
        assert_eq!(first.output["key_source"], "file");
        first
    };
    let key_file = dir.path().join("state.key");
    assert_eq!(std::fs::read_to_string(&key_file).unwrap().trim().len(), 64);
    let device = std::fs::read_to_string(dir.path().join("state/device.json")).unwrap();
    assert!(device.contains("\"sealed\""));
    // Once set up on the file it stays there, keychain or not.
    let again = run(dir.path(), "device.identity", source.clone()).await;
    assert_eq!(again.output["key_source"], "file");
    assert_eq!(again.output["device_id"], first.output["device_id"]);
    let status = run(dir.path(), "signin.status", source).await;
    assert_eq!(status.output["key_source"], "file");
}

#[tokio::test]
async fn the_key_source_is_reported_and_checked() {
    let _one = SERIAL.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let plain = run(dir.path(), "device.identity", json!({})).await;
    assert_eq!(plain.output["key_source"], "none");
    let key_file = dir.path().join("k.key");
    let file = run(
        dir.path(),
        "signin.status",
        json!({"key_source": "file", "key_file": key_file.to_str().unwrap()}),
    )
    .await;
    assert_eq!(file.output["key_source"], "file");
    for bad in [
        json!({"key_source": "file"}),
        json!({"key_source": "vault"}),
    ] {
        let o = run(dir.path(), "device.identity", bad).await;
        assert_eq!(o.exit, exit::USAGE, "{}", o.output);
    }
    // A fallback inside the state directory protects nothing.
    let _off = KeychainOff::new();
    let inside = dir.path().join("state").join("k.key");
    let o = run(
        dir.path(),
        "device.identity",
        json!({"key_source": "keychain", "key_file": inside.to_str().unwrap()}),
    )
    .await;
    assert_eq!(o.exit, exit::USAGE, "{}", o.output);
}
