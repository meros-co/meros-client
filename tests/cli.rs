mod common;

use std::sync::Arc;

use common::*;
use meros_client::cli::{self, Outcome, exit};
use meros_client::fake::{
    ENTITLEMENT_KID, FakeMeros, PERSONAL, SERVER_KID, entitlement_keys, server_keys,
};
use meros_client::{BoxFuture, Error, HttpRequest, HttpResponse, Transport};
use serde_json::{Value, json};

/// A state directory and a fake service, called the way the binary calls.
struct Env {
    fake: Arc<FakeMeros>,
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Env {
        Env {
            fake: FakeMeros::new(),
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn base(&self) -> Value {
        json!({
            "state_dir": self.dir.path().join("state").to_str().unwrap(),
            "issuer": ISSUER,
            "product": "example-app",
            "app_name": "Example",
            "app_version": "1.2.3",
            "client_id": "client-1",
            "scopes": ["openid", "offline_access", "licenses:activate"],
            "keys": {
                SERVER_KID: server_keys()[0].1,
                ENTITLEMENT_KID: entitlement_keys()[0].1,
            },
        })
    }

    async fn run(&self, command: &str, extra: Value) -> Outcome {
        let mut input = self.base();
        for (k, v) in extra.as_object().cloned().unwrap_or_default() {
            input[k] = v;
        }
        cli::run(command, input, self.fake.clone()).await
    }

    async fn ok(&self, command: &str, extra: Value) -> Value {
        let o = self.run(command, extra).await;
        assert_eq!(o.exit, exit::OK, "{command}: {}", o.output);
        assert_eq!(o.output["ok"], true);
        o.output
    }

    async fn refused(&self, command: &str, extra: Value) -> (i32, String) {
        let o = self.run(command, extra).await;
        assert_eq!(o.output["ok"], false, "{command}: {}", o.output);
        (
            o.exit,
            o.output["error"]["code"].as_str().unwrap().to_string(),
        )
    }

    /// Signs in through the device grant, approving on the fake.
    async fn sign_in(&self) {
        let start = self.ok("signin.start", json!({})).await;
        self.fake
            .approve_device(start["user_code"].as_str().unwrap());
        let done = self.ok("signin.poll", json!({})).await;
        assert_eq!(done["status"], "signed_in");
    }

    fn state_file(&self, name: &str) -> std::path::PathBuf {
        self.dir.path().join("state").join(name)
    }
}

#[tokio::test]
async fn the_device_key_is_made_once_kept_and_private() {
    let env = Env::new();
    let first = env.ok("device.identity", json!({})).await;
    let again = env.ok("device.identity", json!({})).await;
    assert_eq!(first["device_id"], again["device_id"]);
    assert_eq!(first["pubkey"], again["pubkey"]);
    assert_eq!(first["pubkey"].as_str().unwrap().len(), 43);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode =
            |p: std::path::PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(env.state_file("device.json")), 0o600);
        assert_eq!(mode(env.dir.path().join("state")), 0o700);
    }
}

#[tokio::test]
async fn a_server_key_activates_renews_reports_and_releases() {
    let env = Env::new();
    env.fake
        .state()
        .server_keys
        .insert("SRV-1".into(), PERSONAL.into());
    let me = env.ok("device.identity", json!({})).await;
    let a = env
        .ok(
            "server.activate",
            json!({"license_key": "SRV-1", "device_name": "Rack 2"}),
        )
        .await;
    assert_eq!(a["licence"]["licence"], "perpetual");
    assert_eq!(a["licence"]["device_id"], me["device_id"]);
    assert_eq!(a["licence"]["account_id"], PERSONAL);
    let activate = &env.fake.requests_to("/v1/device/activate")[0];
    assert_eq!(activate.json_body().unwrap()["device"]["name"], "Rack 2");

    let s = env
        .ok("server.status", json!({"build_date": "2027-01-01"}))
        .await;
    assert_eq!(
        (s["active"].clone(), s["covers_build"].clone()),
        (json!(true), json!(true))
    );
    let s = env
        .ok("server.status", json!({"build_date": "2099-01-01"}))
        .await;
    assert_eq!(s["covers_build"], false);

    let r = env
        .ok("server.renew", json!({"device_info": {"uptime": 5}}))
        .await;
    assert_eq!(r["result"], "renewed");
    assert_eq!(r["licence"]["product"], "example-app");

    // The statement verifies on its own too.
    let statement = std::fs::read_to_string(env.state_file("server.json")).unwrap();
    let statement: Value = serde_json::from_str(&statement).unwrap();
    let v = env
        .ok("server.verify", json!({"statement": statement["licence"]}))
        .await;
    assert_eq!(v["licence"]["device_id"], me["device_id"]);
    let tampered = statement["licence"].as_str().unwrap().replacen('e', "f", 1);
    assert_eq!(
        env.refused("server.verify", json!({"statement": tampered}))
            .await,
        (exit::LOCAL, "verify_failed".into())
    );

    env.ok("server.release", json!({})).await;
    assert_eq!(env.ok("server.status", json!({})).await["active"], false);
}

#[tokio::test]
async fn a_revoked_key_deactivates_at_renewal_and_a_suspended_one_keeps_running() {
    let env = Env::new();
    {
        let mut st = env.fake.state();
        st.server_keys.insert("SRV-1".into(), PERSONAL.into());
    }
    env.ok("server.activate", json!({"license_key": "SRV-1"}))
        .await;
    env.fake.state().suspended_keys.insert("SRV-1".into());
    let r = env.ok("server.renew", json!({})).await;
    assert_eq!(r["result"], "suspended");
    assert_eq!(r["error"]["code"], "license_key_disabled");
    assert_eq!(env.ok("server.status", json!({})).await["active"], true);

    env.fake.state().revoked_keys.insert("SRV-1".into());
    let r = env.ok("server.renew", json!({})).await;
    assert_eq!(r["result"], "revoked");
    assert_eq!(env.ok("server.status", json!({})).await["active"], false);
}

#[tokio::test]
async fn a_meros_login_through_the_device_grant_activates_and_keeps_its_session() {
    let env = Env::new();
    env.fake
        .state()
        .server_keys
        .insert("SRV-9".into(), PERSONAL.into());
    assert_eq!(
        env.refused("server.activate_login", json!({})).await,
        (exit::LOCAL, "no_sign_in".into())
    );

    let start = env.ok("signin.start", json!({})).await;
    assert_eq!(start["verification_uri"], format!("{ISSUER}/link"));
    assert_eq!(start["interval"], 5);
    let pending = env.ok("signin.poll", json!({})).await;
    assert_eq!(pending["status"], "pending");
    // Polling again at once is too soon: the interval goes up and is kept.
    let slower = env.ok("signin.poll", json!({})).await;
    assert_eq!(slower["interval"], 10);
    env.fake.state().clock += 10;
    env.fake
        .approve_device(start["user_code"].as_str().unwrap());
    let done = env.ok("signin.poll", json!({})).await;
    assert_eq!(done["status"], "signed_in");
    assert_eq!(done["user"]["id"], "u1");
    let status = env.ok("signin.status", json!({})).await;
    assert_eq!(status["signed_in"], true);

    let a = env.ok("server.activate_login", json!({})).await;
    assert_eq!(a["licence"]["license_id"], "lic-SRV-9");

    // Each call reuses the stored access token instead of rotating the
    // refresh token.
    let tokens = env.fake.requests_to("/oauth/token").len();
    let t1 = env.ok("signin.token", json!({})).await;
    let t2 = env.ok("signin.token", json!({})).await;
    assert_eq!(t1["access_token"], t2["access_token"]);
    assert_eq!(env.fake.requests_to("/oauth/token").len(), tokens);
    let t3 = env.ok("signin.token", json!({"force": true})).await;
    assert_ne!(t3["access_token"], t1["access_token"]);

    env.ok("signin.signout", json!({})).await;
    assert_eq!(env.ok("signin.status", json!({})).await["signed_in"], false);
}

#[tokio::test]
async fn a_declined_or_expired_sign_in_is_refused_and_forgotten() {
    let env = Env::new();
    let start = env.ok("signin.start", json!({})).await;
    env.fake.deny_device(start["user_code"].as_str().unwrap());
    assert_eq!(
        env.refused("signin.poll", json!({})).await,
        (exit::REFUSED, "access_denied".into())
    );
    assert_eq!(
        env.refused("signin.poll", json!({})).await,
        (exit::LOCAL, "no_sign_in".into())
    );
    env.ok("signin.start", json!({})).await;
    env.fake.state().clock += 600;
    assert_eq!(
        env.refused("signin.poll", json!({})).await,
        (exit::REFUSED, "expired_token".into())
    );
}

#[tokio::test]
async fn a_device_license_activates_renews_works_offline_and_releases() {
    let env = Env::new();
    {
        let mut st = env.fake.state();
        st.signed_tokens = true;
        st.license_keys.insert("KEY-1".into());
        st.features.insert("example-app.pro".into());
    }
    assert_eq!(env.ok("license.status", json!({})).await["active"], false);
    let a = env
        .ok("license.activate", json!({"license_key": "KEY-1"}))
        .await;
    assert_eq!(a["entitlement"]["features"]["example-app.pro"], true);
    let s = env.ok("license.status", json!({})).await;
    assert_eq!(
        (s["active"].clone(), s["valid"].clone()),
        (json!(true), json!(true))
    );
    let r = env.ok("license.renew", json!({})).await;
    assert_eq!(r["renewed"], true);
    assert_ne!(r["token"], a["token"]);
    let url = env.ok("license.manage_url", json!({})).await;
    assert!(url["url"].as_str().unwrap().starts_with(ISSUER));
    env.ok("license.release", json!({})).await;
    assert_eq!(env.ok("license.status", json!({})).await["active"], false);

    // Offline: the blob goes to the service by other means, the token comes
    // back and is imported.
    let blob = env
        .ok("license.offline_request", json!({"license_key": "KEY-1"}))
        .await["blob"]
        .clone();
    let body = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE,
        blob.as_str().unwrap(),
    )
    .unwrap();
    let r = env
        .fake
        .send(
            HttpRequest::new("POST", format!("{ISSUER}/v1/offline/activate"))
                .json(&serde_json::from_slice::<Value>(&body).unwrap()),
        )
        .await
        .unwrap();
    let token = r.value()["token"].as_str().unwrap().to_string();
    let imported = env
        .ok("license.offline_import", json!({"blob": token}))
        .await;
    assert_eq!(imported["token"], token);
    assert_eq!(env.ok("license.status", json!({})).await["active"], true);
    assert_eq!(
        env.refused("license.offline_import", json!({"blob": "junk"}))
            .await,
        (exit::LOCAL, "token_rejected".into())
    );
    // Without the product keys nothing can be stored.
    let no_keys = env
        .run(
            "license.activate",
            json!({"license_key": "KEY-1", "keys": null}),
        )
        .await;
    assert_eq!(no_keys.output["error"]["code"], "token_rejected");
    assert_eq!(no_keys.exit, exit::LOCAL);
}

#[tokio::test]
async fn a_signed_in_user_claims_adopts_and_lists_seats() {
    let env = Env::new();
    {
        let mut st = env.fake.state();
        st.signed_tokens = true;
        st.free_seats = 2;
    }
    env.sign_in().await;
    assert_eq!(
        env.ok("license.adopt", json!({})).await["result"],
        "not_licensed"
    );
    let c = env
        .ok("license.claim", json!({"device_name": "Desk"}))
        .await;
    assert_eq!(c["entitlement"]["account_id"], PERSONAL);
    let seats = env.ok("license.seats", json!({})).await;
    let seat = &seats["seats"][0];
    assert_eq!(seat["name"], "Desk");
    env.ok("license.release_seat", json!({"seat_id": seat["seat_id"]}))
        .await;
}

#[tokio::test]
async fn cloud_documents_profiles_files_and_entitlements() {
    let env = Env::new();
    env.fake.state().features.insert("example-app.sync".into());
    env.sign_in().await;
    let accounts = env.ok("cloud.accounts", json!({})).await;
    assert_eq!(accounts["accounts"][0]["id"], PERSONAL);
    let e = env.ok("cloud.entitlements", json!({})).await;
    assert_eq!(e["features"], json!(["example-app.sync"]));

    let doc = json!({"collection": "shows", "key": "main"});
    let put = |extra: Value| {
        let mut v = doc.clone();
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        v
    };
    let v1 = env
        .ok("cloud.docs.put", put(json!({"body": {"title": "One"}})))
        .await;
    assert_eq!(v1["version"], 1);
    let conflict = env
        .run(
            "cloud.docs.put",
            put(json!({"body": {"title": "Two"}, "base_version": 0})),
        )
        .await;
    assert_eq!(conflict.exit, exit::REFUSED);
    assert_eq!(conflict.output["error"]["code"], "version_conflict");
    assert_eq!(conflict.output["error"]["head_version"], 1);
    let got = env.ok("cloud.docs.get", doc.clone()).await;
    assert_eq!(got["body"]["title"], "One");
    let listed = env
        .ok("cloud.docs.list", json!({"collection": "shows"}))
        .await;
    assert_eq!(listed["docs"][0]["key"], "main");
    let versions = env.ok("cloud.docs.versions", doc.clone()).await;
    assert_eq!(versions["versions"][0]["version"], 1);
    env.ok("cloud.docs.delete", doc.clone()).await;

    env.ok(
        "cloud.profile.put",
        json!({"namespace": "example-app", "keys": {"theme": "dark"}}),
    )
    .await;
    let p = env
        .ok("cloud.profile.get", json!({"namespace": "example-app"}))
        .await;
    assert_eq!(p["keys"]["theme"], "dark");
    env.ok("cloud.profile.delete", json!({"namespace": "example-app"}))
        .await;

    let f = env
        .ok(
            "cloud.files.put",
            json!({"collection": "luts", "content_base64": "AQIDBA=="}),
        )
        .await;
    let sha = f["file"]["sha256"].clone();
    let listed = env
        .ok("cloud.files.list", json!({"collection": "luts"}))
        .await;
    assert_eq!(listed["files"][0]["sha256"], sha);
    let back = env
        .ok(
            "cloud.files.get",
            json!({"collection": "luts", "sha256": sha}),
        )
        .await;
    assert_eq!(back["content_base64"], "AQIDBA==");
    let out = env.dir.path().join("lut.bin");
    env.ok(
        "cloud.files.get",
        json!({"collection": "luts", "sha256": sha, "path": out.to_str().unwrap()}),
    )
    .await;
    assert_eq!(std::fs::read(&out).unwrap(), [1, 2, 3, 4]);
    env.ok(
        "cloud.files.delete",
        json!({"collection": "luts", "sha256": sha}),
    )
    .await;
}

#[tokio::test]
async fn support_tickets_as_the_device_or_the_signed_in_user() {
    let env = Env::new();
    {
        let mut st = env.fake.state();
        st.signed_tokens = true;
        st.license_keys.insert("KEY-1".into());
    }
    env.ok("license.activate", json!({"license_key": "KEY-1"}))
        .await;
    let t = env
        .ok(
            "support.create",
            json!({"subject": "Help", "message": "It broke."}),
        )
        .await;
    let id = t["ticket"]["id"].as_str().unwrap().to_string();
    assert_eq!(t["ticket"]["status"], "open");
    env.fake.support_replies(&id, "Try this.");
    let list = env.ok("support.list", json!({})).await;
    assert_eq!(list["tickets"][0]["status"], "pending");
    let thread = env.ok("support.thread", json!({"ticket_id": id})).await;
    assert_eq!(thread["messages"][1]["author"], "support");
    env.ok(
        "support.reply",
        json!({"ticket_id": id, "message": "Thanks."}),
    )
    .await;

    env.sign_in().await;
    let t = env
        .ok(
            "support.create",
            json!({"via": "account", "subject": "Account", "message": "Hello."}),
        )
        .await;
    assert_eq!(t["ticket"]["subject"], "Account");
    let list = env.ok("support.list", json!({"via": "account"})).await;
    assert_eq!(list["tickets"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn events_are_sent_and_what_isnt_delivered_waits_for_the_next_call() {
    let env = Env::new();
    env.sign_in().await;
    let sent = env
        .ok(
            "events.send",
            json!({"events": [{
                "type": "example-app.show.loaded",
                "severity": "notice",
                "subject": {"kind": "show", "id": "s1", "name": "Main"},
                "actor": {"kind": "user", "id": "u1"},
                "attrs": {"size": 3},
            }]}),
        )
        .await;
    assert_eq!(
        (sent["delivered"].clone(), sent["pending"].clone()),
        (json!(1), json!(0))
    );
    assert_eq!(
        env.fake.state().events[0]["type"],
        "example-app.show.loaded"
    );

    let queued = env
        .ok(
            "events.send",
            json!({"flush": false, "events": [{"type": "example-app.show.saved"}]}),
        )
        .await;
    assert_eq!(queued["pending"], 1);
    let flushed = env.ok("events.flush", json!({})).await;
    assert_eq!(
        (flushed["delivered"].clone(), flushed["pending"].clone()),
        (json!(1), json!(0))
    );
    let events = env.fake.state().events.clone();
    assert_eq!(events.len(), 2);
    assert_eq!(events[1]["seq"], 2);
    assert_eq!(
        events[0]["source"]["instance"],
        events[1]["source"]["instance"]
    );

    let bad = env
        .run("events.send", json!({"events": [{"severity": "info"}]}))
        .await;
    assert_eq!(bad.exit, exit::USAGE);
}

struct Offline;

impl Transport for Offline {
    fn send(&self, _request: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, Error>> {
        Box::pin(async { Err(Error::new(None, "network", "No connection: test.")) })
    }
}

#[tokio::test]
async fn exit_codes_tell_usage_refusals_offline_and_local_state_apart() {
    let env = Env::new();
    let unknown = env.run("server.frobnicate", json!({})).await;
    assert_eq!(
        (unknown.exit, unknown.output["error"]["code"].clone()),
        (exit::USAGE, json!("unknown_command"))
    );
    let missing = env.run("server.activate", json!({})).await;
    assert_eq!(missing.exit, exit::USAGE);
    let no_state = cli::run("device.identity", json!({}), env.fake.clone()).await;
    assert_eq!(no_state.exit, exit::USAGE);
    let not_object = cli::run("device.identity", json!([1]), env.fake.clone()).await;
    assert_eq!(not_object.exit, exit::USAGE);
    assert_eq!(
        env.refused("server.activate", json!({"license_key": "NOPE"}))
            .await,
        (exit::REFUSED, "unknown_license_key".into())
    );
    let mut input = env.base();
    input["license_key"] = json!("SRV-1");
    let offline = cli::run("server.activate", input, Arc::new(Offline)).await;
    assert_eq!(
        (offline.exit, offline.output["error"]["code"].clone()),
        (exit::OFFLINE, json!("network"))
    );
    // A renewal that can't reach the service is not a failure: keep running.
    let mut input = env.base();
    input["license_key"] = json!("SRV-1");
    let kept = cli::run("server.renew", input, Arc::new(Offline)).await;
    assert_eq!(kept.exit, exit::OK);
    assert_eq!(kept.output["result"], "kept");
}

#[test]
fn the_binary_lists_commands_and_refuses_bad_input() {
    let bin = env!("CARGO_BIN_EXE_meros-client");
    let out = std::process::Command::new(bin)
        .arg("commands")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(exit::OK));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["commands"].as_array().unwrap().len(), cli::COMMANDS.len());

    let mut child = std::process::Command::new(bin)
        .arg("device.identity")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child.stdin.take().unwrap().write_all(b"{not json").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(exit::USAGE));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"]["code"], "bad_input");

    // A real call through the binary, against no service at all: the device
    // key needs no network.
    let dir = tempfile::tempdir().unwrap();
    let input = json!({"state_dir": dir.path().join("s").to_str().unwrap()});
    let path = dir.path().join("in.json");
    std::fs::write(&path, input.to_string()).unwrap();
    let out = std::process::Command::new(bin)
        .args(["device.identity", "--input", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(exit::OK));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
    assert!(v["device_id"].as_str().unwrap().len() == 36);
}

#[tokio::test]
async fn status_only_reads_and_verifies_the_statement_every_time() {
    let env = Env::new();
    // Nothing there yet: inactive, and nothing created.
    assert_eq!(env.ok("server.status", json!({})).await["active"], false);
    assert!(!env.dir.path().join("state").exists());

    env.fake
        .state()
        .server_keys
        .insert("SRV-1".into(), PERSONAL.into());
    env.ok("server.activate", json!({"license_key": "SRV-1"}))
        .await;
    let files = |env: &Env| {
        let mut f: Vec<String> = std::fs::read_dir(env.dir.path().join("state"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        f.sort();
        f
    };
    let before = files(&env);
    let s = env
        .ok("server.status", json!({"build_date": "2027-01-01"}))
        .await;
    assert_eq!(s["covers_build"], true);
    assert_eq!(files(&env), before);

    // A statement changed on disk after activation is not believed.
    let path = env.state_file("server.json");
    let mut stored: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let licence = stored["licence"].as_str().unwrap().to_string();
    let (payload, sig) = licence.split_once('.').unwrap();
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut body: Value = serde_json::from_slice(&b64.decode(payload).unwrap()).unwrap();
    body["updates_until"] = json!("2099-12-31");
    stored["licence"] = json!(format!("{}.{sig}", b64.encode(body.to_string())));
    std::fs::write(&path, stored.to_string()).unwrap();
    let s = env
        .ok("server.status", json!({"build_date": "2050-01-01"}))
        .await;
    assert_eq!(s["active"], false);
    assert!(s.get("covers_build").is_none());
}

#[tokio::test]
async fn packs_verify_cache_by_etag_and_stand_offline() {
    let env = Env::new();
    env.fake
        .publish_pack("example-app", "regions", json!({"zones": [1, 2]}), false);
    // A public pack needs no sign-in.
    let p = env.ok("cloud.feed", json!({"pack": "regions"})).await;
    assert_eq!(
        (
            p["version"].clone(),
            p["payload"]["zones"].clone(),
            p["from_cache"].clone()
        ),
        (json!(1), json!([1, 2]), json!(false))
    );
    // The same version again is a 304, answered from the cache.
    let again = env.ok("cloud.feed", json!({"pack": "regions"})).await;
    assert_eq!(again["from_cache"], true);
    assert_eq!(
        env.fake.requests_to("/v1/feeds/example-app/regions")[1].header_value("If-None-Match"),
        Some("\"v1\"")
    );
    env.fake
        .publish_pack("example-app", "regions", json!({"zones": [3]}), false);
    let newer = env.ok("cloud.feed", json!({"pack": "regions"})).await;
    assert_eq!(
        (newer["version"].clone(), newer["from_cache"].clone()),
        (json!(2), json!(false))
    );
    let old = env
        .ok("cloud.feed", json!({"pack": "regions", "version": 1}))
        .await;
    assert_eq!(old["payload"]["zones"], json!([1, 2]));
    let versions = env
        .ok("cloud.feed_versions", json!({"pack": "regions"}))
        .await;
    assert_eq!(versions["versions"].as_array().unwrap().len(), 2);

    // Offline, the cached pack stands; it is still verified.
    let mut input = env.base();
    input["pack"] = json!("regions");
    let offline = cli::run("cloud.feed", input.clone(), Arc::new(Offline)).await;
    assert_eq!(offline.exit, exit::OK);
    assert_eq!(offline.output["from_cache"], true);
    assert_eq!(offline.output["version"], 2);
    input["keys"] = json!({ENTITLEMENT_KID: server_keys()[0].1});
    let wrong_key = cli::run("cloud.feed", input, Arc::new(Offline)).await;
    assert_eq!(wrong_key.exit, exit::LOCAL);
    assert_eq!(wrong_key.output["error"]["code"], "verify_failed");

    // An entitled pack needs a session and the entitlement.
    env.fake
        .publish_pack("example-app", "history", json!({"n": 1}), true);
    let (code, err) = env.refused("cloud.feed", json!({"pack": "history"})).await;
    assert_eq!((code, err.as_str()), (exit::REFUSED, "http_401"));
    env.sign_in().await;
    assert_eq!(
        env.refused("cloud.feed", json!({"pack": "history"})).await,
        (exit::REFUSED, "not_entitled".into())
    );
    env.fake
        .state()
        .features
        .insert("example-app.history".into());
    assert_eq!(
        env.ok("cloud.feed", json!({"pack": "history"})).await["payload"]["n"],
        1
    );
}

#[tokio::test]
async fn entitlements_fall_back_to_the_last_answer_offline() {
    let env = Env::new();
    env.fake.state().features.insert("example-app.sync".into());
    env.sign_in().await;
    let live = env.ok("cloud.entitlements", json!({})).await;
    assert_eq!(live["cached"], false);
    let offline = cli::run("cloud.entitlements", env.base(), Arc::new(Offline)).await;
    assert_eq!(offline.exit, exit::OK, "{}", offline.output);
    assert_eq!(offline.output["cached"], true);
    assert_eq!(offline.output["features"], json!(["example-app.sync"]));
    assert_eq!(offline.output["fetched_at"], live["fetched_at"]);
    // Signing out forgets it.
    env.ok("signin.signout", json!({})).await;
    env.sign_in().await;
    let gone = cli::run("cloud.entitlements", env.base(), Arc::new(Offline)).await;
    assert_eq!(gone.exit, exit::OFFLINE);
}

#[tokio::test]
async fn inventory_and_login_tokens_for_connected_services() {
    let env = Env::new();
    env.fake
        .state()
        .features
        .insert("example-app.inventory".into());
    env.sign_in().await;
    let put = env
        .ok(
            "cloud.inventory.put",
            json!({"devices": [{"id": "d1", "model": "X"}, {"id": "d2"}]}),
        )
        .await;
    assert_eq!(put["count"], 2);
    let got = env.ok("cloud.inventory.get", json!({})).await;
    assert_eq!(got["devices"][1]["id"], "d2");
    let bad = env
        .run(
            "cloud.inventory.put",
            json!({"devices": [{"model": "no id"}]}),
        )
        .await;
    assert_eq!(bad.output["error"]["code"], "invalid_inventory");

    let t = env
        .ok(
            "signin.login_token",
            json!({"audience": "service-a", "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}),
        )
        .await;
    assert_eq!(t["expires_in"], 120);
    assert!(t["login_token"].as_str().unwrap().starts_with("lt"));
    let mint = &env.fake.requests_to("/oauth/sso/ticket")[0];
    assert_eq!(mint.json_body().unwrap()["code_challenge_method"], "S256");
    assert_eq!(
        env.refused("signin.login_token", json!({"audience": "elsewhere"}))
            .await,
        (exit::REFUSED, "invalid_target".into())
    );
}

#[tokio::test]
async fn several_identities_each_keep_their_own_session() {
    let env = Env::new();
    // The console's own session, and an operator's under another client.
    env.sign_in().await;
    let op = json!({"session": "op-7", "client_id": "people-client", "scopes": ["openid", "profile", "email", "offline_access", "profiles:read", "profiles:write"]});
    let with = |extra: Value| {
        let mut v = op.clone();
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        v
    };
    let start = env.ok("signin.start", op.clone()).await;
    let poll = &env.fake.requests_to("/oauth/device/code")[1];
    let fields: std::collections::HashMap<_, _> = poll.form_fields().into_iter().collect();
    assert_eq!(fields["client_id"], "people-client");
    // A second pending grant can be cancelled on its own.
    env.ok("signin.start", json!({"session": "op-8"})).await;
    env.ok("signin.cancel", json!({"session": "op-8"})).await;
    assert_eq!(
        env.refused("signin.poll", json!({"session": "op-8"})).await,
        (exit::LOCAL, "no_sign_in".into())
    );

    env.fake
        .approve_device(start["user_code"].as_str().unwrap());
    let done = env.ok("signin.poll", op.clone()).await;
    assert_eq!(
        (done["user"]["id"].clone(), done["user"]["email"].clone()),
        (json!("u1"), json!("pat@example.com"))
    );
    let list = env.ok("signin.list", json!({})).await;
    let handles: Vec<&str> = list["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["session"].as_str().unwrap())
        .collect();
    assert_eq!(handles, ["default", "op-7"]);

    // The profile is read and written as that identity.
    env.ok(
        "cloud.profile.put",
        with(json!({"namespace": "example-app", "keys": {"theme": "dark"}})),
    )
    .await;
    let p = env
        .ok(
            "cloud.profile.get",
            with(json!({"namespace": "example-app"})),
        )
        .await;
    assert_eq!(p["keys"]["theme"], "dark");
    // Refreshing as the operator uses the operator's client.
    env.ok("signin.token", with(json!({"force": true}))).await;
    let refresh = env.fake.requests_to("/oauth/token");
    let fields: std::collections::HashMap<_, _> =
        refresh.last().unwrap().form_fields().into_iter().collect();
    assert_eq!(fields["client_id"], "people-client");

    // Revoking one identity leaves the other, and revokes with its client.
    env.ok("signin.signout", op.clone()).await;
    let revoke = env.fake.requests_to("/oauth/revoke");
    let fields: std::collections::HashMap<_, _> =
        revoke.last().unwrap().form_fields().into_iter().collect();
    assert_eq!(fields["client_id"], "people-client");
    assert_eq!(env.ok("signin.status", op).await["signed_in"], false);
    assert_eq!(env.ok("signin.status", json!({})).await["signed_in"], true);
}

#[tokio::test]
async fn a_login_token_from_elsewhere_signs_in_and_replaces_a_previous_user() {
    let env = Env::new();
    env.sign_in().await; // the console, which mints
    let cu = json!({"session": "cloud-user", "client_id": "service-a-client"});
    let redeem = |begin: &Value, token: &Value| {
        let mut v = cu.clone();
        v["request_id"] = begin["request_id"].clone();
        v["login_token"] = token["login_token"].clone();
        v
    };
    let mint = |begin: &Value, nonce: &str| json!({"audience": "service-a", "code_challenge": begin["code_challenge"], "nonce": nonce});

    let begin = env.ok("signin.redeem.begin", cu.clone()).await;
    assert_eq!(begin["code_challenge_method"], "S256");
    let token = env
        .ok(
            "signin.login_token",
            mint(&begin, begin["nonce"].as_str().unwrap()),
        )
        .await;
    let done = env
        .ok("signin.redeem.complete", redeem(&begin, &token))
        .await;
    assert_eq!(
        (
            done["user"]["id"].clone(),
            done["replaced_previous"].clone()
        ),
        (json!("u1"), json!(false))
    );
    let grant = env.fake.requests_to("/oauth/token");
    let fields: std::collections::HashMap<_, _> =
        grant.last().unwrap().form_fields().into_iter().collect();
    assert_eq!(
        fields["grant_type"],
        "urn:meros:params:oauth:grant-type:sso-ticket"
    );
    assert!(fields["code_verifier"].len() >= 43);
    // A login token works once.
    assert_eq!(
        env.refused("signin.redeem.complete", redeem(&begin, &token))
            .await,
        (exit::LOCAL, "unknown_request".into())
    );
    // The refresh token rotates like any other session's.
    let mut force = cu.clone();
    force["force"] = json!(true);
    env.ok("signin.token", force).await;

    // A different user signing in here replaces the first, who is revoked.
    env.fake.state().sso_sub = "u2".into();
    let begin = env.ok("signin.redeem.begin", cu.clone()).await;
    let token = env
        .ok(
            "signin.login_token",
            mint(&begin, begin["nonce"].as_str().unwrap()),
        )
        .await;
    let revokes = env.fake.requests_to("/oauth/revoke").len();
    let done = env
        .ok("signin.redeem.complete", redeem(&begin, &token))
        .await;
    assert_eq!(
        (
            done["user"]["id"].clone(),
            done["replaced_previous"].clone()
        ),
        (json!("u2"), json!(true))
    );
    assert_eq!(env.fake.requests_to("/oauth/revoke").len(), revokes + 1);

    // An id_token for another sign-in (wrong nonce) is refused and revoked.
    let begin = env.ok("signin.redeem.begin", cu.clone()).await;
    let token = env
        .ok("signin.login_token", mint(&begin, "someone-elses-nonce"))
        .await;
    let revokes = env.fake.requests_to("/oauth/revoke").len();
    assert_eq!(
        env.refused("signin.redeem.complete", redeem(&begin, &token))
            .await,
        (exit::REFUSED, "invalid_response".into())
    );
    assert_eq!(env.fake.requests_to("/oauth/revoke").len(), revokes + 1);
    // The previous user stays signed in.
    let status = env.ok("signin.status", cu).await;
    assert_eq!(status["user"]["id"], "u2");
}

#[tokio::test]
async fn a_key_file_seals_every_secret_and_is_required_to_read_them() {
    let env = Env::new();
    let key_file = env.dir.path().join("secret.key");
    let sealed = json!({"key_file": key_file.to_str().unwrap()});
    let first = env.ok("device.identity", sealed.clone()).await;
    let start = env.ok("signin.start", sealed.clone()).await;
    env.fake
        .approve_device(start["user_code"].as_str().unwrap());
    env.ok("signin.poll", sealed.clone()).await;
    // Nothing secret is readable on disk.
    let device = std::fs::read_to_string(env.state_file("device.json")).unwrap();
    assert!(device.contains("\"sealed\"") && !device.contains("seed"));
    let session = std::fs::read_to_string(env.state_file("sessions/default.json")).unwrap();
    assert!(!session.contains("refresh_token") && session.contains("\"sealed\""));
    // With the key, everything works across calls.
    assert_eq!(
        env.ok("device.identity", sealed.clone()).await["device_id"],
        first["device_id"]
    );
    assert_eq!(
        env.ok("signin.status", sealed.clone()).await["signed_in"],
        true
    );
    // Without it the files are refused, never replaced.
    let (code, err) = env.refused("device.identity", json!({})).await;
    assert_eq!((code, err.as_str()), (exit::LOCAL, "state_error"));
    assert_eq!(
        env.ok("device.identity", sealed).await["device_id"],
        first["device_id"]
    );
    // A key kept inside the state directory protects nothing.
    let inside = env.state_file("key");
    let o = env
        .run(
            "device.identity",
            json!({"key_file": inside.to_str().unwrap()}),
        )
        .await;
    assert_eq!(o.exit, exit::USAGE);
}

#[tokio::test]
async fn entitlements_report_held_features_through_a_thirty_day_grace() {
    let env = Env::new();
    env.fake.state().features.insert("example-app.sync".into());
    env.sign_in().await;
    let day = 86_400;
    let at = |secs_ago: i64| {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - secs_ago;
        // RFC 3339 from unix seconds, UTC.
        let days = t.div_euclid(day);
        let (z, secs) = (days + 719_468, t.rem_euclid(day));
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = yoe + era * 400 + i64::from(m <= 2);
        format!(
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
            secs / 3600,
            secs % 3600 / 60,
            secs % 60
        )
    };
    let e = env.ok("cloud.entitlements", json!({})).await;
    assert_eq!(e["held"], json!(["example-app.sync"]));
    assert_eq!(
        (e["in_grace"].clone(), e["lapsed"].clone()),
        (json!(false), json!(false))
    );
    assert_eq!(e["account_id"], PERSONAL);

    env.fake.state().entitlement_expires_at = Some(at(10 * day));
    let e = env.ok("cloud.entitlements", json!({})).await;
    assert_eq!(
        (e["in_grace"].clone(), e["held"].clone()),
        (json!(true), json!(["example-app.sync"]))
    );

    env.fake.state().entitlement_expires_at = Some(at(40 * day));
    let e = env.ok("cloud.entitlements", json!({})).await;
    assert_eq!(e["lapsed"], true);
    // Held is the honest answer; the features the service listed stay
    // visible beside it.
    assert_eq!(e["held"], json!([]));
    assert_eq!(e["features"], json!(["example-app.sync"]));
}

#[tokio::test]
async fn an_identical_copy_is_already_current_and_nothing_is_written() {
    let env = Env::new();
    env.sign_in().await;
    let doc = |body: Value, base: i64| json!({"collection": "shows", "key": "main", "body": body, "base_version": base});
    let first = env
        .ok("cloud.docs.put", doc(json!({"b": 1, "a": [2, 1]}), 0))
        .await;
    // The same content in another key order is the same document.
    let same = env
        .ok("cloud.docs.put", doc(json!({"a": [2, 1], "b": 1}), 0))
        .await;
    assert_eq!(
        (same["unchanged"].clone(), same["version"].clone()),
        (json!(true), json!(1))
    );
    assert_eq!(same["content_hash"], first["content_hash"]);
    let got = env
        .ok(
            "cloud.docs.get",
            json!({"collection": "shows", "key": "main"}),
        )
        .await;
    assert_eq!(got["content_hash"], first["content_hash"]);
    // Different content is a real conflict, with the head's hash to compare.
    let o = env
        .run("cloud.docs.put", doc(json!({"a": [1, 2], "b": 1}), 0))
        .await;
    assert_eq!(o.output["error"]["code"], "version_conflict");
    assert_eq!(o.output["error"]["head_version"], 1);
    assert_eq!(
        o.output["error"]["head_content_hash"],
        first["content_hash"]
    );
    assert_eq!(
        meros_client::content_hash(&json!({"b": 1, "a": [2, 1]})),
        first["content_hash"].as_str().unwrap()
    );
}

#[tokio::test]
async fn events_keep_to_the_envelope_size_limits() {
    let env = Env::new();
    env.sign_in().await;
    let attrs: serde_json::Map<String, Value> = (0..40)
        .map(|i| (format!("k{i:02}"), json!("x".repeat(1000))))
        .collect();
    env.ok(
        "events.send",
        json!({"events": [
            {"type": "example-app.big.attrs", "attrs": attrs},
            {"type": "example-app.too.big", "trace": "t".repeat(70 * 1024)},
        ]}),
    )
    .await;
    let events = env.fake.state().events.clone();
    let big = events
        .iter()
        .find(|e| e["type"] == "example-app.big.attrs")
        .unwrap();
    let kept = big["attrs"].as_object().unwrap();
    assert!(serde_json::to_vec(kept).unwrap().len() <= 16 * 1024);
    assert!(kept.contains_key("k00") && kept.len() < 40);
    // The oversized event was dropped, and the loss reported.
    assert!(!events.iter().any(|e| e["type"] == "example-app.too.big"));
    env.ok("events.flush", json!({})).await;
    let events = env.fake.state().events.clone();
    let lost = events
        .iter()
        .find(|e| e["type"] == "example-app.events.dropped")
        .unwrap();
    assert_eq!(lost["attrs"]["count"], 1);
}

#[tokio::test]
async fn nothing_reaches_a_service_without_an_issuer_given() {
    // There is no built-in host: without `issuer`, service commands refuse
    // before sending anything, so nothing can default to production.
    let env = Env::new();
    let mut input = env.base();
    input.as_object_mut().unwrap().remove("issuer");
    for command in [
        "signin.start",
        "server.activate",
        "cloud.feed",
        "events.flush",
    ] {
        let mut i = input.clone();
        i["license_key"] = json!("K");
        i["pack"] = json!("p");
        let o = cli::run(command, i, env.fake.clone()).await;
        assert_eq!(o.exit, exit::USAGE, "{command}: {}", o.output);
    }
    assert!(env.fake.state().requests.is_empty());
    for file in ["src/cli.rs", "src/bin/meros-client.rs"] {
        let text = std::fs::read_to_string(file).unwrap();
        assert!(!text.contains("meros.co"), "{file} names a Meros host");
    }
}

#[tokio::test]
async fn a_two_factor_step_up_signs_the_same_session_in_again() {
    let env = Env::new();
    env.sign_in().await;
    let first = env.ok("signin.token", json!({})).await;
    let mfa = json!({"acr_values": "urn:meros:acr:mfa"});
    let start = env.ok("signin.start", mfa.clone()).await;
    let request = &env.fake.requests_to("/oauth/device/code")[1];
    let fields: std::collections::HashMap<_, _> = request.form_fields().into_iter().collect();
    assert_eq!(fields["acr_values"], "urn:meros:acr:mfa");
    assert_eq!(
        env.fake
            .state()
            .device_sign_ins
            .values()
            .last()
            .map(|d| d.acr_values.clone()),
        Some(Some("urn:meros:acr:mfa".to_string()))
    );
    // Without acr_values nothing extra is sent.
    let plain = &env.fake.requests_to("/oauth/device/code")[0];
    assert!(!plain.form_fields().iter().any(|(k, _)| k == "acr_values"));

    env.fake
        .approve_device(start["user_code"].as_str().unwrap());
    let done = env.ok("signin.poll", json!({})).await;
    assert_eq!(
        (done["user"]["id"].clone(), done["acr_values"].clone()),
        (json!("u1"), json!("urn:meros:acr:mfa"))
    );
    // Same session, new tokens.
    let list = env.ok("signin.list", json!({})).await;
    assert_eq!(list["sessions"].as_array().unwrap().len(), 1);
    let after = env.ok("signin.token", json!({})).await;
    assert_ne!(after["access_token"], first["access_token"]);
}

#[tokio::test]
async fn clearing_events_drops_what_waits_without_sending_it() {
    let env = Env::new();
    env.sign_in().await;
    let queued = env
        .ok(
            "events.send",
            json!({"flush": false, "events": [{"type": "example-app.a.b"}, {"type": "example-app.c.d"}]}),
        )
        .await;
    assert_eq!(queued["pending"], 2);
    let cleared = env.ok("events.clear", json!({})).await;
    assert_eq!(cleared["cleared"], 2);
    let flushed = env.ok("events.flush", json!({})).await;
    assert_eq!(
        (flushed["delivered"].clone(), flushed["pending"].clone()),
        (json!(0), json!(0))
    );
    assert!(env.fake.state().events.is_empty());
    assert!(env.fake.requests_to("/v1/events").is_empty());
    // Clearing needs no service and nothing waiting.
    let mut input = env.base();
    input.as_object_mut().unwrap().remove("issuer");
    let o = cli::run("events.clear", input, env.fake.clone()).await;
    assert_eq!((o.exit, o.output["cleared"].clone()), (exit::OK, json!(0)));
}

#[tokio::test]
async fn a_cache_only_feed_read_never_touches_the_network() {
    let env = Env::new();
    let read = json!({"pack": "regions", "cache_only": true});
    // Nothing cached yet: exit 4, and no request was made.
    assert_eq!(
        env.refused("cloud.feed", read.clone()).await,
        (exit::LOCAL, "not_cached".into())
    );
    assert!(env.fake.state().requests.is_empty());
    env.fake
        .publish_pack("example-app", "regions", json!({"zones": [5]}), false);
    env.ok("cloud.feed", json!({"pack": "regions"})).await;
    let asked = env.fake.state().requests.len();
    // Offline transport and no issuer: the cache answers, verified.
    let mut input = env.base();
    input.as_object_mut().unwrap().remove("issuer");
    input["pack"] = json!("regions");
    input["cache_only"] = json!(true);
    let o = cli::run("cloud.feed", input.clone(), Arc::new(Offline)).await;
    assert_eq!(o.exit, exit::OK, "{}", o.output);
    assert_eq!(
        (
            o.output["payload"]["zones"].clone(),
            o.output["from_cache"].clone()
        ),
        (json!([5]), json!(true))
    );
    assert_eq!(env.fake.state().requests.len(), asked);
    input["keys"] = json!({ENTITLEMENT_KID: server_keys()[0].1});
    let o = cli::run("cloud.feed", input, Arc::new(Offline)).await;
    assert_eq!(o.output["error"]["code"], "verify_failed");
}

#[tokio::test]
async fn an_event_keeps_the_time_it_happened() {
    let env = Env::new();
    env.sign_in().await;
    env.ok(
        "events.send",
        json!({"events": [{"type": "example-app.mic.dropped", "occurred_at": "2026-10-30T19:42:07.125Z"}]}),
    )
    .await;
    assert_eq!(
        env.fake.state().events[0]["occurred_at"],
        "2026-10-30T19:42:07.125Z"
    );
    let bad = env
        .run(
            "events.send",
            json!({"events": [{"type": "example-app.x.y", "occurred_at": "yesterday"}]}),
        )
        .await;
    assert_eq!(bad.exit, exit::USAGE);
}

#[tokio::test]
async fn sign_out_says_whether_the_service_revoked_the_session() {
    let env = Env::new();
    env.sign_in().await;
    let out = env.ok("signin.signout", json!({})).await;
    assert_eq!(out["revoked"], true);
    // Offline the session is still forgotten, but not revoked.
    env.sign_in().await;
    let o = cli::run("signin.signout", env.base(), Arc::new(Offline)).await;
    assert_eq!(
        (o.exit, o.output["revoked"].clone()),
        (exit::OK, json!(false))
    );
    assert_eq!(env.ok("signin.status", json!({})).await["signed_in"], false);
    // Nothing to revoke.
    assert_eq!(env.ok("signin.signout", json!({})).await["revoked"], false);
}

#[tokio::test]
async fn a_document_conflict_says_when_the_other_copy_was_saved() {
    let env = Env::new();
    env.sign_in().await;
    let doc =
        |body: Value| json!({"collection": "shows", "key": "k", "body": body, "base_version": 0});
    env.ok("cloud.docs.put", doc(json!({"a": 1}))).await;
    let o = env.run("cloud.docs.put", doc(json!({"a": 2}))).await;
    assert_eq!(o.output["error"]["code"], "version_conflict");
    assert!(
        o.output["error"]["head_updated_at"]
            .as_str()
            .is_some_and(|t| t.starts_with("2026-"))
    );
}

#[tokio::test]
async fn relayed_events_go_on_unchanged_and_a_resend_is_a_duplicate() {
    let env = Env::new();
    env.sign_in().await;
    let envelope = json!({
        "envelope": 1,
        "id": "01JBX6YQ3Z8N4E2R7T5W9K0M1P",
        "occurred_at": "2026-10-30T20:01:02.003Z",
        "seq": 41,
        "source": {"product": "other-app", "version": "3.1.0", "instance": "abcd1234ef567890"},
        "type": "other-app.channel.muted",
        "severity": "notice",
        "attrs": {"channel": 7},
    });
    let sent = env
        .ok("events.relay", json!({"events": [envelope.clone()]}))
        .await;
    assert_eq!(sent["accepted"], 1);
    let got = env.fake.state().events[0].clone();
    assert_eq!(got, envelope);
    // The same event again: the collector already has it.
    let again = env
        .ok("events.relay", json!({"events": [envelope.clone()]}))
        .await;
    assert_eq!(
        (again["accepted"].clone(), again["duplicates"].clone()),
        (json!(0), json!(1))
    );
    // Undelivered relays wait in the outbox like any event, and clear.
    env.ok(
        "events.relay",
        json!({"flush": false, "events": [envelope]}),
    )
    .await;
    assert_eq!(env.ok("events.clear", json!({})).await["cleared"], 1);
    let bad = env
        .run("events.relay", json!({"events": [{"type": "x.y.z"}]}))
        .await;
    assert_eq!(bad.exit, exit::USAGE);
}

#[tokio::test]
async fn a_server_activation_files_support_tickets_as_the_device() {
    let env = Env::new();
    env.fake
        .state()
        .server_keys
        .insert("SRV-1".into(), PERSONAL.into());
    env.ok("server.activate", json!({"license_key": "SRV-1"}))
        .await;
    let t = env
        .ok(
            "support.create",
            json!({"subject": "Rack", "message": "Help."}),
        )
        .await;
    assert_eq!(t["ticket"]["status"], "open");
    // Device support goes to the product's device base.
    let create = env.fake.requests_to("/v1/support/tickets");
    assert!(
        create[0]
            .url
            .starts_with(&format!("{ISSUER}/app/example-app/"))
    );
}

#[test]
fn fake_mode_runs_the_real_binary_with_no_network() {
    let bin = env!("CARGO_BIN_EXE_meros-client");
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let call = |command: &str, extra: Value| -> (i32, Value) {
        let mut input = json!({
            "state_dir": state.to_str().unwrap(),
            "issuer": "fake:",
            "product": "my-product",
            "client_id": "client-1",
            "scopes": "openid offline_access",
        });
        for (k, v) in extra.as_object().unwrap() {
            input[k] = v.clone();
        }
        let path = dir.path().join("in.json");
        std::fs::write(&path, input.to_string()).unwrap();
        let out = std::process::Command::new(bin)
            .args([command, "--input", path.to_str().unwrap()])
            .output()
            .unwrap();
        (
            out.status.code().unwrap(),
            serde_json::from_slice(&out.stdout).unwrap(),
        )
    };
    let (_, keys) = call("fake.keys", json!({}));
    let all_keys: serde_json::Map<String, Value> = keys["server"]
        .as_object()
        .unwrap()
        .iter()
        .chain(keys["entitlement"].as_object().unwrap())
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let keys = json!(all_keys);

    // Sign in, approving the code on the fake.
    let (code, start) = call("signin.start", json!({}));
    assert_eq!(code, exit::OK, "{start}");
    assert_eq!(start["verification_uri"], "https://fake.meros.test/link");
    call(
        "fake.approve_device",
        json!({"user_code": start["user_code"]}),
    );
    let (_, done) = call("signin.poll", json!({}));
    assert_eq!(done["status"], "signed_in");

    // Seed keys through the knobs, then license both ways.
    let (code, _) = call(
        "fake.set",
        json!({"patch": {"server_keys": {"SRV-1": "acct-personal"}, "license_keys": ["KEY-1"]}}),
    );
    assert_eq!(code, exit::OK);
    let (code, a) = call(
        "server.activate",
        json!({"license_key": "SRV-1", "keys": keys}),
    );
    assert_eq!(code, exit::OK, "{a}");
    assert_eq!(a["licence"]["product"], "my-product");
    let (code, l) = call(
        "license.activate",
        json!({"license_key": "KEY-1", "keys": keys}),
    );
    assert_eq!(code, exit::OK, "{l}");
    let (_, t) = call(
        "support.create",
        json!({"subject": "Hi", "message": "From the fake."}),
    );
    call(
        "fake.support_reply",
        json!({"ticket_id": t["ticket"]["id"], "message": "Hello."}),
    );
    let (_, list) = call("support.list", json!({}));
    assert_eq!(list["tickets"][0]["status"], "pending");

    // The fake's state is there to inspect between calls.
    let (_, st) = call("fake.state", json!({}));
    assert_eq!(st["state"]["tickets"].as_array().unwrap().len(), 1);
    let (code, bad) = call("fake.set", json!({"patch": {"no_such_knob": 1}}));
    assert_eq!(
        (code, bad["error"]["code"].clone()),
        (exit::USAGE, json!("bad_input"))
    );
    // Fake controls refuse a real issuer.
    let mut input = json!({"state_dir": state.to_str().unwrap(), "issuer": "https://example.test"});
    input["x"] = json!(1);
    let path = dir.path().join("real.json");
    std::fs::write(&path, input.to_string()).unwrap();
    let out = std::process::Command::new(bin)
        .args(["fake.state", "--input", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(exit::USAGE));
}
