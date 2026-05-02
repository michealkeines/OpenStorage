//! CLI integration tests for Wave 6 plugin lifecycle
//! (F-PL-1 install, F-PL-2 oauth, F-PL-3 capability drift).

mod common;

use assert_cmd::Command;
use os_crypto::{generate_keypair, sign};
use os_plugin_host::lifecycle::PluginManifest;
use os_types::{Capability, CapabilitySet, Ed25519Sig, LegalClass, PluginId};
use predicates::prelude::*;
use rand::rngs::OsRng;

fn os_cmd(engine: &common::Engine) -> Command {
    let mut c = Command::cargo_bin("os").unwrap();
    c.env("OPENSTORAGE_BASE", &engine.base)
        .env("OPENSTORAGE_STATE_DIR", &engine.state_path)
        .env("OPENSTORAGE_PASSPHRASE", "hunter2");
    c
}

fn signed_manifest_hex(plugin_id: &str, version: &str) -> String {
    let (sk, pk) = generate_keypair(&mut OsRng);
    let mut m = PluginManifest {
        plugin_id: PluginId::new(plugin_id),
        version: version.into(),
        author_pubkey: pk,
        legal_class: LegalClass::Green,
        requested_capabilities: CapabilitySet::default()
            .with(Capability::Put)
            .with(Capability::Get),
        source_url: "https://example.com/p.wasm".into(),
        signature: Ed25519Sig([0u8; 64]),
    };
    let mut canon = Vec::new();
    ciborium::into_writer(&m, &mut canon).unwrap();
    m.signature = sign(&sk, &canon);
    let mut b = Vec::new();
    ciborium::into_writer(&m, &mut b).unwrap();
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_plugin_install_success() {
    let engine = common::spawn_engine().await;
    let manifest_hex = signed_manifest_hex("org.test.cli", "1.0.0");
    os_cmd(&engine)
        .args([
            "plugins",
            "install",
            "--manifest-hex",
            &manifest_hex,
            "--confirmation",
            "confirm",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("plugin installed"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_oauth_start_then_complete() {
    let engine = common::spawn_engine().await;
    os_cmd(&engine).arg("init").assert().success();

    let start = os_cmd(&engine)
        .args([
            "plugins",
            "oauth-start",
            "--plugin-id",
            "org.test.oauth",
            "--auth-url",
            "https://provider/auth",
            "--scope",
            "files.write",
        ])
        .output()
        .unwrap();
    assert!(start.status.success());
    let stdout = String::from_utf8(start.stdout).unwrap();
    let json_start = stdout.find('{').unwrap();
    let json_end = stdout.rfind('}').unwrap() + 1;
    let v: serde_json::Value = serde_json::from_str(&stdout[json_start..json_end]).unwrap();
    let state = v["state"].as_str().unwrap();

    let token_hex: String = b"my-access-token"
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    os_cmd(&engine)
        .args([
            "plugins",
            "oauth-complete",
            "--state",
            state,
            "--token-hex",
            &token_hex,
            "--granted",
            "files.write,files.read",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("credentials_handle_hex"));
}
