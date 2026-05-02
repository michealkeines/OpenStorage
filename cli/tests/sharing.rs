//! CLI integration tests for the F-SH-1/F-SH-2/F-SH-3 sharing flow.

mod common;

use assert_cmd::Command;
use predicates::prelude::*;

fn os_cmd(engine: &common::Engine) -> Command {
    let mut c = Command::cargo_bin("os").unwrap();
    c.env("OPENSTORAGE_BASE", &engine.base)
        .env("OPENSTORAGE_STATE_DIR", &engine.state_path)
        .env("OPENSTORAGE_PASSPHRASE", "hunter2");
    c
}

fn init(engine: &common::Engine) {
    os_cmd(engine).arg("init").assert().success();
}

fn upload_inline(engine: &common::Engine, content: &[u8], remote: &str) {
    let tmp = tempfile::tempdir().unwrap();
    let local = tmp.path().join("payload.bin");
    std::fs::write(&local, content).unwrap();
    os_cmd(engine)
        .args(["upload", local.to_str().unwrap(), "--as", remote])
        .assert()
        .success();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_share_create_emits_blob_and_owner_pub() {
    let engine = common::spawn_engine().await;
    init(&engine);
    upload_inline(&engine, b"abc", "/note.txt");
    os_cmd(&engine)
        .args([
            "shares",
            "create",
            "--recipient",
            "bob",
            "--scope",
            "/note.txt",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("blob_hex"))
        .stdout(predicate::str::contains("owner_sign_pub_hex"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_share_create_accept_revoke_round_trip() {
    let engine = common::spawn_engine().await;
    init(&engine);
    upload_inline(&engine, b"top secret", "/note.txt");

    let create = os_cmd(&engine)
        .args([
            "shares",
            "create",
            "--recipient",
            "bob",
            "--scope",
            "/note.txt",
        ])
        .output()
        .unwrap();
    assert!(create.status.success());
    let stdout = String::from_utf8(create.stdout).unwrap();
    let parsed = parse_create_stdout(&stdout);

    os_cmd(&engine)
        .args([
            "shares",
            "accept",
            &parsed.share_id,
            "--blob-hex",
            &parsed.blob_hex,
            "--owner-pub-hex",
            &parsed.owner_pub_hex,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("accepted"));

    os_cmd(&engine)
        .args(["shares", "inbox"])
        .assert()
        .success()
        .stdout(predicate::str::contains(&parsed.share_id));

    os_cmd(&engine)
        .args(["shares", "revoke", &parsed.share_id])
        .assert()
        .success()
        .stdout(predicate::str::contains("file_key_version → 1"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_share_accept_with_bad_owner_pubkey_fails() {
    let engine = common::spawn_engine().await;
    init(&engine);
    upload_inline(&engine, b"x", "/note.txt");

    let create = os_cmd(&engine)
        .args([
            "shares", "create", "--recipient", "bob", "--scope", "/note.txt",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8(create.stdout).unwrap();
    let parsed = parse_create_stdout(&stdout);

    let bogus = "0".repeat(64);
    os_cmd(&engine)
        .args([
            "shares",
            "accept",
            &parsed.share_id,
            "--blob-hex",
            &parsed.blob_hex,
            "--owner-pub-hex",
            &bogus,
        ])
        .assert()
        .failure();
}

struct ParsedCreate {
    share_id: String,
    blob_hex: String,
    owner_pub_hex: String,
}

/// The `os shares create` command prints a pretty-printed JSON blob. Parse
/// the three fields we need for the accept flow.
fn parse_create_stdout(s: &str) -> ParsedCreate {
    // Strip the leading "✓ share created: " line marker and parse the JSON.
    let json_start = s.find('{').expect("create stdout missing JSON object");
    let json_end = s.rfind('}').expect("create stdout missing JSON close") + 1;
    let v: serde_json::Value =
        serde_json::from_str(&s[json_start..json_end]).expect("create JSON parse");
    ParsedCreate {
        share_id: v["share_id"].as_str().unwrap().to_string(),
        blob_hex: v["blob_hex"].as_str().unwrap().to_string(),
        owner_pub_hex: v["owner_sign_pub_hex"].as_str().unwrap().to_string(),
    }
}
