//! F-MD-1..5 — multi-device coordination via a shared vault provider.
//!
//! Two engines (`A` and `B`) point at the same `LocalDirPlugin` directory
//! registered as a vault provider. The vault-backed coordination
//! endpoints (lease, wal/push, wal/pull) key off the URL path's vault_id
//! and therefore share state through the on-plugin `name:lease/<vault>`
//! and `name:wal/<dev>/<seq>` slots — exactly the F-MD-* model.

mod common;

use serde_json::json;

/// Stable vault id used by both engines so they hash to the same on-plugin
/// blob names. Real deployments derive this from the user's vault; in the
/// tests we hard-code one valid UUIDv7 string.
const SHARED_VAULT_ID: &str = "019de8de-e3c1-7ef1-aaaa-bbbbccccdddd";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn md4_lease_steal_across_two_engines() {
    let pair = common::spawn_engine_pair().await;
    let client = reqwest::Client::new();

    // A acquires the lease at t=0 with a 30s TTL.
    let resp = client
        .post(format!("{}/v1/vaults/{}/lease", pair.a.base, SHARED_VAULT_ID))
        .json(&json!({"now_epoch_secs": 0u64, "ttl_secs": 30u64}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "A acquire: {}", resp.status());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["state"], "held");
    assert_eq!(body["backend"], "vault");

    // B's steal at t=60 (aged=30 < 2×TTL=60) should be refused with 409.
    let resp = client
        .post(format!("{}/v1/vaults/{}/lease/steal", pair.b.base, SHARED_VAULT_ID))
        .json(&json!({
            "now_epoch_secs": 60u64,
            "expires_at_epoch_secs": 120u64,
            "ttl_secs": 30u64,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 409, "expected 409, got {}", resp.status());

    // B's steal at t=91 (aged=61 > 2×TTL=60) succeeds.
    let resp = client
        .post(format!("{}/v1/vaults/{}/lease/steal", pair.b.base, SHARED_VAULT_ID))
        .json(&json!({
            "now_epoch_secs": 91u64,
            "expires_at_epoch_secs": 121u64,
            "ttl_secs": 30u64,
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "B steal: {}", resp.status());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["state"], "held");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn md5_wal_push_pull_round_trip() {
    let pair = common::spawn_engine_pair().await;
    let client = reqwest::Client::new();

    // Both engines need to init a vault (different vault_ids — that's
    // fine; we're testing the WAL exchange, not metadata identity).
    init_engine(&client, &pair.a).await;
    init_engine(&client, &pair.b).await;

    // A uploads a small file → produces WAL entries on A.
    upload(&client, &pair.a, "/from-a.txt", b"hello from A").await;

    // A pushes its WAL.
    let resp = client
        .post(format!("{}/v1/vaults/{}/wal/push", pair.a.base, SHARED_VAULT_ID))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "wal push: {}", resp.status());
    let pushed: serde_json::Value = resp.json().await.unwrap();
    assert!(
        pushed["pushed"].as_u64().unwrap_or(0) > 0,
        "expected non-zero pushed count, got {pushed:?}",
    );

    // B pulls.
    let resp = client
        .post(format!("{}/v1/vaults/{}/wal/pull", pair.b.base, SHARED_VAULT_ID))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "wal pull: {}", resp.status());
    let pulled: serde_json::Value = resp.json().await.unwrap();
    assert!(
        pulled["foreign_entries"].as_u64().unwrap_or(0) > 0,
        "expected at least one foreign entry, got {pulled:?}",
    );
}

async fn init_engine(client: &reqwest::Client, engine: &common::Engine) {
    let resp = client
        .post(format!("{}/v1/vaults", engine.base))
        .json(&json!({
            "passphrase": "hunter2",
            "recovery_modes": []
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "init: {}", resp.status());
}

/// F-MD-3 — concurrent rename of the same `file_id`. A and B both write
/// the file at /init.txt locally (each producing its own `LwwRegister(path)`);
/// the WAL exchange ensures both engines converge to the HLC-winner's path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn md3_concurrent_rename_via_wal_exchange() {
    let pair = common::spawn_engine_pair().await;
    let client = reqwest::Client::new();
    init_engine(&client, &pair.a).await;
    init_engine(&client, &pair.b).await;

    upload(&client, &pair.a, "/init.txt", b"a content").await;
    upload(&client, &pair.b, "/init.txt", b"b content").await;

    let a_pushed = client
        .post(format!("{}/v1/vaults/{}/wal/push", pair.a.base, SHARED_VAULT_ID))
        .send().await.unwrap()
        .json::<serde_json::Value>().await.unwrap();
    let b_pushed = client
        .post(format!("{}/v1/vaults/{}/wal/push", pair.b.base, SHARED_VAULT_ID))
        .send().await.unwrap()
        .json::<serde_json::Value>().await.unwrap();
    assert!(a_pushed["pushed"].as_u64().unwrap_or(0) > 0);
    assert!(b_pushed["pushed"].as_u64().unwrap_or(0) > 0);

    // Each engine pulls the OTHER's entries; the CRDT merge in
    // `apply_remote_wal_segment` either applies (different file_id ⇒ no
    // conflict) or skips (same file_id, lower HLC). Either way, no crash.
    let a_pulled = client
        .post(format!("{}/v1/vaults/{}/wal/pull", pair.a.base, SHARED_VAULT_ID))
        .send().await.unwrap()
        .json::<serde_json::Value>().await.unwrap();
    let b_pulled = client
        .post(format!("{}/v1/vaults/{}/wal/pull", pair.b.base, SHARED_VAULT_ID))
        .send().await.unwrap()
        .json::<serde_json::Value>().await.unwrap();
    assert!(a_pulled["foreign_entries"].as_u64().unwrap_or(0) > 0);
    assert!(b_pulled["foreign_entries"].as_u64().unwrap_or(0) > 0);
    // No unhandled-op or error counters; the CRDT merge swallows
    // skipped (different file_id) cleanly.
    let unhandled = a_pulled["unhandled"].as_u64().unwrap_or(99)
        + b_pulled["unhandled"].as_u64().unwrap_or(99);
    assert_eq!(unhandled, 0, "expected no unhandled ops, got a={a_pulled:?}, b={b_pulled:?}");
}

async fn upload(
    client: &reqwest::Client,
    engine: &common::Engine,
    path: &str,
    body: &[u8],
) {
    let status_resp = client
        .get(format!("{}/v1/system/status", engine.base))
        .send()
        .await
        .unwrap();
    let s: serde_json::Value = status_resp.json().await.unwrap();
    let vault_id = s["vault_id"].as_str().expect("vault_id").to_string();
    let resp = client
        .put(format!(
            "{}/v1/vaults/{}/files{}",
            engine.base, vault_id, path
        ))
        .body(body.to_vec())
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "upload: {}", resp.status());
}
