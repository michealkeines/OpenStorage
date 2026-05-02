//! CLI integration tests for Wave 4 maintenance flows
//! (F-HM-1 scrub, F-HM-4 rebalance, F-HM-5 gc).

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_repair_scrub_gc_rebalance() {
    let engine = common::spawn_engine().await;
    init(&engine);
    os_cmd(&engine)
        .args(["repair", "scrub", "--per-thousand", "50"])
        .assert()
        .success()
        .stdout(predicate::str::contains("scrub enqueued"));
    os_cmd(&engine)
        .args(["repair", "gc"])
        .assert()
        .success()
        .stdout(predicate::str::contains("gc enqueued"));
    os_cmd(&engine)
        .args(["repair", "rebalance", "--per-thousand", "100"])
        .assert()
        .success()
        .stdout(predicate::str::contains("rebalance enqueued"));
}
