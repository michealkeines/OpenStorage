//! CLI-level integration tests for Wave 1 file operations.
//!
//! Each test spawns an in-process engine, then drives the `os` CLI binary
//! against it via `assert_cmd`. The CLI's persistent state is redirected to a
//! temp dir via `OPENSTORAGE_STATE_DIR`.

mod common;

use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Write;

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
async fn cli_upload_then_mv_then_download() {
    let engine = common::spawn_engine().await;
    init(&engine);

    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("hello.txt");
    std::fs::write(&input, b"hello world").unwrap();

    os_cmd(&engine)
        .args(["upload", input.to_str().unwrap(), "--as", "/old.txt"])
        .assert()
        .success();

    // F-FL-5: move
    os_cmd(&engine)
        .args(["mv", "/old.txt", "/new.txt"])
        .assert()
        .success()
        .stdout(predicate::str::contains("/old.txt → /new.txt"));

    // Old path must be gone.
    os_cmd(&engine)
        .args(["stat", "/old.txt"])
        .assert()
        .failure();

    // New path serves the original content.
    let out = tmp.path().join("dl.txt");
    os_cmd(&engine)
        .args(["download", "/new.txt", "--out", out.to_str().unwrap()])
        .assert()
        .success();
    let got = std::fs::read(&out).unwrap();
    assert_eq!(got, b"hello world");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_mv_missing_fails() {
    let engine = common::spawn_engine().await;
    init(&engine);
    os_cmd(&engine)
        .args(["mv", "/missing", "/wherever"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found").or(predicate::str::contains("404")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_patch_byte_range() {
    let engine = common::spawn_engine().await;
    init(&engine);

    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("orig.bin");
    let mut f = std::fs::File::create(&input).unwrap();
    f.write_all(b"AAAAAAAAAAAA").unwrap();
    f.sync_all().unwrap();
    drop(f);

    os_cmd(&engine)
        .args(["upload", input.to_str().unwrap(), "--as", "/data.bin"])
        .assert()
        .success();

    let patch_src = tmp.path().join("patch.bin");
    std::fs::write(&patch_src, b"ZZZZ").unwrap();

    // F-FL-3: patch bytes 4..=7
    os_cmd(&engine)
        .args([
            "patch",
            "/data.bin",
            patch_src.to_str().unwrap(),
            "--start",
            "4",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("patched"));

    let out = tmp.path().join("dl.bin");
    os_cmd(&engine)
        .args(["download", "/data.bin", "--out", out.to_str().unwrap()])
        .assert()
        .success();
    let got = std::fs::read(&out).unwrap();
    assert_eq!(got, b"AAAAZZZZAAAA");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_rm_then_stat_404() {
    // Backfill: F-FL-4 (delete) + F-FL-6 (HEAD).
    let engine = common::spawn_engine().await;
    init(&engine);

    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("z");
    std::fs::write(&input, b"xx").unwrap();
    os_cmd(&engine)
        .args(["upload", input.to_str().unwrap(), "--as", "/z"])
        .assert()
        .success();
    os_cmd(&engine)
        .args(["stat", "/z"])
        .assert()
        .success()
        .stdout(predicate::str::contains("size:"));
    os_cmd(&engine).args(["rm", "/z"]).assert().success();
    os_cmd(&engine).args(["stat", "/z"]).assert().failure();
}
