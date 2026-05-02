//! `os` — OpenStorage CLI.
//!
//! Talks to a local engine over HTTP (default `http://127.0.0.1:7878`).
//!
//! Commands:
//!   os init [--passphrase X]       Create a vault and remember it.
//!   os upload <file> [--as <path>] Stream the file into the active vault.
//!   os download <name> [--out P]   Stream the file back out.
//!   os ls [--prefix /]             List files in the active vault.
//!   os lock                        Lock the active vault.
//!   os unlock                      Re-unlock with the saved passphrase.
//!   os status                      Show vault state.
//!
//! State (vault_id + passphrase) is stored in
//! `$XDG_CONFIG_HOME/openstorage/state.json` (or platform equivalent). The
//! passphrase is plaintext on disk by design — this is a developer CLI.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

#[derive(Parser, Debug)]
#[command(
    name = "os",
    version,
    about = "OpenStorage CLI",
    after_help = "Reads the engine endpoint from --base or $OPENSTORAGE_BASE; default http://127.0.0.1:7878.\n\
                  Vault state is persisted under $XDG_CONFIG_HOME/openstorage/state.json."
)]
struct Cli {
    /// Engine base URL.
    #[arg(long, env = "OPENSTORAGE_BASE", default_value = "http://127.0.0.1:7878")]
    base: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Create a new vault and remember it on disk.
    Init {
        /// Passphrase. Will prompt or use `$OPENSTORAGE_PASSPHRASE` if absent.
        #[arg(long, env = "OPENSTORAGE_PASSPHRASE")]
        passphrase: Option<String>,
    },
    /// Show current vault state.
    Status,
    /// Lock the active vault.
    Lock,
    /// Unlock the active vault with the saved passphrase.
    Unlock,
    /// Upload a local file into the active vault.
    Upload {
        /// Local path to read from.
        file: PathBuf,
        /// Remote name (default: file's basename, prefixed with `/`).
        #[arg(long = "as", short = 'a')]
        as_name: Option<String>,
    },
    /// Download a remote file from the active vault.
    Download {
        /// Remote name (e.g., `notes.txt` or `/notes.txt`).
        name: String,
        /// Local path to write to. Default: basename of `<name>` in CWD.
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,
        /// Verify by recomputing BLAKE3 of the downloaded file. Default true.
        #[arg(long, default_value_t = true)]
        verify: bool,
    },
    /// List files in the active vault.
    Ls {
        #[arg(long, default_value = "/")]
        prefix: String,
    },
    /// Show metadata for a single file (HEAD).
    Stat {
        /// Remote name.
        name: String,
    },
    /// Delete a file from the active vault.
    Rm {
        /// Remote name.
        name: String,
    },
    /// Rename / move a file in the active vault.
    Mv {
        /// Source name.
        src: String,
        /// Destination name.
        dst: String,
    },
    /// Patch a byte range of an existing file (PATCH with Content-Range).
    Patch {
        /// Remote name.
        name: String,
        /// Local file holding the replacement bytes.
        from: PathBuf,
        /// Start byte offset (inclusive).
        #[arg(long)]
        start: u64,
        /// Total file size after patch (defaults to current size or
        /// `start + body_len`, whichever is larger).
        #[arg(long)]
        total: Option<u64>,
    },
    /// Destroy the active vault (requires --confirm).
    Destroy {
        /// Type the vault id to confirm.
        #[arg(long)]
        confirm: String,
    },
    /// Rotate the master key with a new passphrase.
    RotateMk {
        /// New passphrase. Auto-saved to state.json.
        #[arg(long)]
        new_passphrase: String,
    },
    /// Show identity chain on the active vault.
    Identity {
        #[command(subcommand)]
        cmd: IdentityCmd,
    },
    /// Recovery configuration ops.
    Recovery {
        #[command(subcommand)]
        cmd: RecoveryCmd,
    },
    /// Advisory lease ops.
    Lease {
        #[command(subcommand)]
        cmd: LeaseCmd,
    },
    /// WAL inspection.
    Wal {
        #[command(subcommand)]
        cmd: WalCmd,
    },
    /// Snapshot inspection.
    Snapshot {
        #[command(subcommand)]
        cmd: SnapshotCmd,
    },
    /// Provider inventory.
    Providers {
        #[command(subcommand)]
        cmd: ProvidersCmd,
    },
    /// Peer inventory.
    Peers {
        #[command(subcommand)]
        cmd: PeersCmd,
    },
    /// Shadow registry inspection.
    Shadows {
        #[command(subcommand)]
        cmd: ShadowsCmd,
    },
    /// Repair queue operations.
    Repair {
        #[command(subcommand)]
        cmd: RepairCmd,
    },
    /// Share inventory.
    Shares {
        #[command(subcommand)]
        cmd: SharesCmd,
    },
    /// Tail recent events.
    Events {
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Fault-injection control (test-only).
    Fault {
        #[command(subcommand)]
        cmd: FaultCmd,
    },
    /// F-PL — plugin install / oauth / capability drift.
    Plugins {
        #[command(subcommand)]
        cmd: PluginsCmd,
    },
    /// Plugin-state machine transitions.
    PluginState {
        #[command(subcommand)]
        cmd: PluginStateCmd,
    },
    /// Manage credentials in the user's providers file.
    Auth {
        #[command(subcommand)]
        cmd: AuthCmd,
    },
}

#[derive(Subcommand, Debug)]
enum AuthCmd {
    /// List configured providers (secrets redacted).
    Ls,
    /// Print the path of the providers file.
    Path,
    /// Remove a provider entry by label.
    Rm { label: String },
    /// Add a credential entry. Each subcommand walks an interactive flow:
    /// opens a browser when relevant, prompts for paste, validates against
    /// the live API, then writes to the providers file (mode 0600).
    Add {
        #[command(subcommand)]
        kind: AuthKind,
    },
}

#[derive(Subcommand, Debug)]
enum AuthKind {
    /// GitHub repo (Personal Access Token). Opens browser to GitHub's
    /// new-token page; user pastes the token; CLI validates by hitting
    /// /user, then prompts for owner/repo/branch.
    Github {
        #[arg(long)]
        label: Option<String>,
    },
    /// Telegram bot. Prompts for bot_token + chat_id, validates via /getMe.
    Telegram {
        #[arg(long)]
        label: Option<String>,
    },
    /// Discord webhook. Prompts for webhook URL, validates via HEAD.
    Discord {
        #[arg(long)]
        label: Option<String>,
    },
    /// Mint a fresh anonymous Telegraph account and save its access_token.
    Telegraph {
        #[arg(long)]
        label: Option<String>,
    },
    /// uguu.se — anonymous, no credential. Adds an entry so the engine
    /// registers it as a provider on startup.
    Uguu {
        #[arg(long)]
        label: Option<String>,
    },
    /// catbox.moe — anonymous, persistent, 200 MiB cap.
    Catbox {
        #[arg(long)]
        label: Option<String>,
    },
    /// paste.rs — anonymous text-only paste (binary base64-encoded).
    PasteRs {
        #[arg(long)]
        label: Option<String>,
    },
    /// filebin.net — anonymous bin-based host (5 GiB / bin, 7-day TTL).
    Filebin {
        #[arg(long)]
        label: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum FaultCmd {
    Show,
    /// Set or clear fault counters in one shot.
    Set {
        #[arg(long)]
        fail_puts: Option<u32>,
        #[arg(long)]
        fail_gets: Option<u32>,
        #[arg(long)]
        corrupt_gets: Option<u32>,
        #[arg(long)]
        pause: Option<bool>,
    },
    /// Clear all fault counters and unpause.
    Clear,
}

#[derive(Subcommand, Debug)]
enum PluginsCmd {
    /// F-PL-1 — install a signed plugin manifest.
    Install {
        #[arg(long)]
        manifest_hex: String,
        /// "confirm" or "double" (red legal_class needs double).
        #[arg(long, default_value = "confirm")]
        confirmation: String,
    },
    /// F-PL-3 — push a new capability set after a plugin reload.
    Reload {
        plugin_id: String,
        #[arg(long)]
        capabilities_hex: String,
    },
    /// F-PL-2 — start an OAuth flow.
    OauthStart {
        #[arg(long)]
        plugin_id: String,
        #[arg(long)]
        auth_url: String,
        #[arg(long, value_delimiter = ',')]
        scope: Vec<String>,
    },
    /// F-PL-2 — complete an OAuth flow with the access token.
    OauthComplete {
        #[arg(long)]
        state: String,
        #[arg(long)]
        token_hex: String,
        #[arg(long, value_delimiter = ',')]
        granted: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
enum PluginStateCmd {
    Show {
        provider_id: String,
    },
    /// Drive a state transition. transition ∈ init|ready|activate|pause|resume|disable|close.
    Set {
        provider_id: String,
        transition: String,
    },
}

#[derive(Subcommand, Debug)]
enum IdentityCmd {
    Show,
    Rotate,
}

#[derive(Subcommand, Debug)]
enum RecoveryCmd {
    Show,
    RotateToken,
}

#[derive(Subcommand, Debug)]
enum LeaseCmd {
    Show,
    Acquire,
    Renew,
    Release,
    /// CAS-overwrite a stale lease (F-MD-4). The TTL must be the value the
    /// prior holder was using; the steal succeeds only if 2×ttl seconds
    /// have elapsed since the prior expires_at.
    Steal {
        #[arg(long, default_value_t = 30)]
        ttl_secs: u64,
    },
}

#[derive(Subcommand, Debug)]
enum WalCmd {
    Show,
}

#[derive(Subcommand, Debug)]
enum SnapshotCmd {
    Show,
    /// F-SN-1 — push a snapshot to the configured vault provider. The
    /// optional knobs trigger the pointer-CAS guard and differential
    /// filter respectively.
    Push {
        #[arg(long)]
        expect_version: Option<u64>,
        #[arg(long)]
        delta_since_hlc: Option<u64>,
    },
    /// F-SN-2 — pull a snapshot identified by its `snapshot_handle_hex`
    /// (printed by `snapshot push`).
    Pull {
        #[arg(long)]
        handle_hex: String,
    },
}

#[derive(Subcommand, Debug)]
enum ProvidersCmd {
    Ls,
}

#[derive(Subcommand, Debug)]
enum PeersCmd {
    Ls,
}

#[derive(Subcommand, Debug)]
enum ShadowsCmd {
    Ls,
}

#[derive(Subcommand, Debug)]
enum RepairCmd {
    Show,
    /// F-HM-1 — kick a sampled scrub batch.
    Scrub {
        #[arg(long, default_value_t = 50)]
        per_thousand: u32,
    },
    /// F-HM-5 — kick a GC sweep over zero-refcount chunks.
    Gc,
    /// F-HM-4 — kick rebalance enqueue.
    Rebalance {
        #[arg(long, default_value_t = 100)]
        per_thousand: u32,
    },
    /// Manually enqueue a repair task (test-only).
    Enqueue {
        /// 32-byte chunk hash, hex-encoded.
        #[arg(long)]
        chunk_hash: String,
        #[arg(long, default_value_t = 1)]
        priority: u32,
        #[arg(long, default_value = "scrub")]
        source: String,
    },
}

#[derive(Subcommand, Debug)]
enum SharesCmd {
    Ls,
    /// Create a share. Prints the signed blob and the owner pubkey the
    /// recipient needs in order to accept.
    Create {
        /// PeerId. Use `peer:test-recipient` for the harness.
        #[arg(long)]
        recipient: String,
        /// Path scope (`*` for whole vault).
        #[arg(long)]
        scope: String,
    },
    /// Accept a share previously created. Reads `--blob-hex` and
    /// `--owner-pub-hex` from the create command's output.
    Accept {
        share_id: String,
        #[arg(long = "blob-hex")]
        blob_hex: String,
        #[arg(long = "owner-pub-hex")]
        owner_sign_pub_hex: String,
        /// Optional override for the local mount path. Defaults to
        /// `/shared-with-me/<owner>/<scope>`.
        #[arg(long)]
        mount: Option<String>,
    },
    /// List accepted shares (the recipient inbox).
    Inbox,
    Revoke {
        share_id: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct State {
    base: String,
    vault_id: String,
    passphrase: String,
}

impl State {
    fn path() -> Result<PathBuf> {
        // `$OPENSTORAGE_STATE_DIR` lets integration tests pin per-test state
        // without polluting the user's real config directory.
        let dir = if let Ok(p) = std::env::var("OPENSTORAGE_STATE_DIR") {
            PathBuf::from(p)
        } else {
            dirs::config_dir()
                .ok_or_else(|| anyhow!("could not resolve config directory"))?
                .join("openstorage")
        };
        std::fs::create_dir_all(&dir)?;
        Ok(dir.join("state.json"))
    }

    fn load() -> Result<Option<Self>> {
        let p = Self::path()?;
        if !p.exists() {
            return Ok(None);
        }
        let s = std::fs::read_to_string(&p)?;
        Ok(Some(serde_json::from_str(&s)?))
    }

    fn save(&self) -> Result<()> {
        let p = Self::path()?;
        let tmp = p.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, &p)?;
        // 0600 on POSIX so other local users can't read the passphrase.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&p, perms)?;
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()?;

    match cli.cmd {
        Cmd::Init { passphrase } => init(&client, &cli.base, passphrase).await,
        Cmd::Status => status(&client, &cli.base).await,
        Cmd::Lock => lock(&client, &cli.base).await,
        Cmd::Unlock => unlock(&client, &cli.base).await,
        Cmd::Upload { file, as_name } => upload(&client, &cli.base, &file, as_name).await,
        Cmd::Download { name, out, verify } => {
            download(&client, &cli.base, &name, out, verify).await
        }
        Cmd::Ls { prefix } => ls(&client, &cli.base, &prefix).await,
        Cmd::Stat { name } => stat(&client, &cli.base, &name).await,
        Cmd::Rm { name } => rm(&client, &cli.base, &name).await,
        Cmd::Mv { src, dst } => mv(&client, &cli.base, &src, &dst).await,
        Cmd::Patch { name, from, start, total } => {
            patch(&client, &cli.base, &name, &from, start, total).await
        }
        Cmd::Destroy { confirm } => destroy(&client, &cli.base, &confirm).await,
        Cmd::RotateMk { new_passphrase } => rotate_mk(&client, &cli.base, &new_passphrase).await,
        Cmd::Identity { cmd } => identity_cmd(&client, &cli.base, cmd).await,
        Cmd::Recovery { cmd } => recovery_cmd(&client, &cli.base, cmd).await,
        Cmd::Lease { cmd } => lease_cmd(&client, &cli.base, cmd).await,
        Cmd::Wal { cmd } => wal_cmd(&client, &cli.base, cmd).await,
        Cmd::Snapshot { cmd } => snapshot_cmd(&client, &cli.base, cmd).await,
        Cmd::Providers { cmd } => providers_cmd(&client, &cli.base, cmd).await,
        Cmd::Peers { cmd } => peers_cmd(&client, &cli.base, cmd).await,
        Cmd::Shadows { cmd } => shadows_cmd(&client, &cli.base, cmd).await,
        Cmd::Repair { cmd } => repair_cmd(&client, &cli.base, cmd).await,
        Cmd::Shares { cmd } => shares_cmd(&client, &cli.base, cmd).await,
        Cmd::Events { limit } => events_tail(&client, &cli.base, limit).await,
        Cmd::Fault { cmd } => fault_cmd(&client, &cli.base, cmd).await,
        Cmd::Plugins { cmd } => plugins_cmd(&client, &cli.base, cmd).await,
        Cmd::PluginState { cmd } => plugin_state_cmd(&client, &cli.base, cmd).await,
        Cmd::Auth { cmd } => auth_cmd(&client, cmd).await,
    }
}

// ─── commands ──────────────────────────────────────────────────────────────

async fn init(client: &reqwest::Client, base: &str, passphrase: Option<String>) -> Result<()> {
    let pass = match passphrase {
        Some(p) => p,
        None => prompt_password()?,
    };
    if pass.is_empty() {
        bail!("passphrase must not be empty");
    }
    let resp = client
        .post(format!("{base}/v1/vaults"))
        .json(&serde_json::json!({ "passphrase": pass }))
        .send()
        .await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("vault create failed: {status} {body}");
    }
    let parsed: serde_json::Value = resp.json().await?;
    let vault_id = parsed["vault_id"]
        .as_str()
        .ok_or_else(|| anyhow!("missing vault_id in response"))?
        .to_string();

    let state = State {
        base: base.to_string(),
        vault_id: vault_id.clone(),
        passphrase: pass,
    };
    state.save()?;
    println!("vault {vault_id} created and saved to {}", State::path()?.display());
    Ok(())
}

async fn status(client: &reqwest::Client, base: &str) -> Result<()> {
    let resp = client.get(format!("{base}/v1/system/status")).send().await?;
    let body: serde_json::Value = resp.json().await?;
    println!("{}", serde_json::to_string_pretty(&body)?);
    if let Some(state) = State::load()? {
        println!("(saved vault on this device: {})", state.vault_id);
    } else {
        println!("(no saved vault on this device — run `os init` first)");
    }
    Ok(())
}

async fn lock(client: &reqwest::Client, base: &str) -> Result<()> {
    let st = State::load()?.ok_or_else(|| anyhow!("no saved vault — run `os init` first"))?;
    let resp = client
        .post(format!("{base}/v1/vaults/{}/lock", st.vault_id))
        .send()
        .await?;
    if !resp.status().is_success() {
        bail!("lock failed: {}", resp.status());
    }
    println!("vault {} locked", st.vault_id);
    Ok(())
}

async fn unlock(client: &reqwest::Client, base: &str) -> Result<()> {
    let st = State::load()?.ok_or_else(|| anyhow!("no saved vault — run `os init` first"))?;
    let resp = client
        .post(format!("{base}/v1/vaults/{}/unlock", st.vault_id))
        .json(&serde_json::json!({ "passphrase": st.passphrase }))
        .send()
        .await?;
    if !resp.status().is_success() {
        let s = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("unlock failed: {s} {body}");
    }
    println!("vault {} unlocked", st.vault_id);
    Ok(())
}

/// Make sure the active vault is Unlocked. Auto-unlocks if needed.
async fn ensure_unlocked(client: &reqwest::Client, base: &str, st: &State) -> Result<()> {
    let resp = client.get(format!("{base}/v1/system/status")).send().await?;
    let body: serde_json::Value = resp.json().await?;
    let state = body["state"].as_str().unwrap_or("");
    if state == "unlocked" {
        return Ok(());
    }
    // Try to unlock with saved passphrase.
    let resp = client
        .post(format!("{base}/v1/vaults/{}/unlock", st.vault_id))
        .json(&serde_json::json!({ "passphrase": st.passphrase }))
        .send()
        .await?;
    if !resp.status().is_success() {
        let s = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("auto-unlock failed: {s} {body}");
    }
    Ok(())
}

async fn upload(
    client: &reqwest::Client,
    base: &str,
    file: &Path,
    as_name: Option<String>,
) -> Result<()> {
    let st = State::load()?.ok_or_else(|| anyhow!("no saved vault — run `os init` first"))?;
    ensure_unlocked(client, base, &st).await?;

    let metadata = std::fs::metadata(file).with_context(|| format!("stat {}", file.display()))?;
    let size = metadata.len();
    let remote = as_name.unwrap_or_else(|| {
        let base = file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file.bin");
        format!("/{base}")
    });
    let remote_url = format!(
        "{base}/v1/vaults/{vid}/files{name}",
        vid = st.vault_id,
        name = if remote.starts_with('/') {
            remote.clone()
        } else {
            format!("/{remote}")
        }
    );

    println!(
        "→ {} ({}) → {}{}",
        file.display(),
        format_bytes(size),
        remote_url,
        ""
    );

    // Stream upload via reqwest::Body::wrap_stream over a tokio File.
    let pb = ProgressBar::new(size);
    pb.set_style(
        ProgressStyle::with_template(
            "{prefix} {bar:30.cyan/blue} {bytes}/{total_bytes} {bytes_per_sec} eta {eta}",
        )?
        .progress_chars("=> "),
    );
    pb.set_prefix("upload");

    let f = tokio::fs::File::open(file).await?;
    let stream = ProgressStream::new(f, pb.clone());
    let body = reqwest::Body::wrap_stream(stream);

    let started = std::time::Instant::now();
    let resp = client
        .put(&remote_url)
        .header("content-length", size.to_string())
        .header("content-type", "application/octet-stream")
        .body(body)
        .send()
        .await?;
    pb.finish_and_clear();

    if !resp.status().is_success() {
        let s = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("upload failed: {s} {body}");
    }
    let parsed: serde_json::Value = resp.json().await?;
    let elapsed = started.elapsed();
    let mb = size as f64 / 1024.0 / 1024.0;
    println!(
        "✓ uploaded {} as {} in {:.1}s ({:.1} MB/s)",
        format_bytes(size),
        parsed["path"].as_str().unwrap_or("?"),
        elapsed.as_secs_f64(),
        mb / elapsed.as_secs_f64().max(0.001)
    );
    Ok(())
}

async fn download(
    client: &reqwest::Client,
    base: &str,
    name: &str,
    out: Option<PathBuf>,
    verify: bool,
) -> Result<()> {
    let st = State::load()?.ok_or_else(|| anyhow!("no saved vault — run `os init` first"))?;
    ensure_unlocked(client, base, &st).await?;

    let remote = if name.starts_with('/') {
        name.to_string()
    } else {
        format!("/{name}")
    };
    let url = format!("{base}/v1/vaults/{}/files{remote}", st.vault_id);

    let out_path = out.unwrap_or_else(|| {
        let base = remote.trim_start_matches('/');
        PathBuf::from(if base.is_empty() { "download.bin" } else { base })
    });

    println!("← {url} → {}", out_path.display());

    let started = std::time::Instant::now();
    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        let s = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("download failed: {s} {body}");
    }
    let total = resp
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::with_template(
            "{prefix} {bar:30.green/blue} {bytes}/{total_bytes} {bytes_per_sec} eta {eta}",
        )?
        .progress_chars("=> "),
    );
    pb.set_prefix("download");

    let mut file = tokio::fs::File::create(&out_path).await?;
    let mut hasher = if verify { Some(blake3::Hasher::new()) } else { None };
    let mut written: u64 = 0;
    let mut stream = resp.bytes_stream();
    use futures::StreamExt;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        file.write_all(&chunk).await?;
        if let Some(h) = hasher.as_mut() {
            h.update(&chunk);
        }
        written += chunk.len() as u64;
        pb.set_position(written);
    }
    file.sync_all().await?;
    pb.finish_and_clear();

    let elapsed = started.elapsed();
    let mb = written as f64 / 1024.0 / 1024.0;
    println!(
        "✓ downloaded {} → {} in {:.1}s ({:.1} MB/s)",
        format_bytes(written),
        out_path.display(),
        elapsed.as_secs_f64(),
        mb / elapsed.as_secs_f64().max(0.001)
    );
    if let Some(h) = hasher {
        println!("  blake3: {}", h.finalize().to_hex());
    }
    Ok(())
}

async fn stat(client: &reqwest::Client, base: &str, name: &str) -> Result<()> {
    let st = State::load()?.ok_or_else(|| anyhow!("no saved vault — run `os init` first"))?;
    ensure_unlocked(client, base, &st).await?;
    let remote = if name.starts_with('/') {
        name.to_string()
    } else {
        format!("/{name}")
    };
    let url = format!("{base}/v1/vaults/{}/files{remote}", st.vault_id);
    let resp = client.head(&url).send().await?;
    let status = resp.status();
    if status.as_u16() == 404 {
        bail!("not found: {name}");
    }
    if !status.is_success() {
        bail!("stat failed: {status}");
    }
    let size = resp
        .headers()
        .get("x-size-bytes")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("?");
    let file_id = resp
        .headers()
        .get("x-file-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("?");
    println!("path:    {name}");
    println!("size:    {size} bytes");
    println!("file_id: {file_id}");
    Ok(())
}

async fn rm(client: &reqwest::Client, base: &str, name: &str) -> Result<()> {
    let st = State::load()?.ok_or_else(|| anyhow!("no saved vault — run `os init` first"))?;
    ensure_unlocked(client, base, &st).await?;
    let remote = if name.starts_with('/') {
        name.to_string()
    } else {
        format!("/{name}")
    };
    let url = format!("{base}/v1/vaults/{}/files{remote}", st.vault_id);
    let resp = client.delete(&url).send().await?;
    if resp.status().as_u16() == 404 {
        bail!("not found: {name}");
    }
    if !resp.status().is_success() {
        bail!("delete failed: {}", resp.status());
    }
    println!("✓ deleted {name}");
    Ok(())
}

async fn mv(client: &reqwest::Client, base: &str, src: &str, dst: &str) -> Result<()> {
    let st = State::load()?.ok_or_else(|| anyhow!("no saved vault — run `os init` first"))?;
    ensure_unlocked(client, base, &st).await?;
    let src_remote = if src.starts_with('/') { src.to_string() } else { format!("/{src}") };
    let dst_remote = if dst.starts_with('/') { dst.to_string() } else { format!("/{dst}") };
    let url = format!("{base}/v1/vaults/{}/files{src_remote}/move", st.vault_id);
    let resp = client
        .post(&url)
        .json(&serde_json::json!({ "to": dst_remote }))
        .send()
        .await?;
    if resp.status().as_u16() == 404 {
        bail!("not found: {src}");
    }
    if !resp.status().is_success() {
        bail!("rename failed: {}", resp.status());
    }
    println!("✓ {src} → {dst}");
    Ok(())
}

async fn patch(
    client: &reqwest::Client,
    base: &str,
    name: &str,
    from: &Path,
    start: u64,
    total_override: Option<u64>,
) -> Result<()> {
    let st = State::load()?.ok_or_else(|| anyhow!("no saved vault — run `os init` first"))?;
    ensure_unlocked(client, base, &st).await?;
    let body = std::fs::read(from).with_context(|| format!("read {}", from.display()))?;
    if body.is_empty() {
        bail!("body must be non-empty");
    }
    let end = start + body.len() as u64 - 1;
    // Discover current size via HEAD if total not provided.
    let remote = if name.starts_with('/') { name.to_string() } else { format!("/{name}") };
    let total = match total_override {
        Some(t) => t,
        None => {
            let head_url = format!("{base}/v1/vaults/{}/files{remote}", st.vault_id);
            let r = client.head(&head_url).send().await?;
            if !r.status().is_success() {
                bail!("HEAD {name} failed: {}", r.status());
            }
            let cur = r
                .headers()
                .get("x-size-bytes")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            cur.max(end + 1)
        }
    };
    let url = format!("{base}/v1/vaults/{}/files{remote}", st.vault_id);
    let cr = format!("bytes {start}-{end}/{total}");
    let resp = client
        .patch(&url)
        .header("content-range", cr)
        .header("content-type", "application/octet-stream")
        .body(body)
        .send()
        .await?;
    if !resp.status().is_success() {
        let s = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("patch failed: {s} {body}");
    }
    println!("✓ patched {name} [{start}..={end}] of {total}");
    Ok(())
}

async fn ls(client: &reqwest::Client, base: &str, prefix: &str) -> Result<()> {
    let st = State::load()?.ok_or_else(|| anyhow!("no saved vault — run `os init` first"))?;
    ensure_unlocked(client, base, &st).await?;
    let resp = client
        .get(format!("{base}/v1/vaults/{}/dirs", st.vault_id))
        .query(&[("prefix", prefix)])
        .send()
        .await?;
    if !resp.status().is_success() {
        bail!("ls failed: {}", resp.status());
    }
    let body: serde_json::Value = resp.json().await?;
    if let Some(arr) = body.as_array() {
        if arr.is_empty() {
            println!("(no files under {prefix})");
            return Ok(());
        }
        println!("{:<40}  {:>14}  {}", "path", "size", "file_id");
        for entry in arr {
            let path = entry["path"].as_str().unwrap_or("?");
            let size = entry["size_bytes"].as_u64().unwrap_or(0);
            let id = entry["file_id"].as_str().unwrap_or("?");
            println!("{path:<40}  {:>14}  {id}", format_bytes(size));
        }
    } else {
        println!("{}", serde_json::to_string_pretty(&body)?);
    }
    Ok(())
}

// ─── helpers ───────────────────────────────────────────────────────────────

fn prompt_password() -> Result<String> {
    use std::io::Write;
    eprint!("passphrase: ");
    std::io::stderr().flush()?;
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_string())
}

fn format_bytes(n: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let n = n as f64;
    if n < KB {
        format!("{n:.0} B")
    } else if n < MB {
        format!("{:.1} KB", n / KB)
    } else if n < GB {
        format!("{:.1} MB", n / MB)
    } else {
        format!("{:.2} GB", n / GB)
    }
}

// Wraps an AsyncRead and updates a progress bar as bytes flow.
struct ProgressStream {
    inner: tokio_util::io::ReaderStream<tokio::fs::File>,
    pb: ProgressBar,
}

impl ProgressStream {
    fn new(file: tokio::fs::File, pb: ProgressBar) -> Self {
        Self {
            inner: tokio_util::io::ReaderStream::new(file),
            pb,
        }
    }
}

impl futures::Stream for ProgressStream {
    type Item = std::io::Result<bytes::Bytes>;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let pb = self.pb.clone();
        let inner = std::pin::Pin::new(&mut self.inner);
        match inner.poll_next(cx) {
            std::task::Poll::Ready(Some(Ok(b))) => {
                pb.inc(b.len() as u64);
                std::task::Poll::Ready(Some(Ok(b)))
            }
            other => other,
        }
    }
}

// ─── new subcommand handlers ───────────────────────────────────────────────

async fn destroy(client: &reqwest::Client, base: &str, confirm: &str) -> Result<()> {
    let st = State::load()?.ok_or_else(|| anyhow!("no saved vault — run `os init` first"))?;
    if confirm != st.vault_id {
        bail!("--confirm must equal the active vault id ({})", st.vault_id);
    }
    let resp = client
        .delete(format!("{base}/v1/vaults/{}", st.vault_id))
        .header("x-confirm-destroy", "yes")
        .send()
        .await?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await?;
    if !status.is_success() {
        bail!("destroy failed: {status} {body}");
    }
    println!("✓ destroyed vault {}", st.vault_id);
    println!("{}", serde_json::to_string_pretty(&body)?);
    // Remove the saved state file.
    let p = State::path()?;
    let _ = std::fs::remove_file(&p);
    Ok(())
}

async fn rotate_mk(client: &reqwest::Client, base: &str, new_pass: &str) -> Result<()> {
    let mut st = State::load()?.ok_or_else(|| anyhow!("no saved vault — run `os init` first"))?;
    ensure_unlocked(client, base, &st).await?;
    let resp = client
        .post(format!("{base}/v1/vaults/{}/rotate-mk", st.vault_id))
        .json(&serde_json::json!({ "new_passphrase": new_pass }))
        .send()
        .await?;
    if !resp.status().is_success() {
        let s = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("rotate-mk failed: {s} {body}");
    }
    st.passphrase = new_pass.to_string();
    st.save()?;
    println!("✓ master key rotated; saved new passphrase to {}", State::path()?.display());
    Ok(())
}

async fn identity_cmd(client: &reqwest::Client, base: &str, cmd: IdentityCmd) -> Result<()> {
    let st = State::load()?.ok_or_else(|| anyhow!("no saved vault"))?;
    ensure_unlocked(client, base, &st).await?;
    match cmd {
        IdentityCmd::Show => {
            let resp = client
                .get(format!("{base}/v1/vaults/{}/identity", st.vault_id))
                .send()
                .await?;
            let body: serde_json::Value = resp.json().await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        IdentityCmd::Rotate => {
            let resp = client
                .post(format!("{base}/v1/vaults/{}/identity/rotate", st.vault_id))
                .send()
                .await?;
            if !resp.status().is_success() {
                let s = resp.status();
                let body = resp.text().await.unwrap_or_default();
                bail!("identity rotate failed: {s} {body}");
            }
            let body: serde_json::Value = resp.json().await?;
            println!("✓ rotated identity to epoch {}", body["new_epoch"]);
            println!("  fingerprint: {}", body["fingerprint"].as_str().unwrap_or("?"));
        }
    }
    Ok(())
}

async fn recovery_cmd(client: &reqwest::Client, base: &str, cmd: RecoveryCmd) -> Result<()> {
    let st = State::load()?.ok_or_else(|| anyhow!("no saved vault"))?;
    ensure_unlocked(client, base, &st).await?;
    match cmd {
        RecoveryCmd::Show => {
            let resp = client
                .get(format!("{base}/v1/vaults/{}/recovery", st.vault_id))
                .send()
                .await?;
            let body: serde_json::Value = resp.json().await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        RecoveryCmd::RotateToken => {
            let resp = client
                .post(format!("{base}/v1/vaults/{}/recovery/rotate-token", st.vault_id))
                .send()
                .await?;
            if !resp.status().is_success() {
                let s = resp.status();
                let body = resp.text().await.unwrap_or_default();
                bail!("rotate-token failed: {s} {body}");
            }
            let body: serde_json::Value = resp.json().await?;
            println!("✓ rotated recovery token: {}", body["new_token_id"].as_str().unwrap_or("?"));
        }
    }
    Ok(())
}

async fn lease_cmd(client: &reqwest::Client, base: &str, cmd: LeaseCmd) -> Result<()> {
    let st = State::load()?.ok_or_else(|| anyhow!("no saved vault"))?;
    ensure_unlocked(client, base, &st).await?;
    let url_base = format!("{base}/v1/vaults/{}/lease", st.vault_id);
    match cmd {
        LeaseCmd::Show => {
            let resp = client.get(&url_base).send().await?;
            let body: serde_json::Value = resp.json().await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        LeaseCmd::Acquire => {
            let resp = client.post(&url_base).send().await?;
            if !resp.status().is_success() {
                let s = resp.status();
                let body = resp.text().await.unwrap_or_default();
                bail!("acquire failed: {s} {body}");
            }
            let body: serde_json::Value = resp.json().await?;
            println!("✓ lease acquired: {}", serde_json::to_string_pretty(&body)?);
        }
        LeaseCmd::Renew => {
            let resp = client.post(format!("{url_base}/renew")).send().await?;
            if !resp.status().is_success() {
                let s = resp.status();
                let body = resp.text().await.unwrap_or_default();
                bail!("renew failed: {s} {body}");
            }
            let body: serde_json::Value = resp.json().await?;
            println!("✓ lease renewed: {}", serde_json::to_string_pretty(&body)?);
        }
        LeaseCmd::Release => {
            let resp = client.delete(&url_base).send().await?;
            if !resp.status().is_success() {
                let s = resp.status();
                let body = resp.text().await.unwrap_or_default();
                bail!("release failed: {s} {body}");
            }
            println!("✓ lease released");
        }
        LeaseCmd::Steal { ttl_secs } => {
            let resp = client
                .post(format!("{url_base}/steal"))
                .json(&serde_json::json!({"ttl_secs": ttl_secs}))
                .send()
                .await?;
            if resp.status().as_u16() == 409 {
                bail!("lease still live (cannot steal yet)");
            }
            if !resp.status().is_success() {
                let s = resp.status();
                let body = resp.text().await.unwrap_or_default();
                bail!("steal failed: {s} {body}");
            }
            let body: serde_json::Value = resp.json().await?;
            println!("✓ lease stolen: {}", serde_json::to_string_pretty(&body)?);
        }
    }
    Ok(())
}

async fn wal_cmd(client: &reqwest::Client, base: &str, cmd: WalCmd) -> Result<()> {
    let st = State::load()?.ok_or_else(|| anyhow!("no saved vault"))?;
    ensure_unlocked(client, base, &st).await?;
    match cmd {
        WalCmd::Show => {
            let resp = client.get(format!("{base}/v1/vaults/{}/wal", st.vault_id)).send().await?;
            let body: serde_json::Value = resp.json().await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
    }
    Ok(())
}

async fn snapshot_cmd(client: &reqwest::Client, base: &str, cmd: SnapshotCmd) -> Result<()> {
    let st = State::load()?.ok_or_else(|| anyhow!("no saved vault"))?;
    ensure_unlocked(client, base, &st).await?;
    match cmd {
        SnapshotCmd::Show => {
            let resp = client
                .get(format!("{base}/v1/vaults/{}/snapshot", st.vault_id))
                .send()
                .await?;
            let body: serde_json::Value = resp.json().await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        SnapshotCmd::Push { expect_version, delta_since_hlc } => {
            let resp = client
                .post(format!("{base}/v1/vaults/{}/snapshot/push", st.vault_id))
                .json(&serde_json::json!({
                    "expected_version_counter": expect_version,
                    "delta_since_hlc_physical": delta_since_hlc,
                }))
                .send()
                .await?;
            if !resp.status().is_success() {
                let s = resp.status();
                let b = resp.text().await.unwrap_or_default();
                bail!("push failed: {s} {b}");
            }
            let body: serde_json::Value = resp.json().await?;
            println!("✓ snapshot pushed: {}", serde_json::to_string_pretty(&body)?);
        }
        SnapshotCmd::Pull { handle_hex } => {
            let resp = client
                .post(format!("{base}/v1/vaults/{}/snapshot/pull", st.vault_id))
                .json(&serde_json::json!({"snapshot_handle_hex": handle_hex}))
                .send()
                .await?;
            if !resp.status().is_success() {
                let s = resp.status();
                let b = resp.text().await.unwrap_or_default();
                bail!("pull failed: {s} {b}");
            }
            let body: serde_json::Value = resp.json().await?;
            println!("✓ snapshot pulled: {}", serde_json::to_string_pretty(&body)?);
        }
    }
    Ok(())
}

async fn providers_cmd(client: &reqwest::Client, base: &str, cmd: ProvidersCmd) -> Result<()> {
    let st = State::load()?.ok_or_else(|| anyhow!("no saved vault"))?;
    ensure_unlocked(client, base, &st).await?;
    match cmd {
        ProvidersCmd::Ls => {
            let resp = client
                .get(format!("{base}/v1/vaults/{}/providers", st.vault_id))
                .send()
                .await?;
            let body: serde_json::Value = resp.json().await?;
            if let Some(arr) = body["providers"].as_array() {
                println!("{:<40}  {:<28}  {:<14}  health", "provider_id", "plugin_id", "trust_group");
                for p in arr {
                    println!(
                        "{:<40}  {:<28}  {:<14}  {:.2}",
                        p["provider_id"].as_str().unwrap_or("?"),
                        p["plugin_id"].as_str().unwrap_or("?"),
                        p["trust_correlation_group"].as_str().unwrap_or("?"),
                        p["health"].as_f64().unwrap_or(0.0),
                    );
                }
            }
        }
    }
    Ok(())
}

async fn peers_cmd(client: &reqwest::Client, base: &str, cmd: PeersCmd) -> Result<()> {
    let st = State::load()?.ok_or_else(|| anyhow!("no saved vault"))?;
    ensure_unlocked(client, base, &st).await?;
    match cmd {
        PeersCmd::Ls => {
            let resp = client
                .get(format!("{base}/v1/vaults/{}/peers", st.vault_id))
                .send()
                .await?;
            let body: serde_json::Value = resp.json().await?;
            if let Some(arr) = body["peers"].as_array() {
                if arr.is_empty() {
                    println!("(no peers)");
                } else {
                    for p in arr {
                        println!("- {} (label={}, verified={}, epochs={})",
                            p["peer_id"].as_str().unwrap_or("?"),
                            p["label"].as_str().unwrap_or("?"),
                            p["verified"].as_bool().unwrap_or(false),
                            p["epoch_count"].as_u64().unwrap_or(0),
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

async fn shadows_cmd(client: &reqwest::Client, base: &str, cmd: ShadowsCmd) -> Result<()> {
    let st = State::load()?.ok_or_else(|| anyhow!("no saved vault"))?;
    ensure_unlocked(client, base, &st).await?;
    match cmd {
        ShadowsCmd::Ls => {
            let resp = client
                .get(format!("{base}/v1/vaults/{}/shadows", st.vault_id))
                .send()
                .await?;
            let body: serde_json::Value = resp.json().await?;
            if let Some(arr) = body["shadows"].as_array() {
                if arr.is_empty() {
                    println!("(no shadows)");
                } else {
                    for sh in arr {
                        println!("- {}  size={} reason={} chunk={}",
                            sh["shadow_id"].as_str().unwrap_or("?"),
                            sh["ciphertext_length"].as_u64().unwrap_or(0),
                            sh["reason"].as_str().unwrap_or("?"),
                            &sh["original_chunk_hash"].as_str().unwrap_or("?")[..16],
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

async fn repair_cmd(client: &reqwest::Client, base: &str, cmd: RepairCmd) -> Result<()> {
    let st = State::load()?.ok_or_else(|| anyhow!("no saved vault"))?;
    ensure_unlocked(client, base, &st).await?;
    match cmd {
        RepairCmd::Show => {
            let resp = client
                .get(format!("{base}/v1/vaults/{}/repair", st.vault_id))
                .send()
                .await?;
            let body: serde_json::Value = resp.json().await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        RepairCmd::Scrub { per_thousand } => {
            let resp = client
                .post(format!("{base}/v1/system/scrub"))
                .json(&serde_json::json!({"fraction_per_thousand": per_thousand}))
                .send()
                .await?;
            if !resp.status().is_success() {
                bail!("scrub failed: {}", resp.status());
            }
            let body: serde_json::Value = resp.json().await?;
            println!("✓ scrub enqueued {} tasks", body["enqueued"]);
        }
        RepairCmd::Gc => {
            let resp = client
                .post(format!("{base}/v1/system/gc"))
                .send()
                .await?;
            if !resp.status().is_success() {
                bail!("gc failed: {}", resp.status());
            }
            let body: serde_json::Value = resp.json().await?;
            println!("✓ gc enqueued {} tasks", body["enqueued"]);
        }
        RepairCmd::Rebalance { per_thousand } => {
            let resp = client
                .post(format!("{base}/v1/vaults/{}/rebalance", st.vault_id))
                .json(&serde_json::json!({"fraction_per_thousand": per_thousand}))
                .send()
                .await?;
            if !resp.status().is_success() {
                bail!("rebalance failed: {}", resp.status());
            }
            let body: serde_json::Value = resp.json().await?;
            println!("✓ rebalance enqueued {} tasks", body["enqueued"]);
        }
        RepairCmd::Enqueue { chunk_hash, priority, source } => {
            let resp = client
                .post(format!("{base}/v1/vaults/{}/repair", st.vault_id))
                .json(&serde_json::json!({
                    "chunk_hash_hex": chunk_hash,
                    "priority": priority,
                    "source": source,
                }))
                .send()
                .await?;
            if !resp.status().is_success() {
                let s = resp.status();
                let body = resp.text().await.unwrap_or_default();
                bail!("enqueue failed: {s} {body}");
            }
            let body: serde_json::Value = resp.json().await?;
            println!("✓ enqueued; queue depth = {}", body["queue_depth"]);
        }
    }
    Ok(())
}

async fn shares_cmd(client: &reqwest::Client, base: &str, cmd: SharesCmd) -> Result<()> {
    let st = State::load()?.ok_or_else(|| anyhow!("no saved vault"))?;
    ensure_unlocked(client, base, &st).await?;
    let url = format!("{base}/v1/vaults/{}/shares", st.vault_id);
    match cmd {
        SharesCmd::Ls => {
            let resp = client.get(&url).send().await?;
            let body: serde_json::Value = resp.json().await?;
            if let Some(arr) = body["shares"].as_array() {
                if arr.is_empty() {
                    println!("(no shares)");
                } else {
                    for sh in arr {
                        println!("- {} → {}  scope={}  revoked={}",
                            sh["share_id"].as_str().unwrap_or("?"),
                            sh["recipient"].as_str().unwrap_or("?"),
                            sh["scope"].as_str().unwrap_or("?"),
                            sh["revoked"].as_bool().unwrap_or(false),
                        );
                    }
                }
            }
        }
        SharesCmd::Create { recipient, scope } => {
            let resp = client
                .post(&url)
                .json(&serde_json::json!({"recipient": recipient, "scope": scope}))
                .send()
                .await?;
            if !resp.status().is_success() {
                let s = resp.status();
                let b = resp.text().await.unwrap_or_default();
                bail!("create share failed: {s} {b}");
            }
            let body: serde_json::Value = resp.json().await?;
            println!("✓ share created: {}", serde_json::to_string_pretty(&body)?);
        }
        SharesCmd::Accept { share_id, blob_hex, owner_sign_pub_hex, mount } => {
            let url = format!(
                "{base}/v1/vaults/{}/inbox/{share_id}/accept",
                st.vault_id
            );
            let body = serde_json::json!({
                "blob_hex": blob_hex,
                "owner_sign_pub_hex": owner_sign_pub_hex,
                "mount_path": mount,
            });
            let resp = client.post(&url).json(&body).send().await?;
            if !resp.status().is_success() {
                let s = resp.status();
                let b = resp.text().await.unwrap_or_default();
                bail!("accept failed: {s} {b}");
            }
            let body: serde_json::Value = resp.json().await?;
            println!("✓ share accepted: {}", serde_json::to_string_pretty(&body)?);
        }
        SharesCmd::Inbox => {
            let url = format!("{base}/v1/vaults/{}/inbox", st.vault_id);
            let resp = client.get(&url).send().await?;
            let body: serde_json::Value = resp.json().await?;
            if let Some(arr) = body["inbox"].as_array() {
                if arr.is_empty() {
                    println!("(empty)");
                } else {
                    for sh in arr {
                        println!(
                            "- {} from={} mount={} key_v={}",
                            sh["share_id"].as_str().unwrap_or("?"),
                            sh["owner_peer_id"].as_str().unwrap_or("?"),
                            sh["mounted_path"].as_str().unwrap_or("?"),
                            sh["file_key_version"].as_u64().unwrap_or(0),
                        );
                    }
                }
            }
        }
        SharesCmd::Revoke { share_id } => {
            let resp = client.delete(format!("{url}/{share_id}")).send().await?;
            if !resp.status().is_success() {
                let s = resp.status();
                let b = resp.text().await.unwrap_or_default();
                bail!("revoke failed: {s} {b}");
            }
            let body: serde_json::Value = resp.json().await?;
            println!(
                "✓ share revoked (file_key_version → {})",
                body["new_file_key_version"].as_u64().unwrap_or(0)
            );
        }
    }
    Ok(())
}

async fn events_tail(client: &reqwest::Client, base: &str, limit: usize) -> Result<()> {
    let resp = client.get(format!("{base}/v1/system/events?limit={limit}")).send().await?;
    let body: serde_json::Value = resp.json().await?;
    println!("{}", serde_json::to_string_pretty(&body)?);
    Ok(())
}

async fn fault_cmd(client: &reqwest::Client, base: &str, cmd: FaultCmd) -> Result<()> {
    let url = format!("{base}/v1/system/fault");
    match cmd {
        FaultCmd::Show => {
            let resp = client.get(&url).send().await?;
            let body: serde_json::Value = resp.json().await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        FaultCmd::Set { fail_puts, fail_gets, corrupt_gets, pause } => {
            let mut req = serde_json::Map::new();
            if let Some(n) = fail_puts { req.insert("fail_puts".into(), serde_json::json!(n)); }
            if let Some(n) = fail_gets { req.insert("fail_gets".into(), serde_json::json!(n)); }
            if let Some(n) = corrupt_gets { req.insert("corrupt_gets".into(), serde_json::json!(n)); }
            if let Some(p) = pause { req.insert("pause".into(), serde_json::json!(p)); }
            let resp = client.post(&url).json(&serde_json::Value::Object(req)).send().await?;
            if !resp.status().is_success() {
                let s = resp.status();
                let b = resp.text().await.unwrap_or_default();
                bail!("fault set failed: {s} {b}");
            }
            let body: serde_json::Value = resp.json().await?;
            println!("✓ fault state: {}", serde_json::to_string_pretty(&body)?);
        }
        FaultCmd::Clear => {
            let resp = client.delete(&url).send().await?;
            if !resp.status().is_success() {
                bail!("clear failed: {}", resp.status());
            }
            println!("✓ fault cleared");
        }
    }
    Ok(())
}

async fn plugins_cmd(client: &reqwest::Client, base: &str, cmd: PluginsCmd) -> Result<()> {
    match cmd {
        PluginsCmd::Install { manifest_hex, confirmation } => {
            let resp = client
                .post(format!("{base}/v1/plugins/install"))
                .json(&serde_json::json!({
                    "manifest_hex": manifest_hex,
                    "confirmation": confirmation,
                }))
                .send()
                .await?;
            if !resp.status().is_success() {
                let s = resp.status();
                let b = resp.text().await.unwrap_or_default();
                bail!("install failed: {s} {b}");
            }
            let body: serde_json::Value = resp.json().await?;
            println!("✓ plugin installed: {}", serde_json::to_string_pretty(&body)?);
        }
        PluginsCmd::Reload { plugin_id, capabilities_hex } => {
            let resp = client
                .post(format!("{base}/v1/plugins/{plugin_id}/reload"))
                .json(&serde_json::json!({"capabilities_hex": capabilities_hex}))
                .send()
                .await?;
            if !resp.status().is_success() {
                bail!("reload failed: {}", resp.status());
            }
            let body: serde_json::Value = resp.json().await?;
            println!("✓ plugin reloaded: {}", serde_json::to_string_pretty(&body)?);
        }
        PluginsCmd::OauthStart { plugin_id, auth_url, scope } => {
            let resp = client
                .post(format!("{base}/v1/providers/oauth/start"))
                .json(&serde_json::json!({
                    "plugin_id": plugin_id,
                    "auth_url": auth_url,
                    "required_scopes": scope,
                }))
                .send()
                .await?;
            if !resp.status().is_success() {
                bail!("oauth start failed: {}", resp.status());
            }
            let body: serde_json::Value = resp.json().await?;
            println!("✓ oauth session: {}", serde_json::to_string_pretty(&body)?);
        }
        PluginsCmd::OauthComplete { state, token_hex, granted } => {
            let resp = client
                .post(format!("{base}/v1/providers/oauth/complete"))
                .json(&serde_json::json!({
                    "state": state,
                    "token_hex": token_hex,
                    "granted_scopes": granted,
                }))
                .send()
                .await?;
            if !resp.status().is_success() {
                let s = resp.status();
                let b = resp.text().await.unwrap_or_default();
                bail!("oauth complete failed: {s} {b}");
            }
            let body: serde_json::Value = resp.json().await?;
            println!("✓ credentials wrapped: {}", serde_json::to_string_pretty(&body)?);
        }
    }
    Ok(())
}

async fn plugin_state_cmd(client: &reqwest::Client, base: &str, cmd: PluginStateCmd) -> Result<()> {
    let st = State::load()?.ok_or_else(|| anyhow!("no saved vault"))?;
    ensure_unlocked(client, base, &st).await?;
    match cmd {
        PluginStateCmd::Show { provider_id } => {
            let url = format!("{base}/v1/vaults/{}/providers/{}/state", st.vault_id, provider_id);
            let resp = client.get(&url).send().await?;
            let body: serde_json::Value = resp.json().await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        PluginStateCmd::Set { provider_id, transition } => {
            let url = format!("{base}/v1/vaults/{}/providers/{}/state", st.vault_id, provider_id);
            let resp = client
                .post(&url)
                .json(&serde_json::json!({"transition": transition}))
                .send().await?;
            if !resp.status().is_success() {
                let s = resp.status();
                let b = resp.text().await.unwrap_or_default();
                bail!("set state failed: {s} {b}");
            }
            let body: serde_json::Value = resp.json().await?;
            println!("✓ {}", serde_json::to_string_pretty(&body)?);
        }
    }
    Ok(())
}

// ─── auth: providers-file management + interactive flows ──────────────────

/// Canonical path of the providers/secrets file. Engine and CLI must agree.
fn providers_path() -> Result<PathBuf> {
    let dir = if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(|h| {
            let mut p = PathBuf::from(h);
            p.push("Library/Application Support/openstorage");
            p
        })
    } else if cfg!(target_os = "windows") {
        std::env::var_os("APPDATA").map(|a| {
            let mut p = PathBuf::from(a);
            p.push("openstorage");
            p
        })
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|h| {
                    let mut p = PathBuf::from(h);
                    p.push(".config");
                    p
                })
            })
            .map(|mut p| {
                p.push("openstorage");
                p
            })
    };
    let dir = dir.ok_or_else(|| anyhow!("could not resolve config dir"))?;
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("providers.json"))
}

fn load_providers() -> Result<Vec<serde_json::Value>> {
    let p = providers_path()?;
    if !p.exists() {
        return Ok(Vec::new());
    }
    let s = std::fs::read_to_string(&p)?;
    let v: Vec<serde_json::Value> = serde_json::from_str(&s).unwrap_or_default();
    Ok(v)
}

fn save_providers(entries: &[serde_json::Value]) -> Result<()> {
    let p = providers_path()?;
    let tmp = p.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(entries)?)?;
    std::fs::rename(&tmp, &p)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn redact(s: &str) -> String {
    if s.len() <= 8 {
        "****".into()
    } else {
        format!("{}…{}", &s[..4], "*".repeat(8))
    }
}

fn read_secret_line(prompt: &str) -> Result<String> {
    use std::io::{BufRead, Write};
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let stdin = std::io::stdin();
    let mut buf = String::new();
    stdin.lock().read_line(&mut buf)?;
    Ok(buf.trim().to_string())
}

fn open_browser(url: &str) -> bool {
    let cmd = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(target_os = "windows") {
        "start"
    } else {
        "xdg-open"
    };
    std::process::Command::new(cmd)
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_ok()
}

async fn auth_cmd(client: &reqwest::Client, cmd: AuthCmd) -> Result<()> {
    match cmd {
        AuthCmd::Path => {
            println!("{}", providers_path()?.display());
        }
        AuthCmd::Ls => {
            let entries = load_providers()?;
            if entries.is_empty() {
                println!("(no providers yet — run `os auth add <kind>` to add one)");
                return Ok(());
            }
            println!("{:<20}  {:<14}  {}", "label", "kind", "secret/url (redacted)");
            for e in &entries {
                let label = e["label"].as_str().unwrap_or("?");
                let kind = e["kind"].as_str().unwrap_or("?");
                let secret = e["access_token"]
                    .as_str()
                    .or_else(|| e["bot_token"].as_str())
                    .or_else(|| e["webhook_url"].as_str())
                    .unwrap_or("(no secret)");
                println!("{label:<20}  {kind:<14}  {}", redact(secret));
            }
        }
        AuthCmd::Rm { label } => {
            let mut entries = load_providers()?;
            let before = entries.len();
            entries.retain(|e| e["label"].as_str() != Some(&label));
            if entries.len() == before {
                bail!("no entry with label '{}'", label);
            }
            save_providers(&entries)?;
            println!("✓ removed {label}");
        }
        AuthCmd::Add { kind } => match kind {
            AuthKind::Github { label } => add_github(client, label).await?,
            AuthKind::Telegram { label } => add_telegram(client, label).await?,
            AuthKind::Discord { label } => add_discord(client, label).await?,
            AuthKind::Telegraph { label } => add_telegraph(client, label).await?,
            AuthKind::Uguu { label } => add_anonymous("uguu", label)?,
            AuthKind::Catbox { label } => add_anonymous("catbox", label)?,
            AuthKind::PasteRs { label } => add_anonymous("paste_rs", label)?,
            AuthKind::Filebin { label } => add_anonymous("filebin", label)?,
        },
    }
    Ok(())
}

async fn add_github(client: &reqwest::Client, label: Option<String>) -> Result<()> {
    let label = label.unwrap_or_else(|| {
        format!("github-{}", chrono_like_label())
    });
    let url = "https://github.com/settings/tokens/new?scopes=repo&description=openstorage";
    println!("Opening browser to GitHub's new-token page (scope: repo).");
    println!("  {url}");
    if !open_browser(url) {
        println!("(could not open a browser; copy the URL manually)");
    }
    let token = read_secret_line("Paste the new Personal Access Token: ")?;
    if token.is_empty() {
        bail!("empty token");
    }
    // Validate against /user.
    let resp = client
        .get("https://api.github.com/user")
        .header("authorization", format!("token {token}"))
        .header("accept", "application/vnd.github+json")
        .header("user-agent", "openstorage-cli")
        .send()
        .await?;
    if !resp.status().is_success() {
        bail!("token validation failed: {}", resp.status());
    }
    let v: serde_json::Value = resp.json().await?;
    let login = v["login"].as_str().unwrap_or("?").to_string();
    println!("✓ token valid (login = {login})");

    let owner = read_line(&format!("owner [default {login}]: "))?;
    let owner = if owner.is_empty() { login.clone() } else { owner };
    let repo = read_line("repo (must already exist): ")?;
    if repo.is_empty() {
        bail!("repo required");
    }
    let branch = read_line("branch [default main]: ")?;
    let branch = if branch.is_empty() { "main".into() } else { branch };

    let mut entries = load_providers()?;
    entries.retain(|e| e["label"].as_str() != Some(&label));
    entries.push(serde_json::json!({
        "kind": "github",
        "label": label,
        "owner": owner,
        "repo": repo,
        "branch": branch,
        "access_token": token,
    }));
    save_providers(&entries)?;
    println!("✓ saved {label} → {}", providers_path()?.display());
    Ok(())
}

async fn add_telegram(client: &reqwest::Client, label: Option<String>) -> Result<()> {
    let label = label.unwrap_or_else(|| format!("telegram-{}", chrono_like_label()));
    println!("Open https://t.me/BotFather → /newbot to create a bot, then come back.");
    let token = read_secret_line("Bot token: ")?;
    if token.is_empty() {
        bail!("token required");
    }
    let resp = client
        .get(format!("https://api.telegram.org/bot{token}/getMe"))
        .send()
        .await?;
    if !resp.status().is_success() {
        bail!("getMe failed: {}", resp.status());
    }
    let v: serde_json::Value = resp.json().await?;
    if v["ok"].as_bool() != Some(true) {
        bail!("getMe returned ok=false: {v}");
    }
    let username = v["result"]["username"].as_str().unwrap_or("?");
    println!("✓ bot @{username}");
    println!("Send any message to your bot now, then return to this prompt.");
    let chat = read_line("chat_id (or press enter to read /getUpdates): ")?;
    let chat = if !chat.is_empty() {
        chat
    } else {
        let resp = client
            .get(format!("https://api.telegram.org/bot{token}/getUpdates"))
            .send()
            .await?;
        let v: serde_json::Value = resp.json().await?;
        let updates = v["result"].as_array().cloned().unwrap_or_default();
        let chat_id = updates
            .iter()
            .filter_map(|u| u["message"]["chat"]["id"].as_i64())
            .next()
            .ok_or_else(|| anyhow!("no chat in /getUpdates; send a message to the bot first"))?;
        chat_id.to_string()
    };
    let mut entries = load_providers()?;
    entries.retain(|e| e["label"].as_str() != Some(&label));
    entries.push(serde_json::json!({
        "kind": "telegram",
        "label": label,
        "bot_token": token,
        "chat_id": chat,
    }));
    save_providers(&entries)?;
    println!("✓ saved {label}");
    Ok(())
}

async fn add_discord(client: &reqwest::Client, label: Option<String>) -> Result<()> {
    let label = label.unwrap_or_else(|| format!("discord-{}", chrono_like_label()));
    println!("In Discord: server → channel → Integrations → Webhooks → New Webhook → Copy URL");
    let url = read_secret_line("Webhook URL: ")?;
    if !url.starts_with("https://discord.com/api/webhooks/")
        && !url.starts_with("https://discordapp.com/api/webhooks/")
    {
        bail!("not a Discord webhook URL");
    }
    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        bail!("webhook validation failed: {}", resp.status());
    }
    let mut entries = load_providers()?;
    entries.retain(|e| e["label"].as_str() != Some(&label));
    entries.push(serde_json::json!({
        "kind": "discord",
        "label": label,
        "webhook_url": url,
    }));
    save_providers(&entries)?;
    println!("✓ saved {label}");
    Ok(())
}

async fn add_telegraph(client: &reqwest::Client, label: Option<String>) -> Result<()> {
    let label = label.unwrap_or_else(|| format!("telegraph-{}", chrono_like_label()));
    let resp = client
        .post("https://api.telegra.ph/createAccount")
        .form(&[("short_name", "openstorage"), ("author_name", "anon")])
        .send()
        .await?;
    let v: serde_json::Value = resp.json().await?;
    if v["ok"].as_bool() != Some(true) {
        bail!("createAccount failed: {v}");
    }
    let token = v["result"]["access_token"]
        .as_str()
        .ok_or_else(|| anyhow!("no access_token in response"))?;
    let mut entries = load_providers()?;
    entries.retain(|e| e["label"].as_str() != Some(&label));
    entries.push(serde_json::json!({
        "kind": "telegraph",
        "label": label,
        "access_token": token,
    }));
    save_providers(&entries)?;
    println!("✓ minted anonymous Telegraph account; saved as {label}");
    Ok(())
}

fn add_anonymous(kind: &str, label: Option<String>) -> Result<()> {
    let label = label.unwrap_or_else(|| format!("{kind}-{}", chrono_like_label()));
    let mut entries = load_providers()?;
    entries.retain(|e| e["label"].as_str() != Some(&label));
    entries.push(serde_json::json!({ "kind": kind, "label": label }));
    save_providers(&entries)?;
    println!("✓ added {label} (kind={kind}, no credential)");
    Ok(())
}

fn read_line(prompt: &str) -> Result<String> {
    use std::io::{BufRead, Write};
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut buf = String::new();
    std::io::stdin().lock().read_line(&mut buf)?;
    Ok(buf.trim().to_string())
}

fn chrono_like_label() -> String {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{n}")
}
