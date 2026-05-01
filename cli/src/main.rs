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
}

#[derive(Debug, Serialize, Deserialize)]
struct State {
    base: String,
    vault_id: String,
    passphrase: String,
}

impl State {
    fn path() -> Result<PathBuf> {
        let dir = dirs::config_dir()
            .ok_or_else(|| anyhow!("could not resolve config directory"))?
            .join("openstorage");
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
