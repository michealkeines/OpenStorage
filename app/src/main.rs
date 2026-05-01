//! `openstorage` — engine binary.
//!
//! Wires together the engine and an HTTP backend plugin pointing at the
//! Python testbench (`testbench/server.py`). Spins up the API on
//! `127.0.0.1:7878` and registers one chunk plugin so chunked writes and
//! reads can flow.
//!
//! Env knobs:
//!     OPENSTORAGE_BIND        listen address (default 127.0.0.1:7878)
//!     OPENSTORAGE_DATA_DIR    where the local WAL lives
//!     TESTBENCH_URL           the HTTP backend (default http://127.0.0.1:9090)

use std::sync::Arc;

use os_api::{router, AppState};
use os_crypto::generate_keypair;
use os_entities::Provider;
use os_identity::IdentityService;
use os_metadata::backend::MemoryBackend;
use os_metadata::{ColumnFamily, Store, Txn};
use os_plugin_host::Host;
use os_plugin_http_backend::HttpBackendPlugin;
use os_plugin_fault_inject::FaultInjectPlugin;
use os_plugin_zeroxst::ZeroxStPlugin;
use os_plugin_telegram::TelegramPlugin;
use os_plugin_discord::DiscordPlugin;
use os_plugin_host::contract::PluginContract;
use os_recovery::RecoveryService;
use os_sync::SyncEngine;
use os_types::{
    CapabilitySet, CredentialsHandle, DeviceId, HealthScore, LatencyProfile, LegalClass,
    PluginId, ProviderId, QuotaState, RateLimitState, Timestamp, TrustCorrelationGroup,
};
use os_vault::VaultManager;
use os_vfs::VfsService;
use os_wal::WalBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    let bind = std::env::var("OPENSTORAGE_BIND").unwrap_or_else(|_| "127.0.0.1:7878".into());
    let data_dir = std::env::var("OPENSTORAGE_DATA_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            let mut p = std::env::temp_dir();
            p.push(format!("openstorage-{}", uuid_simple()));
            p
        });
    std::fs::create_dir_all(&data_dir)?;
    let testbench_url = std::env::var("TESTBENCH_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:9090".into());

    let store = Arc::new(Store::new(Arc::new(MemoryBackend::new())));
    let host = Arc::new(Host::new());

    // Pick the chunk backend. Defaults to the local testbench; flip to
    // `OPENSTORAGE_BACKEND=zeroxst` to send ciphertext to the public 0x0.st
    // anonymous file host. Fault-injection wraps both so the API can drive
    // Healthy / Degraded transitions either way.
    let backend_kind = std::env::var("OPENSTORAGE_BACKEND")
        .unwrap_or_else(|_| "testbench".into());
    let provider_id = ProviderId::new_v7();
    let (inner_plugin, plugin_id_str, trust_group, label, backend_label):
        (Arc<dyn PluginContract>, &'static str, &'static str, &'static str, String) =
        match backend_kind.as_str() {
            "zeroxst" => (
                Arc::new(ZeroxStPlugin::new()),
                "org.openstorage.zeroxst",
                "uguu.se",
                "uguu.se-public",
                "https://uguu.se (public, anonymous)".to_string(),
            ),
            "telegram" => {
                let p = TelegramPlugin::from_env()
                    .expect("TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID required for backend=telegram");
                (
                    Arc::new(p),
                    "org.openstorage.telegram",
                    "telegram",
                    "telegram-bot",
                    "https://api.telegram.org (Bot API)".to_string(),
                )
            }
            "discord" => {
                let p = DiscordPlugin::from_env()
                    .expect("DISCORD_WEBHOOK_URL required for backend=discord");
                (
                    Arc::new(p),
                    "org.openstorage.discord",
                    "discord",
                    "discord-webhook",
                    "https://discord.com (webhook)".to_string(),
                )
            }
            _ => (
                Arc::new(HttpBackendPlugin::new(testbench_url.clone())),
                "org.openstorage.http_backend",
                "testbench",
                "testbench",
                testbench_url.clone(),
            ),
        };
    let fault_plugin = Arc::new(FaultInjectPlugin::new(inner_plugin));
    let fault_handle = fault_plugin.handle();
    // Host reads `plugin.rate_limit_profile()` and wires the middleware
    // automatically. No per-backend `RateLimitConfig` switch — the plugin
    // is the source of truth for its own backend's limits.
    host.register_chunk(provider_id, fault_plugin);
    persist_provider(&store, provider_id, plugin_id_str, label, trust_group)?;

    // Multi-instance providers: every entry in the JSON file at the
    // canonical secrets path (or $OPENSTORAGE_PROVIDERS override) becomes
    // its own provider, registered under a fresh ProviderId with its own
    // rate-limit middleware. This file is the **single source of truth**
    // for authenticated backends — nothing in code embeds tokens.
    let providers_path = std::env::var("OPENSTORAGE_PROVIDERS")
        .ok()
        .or_else(default_providers_path);
    if let Some(path) = providers_path {
        if std::path::Path::new(&path).exists() {
            if let Err(e) = load_providers_file(&path, &host, &store).await {
                tracing::warn!(error = %e, file = %path, "providers file load failed");
            }
        } else {
            tracing::info!(file = %path, "no providers file yet (run `os auth add ...` to create entries)");
        }
    }

    // Also register a vault-provider role so the engine has somewhere to push
    // snapshots. The testbench's `HttpBackendPlugin` implements
    // `VaultPluginContract` (list / cas_write); the public-host
    // `ZeroxStPlugin` does not, so vault-role registration is testbench-only.
    let vault_provider_id = ProviderId::new_v7();
    if backend_kind == "testbench" || backend_kind.is_empty() {
        let vp = Arc::new(HttpBackendPlugin::new(testbench_url.clone()));
        host.register_vault(vault_provider_id, vp);
        tracing::info!(provider_id = %vault_provider_id, "registered vault provider on testbench");
    } else {
        tracing::info!(
            backend = %backend_kind,
            "skipping vault-provider role: backend does not implement VaultPluginContract"
        );
    }

    let identity = Arc::new(IdentityService::new(store.clone()));
    let vault = Arc::new(VaultManager::new(store.clone(), host.clone()));
    let device_id = DeviceId::new_v7();
    let (sk, _pk) = {
        let mut rng = rand::rngs::OsRng;
        generate_keypair(&mut rng)
    };
    let wal = WalBuilder::new()
        .path(data_dir.join("wal.bin"))
        .build(device_id, sk)?;
    let sync = Arc::new(SyncEngine::new(Arc::new(wal)));
    let recovery = Arc::new(RecoveryService::new(
        store.clone(),
        identity.clone(),
        vault.clone(),
    ));
    let vfs = Arc::new(VfsService::with_host(
        store.clone(),
        vault.clone(),
        sync,
        host.clone(),
        os_vfs::VfsConfig::default(),
    ));
    let lease = Arc::new(os_lease::LeaseService::new());
    let repair = Arc::new(os_repair::RepairScheduler::new(4096));
    let events = Arc::new(os_events::EventBus::new());

    // Repair worker: drains the scheduler. Currently handles GcSweep tasks
    // by deleting shards through their plugins and removing chunk/shard
    // records when fully reclaimed. Read-repair / scrub re-placement is
    // queued but no-ops past task acknowledgement until the placement loop
    // is wired (no parity replicas to recover from on EC(1,1) anyway).
    {
        let repair_w = repair.clone();
        let store_w = store.clone();
        let host_w = host.clone();
        tokio::spawn(async move {
            loop {
                let task = match repair_w.drain_one() {
                    Some(t) => t,
                    None => {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                };
                tracing::info!(
                    chunk = %hex::encode(&task.chunk_hash.as_bytes()[..8]),
                    priority = task.priority,
                    source = ?task.source,
                    "repair: in-flight"
                );
                match task.source {
                    os_repair::RepairSource::GcSweep => {
                        if let Err(e) = run_gc_sweep(&store_w, &host_w, task.chunk_hash).await {
                            tracing::warn!(error = %e, "gc-sweep failed");
                        }
                    }
                    _ => {
                        // Other sources (Scrub / ReadRepair / AntiEntropy /
                        // Rebalance): not yet implemented. Acknowledge and
                        // move on so the queue drains.
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                }
                tracing::info!("repair: completed");
            }
        });
    }

    // Shadow sweep: periodically peek each registered shadow. If the upstream
    // backend reports `not_found`, the shadow is Cleared (removed). If it
    // persistently exists despite delete attempts, mark it Permanent.
    {
        let store_w = store.clone();
        let host_w = host.clone();
        tokio::spawn(async move {
            let interval = std::time::Duration::from_secs(2);
            loop {
                if let Err(e) = run_shadow_sweep(&store_w, &host_w).await {
                    tracing::warn!(error = %e, "shadow sweep failed");
                }
                tokio::time::sleep(interval).await;
            }
        });
    }

    let fh = fault_handle.clone();
    let fault_any = os_api::FaultHandleAny {
        fail_puts: Arc::new({
            let fh = fh.clone();
            move |n| fh.fail_next_puts(n)
        }),
        fail_gets: Arc::new({
            let fh = fh.clone();
            move |n| fh.fail_next_gets(n)
        }),
        corrupt_gets: Arc::new({
            let fh = fh.clone();
            move |n| fh.corrupt_next_gets(n)
        }),
        pause: Arc::new({
            let fh = fh.clone();
            move || fh.pause()
        }),
        resume: Arc::new({
            let fh = fh.clone();
            move || fh.resume()
        }),
        clear: Arc::new({
            let fh = fh.clone();
            move || fh.clear()
        }),
        snapshot: Arc::new({
            let fh = fh.clone();
            move || {
                let s = fh.snapshot();
                serde_json::json!({
                    "enabled": true,
                    "fail_puts": s.fail_puts,
                    "fail_gets": s.fail_gets,
                    "corrupt_gets": s.corrupt_gets,
                    "failed_handle_count": s.failed_handle_count,
                    "paused": s.paused,
                })
            }
        }),
    };

    let app = router(AppState {
        recovery,
        vault,
        vfs,
        identity,
        lease,
        repair,
        events,
        host,
        device_id,
        fault: Some(fault_any),
        plugin_states: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
    });

    tracing::info!(
        %bind,
        data_dir = %data_dir.display(),
        device_id = %device_id,
        backend = %backend_label,
        "openstorage starting"
    );

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Canonical path for the secrets/providers file. Engine and CLI agree on
/// this so `os auth add ...` (writes) and the engine's startup loader
/// (reads) target the same file. The file is operator-owned, mode 0600,
/// and never committed to source control.
fn default_providers_path() -> Option<String> {
    let dir = if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(|h| {
            let mut p = std::path::PathBuf::from(h);
            p.push("Library/Application Support/openstorage");
            p
        })
    } else if cfg!(target_os = "windows") {
        std::env::var_os("APPDATA").map(|a| {
            let mut p = std::path::PathBuf::from(a);
            p.push("openstorage");
            p
        })
    } else {
        // XDG: $XDG_CONFIG_HOME or ~/.config
        std::env::var_os("XDG_CONFIG_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|h| {
                    let mut p = std::path::PathBuf::from(h);
                    p.push(".config");
                    p
                })
            })
            .map(|mut p| {
                p.push("openstorage");
                p
            })
    };
    dir.map(|d| d.join("providers.json").to_string_lossy().into_owned())
}

/// Load `OPENSTORAGE_PROVIDERS` JSON and register every entry as its own
/// provider. Each entry is `{ "kind": "...", "label": "...", "..." }`.
/// Supported kinds: `telegraph`, `uguu`, `gofile`, `catbox`, `discord`,
/// `telegram`. New kinds get added here as plugins land.
async fn load_providers_file(
    path: &str,
    host: &Arc<Host>,
    store: &Arc<Store>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bytes = std::fs::read(path)?;
    let entries: Vec<serde_json::Value> = serde_json::from_slice(&bytes)?;
    let mut counts: std::collections::HashMap<String, usize> = Default::default();
    for entry in &entries {
        let kind = entry["kind"].as_str().unwrap_or("?").to_string();
        let label = entry["label"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| format!("{kind}-{}", counts.get(&kind).copied().unwrap_or(0) + 1));
        let provider_id = ProviderId::new_v7();
        let plugin: Arc<dyn PluginContract> = match kind.as_str() {
            "telegraph" => {
                let token = entry["access_token"].as_str().map(str::to_string);
                let plugin = match token {
                    Some(t) => os_plugin_telegraph::TelegraphPlugin::new(t, label.clone()),
                    None => match os_plugin_telegraph::TelegraphPlugin::from_anonymous(
                        label.clone(),
                    )
                    .await
                    {
                        Ok(p) => {
                            tracing::info!(label = %label, "minted anonymous Telegraph account");
                            p
                        }
                        Err(e) => {
                            tracing::warn!(error = ?e, label = %label, "telegraph mint failed; skipping");
                            continue;
                        }
                    },
                };
                Arc::new(plugin)
            }
            "uguu" => Arc::new(os_plugin_zeroxst::ZeroxStPlugin::new()),
            "github" => {
                let owner = match entry["owner"].as_str() {
                    Some(s) => s.to_string(),
                    None => { tracing::warn!(label=%label, "github entry missing owner"); continue; }
                };
                let repo = match entry["repo"].as_str() {
                    Some(s) => s.to_string(),
                    None => { tracing::warn!(label=%label, "github entry missing repo"); continue; }
                };
                let branch = entry["branch"].as_str().unwrap_or("main").to_string();
                let pat = match entry["access_token"].as_str() {
                    Some(s) => s.to_string(),
                    None => { tracing::warn!(label=%label, "github entry missing access_token"); continue; }
                };
                Arc::new(os_plugin_github_repo::GitHubRepoPlugin::new(owner, repo, branch, pat))
            }
            "telegram" => {
                let token = match entry["bot_token"].as_str() {
                    Some(t) => t.to_string(),
                    None => {
                        tracing::warn!("telegram entry missing bot_token; skipping");
                        continue;
                    }
                };
                let chat = match entry["chat_id"].as_str() {
                    Some(c) => c.to_string(),
                    None => {
                        tracing::warn!("telegram entry missing chat_id; skipping");
                        continue;
                    }
                };
                Arc::new(os_plugin_telegram::TelegramPlugin::new(token, chat))
            }
            "discord" => {
                let url = match entry["webhook_url"].as_str() {
                    Some(u) => u.to_string(),
                    None => {
                        tracing::warn!("discord entry missing webhook_url; skipping");
                        continue;
                    }
                };
                Arc::new(os_plugin_discord::DiscordPlugin::new(url))
            }
            other => {
                tracing::warn!(kind = %other, "unknown provider kind; skipping");
                continue;
            }
        };
        host.register_chunk(provider_id, plugin);
        *counts.entry(kind.clone()).or_default() += 1;
        let trust_group: &'static str = match kind.as_str() {
            "telegraph" => "telegram-graph",
            "uguu" => "uguu",
            "github" => "github",
            "telegram" => "telegram",
            "discord" => "discord",
            _ => "unknown",
        };
        let plugin_id_str: &'static str = match kind.as_str() {
            "telegraph" => "org.openstorage.telegraph",
            "uguu" => "org.openstorage.zeroxst",
            "github" => "org.openstorage.github",
            "telegram" => "org.openstorage.telegram",
            "discord" => "org.openstorage.discord",
            _ => "org.openstorage.unknown",
        };
        // We can't reuse persist_provider with a borrowed label since it
        // expects &'static str. Inline a one-off persist.
        persist_dynamic_provider(store, provider_id, plugin_id_str, &label, trust_group)?;
        tracing::info!(provider_id = %provider_id, kind = %kind, label = %label, "registered provider");
    }
    let counts_str: String = counts
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(", ");
    tracing::info!("providers loaded: {} ({counts_str})", entries.len());
    Ok(())
}

fn persist_dynamic_provider(
    store: &Store,
    provider_id: ProviderId,
    plugin_id: &str,
    label: &str,
    trust_group: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let provider = Provider {
        provider_id,
        plugin_id: PluginId::new(plugin_id),
        instance_label: label.into(),
        credentials_handle: CredentialsHandle::new(vec![])?,
        capabilities: CapabilitySet::default(),
        legal_class: LegalClass::Green,
        trust_correlation_group: TrustCorrelationGroup::new(trust_group),
        quota: QuotaState {
            total: None,
            used: None,
            untrusted: false,
        },
        rate_limit: RateLimitState {
            remaining: u32::MAX,
            reset_at: Timestamp::from_string("now"),
        },
        health: HealthScore::new(1.0),
        latency: LatencyProfile::default(),
        untrusted_quota: false,
    };
    let mut txn = Txn::new();
    store.put_provider(&mut txn, &provider)?;
    store.commit(txn)?;
    Ok(())
}

async fn run_gc_sweep(
    store: &Arc<Store>,
    host: &Arc<Host>,
    chunk_hash: os_types::ChunkHash,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let chunk = match store.get_chunk(chunk_hash)? {
        Some(c) => c,
        None => return Ok(()), // already gone
    };
    let mut all_done = true;
    for shard_id in &chunk.shard_list {
        let shard = match store.get_shard(*shard_id)? {
            Some(s) => s,
            None => continue,
        };
        let plugin = match host.get_chunk(shard.driver_id.value) {
            Ok(p) => p,
            Err(_) => {
                all_done = false;
                continue;
            }
        };
        let outcome = plugin.delete(&shard.native_handle.value).await;
        match outcome {
            Ok(r) => match r.outcome {
                os_types::DeleteOutcome::Removed | os_types::DeleteOutcome::NotFound => {
                    let mut txn = os_metadata::Txn::new();
                    txn.delete(
                        os_metadata::ColumnFamily::Shards,
                        shard_id.as_bytes().as_slice(),
                    );
                    store.commit(txn)?;
                }
                os_types::DeleteOutcome::Tombstoned
                | os_types::DeleteOutcome::Abandoned
                | os_types::DeleteOutcome::NotSupported => {
                    // Leave Shadow Registered; shadow_sweep will eventually
                    // peek and either Clear or mark Permanent.
                    all_done = false;
                }
            },
            Err(_) => {
                all_done = false;
            }
        }
    }
    if all_done {
        let mut txn = os_metadata::Txn::new();
        txn.delete(
            os_metadata::ColumnFamily::Chunks,
            chunk_hash.as_bytes().as_slice(),
        );
        store.commit(txn)?;
    }
    Ok(())
}

async fn run_shadow_sweep(
    store: &Arc<Store>,
    host: &Arc<Host>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let backend = store.backend();
    let mut to_clear: Vec<os_types::ShadowId> = Vec::new();
    for kv in backend.scan_prefix(os_metadata::ColumnFamily::Shadows, b"")? {
        let (_, v) = kv?;
        let sh: os_entities::Shadow = ciborium::from_reader(&v[..])?;
        let plugin = match host.get_chunk(sh.driver_id) {
            Ok(p) => p,
            Err(_) => continue,
        };
        match plugin.peek(&sh.native_handle).await {
            Ok(p) => {
                if !p.exists {
                    to_clear.push(sh.shadow_id);
                }
            }
            Err(_) => {}
        }
    }
    if !to_clear.is_empty() {
        let mut txn = os_metadata::Txn::new();
        for id in to_clear {
            txn.delete(
                os_metadata::ColumnFamily::Shadows,
                id.as_uuid().as_bytes().as_slice(),
            );
        }
        store.commit(txn)?;
    }
    Ok(())
}

fn persist_provider(
    store: &Store,
    provider_id: ProviderId,
    plugin_id: &str,
    label: &str,
    trust_group: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let provider = Provider {
        provider_id,
        plugin_id: PluginId::new(plugin_id),
        instance_label: label.into(),
        credentials_handle: CredentialsHandle::new(vec![]).expect("empty creds fits in 64 bytes"),
        capabilities: CapabilitySet::default(),
        legal_class: LegalClass::Green,
        trust_correlation_group: TrustCorrelationGroup::new(trust_group),
        quota: QuotaState {
            total: None,
            used: None,
            untrusted: false,
        },
        rate_limit: RateLimitState {
            remaining: u32::MAX,
            reset_at: Timestamp::from_string("now"),
        },
        health: HealthScore::new(1.0),
        latency: LatencyProfile::default(),
        untrusted_quota: false,
    };
    let mut txn = Txn::new();
    store.put_provider(&mut txn, &provider)?;
    store.commit(txn)?;
    Ok(())
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
}

fn uuid_simple() -> String {
    use rand::RngCore;
    let mut b = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}
