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
use os_metadata::{Store, Txn};
use os_plugin_host::Host;
use os_plugin_http_backend::HttpBackendPlugin;
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

    // Register one HTTP-backend chunk plugin pointed at the testbench.
    let provider_id = ProviderId::new_v7();
    let plugin = Arc::new(HttpBackendPlugin::new(testbench_url.clone()));
    host.register_chunk(provider_id, plugin);
    persist_provider(&store, provider_id)?;

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
    let recovery = Arc::new(RecoveryService::new(store.clone(), identity, vault.clone()));
    let vfs = Arc::new(VfsService::with_host(
        store,
        vault.clone(),
        sync,
        host,
        os_vfs::VfsConfig::default(),
    ));

    let app = router(AppState {
        recovery,
        vault,
        vfs,
    });

    tracing::info!(
        %bind,
        data_dir = %data_dir.display(),
        device_id = %device_id,
        backend = %testbench_url,
        "openstorage starting"
    );

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn persist_provider(store: &Store, provider_id: ProviderId) -> Result<(), Box<dyn std::error::Error>> {
    let provider = Provider {
        provider_id,
        plugin_id: PluginId::new("org.openstorage.http_backend"),
        instance_label: "testbench".into(),
        credentials_handle: CredentialsHandle::new(vec![]).expect("empty creds fits in 64 bytes"),
        capabilities: CapabilitySet::default(),
        legal_class: LegalClass::Green,
        trust_correlation_group: TrustCorrelationGroup::new("testbench"),
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
