//! Entity records. The model below is the single source of truth for
//! persisted data shapes; conflicts with prose elsewhere should be resolved
//! against this module.

use serde::{Deserialize, Serialize};

use os_types::{
    AeadNonce, AeadSuite, AeadTag, BlakeHash, CachedElsewhereRisk, CapabilitySet, ChunkHash,
    CredentialsHandle, DeviceId, Duration, ECScheme, Ed25519Pub, Ed25519Sig, EpochId, FileId,
    HealthScore, Hlc, IdentityId, LatencyProfile, LegalClass, MlKemPub, MonotonicCounter, PeerId,
    PluginId, ProviderId, QuotaState, RateLimitState, RecoveryManifestId, RecoveryTokenId,
    ShadowId, ShareId, Tier, Timestamp, TrustCorrelationGroup, VaultId, WrappedKey,
};

use crate::crdt::{Counter, LwwRegister, LwwSet, OrSet};

/// Top-level vault record. Encrypted under MK at rest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vault {
    pub vault_id: VaultId,
    pub format_version: u32,
    pub owner: IdentityId,
    pub created_at: Timestamp,
    pub aead_suite: AeadSuite,
    #[serde(with = "serde_bytes")]
    pub vault_salt: Vec<u8>,
    pub recovery_manifest_ref: RecoveryManifestId,
    pub snapshot_pointer: SignedSnapshotPointer,
    pub lease_path: String,
    pub allowed_devices: OrSet<DeviceAuthorization>,
    pub identity_chain: Vec<IdentityEpoch>,
    pub merkle_root: BlakeHash,
}

/// A file in a vault. Path is a CRDT-managed LWW field, not a tree key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct File {
    pub file_id: FileId,
    pub path: LwwRegister<String>,
    pub size_bytes: LwwRegister<u64>,
    pub created_at: LwwRegister<Timestamp>,
    pub modified_at: LwwRegister<Timestamp>,
    pub permissions: LwwRegister<Permissions>,
    pub content_type: LwwRegister<String>,
    pub tier_pinned: LwwRegister<Option<Tier>>,
    /// Mutually exclusive with `chunk_list`.
    pub inline_payload: Option<InlineBlob>,
    pub chunk_list: Option<Vec<ChunkHash>>,
    pub wrapped_keys: OrSet<WrappedKey>,
    pub acl: OrSet<AclEntry>,
    pub exists: LwwRegister<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InlineBlob {
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    pub nonce: AeadNonce,
    pub tag: AeadTag,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Permissions {
    pub mode: u32,
    pub owner_uid: Option<u32>,
    pub owner_gid: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AclEntry {
    pub principal: PeerId,
    pub permission: Permission,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Permission {
    #[serde(rename = "read")]
    Read,
    #[serde(rename = "write")]
    Write,
    #[serde(rename = "share")]
    Share,
    #[serde(rename = "admin")]
    Admin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chunk {
    pub chunk_hash: ChunkHash,
    pub plaintext_length: u64,
    pub ec_scheme: ECScheme,
    pub shard_list: Vec<os_types::ShardId>,
    pub refcount: Counter,
    pub replication_state: ReplicationState,
    pub last_scrubbed_at: Timestamp,
    pub access_count_window: Counter,
    pub tier: Tier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReplicationState {
    #[serde(rename = "full")]
    Full,
    #[serde(rename = "degraded")]
    Degraded,
    #[serde(rename = "recovering")]
    Recovering,
    #[serde(rename = "lost")]
    Lost,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Shard {
    pub shard_id: os_types::ShardId,
    pub chunk_hash: ChunkHash,
    pub shard_index: u8,
    pub encryption_nonce: AeadNonce,
    pub encryption_tag: AeadTag,
    pub ciphertext_length: u64,
    pub driver_id: LwwSet<ProviderId>,
    pub native_handle: LwwSet<NativeHandle>,
    pub stored_at: Timestamp,
    pub last_verified_at: Timestamp,
    pub health_score: HealthScore,
    pub ack_state: AckState,
}

/// Opaque per-plugin handle for a stored object.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NativeHandle(#[serde(with = "serde_bytes")] pub Vec<u8>);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AckState {
    #[serde(rename = "acked")]
    Acked,
    #[serde(rename = "in_flight")]
    InFlight,
    #[serde(rename = "failed")]
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Shadow {
    pub shadow_id: ShadowId,
    pub original_chunk_hash: ChunkHash,
    pub driver_id: ProviderId,
    pub native_handle: NativeHandle,
    pub ciphertext_length: u64,
    pub abandoned_at: Timestamp,
    pub reason: ShadowReason,
    pub cached_elsewhere_risk: CachedElsewhereRisk,
    pub counts_against_quota: bool,
    pub tombstone_clears_at: Option<Timestamp>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ShadowReason {
    #[serde(rename = "update_replaced")]
    UpdateReplaced,
    #[serde(rename = "repair_replaced")]
    RepairReplaced,
    #[serde(rename = "deletion_orphaned")]
    DeletionOrphaned,
    #[serde(rename = "concurrent_update_demoted")]
    ConcurrentUpdateDemoted,
    #[serde(rename = "plugin_idempotency_violation")]
    PluginIdempotencyViolation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Provider {
    pub provider_id: ProviderId,
    pub plugin_id: PluginId,
    pub instance_label: String,
    pub credentials_handle: CredentialsHandle,
    pub capabilities: CapabilitySet,
    pub legal_class: LegalClass,
    pub trust_correlation_group: TrustCorrelationGroup,
    pub quota: QuotaState,
    pub rate_limit: RateLimitState,
    pub health: HealthScore,
    pub latency: LatencyProfile,
    pub untrusted_quota: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultProvider {
    pub provider_id: ProviderId,
    pub plugin_id: PluginId,
    pub priority: VaultProviderPriority,
    pub credentials_handle: CredentialsHandle,
    pub last_synced_at: Timestamp,
    #[serde(with = "serde_bytes")]
    pub merkle_root_etag: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VaultProviderPriority {
    #[serde(rename = "primary")]
    Primary,
    #[serde(rename = "replica")]
    Replica,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub identity_id: IdentityId,
    pub epochs: Vec<IdentityEpoch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityEpoch {
    pub epoch: EpochId,
    pub sign_pubkey: Ed25519Pub,
    pub kem_pubkey: MlKemPub,
    pub fingerprint: BlakeHash,
    pub created_at: Timestamp,
    #[serde(with = "serde_bytes")]
    pub wrapped_privkeys: Vec<u8>,
    pub signed_by_prev: Option<Ed25519Sig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub peer_id: PeerId,
    pub epochs: Vec<IdentityEpoch>,
    pub label: String,
    pub verified: bool,
    pub last_seen_epoch: EpochId,
    pub added_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub device_id: DeviceId,
    pub device_label: String,
    pub device_pubkey: Ed25519Pub,
    pub first_seen_at: Timestamp,
    pub last_seen_at: Timestamp,
    pub revoked_at: Option<Timestamp>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeviceAuthorization {
    pub device_id: DeviceId,
    pub device_pubkey: Ed25519Pub,
    pub authorized_from_hlc: Hlc,
    pub revoked_at_hlc: Option<Hlc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Share {
    pub share_id: ShareId,
    pub scope: ShareScope,
    pub recipient: PeerId,
    pub permissions: Vec<Permission>,
    pub wrapped_keys_ref: WrappedKeyRef,
    pub created_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub revoked_at: Option<Timestamp>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShareScope {
    #[serde(rename = "file")]
    File(String),
    #[serde(rename = "folder")]
    Folder(String),
    #[serde(rename = "vault")]
    Vault,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedKeyRef {
    pub file_id: FileId,
    pub or_set_add_id: u128,
}

/// Per-device, encrypted under the OS keystore (not under MK). Breaks the
/// cold-start vault provider bootstrap — see ABSTRACTIONS §4.7a.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultBinding {
    pub vault_id: VaultId,
    pub providers: Vec<VaultBindingProvider>,
    pub last_seen_snapshot_pointer: Option<SignedSnapshotPointer>,
    pub last_seen_identity_anchor_fingerprint: Option<BlakeHash>,
    pub device_id: DeviceId,
    pub format_version: u32,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultBindingProvider {
    pub plugin_id: PluginId,
    pub credentials_handle: CredentialsHandle,
    pub priority: VaultProviderPriority,
    pub added_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryManifest {
    pub manifest_id: RecoveryManifestId,
    pub format_version: u32,
    pub version_counter: MonotonicCounter,
    pub signing_epoch_id: EpochId,
    pub signature: Ed25519Sig,
    pub modes: Vec<RecoveryMode>,
    pub wrapped_master_keys: Vec<WrappedMasterKey>,
    pub identity_anchor_fingerprint: BlakeHash,
    pub identity_chain: Vec<IdentityEpoch>,
    pub recovery_token_active_set: OrSet<RecoveryTokenId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryMode {
    #[serde(rename = "passphrase")]
    Passphrase,
    #[serde(rename = "recovery_file")]
    RecoveryFile { fingerprint: BlakeHash },
    #[serde(rename = "shamir")]
    Shamir { k: u8, n: u8 },
    #[serde(rename = "hardware_key")]
    HardwareKey { device_descriptor: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedMasterKey {
    pub mode_index: u32,
    pub recovery_token_id: RecoveryTokenId,
    #[serde(with = "serde_bytes")]
    pub wrapped: Vec<u8>,
    pub nonce: AeadNonce,
    pub tag: AeadTag,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRecord {
    pub lease_id: os_types::LeaseId,
    pub holder_device_id: DeviceId,
    pub acquired_at: Timestamp,
    pub expires_at: Timestamp,
    pub renewal_count: u32,
    pub holder_signature: Ed25519Sig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedSnapshotPointer {
    #[serde(with = "serde_bytes")]
    pub snapshot_id: Vec<u8>,
    pub version_counter: MonotonicCounter,
    pub epoch_id: EpochId,
    pub format_version: u32,
    pub created_at: Timestamp,
    pub signature: Ed25519Sig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotPage {
    #[serde(with = "serde_bytes")]
    pub page_id: Vec<u8>,
    pub page_version: MonotonicCounter,
    pub payload_kind: SnapshotPayloadKind,
    pub payload_codec: SnapshotPayloadCodec,
    #[serde(with = "serde_bytes")]
    pub payload_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SnapshotPayloadKind {
    #[serde(rename = "file_records")]
    FileRecords,
    #[serde(rename = "chunk_records")]
    ChunkRecords,
    #[serde(rename = "namespace")]
    Namespace,
    #[serde(rename = "shadows")]
    Shadows,
    #[serde(rename = "providers")]
    Providers,
    #[serde(rename = "peers")]
    Peers,
    #[serde(rename = "shares")]
    Shares,
    #[serde(rename = "large_values")]
    LargeValues,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SnapshotPayloadCodec {
    #[serde(rename = "cbor_v1")]
    CborV1,
}

/// Plugin-side hint used in `put` ops.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PutHint {
    pub durability_class: Option<os_types::DurabilityClass>,
    pub tier: Option<Tier>,
    pub idempotency_key: Option<os_types::IdempotencyKey>,
    pub replaces_handle: Option<NativeHandle>,
    pub expected_size_bytes: Option<u64>,
    pub retry_after: Option<Duration>,
}
