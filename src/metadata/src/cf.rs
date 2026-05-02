//! Column-family identifiers. Backends map these onto their native namespace
//! mechanism (sled trees, sqlite tables, etc.).

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ColumnFamily {
    Files,
    Chunks,
    Shards,
    Shadows,
    Peers,
    Shares,
    Devices,
    Providers,
    VaultMeta,
    BloomState,
    MerkleState,
    WalIndex,
    LargeValues,
    Identity,
    /// Secondary index: `path bytes → file_id (16 bytes)`.
    /// Lets `find_by_path` be a single point-lookup and `list(prefix)` a
    /// scan_prefix instead of decoding every File record.
    PathIndex,
}

impl ColumnFamily {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Files => "files",
            Self::Chunks => "chunks",
            Self::Shards => "shards",
            Self::Shadows => "shadows",
            Self::Peers => "peers",
            Self::Shares => "shares",
            Self::Devices => "devices",
            Self::Providers => "providers",
            Self::VaultMeta => "vault_meta",
            Self::BloomState => "bloom_state",
            Self::MerkleState => "merkle_state",
            Self::WalIndex => "wal_index",
            Self::LargeValues => "large_values",
            Self::Identity => "identity",
            Self::PathIndex => "path_index",
        }
    }

    pub const ALL: [ColumnFamily; 15] = [
        Self::Files,
        Self::Chunks,
        Self::Shards,
        Self::Shadows,
        Self::Peers,
        Self::Shares,
        Self::Devices,
        Self::Providers,
        Self::VaultMeta,
        Self::BloomState,
        Self::MerkleState,
        Self::WalIndex,
        Self::LargeValues,
        Self::Identity,
        Self::PathIndex,
    ];
}
