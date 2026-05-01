# keystore/ — OS Secure Storage Adapter

**Layer**: L2.
**Role**: hides platform-specific secret storage behind a uniform interface for `crypto/`. Holds (a) the per-vault MK wrap key (set after each successful unlock) and (b) the per-device wrap key used for the **VaultBinding** file ([`ABSTRACTIONS.md`](../../ABSTRACTIONS.md) §4.7a).

> **Why two roles?** The MK wrap key is per-vault and is derived after MK is in memory; it's used only to make subsequent unlocks fast within a session. The per-device wrap key is bootstrap-critical: it protects the VaultBinding file that tells the engine *which vault provider to ask for the manifest* on cold start, before any MK exists. The two keys are independent — losing one doesn't invalidate the other.

## What lives here

- `store(key_id, secret)`, `load(key_id) → secret`, `delete(key_id)`.
- Special key IDs:
  - `mk_wrap_<vault_id>` — the MK-wrap key set on first unlock per vault.
  - `device_wrap` — the per-device key, generated on engine first run, used to encrypt the VaultBinding file.
- VaultBinding I/O helpers:
  - `wrap_vault_binding(VaultBinding) → encrypted bytes`
  - `unwrap_vault_binding(encrypted bytes) → VaultBinding`
- Platform implementations:
  - macOS / iOS: Keychain Services.
  - Windows: DPAPI / Credential Manager.
  - Android: Android Keystore (AES-wrapped).
  - Linux: Secret Service (libsecret) or kernel keyring; encrypted file fallback.
  - Self-hosted daemon: encrypted file under user's data dir, password-derived wrap.
- Hardware-backed key wrapping where the platform supports it.

## Boundaries

- Depends on `types/`.
- Used only by `crypto/`. No other module should ever touch keystore directly.
- No persistence beyond the platform mechanism.

## Flow

```
   on engine first run on this device:
     keystore/.generate(device_wrap)
       └─ random key, persisted in platform secret store

   on vault unlock (cold start path):
     recovery/ needs to read VaultBinding before deriving MK
       ──► keystore/.unwrap_vault_binding(file_bytes)
            │
            ▼
       platform secret store returns device_wrap
       AEAD-decrypt VaultBinding bytes
            │
            ▼
       VaultBinding handed to recovery/

   on first unlock per session:
     after MK derived and verified, keystore/.store("mk_wrap_<vault_id>", wrap_key)
     subsequent unlocks within the session use this for fast unwrap

   on VaultBinding update (provider added/removed, pointer advanced):
     keystore/.wrap_vault_binding(new VaultBinding) → encrypted bytes
     atomic file replace on disk

   on vault destruction:
     crypto/.zeroize(MK) (in memory) +
     keystore/.delete("mk_wrap_<vault_id>")
     delete VaultBinding file on disk
       └─ device_wrap remains (other vaults on this device still need it)
```

## Inputs / Outputs

- Inputs: key id (string), secret bytes.
- Outputs: stored secret bytes; or NotFound.
- Side: platform-specific access prompts (Touch ID, Windows Hello) on first use per session.

## Invariants this module supports

- **I1 (confidentiality)** — secrets never written to filesystem in unprotected form.
- **I8 (plugin containment)** — plugins have no access path to keystore. The `signed_fetch` boundary ensures plugins can't request secrets.

## Implementation notes

- The "secret" stored here is typically a wrapping key for the master key, not the master key itself. Master key is derived per-unlock via Argon2id; the wrap key persists across unlocks for fast re-unlock UX.
- On platforms with hardware-backed key storage, the wrap key never leaves the secure element; we hand the secure element opaque ciphertext to wrap/unwrap.
- The encrypted-file fallback uses a passphrase-derived KEK; plays the role of secret store on platforms without one.
- Self-hosted daemon mode: secret stored under root-only mode 0600 file; daemon process is the only reader.

### VaultBinding File Layout (M-3)

Per-vault binding files live under a per-OS engine data directory:

| Platform | Engine data dir | Binding file path |
|---|---|---|
| Linux | `$XDG_DATA_HOME/openstorage` (default `~/.local/share/openstorage`) | `<dir>/vaults/<vault_id>/binding.bin` |
| macOS | `~/Library/Application Support/OpenStorage` | `<dir>/vaults/<vault_id>/binding.bin` |
| Windows | `%LOCALAPPDATA%\OpenStorage` | `<dir>\vaults\<vault_id>\binding.bin` |
| Self-hosted daemon | configurable; default `/var/lib/openstorage` | `<dir>/vaults/<vault_id>/binding.bin` |

**Vault discovery on engine startup**:
1. Enumerate `<engine_data_dir>/vaults/*/binding.bin`.
2. For each, attempt `unwrap_vault_binding`. Successful decrypts populate the engine's known-vaults list.
3. Files that fail to decrypt are logged (mode/permission issues, corruption, or device_wrap key mismatch) but do not block startup.

The `<vault_id>` directory may also contain other per-vault state (local cache, WAL files, idempotency cache). Layout for those is determined by `metadata/` and `wal/`; they live alongside `binding.bin` under the same vault directory.

### Atomic VaultBinding writes (M-2)

Every VaultBinding write follows the temp-rename pattern:

```
1. serialize VaultBinding via wrap_vault_binding → encrypted bytes
2. write encrypted bytes to <binding_path>.tmp
3. fsync(<binding_path>.tmp)
4. rename(<binding_path>.tmp, <binding_path>)  ← atomic on POSIX/Windows
5. fsync(parent dir) on POSIX
```

**Crash recovery on engine startup**:
- If `<binding_path>` exists and decrypts: use it.
- If `<binding_path>` does not exist but `<binding_path>.tmp` exists: discard the .tmp (incomplete write) and treat the vault as not bound on this device.
- If both exist: a rename-style crash; use `<binding_path>` (rename is atomic, so if both exist the rename completed but the OS hasn't cleaned the source — unlikely with `rename(2)` semantics, but defensive).

This makes mid-write crashes safe: either we have the previous binding intact or we have nothing, never a corrupted file. The "nothing" state requires re-binding on this device via the setup wizard, which is recoverable.

## Tests

- Round-trip per platform.
- Delete after store: load returns NotFound.
- Concurrent access: two threads loading simultaneously don't corrupt.
- Adversarial: another local user reading our process memory cannot extract the in-memory wrap key (within OS guarantees; out of scope for full defense).
