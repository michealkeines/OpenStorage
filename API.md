# OpenStorage — Local API Specification

> **Audience**: frontend authors (CLI, native app, web app, mobile, FUSE/WinFsp shims). This document defines the contract between the OpenStorage engine and any client that drives it.
>
> **Stability**: this document defines **API v1**. Once tagged stable, it is frozen for the life of the major version. New features arrive as additive endpoints or via capability flags. Breaking changes go to v2 with parallel-served paths.
>
> **Read alongside**: [`DESIGN.md`](./DESIGN.md), [`PLUGIN_SDK.md`](./PLUGIN_SDK.md), [`THREAT_MODEL.md`](./THREAT_MODEL.md).

---

## 1. Overview

The engine is a single binary that runs as a long-lived process on the user's machine (or on a self-hosted box they own). It exposes a **local-only HTTP/2 API** that frontends consume. There is no remote API. There is no service we operate. The same API is served regardless of deployment topology.

Frontends are interchangeable. Any one of {CLI, native app, web SPA in a local browser, mobile app over Tailscale, FUSE shim, WebDAV bridge} can drive a fully featured experience by speaking this API.

```
┌──────────────────────────────────────────────────────────────────┐
│                         FRONTEND LAYER                           │
│   CLI │ Native app │ Local web app │ Mobile │ FUSE │ WebDAV      │
└────────────────────────────┬─────────────────────────────────────┘
                             │ HTTP/2 + WS over UDS / TLS-localhost
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│                      ENGINE — API SERVER                         │
│   Auth │ Routing │ Streaming │ Events │ Capabilities             │
└────────────────────────────┬─────────────────────────────────────┘
                             │
┌────────────────────────────▼─────────────────────────────────────┐
│                       ENGINE — CORE                              │
│ VFS │ Metadata │ Crypto │ Chunk │ Placement │ Vault Mgr │ Lease  │
│ Plugin Host │ Sync (CRDT) │ Recovery │ Share Mgr │ Identity      │
└────────────────────────────┬─────────────────────────────────────┘
                             │
                             ▼
                  Provider plugins → backends
```

---

## 2. Design Principles for the API

1. **Local-only.** The API binds to a Unix domain socket (default) or a loopback TCP port; never to a public interface. Self-hosted daemons may bind to a private LAN address with mutual TLS.
2. **Frontend-agnostic.** Any frontend can implement against the spec without engine changes.
3. **Capability-driven.** Frontends discover what the engine supports via `/capabilities`; absent endpoints return a documented status.
4. **Streaming-first for data.** File bytes are streamed. Control plane is small and synchronous; data plane is chunked.
5. **Push events for state.** Long-running and asynchronous changes are surfaced via events; clients subscribe rather than poll.
6. **Idempotent mutations.** Every mutating call accepts an `Idempotency-Key`.
7. **Auth is mandatory.** Even on UDS. The token model survives across deployment topologies.
8. **Stable error model.** A small, fixed error code vocabulary that maps cleanly to plugin error codes.

---

## 3. Transport & Encoding

### 3.1 Transport

| Topology | Default | Notes |
|---|---|---|
| Single-device app, POSIX | Unix domain socket at `~/.openstorage/api.sock` | Permissions: 0600, owner-only |
| Single-device app, Windows | Named pipe `\\.\pipe\openstorage-api` | ACL: current user only |
| Self-hosted daemon | TCP on LAN address with TLS + mTLS | Configurable bind |
| Mobile sidecar (e.g., Tailscale) | TCP on tailnet address with mTLS | Same engine, remote topology |

All transports speak HTTP/2.

### 3.2 Encoding

| Plane | Format |
|---|---|
| Control (small JSON requests/responses) | `application/json; charset=utf-8` |
| Bulk data (file content) | Streaming bytes (`application/octet-stream` with `Transfer-Encoding: chunked`) |
| Events | WebSocket subprotocol `openstorage-events.v1`, JSON frames |

### 3.3 Time, IDs, and Encoding Conventions

- All timestamps: RFC 3339 with millisecond precision, UTC.
- All durations: ISO 8601 (`PT5M` for 5 minutes).
- All identifiers: opaque strings, treat as case-sensitive. Sizes ≤ 256 bytes.
- All hashes: lowercase hex with explicit prefix (`blake3:abc…`, `sha256:abc…`).
- All sizes: bytes (integer).

---

## 4. Authentication & Pairing

### 4.1 Token Model

Every request carries an `Authorization: Bearer <token>` header. Tokens are minted by the engine, never by a remote service.

### 4.2 First-Use Pairing (single-device)

```
1. The user installs the engine; engine generates a pairing secret on first run,
   prints it to the engine's local log file (mode 0600, user-only).
2. A frontend prompts the user for the pairing secret.
3. Frontend POSTs the pairing secret to /v1/auth/pair, receives a long-lived
   bearer token plus a refresh token.
4. The pairing secret is invalidated after first successful pair.
```

This protects against another local user account on the same machine accessing the API, even though they could connect to the UDS by file permissions.

### 4.3 Self-Hosted Pairing

The daemon ships an admin CLI that runs locally on the daemon host. It mints pairing codes that the user enters into a remote frontend. Mutual TLS additionally pins client certificates.

### 4.4 Token Lifecycle

| Op | Endpoint |
|---|---|
| Pair | `POST /v1/auth/pair` |
| Refresh | `POST /v1/auth/refresh` |
| Revoke | `POST /v1/auth/revoke` |
| List active tokens | `GET /v1/auth/tokens` |

A frontend surfaces token list and revocation in its UI; the user can kill the laptop's session from the phone if needed.

---

## 5. Versioning & Capability Discovery

### 5.1 URL Versioning

All endpoints live under `/v1/…`. Major-version bumps go to `/v2`. Within `v1`, additions are non-breaking.

### 5.2 Capabilities

```
GET /v1/capabilities
→ {
    "engine_version": "1.0.0",
    "api_version": "1",
    "features": [
      "vaults", "files", "events", "sharing",
      "multi_device", "recovery", "self_host",
      "quorum_writes", "hedged_reads", "read_repair",
      "anti_entropy_merkle", "priority_repair",
      "tiny_file_inline", "bloom_dedup",
      "cdc_with_attack_mitigations"
    ],
    "plugin_sdk_versions_supported": ["1"],
    "max_concurrent_streams": 64,
    "max_request_bytes": 16777216,
    "wal_supports_crdt": true,
    "ec_default": "rs(4,7)",
    "default_quorum_W": 5,
    "merkle_tree_depth": 15
  }
```

Frontends consult this on startup and adapt UI to engine support.

---

## 6. Resource Model

The API exposes the following top-level resource families:

| Resource | Description |
|---|---|
| `vaults` | The user's encrypted namespaces |
| `files` | Bytes addressed by path within a vault |
| `dirs` | Directory listings within a vault |
| `providers` | Configured backend instances (e.g., "my Drive #1") |
| `plugins` | Installed plugin code |
| `devices` | Devices currently registered to a vault |
| `lease` | Advisory primary-writer hint per vault |
| `recovery` | Recovery manifest configuration |
| `shares` | Outbound shares (this user → others) |
| `inbox` | Inbound shares (others → this user) |
| `identities` | The user's identity keys + known peers |
| `replication` | Per-vault replication health and per-file shard placement |
| `repair` | Repair scheduler stats and queue inspection |
| `anti-entropy` | Merkle-tree reconciliation between vault replicas |
| `bloom` | Per-vault Bloom-filter dedup index inspection |
| `snapshots` | Versioned metadata snapshots in vault providers |
| `chunking` | CDC mitigation state and toggles |
| `read-stats` | Hedged-read performance and read-repair counters |
| `system` | Engine introspection, triggers, logs, shutdown |
| `events` | Push channel for state changes |

Everything below is grouped by family.

---

## 7. Vaults

### 7.1 Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/vaults` | Create a new vault |
| `GET` | `/v1/vaults` | List configured vaults |
| `GET` | `/v1/vaults/{vault_id}` | Vault details |
| `POST` | `/v1/vaults/{vault_id}/unlock` | Unlock with passphrase / recovery |
| `POST` | `/v1/vaults/{vault_id}/lock` | Lock and zeroize keys |
| `POST` | `/v1/vaults/{vault_id}/rotate-key` | Rotate master key |
| `DELETE` | `/v1/vaults/{vault_id}` | Destroy (crypto-shred + best-effort backend delete) |
| `GET` | `/v1/vaults/{vault_id}/status` | Health, sizes, replica health summary |
| `POST` | `/v1/vaults/{vault_id}/import` | Import from recovery materials |
| `POST` | `/v1/vaults/{vault_id}/export-recovery` | Generate recovery file |

### 7.2 Create

```
POST /v1/vaults
{
  "label": "Personal",
  "passphrase": "<user secret>",
  "recovery": {
    "modes": ["recovery_file", "shamir"],
    "shamir": { "k": 3, "n": 5 }
  },
  "vault_providers": [
    { "provider_id": "drive-1", "role": "primary" },
    { "provider_id": "onedrive-1", "role": "replica" }
  ],
  "redundancy": { "mode": "erasure", "k": 4, "n": 7 }
}
→ 201 { "vault_id": "vlt_…", "recovery_file_url": "/v1/vaults/vlt_…/export-recovery" }
```

The response includes a one-time URL the frontend uses to download the recovery file; it is invalidated after first read.

### 7.3 Unlock

```
POST /v1/vaults/{vault_id}/unlock
{ "method": "passphrase", "passphrase": "…" }
or
{ "method": "shamir", "shares": ["share1", "share2", "share3"] }
or
{ "method": "hardware_key", "challenge_response": "…" }
→ 200 { "session_id": "sess_…", "expires_at": "…" }
```

Unlock derives the master key, holds it in OS secure storage for the session, and emits a `vault.unlocked` event. The session ID is required for sensitive operations (sharing, key rotation) but ordinary file access does not need it after unlock.

---

## 8. Files & Directories

### 8.1 Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/vaults/{v}/files/{path}` | Read file (streaming) |
| `PUT` | `/v1/vaults/{v}/files/{path}` | Write file (streaming) |
| `PATCH` | `/v1/vaults/{v}/files/{path}` | Partial write (range) |
| `DELETE` | `/v1/vaults/{v}/files/{path}` | Delete |
| `HEAD` | `/v1/vaults/{v}/files/{path}` | Peek (size, mtime, content_type, replica_health) |
| `POST` | `/v1/vaults/{v}/files/{path}/move` | Move/rename |
| `POST` | `/v1/vaults/{v}/files/{path}/copy` | Server-side copy (dedup-aware) |
| `GET` | `/v1/vaults/{v}/dirs/{path}` | List directory (paginated) |
| `POST` | `/v1/vaults/{v}/dirs/{path}` | Create directory |
| `DELETE` | `/v1/vaults/{v}/dirs/{path}` | Delete directory (recursive flag) |

### 8.2 Reads

`GET /v1/vaults/{v}/files/{path}`

Headers:
- `Range: bytes=…` (optional) — partial read.
- `If-None-Match: <etag>` — caching.
- `Accept: application/octet-stream`
- `X-OpenStorage-Hedge-Override: <count>` (optional) — request a specific hedge count for this read; default uses configured policy.

Response:
- `200 OK` or `206 Partial Content`
- `Content-Length: <bytes>`
- `Last-Modified: <rfc3339>`
- `ETag: <hash>`
- `X-OpenStorage-Replication-State: full | degraded | recovering` — chunk-level state aggregated for the file
- `X-OpenStorage-Replica-Health: 0.95` — informational
- `X-OpenStorage-Inline: true | false` — whether the file was served from inline payload (no chunk fetch)
- `X-OpenStorage-Hedges-Fired: <int>` — number of hedge requests issued for this read
- `X-OpenStorage-Read-Repair-Triggered: <int>` — number of shards enqueued for repair as a side effect of this read
- Body: streaming bytes.

The engine fetches needed shards using the **hedged-reads strategy** (see DESIGN §6.4): fires `K + H` parallel requests, takes first K to complete, cancels rest. On any verify failure, the affected shard is enqueued in the **inline read repair** path (DESIGN §6.5) without delaying the response. For files smaller than `inline.threshold_bytes` the response is served from the inline payload with no plugin calls at all.

### 8.3 Writes

`PUT /v1/vaults/{v}/files/{path}`

Headers:
- `Content-Length` or `Transfer-Encoding: chunked`
- `Idempotency-Key: <uuid>` (recommended for retry safety)
- `If-Match: <etag>` (optional) — fail if file changed since last read
- `Content-Type: <type>` — stored in metadata
- `X-OpenStorage-Quorum-Override: <int>` (optional) — request specific W (write-acks-required) value; clamped to `[k+1, n]` for EC mode.
- `X-OpenStorage-Inline-Hint: force | never | auto` (default `auto`) — control tiny-file inlining for this write.

Behavior:
- For files ≤ `inline.threshold_bytes`: encrypted as a single AEAD blob and stored inline; no chunks created.
- Otherwise: streaming bytes are chunked, encrypted, EC-encoded, placed on backends.
- Quorum semantics: write commits and returns 201 once `W` shards (default `k+1`) ack per chunk; remaining shards continue placing in the background, emitting `chunk.replication_state_changed` events.
- The engine emits progress events (`file.write.progress`).
- On success, returns the new `etag`, metadata, and replication state.

Response (201):
- `ETag: <hash>`
- `X-OpenStorage-Replication-State: full | degraded`  — `degraded` if quorum acked but full N replicas not yet placed
- `X-OpenStorage-Quorum-Acked: <int>` — actual W achieved
- `X-OpenStorage-Inline: true | false`
- Body: JSON with `{etag, size, chunks, inline}`.

### 8.4 Range Writes

`PATCH /v1/vaults/{v}/files/{path}` with `Content-Range: bytes <start>-<end>/<total>` performs a partial overwrite. The engine re-encrypts only affected chunks. Useful for FUSE shims and binary patching.

### 8.5 Listing

`GET /v1/vaults/{v}/dirs/{path}?cursor=<c>&limit=100&order=name`

Cursor-based pagination. Result entries include `name`, `is_dir`, `size`, `mtime`, `content_type`, and `etag`. Hidden files via dot-prefix; honored.

---

## 9. Providers

A *provider instance* is a configured backend (e.g., "my Drive account #1", "my home NAS"). A provider is an instantiation of a *plugin*.

### 9.1 Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/providers/oauth/start` | Begin OAuth flow for a plugin (engine handles browser) |
| `POST` | `/v1/providers/oauth/complete` | Complete OAuth flow with code |
| `POST` | `/v1/providers` | Register a configured provider instance |
| `GET` | `/v1/providers` | List configured providers |
| `GET` | `/v1/providers/{id}` | Provider details |
| `PATCH` | `/v1/providers/{id}` | Update settings |
| `DELETE` | `/v1/providers/{id}` | Remove (with chunk migration option) |
| `GET` | `/v1/providers/{id}/health` | Health snapshot |
| `POST` | `/v1/providers/{id}/test` | Round-trip a tiny test object |
| `POST` | `/v1/providers/{id}/migrate-out` | Move all chunks off this provider |

### 9.2 OAuth Flow

The engine runs the OAuth flow itself, not the frontend or the plugin. The flow:

```
1. Frontend POST /v1/providers/oauth/start { plugin_id }
   → 200 { "auth_url": "...", "session": "..." }
2. Engine spawns a localhost listener on a random port for the OAuth callback.
3. Frontend opens auth_url in the user's browser.
4. User authorizes; provider redirects to engine's callback.
5. Engine exchanges code for token, stores wrapped under master key.
6. Frontend POST /v1/providers/oauth/complete { session }
   → 200 { "credentials_handle": "..." }
7. Frontend POST /v1/providers { plugin_id, credentials_handle, settings }
   → 201 { "provider_id": "..." }
```

Tokens are never exposed to the frontend or the plugin.

---

## 9.A Vault Binding (per-device, fresh-device flow)

The local file that tells *this device* which vault provider holds the metadata for a given vault. Created during the setup wizard's first vault-bind step; updated on provider add/remove and on snapshot pointer advances.

### 9.A.1 Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/vaults/{v}/binding` | Inspect this device's binding (no secrets) |
| `POST` | `/v1/vaults/bind` | Bind this device to a vault: `{ vault_id, plugin_id, credentials_handle }` |
| `POST` | `/v1/vaults/{v}/binding/providers` | Add a vault-provider entry |
| `DELETE` | `/v1/vaults/{v}/binding/providers/{provider_id}` | Remove a vault-provider entry |
| `DELETE` | `/v1/vaults/{v}/binding` | Unbind this device (does NOT destroy the vault — just removes local binding; user can re-bind later) |

### 9.A.2 Bind Flow (fresh device)

```
   user runs setup wizard → "I have an existing vault"
                          │
                          ▼
   POST /v1/providers/oauth/start  { plugin_id }   ← OAuth into a chosen provider
                          │
                          ▼
   user authorizes; engine completes OAuth
                          │
                          ▼
   POST /v1/vaults/bind  { vault_id, plugin_id, credentials_handle }
                          │
                          ▼
   engine peeks the provider for "recovery.manifest"
   if found: writes encrypted VaultBinding to local disk
   if not found: returns error "no manifest at this provider for vault X"
                          │
                          ▼
   user proceeds to POST /v1/vaults/{v}/unlock with recovery materials
```

### 9.A.3 Edge Cases

- Binding to a provider that doesn't have the manifest: rejected; user picks a different provider or different vault_id.
- Re-binding when a binding already exists: replaces atomically.
- Unbinding while vault is unlocked: rejected (must lock first).
- Multiple devices binding to the same vault simultaneously: each writes its own local binding; both register in `allowed_devices` via OrSetAdd on first unlock.

---

## 10. Plugins

### 10.1 Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/plugins` | List installed plugins |
| `GET` | `/v1/plugins/{id}` | Plugin manifest details |
| `POST` | `/v1/plugins/install` | Install plugin from URL or file |
| `POST` | `/v1/plugins/{id}/conformance` | Run conformance suite |
| `POST` | `/v1/plugins/{id}/enable` | Enable for use |
| `POST` | `/v1/plugins/{id}/disable` | Disable without uninstall |
| `DELETE` | `/v1/plugins/{id}` | Uninstall (only if no active provider uses it) |

### 10.2 Install Flow

```
POST /v1/plugins/install
{ "source_url": "https://...", "expected_signature": "..." }
→ 202 { "install_id": "...", "review": { …manifest… } }
```

The engine fetches, verifies the signature, surfaces the manifest to the frontend (legal class, network hosts, capabilities, author). The frontend MUST display this and require explicit user confirmation before:

```
POST /v1/plugins/install/{install_id}/confirm
→ 201 { "plugin_id": "..." }
```

---

## 11. Devices & Lease

### 11.1 Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/vaults/{v}/devices` | List devices that have unlocked this vault |
| `DELETE` | `/v1/vaults/{v}/devices/{device_id}` | Revoke device (next sync will lock it) |
| `GET` | `/v1/vaults/{v}/lease` | Current lease state |
| `POST` | `/v1/vaults/{v}/lease/acquire` | Force acquire (steal expired lease) |
| `POST` | `/v1/vaults/{v}/lease/release` | Release current device's lease |

### 11.2 Multi-Device Behavior

Devices coordinate via:
- **Lease**: a hint about the current "primary writer" — used to drive snapshot timing, not to gate writes (see DESIGN.md §13).
- **CRDT-encoded WAL**: every metadata mutation carries causal context; concurrent writes from multiple devices merge deterministically.

Frontends typically need to surface:
- Lease state (so the user knows which device is "active").
- Device list (so the user can revoke a stolen laptop).
- Sync progress for the current device's pending changes.

---

## 12. Recovery

### 12.1 Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/vaults/{v}/recovery` | Current recovery configuration (without secrets) |
| `POST` | `/v1/vaults/{v}/recovery/configure` | Add/replace recovery modes |
| `POST` | `/v1/vaults/{v}/recovery/test` | Dry-run a recovery method |
| `POST` | `/v1/vaults/{v}/recovery/perform` | Perform recovery on a fresh device |
| `POST` | `/v1/vaults/{v}/recovery/file/generate` | Generate a fresh recovery file |
| `POST` | `/v1/vaults/{v}/recovery/shamir/distribute` | Generate Shamir shares (one-time) |
| `POST` | `/v1/vaults/{v}/recovery/rotate` | Rotate tokens of one mode; old artifacts invalidated |
| `GET` | `/v1/vaults/{v}/recovery/active-tokens` | List currently-valid `recovery_token_id`s with mode and creation time (no secret material) |

### 12.2 Recovery Configuration

Setting recovery options is a single explicit operation:

```
POST /v1/vaults/{v}/recovery/configure
{
  "modes": [
    { "kind": "passphrase", "active": true },
    { "kind": "recovery_file", "active": true },
    { "kind": "shamir", "active": true, "k": 3, "n": 5 },
    { "kind": "hardware_key", "active": false }
  ]
}
→ 200 { "manifest_id": "..." }
```

Modes are additive; turning one on doesn't turn off the others. The frontend surfaces this as a checklist with explicit warnings ("if you forget your passphrase and have not configured another mode, your data is unrecoverable").

---

## 13. Sharing & Identity

The engine treats identity as a first-class concept: every user has at least one identity keypair (Ed25519 for signing + ML-KEM for KEM). Sharing a file means encrypting the file's per-file key under the recipient's KEM public key and adding the wrap to the file's `wrapped_keys` list.

### 13.1 Identity Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/identities/self` | Get this user's public identity (shareable) |
| `POST` | `/v1/identities/self/rotate` | Rotate identity keys (sharing-impacting) |
| `GET` | `/v1/identities/peers` | List known peer identities |
| `POST` | `/v1/identities/peers` | Add peer (paste their public identity) |
| `DELETE` | `/v1/identities/peers/{id}` | Remove peer |
| `POST` | `/v1/identities/peers/{id}/verify` | Mark peer as verified (out-of-band fingerprint check) |

There is no central identity directory. Peers exchange identity blobs out-of-band (email, QR code, signal, paper). The frontend must surface fingerprint comparison clearly; T-PL-6 in the threat model maps onto this UX.

### 13.2 Share Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/vaults/{v}/shares` | Create a share |
| `GET` | `/v1/vaults/{v}/shares` | List outbound shares |
| `GET` | `/v1/vaults/{v}/shares/{share_id}` | Share details |
| `DELETE` | `/v1/vaults/{v}/shares/{share_id}` | Revoke share |
| `GET` | `/v1/inbox` | List inbound shares |
| `POST` | `/v1/inbox/{share_id}/accept` | Accept and import an inbound share |
| `DELETE` | `/v1/inbox/{share_id}` | Reject |

### 13.3 Create Share

```
POST /v1/vaults/{v}/shares
{
  "scope": { "kind": "file", "path": "/docs/plan.pdf" },
  "recipients": ["peer:alice-abc123"],
  "permissions": ["read"],
  "expires_at": "2026-12-01T00:00:00Z"
}
→ 201 { "share_id": "shr_…", "share_blob": "…" }
```

The `share_blob` is what the user sends to the recipient out-of-band. Importing it on the recipient's side wires the share into their inbox.

### 13.4 Revocation

Revocation rotates the affected file key, re-encrypts the chunks, and removes all wrappings. Future fetches by revoked recipients fail. Already-cached plaintext on a revoked recipient's device is *not* recallable — that's a fundamental property of any access-control-after-handover system.

---

## 14. System & Introspection

### 14.1 General Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/system/status` | Engine state, version, uptime, vault summaries |
| `GET` | `/v1/system/capabilities` | Same as `/v1/capabilities` |
| `GET` | `/v1/system/metrics` | Local metrics (Prometheus exposition format) |
| `GET` | `/v1/system/logs` | Tail engine logs (streaming) |
| `POST` | `/v1/system/snapshot` | Force a metadata snapshot |
| `POST` | `/v1/system/scrub` | Force a chunk scrub run |
| `POST` | `/v1/system/gc` | Force garbage collection |
| `POST` | `/v1/system/shutdown` | Graceful shutdown |

`/v1/system/metrics` is local-only; there is no remote scrape target. A self-hosted user can run a local Prometheus that scrapes their own daemon if they want.

### 14.2 Repair Scheduler

The repair scheduler exposes its priority queue and stats. See DESIGN §6.9 / §7 for the algorithm.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/system/repair/stats` | Queue depth, throughput, recently-completed, recently-lost |
| `GET` | `/v1/system/repair/queue?limit=50&order=urgency` | Top-N items in the priority queue |
| `POST` | `/v1/system/repair/run` | Trigger an immediate repair pass over the current queue |
| `POST` | `/v1/system/repair/enqueue` | Manually enqueue a chunk for repair `{ vault_id, chunk_hash, urgency? }` |
| `PATCH` | `/v1/system/repair/config` | Adjust runtime knobs (concurrency, urgency weights) |

Example response from `/v1/system/repair/stats`:
```
{
  "queue_depth": 23,
  "in_flight": 8,
  "completed_last_hour": 412,
  "lost_last_hour": 0,
  "avg_repair_time_ms": 1840,
  "by_source": { "scrub": 19, "read_repair": 4 },
  "rate_limited_by_provider": []
}
```

### 14.3 Anti-Entropy (Merkle Reconciliation)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/vaults/{v}/anti-entropy/status` | Last run, divergence summary across vault replicas |
| `GET` | `/v1/vaults/{v}/anti-entropy/merkle-root` | Current Merkle root + tree depth (debug) |
| `POST` | `/v1/vaults/{v}/anti-entropy/run` | Force a Merkle exchange with all configured vault replicas |

Example response from `/anti-entropy/status`:
```
{
  "last_run_at": "2026-04-30T08:14:00.000Z",
  "duration_ms": 4210,
  "vault_replicas": [
    { "provider_id": "drive-1", "merkle_root": "blake3:abc…", "in_sync": true },
    { "provider_id": "onedrive-1", "merkle_root": "blake3:abc…", "in_sync": true },
    { "provider_id": "nas-1", "merkle_root": "blake3:def…", "in_sync": false,
      "divergent_pages": 12, "reconcile_in_progress": true }
  ],
  "next_run_at": "2026-04-30T09:14:00.000Z"
}
```

### 14.4 Read Path Statistics (hedging, read-repair)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/system/read-stats?window=1h` | p50/p95/p99 read latency, hedge fire rate, hedge-saved count, read-repair triggered |
| `GET` | `/v1/providers/{id}/read-stats?window=1h` | Per-provider latency distribution and hedge contribution |
| `PATCH` | `/v1/system/read-stats/policy` | Adjust `read.hedge_count`, `read.hedge_after_ms` at runtime |

Example response from `/v1/system/read-stats`:
```
{
  "window": "1h",
  "reads": 4812,
  "p50_ms": 38, "p95_ms": 240, "p99_ms": 612,
  "hedges_fired": 92,
  "hedge_fire_rate_pct": 1.91,
  "saved_by_hedge_count": 71,
  "p99_without_hedge_estimate_ms": 1850,
  "read_repair_triggered": 3,
  "verify_failures": 3
}
```

### 14.5 Replication State

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/vaults/{v}/replication/summary` | Vault-wide replication health: counts of `full` / `degraded` / `recovering` / `lost` chunks |
| `GET` | `/v1/vaults/{v}/files/{path}/replication` | Per-file chunk-level replication state, including per-shard driver placement |
| `GET` | `/v1/vaults/{v}/replication/lost` | Paginated list of files with one or more LOST chunks |

Example response from `/v1/vaults/{v}/replication/summary`:
```
{
  "chunk_count_total": 42_310_211,
  "by_state": {
    "full": 42_309_854,
    "degraded": 312,
    "recovering": 41,
    "lost": 4
  },
  "ec_scheme": "rs(4,7)",
  "write_acks_required": 5,
  "diversity_groups_active": ["google", "microsoft", "self-hosted-nas"]
}
```

### 14.5a Capacity Planner & Rebalancer

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/vaults/{v}/capacity/projection` | Pool-aware fill projection: usable bytes, fill rate, projected_full_at |
| `GET` | `/v1/vaults/{v}/capacity/per-plugin` | Each plugin's contribution to capacity, including shadow overhead |
| `POST` | `/v1/vaults/{v}/rebalance/run` | Force a rebalance pass over the current pool |
| `GET` | `/v1/vaults/{v}/rebalance/status` | Current rebalancer state, queued work, throughput |
| `PATCH` | `/v1/vaults/{v}/rebalance/config` | Adjust bandwidth cap, priority weights at runtime |

### 14.5b Tier Classification

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/vaults/{v}/tiers/summary` | Counts of hot / warm / cold chunks; bytes per tier |
| `GET` | `/v1/vaults/{v}/files/{path}/tier` | Tier of a specific file's chunks |
| `POST` | `/v1/vaults/{v}/files/{path}/tier` | Force-pin a file's tier (override classification) |
| `PATCH` | `/v1/vaults/{v}/tiers/policy` | Adjust the access-count thresholds and per-tier EC schemes |

### 14.5c Identity & Epoch Management

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/identities/self/chain` | Full identity chain (all epochs with signatures) |
| `POST` | `/v1/identities/self/rotate` | Begin identity rotation: new epoch signed by current |
| `GET` | `/v1/identities/self/epoch` | Currently-active epoch_id and pubkey |

### 14.6a Shadow Registry (unreclaimable ciphertext)

When a plugin reports `prior_handle_state ∈ {tombstoned, abandoned, unknown}` on update, or `outcome ∈ {tombstoned, abandoned, not_supported}` on delete, the engine registers a *shadow shard* — ciphertext we no longer reference but cannot reclaim. The shadow registry is the user's authoritative view of "what's left behind."

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/vaults/{v}/shadows` | List shadow shards (paginated, filterable by driver / reason / risk) |
| `GET` | `/v1/vaults/{v}/shadows/summary` | Aggregate by driver: byte count, by `cached_elsewhere_risk`, by `reason` |
| `POST` | `/v1/vaults/{v}/shadows/retry-delete` | Opportunistic re-attempt of pending-tombstone or unknown-state shadows |
| `GET` | `/v1/vaults/{v}/shadows/destruction-preview` | What would be left behind if the vault were destroyed right now |

Example response from `/shadows/summary`:
```
{
  "total_shadows": 412,
  "total_bytes": 1_843_220_000,
  "by_driver": [
    { "driver_id": "archive-org-1", "shadows": 312, "bytes": 1_240_000_000,
      "reclaimable_count": 0, "cached_elsewhere_risk": "low" },
    { "driver_id": "imgur-1", "shadows": 89, "bytes": 540_000_000,
      "reclaimable_count": 12, "cached_elsewhere_risk": "high" },
    { "driver_id": "telegram-1", "shadows": 11, "bytes": 63_220_000,
      "reclaimable_count": 11, "cached_elsewhere_risk": "low",
      "tombstone_clears_at": "2026-05-15T00:00:00Z" }
  ],
  "by_reason": {
    "update_replaced": 285,
    "repair_replaced": 47,
    "deletion_orphaned": 80
  }
}
```

This is what the frontend surfaces to a user who asks "what did I leave behind?" Crypto-shred makes the bytes random; the registry tells the user where the bytes are.

### 14.6 Bloom Filter

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/vaults/{v}/bloom/stats` | Current fill rate, FPR estimate, last rebuild |
| `POST` | `/v1/vaults/{v}/bloom/rebuild` | Force rebuild (typically post-GC) |

Example response:
```
{
  "size_bytes": 62_914_560,
  "expected_chunks": 50_000_000,
  "current_chunks": 41_882_109,
  "estimated_fpr": 0.0094,
  "last_rebuilt_at": "2026-04-29T22:00:00.000Z"
}
```

### 14.7 CDC Mitigation Inspection

For vaults configured with CDC chunking, the engine auto-applies compression + padding + packing per THREAT_MODEL T-CR-8.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/vaults/{v}/chunking/state` | Current chunking strategy and active mitigations |
| `PATCH` | `/v1/vaults/{v}/chunking/state` | Toggle mitigations (with explicit confirmation header) |

Disabling mitigations requires `X-OpenStorage-Confirm-Insecure: i-understand-cdc-attack-risk` and produces a `system.error` event of severity `warn` to remind the user.

Example response:
```
{
  "strategy": "content-defined",
  "size_target": 4194304,
  "mitigations": {
    "compression": "zstd-3",
    "padding": "next-power-of-two",
    "packing": "fixed-256kb-containers"
  },
  "attack_reference": "Truong 2024 — Breaking and Fixing CDC"
}
```

### 14.8 Snapshot Inspection

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/vaults/{v}/snapshots` | List snapshot history (versioned) |
| `GET` | `/v1/vaults/{v}/snapshots/current` | Pointer to current snapshot + signed monotonic counter |
| `POST` | `/v1/vaults/{v}/snapshots/full` | Force a full (non-delta) snapshot + WAL compaction |
| `POST` | `/v1/vaults/{v}/snapshots/verify` | Re-verify the current snapshot against vault providers |

### 14.9 Quorum & Read-Path Configuration (per vault)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/vaults/{v}/config` | Full vault config (chunking, redundancy, hedge, repair, snapshot) |
| `PATCH` | `/v1/vaults/{v}/config` | Update tunable parameters online |

Patches to `redundancy.write_acks_required`, `redundancy.repair_floor`, or `redundancy.diversity_groups_min` apply on the next write; the API responds with the affected runtime sections.

---

## 15. Events

### 15.1 Subscription

```
GET /v1/events  (Upgrade: websocket; Sec-WebSocket-Protocol: openstorage-events.v1)
```

After upgrade, the frontend sends a JSON subscription:

```
{ "subscribe": ["vault.*", "share.received", "plugin.health_changed"] }
```

The engine pushes events as JSON frames.

### 15.2 Event Catalog

#### Lifecycle / Vault
| Event | Payload |
|---|---|
| `vault.unlocked` | `{ vault_id, by_method }` |
| `vault.locked` | `{ vault_id, reason }` |
| `vault.locking` | `{ vault_id, in_seconds }` (about to auto-lock) |
| `vault.bound` | `{ vault_id, device_id, provider_id }` — first-time bind on this device |
| `vault.unbound` | `{ vault_id, device_id }` |
| `vault.destroying` | `{ vault_id, sweep_progress_pct }` — emitted during destruction sweep |
| `vault.destroyed` | `{ vault_id, residual_report }` |

#### Recovery
| Event | Payload |
|---|---|
| `recovery.tokens_rotated` | `{ vault_id, mode, new_count, revoked_count }` |
| `recovery.token_revoked` | `{ vault_id, token_id, mode }` |
| `recovery.failed` | `{ vault_id, reason: "wrong_passphrase" \| "token_revoked" \| "chain_invalid" \| ... }` |
| `manifest.synced` | `{ vault_id, providers_caught_up: int, version_counter }` |
| `manifest.fork_detected` | `{ vault_id, providers_with_diverging_manifests }` (corrupted state) |

#### File-level
| Event | Payload |
|---|---|
| `file.write.progress` | `{ vault_id, path, bytes_written, bytes_total }` |
| `file.changed` | `{ vault_id, path, etag, by_device }` (from another device) |
| `file.inline_promoted` | `{ vault_id, path, etag }` (file size grew past `inline.threshold` on update; switched to chunked storage) |

#### Quorum & Replication
| Event | Payload |
|---|---|
| `chunk.replication_state_changed` | `{ vault_id, chunk_hash, from, to, healthy_shards, n_total }` (e.g., `degraded → full` when async fan-out completes) |
| `chunk.lost` | `{ vault_id, chunk_hash, affected_files[] }` (EC threshold breached) |
| `write.quorum_acked` | `{ vault_id, file_path, w_required, w_actual, async_remaining }` |
| `write.fully_replicated` | `{ vault_id, file_path }` (last shard acked) |

#### Repair Scheduler
| Event | Payload |
|---|---|
| `repair.enqueued` | `{ vault_id, chunk_hash, urgency, source: "scrub"\|"read_repair"\|"plugin_health"\|"manual" }` |
| `repair.started` | `{ vault_id, chunk_count }` |
| `repair.shard_completed` | `{ vault_id, chunk_hash, shard_index, new_driver_id, duration_ms }` |
| `repair.completed` | `{ vault_id, repaired, lost, duration_ms }` |
| `repair.queue_overflow` | `{ vault_id, queue_size, demoted_to_scrub }` |

#### Read Path
| Event | Payload |
|---|---|
| `read.hedge_fired` | `{ vault_id, chunk_hash, after_ms, hedge_index }` (debug-level; opt-in subscription) |
| `read.repair_triggered` | `{ vault_id, chunk_hash, shard_index, reason: "verify_fail"\|"timeout" }` |
| `read.hedge_policy_adjusted` | `{ new_hedge_after_ms, reason }` (engine adapted threshold based on rolling p95) |

#### Anti-Entropy
| Event | Payload |
|---|---|
| `anti_entropy.run_started` | `{ vault_id, replicas_checked }` |
| `anti_entropy.divergence_detected` | `{ vault_id, replica_provider_id, divergent_pages }` |
| `anti_entropy.run_completed` | `{ vault_id, reconciled_pages, duration_ms }` |
| `anti_entropy.merkle_root_changed` | `{ vault_id, new_root, page_count }` |

#### Snapshot
| Event | Payload |
|---|---|
| `snapshot.started` | `{ vault_id, kind: "full"\|"delta" }` |
| `snapshot.completed` | `{ vault_id, snapshot_id, bytes_uploaded }` |
| `snapshot.verify_failed` | `{ vault_id, snapshot_id, reason }` |

#### Plugins / Providers
| Event | Payload |
|---|---|
| `plugin.health_changed` | `{ plugin_id, state }` |
| `provider.health_changed` | `{ provider_id, state, note, p95_read_latency_ms }` |
| `provider.quota_low` | `{ provider_id, used_pct }` |
| `provider.quarantined` | `{ provider_id, reason, affected_chunks }` (mass-enqueue triggered) |

#### Bloom Filter
| Event | Payload |
|---|---|
| `bloom.rebuilt` | `{ vault_id, current_chunks, estimated_fpr, duration_ms }` |
| `bloom.fpr_warning` | `{ vault_id, estimated_fpr }` (FPR climbed above target; rebuild recommended) |

#### Shadow Registry (unreclaimable ciphertext)
| Event | Payload |
|---|---|
| `shadow.registered` | `{ vault_id, shadow_id, driver_id, reason, bytes, cached_elsewhere_risk }` (a shard could not be deleted on update / repair / GC; ciphertext remains on backend) |
| `shadow.cleared` | `{ vault_id, shadow_id, driver_id, reason }` (a tombstoned or unknown-state shadow was confirmed removed on a later peek) |
| `shadow.destruction_preview` | `{ vault_id, total_shadows, total_bytes, by_driver }` (emitted on POST /shadows/destruction-preview) |
| `quota.unreclaimable_growing` | `{ driver_id, abandoned_bytes, abandoned_pct_of_quota }` (shadow bytes on a driver exceed configured threshold; consider migrate-out) |

#### Capacity Planner & Rebalancer
| Event | Payload |
|---|---|
| `capacity.projection_updated` | `{ vault_id, usable_bytes, fill_rate_per_day, projected_full_at }` |
| `capacity.threshold_warning` | `{ vault_id, projected_full_at, days_remaining }` (< 14 days) |
| `capacity.threshold_critical` | `{ vault_id, projected_full_at, days_remaining }` (< 3 days) |
| `provider.quota_untrusted` | `{ provider_id, observed_divergence }` (plugin's quota report disbelieved) |
| `rebalance.started` | `{ vault_id, reason, chunks_to_evaluate }` |
| `rebalance.progress` | `{ vault_id, chunks_moved, bytes_moved, eta }` |
| `rebalance.completed` | `{ vault_id, chunks_moved, bytes_moved, duration_ms }` |

#### Tier Classification
| Event | Payload |
|---|---|
| `tier.changed` | `{ vault_id, chunk_hash, from, to }` (a chunk crossed an access threshold) |
| `tier.policy_updated` | `{ vault_id, by }` |

#### Identity & Epoch
| Event | Payload |
|---|---|
| `identity.epoch_rotated` | `{ vault_id, from_epoch, to_epoch }` |
| `identity.chain_invalid` | `{ vault_id, broken_at_epoch, reason }` (cold start verification failed; user must intervene) |
| `identity.chain_forked` | `{ vault_id, manifest_chain_tip, snapshot_chain_tip }` — manifest and snapshot chains diverge; corrupted state |
| `identity.chain_lagged` | `{ vault_id, where: "snapshot"\|"manifest", lagging_by: int }` — recoverable lag; engine self-corrects |

#### Plugin Capability Drift
| Event | Payload |
|---|---|
| `plugin.capability_changed` | `{ plugin_id, gained: [], lost: [] }` |
| `plugin.confirmation_required` | `{ plugin_id, lost_capabilities: [], affected_chunks: int }` (plugin lost a capability that affects placed data; user must confirm load or migrate-out) |

#### Lease / Devices
| Event | Payload |
|---|---|
| `lease.acquired` | `{ vault_id, by_device }` |
| `lease.lost` | `{ vault_id, to_device }` |
| `device.added` | `{ vault_id, device_id, device_label }` |
| `device.revoked` | `{ vault_id, device_id }` |

#### Sharing
| Event | Payload |
|---|---|
| `share.received` | `{ share_id, from_peer }` |
| `share.revoked` | `{ share_id, by_peer }` |
| `share.created` | `{ share_id, scope, recipients[] }` |
| `share.expired` | `{ share_id }` |

#### CRDT Multi-device
| Event | Payload |
|---|---|
| `sync.peer_wal_pulled` | `{ from_device, ops_applied }` |
| `sync.merge_completed` | `{ vault_id, ops_total, conflicts_resolved }` |

#### System Health
| Event | Payload |
|---|---|
| `system.error` | `{ severity: "info"\|"warn"\|"error", code, message, correlation_id? }` |
| `system.config_changed` | `{ section, by }` |
| `system.kdf_profile_changed` | `{ from, to, reason }` |
| `device.revoked` | `{ vault_id, device_id }` |
| `system.error` | `{ severity, code, message }` |

### 15.3 Replay

Events have monotonic IDs. Frontends that disconnect can reconnect with `?since=<id>` to receive missed events from a bounded buffer.

---

## 16. Error Model

All errors return the same envelope:

```
HTTP/1.1 4xx or 5xx
Content-Type: application/json
{
  "error": {
    "code": "snake_case_code",
    "message": "human-readable",
    "retryable": true,
    "retry_after_ms": 1500,
    "details": { … },
    "correlation_id": "…"
  }
}
```

### 16.1 Code Catalog

| Code | HTTP | Meaning |
|---|---|---|
| `unauthenticated` | 401 | No / invalid token |
| `forbidden` | 403 | Token lacks scope |
| `not_found` | 404 | Resource missing |
| `precondition_failed` | 412 | If-Match or version mismatch |
| `conflict` | 409 | Concurrent state change |
| `rate_limited` | 429 | Backoff and retry |
| `validation_failed` | 422 | Bad input |
| `vault_locked` | 423 | Operation needs unlock |
| `provider_unavailable` | 503 | Backend backend not reachable |
| `quota_exceeded` | 507 | Out of space at backend |
| `corrupted` | 500 | Integrity check failed (data loss event) |
| `unsupported_operation` | 501 | Engine does not support feature |
| `internal_error` | 500 | Engine bug; retry not advised |

These map cleanly to the plugin error taxonomy in `PLUGIN_SDK.md` §9.

---

## 17. Streaming Details

### 17.1 Uploads

- Chunked transfer, content-length optional.
- The engine can absorb arbitrarily large uploads with bounded memory.
- Mid-flight failure: if the connection drops, the engine keeps already-placed chunks; a subsequent `PUT` with the same `Idempotency-Key` resumes from the last completed chunk.

### 17.2 Downloads

- The engine streams plaintext as soon as the first chunk decrypts.
- Range requests: `Range: bytes=<a>-<b>`.
- The engine prefers replicas with `supports_range_reads`; falls back to whole-chunk fetch + slice.

### 17.3 Backpressure

HTTP/2 flow control gives natural backpressure. The engine paces fetches to match the frontend's read rate — large reads do not balloon RAM.

---

## 18. Idempotency

Every mutating call accepts `Idempotency-Key: <uuid>`. The engine remembers the result for 24 hours. Replays return the cached response.

This is essential for:
- Crash recovery on the frontend mid-upload.
- Mobile background uploads with poor connectivity.
- Browser "double-click submit" hardening.

---

## 19. Frontend Conformance

### 19.1 Minimum Frontend (must implement)

A frontend claiming "OpenStorage compatible" must:

- Implement the auth pairing flow.
- Implement vault unlock and lock (with passphrase prompt).
- Implement at least file read, write, delete, and dir list.
- Honor the events stream for `vault.locked` (force re-prompt) and `system.error` (surface to user).
- Display the manifest review at plugin install time (legal class, network hosts, capabilities).
- Surface peer fingerprints clearly when adding identities.

### 19.2 Optional (capability-gated)

- Sharing and inbox UI.
- Recovery configuration UI (otherwise restricted to "passphrase only" default).
- Plugin install UI (otherwise only first-party plugins available).
- Lease / device management.
- Self-hosted pairing flow.
- Replication-health dashboard (consumes `/v1/vaults/{v}/replication/summary` + `chunk.replication_state_changed` events).
- Repair queue inspector.
- Anti-entropy status / divergence reporting.
- Read-stats dashboard (hedge fire rate, p99 latency).
- CDC mitigation toggle (must surface T-CR-8 warning prominently).

### 19.3 Surfacing Distributed-State Honestly

Frontends SHOULD surface the following so users understand the trust model:

- **Write durability**: when a write returns 201 with `X-OpenStorage-Replication-State: degraded`, surface "your file is durable but still replicating" rather than just "saved." Subscribe to `write.fully_replicated` to update the indicator.
- **Lost chunks**: on `chunk.lost` events, immediately surface affected files to the user with recovery options (restore from share, re-upload, accept loss).
- **Anti-entropy divergence**: on prolonged divergence between vault replicas (>24h), warn the user — possible misconfiguration or one-vault failure.
- **Bloom FPR warning**: surface when FPR climbs past target so the user can trigger a rebuild.
- **CDC mitigation status**: if a user disables mitigations, surface a persistent warning until re-enabled.

### 19.4 Anti-Patterns

A frontend MUST NOT:

- Cache the user's passphrase or master key.
- Persist plaintext file content beyond the user's explicit save action.
- Display peer keys without fingerprint verification UI.
- Bypass the manifest review at plugin install.
- Make API calls to non-localhost engines without explicit user-configured trust.
- Disable CDC attack mitigations without surfacing the persistent warning required by §14.7.
- Treat `degraded` replication state as failure; it is the normal post-quorum state until full N replicas are placed.
- Suppress `chunk.lost` events; users must always know when data has actually been lost.

---

## 20. Frontend Patterns

### 20.1 CLI

A CLI is the simplest possible frontend. Each command is one or two API calls. Streams to stdout/stdin. Authentication via a token in `~/.openstorage/cli.token`.

### 20.2 Native App (desktop)

Bundles the engine as a child process or as a sibling daemon. Uses UDS. Provides directory tree UI, drag-and-drop, sync indicators.

### 20.3 Web App (local)

A static SPA the engine serves on the same loopback port (under a different path, e.g., `/ui/…`). Same-origin, talks to `/v1/…`. Useful for a "no-install" experience when the engine is already running.

### 20.4 Mobile

A native iOS/Android app that talks to the user's self-hosted daemon over a private network (Tailscale, WireGuard, LAN). Uses mTLS. Implements the file-provider extension on iOS, document provider on Android.

### 20.5 FUSE / WinFsp Shim

A thin frontend that translates FUSE/WinFsp callbacks into API calls. Caches aggressively to satisfy POSIX semantics; honors `file.changed` events to invalidate caches.

### 20.6 WebDAV Bridge

A frontend exposing the API as a WebDAV endpoint, letting any WebDAV client talk to the vault. Useful for legacy software interop.

---

## 21. Examples

### 21.1 List the Top of the Vault

```
GET /v1/vaults/vlt_abc/dirs/?limit=50 HTTP/2
Authorization: Bearer …

→ 200 OK
{
  "entries": [
    { "name": "docs", "is_dir": true, "mtime": "2026-04-30T10:11:12.000Z" },
    { "name": "photo.jpg", "is_dir": false, "size": 4582943, "etag": "blake3:…" }
  ],
  "next_cursor": null
}
```

### 21.2 Stream a 4 GB File Up

```
PUT /v1/vaults/vlt_abc/files/movies/holiday.mp4 HTTP/2
Authorization: Bearer …
Idempotency-Key: 4f0a-…
Transfer-Encoding: chunked
Content-Type: video/mp4

…streamed bytes…

→ 201 Created
{ "etag": "blake3:…", "size": 4_312_345_678, "chunks": 1078 }
```

While the upload is in flight the frontend's events stream emits `file.write.progress` frames it can use to draw a progress bar.

### 21.3 Receive a Share

```
GET /v1/inbox HTTP/2
→ 200
{
  "shares": [
    {
      "share_id": "shr_xyz",
      "from_peer": { "id": "peer:alice-abc", "label": "Alice", "verified": true },
      "scope": "file:plan.pdf",
      "received_at": "2026-04-29T08:11:00Z"
    }
  ]
}

POST /v1/inbox/shr_xyz/accept HTTP/2
→ 200 { "imported_path": "/shared-with-me/alice/plan.pdf" }
```

---

## 22. Security Notes (cross-reference)

The API surface inherits the security properties of the engine:

- All file content traversing the API is plaintext; the API endpoint enforces auth and runs only locally.
- Plaintext never leaves the user's machine via the API (it goes to the frontend, which is on the same machine — except in self-hosted mode where it traverses the user's private network with mTLS).
- Tokens and credentials never appear in logs.
- See `THREAT_MODEL.md` for the full picture.

---

## 23. Glossary

- **Engine**: the core process; the only thing that holds keys.
- **Frontend**: any client of the API (CLI, app, web, mobile, FUSE).
- **Pairing**: one-time exchange that mints a long-lived bearer token.
- **Capability**: a feature flag the engine reports; frontends adapt UI accordingly.
- **Identity**: a user's public keypair (signing + KEM) used for sharing and verifying.
- **Peer**: another user's identity known to this user.
- **Share**: a key-wrap that grants a peer access to a file/folder/vault.
- **Inbox**: incoming shares pending acceptance.
- **Lease**: the writer-priority hint coordinated through the metadata vault.
