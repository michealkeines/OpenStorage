# OpenStorage — Plugin Contract (SDK Specification)

> **Audience**: plugin authors. This document defines the contract a plugin must satisfy to be loaded and used by the OpenStorage core. Read alongside [`DESIGN.md`](./DESIGN.md).
>
> **Stability**: this document defines **SDK ABI v1**. Once tagged stable, the contract is frozen for the life of the major version. Breaking changes go to v2 with parallel-loadable shims.

---

## 1. Overview & Goals

### 1.1 What a Plugin Is

A plugin is a self-contained unit that lets OpenStorage talk to one external storage provider (e.g. Google Drive, OneDrive, an S3-compatible bucket, or — via community plugins — Telegram, Discord, etc.). The plugin is the *only* code in the system that knows the provider's protocol; the rest of the system treats every plugin as a generic put/get/peek/delete object store.

### 1.2 Design Goals

1. **Minimum surface, maximum extensibility.** Required operations are tiny; everything else is gated by capability flags.
2. **Security-first.** Third-party plugins run in a WASM sandbox with no key access and a narrow network capability. Plugins never see plaintext.
3. **Honest declarations.** A plugin declares what it can and cannot do; lying about capabilities is a conformance bug, not a feature.
4. **No host trust required.** The plugin doesn't need to trust the host beyond the protocol; the host doesn't need to trust the plugin beyond the sandbox.
5. **Forward-compatible.** Capability negotiation lets old plugins keep working when the host gains new features.

### 1.3 What a Plugin Is *Not*

- A plugin is not an encryption layer. The host encrypts before calling the plugin. Plugins always see ciphertext.
- A plugin is not a placement engine. Where a chunk goes is the host's decision; the plugin only stores it where instructed.
- A plugin is not a network library. The host provides the egress capability; plugins use the host-provided fetch.
- A plugin is not allowed to phone home. Outbound network is restricted to the declared provider host(s) only.

---

## 2. Plugin Roles

A plugin declares one or more **roles**. Each role unlocks a different operation set.

| Role | Purpose | Required ops |
|---|---|---|
| `chunk_backend` | Stores encrypted chunk shards | put, get, peek, delete, health |
| `metadata_vault` | Stores snapshots + WAL + lease | put, get, peek, delete, health, list, cas_write |

A single plugin may declare both roles (most legitimate cloud providers fit both). The host treats them as independent; configuration may enable one role and disable the other.

---

## 3. Plugin Manifest

Every plugin ships with a static manifest declared at load time. The manifest is signed (for first-party) or hash-pinned (for third-party). It is the *only* place the plugin can claim things; lying here is a conformance failure.

Manifest fields:

| Field | Type | Description |
|---|---|---|
| `plugin_id` | string | Globally unique reverse-DNS, e.g. `org.openstorage.drive` |
| `plugin_name` | string | Human-readable name |
| `plugin_version` | semver | Plugin's own version |
| `sdk_version` | semver | SDK ABI version it targets |
| `roles` | list of role names | Roles this plugin supports |
| `legal_class` | enum | `green` / `yellow` / `red` (see §3.2) |
| `trust_correlation_group` | string | E.g. `google`, `microsoft`, `independent-mega` |
| `capabilities` | flag set | Per §6 |
| `network_hosts` | list of host patterns | Domains the plugin is permitted to contact |
| `auth_kinds` | list | E.g. `oauth2`, `api_key`, `basic`, `signed_request` |
| `default_settings` | map | Tunable settings with defaults |
| `author` | string | Plugin author identity |
| `homepage_url` | URL | Documentation / source |
| `license` | SPDX id | E.g. `Apache-2.0` |

### 3.1 Network Host Allowlist

`network_hosts` is a list of host patterns the host's egress capability will allow. Examples:
- `*.googleapis.com`
- `api.dropbox.com`
- `*.r2.cloudflarestorage.com`

Outbound connections to anything outside the allowlist are blocked by the host before the plugin's request leaves the sandbox. Plugins may not request `*` — wildcards are validated by the host loader.

### 3.2 Legal Class

| Class | Meaning | Default policy |
|---|---|---|
| `green` | Provider's ToS permits programmatic blob storage | Loadable in core |
| `yellow` | Provider's ToS is ambiguous; user discretion advised | Loadable with explicit user opt-in |
| `red` | Provider's ToS forbids this use | Loadable only with double-confirm + warning; never shipped in core |

The host enforces these classes against user policy (`plugin.thirdparty.allowed_legal_classes`).

---

## 4. Plugin Lifecycle

```
   ┌──────────┐
   │  LOADED  │ — manifest verified, sandbox prepared, no state yet
   └────┬─────┘
        │ host.init(settings, credentials_handle)
        ▼
   ┌──────────┐
   │   INIT   │ — plugin sets up internal state, may probe provider
   └────┬─────┘
        │ ok
        ▼
   ┌──────────┐
   │  READY   │ ◄────────────┐
   └────┬─────┘              │
        │                    │ resume
        │ host calls ops     │
        │                    │
   ┌────▼─────┐         ┌────┴─────┐
   │  ACTIVE  │         │ PAUSED   │ — host throttles or quarantines
   └────┬─────┘         └────▲─────┘
        │ pause              │
        └────────────────────┘
        │ shutdown
        ▼
   ┌──────────┐
   │  CLOSING │ — drain in-flight ops
   └────┬─────┘
        │
        ▼
   ┌──────────┐
   │  CLOSED  │
   └──────────┘
```

### 4.1 Lifecycle Operations

| Op | Direction | Description |
|---|---|---|
| `init` | host → plugin | Provide settings + credentials handle; plugin may make a probe call |
| `ready` | plugin → host | Plugin reports ready; may include warm capacity / quota info |
| `pause` | host → plugin | Plugin should stop accepting new ops, drain in-flight |
| `resume` | host → plugin | Resume normal operation |
| `shutdown` | host → plugin | Final; release resources |
| `health_changed` | plugin → host | Asynchronous push (optional) when plugin's self-assessed health changes |

---

## 5. Required Operations

These are the operations every plugin in a given role must implement. Each is described as input → output + side effects.

### 5.1 Common to All Roles

#### `health() → HealthReport`

Input: none.
Output:
- `state`: `healthy` / `degraded` / `unhealthy`
- `quota_total_bytes` (optional)
- `quota_used_bytes` (optional)
- `rate_limit_remaining` (optional, requests / window)
- `rate_limit_reset_at` (optional)
- `last_error` (optional, machine-readable code)
- `note` (optional, human string)

Side effects: a probe request to the provider may be issued, but the plugin should cache and rate-limit its own probes.

### 5.2 Role: `chunk_backend`

#### `put(payload, hint) → PutResult`

Input:
- `payload`: opaque bytes (always ciphertext; the plugin must not assume anything about content)
- `hint`: optional metadata
  - `content_type` suggestion (advisory only)
  - `desired_durability_class`
  - `idempotency_key` (the host may retry; plugin must dedupe by this key for at least 1 hour)
  - `replaces_handle` (optional): if the host is logically updating an existing object, it passes the old handle here. The plugin uses this to attempt an in-place overwrite; failing that, to attempt to delete the old object after the new one is written; failing that, to abandon it.

Output (`PutResult`):
- `handle`: opaque bytes (≤ 1 KiB), the *current* native reference to the new object
- `handle_changed`: bool — `true` if a new handle was minted (any backend that can't update in place); `false` if `payload` was written to the same handle (`replaces_handle == handle`)
- `prior_handle_state`: present **only** if `replaces_handle` was supplied. One of:
  - `overwritten` — same handle, content replaced in place; old bytes gone
  - `removed` — new handle was minted, and the plugin successfully deleted the old object
  - `tombstoned` — new handle minted; old object is queued for backend-side deletion (with `tombstone_clears_at` timestamp)
  - `abandoned` — new handle minted; old object cannot be deleted; bytes will remain forever on the backend
  - `unknown` — new handle minted; the plugin couldn't determine the old object's fate
- `stored_at`: timestamp
- `actual_bytes_stored`: may differ from input if encoding adds overhead
- `provider_object_id` (optional, debug aid)
- `tombstone_clears_at`: timestamp (only with `prior_handle_state == tombstoned`)
- `quota_reclaimed`: `yes` / `no` / `unknown` — was the old object's storage freed against the user's quota? (only meaningful when `replaces_handle` was supplied)

Constraints:
- `len(payload)` must be within `[min_chunk_bytes, max_chunk_bytes]`.
- If the plugin requires encoding (e.g. `data_clean=false`), encoding happens *inside* the plugin.
- Idempotency: same `idempotency_key` + same payload hash within the dedupe window must return the same handle and the same `prior_handle_state`.
- A plugin that declares `update_in_place=true` SHOULD return `overwritten` whenever feasible. A plugin that declares `objects_are_immutable=true` always returns a new handle and reports `prior_handle_state ∈ {removed, tombstoned, abandoned, unknown}`.

Errors: `quota_exceeded`, `rate_limited`, `auth_failure`, `unsupported_size`, `network_error`, `provider_error` (with retryable flag).

#### `get(handle, range?) → GetResult`

Input:
- `handle`: opaque bytes from a prior `put`
- `range`: optional `[start, end)` byte range (only if `supports_range_reads`)

Output:
- `payload`: ciphertext bytes
- `etag` or content hash (optional, used by host for integrity check)

Errors: `not_found`, `auth_failure`, `rate_limited`, `corrupted` (host treats as data-loss event), `network_error`.

#### `peek(handle) → PeekResult`

Input: `handle`.
Output:
- `exists`: bool
- `size_bytes`: integer
- `last_modified_at`: timestamp
- `etag` (optional)

Crucially: peek must not transfer the body. It must be cheap.

Errors: `not_found`, `auth_failure`.

#### `delete(handle) → DeleteResult`

Input: `handle`.

Output (`DeleteResult`):
- `outcome`:
  - `removed` — bytes physically gone, irrecoverable from this backend
  - `tombstoned` — backend has scheduled deletion; bytes still recoverable until `tombstone_clears_at`
  - `abandoned` — call returned successfully *for our purposes* (host should forget the handle), but the bytes remain on the backend; nothing more we can do
  - `not_found` — handle did not exist
  - `not_supported` — plugin's backend offers no deletion at all
- `acknowledged_at`: timestamp
- `tombstone_clears_at`: optional timestamp (only with `tombstoned`)
- `quota_reclaimed`: `yes` / `no` / `unknown`
- `cached_elsewhere_risk`: `low` / `medium` / `high` — how likely the bytes survive in third-party caches (Imgur thumbnails, search engine snapshots, archive.org crawls); informational

A plugin that declares `supports_delete=false` always returns `outcome=not_supported`. A plugin that declares `delete_reclaims_quota=true` is committing to `quota_reclaimed=yes` on `removed`. A plugin that returns `abandoned` is honestly admitting the backend doesn't honor delete (e.g., archive.org, public pastebins, immutable logs); the host will register a *shadow shard* and rely on crypto-shred for privacy.

Errors (distinct from outcomes above): `auth_failure`, `rate_limited`, `network_error`, `provider_error`.

### 5.3 Role: `metadata_vault`

In addition to `health`, `put`, `get`, `peek`, `delete`:

#### `list(prefix, limit, page_token?) → ListResult`

Input:
- `prefix`: namespace prefix (e.g. `snapshots/`, `wal/`)
- `limit`: max entries
- `page_token`: optional pagination cursor

Output:
- `entries`: list of `{name, size, last_modified, etag}`
- `next_page_token`: optional

#### `cas_write(name, payload, expected_etag?) → CasResult`

Compare-and-swap write. Used for the lease file and the snapshot pointer.

Input:
- `name`: stable string key (e.g. `lease.json`, `snapshot.current`)
- `payload`: bytes
- `expected_etag`: previous etag the writer expects to overwrite, or null for "create only"

Output:
- `outcome`: `applied` / `precondition_failed` / `not_supported`
- `new_etag`: updated etag if applied

If the provider does not support CAS, the plugin declares `supports_cas=false` and the role `metadata_vault` is not eligible (the host falls back to other vault providers).

---

## 6. Capability Flags

Each capability is a boolean (or small enum) declared in the manifest. The placement engine and the host runtime route work only to plugins whose capabilities match the request.

### 6.1 Sizing
- `min_chunk_bytes`: smallest accepted payload
- `max_chunk_bytes`: largest accepted payload

### 6.2 Read Patterns
- `supports_range_reads`: can fetch a sub-range of a stored object
- `range_read_min_bytes` / `range_read_alignment`: granularity hints
- `supports_streaming_get`: get can return a stream rather than a buffer

### 6.3 Write Patterns
- `supports_streaming_put`: put accepts a stream
- `supports_cas`: compare-and-swap on a named object (required for `metadata_vault` role)
- `supports_versioning`: provider keeps prior versions

### 6.4 Update Behaviour (when `put` carries `replaces_handle`)
- `update_in_place`: bool — when given an existing handle, the plugin can overwrite at that handle (returns `prior_handle_state=overwritten`, `handle_changed=false`).
- `objects_are_immutable`: bool — once written, cannot be modified at all; updates always mint a new handle.
- `update_leaves_old_handle`: enum — when the handle changes, what happens to the old object by default?
  - `removed` — plugin deletes the old object after the new one is committed (best case)
  - `tombstoned` — old object is queued for backend-side removal
  - `abandoned` — old object stays forever (e.g., archive.org, immutable logs)
  - `unknown` — plugin cannot determine

### 6.5 Deletion
- `supports_delete`: delete operation has any effect (false → always `outcome=not_supported`)
- `delete_eventually_consistent`: delete may take time to propagate; reads may still succeed briefly
- `delete_reclaims_quota`: deleting an object frees quota (some backends count abandoned objects forever)
- `delete_irreversible`: once deleted, cannot be recovered (true for most; false for versioned object stores)
- `delete_propagation_seconds`: typical lag until "really gone" (`null` if never)
- `cached_elsewhere_risk`: `low` / `medium` / `high` — likelihood that third-party caches (search engines, archive.org, hot-linkers) retain bytes after delete

### 6.5 Encoding
- `data_clean`: accepts arbitrary bytes
- `encoding_kind`: if not data-clean, one of `none` / `base64` / `base85` / `png-stego` / `video-frames` / `text-chains` / etc.
- `encoding_overhead_pct`: typical inflation from encoding

### 6.6 Reliability
- `durability_class`: `ephemeral` / `weekly` / `yearly` / `archival`
- `expected_uptime_pct`: best-effort estimate
- `geographic_region` (optional): provider region code

### 6.7 Throughput / Cost
- `requires_throttle`: hard rate limit applies
- `concurrency_limit`: max simultaneous in-flight ops
- `cost_class`: `free_tier` / `paid_metered` / `paid_flat`

### 6.8 Visibility & Legal
- `public_visibility`: stored content is publicly enumerable / indexable
- `legal_class`: green / yellow / red

### 6.9 Conformance Rule

A plugin **must not exceed** what its capabilities declare. If a capability is `supports_delete=false`, the plugin must not delete (even if it could). The host plans around declarations; surprising the host is worse than missing a feature.

---

## 7. Sandbox & Security Model

### 7.1 Plugin Categories

| Category | Loader | Trust | Examples |
|---|---|---|---|
| First-party | In-process, signed by project | Full | Drive, OneDrive, Mega (shipped in core) |
| Third-party | WASM sandbox | Restricted | Community plugins |

### 7.2 What a Sandboxed Plugin May Do

- Compute, read its own bundled assets, hold internal state.
- Make HTTP/HTTPS requests via the host-provided `fetch` capability — restricted to manifest-declared `network_hosts`.
- Read its own settings and a credentials handle (opaque) provided at init.
- Emit structured log records to the host.
- Sleep, get monotonic time, get bounded random bytes.

### 7.3 What a Sandboxed Plugin May *Not* Do

- Open arbitrary network sockets.
- Read or write the user's filesystem.
- Read or unwrap the user's master key, file keys, chunk keys.
- See plaintext of any user file.
- Spawn processes or threads beyond the runtime's worker pool.
- Persist state outside the host-provided settings store.
- Phone home to any host outside `network_hosts`.

### 7.4 Credentials Handle

Plugins do **not** receive raw OAuth tokens or API keys. Instead, they receive an opaque `credentials_handle` and use a host-provided `signed_fetch` capability:

```
plugin → host: signed_fetch(credentials_handle, http_request)
host:   - looks up credentials by handle
        - injects appropriate auth (Bearer header, signed query, etc.)
        - issues request through the network capability
        - returns response to plugin
plugin:  observes only the response body
```

This means a malicious or compromised plugin cannot exfiltrate the user's OAuth token to its allowlisted host; it can only invoke the provider's API as the user, within the request shape the host permits. (For first-party in-process plugins, the same handle pattern is used for symmetry, even though the technical isolation is weaker.)

### 7.5 Memory Limits

The sandbox enforces:
- Maximum heap size (default 256 MiB, plugin-declarable up to 1 GiB).
- Maximum execution time per request (default 60 s).
- Maximum concurrent in-flight requests per plugin instance.

A plugin that exceeds limits is terminated and its current call returns `plugin_resource_error` (retryable=false from the plugin, but the host may retry on a new instance).

---

## 8. Authentication Flow

```
Initial authorization (one-time, user-driven):
  ┌──────┐                 ┌──────┐                 ┌──────────┐
  │ User │                 │ Host │                 │ Provider │
  │  UX  │                 │      │                 │          │
  └──┬───┘                 └──┬───┘                 └────┬─────┘
     │ "add Drive"            │                          │
     ├───────────────────────►│                          │
     │                        │ open browser / OAuth     │
     │                        │ flow (host runs this,    │
     │                        │ NOT the plugin)          │
     │◄───────────────────────┤                          │
     │ user signs in          │                          │
     │ ────────────────────────────────────────────────► │
     │ token issued                                      │
     │ ◄──────────────────────────────────────────────── │
     │                        │ host receives token      │
     │                        │ stores in OS secure      │
     │                        │ storage, mints credentials│
     │                        │ handle                   │
     │                        │                          │
     │                        │ init plugin with handle  │
     │                        │                          │
Plugin operates:
     │                        │ signed_fetch(handle,req) │
     │                        │ host injects Bearer      │
     │                        │ ─────────────────────────►
     │                        │                          │
```

The host runs OAuth flows itself (same code regardless of which provider). The plugin only declares which auth kinds it accepts.

---

## 9. Error Taxonomy

Every operation can return a structured error. The host treats errors uniformly based on the standard codes below; plugins should map provider-specific errors to these.

| Code | Retryable? | Semantics |
|---|---|---|
| `ok` | n/a | Success |
| `not_found` | no | Object doesn't exist |
| `auth_failure` | maybe (after re-auth) | Token expired / revoked |
| `permission_denied` | no | Authenticated but not allowed |
| `quota_exceeded` | no (until quota refresh) | Storage quota full |
| `rate_limited` | yes (after `retry_after`) | API throttled |
| `unsupported_size` | no | Payload outside size bounds |
| `unsupported_operation` | no | Capability not declared |
| `precondition_failed` | no | CAS expectation mismatch |
| `corrupted` | no | Data integrity check failed; host treats as loss |
| `network_error` | yes | Transport failure |
| `provider_error` | maybe | Generic remote failure (must include retryable flag) |
| `plugin_resource_error` | yes (on new instance) | Sandbox limits exceeded |
| `internal_error` | maybe | Plugin bug |

Errors include:
- `code`: from the table
- `retry_after_ms`: optional
- `provider_code`: original provider code (for diagnostics)
- `note`: short human string
- `correlation_id`: optional

---

## 10. Rate Limiting & Backpressure

### 10.1 Plugin-Reported Rate Limits

Plugins should track their provider's rate limit state and surface it via `health()`. The placement engine consults this when scheduling work.

If a plugin returns `rate_limited` with a `retry_after_ms`, the host backs off by exactly that amount before retrying that specific operation against that plugin.

### 10.2 Concurrency Limits

A plugin declares `concurrency_limit` as a capability. The host serializes requests beyond this limit into a per-plugin queue. The plugin does not need to internally throttle.

### 10.3 Quota Management

The plugin reports `quota_used_bytes` and `quota_total_bytes` via health. The placement engine refuses to send new chunks to a plugin that would exceed quota. There is no enforcement on the plugin side; trust the report.

---

## 11. Configuration & Settings

### 11.1 Settings Sources

Settings reach the plugin via `init`. They come from three layers, merged:
1. Manifest defaults.
2. User-edited settings stored in vault metadata.
3. Per-instance overrides (if the user runs multiple instances of the same plugin, e.g. two Drive accounts).

### 11.2 Allowed Setting Types

- `string`, `int`, `bool`, `enum`, `duration`, `size`.
- Arrays and maps of the above.
- No code, no callbacks, no opaque blobs (settings are user-readable).

### 11.3 Setting Change Notifications

The host calls `settings_changed` when settings are updated. The plugin must apply changes within 5 s or report `configuration_error`.

---

## 12. Logging & Diagnostics

### 12.1 Log Records

Plugins emit structured log records:

| Field | Type |
|---|---|
| `level` | `debug` / `info` / `warn` / `error` |
| `message` | string |
| `attrs` | map of string → primitive |
| `op` | optional operation name |
| `correlation_id` | optional |
| `error_code` | optional |

Logs go to the host. The host writes them to the local crash/log directory, gated by the user's verbosity setting.

### 12.2 What Plugins Must Not Log

- Plaintext payload bytes (the plugin should never see them anyway).
- Credentials, tokens, or any part of a credentials handle's content.
- User-identifying personal data beyond what's strictly needed for diagnostics.

### 12.3 Crash Reporting

There is no crash reporting endpoint. The host writes crash dumps locally. The user may choose to manually share them. Plugins may not include any code that uploads diagnostics anywhere.

---

## 13. ABI Versioning

### 13.1 Version Negotiation at Load

```
host:    "I support SDK v1.0–v1.4"
plugin:  manifest declares sdk_version: 1.2
host:    plugin loads against v1.2 stub; v1.3+ features unavailable
```

A plugin built against SDK v1.x continues to load on hosts supporting any v1.y where y ≥ x, by feature-detection.

### 13.2 Capability Additions

New capabilities introduced in later minor versions are advisory: the host treats unknown capabilities from a newer plugin as "not declared" and routes work accordingly.

### 13.3 Breaking Changes

Breaking changes go to SDK v2. Hosts may load both v1 and v2 plugins simultaneously; users migrate plugins individually.

---

## 14. Distribution & Signing

### 14.1 First-Party Plugins

- Built into the core release.
- Signed with the project release key.
- Loaded in-process for performance.

### 14.2 Third-Party Plugins

- Distributed as WASM modules + manifest in a single `.osplugin` file (zip).
- Signed by the plugin author with their own key.
- The user installs by URL or file; on install the host shows:
  - Plugin name, author, version, SDK version
  - `legal_class` and matching policy warning
  - `network_hosts` allowlist
  - Capabilities declared
  - Author signature fingerprint
- The user double-confirms before the plugin loads.

### 14.3 Reputation & Discovery

There is no central plugin registry the project operates. The community may maintain a static signed list of vetted plugins (e.g., a Git repository), but the host treats it as just another source the user may consult.

---

## 15. Conformance Tests

A plugin claiming SDK v1 must pass the following test suite (provided by the project):

### 15.1 Round-trip Tests
- put a 1 KiB ciphertext-shaped buffer → get → byte-equal
- put / peek (size + mtime accurate)
- put / delete / peek (returns `not_found`)
- put / get with range (if `supports_range_reads`)

### 15.2 Idempotency Tests
- put with same `idempotency_key` twice within window → same handle
- put with same `idempotency_key` but different payload → must error or return original

### 15.3 Capability Honesty Tests
- All declared capabilities tested against actual behavior
- Undeclared operations return `unsupported_operation`

### 15.4 Failure Mode Tests
- Provider unreachable → `network_error` with retryable=true
- Auth revoked mid-test → `auth_failure`
- Quota exceeded → `quota_exceeded`

### 15.5 Sandbox Tests (third-party only)
- Attempted out-of-allowlist network access → blocked by host
- Attempted FS access → trap
- Attempted memory beyond limit → terminated cleanly

### 15.6 Concurrency Tests
- N parallel ops where N > `concurrency_limit` → host queues; plugin observes only N at once
- Pause / resume mid-flight → in-flight drains, queued ops resume after

### 15.7 Lifecycle Tests
- init / ready / shutdown sequence respects state machine
- Repeated init without shutdown → error

A plugin author runs the test suite locally before publishing. The host can re-run it on first load to verify (optional, user-controlled).

---

## 16. Plugin Author Guide (best practices)

### 16.1 Honest Capability Declarations

Declare exactly what your plugin does, no more. The placement engine relies on you. If your provider's `delete` is asynchronous and may leave content for hours, declare `delete_eventually_consistent=true`.

### 16.2 Defensive Provider Calls

Providers misbehave. Always:
- Validate response status before parsing body.
- Handle 5xx with retry + jitter, capped retries.
- Treat any `auth_failure` as terminal until re-init.
- Clamp request sizes to declared limits before transmission.

### 16.3 Idempotency

Use the host-supplied `idempotency_key` as your dedup token. Most providers support a request idempotency header; map to it. Hold a small in-memory cache of recent (key → handle) pairs for retries.

### 16.4 Surface, Don't Hide

If the provider returns rate limit info (e.g., `Retry-After` header), pass it up. If quota is approaching, surface it. The host plans better with more information.

### 16.5 No Magic in Storage

If your provider needs a particular storage format (e.g., one chunk per file vs. concatenated container), document it in the manifest's `note` field. Future migrations will need to know.

### 16.6 Testability

Make your plugin work against a local mock of your provider (e.g., a local HTTP server). The conformance suite should run without network.

### 16.7 Don't Implement Encryption

The host encrypts before calling you. Implementing your own crypto is a security bug. The only "encoding" you should do is format conversion (binary → image/video/text) for hostile backends, and that's not encryption.

---

## 17. Glossary

- **Plugin**: A loadable module implementing this contract.
- **Role**: A declared kind of work the plugin supports (`chunk_backend`, `metadata_vault`).
- **Capability**: A declared optional feature of a plugin (e.g., `supports_range_reads`).
- **Handle**: An opaque, plugin-private reference to a stored object.
- **Credentials handle**: An opaque reference the host gives the plugin to identify which user credentials to use, without revealing them.
- **Idempotency key**: A short host-supplied string the plugin uses to dedupe retries.
- **CAS**: Compare-and-swap; atomic conditional write.
- **Sandbox**: The WASM execution environment for third-party plugins.
- **Allowlist**: The list of network hosts a plugin may contact.
- **Conformance suite**: The test set a plugin must pass before being considered SDK v1 compliant.
