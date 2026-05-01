# plugin_host/ — Plugin Host & WASM Sandbox

**Layer**: L4 (revised — was L1 in earlier drafts).
**Role**: implements `PluginHostContract` ([`ABSTRACTIONS.md`](../../ABSTRACTIONS.md) §5.13). Loads plugins (in-process for first-party, WASM-sandboxed for third-party), runs the credentials-handle pattern, mediates `signed_fetch`, enforces capability declarations.

> **Why L4, not L1**: dependency depth places this at L4. plugin_host/ depends on `crypto/` (L2, for token wrapping), `metadata/` (L2, for credentials store), `keystore/` (L2). Its L0-facing role (talking to plugins) is geographic, not architectural — the layer rule is about depth, not picture position.

## What lives here

- Plugin loader: parse manifest, verify signature, sandbox prep.
- WASM runtime (wasmtime / wasmer) for third-party plugins.
- Capability surface for plugins: `signed_fetch`, `log`, `time` (monotonic), `random` (bounded).
- Credentials store: maps `credentials_handle` → wrapped OAuth token / API key, persisted via `metadata/`.
- Network capability: only allows requests to manifest-declared `network_hosts`.
- Per-plugin worker pool with bounded concurrency.
- Health and rate-limit tracking; surfaces to `placement/` and capacity planner.
- Lifecycle: Loaded → Init → Ready → Active / Paused → Closing → Closed.

## Boundaries

- Depends on `types/` (L1), `entities/` (L1), `crypto/` (L2, token wrap), `metadata/` (L2, credentials store), `keystore/` (L2, wrap key).
- Called by `vfs/`, `repair/`, `vault/`, `share/`, `recovery/` (peers at L4 — same-layer composition allowed).
- The only module allowed to instantiate a plugin process or WASM instance.

## Flow — Plugin Install

```
   API → POST /v1/plugins/install
                          │
                          ▼
   plugin_host/.fetch_artifact (URL or local file)
   plugin_host/.verify_signature against author's pubkey (or first-party key)
   plugin_host/.parse_manifest → PluginId, capabilities, network_hosts, legal_class
                          │
                          ▼
   surface manifest to user via API for confirmation
                          │
                          ▼
   on confirm: persist manifest, mark plugin Loaded
```

## Flow — Plugin Init (first use)

```
   plugin_host/.load(plugin_id):
     for first-party: dlopen / static link; instantiate
     for third-party: wasmtime instance with capability table
                          │
                          ▼
   plugin_host/.init(settings, credentials_handle):
     plugin runs; may issue probes via signed_fetch
     plugin returns ready or error
                          │
                          ▼
   transition Init → Ready → Active on first invocation
```

## Flow — Invoke (the hot path)

```
   any L4 service: plugin_host/.invoke(plugin_id, op, args)
                          │
                          ▼
   look up PluginInstance
   queue into per-plugin worker pool (respect concurrency_limit)
                          │
                          ▼
   execute:
     for first-party: direct in-process call
     for third-party: WASM call with arg marshalling
                          │
                          ▼
   plugin may call signed_fetch:
     plugin_host/.signed_fetch(credentials_handle, http_request):
       look up credentials, decrypt-in-memory
       inject auth header / sign request
       enforce request URL host ∈ network_hosts (else block)
       fire HTTP request
       return response body to plugin
                          │
                          ▼
   plugin returns result
   record success/failure for health tracking; update p95 latency
```

## Flow — Capability Drift Detection

```
   on plugin reload (e.g., user updates plugin):
     diff manifest.capabilities vs. last_known
     if any capability LOST that affects placed chunks:
       emit plugin.confirmation_required
       require user confirm or migrate-out
     if capability GAINED:
       hot-load; future placements may use it
     emit plugin.capability_changed
```

## Flow — Sandbox Limits

```
   per WASM call:
     enforce heap limit (default 256 MiB)
     enforce execution timeout (default 60 s)
     out-of-memory or timeout → trap → fail with plugin_resource_error
                          │
                          ▼
   network_hosts allowlist enforced at signed_fetch boundary
   any out-of-allowlist attempt → log + block
```

## Inputs / Outputs

- Inputs: install requests; invoke calls from L4; OAuth flow tokens (during initial bind).
- Outputs: plugin call results; events (`plugin.health_changed`, `plugin.capability_changed`, etc.).
- Side: token storage. **Two-stage credentials wrap** to support fresh-device OAuth before MK exists:
  - **Stage 1 (pre-unlock, fresh device)**: token wrapped under the per-device `device_wrap` key in `keystore/`. Stored in a small "pending credentials" column family in `metadata/` (the metadata KV exists locally from engine first run; what doesn't exist yet is the *vault's* MK and the encrypted vault metadata).
  - **Stage 2 (post first unlock)**: token re-wrapped under MK via `kp:cred-wrap`. Pending entry deleted; permanent entry committed via `wal/`.
  - The `credentials_handle` returned to the caller is stable across both stages — the plugin never knows which wrap form is in effect.

## Invariants this module preserves

- **I8 (plugin containment)** — sandbox + network allowlist + credentials handle pattern.
- **I1, I2** — plugins never see plaintext or keys; only ciphertext bytes.

## Implementation notes

- Use `wasmtime` for the WASM runtime; pin a specific version + audit before each minor version bump.
- The `credentials_handle` is the only thing plugins ever see for auth; the actual token is wrapped (under `device_wrap` pre-unlock, under MK post-unlock) and lives in `metadata/`. Plugins call `signed_fetch(handle, request)` and the host injects auth at the boundary.
- The handle resolution path queries the pending-credentials table first (pre-unlock case); falls back to MK-wrapped credentials post-unlock. Migration of pending → permanent happens during the first successful unlock that follows a bind.
- For first-party plugins, the same handle pattern is used for symmetry — even though the technical isolation is weaker, the API discipline is identical.
- `network_hosts` patterns are validated at install time (no `*` wildcards; specific domains or `*.subdomain.example`).
- Concurrency limit per plugin defaults to 8; a slow plugin can't tie up the whole engine.
- Rate limit tracking: each `signed_fetch` records a sliding window; the host can pre-emptively pace if a plugin is approaching limits.
- WASM ABI versioning: pin to SDK ABI v1 for the project's life of v1 major; v2 plugins load only on v2-supporting hosts.

## Tests

- Plugin install / load / invoke round-trip with a mock plugin.
- Sandbox: heap-exhaustion attempt → trap.
- Sandbox: filesystem access attempt → blocked (no FS capability granted).
- Network allowlist: request to non-allowlisted host → blocked.
- Credentials: plugin cannot read raw token; signed_fetch injects auth correctly.
- Capability drift: simulate downgrade → user-confirmation event emitted.
- First-party in-process: same contract surface, faster execution.
