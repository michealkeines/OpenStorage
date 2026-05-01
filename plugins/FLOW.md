# plugins/ — First-Party Plugin Implementations

**Layer**: L0 (external from the engine's perspective; loaded by L1 plugin host).
**Role**: concrete plugin implementations shipped with the project. Each plugin satisfies the contract in [`../PLUGIN_SDK.md`](../PLUGIN_SDK.md) and is loaded by [`../src/plugin_host/`](../src/plugin_host/FLOW.md).

## Layout

```
plugins/
├ org.openstorage.drive/             ← Google Drive
├ org.openstorage.onedrive/          ← Microsoft OneDrive
├ org.openstorage.dropbox/           ← Dropbox
├ org.openstorage.mega/              ← MEGA
├ org.openstorage.storj/             ← Storj
├ org.openstorage.s3compat/          ← S3-compatible (B2, Wasabi, R2, …)
├ org.openstorage.webdav/            ← WebDAV (NAS, etc.)
└ org.openstorage.localdir/          ← local directory / SFTP
```

Each plugin is its own crate with:
- `manifest.toml` — declared identifiers, capabilities, network_hosts, legal_class.
- `src/lib.rs` — implementation of the contract.
- `tests/conformance.rs` — runs the project conformance suite.
- `README.md` — backend-specific quirks (rate limits, OAuth scopes, etc.).

## What each plugin does

Each plugin implements the five operations:

| Op | Concrete behaviour (typical) |
|---|---|
| `put` | HTTP POST/PUT to the provider with auth injected; honors `replaces_handle` by attempting in-place update or delete-after-write |
| `get` | HTTP GET, possibly with Range header for `supports_range_reads` |
| `peek` | HTTP HEAD — never transfers body |
| `delete` | HTTP DELETE; reports honest `outcome` (some providers tombstone, some abandon) |
| `health` | Returns rate-limit budget from response headers + last observed quota |

For metadata-vault role, also `list` and `cas_write` (CAS via If-Match etag header).

## Boundaries

- Each plugin is loaded as a separate compilation unit.
- First-party plugins compile to native code (in-process, fast); third-party plugins compile to WASM (sandboxed).
- Plugins **never** import from the engine modules (they speak the SDK contract, not internal types).
- Plugins **never** see plaintext or keys.

## Invariants each plugin must preserve

- Honest capability declarations (per [`../PLUGIN_SDK.md`](../PLUGIN_SDK.md) §16.1).
- Idempotency by `idempotency_key` for at least 1 hour.
- Honest `health()` reporting; never lie about quota or rate-limit.
- Honest `delete()` outcomes; if the backend doesn't physically remove, return `Abandoned` or `NotSupported`, never `Removed`.

## Test surface

- Each plugin runs the project's conformance suite against:
  - A real account (gated tests; require credentials).
  - A local mock server simulating the provider's API (always-on tests).
- Property tests for idempotency.
- Round-trip tests for every capability declared.

## Adding a new plugin

1. Copy `org.openstorage.template/` (to be created).
2. Edit manifest with new `plugin_id`, capabilities, network_hosts.
3. Implement the five operations against the new backend.
4. Run conformance suite locally; fix until green.
5. Submit upstream OR distribute as a community third-party WASM plugin.
