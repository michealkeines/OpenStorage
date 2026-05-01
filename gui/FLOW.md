# gui/ — Native Desktop Application

**Layer**: L6.
**Role**: a native graphical frontend for desktop platforms (macOS, Windows, Linux). Consumes the API; does not embed the engine in v1 (engine runs as a sibling process or daemon).

## What lives here

- Native windowing (egui / iced / Tauri / GPUI — decision pending).
- Vault browser: directory tree, file list, drag-and-drop import.
- Provider configuration: OAuth flows, plugin install reviews.
- Replication-health dashboard: per-vault summary, live updates from `chunk.replication_state_changed`.
- Repair queue inspector.
- Capacity planner: "you have 240 GB usable; projected full in 47 days."
- Share management UI: create share, copy share blob, view inbox, fingerprint comparison flow.
- Recovery configuration UI: explicit warnings, share generation.
- Event subscription: live state updates without polling.

## Boundaries

- Depends only on the API contract.
- Installs the engine binary as a sibling process on first run; manages its lifecycle (launch, supervise, restart on crash, shutdown on app quit).
- For self-hosted mode: a setting points to an mTLS-protected daemon URL; same UX otherwise.

## Flow — Application Launch

```
   user opens the app
                          │
                          ▼
   if engine binary exists locally:
     spawn engine as child process (UDS bound to ~/.openstorage/api.sock)
   else:
     prompt user to install or configure self-hosted target
                          │
                          ▼
   read paired token from secure storage (Keychain / DPAPI)
                          │
                          ▼
   subscribe to event stream
   load capabilities → enable/disable UI features
                          │
                          ▼
   present vault list; user picks one to unlock
```

## Flow — File Operation

```
   user drags photo.jpg into a folder in the vault browser
                          │
                          ▼
   PUT /v1/vaults/{v}/files/{path}  with stream
                          │
                          ▼
   show progress bar driven by file.write.progress events
                          │
                          ▼
   on 201: show "uploaded; replicating across N providers" with live counter
   on chunk.replication_state_changed → "fully replicated" (subtle, optional toast)
```

## Flow — Plugin Install Review

```
   user clicks "Add Plugin" → enters URL or picks file
                          │
                          ▼
   POST /v1/plugins/install
                          │
                          ▼
   manifest review screen:
     plugin name, author signature fingerprint
     legal class (with warning for yellow / red)
     network_hosts allowlist
     declared capabilities
                          │
                          ▼
   user must explicitly confirm; double-confirm for red
                          │
                          ▼
   POST /v1/plugins/install/{install_id}/confirm
```

## Flow — Share Creation

```
   user right-clicks a file → Share
                          │
                          ▼
   pick recipient from peer list (with verified fingerprint badge)
                          │
                          ▼
   POST /v1/vaults/{v}/shares
                          │
                          ▼
   on 201: show share_blob as QR code + copyable text
                          │
                          ▼
   user transmits OOB (mail, Signal, paper)
```

## Implementation notes

- Use `Tauri` (web UI) or `egui` (Rust native) — Tauri offers richer UI; egui is simpler and avoids browser WebView.
- Decision will be driven by team skill / target platforms; not blocking for v1 design.
- iOS/Android are separate frontends with platform-native code; not part of this directory.
- Honor the API anti-patterns: never cache passphrase or master key; never persist plaintext file content beyond explicit save; always show fingerprint comparison clearly.

## Test surface

- UI snapshot tests for major screens.
- End-to-end tests against a real local engine.
- Manual fingerprint-comparison UX testing (this is security-critical UX).
