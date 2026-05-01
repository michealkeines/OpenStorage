# cli/ — Command-Line Frontend

**Layer**: L6.
**Role**: a frontend that consumes [`../API.md`](../API.md) over UDS / TLS-localhost. The simplest possible OpenStorage UX surface.

## What lives here

- Argument parsing.
- Command dispatch: each command maps to one or two API calls.
- Streaming I/O: stdin → PUT, GET → stdout.
- Token storage: reads/writes a paired bearer token at `~/.openstorage/cli.token` (mode 0600).
- Output formatting: human-readable by default; `--json` for machine consumption.

## Boundaries

- Depends only on the API contract. No engine internals; no shared crate with the engine beyond a thin API client library.
- Speaks the same API as every other frontend; no privileged path.

## Flow — Typical Command

```
   user: openstorage put /local/photo.jpg /vault/photos/photo.jpg
                          │
                          ▼
   parse args → resolve vault id → load token from ~/.openstorage/cli.token
                          │
                          ▼
   open local file as stream
                          │
                          ▼
   PUT /v1/vaults/{v}/files/photos/photo.jpg
     Authorization: Bearer ...
     Idempotency-Key: <generated UUID>
     Content-Type: image/jpeg
     body: (streamed)
                          │
                          ▼
   on 201: print "uploaded; etag=…"
   on error: print human-readable error code + message
```

## Flow — Pairing on First Run

```
   user: openstorage pair
                          │
                          ▼
   prompt for pairing secret (printed by engine on first launch)
                          │
                          ▼
   POST /v1/auth/pair { secret }
                          │
                          ▼
   store returned token at ~/.openstorage/cli.token (0600)
```

## Flow — Streaming Read

```
   user: openstorage cat /vault/photos/photo.jpg > /tmp/out.jpg
                          │
                          ▼
   GET /v1/vaults/{v}/files/photos/photo.jpg → response body stream
                          │
                          ▼
   pipe response stream → stdout
```

## Commands (initial set)

- `pair` — initial token exchange.
- `unlock`, `lock` — vault session management.
- `ls`, `stat` — directory ops.
- `put`, `get`, `cat`, `rm`, `mv` — file ops.
- `provider list/add/remove` — plugin instance config.
- `share create/list/revoke` — share management.
- `events` — tail event stream (subscribes to WebSocket).
- `system status/snapshot/scrub/repair/gc` — operational commands.
- `recovery configure/test/perform` — recovery flows.

## Implementation notes

- Use `clap` for parsing; subcommand-per-resource layout.
- `reqwest` or `hyper` for HTTP; `tokio` runtime; UDS via the platform-specific UDS feature flag.
- Always forward `Idempotency-Key` for mutating ops; generate a fresh UUID per attempt unless `--retry-key=...` is given.
- Avoid printing tokens or sensitive data on errors; print correlation IDs.
- Pretty-print event subscriptions; allow `--filter` for the WebSocket subscription filter.

## Test surface

- Each command tested against a mock engine.
- Streaming correctness with large files.
- Pairing flow: invalid secret rejected; valid secret stores token.
