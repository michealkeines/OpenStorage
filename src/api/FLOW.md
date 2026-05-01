# api/ — Local API Server

**Layer**: L5.
**Role**: implements `ApiServerContract` ([`ABSTRACTIONS.md`](../../ABSTRACTIONS.md) §5.12). Serves the local HTTP/2 API to frontends. Auth, routing, streaming, events. Owns the event bus for fanout.

## What lives here

- HTTP/2 server bound to UDS (POSIX) / named pipe (Windows) / TLS-localhost or mTLS LAN (self-hosted).
- Auth: pairing flow + bearer-token check on every request.
- Route table: maps `(method, path)` to handlers; handlers translate to L4 service calls.
- Streaming: chunked uploads/downloads with backpressure.
- Idempotency cache: keyed by `Idempotency-Key`; 24-hour retention.
- Event bus: WebSocket subprotocol, fanout to subscribed frontends.
- Capability advertisement at `/v1/capabilities`.

## Boundaries

- Depends on `types/`, `entities/`, every L4 service.
- Plus `events/` which is technically the event bus implementation, structurally close.

## Flow — Bearer Token Pairing

```
   first launch:
     engine generates pairing secret on disk (mode 0600)
     frontend prompts user for the secret
                          │
                          ▼
   frontend → POST /v1/auth/pair { secret }
                          │
                          ▼
   api/ verifies secret matches on-disk one; mints bearer token
   pairing secret invalidated after first use
                          │
                          ▼
   frontend receives bearer token; uses on every subsequent request
```

## Flow — Request Handling (file PUT example)

```
   frontend → PUT /v1/vaults/{v}/files/{path}
              Authorization: Bearer ...
              Idempotency-Key: ...
              Transfer-Encoding: chunked
                          │
                          ▼
   api/.authenticate → AuthSubject
   api/.route → handler "put_file"
                          │
                          ▼
   handler:
     check idempotency cache; if cached, return prior result
     vfs/.open(path, write_mode) → FileHandle
     stream request body chunks → vfs/.write
     vfs/.close
                          │
                          ▼
   build response with X-OpenStorage-* headers
                          │
                          ▼
   record idempotency cache entry
   return 201 + JSON
```

## Flow — Streaming GET

```
   frontend → GET /v1/vaults/{v}/files/{path}
                          │
                          ▼
   api/ → vfs/.open(read) → vfs/.read returns stream
                          │
                          ▼
   api/ pipes the stream to response body
   HTTP/2 flow control gives backpressure
                          │
                          ▼
   on first verify-fail during read: chunk/ enqueues repair (side effect);
   the stream still completes from K healthy shards
```

## Flow — Event Subscription

```
   frontend → GET /v1/events  (Upgrade: websocket)
                          │
                          ▼
   api/.upgrade → WebSocket connection
   frontend sends { subscribe: [...] } with filters
                          │
                          ▼
   events/ subscribes the connection to matching events
                          │
                          ▼
   any L4 service emits an event:
     events/.publish(event) → fanned to all matching subscribers
                          │
                          ▼
   frontend receives JSON frames
```

## Inputs / Outputs

- Inputs: HTTP requests, WebSocket subscriptions.
- Outputs: HTTP responses, event frames.
- Side: idempotency cache mutations; auth token lifecycle.

## Invariants this module preserves

- Local-only binding: never accessible to other hosts on the public internet (UDS / loopback / authenticated LAN only).
- Auth on every request: no anonymous access, even on UDS.
- Plaintext content traversing the API stays on the user's machine (or their private network in self-hosted mode).

## Implementation notes

- Use `axum` or `hyper` for the HTTP/2 server.
- WebSocket subprotocol: `openstorage-events.v1`; renegotiated on major version.
- Idempotency cache is a small LSM column family; sized for 24h × peak request rate.
- Request bodies are streamed end-to-end; never buffered to a file by `api/`.
- Tokens are HMAC-stamped; revocation on the engine side invalidates them immediately (a token list lives in metadata).
- Pairing: secret regeneration on demand via admin CLI; only valid on a single host (UDS bound to local user).

## Tests

- Pairing round-trip: pair, use token, revoke, subsequent use rejected.
- Idempotency: same Idempotency-Key on retry returns cached response without re-running handler.
- Streaming: large upload in chunked mode succeeds without buffering full body.
- Event fanout: one publish reaches multiple subscribers; subscribers with filters get only matching events.
- Concurrent frontends: two CLI sessions can both subscribe and operate independently.
