# events/ — Event Bus

**Layer**: L3 (revised — was L5 in earlier drafts).
**Role**: in-process pub/sub event bus. A primitive, not a service. Fans out events from any module to subscribed frontends (via `api/`) and to internal observers.

> **Why L3, not L5**: events/ is a pure pub/sub primitive with no orchestration. L4 services emit; L5 (api/) consumes. The L5 placement was geographic. By dependency depth: events/ depends only on `types/` (L1) and `entities/` (L1), so it sits at L3 (or L2; placing at L3 alongside other primitives like `merkle/` and `bloom/`).

## What lives here

- Event types: closed enum matching [`API.md`](../../API.md) §15.2.
- Publish: any L4 module calls `events/.publish(event)`.
- Subscribe: API frontends connect via `/v1/events` WebSocket; internal observers (logs, metrics) subscribe at startup.
- Filtering by event-name pattern.
- Replay from a bounded ring buffer (so reconnecting frontends can pick up missed events).

## Boundaries

- Depends on `types/`, `entities/`.
- Used by every L4 module and `api/`.
- Not persisted to disk; lives in memory.

## Flow

```
   any module: events/.publish(event)
                          │
                          ▼
   events/ assigns monotonic event_id, current Hlc, vault_id
                          │
                          ▼
   ring buffer push (bounded size)
                          │
                          ▼
   for each subscriber matching the event's name pattern:
     deliver via subscriber's channel (WebSocket or in-process)
   
   subscriber reconnect:
     subscribe with ?since=<event_id>; bus replays from ring buffer
```

## Inputs / Outputs

- Inputs: events from anywhere.
- Outputs: event frames to subscribers.
- Side: ring buffer trimming as it fills.

## Invariants this module supports

- No persistence: events are ephemeral by design (no telemetry, no remote sink).
- At-most-once delivery within a connection; replay-from-id for reconnection windows.
- No event contains plaintext content (only metadata: paths, sizes, ids).

## Implementation notes

- Internal channels can use crossbeam or tokio mpsc.
- Ring buffer size is configurable (default ~10K events ≈ minutes of activity).
- Fanout is non-blocking: a slow subscriber backs up its own channel, doesn't slow the publisher.
- Slow-subscriber policy: drop oldest events for that subscriber when its queue is full; emit a `system.error` letting it know.
- Filter syntax: glob-like (`vault.*`, `repair.*`, `chunk.replication_state_changed`). Compile filters once on subscribe.

## Tests

- Publish + subscribe + receive.
- Replay: subscribe with since=N → receives all events from id N+1 onward.
- Slow subscriber: doesn't block the bus; oldest events dropped for it; rest of subscribers unaffected.
- Filter correctness: `vault.*` matches `vault.unlocked` but not `share.received`.
