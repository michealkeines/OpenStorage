# OpenStorage

> **Your data. Your keys. Any cloud.**
>
> **From 15 GB to 1 TB — the scale where consumer plans end and your data starts.**
>
> An end-to-end-encrypted personal storage engine that turns *anyone's*
> object store into your own private filesystem.

OpenStorage stitches together cloud accounts you already have — Google Drive,
Dropbox, S3, a Raspberry Pi in a closet — into one encrypted, deduplicating,
multi-device namespace. Backends never see your filenames, your folder tree,
or a single byte of plaintext. Lose a backend, your data is still safe. Lose
your laptop, your data is still safe. Bring your own backend, your own keys,
your own redundancy. **Forever.**

```
            ┌───────────────────────────────────────┐
            │           os (CLI / FUSE / GUI)       │
            └─────────────────┬─────────────────────┘
                              │   plaintext, briefly
   ┌──────────────────────────▼─────────────────────────────┐
   │  openstorage engine                                     │
   │  ─ HKDF / Argon2id / Ed25519 / ChaCha20-Poly1305 / EC   │
   │  ─ CRDT log + HLC + signed snapshots                    │
   │  ─ chunk-level dedup + erasure coding                   │
   └────┬─────────────┬─────────────┬───────────────┬────────┘
        │ ciphertext  │ ciphertext  │ ciphertext    │ ciphertext
        ▼             ▼             ▼               ▼
   ┌────────┐    ┌─────────┐  ┌───────────┐  ┌─────────────────┐
   │ Drive  │    │ Dropbox │  │ S3 / R2   │  │ python testbench│
   │ plugin │    │ plugin  │  │ plugin    │  │ (this repo)     │
   └────────┘    └─────────┘  └───────────┘  └─────────────────┘
```

---

## What works *today*

This repository implements a working baseline of the engine end-to-end. Every
column in the table below has tests behind it; the smoke scripts under
[`scripts/`](./scripts) drive the whole system at 1 GiB scale.

| Capability | Status |
|---|---|
| Vault create / unlock / lock / destroy | ✅ working |
| AEAD-encrypted file storage (ChaCha20-Poly1305 / AES-GCM) | ✅ working |
| Argon2id master-key derivation + Ed25519 identity chain | ✅ working |
| **Inline files** (≤16 KB, in-record AEAD blob) | ✅ working |
| **Chunked files** (4 MB chunks, per-chunk derived keys) | ✅ working |
| Reed–Solomon erasure coding (`k`, `n` schemes; `(1,1)` default) | ✅ working |
| Pluggable backends via `PluginContract` | ✅ working |
| HTTP-backend plugin (talks to any compatible object store) | ✅ working |
| Local-directory plugin (filesystem-as-backend) | ✅ working |
| Streaming PUT/GET (1 GB without buffering in RAM) | ✅ working |
| HTTP API (axum) — vaults, files, status, list | ✅ working |
| CLI (`os init / upload / download / ls / lock / unlock`) | ✅ working |
| Python testbench with comments-box UI | ✅ working |
| Append-only signed WAL + HLC | ✅ working (single-device) |
| Per-vault salted Bloom filter | ✅ working |
| 32K-leaf Merkle tree for anti-entropy | ✅ working |
| CRUSH-style placement + diversity policy | ✅ working |
| 95 unit tests across 24 crates | ✅ green |

### Currently stubbed / next up

Multi-device CRDT merge, snapshot push to vault providers, live anti-entropy
reconcile, share creation + revocation, repair scheduler workers, ML-KEM
KEM (placeholder is X25519-XOR), real WASM plugin sandbox, and persistent
metadata via sled (a one-line swap from the in-memory backend). All have
shapes in code; none have prod wiring.

---

## The pitch in one paragraph

Object storage is a commodity. Encryption-at-rest from your cloud provider
protects them, not you. **OpenStorage flips the trust model:** the engine
runs on your machine, encrypts everything before any byte leaves the
process, and addresses your data by content hash so you can scatter shards
across mutually-distrusting providers. A 1 GB file goes through 256
ChaCha20-Poly1305-encrypted 4 MB chunks; lose any subset of providers and
the rest reconstruct what you need. Plugins are a thin trait — write 200
lines of Rust to add a new backend.

---

## Quick start

You'll need: Rust ≥ 1.80, Python ≥ 3.10, `curl`.

```bash
# 1. build the engine + CLI
cargo build --release --bin openstorage --bin os

# 2. start the test backend (Python; gives you a UI with a comments box)
python3 -m venv testbench/.venv
testbench/.venv/bin/pip install -q -r testbench/requirements.txt
testbench/.venv/bin/python testbench/server.py &

# 3. start the engine (registers the testbench as a chunk plugin)
TESTBENCH_URL=http://127.0.0.1:9090 ./target/release/openstorage &

# 4. drive it
./target/release/os init --passphrase hunter2
./target/release/os upload some-file.bin
./target/release/os ls
./target/release/os download some-file.bin --out /tmp/round-tripped.bin

# 5. open http://127.0.0.1:9090 in a browser to see the comments box
#    and the encrypted shards landing in the testbench
```

### One-liner end-to-end test

```bash
SIZE=$((1024 * 1024 * 1024)) ./scripts/baseline_1gb.sh   # 1 GiB through the API
SIZE=$((64  * 1024 * 1024))  ./scripts/test_cli.sh       # 64 MiB through the CLI
```

A successful run looks like this:

```
✓ uploaded 1.00 GB as /notes.bin in 9.7s (106.1 MB/s)
✓ downloaded 1.00 GB in 3.7s (274.8 MB/s)
✓ hash matches
✓ auto-unlock + download path works
   src=1876a3805…  dst=1876a3805…
```

---

## Architecture

Six layers, dependency-depth-numbered. No upward calls, no peer orchestration
loops. Backends live outside the engine binary and are reached only through
`plugin_host`.

```
L6  FRONTENDS  cli │ gui │ fuse                     ← user-facing
L5  API        axum HTTP/2 server                   ← bind, auth, route
L4  SERVICES   vfs │ vault │ sync │ recovery │
               identity │ share │ repair │
               antientropy │ lease │ plugin_host    ← orchestrate
L3  PRIMITIVES chunk │ ec │ placement │
               bloom │ merkle │ events              ← pure
L2  STORAGE    metadata │ wal │ keystore │ crypto   ← bytes/state
L1  FOUNDATION types │ entities                     ← shapes
L0  EXTERNAL   plugins/ + their backends            ← outside the engine
```

Every entity, every operation, every state transition, and every edge case
is written down in the design suite:

- [`DESIGN.md`](./DESIGN.md) — narrative design (1660 lines)
- [`ABSTRACTIONS.md`](./ABSTRACTIONS.md) — types, interfaces, state machines
- [`STATES_AND_FLOWS.md`](./STATES_AND_FLOWS.md) — exhaustive flow catalog
- [`RESILIENCE.md`](./RESILIENCE.md) — invariants and edge cases
- [`THREAT_MODEL.md`](./THREAT_MODEL.md) — adversaries and mitigations
- [`API.md`](./API.md) — REST surface
- [`PLUGIN_SDK.md`](./PLUGIN_SDK.md) — how to write a backend plugin

---

## Repository map

```
src/                ← 22 Rust crates, one per module (L1–L5)
plugins/            ← first-party plugin implementations
    http_backend/   ← talks to the testbench (or any compatible HTTP store)
testbench/          ← Python object-store with comments UI; baseline backend
cli/                ← `os` CLI (clap + reqwest)
app/                ← `openstorage` engine binary
scripts/            ← baseline_1gb.sh, test_cli.sh
*.md                ← design docs (read in order: DESIGN → ABSTRACTIONS → STATES_AND_FLOWS)
```

---

## Build and test

```bash
cargo build --release         # engine + CLI + plugins
cargo test --workspace        # 95 tests across 24 crates
./scripts/baseline_1gb.sh     # full system 1 GiB round-trip
./scripts/test_cli.sh         # full CLI round-trip
```

---

## Design principles (and why they matter to you)

1. **You own the keys.** A plaintext byte never crosses the engine boundary.
2. **You own the trust topology.** Diversity rules force shards across
   distinct correlation groups (no two shards on the same operator) so
   no single provider revoke can hold your data hostage.
3. **You own the format.** Every persisted record has a `format_version`;
   migrations are forward-only and online; nothing is locked to a vendor.
4. **No silent leaks.** Every orphaned ciphertext object gets a `Shadow`
   record so your residual report is honest about what's still floating.
5. **Eventual consistency, no shared coordinator.** HLC + signed CRDT WAL
   means two devices can write while offline and converge on reconnect
   without a server in between.

---

## License

Apache-2.0. See [`LICENSE`](./LICENSE) (TBD).

---

*OpenStorage is a personal-data project — built so I can sleep at night
knowing my files survive both me and the providers I rely on.*
