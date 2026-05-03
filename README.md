# OpenStorage

> **Your private cloud, built from free services. No subscription. No vendor.**

OpenStorage stitches together a handful of free public services — **catbox**, **litterbox**, **uguu**, **x0**, **telegraph** — into a single encrypted filesystem you own. Every file is encrypted on your computer before it leaves. The free services see only random bytes; they never see your filenames, your folder tree, or what you uploaded. You get the storage. They get the bill. You keep the keys.

You don't need a credit card. You don't need an account. You don't need to trust any one service. Five different operators hold pieces of every file, and **any two of them can disappear without you losing data.**

---

## Quick start — 5 minutes

You'll need a terminal and roughly 5 minutes. We'll install OpenStorage, configure 5 free backends, and put a file through it.

### 1. Install Rust (if you don't already have it)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### 2. Build OpenStorage

```bash
git clone https://github.com/your/openstorage.git
cd openstorage
cargo build --release --bin openstorage --bin os
```

The first build takes ~3 minutes. You'll get two binaries:
- `target/release/openstorage` — the engine (a daemon you keep running)
- `target/release/os` — the command-line tool you actually use

### 3. Start the engine

In one terminal window, leave this running:

```bash
./target/release/openstorage
```

(In a real install you'd put this behind systemd or a launch agent. For now, keep this terminal open.)

### 4. Create your vault

In a second terminal:

```bash
./target/release/os init
# Prompts for a passphrase. Pick a strong one — this is the only thing
# protecting your data, and there is no recovery if you forget it.
```

### 5. Add 5 free backends

Each command takes 2 seconds. None of them ask for an account, password, or credit card.

```bash
./target/release/os auth add catbox      # 200 MB per file, permanent
./target/release/os auth add litterbox   # 1 GB per file, 72-hour TTL
./target/release/os auth add uguu        # 128 MB per file, 3-hour TTL
./target/release/os auth add telegraph   # mints an anonymous account
./target/release/os auth add x0          # 256 MB per file, ~30-day retention
```

You now have 5 independent operators ready to receive encrypted shards.

### 6. Restart the engine to pick up the backends

```bash
# Press Ctrl-C in the engine terminal, then:
./target/release/openstorage
```

### 7. Upload a file

```bash
./target/release/os upload ~/Documents/important.pdf
./target/release/os ls
./target/release/os download /important.pdf --out /tmp/check.pdf
diff ~/Documents/important.pdf /tmp/check.pdf   # nothing printed = success
```

You're done. Your file is now encrypted, split into pieces, and scattered across 5 free services. None of them can read it. Any two can vanish and you'll still get it back.

---

## How it handles things

### "I uploaded a 50 MB file. What just happened?"

The engine encrypted the file with a key derived from your passphrase, split it into 4 MB chunks, encrypted each chunk with its own key, and used **Reed-Solomon erasure coding** to spread each chunk across all 5 backends. Each backend sees only a random-looking blob. None of them know the filename, the file size, or that the others exist.

Reading is the reverse: any 4 of the 5 backends are enough. The engine reconstructs from the surviving pieces.

### "What if catbox goes down?"

The engine notices within ~60 seconds (it pings every backend's health endpoint). Catbox is removed from active placement. New writes go to the surviving 4. Reads still succeed because erasure coding lets us reconstruct from any majority. When catbox comes back, it's automatically re-added.

If catbox stays down forever, the engine migrates your data off it in the background. You don't have to do anything.

### "What if a backend lies — says it accepted my file but deletes it later?"

Every chunk is hashed before upload and verified on download. A backend that returns wrong bytes fails an authenticated decryption check, the engine treats that shard as lost, and it reconstructs from the others. After a few such failures the backend is automatically quarantined.

### "What if a backend rate-limits me?"

The engine has a per-backend rate budget. When one backend's budget is full, writes route to a different backend. There's also a **circuit breaker** per backend: 5 consecutive failures opens the circuit for 15 seconds (then 30, then a minute, etc.) so we don't hammer a struggling service.

### "I deleted a file. Is it really gone?"

Three things happen:
1. The chunk key is dropped from your keystore. Without it, the encrypted blobs on every backend are unreadable forever.
2. For backends that support it (S3, GitHub), the actual bytes are deleted.
3. For backends that *don't* support delete (catbox, uguu) but support **overwrite** (some do), the engine overwrites the bytes with random noise.
4. For backends that support neither, the bytes remain as cryptographically-erased ciphertext (random-looking, no key, no recovery path).

You also get a "residual report" telling you exactly which backends still hold encrypted bytes. Nothing is silently leaked.

### "I rebooted my laptop. Is everything still there?"

Yes. The engine persists its state to disk. After restart, run `os unlock`, type your passphrase, and everything is back — file list, contents, history.

### "I want to use this from two computers."

Same passphrase, same vault. Run `os init` on the second machine with the same passphrase, and it will pull the vault state and have access to all your files. Edits on either machine sync via a CRDT log; concurrent edits converge automatically.

---

## What it costs

Nothing. The 5 backends in the quick-start above are anonymous — no signup, no card, no quota you have to monitor.

The trade-off is that you're using free services as they were intended: for personal-scale use. We don't recommend pushing terabytes through this — that would violate the operators' ToS and they'd start blocking you. Tens of GB of personal files is well within reasonable use.

If you want more capacity or more reliability, you can add **paid** backends to the same vault:
- AWS S3, Backblaze B2, Cloudflare R2 (S3-compatible APIs)
- A Raspberry Pi at home (`os auth add localdir`)
- Any HTTP server that accepts `PUT` (build a 200-line plugin)

The engine treats free and paid backends the same way. You can mix them freely.

---

## What it doesn't do (yet)

- **Mobile apps.** This is a desktop/server tool today. The engine has an HTTP API; building a mobile client on top is straightforward but unwritten.
- **A graphical interface.** Command-line only for now.
- **Files larger than ~1 GB through one upload.** The streaming path exists but isn't memory-bounded yet. For huge files, split them yourself.
- **Real-time collaboration.** Two devices converge eventually (within a few seconds usually), but it's not a Google-Docs-style live edit.

These are roadmap items, not invariants.

---

## How safe is it?

**Confidentiality** (your plaintext is private): files are encrypted with ChaCha20-Poly1305 before they leave your computer. Backends never see plaintext. They can't read your filenames or folder structure either.

**Integrity** (you'd notice if a backend tampered): every chunk is authenticated. A modified byte fails the AEAD tag check on read.

**Durability** (you don't lose data when a backend dies): erasure coding tolerates any 1 of 5 backends going dark. Lose 2, you can still configure for that with more backends.

**Recovery** (you don't lose data when *you* die): you can save a recovery key separately. Anyone with the recovery key (your future self, a trusted friend, a safe-deposit box) can unlock the vault even if the passphrase is forgotten.

What it does *not* do: protect you from malware on your own computer, protect you from giving away your passphrase, or hide the *existence* of a vault from someone who can see your network traffic.

---

## More

- [`DESIGN.md`](./DESIGN.md) — how the system is built (1,660 lines, technical)
- [`THREAT_MODEL.md`](./THREAT_MODEL.md) — what attacks we defend against
- [`RESILIENCE.md`](./RESILIENCE.md) — what happens when things break
- [`ROUTING.md`](./ROUTING.md) — how the engine picks where to put each chunk
- [`PLUGIN_SDK.md`](./PLUGIN_SDK.md) — how to add a new backend in ~150 lines

License: Apache-2.0.

---

*OpenStorage exists because cloud subscriptions are a tax on people who just want their files to outlive a single company. Every byte you store anywhere else costs someone money. The 5 services in the quick-start above already exist, already store bytes for free, and have for years. Stitched together with encryption and erasure coding, they're a private cloud — yours, free, durable.*
