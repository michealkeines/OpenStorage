# OpenStorage — Threat Model

> **Purpose**: enumerate the adversaries, attack surfaces, threats, and mitigations for the OpenStorage system as defined in [`DESIGN.md`](./DESIGN.md) and [`PLUGIN_SDK.md`](./PLUGIN_SDK.md). This document is the source of truth for "is this threat in scope?" — anything not listed here is either out of scope or an undocumented gap and must be raised.
>
> **Stability**: this document is updated whenever DESIGN.md or PLUGIN_SDK.md change in a way that alters the threat surface.

---

## 0. Reading Guide

- §1–3 establish what we're protecting and from whom.
- §4 lists adversary profiles in increasing capability.
- §5–10 walk through each attack surface and the threats specific to it.
- §11 is a **threat → mitigation matrix** — the cheat sheet for review.
- §12 is residual risks: things we cannot defend against and explicitly accept.
- §13 is severity calibration.
- §14 is open issues.

---

## 1. Scope

### 1.1 In Scope

- The OpenStorage core engine running on a user's device (or as a self-hosted daemon they own).
- The plugin framework and any plugins it loads.
- Data in flight between the engine and any backend or metadata vault.
- Data at rest in any backend, metadata vault, local cache, or local OS secure storage.
- The release/distribution channel of the core and first-party plugins.
- The user's recovery story.

### 1.2 Out of Scope

- Operating system kernel security.
- Hardware security (we trust CPU/SoC/secure-element to do their jobs).
- The user's choice of passphrase strength (we surface guidance; we do not enforce).
- Adversaries with persistent root on the user's unlocked device (game over by definition).
- Attacks on the user's own self-hosted infrastructure beyond what the daemon controls.
- Defenses against legally compelled cooperation by the user (compelled-disclosure jurisdictions).

### 1.3 Goals

We seek the following security properties, in priority order:

1. **Confidentiality of file content.** No party except the user (with key) can read plaintext.
2. **Integrity of file content.** Any tampering is detected and rejected.
3. **Authenticity of vault state.** Snapshots and leases cannot be silently forged or replayed.
4. **Availability against single-provider failure.** Loss of any one backend or vault provider does not lose data.
5. **Containment of compromised plugins.** A malicious or buggy third-party plugin cannot exfiltrate keys, plaintext, or credentials.
6. **Honest deletion.** Vault destruction renders ciphertext irrecoverable, and the user is told what residual public exposure remains.

We do **not** seek:

- Hiding the existence of a vault (no plausible deniability in v1).
- Hiding the user's identity from their own providers.
- Hiding traffic patterns at the network layer (defended only optionally via proxy).
- Surviving the user voluntarily handing over their key.

---

## 2. Assets

### 2.1 Primary Assets

| Asset | Confidentiality | Integrity | Availability |
|---|---|---|---|
| Plaintext file content | **Critical** | Critical | High |
| File names and paths | High | Critical | High |
| Master key | **Critical** | Critical | Critical |
| Recovery shares | **Critical** | Critical | Medium |
| Per-file / per-chunk keys (derived) | High (transitively from MK) | Critical | n/a |

### 2.2 Secondary Assets

| Asset | Notes |
|---|---|
| Vault metadata (chunk lists, sizes, mtimes) | Sensitive — leaks structure even if content is encrypted |
| Plugin credentials (OAuth tokens) | Sensitive; held by host, never given raw to plugins |
| Lease records | Authenticity matters (forgery → corruption) |
| Snapshot pointers | Authenticity matters (rollback → replay attack) |
| Local cache on disk | Confidentiality matters until vault locks |
| Crash dumps and logs | May leak path names, sizes, error contexts |

### 2.3 Tertiary Assets

| Asset | Notes |
|---|---|
| User's identity at each provider | Visible to provider; out of project scope to hide |
| Network metadata (which providers, how often) | Visible to ISP / passive observer |
| Released binaries | Integrity matters (supply chain) |

---

## 3. Trust Model

### 3.1 Trust Boundaries

```
┌──────────────────────────────────────────────────────────────────┐
│                    USER'S DEVICE (unlocked)                      │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  Trusted: core engine binary (signed)                      │  │
│  │  Trusted: first-party plugins (in-process, signed)         │  │
│  │  ─────────────────────────────────────────────────────────│  │
│  │  Sandboxed: third-party WASM plugins                       │  │
│  │  Trusted-with-limits: OS secure storage (Keychain/DPAPI)  │  │
│  │  Trusted: master key (in memory while unlocked)            │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
                  │ TLS, possibly via proxy/Tor              │
                  ▼                                          ▼
┌──────────────────────────────────┐  ┌────────────────────────────────┐
│   UNTRUSTED: backend providers   │  │   UNTRUSTED: metadata vaults   │
│   (see ciphertext only)          │  │   (see ciphertext + structure) │
└──────────────────────────────────┘  └────────────────────────────────┘
```

### 3.2 What Each Component Sees

| Component | Plaintext? | Master key? | Per-chunk key? | Credentials? | Ciphertext? |
|---|---|---|---|---|---|
| Core engine | ✓ | ✓ | ✓ | ✓ | ✓ |
| First-party plugin (in-process) | ✗ | ✗ | ✗ | handle only | ✓ |
| Third-party plugin (WASM) | ✗ | ✗ | ✗ | handle only | ✓ |
| Backend provider | ✗ | ✗ | ✗ | OAuth grant only | ✓ (their own shards) |
| Metadata vault provider | ✗ | ✗ | ✗ | OAuth grant only | ✓ (encrypted snapshots) |
| Network adversary (TLS) | ✗ | ✗ | ✗ | ✗ | partial (sizes, hosts, timing) |

### 3.3 Trust Anchors

The system's security ultimately rests on:

- The user's passphrase (or recovery materials).
- The OS secure storage on the user's device.
- The release signing key for the core and first-party plugins.
- The cryptographic primitives (AEAD, KDF, signatures, hashes).

Compromise of any of these is catastrophic. The rest of the system is designed to *not* depend on anything else.

---

## 4. Adversary Profiles

Adversaries are listed in roughly increasing capability. Each profile collects the access and motivation we assume.

### A. Honest-but-Curious Provider
- **Capability**: Reads everything stored on their service. May be required by court order to share data.
- **Motivation**: Compliance with ToS, business intelligence, advertising, legal requests.
- **Examples**: Google, Microsoft, Mega, Storj.

### B. Network Observer (Passive)
- **Capability**: Reads encrypted traffic between user and providers. Sees IPs, hostnames (via SNI/DNS), packet sizes, timing.
- **Motivation**: Surveillance, network-flow analytics, ISP profiling, censorship.
- **Examples**: ISP, coffee-shop wifi, transit ISPs, state-level passive collection.

### C. Network Adversary (Active)
- **Capability**: Same as B, plus can MITM, BGP-hijack, DNS-poison, inject packets. Cannot break TLS without certificate compromise.
- **Motivation**: Targeted compromise, censorship, traffic redirection.
- **Examples**: hostile state actor, malicious public wifi, compromised CDN.

### D. Malicious Third-Party Plugin Author
- **Capability**: Authors a plugin that the user installs. Runs inside WASM sandbox; restricted to manifest-declared `network_hosts`; cannot access keys or filesystem.
- **Motivation**: Steal data, exfiltrate credentials, abuse user's provider quota, deanonymize user.
- **Examples**: typosquat plugins, social-engineered "convenient" plugins.

### E. Compromised First-Party Plugin / Core (Supply Chain)
- **Capability**: Runs in-process with full trust. Can read keys, plaintext, anything.
- **Motivation**: Mass compromise via release channel.
- **Examples**: stolen signing key, malicious dependency, compromised maintainer machine.

### F. Local Malware
- **Capability**: Code execution on user's device, possibly elevated. Can read files the user can read; on unlocked device with vault open, can read plaintext.
- **Motivation**: Targeted compromise, ransomware, banker malware.

### G. Physical Adversary (Locked Device)
- **Capability**: Possesses the device while it is locked. May attempt cold-boot, side-channel, firmware attacks, brute-force.
- **Motivation**: Theft, forensics, customs/border seizure.

### H. Physical Adversary (Unlocked Device)
- **Capability**: Possesses the device while unlocked, with the user logged in.
- **Motivation**: Theft of opportunity, brief access.

### I. Coercive Adversary (Legal / Physical)
- **Capability**: Can compel the user to surrender passphrase or recovery materials.
- **Motivation**: Investigation, prosecution, abusive control.
- **Examples**: courts in compelled-disclosure jurisdictions, abusive partners, extortion.

### J. Banned-User Provider
- **Capability**: A provider who has banned the user, retaining their data but denying access. May be coordinated across providers under one parent (Google ban → Drive + YouTube + everything).
- **Motivation**: ToS enforcement, fraud signal, legal compliance.

### K. Future Cryptanalytic Adversary
- **Capability**: Can break a primitive that is currently considered secure.
- **Motivation**: Long-term archival decryption.
- **Examples**: cryptographically relevant quantum computer (CRQC) for asymmetric primitives; novel attack on AEAD.

---

## 5. Attack Surface — Local Device

### T-LD-1: Malware reads master key from memory while vault is unlocked
- **Adversary**: F.
- **Impact**: Total compromise — adversary decrypts everything.
- **Mitigation**: Out-of-scope (we do not defend against compromised endpoints). We minimize key residency: master key derived on demand and zeroized when locked; per-chunk keys ephemeral.
- **Residual**: If the user's device is compromised while unlocked, plaintext is exposed.

### T-LD-2: Cold-boot or DMA attack on locked device
- **Adversary**: G.
- **Impact**: Possible recovery of master key if recently unlocked.
- **Mitigation**: Master key in OS secure storage (Keychain/DPAPI/Android Keystore), which uses hardware key wrapping where available. Vault auto-locks on idle and on screen lock.
- **Residual**: Unaccelerated platforms (older Android) provide weaker isolation.

### T-LD-3: Forensic recovery of plaintext cache after deletion
- **Adversary**: G, F.
- **Impact**: Plaintext chunks the user thought were deleted are recoverable from disk.
- **Mitigation**: Plaintext read cache is stored encrypted-at-rest under a per-session key (zeroized on lock). Plaintext is never written to swap (we mark pages no-swap on platforms that allow it; on others, this is a residual).
- **Residual**: Swap on platforms without `mlock` may leak plaintext.

### T-LD-4: Shoulder-surfing or keylogger captures passphrase
- **Adversary**: F, H.
- **Impact**: Passphrase compromise → master key compromise.
- **Mitigation**: Out-of-scope. We support optional hardware-key second-factor that mitigates this case.

### T-LD-5: Multiple processes contend for vault on same device
- **Adversary**: not adversarial — accidental.
- **Impact**: Metadata corruption.
- **Mitigation**: OS file lock on the local cache directory; second instance refuses to start.

### T-LD-6: Theft of unlocked device
- **Adversary**: H.
- **Impact**: Adversary has plaintext access until user remotely revokes.
- **Mitigation**: Auto-lock on idle. Optional remote-revocation: rotate master key from another device, which crypto-shreds the previous key in the recovery manifest. Old device's local key becomes useless on next online check.
- **Residual**: Brief window of plaintext access before auto-lock or revocation.

---

## 6. Attack Surface — Network

### T-NET-1: Passive traffic analysis reveals which providers the user uses
- **Adversary**: B.
- **Impact**: Deanonymization (linking provider accounts to a single user).
- **Mitigation**: Optional per-plugin proxy or Tor. Default-off because it slows things down dramatically.
- **Residual**: Default deployment leaks provider list to the network.

### T-NET-2: Traffic analysis infers file sizes and write frequency
- **Adversary**: B.
- **Impact**: Provider correlation, behavioral profiling, presence inference.
- **Mitigation**: Fixed-size chunks default (instead of CDC) hide individual file sizes. Padding within chunks hides exact sizes. Background-traffic shaping is *not* implemented (would consume too much bandwidth for marginal gain).
- **Residual**: Aggregate traffic volume and timing remain visible.

### T-NET-3: Active MITM substitutes ciphertext or breaks connections
- **Adversary**: C.
- **Impact**: With successful TLS MITM (compromised CA, hostile-CA-on-device): provider responses can be replaced. Without TLS compromise: only DoS.
- **Mitigation**: Standard TLS with pinned CA roots (system trust store). Optionally certificate pinning for first-party providers. Provider responses are validated against expected hashes (chunk hash check after fetch); modified ciphertext fails decryption. Snapshot integrity is signed by user's identity key — tampered snapshots are rejected.
- **Residual**: Active downgrade DoS possible (attacker can block, but not corrupt undetected).

### T-NET-4: BGP / DNS hijack redirects requests
- **Adversary**: C.
- **Impact**: Same as TLS MITM if attacker also forges TLS.
- **Mitigation**: Pinned roots; certificate transparency monitoring (advisory); sanity-check unusual redirects.

---

## 7. Attack Surface — Backend Providers

### T-BE-1: Honest-but-curious provider reads stored ciphertext
- **Adversary**: A.
- **Impact**: Provider sees encrypted blobs only.
- **Mitigation**: All chunks AEAD-encrypted client-side. Provider sees ciphertext indistinguishable from random.
- **Residual**: Provider sees blob sizes, upload/download timing, and the user's identity at the provider.

### T-BE-2: Provider correlates multiple user blobs
- **Adversary**: A.
- **Impact**: Provider can map "which blobs belong to which user," and reason about access patterns. With enough timing data, may infer "this user is editing a doc now" or "this user pulled a 4 GB file at 03:14."
- **Mitigation**: Out-of-scope. Defending traffic analysis fully requires constant-rate covert channels.

### T-BE-3: Provider tampers with stored ciphertext
- **Adversary**: A.
- **Impact**: Modified blob would fail AEAD verification on retrieval.
- **Mitigation**: Per-chunk AEAD with chunk-hash AAD. Any tampering produces a verification failure; host treats as a `corrupted` shard, falls through to other replicas, repairs.
- **Residual**: Provider can perform a denial-of-availability by deleting or refusing access (handled via redundancy).

### T-BE-4: Provider rolls back to an older state
- **Adversary**: A.
- **Impact**: Reverting a snapshot to an earlier version causes the user to see "old" state, possibly losing recent writes.
- **Mitigation**: Snapshot pointers signed with user's identity key, including a monotonic version counter. Client rejects pointer with a counter ≤ what it has previously seen. The user's local cache is the authoritative version; vault is only consulted on cold start.
- **Residual**: A user who has *only* the vault (e.g., on first cold start to a new device) cannot detect rollback to an earlier state if the attacker also forged the user's identity key signature — but doing so requires breaking Ed25519 or stealing the key.

### T-BE-5: Provider bans or freezes the account
- **Adversary**: A, J.
- **Impact**: Loss of access to data on that provider.
- **Mitigation**: Erasure-coded redundancy across diverse providers. A single ban affects ≤ 1 trust-correlation group; data remains reconstructible from the others. Background scrubber notices the loss and re-places shards on healthy providers.
- **Residual**: Coordinated multi-provider ban (e.g., a state ordering all major providers to ban the user) defeats any redundancy that overlaps with that order.

### T-BE-6: Provider permanently deletes user data
- **Adversary**: A, J.
- **Impact**: Same as ban for redundancy purposes — data lost on that provider.
- **Mitigation**: Same as T-BE-5.

### T-BE-7: Subpoena or legal seizure of provider data
- **Adversary**: A, I (via legal channel).
- **Impact**: Adversary gets the user's encrypted blobs.
- **Mitigation**: Encryption is the entire protection. Legally compelled provider hand-over yields ciphertext only.
- **Residual**: Metadata about *which* user has *what* blobs at *which times* is provided.

---

## 8. Attack Surface — Metadata Vault

### T-MV-1: Vault provider reads snapshot
- **Adversary**: A (in vault role).
- **Impact**: Provider sees encrypted snapshot blobs only.
- **Mitigation**: Snapshots encrypted with snapshot key (HKDF-derived from master key).
- **Residual**: Snapshot size and update frequency are visible to provider, allowing inference of vault size and activity.

### T-MV-2: Vault provider tampers with lease file
- **Adversary**: A.
- **Impact**: Tampered lease can cause two devices to both believe they hold the lease — corrupting the WAL.
- **Mitigation**: Lease records are Ed25519-signed with a per-device key. Devices verify the holder signature; tampered leases are rejected. CAS at the provider provides write atomicity; signatures provide content authenticity.
- **Residual**: If both devices' keys are compromised, lease integrity collapses (out of scope at that point).

### T-MV-3: Vault provider rolls back snapshot pointer
- **Adversary**: A.
- **Impact**: Same as T-BE-4.
- **Mitigation**: Same — signed monotonic version counter.

### T-MV-4: Loss of all configured vault providers simultaneously
- **Adversary**: A (multiple).
- **Impact**: Cannot recover metadata on a fresh device.
- **Mitigation**: Vault replication across ≥ 2 trust-correlation groups by default. Recommended user practice: include a self-hosted vault (NAS / encrypted local mirror) as one of the replicas — completely outside provider control.
- **Residual**: A user with only one vault provider configured loses metadata if that provider fails. Default config nags the user to configure ≥ 2.

### T-MV-5: Race between two devices both attempting to write lease
- **Adversary**: not adversarial.
- **Impact**: Concurrent write corruption.
- **Mitigation**: CAS write semantics on vault provider. One device wins; the other's CAS fails and it backs off.
- **Residual**: Vault providers without CAS support cannot serve as metadata vaults — enforced via capability flag.

---

## 9. Attack Surface — Plugins

### T-PL-1: Malicious third-party plugin attempts to read master key
- **Adversary**: D.
- **Impact**: Total compromise if successful.
- **Mitigation**: WASM sandbox provides no key access — keys are not exposed to the plugin host API. The host only ever passes ciphertext to plugins.
- **Residual**: Sandbox escape via WASM runtime bug. Mitigated by using a hardened runtime with ongoing security updates.

### T-PL-2: Malicious plugin attempts to exfiltrate ciphertext / credentials to attacker host
- **Adversary**: D.
- **Impact**: Attacker collects ciphertext (which is unreadable without the key) and OAuth tokens (which are real damage — they let the attacker abuse the user's provider account).
- **Mitigation**:
  - Plugins do *not* receive raw OAuth tokens — only an opaque `credentials_handle`. The host injects auth at the `signed_fetch` boundary.
  - Plugins can only contact hosts in their declared `network_hosts` allowlist. Attempts to contact other hosts are blocked at the sandbox boundary.
  - Plugins cannot encode exfiltration into requests to allowlisted hosts in any way the host cannot inspect — but they can encode it *within* normal-looking provider requests (e.g., embed stolen data in metadata fields). This is a real residual.
- **Residual**: A plugin can theoretically exfiltrate ciphertext via covert-channel encoding within its own provider's normal API surface (e.g., uploading bytes as filenames). Ciphertext is useless without the key, but credential abuse via the user's own provider quota is possible.

### T-PL-3: Plugin lies about its capabilities
- **Adversary**: D.
- **Impact**: Host routes work that the plugin will silently fail or mishandle.
- **Mitigation**: Conformance test suite run on first load (optional, user-controlled). Plugins claiming `supports_delete=true` but silently ignoring deletes are caught by the test. Honest declaration is also enforced by code review for first-party plugins.
- **Residual**: A clever plugin can pass tests but misbehave on specific inputs in production. The redundancy and integrity checks limit blast radius.

### T-PL-4: Plugin abuses signed_fetch to attack the provider on behalf of the user
- **Adversary**: D.
- **Impact**: Plugin sends abusive requests to the provider using the user's credentials, getting the user banned.
- **Mitigation**: Host rate-limits per plugin. The user's OAuth scope (which the user grants explicitly) bounds the damage. Plugins do not get arbitrary fetch — only the request shapes the host expects (e.g., GET / PUT to specific URL templates).
- **Residual**: A plugin operating within its legitimate request shape can still abuse quota.

### T-PL-5: Compromised first-party plugin via supply chain
- **Adversary**: E.
- **Impact**: Catastrophic — first-party plugins run in-process with full trust.
- **Mitigation**: Reproducible builds, signed releases, multi-maintainer signing for releases, dependency review. Users can pin specific versions.
- **Residual**: Supply-chain attacks remain a serious threat for any signed-software model.

### T-PL-6: Typosquatting plugin masquerades as a legitimate one
- **Adversary**: D.
- **Impact**: User installs malicious plugin thinking it's the legitimate one.
- **Mitigation**: Plugin install UX shows author signature fingerprint, source URL, and (if applicable) prior install history. The community-maintained signed list (a static text file in a Git repo, not a service we operate) provides a soft authority for "is this the real one?"
- **Residual**: Users can still ignore the warnings.

---

## 10. Attack Surface — Cryptography & Recovery

### T-CR-1: Weak passphrase brute-forced
- **Adversary**: A, F, G with offline access to encrypted material.
- **Impact**: Master key recovered → total compromise.
- **Mitigation**: Argon2id KDF with profile-driven memory/time cost. UI nags the user about weak passphrases (minimum entropy meter).
- **Residual**: Users will pick weak passphrases despite warnings. Hardware-key second factor is the strong defense for users who care.

### T-CR-2: Forgotten passphrase, no recovery configured
- **Adversary**: not adversarial — user is own adversary.
- **Impact**: Total data loss.
- **Mitigation**: Recovery flows are first-class. UI strongly recommends configuring at least one recovery mode at vault creation.
- **Residual**: Users who explicitly decline recovery and forget the passphrase lose data. By design.

### T-CR-3: Loss of recovery share(s) below Shamir threshold
- **Adversary**: not adversarial.
- **Impact**: Recovery impossible if also forgot passphrase.
- **Mitigation**: User picks `(k, n)` with k < n. UI prompts user to verify share locations periodically.

### T-CR-4: Compromise of recovery share above threshold
- **Adversary**: D, F, G, I — depends on share location.
- **Impact**: Master key recovery possible without passphrase.
- **Mitigation**: User chooses share locations carefully (separate trust domains).

### T-CR-5: Compromise of hardware-key device
- **Adversary**: G, H, I.
- **Impact**: If hardware-key is the only second factor and adversary has both passphrase and the device — compromise.
- **Mitigation**: Hardware key + passphrase = two-factor. Compromise of one alone is insufficient.

### T-CR-6: Future cryptanalytic break of AEAD
- **Adversary**: K.
- **Impact**: Long-term archival ciphertext becomes readable.
- **Mitigation**: ChaCha20-Poly1305 / AES-256-GCM are conservative choices unlikely to break. Format versioning lets us migrate to a future AEAD if needed (re-encrypt during snapshot rotation). For maximum-paranoia archival, layered encryption with two independent AEAD families is supported as a power-user mode.
- **Residual**: Pre-migration ciphertext remains vulnerable to a successful future attack.

### T-CR-7: Future quantum break of asymmetric primitives
- **Adversary**: K.
- **Impact**: For v1 (Ed25519 used only for signatures on lease and snapshot pointers), an attacker who has both old vault data *and* future quantum could re-sign forged snapshot pointers — but only if they also possess access to the vault provider, and only to attack devices that haven't yet seen newer pointers. The actual chunk encryption (symmetric) is unaffected.
- **Mitigation**: Confine asymmetric use to non-confidentiality-critical paths (signing, not encrypting). Plan migration to ML-DSA (Dilithium) when needed; format versioning supports key-type switch.
- **Residual**: A determined long-haul adversary could store ciphertext + signed snapshots today to attack signatures later — but symmetric encryption is unaffected and the data remains confidential.

### T-CR-8: Algebraic recovery of CDC chunking secret
- **Adversary**: A, F, G with offline access to ciphertext shards and structural knowledge of the chunking algorithm.
- **Impact**: Recent research (Truong, "Breaking and Fixing CDC", 2024) shows the keyed CDC schemes used by Borg, Restic, Tarsnap, Bupstash, and Duplicacy can have their chunking secret recovered via the algebraic structure of the rolling hash. Once recovered, the attacker can probe content (test "is this file in this vault?") by checking whether their candidate plaintext, run through CDC with the recovered secret, produces chunk boundaries matching the observed ciphertext shard sizes. This breaks dedup-confidentiality and enables file-presence inference.
- **Mitigation**: When CDC is enabled, the engine **automatically applies the documented mitigations from Truong (2024)**:
  - **zstd compression** of file content before chunking, so chunk boundaries don't directly reveal plaintext byte patterns.
  - **Padding** every chunk to the next power-of-two within size bounds, hiding exact chunk sizes.
  - **Packing** small chunks into fixed-size containers before EC, so individual chunk size leakage is bounded.
  This combination defeats the algebraic attack. Cost: ~5–10% storage overhead.
- **Residual**: Users who explicitly disable mitigations (e.g., for benchmarking) re-expose themselves to the attack. Default-on; opt-out requires confirmation.
- **Note**: The default chunking strategy is `fixed`, not CDC. CDC is opt-in for archival workloads where dedup gain justifies the trade. Fixed-size chunks are not vulnerable to this attack.

---

## 11. Threat → Mitigation Matrix

| ID | Threat | Adversary | Impact | Primary mitigation | Residual? |
|---|---|---|---|---|---|
| T-LD-1 | Malware reads key from memory | F | Total | OS protection, key minimization | Yes — out of scope |
| T-LD-2 | Cold-boot on locked device | G | High | OS secure storage, hardware-backed keys | Some platforms |
| T-LD-3 | Forensic recovery from disk | G, F | High | Encrypted local cache, no-swap | Limited swap defense |
| T-LD-4 | Keylogger / shoulder-surfing | F, H | Total | Hardware-key second factor (opt-in) | Yes if no 2FA |
| T-LD-5 | Multi-process race | n/a | Corruption | OS file lock | None |
| T-LD-6 | Stolen unlocked device | H | High | Auto-lock + remote revocation | Brief window |
| T-NET-1 | Provider list leaked to ISP | B | Medium | Optional proxy/Tor | Default leaks |
| T-NET-2 | Traffic analysis on sizes/timing | B | Medium | Fixed chunk size + padding | Aggregate volume |
| T-NET-3 | Active TLS MITM | C | High → Low | Pinned roots + content hash check + signed snapshots | DoS only |
| T-NET-4 | BGP/DNS hijack | C | Same as MITM | Same | Same |
| T-BE-1 | Provider reads ciphertext | A | None | AEAD client-side | Sizes/timing |
| T-BE-2 | Provider correlation | A | Medium | Out of scope (TA defense) | Yes |
| T-BE-3 | Provider tampers ciphertext | A | None | AEAD verification + repair | None |
| T-BE-4 | Snapshot rollback | A | High → Low | Signed monotonic counter | Cold-start vulnerable to forged signature only |
| T-BE-5 | Provider bans account | A, J | Medium → Low | EC redundancy across trust groups | Coordinated multi-ban |
| T-BE-6 | Provider deletes data | A, J | Same as ban | Same | Same |
| T-BE-7 | Legal subpoena to provider | A, I | Low | Encryption | Metadata leaked |
| T-MV-1 | Vault reads snapshot | A | None | Snapshot encrypted | Size/timing |
| T-MV-2 | Lease tampering | A | High → None | Signed lease + CAS | None |
| T-MV-3 | Snapshot pointer rollback | A | Same as T-BE-4 | Same | Same |
| T-MV-4 | All vaults lost | A (multi) | Catastrophic | Multi-vault default | Misconfig risk |
| T-MV-5 | Lease race | n/a | Corruption | CAS | None if CAS supported |
| T-PL-1 | Plugin reads master key | D | Total | WASM sandbox + no key API | Sandbox escape |
| T-PL-2 | Plugin exfiltrates data | D | Medium | Allowlist + signed_fetch + no raw tokens | Covert channel via provider API |
| T-PL-3 | Plugin lies about caps | D | Medium | Conformance suite | Subtle behavior |
| T-PL-4 | Plugin abuses signed_fetch | D | Medium | Rate limits + scope bounding | Quota abuse |
| T-PL-5 | Supply chain on first-party | E | Catastrophic | Reproducible builds, signed releases, multi-sig | Yes — fundamental |
| T-PL-6 | Typosquat plugin | D | Same as T-PL-1/2 | UX warnings + community list | User error |
| T-CR-1 | Weak passphrase brute force | A, F, G | Total | Argon2id + UI nag + hardware-key option | User choice |
| T-CR-2 | Forgotten passphrase | n/a | Total loss | Recovery flows + UI insistence | User choice |
| T-CR-3 | Lost recovery shares < k | n/a | Total loss | Educate user | User responsibility |
| T-CR-4 | Recovery shares stolen ≥ k | D, F, G, I | Total | Storage diversity guidance | User responsibility |
| T-CR-5 | Hardware key compromised | G, H, I | Partial | 2FA: passphrase still required | Combined compromise |
| T-CR-6 | AEAD broken in future | K | Long-term archival | Format migration on rotation | Pre-migration data |
| T-CR-7 | Quantum break of Ed25519 | K | Signature forgery only | Migrate to ML-DSA | Future signed records |
| T-CR-8 | CDC chunking secret recovery (Truong 2024) | A, F, G | Medium (file-presence inference) | CDC ⇒ compression + padding + packing (auto when CDC on) | If user opts out of mitigations |

---

## 12. Residual Risks (Explicitly Accepted)

The following risks are not mitigated by this design. They are documented so users and reviewers know what they are signing up for.

1. **Compromised endpoint with vault unlocked** is total compromise. We do not defend against this and never claim to.
2. **Network metadata leakage** — which providers, when, how much — is visible by default. Defended only via opt-in proxy.
3. **User identity at each provider** is visible to that provider; this is structural and out of scope to hide.
4. **Compelled passphrase disclosure** in legally-coercive jurisdictions — no software defense. We do not implement plausible deniability in v1.
5. **Coordinated multi-provider ban** (e.g., state ordering all configured providers to ban a user) defeats redundancy that overlaps with the order.
6. **Supply chain compromise** of the project's release channel is a fundamental threat for any signed-software model. We mitigate but cannot eliminate.
7. **Sandbox escape** via WASM runtime bug is a residual we accept — mitigated by using a hardened runtime and rapid security updates.
8. **Forgotten passphrase with no recovery configured** loses the data, by design.
9. **Long-term archival ciphertext** may become readable if the AEAD is ever broken — pre-migration data is at risk.
10. **Covert-channel exfiltration from a plugin via legitimate provider API** is possible — ciphertext is useless without the key, but credential/quota abuse is real.

---

## 13. Severity Calibration

How we score impact, for prioritization:

| Severity | Definition | Examples |
|---|---|---|
| **Catastrophic** | Loss or exposure of all user data with no recovery | Master key leak, supply chain |
| **High** | Significant, possibly recoverable, exposure or loss | Provider ban without redundancy, locked device cold-boot |
| **Medium** | Limited exposure or recoverable loss | Single shard corruption, traffic analysis |
| **Low** | Confidentiality holds; minor inconvenience | DoS, rate-limit hits |

Mitigations are prioritized by (severity × likelihood × adversary capability). Catastrophic-severity mitigations are hard requirements; medium-severity items are best-effort.

---

## 14. Open Questions

1. **Should we ship a constant-rate cover-traffic mode?** Defends against fine-grained traffic analysis. Costs bandwidth. Probably opt-in only; not v1.
2. **Should we offer plausible-deniability vaults?** Genuinely hard to do well. Probably v3+.
3. **How do we handle CRQC migration UX?** When the day comes that AES-256 or Ed25519 is at risk, we need a re-encrypt-everything ceremony. Design that flow before we need it.
4. **Should we recommend specific recovery-share storage practices?** E.g., explicit guidance: "one printed share in a safe, one with a trusted family member, one in a bank deposit box." UX guidance is hard in software.
5. **How should we surface "your provider just rolled back your snapshot pointer" to a user?** False positives could be alarming; false negatives are dangerous.
6. **Should plugins be required to have a public source repository?** Strengthens trust but limits ecosystem.

---

## 15. Glossary

- **AAD**: Additional Authenticated Data; bound into AEAD tag without being encrypted.
- **AEAD**: Authenticated Encryption with Associated Data; provides confidentiality + integrity in one primitive.
- **CAS**: Compare-and-swap; atomic conditional write.
- **CRQC**: Cryptographically Relevant Quantum Computer.
- **HKDF**: HMAC-based Key Derivation Function.
- **MK**: Master Key.
- **Trust-correlation group**: Provider grouping for diversity (e.g., Microsoft owns multiple services).
- **Vault**: The user's complete encrypted namespace.
- **Crypto-shred**: Destruction by deleting the key, rendering ciphertext irrecoverable.
