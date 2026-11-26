# LumaBridge Display — M1.3 Security Qualification Report (`lumabridge-security`)

> **Governance Status:** `ADR-0004 = Accepted`, **`ADR-0005 = Proposed`**, **`wire-protocol-v1.md = Draft`**, **`LBWP_V1_FORMALLY_FROZEN = False`**, **`M1_COMPLETE = False`**, **`M1_3_INTEGRATED_IN_DEV = False`**.  
> **Scope Boundary:** `lumabridge-security` implements cryptographic device identity, self-signed X.509 v3 Ed25519 certificates, RFC 9846 TLS 1.3-only mTLS configuration, RFC 9266 `EXPORTER-Channel-Binding`, RFC 9382 SPAKE2-P256 PIN pairing, single-use channel-bound QR pairing, zero-trust storage/revocation, default-deny authorization, HMAC-SHA256 session/resume token lifecycle, anti-replay, and multi-endpoint rate limiting. **Limitations explicitly retained:** [`InMemoryTrustStore`](../../core/crates/lumabridge-security/src/trust_store.rs) is an in-memory reference store and **not** a native OS hardware/platform keystore (Windows DPAPI/CNG, Android Keystore, Linux Secret Service remain out of M1.3 scope); third-party crate `pakery-spake2` / `pakery-crypto` (`0.6.2`) does **not** have an independent third-party cryptographic audit; and compromise of the local OS or private identity seed cannot be mitigated in software alone.

---

## 1. Crate & Boundary Architecture

- **Crate:** `core/crates/lumabridge-security` (`#![forbid(unsafe_code)]`, `#![warn(clippy::all, clippy::pedantic)]`, Rust `1.100.0`).
- **Consolidated `lumabridge-protocol` M1.3 Wire Contracts (`core/crates/lumabridge-protocol/src/control.rs`):**
  - `PairHello`: exact 44-byte canonical RFC 8410/9295 Ed25519 SPKI DER (`ED25519_SPKI_DER_LEN = 44`, `ED25519_SPKI_DER_PREFIX`), `SHA-256(spki_ed25519) == device_id`, strict `UnknownFieldPolicy::Reject`.
  - `PairSpakeMsg`: `SpakeStep::KeyExchange` mandates 65-byte uncompressed P-256 SEC1 point (`0x04..`) with `key_confirmation = None`; `SpakeStep::KeyConfirmation` mandates empty `spake_payload` with 32-byte `key_confirmation = Some(...)`.
  - `PairQrAuth`: 32-byte opaque single-use token + 64-byte Ed25519 initiator signature over RFC 9266 `EXPORTER-Channel-Binding` context.
  - `PairConfirm`: `accepted = true` requires 64-byte acceptor signature and strictly forbids `Permissions::INPUT_MASK`; `accepted = false` enforces `Permissions::NONE` and `confirm_signature = None`.
  - `SessionOpenResponse` / `SessionResumeRequest`: 32-byte `resume_token` (`OPAQUE_TOKEN_LEN = 32`).

## 2. Cryptographic Dependency Assessment

| Crate | Version | Role | License | Security & Audit Assessment |
|---|---:|---|---|---|
| `ed25519-dalek` | `3.0.0` | RFC 8032 Ed25519 keys & `verify_strict` | `BSD-3-Clause` | Cofactorless strict verification, `ZeroizeOnDrop`, `#![forbid(unsafe_code)]`; validated against RFC 8032 §7.1 TEST 1 & TEST 2. |
| `ring` (via `rustls`/`rcgen`) | `0.17.14` | TLS 1.3 AEAD/ECDHE/HKDF/Ed25519 backend | `Apache-2.0` / `ISC` | Battle-tested BoringSSL-derived crypto backend; cross-compiled cleanly on Windows x64 and Android ARM64 NDK `28.2.13676358`. |
| `rustls` | `0.23.46` | RFC 9846 TLS 1.3-only mTLS (`tls12` feature omitted) | `Apache-2.0 OR MIT` | Memory-safe TLS 1.3 state machine, ALPN enforcement (`lumabridge-pair/1`, `lumabridge/1`), RFC 9266 `EXPORTER-Channel-Binding` export. |
| `rcgen` / `x509-cert` | `0.14.10` / `0.3.1` | Self-signed X.509 v3 Ed25519 cert generation & strict DER validation | `Apache-2.0 OR MIT` | Validates canonical DER round-trip, Version::V3, `id-Ed25519` OID (`1.3.101.112`), validity interval, and strict self-signature. |
| `pakery-spake2` / `pakery-crypto` | `0.6.2` | RFC 9382 SPAKE2 (`Spake2P256`, HKDF-SHA256, HMAC-SHA256) | `MIT OR Apache-2.0` | Implements exact RFC 9382 P-256 transcript (`u64` LE lengths + `ConfirmationKeys || AAD`); **no independent external cryptographic audit** — mitigated with strict 65-byte `0x04` SEC1 validation, RFC 9382 Appendix B vectors 1–3 verification, TLS channel binding into both `w` & `AAD`, and explicit boundary isolation. |
| `hkdf` / `hmac` / `sha2` | `0.13.0` / `0.13.0` / `0.11.2` | Domain-separated KDFs, token digests, canonical IDs | `MIT OR Apache-2.0` | RustCrypto crates with `Zeroize`; no raw tokens or PINs persisted. |
| `getrandom` / `rand_core` / `subtle` / `zeroize` | `0.4.3` / `0.10.1` / `2.6.1` / `1.9.2` | Checked OS CSPRNG, CT equality, zeroization on drop | Permissive | Checked error propagation via `CheckedOsCryptoRng` & `PrefetchedCryptoRng` without panic/unwrap on RNG errors. |

*(Rejected `spake2 0.5.0-pre.0`: pre-release crate locked to Ed25519 with known RFC 9382 transcript differences.)*

## 3. Normative Standards & Threat Test Results

- **Workspace Suites (`cargo test --locked --workspace`):** `58` passed (`lumabridge-core` 7, `lumabridge-ffi` 5, `lumabridge-protocol` 33, `lumabridge-security` 13).
- **`rfc_vectors_and_identity` (`4/4` PASS):**
  - RFC 8032 §7.1 TEST 1 (empty msg) & TEST 2 (`0x72`) byte-for-byte match, strict malleability/tamper rejection, small-order weak Ed25519 public key rejection.
  - All 3 official RFC 9382 Appendix B P-256/SHA-256/HKDF/HMAC vectors matched byte-for-byte on `pA`, `pB`, `Ke`, `cA`, and `cB`.
  - X.509 expiry/not-before/trailing-DER/wrong-OID/signature tampering checks + `proptest` identity & fuzz rejection properties.
- **`pairing_and_tls_tests` (`3/3` PASS):**
  - All 9 real in-memory RFC 9846 TLS 1.3 mTLS scenarios (`rustls::ClientConnection` ↔ `rustls::ServerConnection`): operational mTLS + RFC 9266 equality + encrypted app data; pairing mTLS; raw TLS 1.2 ClientHello rejection; missing client cert rejection; untrusted peer rejection; wrong role rejection; expired & future cert rejection; revoked peer rejection (in both operational & pairing modes); tampered cert & ALPN mismatch rejection.
  - Full channel-bound SPAKE2-P256 & QR flows with explicit `HumanApprovalDecision` and `PairConfirm` input-permission rejection.
  - Real 2-connection active MITM (`Controller <-> MITM <-> Host`) failing BOTH forwarded SPAKE2 confirmation and forwarded `PairQrAuth` due to mismatched RFC 9266 channel bindings.
  - 16-thread concurrent QR `consume_once` race confirming strictly `1` winner and `15` `QrTokenReusedOrUnknown` rejections.
- **`trust_authz_revocation_tests` (`6/6` PASS):**
  - Zero-trust defaults, live `TrustStore` permission downgrade immediately invalidating mid-session `INPUT_POINTER`, explicit `InputApprovalDecision` enforcement, single-use resume token rotation & replay rejection (`SessionTokenReused`), mid-session revocation race & monotonic `trust_epoch` advance, per-peer backoff + multi-endpoint global rate limiting, bounded replay cache (`MAX_TRACKED_CHALLENGES = 4096`), redacted `{:?}`/`{:#?}`/`Display` privacy sentinels, and fuzz corpus replay.

## 4. Performance Benchmarks (`cargo bench --locked -p lumabridge-security`)

| Benchmark Operation | avg (ns) | p50 (ns) | p95 (ns) | p99 (ns) | max (ns) |
|---|---:|---:|---:|---:|---:|
| `ed25519_sign_256b` | 17,699.6 | 16,400 | 25,000 | 29,400 | 50,700 |
| `ed25519_verify_strict_256b` | 33,222.4 | 31,700 | 41,900 | 54,900 | 130,200 |
| `x509_v3_self_signed_verify` | 47,890.0 | 40,000 | 72,000 | 109,300 | 120,000 |
| `tls13_mtls_handshake_plus_rfc9266` | 436,956.2 | 475,700 | 517,200 | 533,400 | 567,600 |
| `spake2_p256_channel_bound_full` | 1,916,735.0 | 1,841,300 | 2,236,900 | 2,265,300 | 2,430,800 |
| `qr_channel_bound_full` | 122,266.5 | 110,800 | 168,900 | 186,400 | 192,100 |
| `session_token_plus_live_authz` | 549.7 | 500 | 700 | 800 | 1,000 |

## 5. AddressSanitizer Fuzzing Campaigns (`nightly-2026-04-01`, Windows MSVC)

| Target | Duration | Executions | Throughput (exec/s) | Peak RSS (MB) | Crashes / Sanitizer Errors |
|---|---|---:|---:|---:|---:|
| `fuzz_spki_identity` (`lumabridge-security`) | 61 s | 2,583,137 | 42,346 | 391 | 0 |
| `fuzz_x509_cert` (`lumabridge-security`) | 61 s | 1,774,717 | 29,093 | 533 | 0 |
| `fuzz_spake2_messages` (`lumabridge-security`) | 61 s | 26,570 | 435 | 363 | 0 |
| `fuzz_qr_pairing` (`lumabridge-security`) | 61 s | 26,507 | 434 | 359 | 0 |
| `fuzz_session_authz` (`lumabridge-security`) | 61 s | 101,496 | 1,663 | 402 | 0 |
| `fuzz_cbor_control` (`lumabridge-protocol`, incremental) | 61 s | 1,640,921 | 26,900 | 563 | 0 |
| `fuzz_contextual_validation` (`lumabridge-protocol`, incremental) | 61 s | 1,491,203 | 24,445 | 557 | 0 |
| **Total M1.3 Fuzzing** | **7 x 61 s** | **7,644,551** | — | **563 max** | **0** |

## 6. Dependency Policy, Android ARM64 & CI Coverage

- `cargo deny --locked check advisories licenses bans sources` passed (`exit=0`) across `core/`, `core/crates/lumabridge-protocol/fuzz/deny.toml`, and `core/crates/lumabridge-security/fuzz/deny.toml` (dedicating `NCSA` strictly to `libfuzzer-sys` + `allow-wildcard-paths = true`).
- Android NDK `28.2.13676358` `arm64-v8a` (`-P 29`) release build passed for `lumabridge-protocol` and `lumabridge-security`.
- Full local Windows MSVC CI suite (`Invoke-LumaBridgeFfiPocCi.ps1 -SkipBenchmark -RequireCargoDeny`) passed with zero regression in protected M0/FFI deliverables.
