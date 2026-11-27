# LumaBridge Display — M1.3 / M1.3.1 Security Qualification Report (`lumabridge-security`)

> **Governance Status:** `ADR-0004 = Accepted`, **`ADR-0005 = Proposed`**, **`wire-protocol-v1.md = Draft`**, **`LBWP_V1_FORMALLY_FROZEN = False`**, **`M1_COMPLETE = False`**, **`M1_3_INTEGRATED_IN_DEV = False`**.  
> **Scope Boundary:** `lumabridge-security` implements cryptographic device identity, self-signed X.509 v3 Ed25519 certificates, RFC 9846 TLS 1.3-only mTLS configuration (with TLS resumption, session tickets, 0-RTT, and `KeyLog` disabled), RFC 9266 `EXPORTER-Channel-Binding`, RFC 9382 SPAKE2-P256 8-digit PIN pairing with atomic 3-attempt budget, single-use channel-bound QR pairing, mutual local human consent, zero-trust storage/revocation, default-deny 5-factor authorization, channel-bound HMAC/HKDF/SHA-256 session & rotating resume tokens, fail-closed anti-replay, and multi-endpoint rate limiting. **Limitations explicitly retained:** [`InMemoryTrustStore`](../../core/crates/lumabridge-security/src/trust_store.rs) is an in-memory reference store and **not** a native OS hardware/platform keystore (Windows DPAPI/CNG, Android Keystore, Linux Secret Service remain out of M1.3/M1.3.1 scope); third-party crate `pakery-spake2` / `pakery-crypto` (`0.6.2`) does **not** have an independent third-party cryptographic audit; and compromise of the local OS or private identity seed cannot be mitigated in software alone.

---

## 1. Crate & Boundary Architecture

- **Crate:** `core/crates/lumabridge-security` (`#![forbid(unsafe_code)]`, `#![warn(clippy::all, clippy::pedantic)]`, Rust `1.100.0`).
- **Consolidated `lumabridge-protocol` M1.3 Wire Contracts (`core/crates/lumabridge-protocol/src/control.rs`):**
  - `PairHello`: exact 44-byte canonical RFC 8410/9295 Ed25519 SPKI DER (`ED25519_SPKI_DER_LEN = 44`, `ED25519_SPKI_DER_PREFIX`), `SHA-256(spki_ed25519) == device_id`, strict `UnknownFieldPolicy::Reject`.
  - `PairSpakeMsg`: `SpakeStep::KeyExchange` mandates 65-byte uncompressed P-256 SEC1 point (`0x04..`) with `key_confirmation = None`; `SpakeStep::KeyConfirmation` mandates empty `spake_payload` with 32-byte `key_confirmation = Some(...)`.
  - `PairQrAuth`: 32-byte opaque single-use token + 64-byte Ed25519 initiator signature over RFC 9266 `EXPORTER-Channel-Binding` CBOR context.
  - `PairConfirm`: `accepted = true` requires 64-byte acceptor signature and strictly forbids `Permissions::INPUT_MASK`; `accepted = false` enforces `Permissions::NONE` and `confirm_signature = None`.
  - `SessionOpenResponse` / `SessionResumeRequest`: 32-byte `resume_token` (`OPAQUE_TOKEN_LEN = 32`).

## 2. M1.3.1 Security Hardening Summary

1. **TLS Resumption & 0-RTT Disabled (`tls.rs`, `channel_binding.rs`):** `Resumption::disabled()`, `enable_early_data = false`, `send_tls13_tickets = 0`, `max_early_data_size = 0`, `NoServerSessionStorage`, `NoKeyLog`, plus explicit `HandshakeKind::Resumed` rejection in `extract_tls13_channel_binding` and `extract_authenticated_session_with_alpn`.
2. **`PinnedPeer` Trust Store Enforcement (`tls.rs`):** `TlsPeerTrustPolicy::PinnedPeer` and `TlsPeerTrustPolicy::Pairing` unconditionally attach and consult `TrustStore` (`verify_trusted_peer` / `is_revoked`).
3. **Checked CSPRNG Health (`secret.rs`, `pairing.rs`):** `PrefetchedCryptoRng` records any `getrandom` refill failure, zeroizes output, and `ensure_healthy()` is enforced immediately after SPAKE2 scalar generation.
4. **Normative 8-Digit PIN & Atomic 3-Attempt Budget (`secret.rs`, `pairing.rs`):** `PinSecret` mandates exact 8 ASCII digits (`00000000..=99999999`) preserving leading zeros; `PinPairingWindow` + RAII `PinAttemptLease` enforce a 90 s TTL, atomic 3-attempt concurrency budget, and immediate PIN zeroization on success, expiry, close, or 3rd failure.
5. **Normative Deterministic CBOR Transcripts & Token Domains (`transcript.rs`):** `build_spake2_aad`, `build_qr_auth_signing_message`, and `build_pair_confirm_signing_message` emit `LBWP-CBOR-v1` (RFC 8949 §4.2.1) maps with `LB-INIT:`/`LB-ACC:` identities, `lumabridge.pair.pin.salt.v1` / `lumabridge.pair.spake2.w.v1`, and separated `lumabridge.session.access.token.v1` / `lumabridge.session.resume.token.v1` / `lumabridge.session.resume.proof.v1` domains.
6. **Authenticated Provenance (`channel_binding.rs`, `tls.rs`, `authorization.rs`, `session_token.rs`):** `ChannelBinding::from_tls13_exporter` is crate-private (`SyntheticTest` gated behind `#[cfg(any(test, feature = "test-utils"))]`), `AuthenticatedTlsSession` fields are private, and operational authorization/session APIs require `&AuthenticatedTlsSession` (`lumabridge/1`).
7. **Mutual Local Human Consent (`pairing.rs`, `authorization.rs`):** `PairConfirm` never promotes `PairingInitiator` to `Confirmed` without explicit `apply_local_approval`; `HumanApprovalDecision` and `InputApprovalDecision` are bound to `(attempt/session, seq, peer_device_id)`.
8. **Authorization & Revocation Concurrency (`trust_store.rs`, `authorization.rs`, `session_token.rs`):** `InMemoryTrustStore::elevate_permissions_atomic` eliminates elevation TOCTOU; 5-factor intersection (`local_policy & persisted_peer_perms & session_grant & requested_operation & negotiated_caps`) is enforced; `SessionTokenManager` acquires its lock before live `TrustStore` checks and exposes `revoke_peer_and_sessions` emitting `SecurityAction::DisconnectPeerSessions`.
9. **Fail-Closed Anti-Replay (`anti_replay.rs`):** `BoundedChallengeCache` purges expired entries by timestamp and fails closed (`ResourceExhausted`) when saturated with `MAX_TRACKED_CHALLENGES = 4096` unexpired challenges.
10. **Channel-Bound Session & Resume Tokens (`session_token.rs`):** Sessions bind to `ChannelBinding`, reject cross-channel token presentation without `SessionResume`, require `ChannelBinding` + proof on resume, and reject same-channel resume replay.
11. **Bounded Security State (`pairing.rs`, `trust_store.rs`, `session_token.rs`, `rate_limit.rs`):** Hard caps on `MAX_ACTIVE_PAIRING_ATTEMPTS = 16`, `MAX_ACTIVE_QR_TOKENS = 64`, `MAX_TRUSTED_PEERS = 256`, `MAX_REVOKED_PEERS = 1024`, `MAX_ACTIVE_SESSIONS = 256`, `MAX_ACTIVE_RESUME_TOKENS = 512`, and `MAX_GLOBAL_FAILURE_EVENTS = 4096`.
12. **ChannelBinding & Key Privacy (`channel_binding.rs`, `certificate.rs`):** `ChannelBinding` redacts all bytes (`ChannelBinding([REDACTED])`) and `GeneratedDeviceCertificate` redacts `pkcs8_der`.
13. **Secret Lifecycle (`secret.rs`, `channel_binding.rs`, `identity.rs`, `pairing.rs`):** `Zeroize`/`ZeroizeOnDrop` across `ChannelBinding`, `IdentityKeyPair::from_seed_zeroizing`, `PairingInitiator`/`PairingAcceptor` `Drop`, and `PinAttemptLease`.
14. **Adversarial Review Resolutions (`M1.3.1`):**
    - Added monotonic `pin_generation` tracking in `PinPairingWindow`/`PinAttemptLease` so stale leases after PIN rotation cannot poison or destroy the new PIN (`pairing.rs`).
    - Made `PendingPermissionUpgrade` single-use (non-`Copy`/`Clone`, consumed by value) and enforced `perm_epoch` monotonicity across `InMemoryTrustStore::update_base_permissions` and `elevate_permissions_atomic` (`trust_store.rs`, `authorization.rs`).
    - Enforced `ticket.acceptor_role == self.peer_role` in `PairingInitiator::create_qr_auth`, rejected `pairing_attempt_id == 0` and control-char `friendly_name` in `start()`, and zeroized expired PIN state on `remaining_attempts` (`pairing.rs`).
    - Tightened handshake completion checks to `HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest`, rejected `update_session_permissions` on revoked sessions, and activated real negative `PairConfirm` / ALPN mismatch tests (`tls.rs`, `channel_binding.rs`, `session_token.rs`, `pairing_and_tls_tests.rs`).

## 3. Cryptographic Dependency Assessment

| Crate | Version | Role | License | Security & Audit Assessment |
|---|---:|---|---|---|
| `ed25519-dalek` | `3.0.0` | RFC 8032 Ed25519 keys & `verify_strict` | `BSD-3-Clause` | Cofactorless strict verification, `ZeroizeOnDrop`, `#![forbid(unsafe_code)]`; validated against RFC 8032 §7.1 TEST 1 & TEST 2. |
| `ring` (via `rustls`/`rcgen`) | `0.17.14` | TLS 1.3 AEAD/ECDHE/HKDF/Ed25519 backend | `Apache-2.0` / `ISC` | BoringSSL-derived crypto backend; cross-compiled cleanly on Windows x64 and Android ARM64 NDK `28.2.13676358`. |
| `rustls` | `0.23.46` | RFC 9846 TLS 1.3-only mTLS (`tls12` feature omitted) | `Apache-2.0 OR MIT` | Memory-safe TLS 1.3 state machine, ALPN enforcement (`lumabridge-pair/1`, `lumabridge/1`), resumption/0-RTT disabled, RFC 9266 `EXPORTER-Channel-Binding` export. |
| `rcgen` / `x509-cert` | `0.14.10` / `0.3.1` | Self-signed X.509 v3 Ed25519 cert generation & strict DER validation | `Apache-2.0 OR MIT` | Validates canonical DER round-trip, Version::V3, `id-Ed25519` OID (`1.3.101.112`), validity interval, and strict self-signature. |
| `pakery-spake2` / `pakery-crypto` | `0.6.2` | RFC 9382 SPAKE2 (`Spake2P256`, HKDF-SHA256, HMAC-SHA256) | `MIT OR Apache-2.0` | Implements exact RFC 9382 P-256 transcript (`u64` LE lengths + `ConfirmationKeys || AAD`); **no independent external cryptographic audit** — mitigated with strict 65-byte `0x04` SEC1 validation, RFC 9382 Appendix B vectors 1–3 verification, TLS channel binding into `AAD`, and explicit boundary isolation. |
| `hkdf` / `hmac` / `sha2` | `0.13.0` / `0.13.0` / `0.11.2` | Domain-separated KDFs, token digests, canonical IDs | `MIT OR Apache-2.0` | RustCrypto crates with `Zeroize`; no raw tokens or PINs persisted. |
| `getrandom` / `rand_core` / `subtle` / `zeroize` | `0.4.3` / `0.10.1` / `2.6.1` / `1.9.2` | Checked OS CSPRNG, CT equality, zeroization on drop | Permissive | Checked error propagation via `CheckedOsCryptoRng` & `PrefetchedCryptoRng::ensure_healthy()`. |

*(Rejected `spake2 0.5.0-pre.0`: pre-release crate locked to Ed25519 with known RFC 9382 transcript differences.)*

## 4. Normative Standards & Threat Test Results

- **Workspace Suites (`cargo test --locked --workspace` across default, `poc-fault-injection`, `uniffi`):** `62` passed (`lumabridge-core` 7, `lumabridge-ffi` 5 default / 7 fault-injection, `lumabridge-protocol` 33, `lumabridge-security` 17).
- **`lumabridge-security` unit tests (`2/2` PASS):**
  - `PrefetchedCryptoRng` refill failure detection (`ensure_healthy()` returns `RngUnavailable` and zeroizes output).
  - Exact 8-digit ASCII PIN validation preserving leading zeros (`00000001`) and unbiased CSPRNG generation.
- **`rfc_vectors_and_identity` (`5/5` PASS):**
  - RFC 8032 §7.1 TEST 1 & TEST 2 byte-for-byte match, strict malleability/tamper rejection, small-order weak Ed25519 public key rejection.
  - All 3 official RFC 9382 Appendix B P-256/SHA-256/HKDF/HMAC vectors matched byte-for-byte on `pA`, `pB`, `Ke`, `cA`, and `cB`.
  - Strict deterministic CBOR (`LBWP-CBOR-v1`) transcript verification (`build_spake2_aad` keys `1..=13`, `build_qr_auth_signing_message` keys `1..=12`, `build_pair_confirm_signing_message` keys `1..=10`), `LB-INIT:`/`LB-ACC:` endpoint IDs, and separated access/resume token digest domains.
  - X.509 expiry/not-before/trailing-DER/wrong-OID/signature tampering checks + `proptest` identity & fuzz rejection properties.
- **`pairing_and_tls_tests` (`4/4` PASS):**
  - Real TLS 1.3 mTLS operational & pairing handshakes (`ChannelBindingSource::Tls13Exporter`), TLS resumption/0-RTT rejection even against resumption-enabled clients (`HandshakeKind::Full`), `PinnedPeer` enforcing live `TrustStore` & role, TLS 1.2 rejection, missing cert rejection, untrusted/wrong-role/expired/future/revoked rejection, ALPN mismatch rejection.
  - Channel-bound SPAKE2-P256 & QR flows with mutual local human consent on Acceptor & Initiator, `PairConfirm` non-bypassability, and real 2-connection active MITM rejection.
  - Atomic 3-attempt PIN budget destruction (single-thread 3 wrong guesses + 16-thread concurrency race + 90 s expiry) and 16-thread QR `consume_once` race (`1` winner, `15` rejections).
- **`trust_authz_revocation_tests` (`6/6` PASS):**
  - 5-factor authorization (`local_policy`, `persisted_peer_perms`, `session_grant`, `requested_operation`, `negotiated_caps`), `PendingPermissionUpgrade` binding, atomic input elevation, and live `TrustStore` downgrade.
  - Channel-bound session tokens, mandatory channel-bound resume rotation, same-channel resume replay rejection, coordinated `revoke_peer_and_sessions` (`DisconnectPeerSessions`), and 16-thread concurrent issuance vs revocation stress test.
  - Fail-closed saturated `BoundedChallengeCache` (`MAX_TRACKED_CHALLENGES = 4096`), bounded `QrTokenStore` (`MAX_ACTIVE_QR_TOKENS = 64`), bounded `AuthRateLimiter` (`MAX_GLOBAL_FAILURE_EVENTS = 4096`), full `ChannelBinding` + `GeneratedDeviceCertificate` privacy redaction sentinels, and fuzz corpus replay.

## 5. Performance Benchmarks (`cargo bench --locked -p lumabridge-security`)

| Benchmark Operation | avg (ns) | p50 (ns) | p95 (ns) | p99 (ns) | max (ns) |
|---|---:|---:|---:|---:|---:|
| `ed25519_sign_256b` | 17,606.6 | 16,200 | 20,300 | 27,600 | 108,800 |
| `ed25519_verify_strict_256b` | 33,835.8 | 31,400 | 39,300 | 48,700 | 117,500 |
| `x509_v3_self_signed_verify` | 43,905.5 | 40,600 | 54,100 | 68,600 | 156,600 |
| `tls13_mtls_handshake_plus_rfc9266` | 576,523.8 | 564,400 | 661,800 | 711,500 | 717,300 |
| `spake2_p256_channel_bound_full` | 1,767,975.0 | 1,715,000 | 1,957,000 | 2,308,200 | 2,642,600 |
| `qr_channel_bound_full` | 114,969.5 | 108,100 | 144,500 | 171,200 | 370,000 |
| `session_token_plus_live_authz` | 541.9 | 500 | 600 | 600 | 600 |

## 6. AddressSanitizer Fuzzing Campaigns (`nightly-2026-04-01`, Windows MSVC)

### M1.3.1 Re-qualification of Affected Security Targets
| Target | Duration | Executions | Throughput (exec/s) | Peak RSS (MB) | Crashes / Sanitizer Errors |
|---|---|---:|---:|---:|---:|
| `fuzz_spake2_messages` (`lumabridge-security`) | 31 s | 13,400 | 432 | 212 | 0 |
| `fuzz_qr_pairing` (`lumabridge-security`) | 31 s | 14,096 | 454 | 216 | 0 |
| `fuzz_session_authz` (`lumabridge-security`) | 31 s | 16,030 | 517 | 301 | 0 |
| **Total M1.3.1 Security Fuzzing** | **3 x 31 s** | **43,526** | — | **301 max** | **0** |

*(Historical M1.3 baseline also covered `fuzz_spki_identity`, `fuzz_x509_cert`, `fuzz_cbor_control`, and `fuzz_contextual_validation` over `7 x 61 s` / `7,644,551` executions with `0` crashes.)*

## 7. Dependency Policy, Android ARM64 & CI Coverage

- `cargo deny --locked check advisories licenses bans sources` passed (`exit=0`) across `core/`, `core/crates/lumabridge-protocol/fuzz/deny.toml`, and `core/crates/lumabridge-security/fuzz/deny.toml`.
- Android NDK `28.2.13676358` `arm64-v8a` (`-P 29`) release build passed for `lumabridge-protocol` and `lumabridge-security`.
- Full local Windows MSVC CI suite (`Invoke-LumaBridgeFfiPocCi.ps1 -SkipBenchmark -RequireCargoDeny`) and `check_repo_hygiene.py` (`197` tracked files, `50` Markdown files / `98` relative links) passed with zero regression in protected M0/FFI deliverables.
