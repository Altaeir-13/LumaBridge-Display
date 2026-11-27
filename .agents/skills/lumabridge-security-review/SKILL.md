---
name: lumabridge-security-review
description: Adversarial security audit checklist and invariant verification grounded in ADR-0005 and LBWP v1 for TLS, pairing, CBOR transcripts, authorization, revocation, resource bounds, and fuzzing.
---

# LumaBridge Security Review Checklist

Use this skill for security design reviews, pre-PR self-audits, and independent adversarial reviews across protocol, security, transport, session orchestration, FFI, and native host/receiver boundaries. Ground checks in [ADR-0005](../../../docs/architecture/ADR-0005-transport-and-security-architecture.md) and [wire-protocol-v1.md](../../../docs/protocol/wire-protocol-v1.md).

## 1. Transport & TLS 1.3 Invariants (`ADR-0005`)

- Verify strict mutual authentication (`TLS 1.3` only, strong vetted crypto provider, no server session ticket storage or keylogging in production configs).
- Confirm **TLS session resumption and 0-RTT early data are disabled** on pairing and operational endpoints, enforcing full handshakes.
- Confirm **ALPN isolation**: `lumabridge-pair/1` is accepted ONLY for pairing and rejected for operational APIs; `lumabridge/1` is required for operational control/media/session/input flows.
- Verify certificate verifiers on both operational and pairing paths enforce non-optional Trust Store checks (constant-time `device_id`/SPKI identity checks, expected peer role, and revocation rejection).

## 2. Pairing, CSPRNG & Transcript Integrity

- Verify CSPRNG failures propagate explicitly as errors and never silently produce predictable keys, salts, nonces, or shares; zeroize partial buffers on failure.
- Verify short PIN pairing (`6–8` digits per `ADR-0005`, or stricter tightened length if specified) preserves leading zeros, rejects malformed lengths/characters, enforces an atomic attempt budget (`3` failed attempts lockout/cooldown), enforces TTL expiry, protects against cross-generation lease reuse on PIN rotation, and zeroizes PIN material immediately on completion, exhaustion, expiry, or cancellation.
- Verify SPAKE2 associated data/transcripts, QR out-of-band auth tokens, pairing confirmations, and session/resumption tokens use deterministic `LBWP-CBOR-v1` canonical encodings with distinct domain-separation labels.
- Confirm remote input permissions (`INPUT_*`) are strictly rejected during pairing and initial peer persistence, and pairing confirmation never bypasses mutual local human approval.

## 3. Authorization, Revocation & Concurrency

- Audit TOCTOU safety on permission upgrades: approval grants must be single-use, bound to `(session/attempt, sequence, peer_device_id)`, checked against current permission/policy epoch, and evaluated as the strict intersection of peer stored grant, local policy cap, session grant, consent state, and requested mask.
- Audit lock ordering across Trust Store, pairing state, session/token state, and transport handles to guarantee deadlock freedom and atomic state transitions.
- Confirm peer revocation updates revocation epoch, immediately invalidates active sessions and resumption tokens, and emits active transport disconnection signals.
- Verify operational authorization and session issuance require genuine TLS-authenticated session provenance bound to TLS 1.3 exporter channel bindings (`RFC 9266`), with any synthetic test helpers gated exclusively behind test/fuzz configurations (never enabled in default or production builds).

## 4. Resource Exhaustion, Redaction & Fuzzing

- Verify hard upper bounds (`MAX_*`) and fail-closed behavior on active pairing attempts, QR tokens, trusted/revoked peer stores, active sessions/resume tokens, expiry-pruned anti-replay caches, incremental stream decoders, and media reassembly/transport queues.
- Verify `Debug`/`Display` implementations and logs redact private keys, PINs, tokens, channel-binding secrets, signatures, desktop pixels, and remote input events.
- Verify automatic zeroization on drop for keys, seeds, PINs, and channel-binding material.
- Require ASan `libFuzzer` runs on affected parsing/state-machine/authz targets plus deterministic negative regression tests, and ensure no `fuzz/corpus/` or `fuzz/artifacts/` outputs are committed.
