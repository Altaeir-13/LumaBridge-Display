---
name: lumabridge-engineering
description: End-to-end engineering lifecycle, architectural boundaries, Rust safety standards, and license compliance workflow for LumaBridge Display.
---

# LumaBridge Engineering Workflow

Use this skill whenever designing, implementing, refactoring, or auditing any milestone in **LumaBridge Display**.

## 1. Mandatory Engineering Cycle

Execute these phases in order without skipping verification or review:

1. **Inspect Real State:** Check `git status`, `git worktree list`, open PRs (`gh pr list`), latest `origin/dev` commit, and milestone docs/reports. Never rely solely on prior summaries.
2. **Read Normative Contracts:** Verify requirements and boundaries in:
   - [REQUISITOS_LUMABRIDGE.md](../../../REQUISITOS_LUMABRIDGE.md)
   - [UNIVERSAL_ROADMAP.md](../../../docs/planning/UNIVERSAL_ROADMAP.md)
   - [wire-protocol-v1.md](../../../docs/protocol/wire-protocol-v1.md)
   - [ADR-0004](../../../docs/architecture/ADR-0004-core-language-and-native-boundaries.md) and [ADR-0005](../../../docs/architecture/ADR-0005-transport-and-security-architecture.md)
3. **Define Objective Acceptance Criteria:** Establish concrete functional, security, resource-bound, concurrency, performance, and multiplatform targets before editing code.
4. **Enforce Module Ownership:**
   - Isolate changes cleanly per crate/directory (`core/crates/*`, `windows/host/`, `docs/`, and planned `platforms/*` directories such as Linux/Android as introduced).
   - Never touch `windows/driver/` (`LumaBridgeIddDriver`) unless an experimentally proven defect requires it; keep `LBIF` local-only.
   - Keep `#![forbid(unsafe_code)]` on all non-FFI Rust crates.
5. **Implement & Self-Verify:**
   - Apply `#![warn(clippy::all, clippy::pedantic)]`.
   - Never implement custom cryptographic primitives or weaken deny-by-default limits.
   - Verify third-party dependency licenses against `core/deny.toml`, [CONTRIBUTING.md](../../../CONTRIBUTING.md), and [LICENSE_COMPLIANCE_REVIEW.md](../../../docs/planning/LICENSE_COMPLIANCE_REVIEW.md); update [THIRD_PARTY_NOTICES.md](../../../THIRD_PARTY_NOTICES.md) when adding crates or headers.
6. **Run Independent Adversarial Review:** Invoke a fresh-context reviewer using `lumabridge-security-review` and `lumabridge-milestone-validation` criteria to actively hunt defects, normative drift, mock-hidden gaps, and untested error paths.
7. **Fix, Re-Verify & Reconcile Docs:** Fix all confirmed findings, re-run the full validation suite on the final tree, update architecture/qualification docs, and prepare DCO-signed commits.

## 2. Dependency & License Policy

Distinguish the repository's **currently enforced `core/deny.toml` allowlist** from the broader legal policy bands in [LICENSE_COMPLIANCE_REVIEW.md](../../../docs/planning/LICENSE_COMPLIANCE_REVIEW.md) and [CONTRIBUTING.md](../../../CONTRIBUTING.md):

- **Currently enabled in `core/deny.toml` (`M1.2` baseline):** `Apache-2.0`, `MIT`, `Unicode-3.0`, and `MPL-2.0` (`MPL-2.0` provides file-level weak copyleft compatible with static `Apache-2.0` binaries when unmodified or preserved under `MPL-2.0`).
- **Green policy band (`CONTRIBUTING.md`):** `Apache-2.0`, `MIT`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Zlib`, `CC0-1.0` / `Unlicense`. Introducing a new `BSD-*`, `ISC`, `Zlib`, or `CC0-1.0`/`Unlicense` crate requires an explicit, reviewed addition to `core/deny.toml` plus attribution in [THIRD_PARTY_NOTICES.md](../../../THIRD_PARTY_NOTICES.md).
- **Yellow policy band (`LGPL-2.1+` / `LGPL-3.0`):** Permitted on desktop ONLY via dynamic linking (`.dll`/`.so`/`dlopen`) with complete source-access notices; excluded from `core/deny.toml` and avoided in static mobile/core binaries.
- **Red policy band (forbidden in official distributions):** `GPLv2-only`, single-binary `GPLv3`, `AGPL`, proprietary third-party binaries, and unverified patent-encumbered codecs.
- **Validation scope:** Run `cargo deny --locked check advisories licenses bans sources` inside `core/`. For standalone `fuzz/` manifests (which depend on `libfuzzer-sys` `NCSA` and local `{ path = ".." }` crates), run `cargo deny --locked --manifest-path <fuzz>/Cargo.toml check advisories sources` separately because root `licenses`/`bans` reject fuzz-only dev/harness constraints.

## 3. Reconciling Doc vs Code Drift

- Never edit normative requirements downward to make buggy code pass.
- If a provisional spec (`Proposed` ADR or `Draft` protocol) discovers a real engineering constraint during implementation/benchmarking, document the evidence objectively and update both code and specification transparently.
