# AGENTS.md — LumaBridge Display Engineering Instructions

Persistent repository instructions for engineering agents working on **LumaBridge Display**.

---

## 1. Hierarchy of Sources of Truth

Read and reconcile against real code, Git state, and PR/CI checks before editing:

1. [REQUISITOS_LUMABRIDGE.md](REQUISITOS_LUMABRIDGE.md) — product requirements, trust boundaries, quality and non-functional targets.
2. [docs/planning/UNIVERSAL_ROADMAP.md](docs/planning/UNIVERSAL_ROADMAP.md) & [docs/planning/MIGRATION_PLAN.md](docs/planning/MIGRATION_PLAN.md) — milestone sequence (`M0`–`M6`) and deliverables.
3. Architecture Decision Records:
   - [ADR-0001-branching-strategy.md](docs/architecture/ADR-0001-branching-strategy.md)
   - [ADR-0004-core-language-and-native-boundaries.md](docs/architecture/ADR-0004-core-language-and-native-boundaries.md)
   - [ADR-0005-transport-and-security-architecture.md](docs/architecture/ADR-0005-transport-and-security-architecture.md)
4. [wire-protocol-v1.md](docs/protocol/wire-protocol-v1.md) — normative LBWP wire framing, channels, CBOR schemas, and invariants.
5. Planning & Compliance:
   - [docs/planning/BACKLOG.md](docs/planning/BACKLOG.md)
   - [docs/planning/RISK_REGISTER.md](docs/planning/RISK_REGISTER.md)
   - [docs/planning/LICENSE_COMPLIANCE_REVIEW.md](docs/planning/LICENSE_COMPLIANCE_REVIEW.md)
   - [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
   - [CONTRIBUTING.md](CONTRIBUTING.md)
6. [docs/setup/ci-and-test-matrix.md](docs/setup/ci-and-test-matrix.md) & [scripts/ci/check_repo_hygiene.py](scripts/ci/check_repo_hygiene.py).

**Rule on Divergence:** Never alter or weaken requirements or test thresholds to justify a defective implementation. Identify the root cause, verify the normative contract, and reconcile code and docs cleanly.

---

## 2. Non-Negotiable Architectural Boundaries

- **Windows Driver (`windows/driver/`):** Keep `LumaBridgeIddDriver` in C++/WDK, isolated from networking, QUIC/TLS, pairing, and proprietary video encoder SDKs. Preserve `EnableVirtualMonitor = 0` safe opt-in default and keep the `LBIF` Named Pipe protocol private to local Windows IPC. Never rewrite the driver unless an experimentally proven defect demands it.
- **Shared Core (`core/`):** Cross-platform core currently comprises `lumabridge-core`, `lumabridge-ffi`, and `lumabridge-protocol`, expanding across M1+ to security (`lumabridge-security`), transport (`lumabridge-transport`), session orchestration, and narrow FFI/UniFFI boundaries (`lumabridge-ffi`).
- **Memory & Type Safety:** Enforce `#![forbid(unsafe_code)]` across pure Rust crates outside `lumabridge-ffi`. Treat `unsafe` FFI wrappers as critical security/memory-safety boundaries.
- **Security Invariants (`ADR-0005`):**
  - Default-deny authorization; remote input permissions (`INPUT_*`) are forbidden during pairing and require explicit consent on operational sessions.
  - Zero homemade cryptography; use audited crates compliant with `core/deny.toml` and `THIRD_PARTY_NOTICES.md`.
  - Keep pairing ALPN (`lumabridge-pair/1`) strictly isolated from operational ALPN (`lumabridge/1`); disable TLS resumption and 0-RTT; bind operational session/resumption security and anti-replay guarantees to TLS 1.3 exporter channel bindings (`RFC 9266`).
  - Never log private keys, PINs, session/resume tokens, channel-binding secrets, desktop pixels, or remote input payloads.
- **No Unreleased Scope Creep:** Keep active milestones focused and clean; never ship later-milestone stubs or relax release gates.

---

## 3. Git Governance, CI Ruleset & Risk-Based Approval

- **License & DCO:** Original code is `Apache-2.0`. Every new commit MUST include a DCO 1.1 `Signed-off-by` matching commit author identity (`git commit -s`). Use Conventional Commits (`<type>(<scope>): <summary>`).
- **Branches & Integration (`dev`):** Never push directly to `dev` or `main`. Use isolated `git worktree` directories and scoped branches (`feature/*`, `fix/*`, `docs/*`, `chore/*`). Never force-push or rewrite shared history. Always preserve historical worktrees/branches.
- **Ruleset `28020487` on `dev`:** All changes to `dev` must enter via reviewed Pull Request integrated by **merge commit** (`--no-ff`; squash/rebase merges disabled), with **strict up-to-date status checks** (`strict_required_status_checks_policy`) and all **4 required checks** passing:
  1. `Repository Hygiene, Licensing & Prospective DCO`
  2. `Windows Unit & Tooling Tests (Non-Admin)`
  3. `Windows Rust + MSVC Debug/Release FFI PoC`
  4. `Linux Rust Tests + Android ARM64 & UniFFI PoC`
- **Review & Critical External Approval Gate:** Never self-merge or bypass PR review (`CONTRIBUTING.md`, `ADR-0001`). In addition, changes touching critical boundaries require explicit external human approval before merge:
  - Cryptography, TLS/mTLS, pairing (SPAKE2/QR), or key/identity/certificate lifecycle.
  - Authorization, Trust Store, consent flows, session revocation, or remote input elevation.
  - `unsafe` memory contracts or FFI boundary definitions.
  - Windows kernel/UMDF driver (`windows/driver/`) or administrative/privileged scripts.
  - Incompatible `LBWP` wire changes or fundamental architectural ADRs.
  - Production/public distribution workflows.
  Keep unapproved critical PRs `OPEN`, publish an objective review summary, and note that advancing `dev` via unrelated PRs while `strict_required_status_checks_policy` is enabled puts open PRs `BEHIND`.

---

## 4. Verification, Honesty & Privacy Discipline

- **Honest Test Classification:** Explicitly distinguish `PASS`, `FAIL`, `BLOCKED_BY_ENVIRONMENT`, `BLOCKED_BY_DEPENDENCY`, `NOT_TESTED` / `SKIPPED` / `NOT_MEASURED`, and `NOT_APPLICABLE`. Never report WARP/mock/dry-run/loopback tests as proof of physical GPU, Wayland/X11 compositor, or Windows `WUDFHost.exe` validation.
- **Independent Adversarial Review:** Every functional or documentation PR must undergo an independent review (fresh context) before completion, actively checking for norm contradictions, race conditions, resource bounds, false-positive tests, and privacy/hygiene violations.
- **Privacy & Hygiene (`scripts/ci/check_repo_hygiene.py`):**
  - Never commit secrets, keys/certs (`.pem`, `.key`, `.pfx`, `.der`), binaries (`.exe`, `.dll`, `.sys`), personal email addresses, or workstation-specific user paths (use `$env:USERPROFILE`, `$env:ANDROID_HOME`, or relative paths).
  - Remove generated `fuzz/corpus/` or scratch outputs before committing.
  - Verify all relative Markdown links target tracked files that exist on the current branch.

---

## 5. Toolchain Notes

- **Windows PowerShell 5.1:** `&&` is unsupported; chain dependent commands with `; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }`.
- **Rust:** Ensure Rust `1.100.0` (`rustfmt`, `clippy`), `cbindgen`, `cargo-deny`, and `cargo-ndk` (`$env:USERPROFILE\.cargo\bin`) are on `PATH`; run Cargo commands from `core/` with `--locked`.
- **Android Cross-Build:** Set `$env:ANDROID_HOME` / NDK `28.x` and target API level `-P 29` (`aarch64-linux-android`).
- **Windows ASan Fuzzing:** Add MSVC Hostx64 runtime (`clang_rt.asan_dynamic-x86_64.dll`) to `PATH`; omit `--locked` when invoking `cargo fuzz run`; delete generated corpus directories afterward.

---

## 6. Workspace Skills

Project skills in `.agents/skills/`:
- `lumabridge-engineering` — full milestone lifecycle, module ownership, Rust/safety/license standards.
- `lumabridge-security-review` — adversarial audit checklist for TLS, pairing, CBOR transcripts, authz/revocation, bounds, and fuzzing.
- `lumabridge-milestone-validation` — exact command matrix and honest qualification classification.
- `lumabridge-git-integration` — worktrees, DCO 1.1, stacked branches, Ruleset `28020487`, PR discipline.
- `lumabridge-performance` — reproducible Criterion/transport benchmarks and congestion/latency metrics.
- `lumabridge-session-recovery` — deterministic checkpointing and multi-session state recovery.
