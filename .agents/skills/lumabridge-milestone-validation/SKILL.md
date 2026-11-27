---
name: lumabridge-milestone-validation
description: Local and CI qualification command matrix aligned with ci-ffi-poc.yml, ci-linux-hygiene.yml, ci-windows.yml, and honest evidence reporting rules.
---

# LumaBridge Milestone Validation

Run all applicable gates after your **final edit**, before updating documentation or marking any step complete.

## 1. Repository Hygiene & Prospective DCO

```powershell
python -B scripts/ci/test_repo_hygiene.py
python -B scripts/ci/check_repo_hygiene.py --repo-root . --dco-base origin/dev --dco-head HEAD --dco-cutoff 23a2804606b02a85d915a55b75663b67bd5af58b
```

## 2. Rust Core Workspace (`core/`)

Prepend Rust toolchain bin (`$env:USERPROFILE\.cargo\bin`) to `PATH` if needed, and run inside `core/`:

```powershell
Set-Location core
cargo fmt --all --check
cbindgen --config crates/lumabridge-ffi/cbindgen.toml --crate lumabridge-ffi --output "$env:TEMP\lumabridge_ffi.generated.h"
# Compare generated header against crates/lumabridge-ffi/include/lumabridge_ffi.h (ignoring CRLF vs LF)
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked --workspace --all-targets --features poc-fault-injection -- -D warnings
cargo clippy --locked --workspace --all-targets --features uniffi -- -D warnings
cargo test --locked --workspace
cargo test --locked --workspace --features poc-fault-injection
cargo test --locked --workspace --features uniffi
```

## 3. Supply Chain & License Audit (`cargo-deny`)

Inside `core/` (audits `core/Cargo.lock` against `core/deny.toml`):

```powershell
cargo deny --locked check advisories licenses bans sources
```

For each standalone `fuzz/` sub-manifest (e.g., `crates/lumabridge-protocol/fuzz/Cargo.toml`), audit advisories and sources separately (fuzz crates depend on `libfuzzer-sys` `NCSA` and unversioned local `{ path = ".." }` crates, which root `licenses`/`bans` reject by design):

```powershell
cargo deny --locked --manifest-path crates/lumabridge-protocol/fuzz/Cargo.toml check advisories sources
```

## 4. Android ARM64 Cross-Build (`aarch64-linux-android`, API 29)

Ensure `ANDROID_HOME` / NDK `28.x` are configured cleanly and run inside `core/` matching `.github/workflows/ci-ffi-poc.yml`:

```powershell
cargo ndk -t arm64-v8a -P 29 --manifest-path Cargo.toml -- build --locked -p lumabridge-protocol --release
cargo ndk -t arm64-v8a -P 29 --manifest-path Cargo.toml -- build --locked -p lumabridge-ffi --features uniffi --release
```

Also build any additional core crates (`lumabridge-security`, `lumabridge-transport`, etc.) as they enter `core/Cargo.toml`.

## 5. Windows Non-Admin & FFI PoC CI Scripts

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File scripts/ci/Invoke-LumaBridgeCiWindowsTests.ps1 -RepoRoot .
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File scripts/ci/Invoke-LumaBridgeFfiPocCi.ps1 -RepoRoot . -SkipBenchmark -RequireCargoDeny
```

(`Invoke-LumaBridgeFfiPocCi.ps1` also checks `cbindgen` header drift automatically on Windows.)

## 6. Fuzzing (Windows MSVC ASan) & Cleanup

- Add MSVC Hostx64 `bin` directory (`clang_rt.asan_dynamic-x86_64.dll`) to `PATH`.
- Invoke `cargo fuzz build` and `cargo fuzz run <target> -- -max_total_time=30` (omit `--locked` on `cargo fuzz run`).
- Remove generated `fuzz/corpus/` and `fuzz/artifacts/` scratch files (keep intentional committed seed files only).

## 7. Honest Result Classification

Report every qualification gate transparently, distinguishing execution outcome from environment capability (matching [ci-and-test-matrix.md](../../../docs/setup/ci-and-test-matrix.md) profiles such as `DETERMINISTIC_CPU_ONLY`, `GPU_REQUIRED`, `WDK_REQUIRED`, `SKIPPED`, and `NOT_MEASURED`):
- `PASS` — executed on the exact final commit SHA with zero failures or relaxed assertions.
- `FAIL` — executed and failed; blocks milestone sign-off.
- `BLOCKED_BY_ENVIRONMENT` — cannot run on current host (no physical GPU, Linux compositor, Android runtime, or elevated WDK/driver session); provide exact reproduction commands.
- `BLOCKED_BY_DEPENDENCY` — waiting on external approval or upstream PR.
- `NOT_TESTED` / `SKIPPED` / `NOT_MEASURED` / `NOT_APPLICABLE` — state explicitly; never present WARP/mock/dry-run passes as hardware/driver proof.
