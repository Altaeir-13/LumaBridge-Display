# Relatório Técnico de Qualificação — M1.1: Prova de Conceito Rust ↔ C++ MSVC, C ABI e Portabilidade Android

> **Estado arquitetural dos ADRs:** [`ADR-0004`](ADR-0004-core-language-and-native-boundaries.md) e [`ADR-0005`](ADR-0005-transport-and-security-architecture.md) permanecem formalmente em **`Proposed`** neste documento até revisão explícita do mantenedor. Os critérios objetivos definidos na `ADR-0004` foram verificados empiricamente nesta etapa `M1.1` para subsidiar essa decisão.

---

## 1. Resumo Executivo

| Critério de Saída (`ADR-0004` §8) | Status | Evidência Principal |
|---|---|---|
| **1. Build MSVC Debug (`/MDd`) e Release (`/MD`) + Linkage real no host Windows** | **PASS** | `cl.exe 19.51.36248` (`VCTools=14.51.36231`), C11 (`/std:c11`) + C++20 (`/std:c++20`) + linkage real no [`lumabridge-host.exe`](../../windows/host/main.cpp) (`--ffi-poc-selftest`, `Debug` e `Release`) |
| **2. Benchmark reproduzível de overhead na fronteira FFI (`p99 < 100 µs`, 1.800 pacotes)** | **PASS** | [`LumaBridgeFfiBenchmark.cpp`](../../core/tests/native_cpp/LumaBridgeFfiBenchmark.cpp), 1.800 pacotes sintéticos (`30–150 KiB`, `60 pps`, `29,987 s`): `c_abi_noop p99 = 0,800 µs`, `ffi_borrowed_submit p99 = 51,000 µs`, `paired_borrowed_overhead p99 = 35,500 µs`, `ffi_owned_submit p99 = 19,700 µs`, `paired_owned_overhead p99 = 14,800 µs` |
| **3. Ciclo de vida consecutivo `>= 100` ciclos (`create -> start -> submit -> stop -> destroy`) sem leak** | **PASS** | 120 ciclos completos (incluindo desconexões abruptas a cada 10º ciclo), balanço zero em `LbGlobalResourceCounters` e `0` leak de handles (`55 -> 55` Debug e Release) |
| **4. Contenção de pânico (`std::panic::catch_unwind` -> `LB_STATUS_INTERNAL_PANIC`)** | **PASS** | Modos `1` (FFI) e `2` (worker thread) na DLL isolada `--features poc-fault-injection` transicionam para `Faulted`, drenam buffers nativos sem vazamento e preservam o processo C++; export ausente na DLL padrão |
| **5. Cross-build Android ARM64 + geração real de bindings UniFFI Kotlin** | **PASS** | `liblumabridge_ffi.so` (`688.920` B, ELF64 `AArch64` `DYN`, `DT_NEEDED` apenas `libdl.so`/`libc.so`) + `uniffi/lumabridge_ffi/lumabridge_ffi.kt` (`1.765` linhas, `66.553` B) |

**Recomendação arquitetural objetiva:** todos os cinco critérios de saída da [`ADR-0004`](ADR-0004-core-language-and-native-boundaries.md) foram atendidos sem desvios funcionais na pilha `M0`. Recomenda-se ao mantenedor **promover a `ADR-0004` de `Proposed` para `Accepted`** após revisão deste relatório e aprovação dos checks remotos, antes de iniciar a implementação de núcleo compartilhado (`lumabridge-protocol`, `lumabridge-security`, `lumabridge-transport` e `lumabridge-core`) na etapa seguinte da `M1`. O plano de contingência C++20/CMake (`R11`) permanece documentado, porém não foi acionado por ausência de falhas de viabilidade.

---

## 2. Escopo, Isolamento e Verificação de Toolchains

### 2.1 Escopo Estritamente Respeitado

- Baseline verificada: `origin/dev == 440ca3ab8889e4985d9a15862301f45a6cea762a` (árvore `8508e989dacac5528e4fdffc198b32fd983dd628`), ancestral de `6b297856` e `23a28046`, worktree isolado `LumaBridge-Display-m1-ffi-poc`, branch `feature/m1-ffi-poc`.
- **Preservação integral da `M0`:** nenhuma alteração foi feita no driver UMDF (`LumaBridgeIddDriver`), protocolo local `LBIF` (`FrameIpcProtocol.h`), `FrameExtractor`, `SharedTexturePool`, `FrameTransport`, `FrameConsumer`, `NvencH264Encoder`, `H264BitstreamValidator`, `.inf`, scripts/testes históricos do driver ou `nvEncodeAPI.h`.
- Não foram implementados `LBWP v1` operacional, pareamento SPAKE2/QR, mTLS, QUIC/TCP/TLS, mDNS ou receptor Linux/app Android completo.

### 2.2 Toolchains Inventariadas e Alinhamento com MSVC 14.51

- **Windows PowerShell:** `5.1.26100.9818`
- **MSVC Toolset (`VCToolsVersion`):** **`14.51.36231`** — corresponde **exatamente** ao requisito `MSVC 14.51` definido na `ADR-0004` (`cl.exe` versão de compilador `19.51.36248` para x64, VS BuildTools `18.7.11925.98`), sem substituição silenciosa de versão.
- **Windows SDK:** `10.0.28000.0` (também disponível `10.0.26100.0`)
- **Toolchain Rust (provisionamento exclusivamente no escopo do usuário `--no-modify-path`, sem modificar `PATH` global nem registro):**
  - `rustup 1.29.3`, `rustc 1.100.0`, `cargo 1.100.0`, `clippy 0.1.100`, `rustfmt 1.11.0-stable`
  - Pinado em [`core/rust-toolchain.toml`](../../core/rust-toolchain.toml) (`channel = "1.100.0"`) com targets `x86_64-pc-windows-msvc` e `aarch64-linux-android`
  - Ferramentas auxiliares: `cbindgen 0.29.4`, `cargo-deny 0.22.1`, `cargo-ndk 4.1.2`
- **Toolchain Android:** Android NDK **`28.2.13676358`** (`<ANDROID_NDK_HOME>`), `llvm-readelf.exe` / `llvm-readobj.exe`, JBR + `kotlinc.bat` (`<ANDROID_STUDIO>\plugins\Kotlin\kotlinc\bin\kotlinc.bat`).

---

## 3. Arquitetura Implementada da PoC (`core/` + Hook Isolado do Host)

### 3.1 Workspace Rust Mínimo ([`core/Cargo.toml`](../../core/Cargo.toml))

- **`lumabridge-core` ([`core/crates/lumabridge-core/src/lib.rs`](../../core/crates/lumabridge-core/src/lib.rs)):**
  - `#![forbid(unsafe_code)]`, **zero** dependências externas (somente `std`).
  - Máquina de estados explícita (`Created -> Running -> Stopping -> Stopped`, ou `Faulted`), fila FIFO limitada (`1..=256`, padrão `64`), pool reciclável para submissão com cópia, `OwnedByteSlice` para buffer externo liberado fora de locks, desconexão abrupta com dreno garantido e encerramento cooperativo idempotente sem auto-*join* reentrante (`worker_thread_id == current_tid`).
- **`lumabridge-ffi` ([`core/crates/lumabridge-ffi/src/lib.rs`](../../core/crates/lumabridge-ffi/src/lib.rs)):**
  - Compilada como **`cdylib`** (preferida na `ADR-0004` para isolamento rigoroso de alocadores e CRT entre `/MDd` e `/MD`) e **`rlib`**.
  - `panic = "unwind"` nos perfis `dev` e `release` para habilitar `std::panic::catch_unwind` na borda `extern "C"` e na *worker thread*.
  - Header C/C++ gerado automaticamente por [`cbindgen`](../../core/crates/lumabridge-ffi/cbindgen.toml) em [`include/lumabridge_ffi.h`](../../core/crates/lumabridge-ffi/include/lumabridge_ffi.h):
    - Handle opaco (`typedef struct LbCoreHandle LbCoreHandle;`)
    - `LbAbiHeader` (`abi_major = 1`, `abi_minor = 0`, `struct_size`, `reserved = 0`), independente do protocolo IPC `LBIF` e do `LBWP v1`
    - Apenas payloads codificados (`H264AnnexB = 1`, `HevcAnnexB = 2`, `Av1Obu = 3`), limite `8 MiB`; handles GPU / frames RGB não cruzam esta borda
    - Transferência explícita bidirecional via `LbOwnedBuffer` (`data`, `len`, `capacity`, `release`, `user_ctx`)
    - Fault-injection **estritamente** isolada atrás de `--features poc-fault-injection` (`#if defined(LUMABRIDGE_FFI_POC_FAULT_INJECTION)`), ausente na DLL padrão de produção

### 3.2 Verificações Unitárias Rust & `cargo deny`

- `cargo fmt --all --check`: aprovado (0 diffs).
- `cbindgen` drift check: header gerado idêntico ao [`lumabridge_ffi.h`](../../core/crates/lumabridge-ffi/include/lumabridge_ffi.h) versionado.
- `cargo clippy --workspace --all-targets -- -D warnings`: aprovado com zero warnings em **3 configurações** (`default`, `--features poc-fault-injection`, `--features uniffi`).
- `cargo test --workspace`:
  - `default`: **5/5** (`lumabridge-core`: 2, `lumabridge-ffi`: 3)
  - `poc-fault-injection`: **6/6** (`lumabridge-core`: 2, `lumabridge-ffi`: 4)
  - `uniffi`: **6/6** (`lumabridge-core`: 2, `lumabridge-ffi`: 4 incluindo `uniffi_session_roundtrip`)
- `cargo deny check licenses bans sources` ([`core/deny.toml`](../../core/deny.toml)): **`bans ok, licenses ok, sources ok`** (somente warning não bloqueante de duplicata transitiva de `syn` v2/v3 quando features opcionais `uniffi` são habilitadas).
- Inventário de dependências de crates:
  - **Build padrão (`default`):** `Apache-2.0 (2): lumabridge-core@0.1.0, lumabridge-ffi@0.1.0` (**zero crates de terceiros**).
  - **Build completo (`--all-features`, incluindo `uniffi` / `uniffi-cli` opcionais):** `MPL-2.0 (8)` restrita exclusivamente às crates `uniffi* v0.32.2` (`uniffi`, `uniffi_bindgen`, `uniffi_core`, `uniffi_internal_macros`, `uniffi_macros`, `uniffi_meta`, `uniffi_pipeline`, `uniffi_udl`); demais crates transitivas permissivas (`Apache-2.0`, `MIT`, `Unicode-3.0`, `Unlicense`). Veja [`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md).

---

## 4. Critério 1 — Interoperabilidade MSVC 14.51 Debug (`/MDd`) & Release (`/MD`) e Linkage no Host

- Harness C11 ([`LumaBridgeFfiCCompat.c`](../../core/tests/native_cpp/LumaBridgeFfiCCompat.c)) + Harness C++20 ([`LumaBridgeFfiHarness.cpp`](../../core/tests/native_cpp/LumaBridgeFfiHarness.cpp)) compilados com `/W4 /WX` em **Debug (`/MDd /Od /D_DEBUG /Zi`)** e **Release (`/MD /O2 /DNDEBUG`)**.
- Igualdade bit a bit `sizeof`/`alignof`/`offsetof` verificada automaticamente entre **C11 == C++20 == Rust** (`lb_core_layout_signature`).
- Integração real isolada no [`windows/host/main.cpp`](../../windows/host/main.cpp) atrás de `#ifdef LUMABRIDGE_ENABLE_FFI_POC` via [`FfiPocAdapter.h`](../../windows/host/FfiPocAdapter.h) / [`FfiPocAdapter.cpp`](../../windows/host/FfiPocAdapter.cpp):
  - Debug `/MDd`: `lumabridge-host-ffi-poc.exe --ffi-poc-selftest` -> `[FFI-POC] PASS lumabridge-host linkage self-test (abi=1.0, packets=2, bytes=6144, active_instances=0, in_flight=0)` (`dumpbin /DEPENDENTS`: `lumabridge_ffi.dll` + `MSVCP140D.dll` / `ucrtbased.dll`, coexistindo sem corrupção de heap com o alocador Rust da `cdylib`).
  - Release `/MD`: `lumabridge-host-ffi-poc.exe --ffi-poc-selftest` -> `[FFI-POC] PASS lumabridge-host linkage self-test (abi=1.0, packets=2, bytes=6144, active_instances=0, in_flight=0)` (`dumpbin /DEPENDENTS`: `lumabridge_ffi.dll` + `MSVCP140.dll`).
  - **Build padrão de produção (`lumabridge-host.exe` sem `-DLUMABRIDGE_ENABLE_FFI_POC`):** compilado e verificado via `dumpbin /DEPENDENTS` — **zero** referência a `lumabridge_ffi.dll` e comportamento funcional `M0` 100% preservado.
  - `dumpbin /EXPORTS` de `lumabridge_ffi.dll` (Debug e Release padrão): exatamente **13 exportações** (`lb_core_poc_trigger_panic` estritamente **ausente**); DLL isolada `--features poc-fault-injection` exporta **14** símbolos para teste dinâmico via `LoadLibraryExW`.

---

## 5. Critério 2 — Benchmark Reproduzível de Overhead FFI (`p99 < 100 µs`)

### 5.1 Metodologia ([`LumaBridgeFfiBenchmark.cpp`](../../core/tests/native_cpp/LumaBridgeFfiBenchmark.cpp))

- Compilação **Release x64 (`MSVC 14.51.36231 /O2 /MD`, Rust `--release`)**.
- Resolução de tempo: `QueryPerformanceCounter` com `QPC_Hz = 10.000.000` (`0,1 µs` por tick).
- Método estatístico: população ordenada exata (`ExactPopulation`, índice `ceil(p * N) - 1`).
- Aquecimento: **60 pacotes** executados e totalmente drenados antes da medição.
- Medição em regime permanente: **1.800 pacotes sintéticos** H.264 Annex-B cadenciados a **60,0 pps** (`elapsed = 29,987 s`), tamanhos de **`31.717` a `140.348` bytes** (média `64.676,7` bytes, estritamente dentro de `30–150 KiB`).
- Baseline pareado por amostra: implementação C++20 equivalente (`CppBoundedQueueReference`, mutex + `std::deque` limitada + pool reciclável + `memcpy` + `condition_variable`), alternando a ordem C++/FFI entre iterações pares e ímpares e computando a diferença pareada por amostra (`ffi_us[i] - cpp_ref_us[i]`) antes de calcular percentis.
- Submissão `borrowed` (copia bytes para buffer interno Rust antes de retornar) e `owned` (transfere `LbOwnedBuffer` nativo pré-alocado sem cópia no thread chamador) medidas separadamente.

### 5.2 Resultados Obtidos (Execução Local Gated Release x64)

| Métrica | `N` | `min` (µs) | `avg` (µs) | `p50` (µs) | `p95` (µs) | **`p99` (µs)** | `max` (µs) | Gate `< 100 µs` |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `c_abi_noop` (`lb_core_abi_version`) | 1.800 | 0,000 | 0,348 | 0,300 | 0,600 | **0,800** | 9,400 | Referência ABI pura |
| `cpp_ref_borrowed_submit` (baseline C++) | 1.800 | 4,600 | 16,006 | 13,300 | 31,600 | **51,600** | 158,900 | — |
| `ffi_borrowed_submit` (FFI + cópia) | 1.800 | 3,300 | 15,217 | 11,900 | 35,500 | **51,000** | 138,400 | **PASS** (`51,0 < 100`) |
| `paired_borrowed_overhead` (`ffi - cpp` / amostra) | 1.800 | -150,700 | -0,789 | -0,900 | 19,600 | **35,500** | 118,000 | **PASS** (`35,5 < 100`) |
| `cpp_ref_owned_submit` (baseline C++ owned) | 1.800 | 0,100 | 1,993 | 0,300 | 8,200 | **17,200** | 80,300 | — |
| `ffi_owned_submit` (`LbOwnedBuffer`) | 1.800 | 0,500 | 3,164 | 2,100 | 7,900 | **19,700** | 119,000 | **PASS** (`19,7 < 100`) |
| `paired_owned_overhead` (`ffi_own - cpp_own`) | 1.800 | -75,500 | 1,171 | 1,400 | 5,600 | **14,800** | 114,300 | **PASS** (`14,8 < 100`) |
| `async_worker_e2e_lat` (enfileiramento -> callback) | 3.600 | 2,500 | 22,913 | 20,400 | 46,400 | **71,900** | 180,400 | Informativo |

- Pacotes processados totais (`warm-up + medição`, ambos os caminhos): `3.720`, `backpressure = 0`, `rust_buf_bal = 0`, `native_buf_bal = 0`.
- Nota sobre execuções em CI hospedado: [`Invoke-LumaBridgeFfiPocCi.ps1`](../../scripts/ci/Invoke-LumaBridgeFfiPocCi.ps1) executa `--ci-informative` (`300` pacotes em modo informativo) para evitar falsos negativos de jitter de hypervisor compartilhado; a métrica de aprovação da `ADR-0004` é a execução Release local de **1.800 pacotes @ 60 pps** registrada acima.

---

## 6. Critérios 3 e 4 — Estabilidade de Ciclo de Vida (120 Ciclos), Drenos e Contenção de Pânico

- **Validação de entradas e contratos de estado:** testados ponteiros nulos, divergência `abi_major` / `abi_minor` futuro, `struct_size` inválido, `reserved != 0`, capacidade de fila `0` / `> 256`, codecs não suportados, `session_id == 0`, `display_id == 0xFFFF`, regressão `encode_done_ts_us < capture_ts_us`, buffer de `0` B e `> 8 MiB`, `release == nullptr`, rejeição antes de `start` / após `stop` (sem invocar `release` em submissão rejeitada).
- **Ownership bidirecional e backpressure:** verificadas entregas com `release` síncrono dentro do callback e **diferido fora do callback** na thread consumidora C++, saturação determinística para `LB_STATUS_BACKPRESSURE` com preservação do ownership no chamador, e submissão concorrente em 4 threads com `lb_core_stop` reentrante de dentro do callback sem deadlock.
- **Desconexão abrupta:** `lb_core_simulate_disconnect` com 4 `LbOwnedBuffer`s nativos enfileirados drenou e liberou todos os 4 buffers fora de locks.
- **120 ciclos consecutivos (`>= 100` exigidos):**
  - Debug `/MDd`: `handles_before = 55 -> handles_after = 55`, `private_before_kb = 1368 -> private_after_kb = 1368`, `ws_delta_kb = 24`.
  - Release `/MD`: `handles_before = 55 -> handles_after = 55`, `private_before_kb = 1128 -> private_after_kb = 1228`, `ws_delta_kb = 28`.
  - `LbGlobalResourceCounters` ao final em ambos: `active_instances = 0`, `active_worker_threads = 0`, `in_flight_buffers = 0`, `callbacks_in_progress = 0`, `rust_buffers_allocated == rust_buffers_released`, `native_buffers_received == native_buffers_released`.
- **Contenção de pânico (feature `poc-fault-injection` carregada separadamente via `LoadLibraryExW`):**
  - **Modo 1 (pânico na chamada FFI):** retorna `LB_STATUS_INTERNAL_PANIC`, transiciona estado para `LB_CORE_STATE_FAULTED`, incrementa `panic_faults`, expõe mensagem sanitizada via `lb_core_get_last_error`, notifica `on_state_change(Faulted, InternalPanic)`, rejeita novas submissões com `LB_STATUS_FAULTED` e finaliza com `lb_core_destroy` sem derrubar o processo C++.
  - **Modo 2 (pânico na worker thread):** worker thread captura o pânico via `catch_unwind`, transiciona para `Faulted`, drena e libera `LbOwnedBuffer`s pendentes na fila, notifica estado `Faulted` + `InternalPanic` e destrói com balanço zero de recursos.
  - **Limitação documentada na `lumabridge_ffi.h`:** `catch_unwind` contém panics Rust, mas **não** captura exceções fatais de SO (SEH / violação de acesso), abortos de processo ou comportamento indefinido causado por ponteiros nativos inválidos.

---

## 7. Critério 5 — Cross-Build Android ARM64 e Bindings UniFFI Kotlin

Documentação detalhada e comandos reproduzíveis em [`core/android/README.md`](../../core/android/README.md):

- **Biblioteca compartilhada gerada (não versionada no Git):** `core/target/aarch64-linux-android/release/liblumabridge_ffi.so` (`688.920` bytes) via `cargo ndk -t arm64-v8a -P 29 ... --features uniffi --release`.
- **Inspeção ELF (`llvm-readelf`):** `ELF64`, little-endian, `Type: DYN`, `Machine: AArch64`, `DT_NEEDED` exclusivamente `[libdl.so]` e `[libc.so]`; exporta `lb_core_*` e `uniffi_lumabridge_ffi_*` / `ffi_lumabridge_ffi_*`; `lb_core_poc_trigger_panic` **ausente**.
- **Bindings Kotlin gerados (`uniffi-bindgen --library ... --language kotlin`):** `uniffi/lumabridge_ffi/lumabridge_ffi.kt` (`1.765` linhas, `66.553` bytes), expondo `FfiPocSessionInterface`, `FfiPocSession`, `FfiPocCodec`, `FfiPocState`, `FfiPocException`, `FfiPocMetrics` e `ffiPocAbiVersionString`.
- **Transparência de toolchain Kotlin:** o código gerado usa `com.sun.jna.*`; `kotlinc` sem a dependência JNA falha estritamente em `unresolved reference 'jna'`. O empacotamento final Gradle/JNA Android é escopo da etapa do receptor Android posterior à `M1`.

---

## 8. Regressão `M0` e Automação CI Adicionada

- Workflows originais preservados intactos (`ci-windows.yml`, `ci-linux-hygiene.yml`), assim como o Ruleset `28020487` de `dev`.
- Novo pipeline dedicado da PoC: [`.github/workflows/ci-ffi-poc.yml`](../../.github/workflows/ci-ffi-poc.yml) (`permissions: contents: read`, `persist-credentials: false`, Actions fixadas por SHA-40) executando [`Invoke-LumaBridgeFfiPocCi.ps1`](../../scripts/ci/Invoke-LumaBridgeFfiPocCi.ps1) no Windows (`windows-2025`) e verificação Rust + cross-build Android ARM64 + `uniffi-bindgen` Kotlin no Linux (`ubuntu-24.04`).
- Verificação completa da baseline `M0` (`Invoke-LumaBridgeCiWindowsTests.ps1`) e higiene/DCO (`check_repo_hygiene.py`, `test_repo_hygiene.py`): **zero regressões**.
