# Relatório Técnico de Qualificação — M1.1 / M1.1.1: Prova de Conceito Rust ↔ C++ MSVC, Segurança FFI e Portabilidade Android

> **Estado arquitetural dos ADRs:** [`ADR-0004`](ADR-0004-core-language-and-native-boundaries.md) foi promovida a **`Accepted`** em `2026-11-24` após aprovação dos cinco critérios da PoC `M1.1` e auditoria/endurecimento de segurança da FFI em `M1.1.1`. [`ADR-0005`](ADR-0005-transport-and-security-architecture.md) permanece **`Proposed`**, [`wire-protocol-v1.md`](../protocol/wire-protocol-v1.md) permanece **`Draft`** e `M1_COMPLETE = False`.

---

## 1. Resumo Executivo

| Critério de Saída (`ADR-0004`) | Status | Evidência Principal (`M1.1.1` Revalidado) |
|---|---|---|
| **1. Build MSVC Debug (`/MDd`) e Release (`/MD`) + Linkage real no host Windows** | **PASS** | `cl.exe 19.51.36248` (`VCTools=14.51.36231`), C11 (`/std:c11`) + C++20 (`/std:c++20`) + linkage real no [`lumabridge-host.exe`](../../windows/host/main.cpp) (`--ffi-poc-selftest`, `Debug` e `Release`), `lumabridge-host.exe` padrão isolado |
| **2. Benchmark reproduzível de overhead na fronteira FFI (`p99 < 100 µs`, 1.800 pacotes)** | **PASS** | [`LumaBridgeFfiBenchmark.cpp`](../../core/tests/native_cpp/LumaBridgeFfiBenchmark.cpp), 1.800 pacotes sintéticos (`30–150 KiB`, `60 pps`, `29,985 s`): `c_abi_noop p99 = 0,900 µs`, `ffi_borrowed_submit p99 = 56,900 µs`, `paired_borrowed_overhead p99 = 40,200 µs`, `ffi_owned_submit p99 = 25,800 µs`, `paired_owned_overhead p99 = 24,000 µs` *(baseline `M1.1`: `51,0 / 35,5 / 19,7 / 14,8 µs`)* |
| **3. Ciclo de vida consecutivo `>= 100` ciclos + contratos concorrentes sem leak** | **PASS** | 120 ciclos completos, stops concorrentes com barreira (`TestConcurrentExternalStops...`), desconexão concorrente, liberação pós-`destroy` em outra thread, balanço zero em `LbGlobalResourceCounters` e `0` leak de handles (`55 -> 55` Debug e Release) |
| **4. Contenção de pânico (`std::panic::catch_unwind` -> `LB_STATUS_INTERNAL_PANIC`)** | **PASS** | Modos `1..4` na DLL isolada `--features poc-fault-injection` (FFI, worker, pânico pré-commit transacional sem `release` indevido e pós-commit com dreno único), além de pré-leitura segura de `LbAbiHeader` + checagem de alinhamento; símbolo ausente na DLL padrão |
| **5. Cross-build Android ARM64 + geração real de bindings UniFFI Kotlin** | **PASS** | `liblumabridge_ffi.so` (`697.544` B em `M1.1.1` vs `688.920` B em `M1.1`, ELF64 `AArch64` `DYN`, `DT_NEEDED` apenas `libdl.so`/`libc.so`) + `uniffi/lumabridge_ffi/lumabridge_ffi.kt` (`1.765` linhas, `66.553` B). Estados explícitos: `KOTLIN_BINDINGS_GENERATED = True`, `KOTLIN_BINDINGS_FULL_COMPILATION_VERIFIED = False`, `ANDROID_DEVICE_RUNTIME_TESTED = False` |

**Decisão registrada (`M1.1.1`):** todos os cinco critérios de saída e a auditoria de segurança da fronteira FFI foram aprovados sem alterar a pilha funcional `M0`; a [`ADR-0004`](ADR-0004-core-language-and-native-boundaries.md) está formalmente **`Accepted`**. A próxima etapa autorizada para planejamento técnico é a especificação/implementação inicial do núcleo de protocolo `M1.2` (`lumabridge-protocol` / [`wire-protocol-v1.md`](../protocol/wire-protocol-v1.md)), ainda **não iniciada** nesta rodada. O plano de contingência C++20/CMake (`R11`) permanece preservado apenas no histórico da `ADR-0004`.

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
- **Toolchain Android:** Android NDK **`28.2.13676358`** local (`<ANDROID_NDK_HOME>`) e Android NDK **`30.0.16248370`** no runner Linux (`ubuntu-24.04` via `ANDROID_NDK_LATEST_HOME`), `llvm-readelf`.
- **Verificação Miri:** toolchain `nightly` / componente `miri` **não instalado** neste ambiente local (`rustup toolchain list` reportou apenas `stable` e `1.100.0`); logo, verificações dinâmicas Miri não foram executadas e não são reportadas como aprovadas.

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

### 3.2 Auditoria e Endurecimento de Segurança da FFI (`M1.1.1`)

Antes de promover a `ADR-0004`, cinco fragilidades na fronteira FFI/núcleo foram auditadas, reproduzidas e corrigidas incrementalmente mantendo todos os commits anteriores como ancestrais:

1. **Ownership transacional em `lb_core_submit_owned_encoded_frame` (defeito reproduzido em `ff32417`):**
   - *Reprodução controlada pré-correção em `ff32417`:* pânico pré-commit acionava `NativeOwnedBufferGuard::drop` durante o unwind, gerando `REPRO_OBSERVED: status=InternalPanic, native_buffers_freed_during_unwind=1, rx_delta=0, rel_delta=1` (violação de ownership no erro).
   - *Correção (`fix(ffi): guarantee transactional ownership across panic paths`):* assinatura alterada para `*mut LbOwnedBuffer`, remoção integral de `std::mem::forget`, reserva prévia do slot antes do ponto infalível `TransactionalOwnedSlice::commit_ownership()` (que zera `*buffer` no momento do commit), RAII `InFlightToken` e `CallbackInProgressGuard`, incremento de `active_instances` apenas após construção completa e limitação de pré-alocação ansiosa (`MAX_EAGER_PREALLOC_TOTAL_BYTES = 4 MiB`, `<= 8` slots) + teto de slab retido.
   - *Evidência (`Mode 3` e `Mode 4`):* pânico pré-commit deixa `*buffer` intacto (`release` nunca chamado por Rust); pânico pós-commit encontra `*buffer` já zerado e Rust drena/libera uma única vez sem double-free com chamadas defensivas de `lb_core_release_buffer(buffer)`.
2. **Isolamento de pânico de observer durante `mark_faulted`:** `mark_faulted` e recuperação de worker agora envolvem limpeza/notificações em `catch_unwind` dedicado para nunca pular `wait_and_join_worker_external` nem vazar contadores de callback em progresso.
3. **Teardown e `stop` concorrentes (`fix(core): strengthen concurrent stop and teardown contracts`):** adicionado rastreamento `WorkerLifecycle` (`NotSpawned | Active | Joined`), ordem monotônica `notified_rank` (`Created < Running < Stopped < Faulted`) e janelas `running_cb_tid`/`terminal_cb_tid` sinalizadas via `Condvar` + guardas RAII; chamadas externas concorrentes de `lb_core_stop` aguardam até conclusão de callbacks ativos e saída completa da worker thread antes de retornar, garantindo notificação única e zero downgrade `Faulted -> Stopped`.
4. **Pré-leitura e alinhamento do cabeçalho ABI (`fix(ffi): validate ABI headers before accessing versioned structures`):** helpers `read_and_validate_abi_input` e `validate_abi_output` leem **exclusivamente os 16 bytes iniciais de `LbAbiHeader`** e checam alinhamento via `ptr.is_aligned()` antes de criar referências ou ler/escrever structs versionadas (`LbCoreConfig`, `LbEncodedFrameMeta`, `LbCoreMetrics`, `LbGlobalResourceCounters`, `LbAbiLayoutSignature`), além de validação de alinhamento para `handle`, `buffer`, `out_major`/`out_minor`, `out_handle` e `out_len`.
5. **Reprodutibilidade estrita em CI (`ci(ffi): enforce locked dependencies and clarify cross-target validation`):** `--locked` obrigatório em todos os comandos Cargo Windows/Linux/NDK e inclusão explícita de `advisories` em `cargo deny --locked check`.

### 3.3 Verificações Unitárias Rust & `cargo deny` (`M1.1.1`)

- `cargo fmt --all --check`: aprovado (0 diffs).
- `cbindgen` drift check: header gerado idêntico ao [`lumabridge_ffi.h`](../../core/crates/lumabridge-ffi/include/lumabridge_ffi.h) versionado.
- `cargo clippy --locked --workspace --all-targets -- -D warnings`: aprovado com zero warnings em **3 configurações** (`default`, `--features poc-fault-injection`, `--features uniffi`).
- `cargo test --locked --workspace`:
  - `default`: **12/12** (`lumabridge-core`: 7, `lumabridge-ffi`: 5 incluindo testes com structs menores `16 B`/`24 B` e ponteiros desalinhados `+1`)
  - `poc-fault-injection`: **14/14** (`lumabridge-core`: 7, `lumabridge-ffi`: 7 incluindo Modos `1..4` e `lb_core_get_metrics` reentrante dentro de `release`)
  - `uniffi`: **13/13** (`lumabridge-core`: 7, `lumabridge-ffi`: 6 incluindo `uniffi_session_roundtrip`)
- `cargo deny --locked check advisories licenses bans sources` ([`core/deny.toml`](../../core/deny.toml)): **`advisories ok, bans ok, licenses ok, sources ok`** verificado em all-features, `--no-default-features`, `--features poc-fault-injection`, `--features uniffi` e `--features uniffi-cli` (somente warning não bloqueante de duplicata transitiva `syn v2.0.119` vs `v3.0.10` quando `uniffi*` opcionais estão habilitadas).
- Inventário de dependências de crates (`cargo tree --locked`):
  - **Build padrão (`default`) e `poc-fault-injection`:** `Apache-2.0 (2): lumabridge-core@0.1.0, lumabridge-ffi@0.1.0` (**zero crates de terceiros**).
  - **Build opcional (`--features uniffi` / `uniffi-cli`):** `uniffi v0.32.2` como única dependência direta de primeiro nível; `MPL-2.0 (8)` restrita exclusivamente às crates `uniffi* v0.32.2` (`uniffi`, `uniffi_bindgen`, `uniffi_core`, `uniffi_internal_macros`, `uniffi_macros`, `uniffi_meta`, `uniffi_pipeline`, `uniffi_udl`); demais crates transitivas permissivas (`Apache-2.0`, `MIT`, `Unicode-3.0`, `Unlicense`). Veja [`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md).

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

- Compilação **Release x64 (`MSVC 14.51.36231 /O2 /MD`, Rust `--locked --release`)**.
- Resolução de tempo: `QueryPerformanceCounter` com `QPC_Hz = 10.000.000` (`0,1 µs` por tick).
- Método estatístico: população ordenada exata (`ExactPopulation`, índice `ceil(p * N) - 1`).
- Aquecimento: **60 pacotes** executados e totalmente drenados antes da medição.
- Medição em regime permanente (`M1.1.1`): **1.800 pacotes sintéticos** H.264 Annex-B cadenciados a **60,0 pps** (`elapsed = 29,985 s`), tamanhos de **`31.717` a `140.348` bytes** (média `64.676,7` bytes, estritamente dentro de `30–150 KiB`).
- Baseline pareado por amostra: implementação C++20 equivalente (`CppBoundedQueueReference`, mutex + `std::deque` limitada + pool reciclável + `memcpy` + `condition_variable`), alternando a ordem C++/FFI entre iterações pares e ímpares e computando a diferença pareada por amostra (`ffi_us[i] - cpp_ref_us[i]`) antes de calcular percentis.
- Submissão `borrowed` (copia bytes para buffer interno Rust antes de retornar) e `owned` (transfere `LbOwnedBuffer` nativo pré-alocado por ownership transacional sem cópia no thread chamador) medidas separadamente.

### 5.2 Resultados Obtidos (Execução Local Gated Release x64 — `M1.1.1` vs `M1.1`)

| Métrica | `N` | `min` (µs) | `avg` (µs) | `p50` (µs) | `p95` (µs) | **`p99` `M1.1.1` (µs)** | `p99` `M1.1` (µs) | `max` (µs) | Gate `< 100 µs` |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `c_abi_noop` (`lb_core_abi_version`) | 1.800 | 0,000 | 0,457 | 0,400 | 0,700 | **0,900** | 0,800 | 15,000 | Referência ABI pura |
| `cpp_ref_borrowed_submit` (baseline C++) | 1.800 | 5,300 | 18,634 | 14,800 | 39,100 | **69,300** | 51,600 | 312,700 | — |
| `ffi_borrowed_submit` (FFI + cópia) | 1.800 | 3,800 | 16,579 | 13,200 | 36,400 | **56,900** | 51,000 | 196,700 | **PASS** (`56,9 < 100`) |
| `paired_borrowed_overhead` (`ffi - cpp` / amostra) | 1.800 | -265,600 | -2,055 | -1,500 | 19,700 | **40,200** | 35,500 | 183,700 | **PASS** (`40,2 < 100`) |
| `cpp_ref_owned_submit` (baseline C++ owned) | 1.800 | 0,100 | 1,961 | 0,300 | 7,800 | **19,500** | 17,200 | 113,300 | — |
| `ffi_owned_submit` (`LbOwnedBuffer*`) | 1.800 | 0,600 | 4,137 | 2,900 | 10,400 | **25,800** | 19,700 | 77,700 | **PASS** (`25,8 < 100`) |
| `paired_owned_overhead` (`ffi_own - cpp_own`) | 1.800 | -107,300 | 2,177 | 2,200 | 7,500 | **24,000** | 14,800 | 77,500 | **PASS** (`24,0 < 100`) |
| `async_worker_e2e_lat` (enfileiramento -> callback) | 3.600 | 3,800 | 25,500 | 23,100 | 48,700 | **75,100** | 71,900 | 204,600 | Informativo |

- Pacotes processados totais (`warm-up + medição`, ambos os caminhos): `3.720`, `backpressure = 0`, `rust_buf_bal = 0`, `native_buf_bal = 0`, `CountersBalanced=TRUE`, `P99Gate(<100us)=PASS`.
- Comparação `M1.1.1` vs `M1.1`: os contratos transacionais + pré-leitura segura de cabeçalho mantiveram folga ampla de segurança abaixo do corte de `100 µs` (`ffi_borrowed_submit p99 = 56,9 µs`, `ffi_owned_submit p99 = 25,8 µs`, diferença pareada negativa na média/mediana para `borrowed`).
- Nota sobre execuções em CI hospedado: [`Invoke-LumaBridgeFfiPocCi.ps1`](../../scripts/ci/Invoke-LumaBridgeFfiPocCi.ps1) executa `--ci-informative` (`300` pacotes em modo informativo; `ffi_borrowed_submit p99 = 19,6 µs` na execução local de `M1.1.1`) para evitar falsos negativos de jitter de hypervisor compartilhado; a métrica de aprovação da `ADR-0004` é a execução Release local de **1.800 pacotes @ 60 pps** registrada acima.

---

## 6. Critérios 3 e 4 — Estabilidade de Ciclo de Vida (120 Ciclos), Concorrência e Contenção de Pânico

- **Validação de entradas, pré-leitura ABI e alinhamento:** testados em C11 (`LumaBridgeFfiCCompat.c`), C++20 (`LumaBridgeFfiHarness.cpp`) e Rust ponteiros nulos, divergência `abi_major` / `abi_minor` futuro, `struct_size` inválido com structs genuinamente menores (`16 B` e `24 B` preservando sentinela `0xCC` em saída rejeitada), ponteiros desalinhados (`+1` byte), `reserved != 0`, capacidade de fila `0` / `> 256`, codecs não suportados, `session_id == 0`, `display_id == 0xFFFF`, regressão `encode_done_ts_us < capture_ts_us`, buffer de `0` B e `> 8 MiB`, `release == nullptr`, rejeição antes de `start` / após `stop` (sem invocar `release` em submissão rejeitada).
- **Ownership bidirecional, stops concorrentes e pós-`destroy`:** verificadas entregas com `release` síncrono dentro do callback, diferido fora do callback, e **liberação de `LbOwnedBuffer` Rust em outra thread após `lb_core_destroy`** com a DLL ainda carregada (`TestDeferredRustBufferReleaseAfterDestroy`), além de `TestConcurrentExternalStopsWaitForWorkerAndSingleStopped`, saturação `LB_STATUS_BACKPRESSURE`, submissão concorrente com stop reentrante e desconexão abrupta concorrente (`TestAbruptDisconnectRacingConcurrentSubmitters`: `accepted=233/204`, `released=240` sem leaks).
- **120 ciclos consecutivos (`>= 100` exigidos) em `M1.1.1`:**
  - Debug `/MDd`: `11/11` suítes PASS; `handles_before = 55 -> handles_after = 55`, `private_before_kb = 1168 -> private_after_kb = 1164`, `ws_delta_kb = 12`.
  - Release `/MD`: `11/11` suítes PASS; `handles_before = 55 -> handles_after = 55`, `private_before_kb = 1120 -> private_after_kb = 1136`, `ws_delta_kb = 16`.
  - `LbGlobalResourceCounters` ao final em ambos: `active_instances = 0`, `active_worker_threads = 0`, `in_flight_buffers = 0`, `callbacks_in_progress = 0`, `rust_buffers_allocated == rust_buffers_released`, `native_buffers_received == native_buffers_released`.
- **Contenção de pânico (feature `poc-fault-injection` carregada separadamente via `LoadLibraryExW`):**
  - **Modo 1 (pânico na chamada FFI):** retorna `LB_STATUS_INTERNAL_PANIC`, transiciona para `LB_CORE_STATE_FAULTED`, incrementa `panic_faults`, expõe mensagem sanitizada via `lb_core_get_last_error`, notifica `on_state_change(Faulted, InternalPanic)` e finaliza com `lb_core_destroy` sem derrubar o processo C++.
  - **Modo 2 (pânico na worker thread):** worker thread captura pânico via `catch_unwind`, transiciona para `Faulted`, drena e libera `LbOwnedBuffer`s pendentes na fila e notifica `Faulted` + `InternalPanic`.
  - **Modos 3 e 4 (`M1.1.1` — pânicos pré-commit e pós-commit em `submit_owned_encoded_frame`):** comprovam invariante transacional sem double-free (pré-commit mantém `*buffer` e não chama `release`; pós-commit zera `*buffer` e libera uma única vez; `lb_core_release_buffer` defensivo é seguro em ambos).
  - **Limitação documentada na `lumabridge_ffi.h`:** `catch_unwind` contém panics Rust, mas **não** captura exceções fatais de SO (SEH / violação de acesso), abortos de processo ou comportamento indefinido causado por ponteiros nativos inválidos.

---

## 7. Critério 5 — Cross-Build Android ARM64 e Bindings UniFFI Kotlin

Documentação detalhada e comandos reproduzíveis em [`core/android/README.md`](../../core/android/README.md):

- **Estados registrados:** `KOTLIN_BINDINGS_GENERATED = True`, `KOTLIN_BINDINGS_FULL_COMPILATION_VERIFIED = False`, `ANDROID_DEVICE_RUNTIME_TESTED = False`.
- **Biblioteca compartilhada gerada (não versionada no Git):** `core/target/aarch64-linux-android/release/liblumabridge_ffi.so` (`697.544` bytes em `M1.1.1`; `688.920` bytes em `M1.1` inicial) via `cargo ndk -t arm64-v8a -P 29 -- build --locked -p lumabridge-ffi --features uniffi --release`.
- **Inspeção ELF (`llvm-readelf`):** `ELF64`, little-endian, `Type: DYN`, `Machine: AArch64`, `DT_NEEDED` exclusivamente `[libdl.so]` e `[libc.so]`; exporta `lb_core_create` e `14` símbolos `uniffi_lumabridge_ffi*`; `lb_core_poc_trigger_panic` **ausente**.
- **Bindings Kotlin gerados (`uniffi-bindgen --library ... --language kotlin`):** `uniffi/lumabridge_ffi/lumabridge_ffi.kt` (`1.765` linhas, `66.553` bytes), expondo `FfiPocSessionInterface`, `FfiPocSession`, `FfiPocCodec`, `FfiPocState`, `FfiPocException`, `FfiPocMetrics` e `ffiPocAbiVersionString`.
- **Transparência de toolchain Kotlin e execução em dispositivo:** os testes desta etapa cobrem compilação cruzada `.so` ARM64, inspeção ELF/símbolos e geração do código fonte Kotlin em `--library` mode. Como os bindings gerados dependem de JNA (`com.sun.jna.*`) e APIs Android integradas via Gradle, a compilação completa do bytecode Kotlin e os testes em aparelho físico/emulador ficam explicitamente pendentes para a milestone do receptor Android após `M1`.

---

## 8. Regressão `M0` e Automação CI

- Workflows originais preservados intactos (`ci-windows.yml`, `ci-linux-hygiene.yml`), assim como todas as proteções existentes no Ruleset `28020487` de `dev` (ampliado após aprovação deste PR para exigir também os dois jobs da PoC FFI).
- Pipeline dedicado: [`.github/workflows/ci-ffi-poc.yml`](../../.github/workflows/ci-ffi-poc.yml) (`permissions: contents: read`, `persist-credentials: false`, Actions fixadas por SHA-40) executando [`Invoke-LumaBridgeFfiPocCi.ps1`](../../scripts/ci/Invoke-LumaBridgeFfiPocCi.ps1) com `--locked` e `cargo deny --locked check advisories licenses bans sources` no Windows (`windows-2025`), além de Rust checks `--locked` + cross-build Android ARM64 (NDK `30.0.16248370` no runner Linux) + geração Kotlin UniFFI em `ubuntu-24.04`.
- Verificação completa da baseline `M0` (`Invoke-LumaBridgeCiWindowsTests.ps1`) e higiene/DCO (`check_repo_hygiene.py`, `test_repo_hygiene.py`): **zero regressões**.
