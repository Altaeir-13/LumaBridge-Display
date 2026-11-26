# Relatório Técnico de Qualificação — M1.2: Especificação e Implementação do Protocolo Binário `LBWP v1`

> **Estado arquitetural dos documentos:** [`wire-protocol-v1.md`](wire-protocol-v1.md) permanece em **`Draft` (Candidata à Estabilização)**, [`ADR-0004`](../architecture/ADR-0004-core-language-and-native-boundaries.md) permanece **`Accepted`**, [`ADR-0005`](../architecture/ADR-0005-transport-and-security-architecture.md) permanece **`Proposed`** e **`M1_COMPLETE = False`**. **`LBWP v1.0` NÃO é declarado congelado definitivamente** até o fechamento da `M1.3` (criptografia `SPAKE2`/QR/mTLS e transporte `QUIC`/`TCP+TLS 1.3`).

---

## 1. Resumo Executivo e Decisões Normativas

O marco **`M1.2`** implementou o crate Rust **`lumabridge-protocol`** em [`core/crates/lumabridge-protocol/`](../../core/crates/lumabridge-protocol/Cargo.toml) sob `#![forbid(unsafe_code)]`, totalmente desacoplado de transporte (`QUIC`/`TCP`), criptografia operacional e camada C ABI/IPC Windows.

Principais ambiguidades normativas resolvidas em [`wire-protocol-v1.md`](wire-protocol-v1.md) e materializadas no código:

1. **Perfil CBOR determinístico (`LBWP-CBOR-v1` / RFC 8949 §4.2.1):** mapas com chaves inteiras não negativas (`Major Type 0`) estritamente crescentes, inteiros mínimos, comprimentos definidos, UTF-8 estrito e limites antes da alocação. Floats, tags, `null`/`undefined` e itens indefinidos são proibidos; chaves duplicadas e truncamentos são rejeitados em todos os modos.
2. **Separação semântica vs representação CBOR:** `CborError::is_representation_error()` separa falhas exclusivamente canônicas (`NonMinimalInteger`, `UnsortedMapKeys`, `IndefiniteLengthForbidden`, toleráveis apenas se `RelaxedOrderAndWidth` for explicitamente configurado) de violações estruturais/semânticas (`DuplicateMapKey`, `ForbiddenType`, `MissingRequiredField`, `ValueOutOfRange`, `InvalidUtf8`).
3. **Framing unificado de 8 bytes + Mídia em Stream (`Channel 1`):** preservado `FrameHeader` (`frame_len: u32 BE`, `channel_id: u8`, `msg_type: u16 BE`, `flags: u8`) com tetos `65.536 B` (`Ch 0`), `16.384 B` (`Ch 1` stream), `4.096 B` (`Ch 2`) e `1.024 B` (`Ch 3`). Registros de mídia em stream (incluindo fallback TCP/TLS) usam exclusivamente `msg_type = 0x0800` (`MediaVideoFragment`), `44 <= frame_len <= 16_384`, e `StreamBindingMode::BoundSingleChannel` bloqueia troca de canal no meio de um stream.
4. **Mapeamento de canais e `Heartbeat`:** `Heartbeat (0x0503)` padronizado exclusivamente no `Channel 2` (`Feedback`). Datagramas de feedback permanecem reservados para extensão pós-`v1.0`. Identificadores lógicos (`0..3`) são estritamente separados de Stream IDs absolutos do `QUIC`.
5. **Versão, flags e campos reservados:** emissor escreve `0`; receptor `v1.0` rejeita qualquer bit ou byte reservado não zero (`FrameHeader.flags & 0xFE`, `VideoPacketHeader.reserved`, `VideoPacketHeader.flags & 0xFFC0`, máscaras de permissão/capacidade). Mensagens desconhecidas com `MUST_UNDERSTAND` (`0x01`) geram rejeição (`ERR_UNSUPPORTED_FEATURE`); sem `MUST_UNDERSTAND`, só podem ser ignoradas em contexto operacional autorizado nos canais `0`, `2` ou `3` (nunca em `"lumabridge-pair/1"` nem no `Channel 1`, e no `Channel 3` apenas com sessão ativa e permissão de entrada).
6. **Separação `LBWP` / `LBIF` / `C ABI`:** nenhuma estrutura interna Rust determina o layout do fio; `FrameIpcProtocol.h` (`LBIF 0x4649424CU`) e `lumabridge_ffi.h` (`LbAbiHeader`) foram preservados intactos.

---

## 2. Inventário de Dependências e Auditoria (`cargo-deny`)

- **Dependências de produção de `lumabridge-protocol@0.1.0` (`core/Cargo.lock`, `--locked`):**
  - Diretas: `ciborium-io 0.2.2` (`Apache-2.0`, `default-features = false, features = ["alloc"]`) e `ciborium-ll 0.2.2` (`Apache-2.0`).
  - Transitivas em build normal: `half 2.7.1` (`MIT OR Apache-2.0`), `zerocopy 0.8.65` (`BSD-2-Clause OR Apache-2.0 OR MIT`) e `zerocopy-derive 0.8.65` (macro em tempo de compilação).
  - Decodificador streaming zero-alocação de cabeçalhos CBOR escolhido por evitar derivação dependente do layout Rust; toda validação de ordenação, minimalidade, duplicidade, profundidade e limites é aplicada normativamente pelo módulo [`cbor.rs`](../../core/crates/lumabridge-protocol/src/cbor.rs).
- **Dependências exclusivas de desenvolvimento (`[dev-dependencies]`, não embarcadas):**
  - `proptest 1.12.0` (`MIT OR Apache-2.0`, `default-features = false, features = ["std"]`).
- **Workspace isolado de fuzzing (`core/crates/lumabridge-protocol/fuzz/Cargo.lock`, excluído de `core/Cargo.toml` e não embarcado):**
  - `libfuzzer-sys 0.4.13` (`(MIT OR Apache-2.0) AND NCSA`), `arbitrary 1.5.0` (`MIT OR Apache-2.0`), além de dependências auxiliares de build do harness (`cc 1.11.3`, `find-msvc-tools 0.1.15`, `jobserver 0.1.35`, `shlex 2.0.1`, `getrandom 0.4.3`, `libc 0.2.191`).
- **Resultado do gate `cargo deny --locked check advisories licenses bans sources`:** **`advisories ok, bans ok, licenses ok, sources ok`** (`EXIT=0`, sem alterar `core/deny.toml`; apenas warning informativo pré-existente de duplicata `syn v2.0.119` vs `v3.0.10` introduzido quando features `uniffi*` opcionais estão presentes no lockfile).

---

## 3. Arquitetura de Módulos, Catálogo e Pipeline de Mídia

- [`version.rs`](../../core/crates/lumabridge-protocol/src/version.rs): `ProtocolVersion`, `Alpn` (`"lumabridge-pair/1"`, `"lumabridge/1"`), `CodecId` (`H264`, `Hevc`, `Av1`), `negotiate_version`.
- [`limits.rs`](../../core/crates/lumabridge-protocol/src/limits.rs): `FramingLimits`, `CborLimits`, `ReassemblyConfig` (`4` frames incompletos/display, `8 MiB` frame, `16 MiB` display, `32 MiB` sessão, `64 MiB` global experimental padrão, `16` displays, `64` frames pendentes, `64 B/fragmento` de metadados, `150 ms` timeout), `RecoveryConfig` (`200 ms` cooldown IDR, janela de reordenação `3` quadros, `FRAME_ID_RENEWAL_THRESHOLD = u32::MAX - 10_000`).
- [`error.rs`](../../core/crates/lumabridge-protocol/src/error.rs): `ErrorCode` (`1..=12`), `ErrorClass` (`FatalStream`, `DropDatagram`, `FrameRejected`, `ContextualError`), erros tipados por camada.
- [`framing.rs`](../../core/crates/lumabridge-protocol/src/framing.rs): `FrameHeader` (8 B), `StreamFrameDecoder` incremental tolerante a cabeçalhos/payloads parciais, múltiplos registros, validação de teto antes da alocação e EOF inequívoco.
- [`cbor.rs`](../../core/crates/lumabridge-protocol/src/cbor.rs): encoder/decoder estrito `LBWP-CBOR-v1` com `UnknownFieldPolicy::SkipBounded` (teto `16` campos desconhecidos).
- [`control.rs`](../../core/crates/lumabridge-protocol/src/control.rs): catálogo completo das **23 mensagens CBOR** (`0x0100..=0x0700`: `PairHello`, `PairSpakeMsg`, `PairQrAuth`, `PairConfirm`, `PairCancel`, `Hello`, `HelloAck`, `NodeCapabilities`, `SessionOpenRequest`, `SessionOpenResponse`, `DisplayConfigUpdate`, `SessionResumeRequest`, `SessionResumeResponse`, `SessionClose`, `PermissionUpgradeRequest`, `PermissionUpdate`, `MediaFeedback`, `ClockSyncPing`, `ClockSyncPong`, `Heartbeat`, `DiagnosticsSummary`, `InputBatch`, `ErrorNotice`), campos `[M1.3-PROVISIONAL]` demarcados e redação de privacidade em `Debug`.
- [`validation.rs`](../../core/crates/lumabridge-protocol/src/validation.rs): validação contextual pura por ALPN, canal, direção, fase, `Permissions` por tipo de `InputEvent`, correlação `session_id` e `SequenceTracker`.
- [`media/header.rs`](../../core/crates/lumabridge-protocol/src/media/header.rs): codec explícito Big-Endian de 44 bytes sem `unsafe`/`transmute`/`repr(packed)`.
- [`media/fragmentation.rs`](../../core/crates/lumabridge-protocol/src/media/fragmentation.rs): `PacketBudget` com separação de 5 camadas (`max_fragment_payload = effective_lbwp_packet_budget - 44`), aritmética verificada `checked_*`, rejeição antecipada sem truncamento e empacotamento `Channel 1`.
- [`media/reassembly.rs`](../../core/crates/lumabridge-protocol/src/media/reassembly.rs): remontagem sem pré-alocação ansiosa (`frag_count=4096` não reserva `8 MiB`), deduplicação idêntica sem dupla contabilização, rejeição de duplicatas/metadados conflitantes, ignorância de fragmentos atrasados pós-descarte/ProtectedBlank e liberação garantida em conclusão, expiração ou remoção. **Ownership pós-entrega:** após entrega de `ReassembledFrame`, o buffer `payload: Vec<u8>` transfere-se ao consumidor e deixa o orçamento interno de remontagem; filas externas de decodificação/jitter devem impor teto próprio nas camadas consumidoras.
- [`media/recovery.rs`](../../core/crates/lumabridge-protocol/src/media/recovery.rs): máquina de estados pura `InitialAwaitingIdr` / `Healthy` / `AwaitingIdr` / `ProtectedBlanked`, cooldown de `200 ms`, wraparound modular de `u16 gop_id`, ocultação imediata em `ProtectedBlank` até novo IDR limpo e sinalização `session_renewal_required`.

---

## 4. Verificações Determinísticas, Property-Based e Fuzzing Local (Windows MSVC ASan)

### 4.1 Suítes Automatizadas (`rustc 1.100.0`, `--locked`)

- **`cargo fmt --all --check`:** aprovado (`0` diffs).
- **`cargo clippy --locked --workspace --all-targets -- -D warnings`:** aprovado com `0` warnings em `default`, `--features poc-fault-injection` e `--features uniffi`.
- **Testes unitários, golden vectors, corpus malformado e property tests (`cargo test --locked --workspace`):**
  - `default`: **`37/37`** (`lumabridge-core`: `7`, `lumabridge-ffi`: `5`, `lumabridge-protocol`: **`25`** = `6` em `golden_vectors.rs` incluindo replay dos `40` vetores de regressão de fuzzing + `5` em `property_tests.rs` + `14` em `protocol_unit_tests.rs`).
  - `--features poc-fault-injection`: **`39/39`** (`7 + 7 + 25`).
  - `--features uniffi`: **`38/38`** (`7 + 6 + 25`).

### 4.2 Campanhas Locais de Fuzzing (`60 s` sequenciais por alvo com AddressSanitizer)

- **Ambiente:** Windows MSVC (`x86_64-pc-windows-msvc`), toolchain separada `nightly-2026-04-01` (`rustc 1.96.0-nightly 48cc71ee8`), `cargo-fuzz 0.13.2`, **`sanitizer=address` ativo (`clang_rt.asan_dynamic-x86_64.dll` via MSVC `14.51.36231`)**, flags `-max_total_time=60 -timeout=5 -rss_limit_mb=2048 -max_len=8192`.
- **Nota metodológica:** ausência de crashes em campanhas finitas de `60 s` aumenta a confiança defensiva sobre as superfícies testadas, mas **não constitui prova matemática universal de ausência de defeitos**.

| Alvo | Duração Efetiva | Execuções | `exec/s` | Corpus Inicial -> Final (Ativo `libFuzzer`) | Cobertura (`cov` / `ft`) | Crashes / Panics / Timeouts / Mem. Violations | Exit |
|---|---:|---:|---:|---|---|---|---|
| `fuzz_framing` | `61,45 s` (`61 s`) | `655.448` | `10.745` | `190 -> 246` (`78 / 6729 B`) | `164 / 527` | `0 / 0 / 0 / 0` | `0` |
| `fuzz_cbor_control` | `61,46 s` (`61 s`) | `1.460.993` | `23.950` | `118 -> 1.805` (`1.586 / 30 KB`) | `2.585 / 4.532` | `0 / 0 / 0 / 0` | `0` |
| `fuzz_video_header` | `61,42 s` (`61 s`) | `3.787.198` | `62.085` | `118 -> 138` (`33 / 1266 B`) | `211 / 259` | `0 / 0 / 0 / 0` | `0` |
| `fuzz_media_reassembly` | `61,44 s` (`61 s`) | `526.712` | `8.634` | `118 -> 758` (`640 / 68 KB`) | `1.121 / 4.855` | `0 / 0 / 0 / 0` | `0` |
| `fuzz_contextual_validation` | `61,45 s` (`61 s`) | `1.518.306` | `24.890` | `118 -> 1.607` (`1.413 / 24 KB`) | `2.201 / 3.731` | `0 / 0 / 0 / 0` | `0` |

- **Regressão determinística:** `40` amostras descobertas (`8` por alvo) exportadas em formato hexadecimal UTF-8 sem bytes `NUL` para [`fuzz_regression_corpus.hex`](../../core/crates/lumabridge-protocol/tests/corpus/fuzz_regression_corpus.hex) e executadas continuamente pelo teste `fuzz_regression_corpus_never_panics`.

---

## 5. Benchmark Sintético (Estreitamente Informativo)

Executado via `cargo bench --locked -p lumabridge-protocol` (`rustc 1.100.0`, perfil release, `std::hint::black_box`). **Classificação: estritamente informativo** — não estabelece thresholds nem representa latência ponta-a-ponta com GPU/rede real. O benchmark histórico da FFI (`LumaBridgeFfiBenchmark.cpp`) foi preservado sem reexecução (`-SkipBenchmark`).

- **Framing / Headers (`200` warm-up, `2.000` amostras):**
  - `stream_frame_encode_256b`: `avg = 95,8 ns`, `p50 = 100 ns`, `p95 = 100 ns`, `p99 = 100 ns`, `max = 400 ns`
  - `stream_frame_decode_256b`: `avg = 140,9 ns`, `p50 = 100 ns`, `p95 = 200 ns`, `p99 = 200 ns`, `max = 200 ns`
  - `video_header_44b_roundtrip`: `avg = 52,5 ns`, `p50 = 100 ns`, `p95 = 100 ns`, `p99 = 100 ns`, `max = 100 ns`
- **CBOR determinístico (`200` warm-up, `2.000` amostras):**
  - `Hello (63 B)`: encode `avg = 136,8 ns` (`p99 = 200 ns`, `max = 17.100 ns`); decode `avg = 664,9 ns` (`p99 = 1.000 ns`, `max = 7.300 ns`)
  - `MediaFeedback (43 B)`: encode `avg = 157,4 ns` (`p99 = 200 ns`, `max = 200 ns`); decode `avg = 676,1 ns` (`p99 = 700 ns`, `max = 5.000 ns`)
  - `InputBatch 4 eventos (47 B)`: encode `avg = 204,6 ns` (`p99 = 300 ns`, `max = 300 ns`); decode `avg = 1.165,7 ns` (`p99 = 1.400 ns`, `max = 6.800 ns`)
- **Fragmentação e remontagem sintética (`budget = 1.136 B`, payload/frag `1.092 B`, `30` warm-up, `300` amostras):**
  - **`30 KiB` (`29` frags, `1.276 B` hdr wire, `1.856 B` metadados):** frag `avg = 1,72 µs` / `p99 = 1,80 µs` (`16.996,8 MiB/s`); reasm `avg = 4,68 µs` / `p99 = 5,10 µs` (`6.255,1 MiB/s`)
  - **`80 KiB` (`76` frags, `3.344 B` hdr wire, `4.864 B` metadados):** frag `avg = 15,60 µs` / `p99 = 28,10 µs` (`5.007,3 MiB/s`); reasm `avg = 60,21 µs` / `p99 = 96,20 µs` (`1.297,5 MiB/s`)
  - **`150 KiB` (`141` frags, `6.204 B` hdr wire, `9.024 B` metadados):** frag `avg = 47,73 µs` / `p99 = 82,80 µs` (`3.068,7 MiB/s`); reasm `avg = 82,43 µs` / `p99 = 160,70 µs` (`1.777,1 MiB/s`)

---

## 6. Portabilidade, Preservação de Baseline e Pendências para `M1.3`

- **Android ARM64:** compilado localmente com sucesso via Android NDK `28.2.13676358` (`cargo ndk -t arm64-v8a -P 29 -- build --locked -p lumabridge-protocol --release`, `liblumabridge_protocol.rlib = 2.307.196 bytes`) e integrado em [`.github/workflows/ci-ffi-poc.yml`](../../.github/workflows/ci-ffi-poc.yml). **Limitação explícita:** `lumabridge-protocol` ainda **não** foi acoplado ao runtime da `lumabridge-ffi`, nem ao receptor Android/Linux.
- **Preservação integral da `M0` / `M1.1.1`:** baseline `Windows` (driver IddCx, `FrameIpcProtocol.h`, `NvencH264Encoder`, `LumaBridgeIddDriver.inf`, scripts), C ABI (`lumabridge_ffi.h`), thresholds históricos e os seis worktrees anteriores permaneceram intactos. Issues `#33` e `#34` não foram alteradas.
- **Pendências estritamente reservadas à `M1.3`:** definição canônica do transcript de pareamento, escolha definitiva do label TLS Exporter (`RFC 9266` vs aplicação), separação criptográfica de domínios, travamento do formato SPKI/assinatura nos campos `[M1.3-PROVISIONAL]`, algoritmo MAC/HKDF de confirmação `SPAKE2`, expiração e uso único de tokens, política `0-RTT`, além de implementação real de transporte `QUIC` / `TCP+TLS 1.3`, `DPLPMTUD` (`RFC 8899`), `Trust Store` e `mDNS`.
