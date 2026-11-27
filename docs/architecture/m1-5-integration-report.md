# Relatório Técnico e de Qualificação `M1.5` — Integração Operacional de Sessões, Contratos C/FFI e Fechamento da `M1`

> **Status da Milestone `M1.5`:** Qualificada tecnicamente na branch `feature/m1-integration` (empilhada sobre `PR #43` / `feature/m1-transport` -> `PR #41` / `feature/m1-security` -> `dev`).  
> **Gate de Governança:** De acordo com a diretiva de governança do repositório, os PRs `#41`, `#42`, `#43` e `#44` permanecem **`OPEN`** aguardando revisão humana externa obrigatória do `PR #41` antes de qualquer merge em `dev` e da declaração formal `M1_COMPLETE = True`.

---

## 1. Resumo Executivo

A etapa **`M1.5`** unifica os crates do núcleo compartilhado em `core/` em um runtime operacional completo sem introduzir dependências externas adicionais no grafo do `Cargo.lock` (somente arestas internas do workspace) e mantendo integralmente todos os 13 símbolos originais `lb_core_*` da `M1.1`:

1. **Contratos multiplataforma em Rust (`core/crates/lumabridge-core/src/contracts.rs`) e C11 (`core/include/`):**
   - Traits e descritores independentes de plataforma: `VirtualDisplayProvider`, `VideoSource`, `VideoEncoder`, `VideoDecoder`, `DisplayRenderer`, `InputInjector`, `PixelFormat`, `ColorMetadata`, `DisplayGeometry`, `DisplayModeSpec` e `FrameDescriptor` (incluindo propagação de `is_hw_protected`).
   - Headers C11/C++20 sem handles opacos de GPU específicos de SO (`DXGI`/`HANDLE` permanecem estritamente fora da ABI multiplataforma): [`lumabridge_display.h`](../../core/include/lumabridge_display.h), [`lumabridge_media.h`](../../core/include/lumabridge_media.h) e [`lumabridge_input.h`](../../core/include/lumabridge_input.h), validados por `_Static_assert` em C11 (`LumaBridgeFfiCCompat.c`) e `cl.exe` + CMake/MSVC.
2. **Runtime de Sessão e Orquestração (`core/crates/lumabridge-core/src/node.rs`):**
   - `LumaBridgeNode` e `ActiveNodeSession` integrando Fase 1 (`ALPN "lumabridge-pair/1"`, `AuthRateLimiter`, orçamento atômico de 3 tentativas PIN SPAKE2-P256, `QrPairingTicket` com pinning anti-MITM de SPKI Ed25519 antes de transmitir `PairQrAuth`, consentimento humano obrigatório via callbacks) e Fase 2 (`ALPN "lumabridge/1"` mTLS estrito, `SessionOpenRequest` com `session_id` CSPRNG não zero, `SessionResumeRequest` com rotação + channel binding TLS 1.3 retornando `(ActiveNodeSession, SessionResumeResponse)`, autorização *default-deny* em 5 fatores com `PermissionUpgradeRequest`/`PermissionUpdate`, `ClockSyncPing/Pong`, propagação confiável de `ProtectedBlank` e `revoke_peer` com desconexão imediata no `ConnectionRegistry`).
3. **Telemetria Sanitizada e Sincronia de Relógio (`core/crates/lumabridge-core/src/telemetry.rs`):**
   - `ClockSyncTracker` estilo NTP (cálculo EWMA em `i128` com clamping seguro em `i64::MIN..=i64::MAX`, fila pendente limitada a `64` pings).
   - `LatencyPercentileTracker` com reservatório limitado (`4096` amostras, `p50`/`p95`/`p99`) por estágio (`capture`, `encode`, `network`, `decode`, `present`, `end_to_end`).
   - Serialização JSON estritamente sanitizada (`SessionTelemetrySummary::to_sanitized_json()`), livre de pixels, coordenadas sensíveis, teclas, tokens ou chaves privadas.
4. **Ponte FFI Aditiva + UniFFI (`core/crates/lumabridge-ffi/src/{node_ffi.rs,uniffi_api.rs}`):**
   - Adição dos 6 símbolos `lb_node_*` (`lb_node_create`, `lb_node_destroy`, `lb_node_local_device_id`, `lb_node_revoke_peer`, `lb_node_is_peer_trusted`, `lb_node_run_loopback_selftest`), elevando a DLL de produção para 19 exports verificados por `DUMPBIN`, sem alterar nenhum dos 13 exports `lb_core_*` da `M1.1` nem acoplar o worker loop M1.1 ao runtime Tokio.
   - Exposição `FfiNodeTelemetry` e `ffi_node_protocol_version()` na interface UniFFI Kotlin/Android.
5. **Endurecimento de Transporte (`core/crates/lumabridge-transport/src/{quic.rs,tcp.rs,connection.rs}`):**
   - Flush explícito pré-teardown em `PairingConnection::flush()` para TCP (`TcpPeerLink::flush_tx`) e QUIC (`QuicPeerLink::flush_control_and_finish` via `stream.finish()` + `stream.stopped()` limitado), eliminando perda intermitente de `PairConfirm`/`PairCancel`.
   - Caminhos não-bloqueantes sem timer do SO (`try_recv_stream_frame` / `try_recv_control_message` / `try_recv_feedback_message`) evitando stalls do timer wheel do Windows (~15,6 ms).

---

## 2. Achados da Revisão Adversarial Independente e Remediações

O código da `M1.5` passou por **3 rodadas de revisão adversarial independente** antes de receber **`VERDICT: APPROVE`**:

- **Rodada 1 (`REJECT` — 2 HIGH, 2 MEDIUM, 4 LOW):**
  - **[HIGH] Escalonamento de privilégio via `PermissionUpdate`:** `Host` agora rejeita qualquer `PermissionUpdate` recebido do `Controller` com `AuthorizationDenied("only Host may issue PermissionUpdate")`; no `Controller`, a aplicação valida `session_id`, expiração, `TrustStore::verify_trusted_peer` ao vivo, `device_id` e `trust_epoch` antes de intersecar com `local_policy ∩ negotiated_caps`. Coberto por teste negativo dedicado.
  - **[HIGH] Overflow em `ClockSyncTracker::process_pong`:** cálculo EWMA migrado para `i128` com clamping para `i64`; coberto por teste com `u64::MAX`/`0`.
  - **[MEDIUM] Bypass parcial de `AuthRateLimiter`:** lógica extraída para `accept_pairing_inner` de modo que todo erro de handshake/desconexão pós-`check_allowed` aciona `record_failure`, e pareamentos aprovados chamam `record_success`.
  - **[MEDIUM] Race de encerramento QUIC no pareamento:** adicionado `QuicPeerLink::flush_control_and_finish` e fechamento coordenado do iniciador.
  - **[LOW] Sincronia do `SessionTokenManager`, retorno de `resume_operational_session`, rigor de `lb_node_run_loopback_selftest` e escrita atômica em `--endpoint-out`:** todos corrigidos e testados.
- **Rodada 2 (`REJECT` — 1 HIGH):**
  - Identificado erro de compilação C++20 em `core/tests/native_cpp/LumaBridgeFfiHarness.cpp` (`LB_NODE_TRANSPORT_QUIC_DATAGRAM` em vez de `LB_NODE_TRANSPORT_KIND_QUIC_DATAGRAM` gerado pelo `cbindgen`). Corrigido e validado na compilação MSVC real (`TestNodeFfiAbiAndLoopbackSmoke`).
- **Rodada 3 (`APPROVE`):**
  - Confirmada resolução integral de todos os achados de código, concorrência, segurança, ABI e governança.

---

## 3. Evidências Experimentais e Medições

### 3.1 Smoke Multi-Processo Sintético 1080p60 (`lumabridge_node` `--release`, 180 quadros @ 60 fps)

Executado localmente entre dois processos independentes de sistema operacional (`--mode receiver` e `--mode host` em `127.0.0.1`):

| Transporte | Quadros Enviados (`TX`) | Quadros Entregues (`RX`) | Drops | Pedidos `IDR` | `encode` (`RX`) | `clock_sync_rtt_us` (`TX`) | Observação |
|---|---:|---:|---:|---:|---:|---:|---|
| **`QuicDatagram`** | `180` | `180` | `0` | `0` | `300 µs` | `17.737 µs` | Entrega 100% em loopback local |
| **`QuicStream`** | `180` | `180` | `0` | `0` | `300 µs` | `27.354 µs` | Entrega 100% via uni-stream por canal |
| **`TcpTls`** | `180` | `180` | `0` | `0` | `300 µs` | `24.542 µs` | Entrega 100% com flush ordenado |

> **Nota de transparência metodológica:** No executável sintético `lumabridge_node`, o campo `network` do relatório `RX` registra `0 µs` em loopback entre dois processos distintos porque cada processo inicializa seu próprio `Instant::now()` independente e o binário sintético de teste não compensa o offset de partida entre processos. Medidas reais de latência de rede unidirecional/RTT com máquinas separadas e perda/jitter induzidos via `tc netem` pertencem ao marco **`M2` (`Windows -> Linux`)**.

### 3.2 Matriz de Verificação Multiplataforma

Todos os gates abaixo foram executados após a versão final dos arquivos:

- `cargo fmt --all --check` & verificação sem drift de `cbindgen` (`core/crates/lumabridge-ffi/include/lumabridge_ffi.h`) -> **`PASS`**.
- `cargo clippy --locked --workspace --all-targets -- -D warnings` (`default`, `--features poc-fault-injection`, `--features uniffi`) -> **`PASS`** (`0` warnings).
- `cargo test --locked --workspace` (`default`, `--features poc-fault-injection`, `--features uniffi`) -> **`PASS`** (suítes unitárias, propriedades `proptest`, golden vectors, recuperação sob perda/reordenação QUIC, integração `M1.5` de 5 testes e FFI com injeção de pânico).
- Qualificação nativa MSVC (`scripts/ci/Invoke-LumaBridgeFfiPocCi.ps1`): compatibilidade C11 (`LumaBridgeFfiCCompat.c`), harness C++20 `Debug`/`Release` (`12` blocos incluindo `TestNodeFfiAbiAndLoopbackSmoke` e `TestPanicContainmentAndDefaultDllIsolation`), self-test do host PoC em `Release` e inspeção `DUMPBIN` confirmando os `19` exports (`13` `lb_core_*` + `6` `lb_node_*`) -> **`PASS`**.
- `cargo deny --locked check advisories licenses bans sources` em `core/`, `core/crates/lumabridge-protocol/fuzz` e `core/crates/lumabridge-security/fuzz` -> **`PASS`**.
- Cross-build Android ARM64 (`aarch64-linux-android`, API `29`) via `cargo ndk -t arm64-v8a -P 29` para `lumabridge-protocol`, `lumabridge-security`, `lumabridge-transport`, `lumabridge-core` e `lumabridge-ffi --features uniffi` -> **`PASS`**.
- Verificação de higiene, licenciamento e DCO (`scripts/ci/check_repo_hygiene.py`) + workflows remotos do GitHub Actions (`Linux Rust Tests + Android ARM64 & UniFFI PoC` e `Windows Rust + MSVC Debug/Release FFI PoC`) -> **`PASS`**.

---

## 4. Evolução Normativa e Fronteira com a `M2`

- [`ADR-0005`](ADR-0005-transport-and-security-architecture.md) promovida de `Proposed` para **`Accepted`** (sujeita apenas à confirmação final no gate de merge em `dev` e validação de rede física / `tc netem` na `M2`).
- [`wire-protocol-v1.md`](../protocol/wire-protocol-v1.md) promovida de `Draft` para **`v1.0`**.
- **Fora do escopo de `M1.5` (endereçado na `M2` e posteriores):** captura DXGI/IDD real e NVENC no host Windows, receiver Linux real (Wayland/KMS, VA-API, `evdev` condicional), descoberta mDNS ponta-a-ponta entre duas máquinas físicas na LAN e qualificação com `tc netem`.
