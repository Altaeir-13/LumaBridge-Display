# Relatório Técnico e de Qualificação `M2` — Primeiro Fluxo Completo `Windows → Linux` (Extensão Real em LAN)

> **Status da Milestone `M2`:** **Implementada e qualificada parcialmente** em loopback GPU real (`NVIDIA NVENC`) + receptor Linux nativo C++20 em CI sintético na branch `feature/m2-windows-linux-lan` (empilhada na cadeia `PR #45 -> PR #44 -> PR #43 -> PR #41 -> dev`; `PR #42` permanece independente). **Não** declarada concluída para hardware físico até execução do roteiro de aceite presencial (`M2_COMPLETE = False`).
> **Gate de Governança:** Seguindo a política do repositório, os PRs `#41`–`#45` permanecem **`OPEN`** para revisão e aprovação externa explícita de integração sequencial (`#41 -> #43 -> #44 -> #45`; `#42` separado).
> **Gate Físico (`LAN` / `Hyprland` / `VA-API` / `IddCx`):** **`BLOCKED_BY_ENVIRONMENT`** para validação presencial em duas máquinas físicas separadas neste ambiente desktop Windows único (sem máquina Linux física com iGPU Intel/AMD `VA-API` + compositor `Wayland`/`Hyprland` conectada em `LAN` e sem sessão administrativa/test-signing autorizada para instalar o pacote `IddCx`).

---

## 1. Arquitetura Entregue

### 1.1 Núcleo, Segurança Operacional e Ponte FFI Aditiva (`core/`)
- **Configuração persistente validada (`core/crates/lumabridge-core/src/config.rs`):** `RuntimeSessionConfig` com serialização/desserialização determinística `key=value`, rejeição de chaves desconhecidas/duplicadas e validação de faixa (resolução `320×240`..`7680×4320`, `1`..`240 FPS`, `1`..`150 Mbps`, modo de transporte, duração de janela de pareamento).
- **Metodologia honesta de telemetria (`core/crates/lumabridge-core/src/{telemetry.rs,node.rs}`):** todos os estágios registram explicitamente `MeasurementOrigin` (`measured`, `estimated`, `synthetic`, `unavailable`), nunca preenchendo zeros sintéticos em ausência de captura/apresentação real e condicionando o estágio `network` ao circuito real `ClockSync`:

| Origem (`MeasurementOrigin`) | Semântica | Onde se aplica na `M2` |
|---|---|---|
| `measured` | Medição direta em relógio monotônico local ou RTT `ClockSync` real | `encode` (NVENC D3D11), `decode` (MFT / VA-API / FFmpeg), `clock_sync_origin` |
| `estimated` | Derivação entre pares com compensação de offset via `ClockSyncPing`/`ClockSyncPong` (`clock_sync_samples >= 1`) | `network` (quando há amostra `ClockSync` válida) e `end_to_end` |
| `synthetic` | Execução explícita de estímulo/gerador sintético (`lumabridge_node` em CI) | `lumabridge_node` com `set_media_origin_synthetic(true)` no runner sintético; no receptor nativo `lumabridge-linux-receiver`, `decode` via `lb_node_receiver_record_timing` permanece `"measured"` (decodificador real FFmpeg/VA-API) |
| `unavailable` | Estágio ausente no ambiente (`samples: 0`, percentis `0` apenas como sentinela acompanhada de `"origin": "unavailable"`) | `capture` no `--m2-nvenc-loopback-selftest` (sem `IddCx`) e `present` sem swapchain/renderizador físico |

- **Higiene e entrada protegida do PIN (`windows/host/{main.cpp,M2LanStreamer.cpp}`, `linux/receiver/src/main.cpp`, `core/crates/lumabridge-core/src/bin/lumabridge_node.rs`):**
  - Fluxo interativo padrão no host Windows solicita o PIN no console com eco desabilitado (`GetConsoleMode`/`SetConsoleMode` limpando `ENABLE_ECHO_INPUT` com guarda RAII de restauração), suportando alternativamente `--lan-pin-stdin` (Windows) e `--pin-stdin` (`lumabridge_node`).
  - O uso legado `--lan-pin` (Windows) e `--pin` (`lumabridge_node`) emite aviso explícito de depreciação/exposição em processo e foi removido dos comandos normais de uso em produção; credenciais sintéticas de CI usam flags/arquivos separados (`--ci-synthetic-pin` e `--rendezvous-in`).
  - Memória contendo o PIN é zerada imediatamente após consumo (`SecureZeroMemory` em C++ e `zeroize::Zeroize` em Rust), e `--endpoint-out` escreve registro atômico (`pair_addr|op_addr|device_id_hex|pin` com criação temporária, `fsync`/`flush` + `rename`) em modo `0600` (`OpenOptionsExt::mode(0o600)` / POSIX `open(..., S_IRUSR | S_IWUSR)`).
- **ABI FFI ao vivo aditiva (`core/crates/lumabridge-ffi/src/node_ffi.rs`, `core/crates/lumabridge-ffi/include/lumabridge_ffi.h`):**
  - Mantidos integralmente todos os `13` exports `lb_core_*` da `M1.1` e os `6` exports iniciais `lb_node_*` da `M1.5`;
  - Adicionados `12` novos exports `lb_node_host_*` e `lb_node_receiver_*` (`31` exports verificados por `DUMPBIN` em `lumabridge_ffi.dll`): `lb_node_host_connect`, `lb_node_host_submit_h264`, `lb_node_host_send_protected_blank`, `lb_node_host_get_telemetry`, `lb_node_host_close`, `lb_node_receiver_start`, `lb_node_receiver_get_endpoints`, `lb_node_receiver_poll_event`, `lb_node_receiver_record_timing`, `lb_node_receiver_get_telemetry`, `lb_node_receiver_export_telemetry_json`, `lb_node_receiver_stop`, com envio periódico (`1 s`) de `ClockSyncPing` em `lb_node_receiver_start` e sem alteração da ABI C `#[repr(C)]`.
  - Zero novas dependências externas adicionadas a `core/Cargo.lock` (todas as compilações executam com `--locked`).
- **Executável auxiliar (`core/crates/lumabridge-core/src/bin/lumabridge_node.rs`):** modo `--h264-annexb-file`, `--op-connect`, `--rendezvous-in`, `--send-blank-end`, `--pin-stdin`, `--ci-synthetic-pin`, tolerância inicial `not_before` (`startup_now.saturating_sub(300)` / TTL `7_200 s`) contra clock skew e `ClockSyncPing`/`try_recv_feedback` no receptor.

### 1.2 Emissor Host Windows (`windows/host/`)
- **Interfaces de pipeline (`windows/host/HostVideoPipeline.h`):** abstração limpa `IVideoFrameSource` e `IVideoEncoder` (`NvencVideoEncoderAdapter`) desacoplando fonte de quadros D3D11 compartilhada (zero readback CPU no caminho GPU) do encoder e do adaptador LAN.
- **Reconfiguração dinâmica de bitrate e IDR (`windows/host/NvencH264Encoder.{h,cpp}`):** implementação de `UpdateDynamicBitrate` via `nvEncReconfigureEncoder` com staging atômico de `nextEncodeConfig` / `nextInitParams` (só comita estado ativo após `NV_ENC_SUCCESS`) e `RequestIdr()` acoplado ao feedback `force_idr_requested` do protocolo.
- **Streamer LAN ao vivo (`windows/host/M2LanStreamer.{h,cpp}`, `windows/host/main.cpp`):** CLI com `--lan-remote`, `--lan-pair-port`, `--lan-op-port`, entrada interativa sem eco ou `--lan-pin-stdin` (`--lan-pin` mantido apenas com aviso de segurança/depreciação), `--lan-peer-id`, `--lan-transport`, `--lan-config`, `--m2-nvenc-loopback-selftest`; teardown limpo em erros iniciais; binário padrão `lumabridge-host.exe` permanece isolado sem dependência de `lumabridge_ffi.dll` (verificado por `DUMPBIN`).

### 1.3 Receptor Nativo Linux C++20 (`linux/receiver/`)
- **Build CMake C++20 (`linux/receiver/CMakeLists.txt`):** detecção automática de `PkgConfig` para `libavcodec`, `libavutil`, `libswscale`, `sdl2`, `SDL2_ttf` (opcional para texto no overlay `BRIDGE_TERMINAL`), com `-Wall -Wextra -Werror`.
- **Configuração e CLI (`linux/receiver/src/Config.{h,cpp}`, `linux/receiver/src/main.cpp`):** leitura/escrita compatível com `RuntimeSessionConfig` do núcleo, escrita atômica de `--endpoint-out` em modo `0600` (`pipe-delimited`: `pair_addr|op_addr|device_id_hex|pin`), `SecureScrub` sobre buffers transitórios de PIN e registro fiel de `presUs = 0` (`unavailable`) sem apresentação gráfica ativa.
- **Decodificador H.264 VA-API (`linux/receiver/src/VaapiH264Decoder.{h,cpp}`):** inicialização DRM render node (`/dev/dri/renderD*` ou `--vaapi-device`), `GetVaapiHwFormat` retornando `AV_PIX_FMT_NONE` quando `--allow-sw-fallback` não foi autorizado (proibindo fallback silencioso para software por política `ADR-0005` / `M2`), download de superfície VA-API para apresentação e conversão `BGRA32` com guarda de bounds `INT_MAX` / `sws_scale`.
- **Apresentação Wayland / X11 & Overlay `BRIDGE_TERMINAL` (`linux/receiver/src/DisplayRenderer.{h,cpp}`):** backend SDL2 nativo com seleção `wayland` / `x11` automática (`WAYLAND_DISPLAY` / `DISPLAY` / `XDG_SESSION_TYPE`) ou `--video-backend`, tela cheia com `ProtectedBlank`, atalho `F12` para overlay diagnóstico `BRIDGE_TERMINAL` livre de pixels/chaves e saída limpa via `Esc` / `Ctrl+Shift+Q`.
- **Testes unitários C++ (`linux/receiver/tests/receiver_tests.cpp`):** executados diretamente pelo binário `lumabridge-linux-receiver-tests` com checagens incondicionais `LB_TEST_CHECK` (funcionais em `Release` com `-DNDEBUG`) cobrindo configuração persistente, parsing de argumentos, limites inválidos e lifecycle.

---

## 2. Achados da Revisão Adversarial e Reauditoria Pós-Externo

- **Campanha M2 inicial (2 rodadas — `12` achados da Rodada 1 resolvidos -> `APPROVE` na Rodada 2):** endurecimento de `receiver_tests.cpp` (`LB_TEST_CHECK` + path por PID), validação JSON C++/Rust, clock monotônico SPAKE2, limites ABI FFI, `tokio::time::interval(8 ms)`, proibição de SW fallback silencioso no VA-API, cleanup em `main.cpp`, wrap de `gopId`, `0600` em `--endpoint-out` e documentação de `--lan-peer-id`.
- **Correções pós-revisão externa (propagadas de `#41 -> #43 -> #44` + endurecimento M2):**
  1. Eliminação do PIN padrão em `lumabridge_node.rs`, criação de `--pin-stdin`, `--ci-synthetic-pin`, prompt interativo sem eco no Windows (`ENABLE_ECHO_INPUT` desabilitado) + `--lan-pin-stdin`, aviso explícito em `--lan-pin`/`--pin` e scrubbing `SecureZeroMemory`/`Zeroize`.
  2. `MeasurementOrigin` (`measured`/`estimated`/`synthetic`/`unavailable`) nos 5 estágios + `end_to_end`, fim da fabricação de `capture=0` / `present=50`, e inclusão de `clock_sync_samples` / `clock_sync_origin` com envio periódico de `ClockSyncPing` no receptor FFI.
  3. Correções propagadas de transporte (`PR #43`: `UdpImpairmentProxy` ordenado em `BinaryHeap`, `CubicConfig::initial_window(128 KiB)`, `packet_threshold=6`, pacing por quadro no emissor e amostragem janelada de perda sincronizada ao cooldown do `BitrateAdvisor`) e clock-skew (`PR #44`: `not_before - 300 s`, TTL `7200 s`, `now_unix()` dinâmico).

---

## 3. Evidências Experimentais Observadas

### 3.1 Loopback Real com Hardware GPU **NVIDIA GeForce RTX 3060 Ti** (`lumabridge-host-ffi-poc.exe --m2-nvenc-loopback-selftest`)
Executado em ambiente local Windows 11 x64 (`rustc 1.100.0`, MSVC `14.51.36231`, Windows SDK `10.0.28000.0`) após todas as correções:
- **Saída direta verificada:**
  `[M2-NVENC-SELFTEST] PASS encoded=60 rx_delivered=60 decoded=60 idr=2 reconf_bps=8000000 blank=1 enc_avg_us=2984 enc_p95_us=3305 dec_avg_us=1439 leaked_bufs=0`
- **Telemetria sanitizada exportada pelo receptor (`lb_node_receiver_export_telemetry_json`):**

```json
{
  "transport_mode": "QuicDatagram",
  "frames_sent": 0,
  "frames_delivered": 60,
  "dropped_frames": 0,
  "idr_requests": 0,
  "protected_blanks": 1,
  "unauthorized_input_drops": 0,
  "clock_sync_rtt_us": 32005,
  "clock_sync_samples": 2,
  "clock_sync_origin": "measured",
  "timestamp_measurement_errors": 0,
  "stages_us": {
    "capture": { "origin": "unavailable", "samples": 0, "p50": 0, "p95": 0, "p99": 0 },
    "encode": { "origin": "measured", "samples": 60, "p50": 2917, "p95": 3305, "p99": 3317 },
    "network": { "origin": "estimated", "samples": 59, "p50": 9492, "p95": 9895, "p99": 9909 },
    "decode": { "origin": "measured", "samples": 60, "p50": 84, "p95": 1758, "p99": 1871 },
    "present": { "origin": "unavailable", "samples": 0, "p50": 0, "p95": 0, "p99": 0 },
    "end_to_end": { "origin": "estimated", "samples": 59, "p50": 12424, "p95": 12450, "p99": 12494 }
  }
}
```

> **Nota sobre o loopback NVENC:** este autoteste exerce estímulo D3D11 NV12, encoding real NVENC (`60` quadros, `2` IDRs), reconfiguração dinâmica em voo para `8.000.000 bps`, transporte QUIC autenticado com `ProtectedBlank`, decodificação MFT no Windows (`60` quadros), `ClockSync` real (`clock_sync_samples = 2`, `clock_sync_rtt_us = 32005`, `clock_sync_origin = "measured"`) e contagem de vazamento FFI (`leaked_bufs = 0`) na mesma máquina. Como não há monitor virtual `IddCx` montado nem swapchain físico acoplado nesse autoteste, os estágios `capture` e `present` reportam explicitamente `"origin": "unavailable"` (`samples: 0`) em vez de zeros simulados, e `network` / `end_to_end` figuram como `"estimated"`.

### 3.2 Cobertura Automatizada Local & CI Remoto
- **Rust Workspace (`core/`):** `cargo fmt --all --check`, `cargo clippy --locked --workspace --all-targets -- -D warnings`, `lumabridge-core` (`10` unit + `6` integração `m1_5`), `lumabridge-ffi` (`8` unit), `lumabridge-protocol`, `lumabridge-security`, `lumabridge-transport`, `cargo deny --locked`, e cross-build Android ARM64 (`cargo ndk -t arm64-v8a -P 29` para `protocol`/`security`/`transport`/`core` e `ffi --features uniffi`) verdes.
- **FFI PoC Windows (`Invoke-LumaBridgeFfiPocCi.ps1`):** `cbindgen` sem drift, `LumaBridgeFfiCCompat.c` (C11) + `LumaBridgeFfiHarness.cpp` (C++20) em Debug e Release (`12` testes nativos C11/C++20 aprovados), `31` exports verificados em `lumabridge_ffi.dll` e isolamento mantido para `lumabridge-host.exe` padrão.
- **Receptor Linux C++20 CI (`.github/workflows/ci-m2-linux-receiver.yml`):** build CMake Release com `-Wall -Wextra -Werror`, execução direta do binário unitário `lumabridge-linux-receiver-tests` e teste E2E dois processos com **fonte sintética FFmpeg (`testsrc2` `1920×1080 @ 60 fps`, perfil H.264 High zerolatency)** transmitindo **`30` quadros por modalidade (`quic-datagram` e `tcp-tls`)** via `lumabridge_node` para `lumabridge-linux-receiver` sob **`Xvfb` (`1920x1080x24`) com `--allow-sw-fallback` explícito**, exigindo os gates mínimos **`frames_decoded >= 20`**, `decode_errors == 0`, `protected_blanks_rendered >= 1`, **`core_telemetry.frames_delivered >= 25`** e `core_telemetry.protected_blanks >= 1`. **Atenção:** esse workflow valida compilação C++20, ABI FFI e fluxo H.264 1080p60 sintético em runner VM sem GPU — **não** constitui qualificação física de hardware `VA-API`.

---

## 4. Limitações de Ambiente e Próxima Execução em Hardware Físico (`BLOCKED_BY_ENVIRONMENT`)

Os itens abaixo pertencem ao aceite físico final da `M2` e permanecem **`BLOCKED_BY_ENVIRONMENT`** neste ambiente desktop Windows único (sem máquina Linux física Intel/AMD `VA-API` + `Wayland`/`Hyprland` conectada em LAN nem estação Windows 11 dedicada/autorizada para instalar driver `IddCx` em `TestSigning` ou executar `tc netem` administrativo):

1. **Extensão real de desktop Windows 11 (`IddCx` -> compartilhamento GPU -> `NVENC`) para máquina física Linux via Ethernet e Wi-Fi LAN:** valida janela real no monitor virtual estendido em `1920×1080 @ 60 FPS` por `>= 60 s`, medindo separadamente `p50`/`p95`/`p99`, origens de telemetria (`MeasurementOrigin`), CPU, GPU, RAM e VRAM.
2. **Qualificação nativa `VA-API` (Intel/AMD iGPU) em compositor `Wayland` (ex.: `Hyprland`) e sessão `X11` sem `--allow-sw-fallback`:** confirma decodificação por hardware real (`VAProfileH264High`) e funcionamento do overlay `F12` (`BRIDGE_TERMINAL`).
3. **Resiliência LAN com perda/jitter (`tc netem`), `ProtectedBlank`, desconexão e rollback limpo:** confirma recuperação via `RequestForceIdr`, desmontagem limpa sem vazamentos (`leaked_bufs == 0`) e restauração completa de ambos os hosts.

O roteiro reproduzível completo em 12 etapas encontra-se em [`docs/setup/m2-windows-linux-lan-guide.md`](../setup/m2-windows-linux-lan-guide.md).
