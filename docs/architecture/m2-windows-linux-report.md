# Relatório Técnico e de Qualificação `M2` — Primeiro Fluxo Completo `Windows → Linux` (Extensão Real em LAN)

> **Status da Milestone `M2`:** Implementação, qualificação de FFI ao vivo, encoding real **NVIDIA NVENC** e receptor nativo Linux **C++20 (`VA-API` + `Wayland` / `X11` + `BRIDGE_TERMINAL`)** concluídos na branch `feature/m2-windows-linux-lan` (empilhada sobre `PR #44` / `feature/m1-integration` -> `PR #43` -> `PR #42` -> `PR #41` -> `dev`).  
> **Gate de Governança:** Seguindo a política do repositório, o PR da `M2` (`#45`) e os PRs empilhados `#41`–`#44` permanecem **`OPEN`** aguardando revisão humana externa obrigatória do `PR #41`.  
> **Gate Físico (`LAN` / `Hyprland` / `VA-API` / `IddCx`):** **`BLOCKED_BY_ENVIRONMENT`** para validação presencial em duas máquinas físicas separadas neste ambiente desktop Windows único (sem máquina Linux física com iGPU Intel/AMD `VA-API` + compositor `Wayland`/`Hyprland` conectada em `LAN` e sem sessão administrativa/test-signing local para instalar o pacote `IddCx`).

---

## 1. Arquitetura Entregue

### 1.1 Núcleo e Ponte FFI Aditiva (`core/`)
- **Configuração persistente validada (`core/crates/lumabridge-core/src/config.rs`):** `RuntimeSessionConfig` com serialização/desserialização determinística `key=value`, rejeição de chaves desconhecidas/duplicadas e validação de faixa (resolução `320×240`..`7680×4320`, `1`..`240 FPS`, `1`..`150 Mbps`, modo de transporte, duração de janela de pareamento).
- **Telemetria sem diluição sintética (`core/crates/lumabridge-core/src/{telemetry.rs,node.rs}`):** `record_rx_transport_latencies` e `record_rx_decode_present` separam estágios upstream (`encode`/`network`) de estágios locais do receptor (`decode`/`present`), evitando que zeros sintéticos poluam percentis `p50`/`p95`/`p99`.
- **ABI FFI ao vivo aditiva (`core/crates/lumabridge-ffi/src/node_ffi.rs`, `core/crates/lumabridge-ffi/include/lumabridge_ffi.h`):**
  - Mantidos integralmente todos os `13` exports `lb_core_*` da `M1.1` e os `6` exports iniciais `lb_node_*` da `M1.5`;
  - Adicionados `12` novos exports `lb_node_host_*` e `lb_node_receiver_*` (`31` exports verificados por `DUMPBIN` em `lumabridge_ffi.dll`): `lb_node_host_connect`, `lb_node_host_submit_h264`, `lb_node_host_send_protected_blank`, `lb_node_host_get_telemetry`, `lb_node_host_close`, `lb_node_receiver_start`, `lb_node_receiver_get_endpoints`, `lb_node_receiver_poll_event`, `lb_node_receiver_record_timing`, `lb_node_receiver_get_telemetry`, `lb_node_receiver_export_telemetry_json`, `lb_node_receiver_stop`.
  - Validação rigorosa de bounds (`width 320..=7680`, `height 240..=4320`, `fps 1..=240`, `codec == LB_ENCODED_CODEC_H264_ANNEX_B`, `display_id <= 0xFFFE`, `flags <= 0x03`), `SessionTelemetrySummary::default()` em `None`, clock monotônico no rate limiter SPAKE2, laço contínuo de aceitação de pareamento no receptor e permissões `0600` em `--endpoint-out`.
  - Zero novas dependências externas adicionadas a `core/Cargo.lock` (todas as compilações executam com `--locked`).
- **Executável auxiliar (`core/crates/lumabridge-core/src/bin/lumabridge_node.rs`):** modo `--h264-annexb-file`, `--op-connect`, `--rendezvous-in`, `--send-blank-end` e janela de tolerância `not_before` (`300 s`) para clock skew entre processos/máquinas em certificados operacionais efêmeros.

### 1.2 Emissor Host Windows (`windows/host/`)
- **Interfaces de pipeline (`windows/host/HostVideoPipeline.h`):** abstração limpa `IVideoFrameSource` e `IVideoEncoder` (`NvencVideoEncoderAdapter`) desacoplando fonte de quadros D3D11 compartilhada (zero readback CPU no caminho GPU) do encoder e do adaptador LAN.
- **Reconfiguração dinâmica de bitrate e IDR (`windows/host/NvencH264Encoder.{h,cpp}`):** implementação de `UpdateDynamicBitrate` via `nvEncReconfigureEncoder` com staging atômico de `nextEncodeConfig` / `nextInitParams` (só comita estado ativo após `NV_ENC_SUCCESS`) e `RequestIdr()` acoplado ao feedback `force_idr_requested` do protocolo.
- **Streamer LAN ao vivo (`windows/host/M2LanStreamer.{h,cpp}`, `windows/host/main.cpp`):** CLI estendida com `--lan-remote`, `--lan-pair-port`, `--lan-op-port`, `--lan-pin`, `--lan-peer-id`, `--lan-transport`, `--lan-config`, `--m2-nvenc-loopback-selftest`; teardown limpo em erros iniciais; binário padrão `lumabridge-host.exe` permanece isolado sem dependência de `lumabridge_ffi.dll` (verificado por `DUMPBIN`).

### 1.3 Receptor Nativo Linux C++20 (`linux/receiver/`)
- **Build CMake C++20 (`linux/receiver/CMakeLists.txt`):** detecção automática de `PkgConfig` para `libavcodec`, `libavutil`, `libswscale`, `sdl2`, `SDL2_ttf` (opcional para texto no overlay `BRIDGE_TERMINAL`), com `-Wall -Wextra -Werror`.
- **Configuração e CLI (`linux/receiver/src/Config.{h,cpp}`, `linux/receiver/src/main.cpp`):** leitura/escrita compatível com `RuntimeSessionConfig` do núcleo, escrita de `--endpoint-out` com `chmod 0600`, publicação de endereço de pareamento/sessão, prefixo `DeviceId` e PIN SPAKE2 de 8 dígitos.
- **Decodificador H.264 VA-API (`linux/receiver/src/VaapiH264Decoder.{h,cpp}`):** inicialização DRM render node (`/dev/dri/renderD*` ou `--vaapi-device`), `GetVaapiHwFormat` retornando `AV_PIX_FMT_NONE` quando `--allow-sw-fallback` não foi autorizado (proibindo fallback silencioso para software por política `ADR-0005` / `M2`), download de superfície VA-API para apresentação e conversão `BGRA32` com guarda de bounds `INT_MAX` / `sws_scale`.
- **Apresentação Wayland / X11 & Overlay `BRIDGE_TERMINAL` (`linux/receiver/src/DisplayRenderer.{h,cpp}`):** backend SDL2 nativo com seleção `wayland` / `x11` automática (`WAYLAND_DISPLAY` / `DISPLAY` / `XDG_SESSION_TYPE`) ou `--video-backend`, tela cheia com `ProtectedBlank`, atalho `F12` para overlay diagnóstico `BRIDGE_TERMINAL` livre de pixels/chaves e saída limpa via `Esc` / `Ctrl+Shift+Q`.
- **Testes CTest (`linux/receiver/tests/receiver_tests.cpp`):** checagens incondicionais `LB_TEST_CHECK` (funcionais em `Release` com `-DNDEBUG`) cobrindo configuração persistente, parsing de argumentos, limites inválidos e lifecycle.

---

## 2. Achados da Revisão Adversarial Independente (2 Rodadas)

- **Rodada 1 (`REJECT` — 12 achados resolvidos):**
  1. `receiver_tests.cpp` migrado de `assert()` (no-op em `Release` sob `-Werror`) para `LB_TEST_CHECK` e arquivo temporário por PID (`::getpid()`).
  2. `linux/receiver/src/main.cpp` e `windows/host/M2LanStreamer.cpp` validam `exportSt == LB_STATUS_OK && len > 0 && len < sizeof(buf)` antes de imprimir JSON de telemetria; separados histogramas `decode`/`present` de zeros sintéticos upstream (`telemetry.rs` / `node.rs`).
  3. Monotonicidade de relógio (`pair_clock`) passada ao `AuthRateLimiter` em `node_ffi.rs` e `lumabridge_node.rs`, além de laço de retry no receptor até pareamento ou esgotamento das 3 tentativas.
  4. Bounds estritos impostos em `lb_node_host_connect`, `lb_node_receiver_start` e `lb_node_host_submit_h264`.
  5. Substituído `tokio::time::sleep` por `tokio::time::interval(8 ms)` (`MissedTickBehavior::Delay`) para evitar inanição de feedback; encerramento limpo em falhas fatais de envio.
  6. `GetVaapiHwFormat` proíbe fallback SW silencioso (`AV_PIX_FMT_NONE`); validado `sizeBytes <= INT_MAX` e retorno `sws_scale > 0`.
  7. `windows/host/main.cpp` realiza unwinding completo (`asyncH264Worker`, console handler, `stopEvent`, `h264Validator`, `nvencEncoder`, `stimulus`) em falhas iniciais de `--lan-*`; `M2LanStreamer` marca `outSessionClosed` em `LB_STATUS_INVALID_STATE || LB_STATUS_FAULTED`.
  8. `DisplayRenderer::PresentProtectedBlank` verifica `m_impl == nullptr`; `PresentFrame` acumula `stepQuit` sem sobrescrever eventos.
  9. `lb_node_host_get_telemetry` e `lb_node_receiver_get_telemetry` zeram saída via `SessionTelemetrySummary::default()` quando `telemetry` é `None`.
  10. `gopId` realiza wrap `65535 -> 1`; `NvencH264Encoder::UpdateDynamicBitrate` faz staging antes de `nvEncReconfigureEncoder`.
  11. `chmod 0600` aplicado a `--endpoint-out` em Unix (`main.cpp` C++ e `lumabridge_node.rs`).
  12. Documentado uso de `--lan-peer-id` para pinning SPKI explícito junto a `--endpoint-out` em [`docs/setup/m2-windows-linux-lan-guide.md`](../setup/m2-windows-linux-lan-guide.md).
- **Rodada 2 (`APPROVE`):** re-auditoria independente confirmou resolução integral dos 12 achados com zero defeitos críticos/altos/médios pendentes.

---

## 3. Evidências Experimentais Observadas

### 3.1 Loopback Real com Hardware GPU **NVIDIA GeForce RTX 3060 Ti** (`lumabridge-host-ffi-poc.exe --m2-nvenc-loopback-selftest`)
Executado em ambiente local Windows 11 x64 (`rustc 1.100.0`, MSVC `14.51.36231`, Windows SDK `10.0.28000.0`) após todas as correções:
- **Saída direta verificada:**
  `[M2-NVENC-SELFTEST] PASS encoded=60 rx_delivered=60 decoded=60 idr=2 reconf_bps=8000000 blank=1 enc_avg_us=2982 enc_p95_us=3388 dec_avg_us=1303 leaked_bufs=0`
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
  "clock_sync_rtt_us": 0,
  "timestamp_measurement_errors": 0,
  "stages_us": {
    "capture": { "samples": 60, "p50": 0, "p95": 0, "p99": 0 },
    "encode": { "samples": 60, "p50": 2992, "p95": 3388, "p99": 3541 },
    "network": { "samples": 60, "p50": 6247, "p95": 6645, "p99": 9304 },
    "decode": { "samples": 60, "p50": 83, "p95": 1650, "p99": 1741 },
    "present": { "samples": 60, "p50": 50, "p95": 50, "p99": 50 },
    "end_to_end": { "samples": 60, "p50": 9174, "p95": 9270, "p99": 12581 }
  }
}
```

> **Nota sobre o loopback NVENC:** este autoteste exerce captura/estímulo D3D11 NV12, encoding real NVENC (`60` quadros, `2` IDRs), reconfiguração dinâmica em voo para `8.000.000 bps`, transporte QUIC autenticado com `ProtectedBlank`, decodificação MFT no Windows (`60` quadros) e contagem de vazamento FFI (`leaked_bufs=0`) na mesma máquina. Como os relógios locais QPC/monotônicos não passam pelo circuito completo em dois hosts separados, `clock_sync_rtt_us` registra `0` no self-test e o estágio `capture` permanece `0 µs` sem driver virtual IddCx montado.

### 3.2 Cobertura Automatizada Local & CI Remoto
- **Rust Workspace (`core/`):** `cargo fmt --all --check`, `cargo clippy --locked --workspace --all-targets -- -D warnings`, `lumabridge-core` (`9` unit + `5` integração `m1_5`), `lumabridge-ffi` (`8` unit), `lumabridge-protocol`, `lumabridge-security`, `lumabridge-transport`, `cargo deny --locked`, e cross-build Android ARM64 (`cargo ndk -t arm64-v8a -P 29`) verdes.
- **FFI PoC Windows (`Invoke-LumaBridgeFfiPocCi.ps1`):** `cbindgen` sem drift, `LumaBridgeFfiCCompat.c` (C11) + `LumaBridgeFfiHarness.cpp` (C++20) em Debug e Release, `31` exports verificados em `lumabridge_ffi.dll` e isolamento mantido para `lumabridge-host.exe` padrão.
- **Receptor Linux C++20 CI (`.github/workflows/ci-m2-linux-receiver.yml`):** build CMake Release com `-Wall -Wextra -Werror`, `ctest --output-on-failure` e teste ponta-a-ponta com bitstream H.264 real (`ffmpeg` `testsrc2` `1280x720@30`) transmitido via `lumabridge_node` e recebido pelo `lumabridge-linux-receiver` sob `Xvfb` (`SDL_VIDEODRIVER=x11 --allow-sw-fallback`).

---

## 4. Limitações de Ambiente e Próxima Execução em Hardware Físico (`BLOCKED_BY_ENVIRONMENT`)

Os itens abaixo pertencem ao aceite físico final da `M2` e **não puderam ser executados em hardware real dentro deste sandbox Windows único** (`WSL` sem distro Linux gráfica, sem GPU Intel/AMD física nem driver IddCx instalado em modo test-signing nesta estação):

1. **Extensão real de desktop Windows 11 (`IddCx` -> compartilhamento GPU -> `NVENC`) para máquina física Linux via LAN:** valida arrastar janela real para o monitor virtual estendido em `1920×1080 @ 60 FPS`, medindo `p50`/`p95`/`p99`, CPU, RAM, VRAM e confirmando `p95 <= 100 ms` em Ethernet LAN.
2. **Qualificação nativa `VA-API` (Intel/AMD iGPU) em compositor `Wayland` (ex.: `Hyprland`) e sessão `X11`:** confirma que o receptor decodifica por hardware sem recorrer a `--allow-sw-fallback` e responde ao atalho `F12` (`BRIDGE_TERMINAL`).
3. **Resiliência em LAN com `tc netem` (`2%` perda + jitter controlado):** confirma recuperação limpa via `RequestForceIdr` sem artefatos permanentes e desmontagem limpa em desconexão abrupta.

O roteiro reproduzível passo a passo encontra-se em [`docs/setup/m2-windows-linux-lan-guide.md`](../setup/m2-windows-linux-lan-guide.md).
