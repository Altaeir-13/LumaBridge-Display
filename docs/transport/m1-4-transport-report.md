# Relatório Técnico de Qualificação — M1.4: Transporte Operacional (`lumabridge-transport`)

> **Estado arquitetural dos documentos:** [`ADR-0005`](../architecture/ADR-0005-transport-and-security-architecture.md) permanece em **`Proposed`** e [`wire-protocol-v1.md`](../protocol/wire-protocol-v1.md) permanece em **`Draft`**. A promoção definitiva e o congelamento da `v1.0` aguardam o fechamento operacional de ponta a ponta da **`M1.5`** e a aprovação externa do PR base **`feature/m1-security` (`M1.3.1`)**.

---

## 1. Escopo Implementado e Arquitetura (`#![forbid(unsafe_code)]`)

O crate [`core/crates/lumabridge-transport/`](../../core/crates/lumabridge-transport/Cargo.toml) materializa o transporte operacional da [`ADR-0005`](../architecture/ADR-0005-transport-and-security-architecture.md) sobre os contratos de [`lumabridge-protocol`](../../core/crates/lumabridge-protocol/src/lib.rs) e [`lumabridge-security`](../../core/crates/lumabridge-security/src/lib.rs), sem introduzir blocos `unsafe` e mantendo o provedor criptográfico `ring` em **TLS 1.3 exclusivo com mTLS estrito** (resumption e 0-RTT desabilitados):

- **QUIC (`RFC 9000` + `RFC 9221` + `RFC 8899` — [`quic.rs`](../../core/crates/lumabridge-transport/src/quic.rs)):**
  - `QuicTransportEndpoint` constrói `quinn` a partir de `build_tls13_client_config` / `build_tls13_server_config` (`lumabridge-security`), extraindo identidade e binding `EXPORTER-Channel-Binding` (`RFC 9266`) diretamente via `extract_authenticated_quic_session`.
  - Streams unidirecionais dedicados por canal lógico (`ChannelId::Control`, `Media`, `Feedback`, `Input`) validados por `StreamFrameDecoder(..., StreamBindingMode::UnboundSingleChannel)` com mutexes de envio independentes por canal (zero bloqueio HOL cruzado entre controle, feedback, entrada e mídia em `QuicPeerLink`).
  - Modo primário `QuicDatagram` (`RFC 9221` unreliable datagrams) e modo alternativo `QuicStream` (records de `16 KiB` em `Channel 1`).
- **TCP / TLS 1.3 (`TCP_NODELAY` — [`tcp.rs`](../../core/crates/lumabridge-transport/src/tcp.rs)):**
  - Listener e conector `tokio-rustls` sobre `build_tls13_*_config` + `extract_authenticated_session_with_alpn`, com multiplexação `StreamBindingMode::Multiplexed`, prioridade estrita (`Control > ProtectedBlank > Feedback > Input > Media`), descarte pré-socket em TX (`TrySendError::Full`) e fila RX limitada não-bloqueante para mídia (`ProtectedBlank` protegido contra evicção; zero estagnação de controle/feedback na task de leitura).
- **Sinalização Confiável de `ProtectedBlank` ([`connection.rs`](../../core/crates/lumabridge-transport/src/connection.rs)):**
  - `send_video_frame` sempre roteia `FrameKind::ProtectedBlank` pelo stream confiável de `Channel 1` (`encode_stream_frame` / `0x0800`), mesmo quando o modo operacional está em `QuicDatagram`.
  - `recv_media_event` usa `tokio::select! { biased; ... }` e drenagem não bloqueante prévia (`try_recv_media_stream_frame`) garantindo precedência estrita da transição confiável de proteção sobre datagramas atrasados e aposentando `retired_floor` para descartar quadros obsoletos em trânsito.
- **Orçamento MTU em 5 camadas e `DPLPMTUD` ([`mtu.rs`](../../core/crates/lumabridge-transport/src/mtu.rs)):**
  - Mantém piso conservador `1200 B` (`RFC 9000`) com sondagem opcional `MtuDiscoveryConfig` (`RFC 8899`) até `1460 B` e cálculo dinâmico `compute_packet_budget` usando `quinn::Connection::max_datagram_size()` real.
- **Fila TX com Política GOP, Pacing e Adaptação de Taxa ([`queue.rs`](../../core/crates/lumabridge-transport/src/queue.rs), [`metrics.rs`](../../core/crates/lumabridge-transport/src/metrics.rs)):**
  - `MediaTxScheduler` impõe limites por quadros e bytes; se qualquer `P-frame` precisar ser descartado (ou feedback remoto indicar `request_idr = true`), marca `chain_broken = true`, suprime `P-frames` subsequentes da cadeia e aciona `take_tx_force_idr_request()`.
  - `BitrateAdvisor` (AIMD) ajusta a taxa alvo continuamente em `send_video_frame` via `poll_congestion_and_advise_bitrate()` usando `CongestionSnapshot` (`rtt_us`, `packet_loss_ppm`, profundidade de fila) e alimenta `TokenBucketPacer`.
- **Descoberta LAN mDNS + Fallback IP ([`discovery.rs`](../../core/crates/lumabridge-transport/src/discovery.rs)):**
  - Codec DNS-SD puro em Rust para `_lumabridge._udp.local.` + `DiscoveryResponder` / `discover_peers` + `ManualEndpoint`. Campos descobertos permanecem estritamente dicas não confiáveis até a validação mTLS + `TrustStore`.
- **Retomada Vinculada ao Canal e Revogação Imediata:**
  - Extensões opcionais retrocompatíveis em `wire-protocol-v1.md` (`SessionResumeRequest` chave `4` `channel_proof` 32 B e `SessionResumeResponse` chave `5` `rotated_resume_token` 32 B) acopladas a `SessionTokenManager::consume_and_rotate_resume_token`.
  - `ConnectionRegistry::apply_security_action(SecurityAction::DisconnectPeerSessions)` encerra imediatamente conexões QUIC/TCP ativas do par revogado.

---

## 2. Evidências de Qualificação em Sockets Reais e Cross-Build

### 2.1 Suítes Funcionais e Adversariais (`--locked`)

- **`lumabridge-protocol`:** `34/34` PASS (inclui novo teste de `channel_proof` + `rotated_resume_token` + redação `Debug` + rejeição de token em resposta negada).
- **`lumabridge-security`:** `17/17` PASS (`lumabridge-security` + feature opcional `quic` para `extract_authenticated_quic_session`).
- **`lumabridge-transport` (`tests/transport_e2e_tests.rs`, `9/9` PASS):**
  - E2E completo (handshake TLS 1.3 mTLS, `Hello`/`HelloAck`/`NodeCapabilities`, `Heartbeat`, `InputBatch`, vídeo) em `QuicDatagram`, `QuicStream` e `TcpTls`.
  - Isolamento estrito de ALPN (`lumabridge-pair/1` vs `lumabridge/1`), rejeição de par não autorizado e rejeição de mensagens operacionais no canal de pareamento.
  - Revogação em tempo real (`revoke_peer_and_sessions` + `ConnectionRegistry::apply_security_action`) desconectando sessão ativa e bloqueando reconexão subsequente; verificação atômica via `from_link_verified` rejeitando par recém-revogado e limpando registro.
  - Clamping local de `HelloAck.granted_stored_perms` pela `TrustStore` local impedindo escalonamento remoto no iniciador.
  - Filtragem estrita de `session_id` estrangeiro no canal de mídia antes do `Reassembler`.
  - `SessionResumeRequest`/`Response` vinculado ao `EXPORTER-Channel-Binding` da nova conexão com rotação atômica de token e rejeição de replay do token anterior.
  - Detecção determinística de timeout de `Heartbeat` com par silencioso e preservação de flags `VideoFlags::KEYFRAME` / `MIRROR_SOURCE`.
  - Descoberta LAN mDNS UDP (`_lumabridge._udp.local.`) em loopback + fallback manual.
- **`lumabridge-transport` (`tests/impairment_and_recovery_tests.rs`, `3/3` PASS):**
  - Perda `8%`, duplicação `5%`, reordenação `8%` e jitter via [`UdpImpairmentProxy`](../../core/crates/lumabridge-transport/src/impairment.rs): transição para `AwaitingIdr` e recuperação em novo `IDR` limpo sem entregar `P-frames` fora de ordem/corrompidos.
  - `ProtectedBlank` entregue confiavelmente sob perda pesada (`20%` UDP drop + `20 ms` jitter), suprimindo imediatamente quadros `P` dependentes subsequentes no TX e RX.
  - Saturação de fila `MediaTxScheduler` (`chain_broken` + `force_idr_requested`) e mudança dinâmica de banda (`150 kbps -> 12 Mbps`) no `TcpImpairmentProxy` preservando entrega de controle.

---

## 3. Benchmarks Comparativos Reais (`ADR-0005` — `cargo bench --locked -p lumabridge-transport`)

Executado em `--bench` (perfil `bench` otimizado, Windows x64, loopback real OS com proxies deterministicos [`UdpImpairmentProxy` / `TcpImpairmentProxy`](../../core/crates/lumabridge-transport/src/impairment.rs), 45 quadros/cenário com cadência de ~60 fps e malha fechada `MediaFeedback(request_idr)` -> regeneração de IDR no emissor):

| Scenario | Transport | Frame p50 (ms) | Frame p95 (ms) | Frame p99 (ms) | Ctrl p95 (ms) | Delivered | IDR Req | Goodput (Mbps) |
|---|---|---:|---:|---:|---:|---|---:|---:|
| Clean-Loopback | `QuicDatagram` | 0.49 | 16.05 | 16.08 | 1.00 | 45/45 | 0 | 0.78 |
| Clean-Loopback | `QuicStream` | 0.31 | 16.06 | 16.56 | 1.00 | 45/45 | 0 | 0.78 |
| Clean-Loopback | `TcpTls` | 0.23 | 15.95 | 16.06 | 0.00 | 45/45 | 0 | 0.78 |
| WiFi-Mild-0.5pct | `QuicDatagram` | 30.82 | 46.88 | 47.28 | 31.00 | 40/45 | 1 | 0.38 |
| WiFi-Mild-0.5pct | `QuicStream` | 16.38 | 32.16 | 48.60 | 16.00 | 45/45 | 0 | 0.82 |
| WiFi-Mild-0.5pct | `TcpTls` | 30.77 | 46.87 | 47.25 | 32.00 | 45/45 | 0 | 0.77 |
| WiFi-Harsh-2pct | `QuicDatagram` | 234.31 | 566.51 | 583.79 | 78.00 | 29/45 | 6 | 0.33 |
| WiFi-Harsh-2pct | `QuicStream` | 844.28 | 1302.06 | 1334.23 | 95.00 | 45/45 | 0 | 0.47 |
| WiFi-Harsh-2pct | `TcpTls` | 30.69 | 46.36 | 46.63 | 32.00 | 45/45 | 0 | 0.79 |
| Constrained-8Mbps | `QuicDatagram` | 30.76 | 45.00 | 46.95 | 17.00 | 45/45 | 0 | 0.79 |
| Constrained-8Mbps | `QuicStream` | 17.11 | 45.49 | 48.12 | 16.00 | 45/45 | 0 | 0.82 |
| Constrained-8Mbps | `TcpTls` | 30.69 | 46.79 | 47.23 | 32.00 | 45/45 | 0 | 0.79 |

### Interpretação Técnica Honesta dos Resultados Históricos (`45` quadros, `< 1 Mbps`)

1. **Trade-off real sob perda (`WiFi-Harsh-2pct`):**
   - `QuicStream` manteve `45/45` entregas, mas o bloqueio *Head-of-Line* em stream único causou acúmulo de fila atingindo **`1.302 ms` (`1,3 s` em p95)**.
   - `QuicDatagram` evitou explosão de latência de fila via descarte/recuperação `AwaitingIdr` (`6` ciclos `request_idr`, latência média ~4–5x menor que `QuicStream`), ao custo de descartar `P-frames` dependentes (~64% entregues intactos) até o próximo IDR — confirmando que a adição futura de NACK seletivo de curto prazo ou FEC leve (`ADR-0005` §1.4) trará ganho concreto em Wi-Fi de 2%+ perda.
2. **Limitação metodológica explícita do proxy TCP (`TcpImpairmentProxy`):**
   - `TcpImpairmentProxy` atua em user-space entre duas conexões TCP loopback limpas, injetando atraso e teto de banda (`8 Mbps`), **não** perda de segmentos na camada L3/kernel TCP; portanto a linha `WiFi-Harsh-2pct | TcpTls` reflete apenas `base_delay = 12 ms` e não deve ser interpretada como superioridade do TCP sobre perda real de pacotes. Ensaios reais com `tc netem` / WAN/Wi-Fi permanecem necessários antes de promover `ADR-0005` a `Accepted`.
3. **Granularidade de timer do SO em loopback Windows:**
   - Valores discretos ~`15,6 ms` / `31 ms` nos percentis refletem resolução padrão do agendador/timer de sleep no host Windows sob carga sintética em loopback, e não representam medição física sobre adaptador Wi-Fi real.

---

## 4. Qualificação Ampliada Não Administrativa — Perfil Representativo `1080p60` (`~11,85 Mbps`, `180` quadros)

Para superar a limitação de carga do baseline histórico (`45` quadros, `< 1 Mbps`), [`transport_bench.rs`](../../core/crates/lumabridge-transport/benches/transport_bench.rs) foi ampliado com uma suíte representativa **`1080p60` (`180` quadros @ `60 fps`, `IDR = 65.000 B` a cada `60` quadros, `P-frame = 24.000 B`, taxa oferecida nominal `~11,85 Mbps`)** executada em perfil `--bench` otimizado no Windows x64 (`rustc 1.100.0`, loopback real OS + proxies determinísticos), diferenciando explicitamente as 6 dimensões exigidas sem ocultar resultados desfavoráveis.

### 4.1 Investigação Causal Pré-Correção (`4ef26a30`) vs Defeitos Corrigidos

Na execução pré-correção em `4ef26a30`, o cenário `1080p60-LAN-Delay-4ms` (com `drop_ppm = 0`, `jitter_ms = 1`, `reorder_ppm = 0`) havia reportado `0/180` entregas em `QuicDatagram` (`loss_ppm = 30429`) e `60/180` (`p95 = 3309.84 ms`, `loss_ppm = 69077`) em `QuicStream`, além de imprimir percentis inválidos `0.00` quando havia `0` amostras entregues. A investigação empírica comprovou 5 causas combinadas de código/harness (e 1 limitação de timer do SO):

1. **Sonda empírica de timer Windows (SO):** `tokio::time::sleep(4ms) x10` mediu `p50 = 15.29–15.39 ms` e `p95 = 15.68–15.83 ms` na linha base `4ef26a30`, e `p50 = 15.23 ms` / `p95 = 16.49 ms` na execução final pós-correções.
2. **Defeito corrigido — reordenação e clamp de banda no proxy UDP (`impairment.rs`):** `UdpImpairmentProxy` usava `tokio::spawn(sleep)` não ordenado com jitter independente por pacote (reordenando datagramas além do `packet_threshold = 3` do QUIC mesmo com `reorder_ppm = 0`) e aplicava `q_ms.min(500)` sobre o backlog de serialização, o que permitia que fluxos com fila `> 500 ms` (`QuicStream` em `1080p60-Saturated-8Mbps`) ultrapassassem o teto nominal de `8 Mbps` (chegando a `9,96 Mbps`). Substituído por fila ordenada dual-direction (`BinaryHeap<Reverse<ScheduledUdpPacket>>` + `sleep_until_opt`), serialização full-duplex em microssegundos exatos sem clamp `.min(500)` (`schedule_deliver_at`) e preservação estrita de FIFO quando `prof.reorder_ppm == 0` (confirmado pelo teste `udp_proxy_enforces_bandwidth_cap_without_clamping`).
3. **Defeito corrigido — `initial_window` e tolerância de reordenação QUIC (`quic.rs`):** o padrão `~12–14 KB` exigia 5+ RTTs de slow-start (`~31 ms/RTT` sob timer Windows) para escoar um único `IDR` de `65 KB`, excedendo `fragment_timeout_us = 150 ms`. Ajustado para `CubicConfig::initial_window(128 * 1024)`, `initial_rtt(10 ms)` e `packet_threshold(6)` em `build_quinn_transport_config`.
4. **Defeito corrigido — rajada/pacing por fragmento e amostragem janelada alinhada ao `BitrateAdvisor` (`connection.rs` / `metrics.rs`):** `TokenBucketPacer` possuía rajada de `64 KiB` (`< 65 KB` do `IDR`) e dormia entre fragmentos; a rajada foi elevada para `128 * 1024`, o *pacing* de `QuicDatagram` passou a ocorrer uma vez por quadro antes da emissão dos fragmentos (limitado a `(fragment_timeout_us / 2).max(1_000)`), e `poll_congestion_and_advise_bitrate` / `snapshot_congestion` passaram a calcular `loss_ppm` janelado sincronizado com o cooldown de `100 ms` (`min_adjust_interval_us`) do `BitrateAdvisor`, impedindo mascaramento de perdas durante cooldown ou congelamento quando `delta_sent < 10`.
5. **Defeito corrigido — dreno de feedback no emissor e representação de ausência de entregas (`transport_bench.rs`):** o loop TX ignorava `recv_feedback_message()` quando estava atrasado em relação a `next_tick` (`fb_rx = 0` apesar de `idr_req = 16`), e formatava `0` entregas como `0.00`. Adicionado dreno não bloqueante incondicional de `MediaFeedback` por quadro e conversão dos percentis para `Option<f64>`, exibindo `—` quando `0` amostras são entregues.

### 4.2 Tabela Consolidada Pós-Correção (`1080p60` — Latência, Goodput, Entrega, Recuperação de GOP, Saturação e Ambiente)

*(Baseline histórico de `45` quadros revalidado no mesmo código final: `Clean-Loopback` — `QuicDatagram`: `0.83 / 15.65 / 15.91 ms`, `45/45`, `0.80 Mbps`; `QuicStream`: `0.66 / 15.72 / 15.81 ms`, `45/45`, `0.79 Mbps`; `TcpTls`: `0.68 / 15.54 / 15.62 ms`, `45/45`, `0.80 Mbps`; `WiFi-Harsh-2pct` — `QuicDatagram`: `46.78 / 108.43 / 122.50 ms`, `34/45`, `idr = 3`, `0.33 Mbps`; `QuicStream`: `46.08 / 108.91 / 123.27 ms`, `45/45`, `0.79 Mbps`; `TcpTls`: `29.10 / 44.91 / 46.35 ms`, `45/45`, `0.80 Mbps`.)*

| Cenário | Transporte | Latência Quadro `p50 / p95 / p99` (ms) | Latência Controle `p95` (ms) | Taxa Oferecida / Goodput (Mbps) | Taxa de Entrega | Recuperação GOP (`idr_req / idr_sent`, `p95 / max` ms) | Saturação (`tx_drop / rx_dep / advised_Mbps`) | Diag (`rtt_ms / loss_ppm / cwnd / fb_rx`) | Condições Ambientais |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| `1080p60-Clean-12Mbps` | `QuicDatagram` | `0.65 / 1.87 / 2.64` | `17.00` | `11.85 / 11.67` | `180/180 (100.0%)` | `0/3, —` | `0 / 0 / 40.00` | `0.96 / 0 / 212100 / 0` | Sockets OS loopback limpos, sem proxy |
| `1080p60-Clean-12Mbps` | `QuicStream` | `0.65 / 1.65 / 2.19` | `1.00` | `11.85 / 11.68` | `180/180 (100.0%)` | `0/3, —` | `0 / 0 / 40.00` | `0.58 / 0 / 196772 / 0` | Sockets OS loopback limpos, sem proxy |
| `1080p60-Clean-12Mbps` | `TcpTls` | `0.27 / 0.67 / 1.03` | `1.00` | `11.85 / 11.71` | `180/180 (100.0%)` | `0/3, —` | `0 / 0 / 40.00` | `0.00 / 0 / 0 / 0` | Sockets OS loopback limpos, sem proxy |
| `1080p60-LAN-Delay-4ms` | `QuicDatagram` | `14.68 / 29.84 / 46.30` | `17.00` | `11.85 / 7.76` | `120/180 (66.7%)` | `7/3, —` | `0 / 58 / 40.00` | `28.00 / 0 / 298031 / 7` | Loopback + proxy UDP delay `4ms` jitter `1ms` (sem perda L3) |
| `1080p60-LAN-Delay-4ms` | `QuicStream` | `14.77 / 18.54 / 44.28` | `18.00` | `11.85 / 11.61` | `180/180 (100.0%)` | `0/3, —` | `0 / 0 / 40.00` | `31.87 / 0 / 361062 / 0` | Loopback + proxy UDP delay `4ms` jitter `1ms` (sem perda L3) |
| `1080p60-LAN-Delay-4ms` | `TcpTls` | `76.99 / 117.35 / 130.12` | `99.00` | `11.85 / 11.21` | `180/180 (100.0%)` | `0/3, —` | `0 / 0 / 40.00` | `0.00 / 0 / 0 / 0` | Loopback + proxy TCP delay `4ms` (sem perda L3) |
| `1080p60-Saturated-8Mbps` | `QuicDatagram` | `124.11 / 266.22 / 307.57` | `184.00` | `2.54 / 2.51` | `179/180 (99.4%)` | `1/3, —` | `0 / 0 / 2.00` | `46.00 / 0 / 668870 / 0` | Loopback + teto `8 Mbps` user-space (`< 11,85 Mbps` oferecidos) |
| `1080p60-Saturated-8Mbps` | `QuicStream` | `834.27 / 1185.37 / 1200.06` | `1107.00` | `10.20 / 7.66` | `180/180 (100.0%)` | `0/3, —` | `0 / 0 / 2.00` | `993.79 / 0 / 3478264 / 0` | Loopback + teto `8 Mbps` user-space (`< 11,85 Mbps` oferecidos) |
| `1080p60-Saturated-8Mbps` | `TcpTls` | `1142.02 / 2149.56 / 2222.52` | `554.00` | `11.85 / 4.12` | `72/180 (40.0%)` | `0/3, —` | `0 / 0 / 40.00` | `0.00 / 0 / 0 / 0` | Loopback + teto `8 Mbps` user-space (`< 11,85 Mbps` oferecidos) |
| `1080p60-WiFi-Mild-0.5pct-UDP` | `QuicDatagram` | `62.61 / 153.98 / 154.25` | `76.00` | `3.81 / 1.14` | `50/180 (27.8%)` | `43/9, 1263.70/2020.96` | `0 / 96 / 2.62` | `31.02 / 0 / 28854 / 43` | Proxy UDP `0,5%` perda (`8ms` delay, `4ms` jitter); TCP perda L3 **`BLOCKED_BY_ENVIRONMENT`** |
| `1080p60-WiFi-Mild-0.5pct-UDP` | `QuicStream` | `1219.73 / 1730.07 / 1777.59` | `50.00` | `9.05 / 6.15` | `180/180 (100.0%)` | `0/3, —` | `0 / 0 / 3.26` | `31.60 / 7017 / 21783 / 0` | Proxy UDP `0,5%` perda (`8ms` delay, `4ms` jitter); TCP perda L3 **`BLOCKED_BY_ENVIRONMENT`** |
| `1080p60-WiFi-Mild-0.5pct-UDP` | `TcpTls` | **`BLOCKED_BY_ENVIRONMENT`** | — | — | — | — | — | — | `TcpImpairmentProxy` user-space não injeta perda L3 de segmentos TCP |
| `1080p60-WiFi-Harsh-2pct-UDP` | `QuicDatagram` | `284.52 / 284.52 / 284.52` | `1739.00` | `2.36 / 0.03` | `1/180 (0.6%)` | `19/5, 324.37/324.37` | `0 / 3 / 2.00` | `49.48 / 153846 / 4180 / 19` | Proxy UDP `2%` perda + `2%` reordenação; TCP perda L3 **`BLOCKED_BY_ENVIRONMENT`** |
| `1080p60-WiFi-Harsh-2pct-UDP` | `QuicStream` | `117.11 / 164.05 / 164.05` | `123.00` | `1.31 / 0.07` | `6/180 (3.3%)` | `16/4, —` | `0 / 65 / 2.00` | `48.28 / 375000 / 7476 / 16` | Proxy UDP `2%` perda + `2%` reordenação; TCP perda L3 **`BLOCKED_BY_ENVIRONMENT`** |
| `1080p60-WiFi-Harsh-2pct-UDP` | `TcpTls` | **`BLOCKED_BY_ENVIRONMENT`** | — | — | — | — | — | — | `TcpImpairmentProxy` user-space não injeta perda L3 de segmentos TCP |

*(Observação: `—` nas colunas de latência de quadro indica `0` quadros entregues — nunca exibido como `0.00`; na coluna `Recuperação GOP`, `—` indica que nenhuma recuperação por keyframe foi concluída durante a janela.)*

### 4.3 Defeitos Corrigidos vs Limitações Experimentais e Arquiteturais Remanescentes

1. **Latência (`Clean` vs `LAN-Delay-4ms`):** Em `Clean`, os três transportes entregam `180/180` com `p95 <= 1.87 ms`. Em `1080p60-LAN-Delay-4ms`, `QuicStream` e `TcpTls` mantiveram `180/180 (100.0%)` (`p95 = 18.54 ms` e `117.35 ms`), enquanto `QuicDatagram` entregou `120/180` (`p95 = 29.84 ms`) sob variância de timer Windows (`p50 = 15.23 ms`, causando timeout pontual de remontagem de 150 ms quando um IDR coincide com múltiplos *sleeps* de ~16 ms do agendador).
2. **Saturação (`Saturated-8Mbps`) e semântica de `180/180` (não é `60 fps` em tempo real):** Com o teto corrigido sem clamp (`schedule_deliver_at`), `QuicStream` passou a respeitar o limite nominal entregando **`7.66 Mbps <= 8.00 Mbps`** (substituindo a anomalia anterior de `9.96 Mbps` causada por `q_ms.min(500)`). Contudo, entregar **`180/180`** nessa condição com `p95 = 1185.37 ms` (`controle 1107.00 ms`) e `advised = 2.00 Mbps` **não** significa manutenção de `60 fps` em tempo real — significa apenas que todos os quadros acabaram drenados em fila ao longo de uma janela estendida (`~4 s`). `QuicDatagram` entregou `179/180` (`p95 = 266.22 ms`, `2.51 Mbps` após recuo do advisor para `2.00 Mbps`) e `TcpTls` caiu para `72/180 (40.0%)` com `p95 = 2149.56 ms`.
3. **Limitação real sob perda UDP em `1080p60` (`WiFi-Mild-0.5pct` / `WiFi-Harsh-2pct`) — achado desfavorável preservado:**
   - Em `WiFi-Mild-0.5pct-UDP`, `QuicDatagram` entregou **`50/180 (27.8%)`** (`p95 = 153.98 ms`, `goodput = 1.14 Mbps`, `fb_rx = 43`, `idr_sent = 9`, recuperação GOP `p95/max = 1263.70 / 2020.96 ms`), enquanto `QuicStream` entregou **`180/180` com `p95 = 1730.07 ms`** (`loss_ppm = 7017`, `advised = 3.26 Mbps`).
   - Em `WiFi-Harsh-2pct-UDP` (`2%` perda + `2%` reordenação, `57` datagramas por `IDR` de `65 KB` sem NACK/FEC), perder `1` entre `57` datagramas invalida o `IDR` inteiro (`P(sucesso) ≈ 0.98^57 ≈ 31,6%`), levando `cwnd` ao piso (`4180` / `7476` bytes, `loss_ppm = 153846` / `375000`, `advised = 2.00 Mbps`), resultando em **`1/180 (0.6%)` em `QuicDatagram`** e **`6/180 (3.3%)` em `QuicStream`**.
   - Essa limitação é real para transporte QUIC de datagrama puro sem NACK seletivo ou FEC sobre carga CBR de `65 KB/IDR` com baixa cadência de feedback (`rtt ~31–49 ms`), e mantém `ADR-0005` em **`Proposed`** até acoplamento ao encoder (`M2`), mitigação NACK/FEC (`ADR-0005` §1.4) e validação física / `tc netem`.

---

## 5. Bloqueador para Comparação Equivalente L3 (`BLOCKED_BY_ENVIRONMENT`) e Procedimento `tc netem`

- **Bloqueador registrado (`BLOCKED_BY_ENVIRONMENT`):** A comparação equivalente entre `QuicDatagram`, `QuicStream` e `TcpTls` sob **perda real de pacotes na camada IP/L3** (`0,5%`, `2%`, `5%` + jitter) é **impossível com proxies user-space não administrativos no Windows**, pois `TcpImpairmentProxy` opera acima do socket TCP do kernel e não injeta descarte/retransmissão de segmentos TCP. Essa qualificação depende de **host Linux físico (ou VM Linux com kernel `sch_netem`)** e privilégio administrativo `tc netem`.

### Procedimento Reproduzível Equivalente com Linux `tc netem`

> **Nota de escopo na pilha de PRs:** Nesta branch (`PR #43 — M1.4`), o crate `lumabridge-transport` ainda não contém o binário CLI dual-processo `lumabridge_node` (introduzido nas entregas downstream `M1.5 / PR #44` e `M2 / PR #45`). Portanto, fornecem-se abaixo os dois procedimentos: **(A)** executável diretamente neste commit via `transport_bench` sobre `lo` Linux com `sch_netem`, e **(B)** entre dois namespaces isolados (`ip netns` + `veth`) ou dois hosts reais após integração da `M2`.

#### (A) Executável diretamente neste branch (`PR #43`) — Kernel `sch_netem` em Linux `lo`

Execute em Linux com `CAP_NET_ADMIN` (neste cenário, os proxies user-space ficam desativados nos cenários `Clean-*` e o kernel `tc netem` degrada UDP e TCP simetricamente em L3):

```bash
set -euo pipefail
cleanup() { sudo tc qdisc del dev lo root 2>/dev/null || true; }
trap cleanup EXIT

cd core
cargo build --locked --release -p lumabridge-transport --bench transport_bench

# Exemplo para perfil equivalente a WiFi-Mild 0.5%, WiFi-Harsh 2% e Saturated 8 Mbps (+6ms delay):
for PROFILE in \
  "clean:" \
  "wifi-mild:netem delay 8ms 4ms loss 0.5%" \
  "wifi-harsh:netem delay 12ms 8ms loss 2% 25% reorder 2% 50%" \
  "sat-8m:custom"
do
  NAME="${PROFILE%%:*}"
  QDISC="${PROFILE#*:}"
  sudo tc qdisc del dev lo root 2>/dev/null || true
  if [ "$NAME" = "sat-8m" ]; then
    sudo tc qdisc replace dev lo root handle 1: netem delay 6ms
    sudo tc qdisc add dev lo parent 1:1 handle 10: tbf rate 8mbit burst 32kbit latency 50ms
  elif [ -n "$QDISC" ]; then
    sudo tc qdisc replace dev lo root $QDISC
  fi
  echo "=== $NAME ==="
  cargo bench --locked -p lumabridge-transport --bench transport_bench
done
```

#### (B) Entre dois hosts físicos ou `ip netns` + `veth` (requer `lumabridge_node` das entregas downstream `M1.5 / M2`)

Em um único Linux com namespaces isolados (`lb_tx` ↔ `lb_rx` ligados via `veth_tx` ↔ `veth_rx`, evitando roteamento curto-circuitado em `lo`), utilizando o binário `lumabridge_node` disponível a partir do `PR #44`/`#45`:

```bash
set -euo pipefail
cleanup() {
  sudo ip netns del lb_tx 2>/dev/null || true
  sudo ip netns del lb_rx 2>/dev/null || true
}
trap cleanup EXIT

sudo ip netns add lb_tx && sudo ip netns add lb_rx
sudo ip link add veth_tx type veth peer name veth_rx
sudo ip link set veth_tx netns lb_tx && sudo ip link set veth_rx netns lb_rx
sudo ip netns exec lb_tx ip addr add 10.200.1.1/24 dev veth_tx && sudo ip netns exec lb_tx ip link set veth_tx up
sudo ip netns exec lb_rx ip addr add 10.200.1.2/24 dev veth_rx && sudo ip netns exec lb_rx ip link set veth_rx up

# Aplique em lb_tx (ex.: WiFi-Harsh 2%):
sudo ip netns exec lb_tx tc qdisc replace dev veth_tx root netem delay 12ms 8ms loss 2% 25% reorder 2% 50%

cd core
cargo build --locked --release -p lumabridge-core --bin lumabridge_node
BIN=./target/release/lumabridge_node
for TRANS in quic-datagram quic-stream tcp-tls; do
  RDV="/tmp/lb_netem_${TRANS}.rdv"
  rm -f "$RDV"
  sudo ip netns exec lb_rx "$BIN" --mode receiver --transport "$TRANS" --bind 10.200.1.2:0 \
    --frames 600 --fps 60 --endpoint-out "$RDV" --json-report "/tmp/rx_${TRANS}.json" &
  RX_PID=$!
  sleep 1
  sudo ip netns exec lb_tx "$BIN" --mode host --transport "$TRANS" --rendezvous-in "$RDV" \
    --frames 600 --fps 60 --send-blank-end --json-report "/tmp/tx_${TRANS}.json"
  wait "$RX_PID"
done
```

---

## 6. Limitações Conhecidas e Próximos Passos

- Interfaces de adaptador de rede real (`Windows -> Linux` em LAN física) e modelagem L3 equivalente em kernel (`tc netem` sobre `quic-datagram`, `quic-stream` e `tcp-tls`) continuam pendentes para qualificação operacional completa (`BLOCKED_BY_ENVIRONMENT` em sandbox Windows não administrativo).
- `ADR-0005` mantém status **`Proposed`** e `wire-protocol-v1.md` mantém status **`Draft`** até o cumprimento dos critérios de aceitação completos e aprovação humana externa da pilha `#41 → #43 → #44 → #45`.
- Este PR está empilhado sobre `feature/m1-security` (`PR #41`) enquanto `PR #41` aguarda aprovação humana externa; não deve ser integrado antes da aprovação do `PR #41`.
