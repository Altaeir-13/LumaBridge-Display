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
  - Saturação de fila `MediaTxScheduler` (`chain_broken` + `force_idr_requested`) e mudança dinâmica de banda (`1 Mbps -> 12 Mbps`) no `TcpImpairmentProxy` preservando entrega de controle.

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

### Interpretação Técnica Honesta dos Resultados

1. **Trade-off real sob perda (`WiFi-Harsh-2pct`):**
   - `QuicStream` manteve `45/45` entregas, mas o bloqueio *Head-of-Line* em stream único causou acúmulo de fila atingindo **`1.302 ms` (`1,3 s` em p95)**.
   - `QuicDatagram` evitou explosão de latência de fila via descarte/recuperação `AwaitingIdr` (`6` ciclos `request_idr`, latência média ~4–5x menor que `QuicStream`), ao custo de descartar `P-frames` dependentes (~64% entregues intactos) até o próximo IDR — confirmando que a adição futura de NACK seletivo de curto prazo ou FEC leve (`ADR-0005` §1.4) trará ganho concreto em Wi-Fi de 2%+ perda.
2. **Limitação metodológica explícita do proxy TCP (`TcpImpairmentProxy`):**
   - `TcpImpairmentProxy` atua em user-space entre duas conexões TCP loopback limpas, injetando atraso e teto de banda (`8 Mbps`), **não** perda de segmentos na camada L3/kernel TCP; portanto a linha `WiFi-Harsh-2pct | TcpTls` reflete apenas `base_delay = 12 ms` e não deve ser interpretada como superioridade do TCP sobre perda real de pacotes. Ensaios reais com `tc netem` / WAN/Wi-Fi permanecem necessários em `M1.5`/`M2` antes de promover `ADR-0005` a `Accepted`.
3. **Granularidade de timer do SO em loopback Windows:**
   - Valores discretos ~`15,6 ms` / `31 ms` nos percentis refletem resolução padrão do agendador/timer de sleep no host Windows sob carga sintética em loopback, e não representam medição física sobre adaptador Wi-Fi real.

---

## 4. Limitações Conhecidas e Próximos Passos (`M1.5`)

- Interfaces de adaptador de rede real (`Windows -> Linux` em LAN física) e modelagem L3 em kernel (`tc netem`) ainda dependem da integração operacional **`M1.5`** e **`M2`**.
- `ADR-0005` mantém status **`Proposed`** e `wire-protocol-v1.md` mantém status **`Draft`** até a qualificação ponta-a-ponta da `M1.5`.
- Este PR está empilhado sobre `feature/m1-security` (`PR #41`) enquanto `PR #41` aguarda aprovação humana externa; não deve ser integrado antes da aprovação do `PR #41`.
