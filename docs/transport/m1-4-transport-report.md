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

Para superar a limitação de carga do baseline histórico (`45` quadros, `< 1 Mbps`), [`transport_bench.rs`](../../core/crates/lumabridge-transport/benches/transport_bench.rs) foi ampliado com uma suíte representativa **`1080p60` (`180` quadros @ `60 fps`, `IDR = 65.000 B` a cada `60` quadros, `P-frame = 24.000 B`, taxa oferecida nominal `~11,85 Mbps`)** executada em perfil `--bench` otimizado no Windows x64 (`rustc 1.100.0`, loopback real OS + proxies determinísticos), diferenciando explicitamente as 6 dimensões exigidas sem ocultar resultados desfavoráveis:

### 4.1 Tabela Consolidada (`1080p60` — Latência, Goodput, Entrega, Recuperação de GOP, Saturação e Ambiente)

| Cenário | Transporte | Latência Quadro `p50 / p95 / p99` (ms) | Latência Controle `p95` (ms) | Taxa Oferecida / Goodput (Mbps) | Taxa de Entrega | Recuperação GOP (`idr_req / idr_sent`, `p95 / max` ms) | Saturação (`tx_drop / rx_dep / advised_Mbps`) | Condições Ambientais |
|---|---|---:|---:|---:|---:|---:|---:|---|
| `1080p60-Clean-12Mbps` | `QuicDatagram` | `0.36 / 0.44 / 12.30` | `1.00` | `11.85 / 11.70` | `180/180 (100.0%)` | `0/3, —` | `0 / 0 / 40.00` | Sockets OS loopback limpos, sem proxy |
| `1080p60-Clean-12Mbps` | `QuicStream` | `0.41 / 0.60 / 0.65` | `1.00` | `11.85 / 11.68` | `180/180 (100.0%)` | `0/3, —` | `0 / 0 / 40.00` | Sockets OS loopback limpos, sem proxy |
| `1080p60-Clean-12Mbps` | `TcpTls` | `0.17 / 0.23 / 0.28` | `0.00` | `11.85 / 11.69` | `180/180 (100.0%)` | `0/3, —` | `0 / 0 / 40.00` | Sockets OS loopback limpos, sem proxy |
| `1080p60-LAN-Delay-4ms` | `QuicDatagram` | `0.00 / 0.00 / 0.00` | `32.00` | `2.11 / 0.00` | `0/180 (0.0%)` | `16/3, —` | `0 / 176 / 2.00` | Loopback + proxy UDP delay `4ms` jitter `1ms` (sem perda L3) |
| `1080p60-LAN-Delay-4ms` | `QuicStream` | `3729.09 / 4200.98 / 4262.35` | `81.00` | `3.37 / 1.71` | `120/180 (66.7%)` | `16/4, 4819.71/4819.71` | `0 / 53 / 2.00` | Loopback + proxy UDP delay `4ms` jitter `1ms` (sem perda L3) |
| `1080p60-LAN-Delay-4ms` | `TcpTls` | `66.87 / 116.77 / 129.40` | `71.00` | `11.85 / 11.35` | `180/180 (100.0%)` | `0/3, —` | `0 / 0 / 40.00` | Loopback + proxy TCP delay `4ms` (sem perda L3) |
| `1080p60-Saturated-8Mbps` | `QuicDatagram` | `1018.94 / 1518.13 / 1533.97` | `47.00` | `2.22 / 0.74` | `60/180 (33.3%)` | `16/3, —` | `0 / 117 / 2.00` | Loopback + teto `8 Mbps` user-space (`< 11,85 Mbps` oferecidos) |
| `1080p60-Saturated-8Mbps` | `QuicStream` | `2758.20 / 3684.55 / 3798.24` | `79.00` | `3.97 / 3.03` | `180/180 (100.0%)` | `0/3, —` | `0 / 0 / 2.00` | Loopback + teto `8 Mbps` user-space (`< 11,85 Mbps` oferecidos) |
| `1080p60-Saturated-8Mbps` | `TcpTls` | `1150.21 / 2188.59 / 2246.86` | `565.00` | `11.85 / 4.09` | `72/180 (40.0%)` | `0/3, —` | `0 / 0 / 40.00` | Loopback + teto `8 Mbps` user-space (`< 11,85 Mbps` oferecidos) |
| `1080p60-WiFi-Mild-0.5pct-UDP` | `QuicDatagram` | `0.00 / 0.00 / 0.00` | `139.00` | `2.11 / 0.00` | `0/180 (0.0%)` | `16/3, —` | `0 / 152 / 2.00` | Proxy UDP `0,5%` perda (`8ms` delay, `4ms` jitter); TCP perda L3 **`BLOCKED_BY_ENVIRONMENT`** |
| `1080p60-WiFi-Mild-0.5pct-UDP` | `QuicStream` | `4215.01 / 4737.25 / 4831.42` | `93.00` | `2.97 / 2.24` | `180/180 (100.0%)` | `0/3, —` | `0 / 0 / 2.00` | Proxy UDP `0,5%` perda (`8ms` delay, `4ms` jitter); TCP perda L3 **`BLOCKED_BY_ENVIRONMENT`** |
| `1080p60-WiFi-Mild-0.5pct-UDP` | `TcpTls` | **`BLOCKED_BY_ENVIRONMENT`** | — | — | — | — | — | `TcpImpairmentProxy` user-space não injeta perda L3 de segmentos TCP |
| `1080p60-WiFi-Harsh-2pct-UDP` | `QuicDatagram` | `0.00 / 0.00 / 0.00` | `438.00` | `2.10 / 0.00` | `0/180 (0.0%)` | `16/3, —` | `0 / 1 / 2.00` | Proxy UDP `2%` perda + `2%` reordenação; TCP perda L3 **`BLOCKED_BY_ENVIRONMENT`** |
| `1080p60-WiFi-Harsh-2pct-UDP` | `QuicStream` | `0.00 / 0.00 / 0.00` | `114.00` | `1.06 / 0.00` | `0/180 (0.0%)` | `16/2, —` | `0 / 52 / 2.00` | Proxy UDP `2%` perda + `2%` reordenação; TCP perda L3 **`BLOCKED_BY_ENVIRONMENT`** |
| `1080p60-WiFi-Harsh-2pct-UDP` | `TcpTls` | **`BLOCKED_BY_ENVIRONMENT`** | — | — | — | — | — | `TcpImpairmentProxy` user-space não injeta perda L3 de segmentos TCP |

*(Observação: `—` na coluna `Recuperação GOP` indica que nenhuma recuperação por keyframe foi concluída durante a janela, seja por ausência de solicitação (`0` pedidos) ou por perda contínua impedindo a remontagem do `IDR`.)*

### 4.2 Diagnóstico Técnico das 6 Dimensões em `1080p60`

1. **Latência (`Clean` vs Proxy Windows):** Em sockets diretos (`1080p60-Clean-12Mbps`), todas as modalidades sustentam `180/180` quadros com `p95 <= 0,60 ms` de mídia e `<= 1,00 ms` de controle. Sob qualquer proxy com `tokio::time::sleep` no Windows (`15,6 ms` de granularidade de timer por rajada/pacote), tanto a fila de pacing quanto o proxy inflam a latência em múltiplos de `15,6 ms`.
2. **Goodput vs Taxa Oferecida:** Em `Clean`, os três transportes entregam `11,68–11,70 Mbps` de `11,85 Mbps` oferecidos (`98,6%–98,7%`). Em `Saturated-8Mbps`, `TcpTls` atingiu `4,09 Mbps` efetivos (`72/180`), `QuicStream` reteve `180/180` em fila acumulando `3,68 s` em `p95` (`3,03 Mbps`), e `QuicDatagram` entregou apenas `60/180` (`0,74 Mbps`) porque o proxy/pacer quebrou remontagem dos quadros `P` após recuo do `BitrateAdvisor` para `2,00 Mbps`.
3. **Taxa de Entrega e Recuperação de GOP (achado desfavorável preservado):**
   - No benchmark CBR fixo (`transport_bench.rs` **não** reduz o tamanho de `IDR = 65 KB` quando `BitrateAdvisor` recua `advised_Mbps` para `2,00 Mbps`), sempre que `UdpImpairmentProxy` gera atraso/jitter ou perda com `tokio::time::sleep` no Windows (`15,6 ms`), o `TokenBucketPacer` espaça os `57` datagramas de cada `IDR` acima de `150 ms` (`DEFAULT_FRAGMENT_TIMEOUT_US`), provocando descarte por timeout de remontagem (`0/180` em `LAN-Delay-4ms`, `WiFi-Mild` e `WiFi-Harsh` com apenas `3` `IDR` enviados).
   - Em `WiFi-Mild-0.5pct-UDP`, `QuicStream` entregou `180/180` (`4,74 s` `p95`), ao passo que em `WiFi-Harsh-2pct-UDP` colapsou (`0/180`) por bloqueio e atraso acumulado superior à janela.
   - Esse achado empírico confirma duas exigências arquiteturais para `M2` e pós-MVP: (i) acoplamento real do `BitrateAdvisor` ao encoder (`UpdateDynamicBitrate` presente em `M2`), e (ii) eliminação de `sleep` por pacote em granularidade de `15,6 ms` / adição futura de NACK seletivo ou FEC leve (`ADR-0005` §1.4) antes de promover `ADR-0005` a `Accepted`.
4. **Saturação e Isolamento de Controle:** Em `Saturated-8Mbps`, `Control/Feedback` (`Heartbeat`) permaneceu entregue em `47–79 ms` no `QUIC` versus `565,00 ms` no `TcpTls` multiplexado, evidenciando o benefício da separação de streams no QUIC sob saturação de mídia.

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
  "sat-8m:netem delay 6ms && sudo tc qdisc add dev lo parent 1:1 handle 10: tbf rate 8mbit burst 32kbit latency 50ms"
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
