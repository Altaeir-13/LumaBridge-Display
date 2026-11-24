# Especificação do Protocolo de Rede LumaBridge (`LBWP v1`)

> **Status do documento: `Draft` (Rascunho arquitetural)**
>
> Esta especificação permanece em estado de **rascunho** até que existam testes automatizados de serialização, *round-trip*, *fuzzing*, compatibilidade de versões e validação de segurança no módulo `lumabridge-protocol` (`M1`).
>
> **Independência estrita do IPC local Windows:** Este protocolo (`LBWP`) governa exclusivamente a comunicação remota entre dispositivos (LAN, Wi-Fi, IP direto, USB compatível e futuro WAN). Ele é totalmente independente do protocolo local Windows `LBIF` v1.0/v1.1 (`Named Pipe` + `HANDLE` NT compartilhado + `QPC` / `DXGI_FORMAT` definido em `windows/driver/LumaBridgeIddDriver/FrameIpcProtocol.h`, consolidado localmente em `integration/m0-windows-closure` e ainda não integrado em `origin/dev`).

---

## 1. Princípios de Design e Versionamento

1. **Ordenação de bytes (Endianness):** Todos os cabeçalhos binários fixos e campos inteiros de *framing* trafegam em **Big-Endian (Network Byte Order)**.
2. **Versionamento explícito:** Toda conexão negocia `(protocol_major: u16, protocol_minor: u16)`, iniciando em **`1.0`**.
   - **Incompatibilidade de `protocol_major`:** qualquer divergência no `major` é rejeitada imediatamente com `ERR_UNSUPPORTED_VERSION` e encerramento limpo da sessão.
   - **Negociação de `protocol_minor`:** a versão efetiva da sessão é `min(local_minor, remote_minor)`.
   - **Compatibilidade futura em mensagens de controle:** o plano de controle usa serialização extensível por tags (candidatos: **Protobuf** ou **CBOR canônico**, decisão travada em `M1`). Campos opcionais desconhecidos de uma versão `minor` superior devem ser **ignorados** sem falha, enquanto flags críticas desconhecidas (marcadas como `must_understand`) provocam rejeição limpa com `ERR_UNSUPPORTED_FEATURE`.
3. **Separação de ALPN e superfícies de confiança (conforme [ADR-0005](../architecture/ADR-0005-transport-and-security-architecture.md)):**
   - **ALPN `"lumabridge-pair/1"`:** aceito somente quando o dispositivo alvo tiver janela explícita de pareamento aberta pelo usuário; aceita exclusivamente mensagens `Pair*` e `ErrorNotice`. Qualquer mensagem de sessão, mídia, captura ou input neste ALPN é erro fatal de protocolo.
   - **ALPN `"lumabridge/1"`:** exige TLS 1.3 com autenticação mútua (**mTLS**) usando SPKI Ed25519 pinado no Trust Store local. Rejeita pares não autorizados ou revogados no handshake TLS.
4. **Identificadores canônicos:**
   - `device_id`: 32 bytes (`SHA-256` do SPKI Ed25519 do nó).
   - `session_id`: `uint64` gerado por CSPRNG por sessão (nunca `0`).
   - `display_id`: `uint16` identificando unicamente cada tela lógica dentro da sessão (`0 .. 65534`; `0xFFFF` reservado para broadcast de controle quando aplicável).
   - `frame_id`: `uint32` estritamente monotônico (`>= 1`) por `(session_id, display_id)`.
   - `gop_id`: `uint16` incrementado a cada keyframe `IDR` / `CHAIN_RESET` por `(session_id, display_id)`.
5. **Timestamps:** todos os timestamps de rede trafegam em **microssegundos (`uint64`)** de relógio monotônico do respectivo emissor, nunca dependentes de relógio de parede (`UTC`) para cálculos de duração ou jitter; correlação ponta-a-ponta utiliza `ClockSyncPing`/`ClockSyncPong`.

---

## 2. Descoberta de Dispositivos

### 2.1 Descoberta Local via mDNS / DNS-SD

- **Tipos de serviço:**
  - `_lumabridge._udp.local.` (anúncio primário compatível com QUIC)
  - `_lumabridge._tcp.local.` (quando apenas fallback TCP/TLS estiver ativo)
- **Registros TXT (somente metadados mínimos não sensíveis):**
  - `pv=1.0` (versão do protocolo)
  - `did=<prefixo hex de 16 bytes do device_id>`
  - `caps=<bitmask hex: RX, MIRROR, EXTEND, INPUT>`
  - `pair=<0|1>` (indica apenas se a janela de pareamento está aberta no momento)
  - `name=<rótulo amigável UTF-8 truncado <= 48 B>` *(opcional, configurável para modo discreto)*
- **Proibição:** nunca anunciar PINs, tokens de pareamento, chaves privadas, permissões detalhadas ou informações sensíveis de usuário nos registros TXT mDNS.

### 2.2 Alternativas quando Multicast Indisponível

- Conexão manual direta por `host/IP:porta`.
- Leitura de QR Code contendo dicas de endpoint (`ip:port`), `spki_sha256` e token efêmero de pareamento.
- Descoberta local via interface USB IP (tethering) ou túnel explícito de desenvolvimento (`adb`).

---

## 3. Canais Lógicos e Framing

| Canal | Nome | Transporte sobre QUIC | Transporte sobre TCP/TLS 1.3 | Limite Máximo de Mensagem |
|---:|---|---|---|---|
| `0` | **Control & Session** | Stream bidirecional confiável #0 | Stream TLS multiplexado (`channel_id = 0`) | `64 KiB` (`65.536 B`) |
| `1` | **Media Video** | RFC 9221 Unreliable Datagrams *(ou stream curto se fallback)* | Framing sobre TCP/TLS com descarte no emissor antes do congestionamento | `1 fragmento <= negotiated_mtu` (quadro remontado `<= 8 MiB`) |
| `2` | **Feedback & ClockSync** | Stream confiável / datagram de controle rápido | Stream TLS multiplexado (`channel_id = 2`) | `4 KiB` (`4.096 B`) |
| `3` | **Remote Input** | Stream confiável ordenado #2 *(bloqueado sem permissão)* | Stream TLS multiplexado (`channel_id = 3`) | `1 KiB` (`1.024 B`) |

### 3.1 Framing dos Canais Confiáveis (`Channel 0`, `Channel 2`, `Channel 3`)

Cada mensagem serializada em canal orientado a stream é precedida por um cabeçalho fixo de **8 bytes (Big-Endian)**:

| Offset | Tamanho | Campo | Tipo | Descrição |
|---:|---:|---|---|---|
| `0..3` | 4 B | `frame_len` | `uint32` BE | Tamanho em bytes do payload seguinte (exclui os 8 bytes de cabeçalho). |
| `4` | 1 B | `channel_id` | `uint8` | `0` (Control), `2` (Feedback/ClockSync), `3` (Input). |
| `5..6` | 2 B | `msg_type` | `uint16` BE | Código numérico da mensagem (ver Seção 5). |
| `7` | 1 B | `flags` | `uint8` | Bit 0: `MUST_UNDERSTAND`; bits `1..7` reservados (`0` na v1.0). |

Qualquer pacote em que `frame_len` exceda o limite rígido do canal (`64 KiB`, `4 KiB` ou `1 KiB`) deve causar erro imediato `ERR_FRAME_TOO_LARGE` e encerramento da conexão.

---

## 4. Formato de Pacote de Vídeo (`Channel 1 Media`)

### 4.1 Cabeçalho Binário Fixo (`VideoPacketHeader` — 44 bytes Big-Endian)

Todo datagrama (ou frame encapsulado no fallback TCP/TLS) de mídia inicia com exatamente **44 bytes** seguidos pelos bytes do fragmento de bitstream codificado (ex.: slice Annex-B H.264/HEVC ou OBU AV1):

| Offset | Tamanho | Campo | Tipo | Limite / Regra |
|---:|---:|---|---|---|
| `0..1` | 2 B | `magic_ver` | `uint16` BE | Valor fixo `0x4C42` (`'LB'`); outro valor é descartado imediatamente. |
| `2..3` | 2 B | `flags` | `uint16` BE | Bitmask (ver tabela abaixo). |
| `4..11` | 8 B | `session_id` | `uint64` BE | Deve coincidir com a sessão ativa (`!= 0`). |
| `12..13` | 2 B | `display_id` | `uint16` BE | Display ativo negociado na sessão. |
| `14` | 1 B | `codec_id` | `uint8` | `1 = H264`, `2 = HEVC`, `3 = AV1` (deve coincidir com o negociado no display). |
| `15` | 1 B | `reserved` | `uint8` | Deve ser `0` na v1.0 (ignorado na leitura). |
| `16..19` | 4 B | `frame_id` | `uint32` BE | Monotônico `>= 1` por `(session_id, display_id)`. |
| `20..21` | 2 B | `gop_id` | `uint16` BE | Identificador da cadeia de predição; incrementa em todo IDR. |
| `22..23` | 2 B | `frag_index` | `uint16` BE | Índice do fragmento (`0 <= frag_index < frag_count`). |
| `24..25` | 2 B | `frag_count` | `uint16` BE | Total de fragmentos do quadro (`1 <= frag_count <= 4096`). |
| `26..27` | 2 B | `payload_len` | `uint16` BE | Comprimento do fragmento em bytes; `payload_len <= negotiated_mtu - 44`. |
| `28..35` | 8 B | `capture_ts_us` | `uint64` BE | Timestamp monotônico da captura/aquisição na origem (`µs`). |
| `36..43` | 8 B | `encode_done_ts_us` | `uint64` BE | Timestamp monotônico pós-encode na origem (`µs`, `>= capture_ts_us`). |

**Flags do campo `flags` (bitmask `uint16`):**
- `0x0001` (`FLAG_KEYFRAME`): o quadro é um IDR / ponto limpo de acesso aleatório.
- `0x0002` (`FLAG_END_OF_FRAME`): marca este fragmento como o último esperado (`frag_index == frag_count - 1`).
- `0x0004` (`FLAG_HAS_CODEC_CONFIG`): payload contém parâmetros de sequência inline (SPS/PPS/VPS).
- `0x0008` (`FLAG_PROTECTED_BLANK`): quadro substituído na origem por proteção DRM/HDCP (`payload_len = 0`, zero pixels expostos).
- `0x0010` (`FLAG_CHAIN_RESET`): sinaliza que o `gop_id` atual inicia uma cadeia limpa após recuperação de perda/backpressure.
- `0x0020` (`FLAG_MIRROR_SOURCE`): indica que a fonte é espelhamento (vs extensão virtual `0`).

### 4.2 Regras de MTU, Fragmentação e Remontagem

1. **Orçamento inicial de MTU:** cada fragmento completo (`44 + payload_len`) inicia limitado a **`1200 bytes`** (payload máximo inicial de **`1156 bytes`**), podendo subir via DPLPMTUD dentro do limite `max_datagram_frame_size` negociado pelo QUIC.
2. **Tamanho máximo de quadro:** a soma de `payload_len` de todos os fragmentos de um `frame_id` não pode exceder **`8 MiB` (`8.388.608 bytes`)**. Exceder o limite descarta o quadro incompleto imediatamente.
3. **Janela de remontagem e política `gop_id`:**
   - O receptor mantém no máximo `4` quadros em remontagem por `display_id`.
   - Se chegar um quadro `IDR` (`FLAG_KEYFRAME`) completo com `frame_id` mais novo, quadros incompletos mais antigos são descartados.
   - Se qualquer fragmento de um quadro `P` expirar ou houver salto em `frame_id` dentro do mesmo `gop_id`, o receptor entra em estado `AwaitingIdr`, descarta os demais fragmentos dependentes daquele `gop_id`, preserva na tela o último quadro íntegro já decodificado e solicita IDR via `MediaFeedback(request_idr = true)` respeitando cooldown mínimo (`150–250 ms`).

---

## 5. Catálogo de Mensagens (`msg_type`)

### 5.1 Pareamento (`0x0100–0x01FF`, exclusivamente em ALPN `"lumabridge-pair/1"`)

| Código | Mensagem | Direção | Conteúdo Principal |
|---:|---|---|---|
| `0x0100` | `PairHello` | Init ↔ Acc | `protocol_major`, `protocol_minor`, `device_id`, `friendly_name`, `auth_mode (PIN | QR)`, `spki_ed25519`. |
| `0x0101` | `PairSpakeMsg` | Init ↔ Acc | Mensagem da troca SPAKE2 (`RFC 9382`) + *key confirmation* ligada a `Hash(tls_exporter \|\| pk_init \|\| pk_acc)`. |
| `0x0102` | `PairQrAuth` | Init → Acc | `one_time_pairing_token`, assinatura Ed25519 do iniciador sobre `(tls_exporter \|\| token \|\| acc_device_id)`. |
| `0x0103` | `PairConfirm` | Acc → Init | `accepted: bool`, `granted_base_perms` (sempre restrito inicialmente, input negado por padrão), assinatura de confirmação. |
| `0x0104` | `PairCancel` | Init ↔ Acc | Cancelamento explícito pelo usuário ou timeout da janela de pareamento. |

### 5.2 Handshake Operacional e Capacidades (`0x0200–0x02FF`, ALPN `"lumabridge/1"`)

| Código | Mensagem | Conteúdo Principal |
|---:|---|---|
| `0x0200` | `Hello` | `protocol_major`, `protocol_minor`, `device_id`, `app_version`, `max_control_bytes`, `max_frame_bytes`, `preferred_mtu`. |
| `0x0201` | `HelloAck` | `negotiated_major`, `negotiated_minor`, `device_id`, `granted_stored_perms`, `status`. |
| `0x0202` | `NodeCapabilities` | Lista de papéis (`can_receive_video`, `can_mirror`, `can_extend_session`), SO/servidor gráfico (`WinDwm`, `WaylandGnome`, `WaylandKde`, `WaylandWlroots`, `X11`, `Android`, etc.), lista de encoders/decoders HW por codec (`H264`, `HEVC`, `AV1`), resoluções/FPS máximos, suporte a B-frames (`0` exigido em baixa latência), `max_virtual_displays`, suporte a escala/rotação e capacidades de entrada (`pointer`, `keyboard`, `touch`, `stylus`). |

### 5.3 Ciclo de Vida de Sessão e Displays (`0x0300–0x03FF`, ALPN `"lumabridge/1"`)

| Código | Mensagem | Conteúdo Principal |
|---:|---|---|
| `0x0300` | `SessionOpenRequest` | `session_id` proposto (`!= 0`), lista de displays solicitados (`display_id`, `mode: MIRROR \| EXTEND`, `width`, `height`, `fps_num/den`, `scale_milli`, `rotation_deg`, `codec_pref[]`, `max_bitrate_bps`, `latency_profile`), `requested_perms`. |
| `0x0301` | `SessionOpenResponse` | `status`, `session_id`, `resume_token` efêmero, displays efetivamente ativados (com modo, codec, formato de cor, bitrate inicial e `capture_mode` real), `granted_perms`. |
| `0x0302` | `DisplayConfigUpdate` | Alteração dinâmica de resolução, FPS, orientação, escala ou posição relativa de `display_id` existente ou adição/remoção de display na sessão. |
| `0x0303` | `SessionResumeRequest` | `session_id`, `resume_token`, `last_good_frame_id_per_display[]` após queda breve de transporte. |
| `0x0304` | `SessionResumeResponse` | `accepted: bool`, estado dos displays preservados e solicitação automática de IDR limpo. |
| `0x0305` | `SessionClose` | `session_id`, `reason_code`, `teardown_virtual_displays: bool`. |

### 5.4 Permissões e Autorização (`0x0400–0x04FF`, ALPN `"lumabridge/1"`)

| Código | Mensagem | Conteúdo Principal |
|---:|---|---|
| `0x0400` | `PermissionUpgradeRequest` | `session_id`, `request_seq` monotônico, `requested_perms` (ex.: `INPUT_POINTER \| INPUT_KEYBOARD`), motivo amigável. |
| `0x0401` | `PermissionUpdate` | `session_id`, `update_seq` monotônico, `effective_perms` atuais após aprovação ou revogação imediata pelo usuário local. |

### 5.5 Feedback de Mídia, Sincronização de Relógio e Telemetria (`0x0500–0x05FF`)

| Código | Mensagem | Canal | Conteúdo Principal |
|---:|---|---|---|
| `0x0500` | `MediaFeedback` | `2` | `session_id`, `display_id`, `last_complete_frame_id`, `last_displayed_frame_id`, `broken_gop_id`, `request_idr: bool`, `decode_p50_us`, `decode_p95_us`, `present_p95_us`, `rx_fps_milli`, `packet_loss_ppm`, `jitter_us`, `suggested_bitrate_bps`. |
| `0x0501` | `ClockSyncPing` | `2` | `seq`, `t1_client_mono_us`. |
| `0x0502` | `ClockSyncPong` | `2` | `seq`, `t1_client_mono_us`, `t2_server_recv_us`, `t3_server_send_us`. |
| `0x0503` | `Heartbeat` | `0` ou `2` | `session_id`, `seq`, `uptime_ms`. |
| `0x0504` | `DiagnosticsSummary` | `0` | Snapshot não visual agregado (`p50/p95/p99`, uso CPU/GPU/RAM, quedas por backpressure, estado HW vs SW). |

### 5.6 Entrada Remota Autorizada (`0x0600–0x06FF`, exclusivamente `Channel 3`)

- **Pré-condição absoluta:** qualquer evento `InputEvent` cujo tipo exija uma permissão (`INPUT_POINTER`, `INPUT_KEYBOARD`, `INPUT_TOUCH`, `INPUT_STYLUS`) não ativa em `effective_perms` é **descartado antes de tocar APIs do SO**.
- **Unidade e normalização:**
  - `InputBatch` (`0x0600`): `session_id`, `display_id`, `input_seq` (`uint64` monotônico), lista de eventos tipados:
    - `PointerMoveAbs`: `x_norm` (`0..65535`), `y_norm` (`0..65535`) mapeados ao retângulo lógico de `display_id`.
    - `PointerButton`: `button_id`, `pressed: bool`.
    - `PointerScroll`: `delta_x_milli`, `delta_y_milli` (alta precisão para trackpad/roda).
    - `KeyEvent`: **`hid_usage_page` + `hid_usage_id` (USB HID Usage Tables)** + `pressed: bool` + `modifiers_mask`, evitando dependência de X11 KeySyms, Windows Virtual Keys ou Android KeyCodes.
    - `TouchContact`: `contact_id`, `phase (Down|Move|Up|Cancel)`, `x_norm`, `y_norm`, `pressure_norm`.
    - `StylusEvent`: `x_norm`, `y_norm`, `pressure_norm`, `tilt_x_deg`, `tilt_y_deg`, `buttons_mask` *(futuro)*.

### 5.7 Erros Estruturados (`0x0700`)

`ErrorNotice`: `code` (`uint32`), `fatal: bool`, `related_msg_type` (`uint16`), `context_ascii` (mensagem diagnóstica sanitizada sem dados privados).

| Código | Nome | Descrição |
|---:|---|---|
| `1` | `ERR_UNSUPPORTED_VERSION` | `protocol_major` incompatível no handshake. |
| `2` | `ERR_INVALID_FRAMING` | `magic_ver`, `channel_id`, `msg_type` ou layout inválido. |
| `3` | `ERR_FRAME_TOO_LARGE` | Payload excede teto do canal ou teto `8 MiB` do quadro. |
| `4` | `ERR_UNSUPPORTED_FEATURE` | Flag `MUST_UNDERSTAND` desconhecida ou capacidade ausente. |
| `5` | `ERR_UNAUTHORIZED_PEER` | Certificado não presente ou revogado no Trust Store. |
| `6` | `ERR_PAIRING_CLOSED` | Tentativa em `"lumabridge-pair/1"` sem janela de pareamento aberta. |
| `7` | `ERR_PAIRING_FAILED` | Falha criptográfica SPAKE2/QR ou limite de tentativas excedido. |
| `8` | `ERR_PERMISSION_DENIED` | Captura, extensão ou entrada solicitada sem permissão concedida. |
| `9` | `ERR_SESSION_NOT_FOUND` | `session_id` desconhecido ou expirado em `SessionResumeRequest`. |
| `10` | `ERR_DISPLAY_UNAVAILABLE` | `display_id` inválido ou compositor incapaz de criar saída virtual. |
| `11` | `ERR_CODEC_NEGOTIATION_FAILED` | Nenhum codec/perfil compatível encontrado entre os nós. |
| `12` | `ERR_RATE_LIMITED` | Excesso de requisições de pareamento, controle ou pedidos de IDR. |

---

## 6. Matriz de Tratamento de Mensagens Inválidas

| Condição Inválida Detectada | Ação Obrigatória | Resposta Emitida | Impacto na Conexão |
|---|---|---|---|
| Mensagem de sessão/mídia/input recebida no ALPN `"lumabridge-pair/1"` | Rejeitar antes do parser de sessão | `ErrorNotice(ERR_INVALID_FRAMING, fatal=true)` | Encerra conexão TLS imediatamente |
| `frame_len` acima do limite do canal ou `frag_count > 4096` / `== 0` | Não alocar buffer; abortar leitura/remontagem | `ErrorNotice(ERR_FRAME_TOO_LARGE, fatal=true)` | Encerra conexão (canal stream) ou descarta quadro |
| `magic_ver != 0x4C42` ou `reserved != 0` inesperado em cabeçalho crítico | Descartar datagrama | Nenhum erro por pacote (evitar amplificação) | Mantém sessão; incrementa contador diagnóstico |
| `frag_index >= frag_count` ou soma de fragmentos `> 8 MiB` | Descartar quadro em montagem; marcar `AwaitingIdr` | `MediaFeedback(request_idr=true)` se afetar `gop_id` ativo | Mantém sessão; previne overflow/DoS |
| `session_id` desconhecido em canal de controle ou input | Ignorar evento / rejeitar comando | `ErrorNotice(ERR_SESSION_NOT_FOUND)` | Encerra se repetido ou em controle crítico |
| `InputEvent` recebido sem permissão ativa para aquele tipo | Descartar evento imediatamente sem chamar API do SO | `ErrorNotice(ERR_PERMISSION_DENIED, fatal=false)` | Mantém vídeo se `VIEW` estiver ativo; registra auditoria |
| Tentativa de PIN inválido repetida (`>= 3` falhas) | Invalidar PIN atual e fechar janela de pareamento | `ErrorNotice(ERR_PAIRING_FAILED, fatal=true)` | Encerra conexão de pareamento e aplica backoff |

---

## 7. Regras de Privacidade e Diagnóstico

1. **Zero dados sensíveis em logs:** logs de protocolo, métricas `DiagnosticsSummary` e relatórios de erro **nunca** devem conter conteúdo de quadros, coordenadas associadas a senhas, caracteres de teclado digitados, segredos de sessão, `tls_exporter`, `pairing_token`, PINs ou chaves privadas.
2. **Sinalização de conteúdo protegido:** quando o emissor detectar superfície DRM/HDCP protegida, deve transmitir quadro sinalizado com `FLAG_PROTECTED_BLANK` (`payload_len = 0`) para que o receptor exiba tela neutra segura sem capturar nem vazar pixels protegidos.
