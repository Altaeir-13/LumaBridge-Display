# Especificação do Protocolo de Rede LumaBridge (`LBWP v1`)

> **Status do documento: `Draft` — Revisão Candidata à Estabilização (`M1.2`)**
>
> Este documento especifica o protocolo binário **LumaBridge Wire Protocol (`LBWP v1`)** implementado pelo crate `lumabridge-protocol` (`M1.2`). Ele permanece em estado **`Draft` (revisão candidata à estabilização)** — **`LBWP v1.0` NÃO é declarado definitivamente congelado** nesta etapa enquanto contratos criptográficos (`M1.3`: transcript de pareamento, TLS Exporter / channel binding, assinaturas SPKI e confirmação SPAKE2), transporte operacional (`QUIC` / `TCP+TLS 1.3`, `DPLPMTUD`, política `0-RTT`) e interoperabilidade ponta-a-ponta permanecerem pendentes.
>
> **Separação estrita entre `LBWP`, `LBIF` e `C ABI`:**
> - **`LBWP` (`v1.0`):** protocolo de rede multiplataforma independente de transporte (QUIC, TCP/TLS 1.3, futuro USB/WAN), implementado em `core/crates/lumabridge-protocol`.
> - **`LBIF` (`v1.0` / `v1.1`):** protocolo IPC local do host Windows (`Named Pipe` + `HANDLE` NT compartilhado + `QPC` / `DXGI_FORMAT`), definido em [`windows/driver/LumaBridgeIddDriver/FrameIpcProtocol.h`](../../windows/driver/LumaBridgeIddDriver/FrameIpcProtocol.h) e preservado sem alterações.
> - **`C ABI` (`v1.0`):** contrato nativo local entre host C++/Kotlin e `lumabridge-ffi` (`LbAbiHeader`), definido em [`core/crates/lumabridge-ffi/include/lumabridge_ffi.h`](../../core/crates/lumabridge-ffi/include/lumabridge_ffi.h).

---

## 1. Princípios de Design, Versionamento e Dependências Normativas

### 1.1 Referências Normativas

- **RFC 8949:** Concise Binary Object Representation (CBOR), especialmente **§4.2.1 (Core Deterministic Encoding Requirements)**.
- **RFC 8610:** Concise Data Definition Language (CDDL) para definição formal dos schemas de mensagens.
- **RFC 9000:** QUIC: A UDP-Based Multiplexed and Secure Transport.
- **RFC 9221:** An Unreliable Datagram Extension to QUIC.
- **RFC 8899:** Packetization Layer Path MTU Discovery for Datagram Transports (DPLPMTUD) *(apenas delimitação de orçamento para camadas futuras; não implementado na `M1.2`)*.
- **RFC 9266:** Channel Bindings for TLS 1.3 (`tls-exporter`) *(delimitação para `M1.3`)*.
- **RFC 9382:** SPAKE2, a PAKE *(apenas delimitação estrutural dos envelopes de pareamento até `M1.3`)*.

### 1.2 Versionamento Explícito e Negociação

1. **Ordenação de bytes (Endianness):** Todos os cabeçalhos binários fixos (`FrameHeader` de 8 bytes e `VideoPacketHeader` de 44 bytes) trafegam em **Big-Endian (Network Byte Order)**.
2. **Versão do protocolo (`LBWP`):**
   - `protocol_major: u16` = **`1`**
   - `protocol_minor: u16` = **`0`**
   - **Regra de compatibilidade de `major`:** qualquer divergência `local_major != remote_major` é erro fatal imediato (`ERR_UNSUPPORTED_VERSION`, código `1`), exigindo rejeição da mensagem/sessão e encerramento limpo da conexão.
   - **Negociação de `minor`:** a versão efetiva da sessão é `effective_minor = min(local_minor, remote_minor)`.
   - **Independência de versões:** `LBWP (1.0)` evolui independentemente de `LBIF (1.0/1.1)` e da `C ABI (1.0)` de `lumabridge_ffi`.
3. **Separação de ALPN e Superfícies de Confiança ([ADR-0005](../architecture/ADR-0005-transport-and-security-architecture.md)):**
   - **`"lumabridge-pair/1"`:** contexto restrito de pareamento inicial (aceito somente quando a janela explícita de pareamento estiver aberta pelo usuário). Permite **exclusivamente** mensagens `Pair*` (`0x0100..=0x0104`) e `ErrorNotice` (`0x0700`) no `Channel 0`. Qualquer tentativa de envio de mensagens operacionais, mídia ou input neste ALPN é erro fatal (`ERR_INVALID_FRAMING`).
   - **`"lumabridge/1"`:** contexto operacional pós-pareamento autenticado externamente pelo módulo de segurança (`mTLS` com SPKI Ed25519 verificado no Trust Store na futura `M1.3`). O parser de protocolo **não** concede confiança, autenticação nem permissões por conta própria; ele apenas valida envelopes e políticas puras com base no contexto fornecido pelo chamador.
4. **Identificadores canônicos:**
   - `device_id`: `32 bytes` (`SHA-256` do SPKI Ed25519 do nó).
   - `session_id`: `uint64` não zero (`!= 0`, gerado por CSPRNG na futura camada de segurança/sessão).
   - `display_id`: `uint16` no intervalo `0..=65534` (`0x0000..=0xFFFE`); `0xFFFF` é reservado e **inválido** em quadros de vídeo e configurações individuais de display.
   - `frame_id`: `uint32` estritamente crescente (`>= 1`) por `(session_id, display_id)`, **sem wraparound** dentro da mesma sessão (ver Seção 8.4).
   - `gop_id`: `uint16` modular por `(session_id, display_id)`, permitindo wraparound `65535 -> 0`.
5. **Timestamps:** todos os timestamps de rede trafegam em **microssegundos (`uint64`)** de relógio monotônico do respectivo emissor (`encode_done_ts_us >= capture_ts_us`, `t3_server_send_us >= t2_server_recv_us`), nunca relógio de parede (`UTC`) para deltas de duração ou jitter.

### 1.3 Escolha da Biblioteca CBOR e Política de Dependências (`M1.2`)

A decisão entre Protobuf e CBOR foi **resolvida na `M1.2` em favor do Perfil CBOR Restrito (`LBWP-CBOR-v1`)** utilizando **`ciborium-ll`** (versão **`0.2.2`**, licença **`Apache-2.0`**) e **`ciborium-io`** (versão **`0.2.2`**, licença **`Apache-2.0`**):

| Atributo | Especificação |
|---|---|
| **Dependência direta** | `ciborium-ll = "0.2.2"`, `ciborium-io = { version = "0.2.2", default-features = false, features = ["alloc"] }` |
| **Dependência transitiva** | `half` (`2.x`, `MIT OR Apache-2.0`, exigida pelo tipo `Header::Float` em `ciborium-ll`; floats continuam **rejeitados** pelo perfil LBWP) |
| **Licença & RustSec** | `Apache-2.0` / `MIT OR Apache-2.0`; sem `GPL`/`LGPL`; zero advisories conhecidos e compatível com `core/deny.toml` |
| **Multiplataforma** | Pura em Rust (`no_std` + `alloc`), `#![forbid(unsafe_code)]` no consumidor, compatível com Windows x64, Linux x86_64/ARM64 e Android `aarch64-linux-android` |
| **Justificativa técnica** | O `ciborium-ll` fornece codec de fluxo pull/push sem acoplar a representação de fio ao layout interno de structs Rust (`serde` não é utilizado) e permite inspeção de `offset()` antes/depois de `pull()` para impor RFC 8949 §4.2.1 estrito em entradas não confiáveis. |

**Importante:** O `ciborium-ll` é permissivo na leitura por construção (aceita inteiros não mínimos, chaves desordenadas ou duplicadas, tamanhos indefinidos, floats e tags). Toda a imposição do perfil determinístico e dos limites defensivos é realizada explicitamente pela camada `cbor` de `lumabridge-protocol`.

---

## 2. Perfil CBOR Restrito (`LBWP-CBOR-v1`)

Todas as mensagens dos canais `0`, `2` e `3` utilizam mapas CBOR determinísticos conforme **RFC 8949 §4.2.1 (Core Deterministic Encoding Requirements)** com as seguintes restrições normativas adicionais:

1. **Estrutura de topo:** toda mensagem de controle, feedback ou input é exatamente um **mapa CBOR de comprimento definido (`Major Type 5`)** com **chaves inteiras não negativas (`Major Type 0`)** estáveis.
2. **Codificação inteira mínima:** todo inteiro positivo (`Major Type 0`), negativo (`Major Type 1`, permitido apenas em campos de valor com sinal como deltas de scroll ou posição) e todo prefixo de comprimento de `bstr`, `tstr`, `array` e `map` **deve** utilizar a menor codificação possível segundo RFC 8949 §4.1 (`0..=23` em 1 byte; `24..=255` em 2 bytes; `256..=65535` em 3 bytes; `65536..=u32::MAX` em 5 bytes; acima em 9 bytes).
3. **Ordenação determinística e unicidade de chaves:** como todas as chaves são `Major Type 0` codificadas em largura mínima, a ordenação lexicográfica byte a byte exigida pela RFC 8949 §4.2.1 coincide com a ordenação numérica estritamente crescente (`key_prev < key_curr`). Chaves duplicadas ou fora de ordem são **rejeitadas**.
4. **Comprimentos definidos obrigatórios:** qualquer item de comprimento indefinido (`0x5F`, `0x7F`, `0x9F`, `0xBF`) ou marcador `Break` (`0xFF`) é **rejeitado**.
5. **Tipos proibidos:**
   - Pontos flutuantes (`f16`, `f32`, `f64` — `Major Type 7` AI `25..=27`) são **proibidos**.
   - Tags semânticas (`Major Type 6`) são **proibidas**.
   - Valores `null` (`0xF6`), `undefined` (`0xF7`) e valores simples não padronizados são **proibidos** (campos opcionais ausentes devem simplesmente ser **omitidos** do mapa). Somente `false` (`0xF4`) e `true` (`0xF5`) são aceitos em `Major Type 7`.
6. **Dados truncados, trailing bytes e UTF-8:**
   - Truncamento em qualquer posição resulta em `Truncated`.
   - Bytes remanescentes após o fim do mapa de topo resultam em `TrailingBytes`.
   - Toda `tstr` (`Major Type 3`) tem validação UTF-8 estrita antes da construção de `String`.
7. **Limites rígidos do perfil (verificados antes de alocar):**
   - `MAX_CBOR_DEPTH = 8`
   - `MAX_CBOR_MAP_ENTRIES = 64`
   - `MAX_CBOR_ARRAY_ITEMS = 64`
   - `MAX_CBOR_TEXT_BYTES = 256` *(campos específicos possuem tetos menores, ex.: `48` B ou `128` B)*
   - `MAX_CBOR_BYTE_STRING_BYTES = 1024`
   - `MAX_CBOR_UNKNOWN_FIELDS_PER_MAP = 16`
   - `MAX_CBOR_TOTAL_ITEMS = 512`
   - Antes de qualquer alocação para `bstr`, `tstr`, `array` ou `map`, o decoder verifica `len <= max_campo` e `bytes_restantes >= len_minimo_exigido`, impedindo ataques de exaustão de memória por prefixos forjados (ex.: `0x5A 0x7F 0xFF 0xFF 0xFF`).
8. **Tratamento limitado e seguro de campos opcionais desconhecidos:**
   - Em modo padrão (`UnknownFieldPolicy::SkipBounded`), chaves inteiras desconhecidas dentro de mapas são saltadas por um skipper recursivo limitado por `max_depth`, `max_total_items` e `max_unknown_fields_per_map = 16`, que **continua impondo todas as regras do perfil** (sem floats, sem tags, sem `null`, sem comprimento indefinido, UTF-8 válido em strings ignoradas, ordenação estrita das chaves e codificação mínima).
   - Emissor v1.0 nunca emite campos desconhecidos ou valores nulos.
9. **Compatibilidade semântica vs representação determinística:**
   - O decodificador diferencia explicitamente **erros de representação determinística** (`NonMinimalInteger`, `UnsortedMapKeys`, `IndefiniteLengthForbidden`) de **erros estruturais/semânticos** (`DuplicateMapKey`, `ForbiddenType`, `InvalidUtf8`, `Truncated`, `TrailingBytes`, `DepthExceeded`, `LimitExceeded`, `MissingRequiredField`, `TypeMismatch`, `ValueOutOfRange`).
   - O modo normativo padrão de produção é **`StrictDeterministic`**, rejeitando qualquer desvio de RFC 8949 §4.2.1. O modo diagnóstico explícito `RelaxedOrderAndWidth` pode ser utilizado apenas em ferramentas/testes para distinguir falhas puramente de canonicalização de falhas semânticas (ainda rejeitando chaves duplicadas, floats, tags, indefinidos, UTF-8 inválido e estouro de limites).

---

## 3. Canais Lógicos, Mapeamento de Transporte e Framing de Streams

### 3.1 Mapeamento de Canais Lógicos (`channel_id`)

| `channel_id` | Nome | Transporte sobre QUIC | Transporte sobre TCP/TLS 1.3 | Teto por Registro (`frame_len`) |
|---:|---|---|---|---:|
| `0` | **Control & Session** | Stream bidirecional confiável dedicado ao canal `0` | Stream TLS multiplexado (`channel_id = 0`) | **`65.536 B` (`64 KiB`)** |
| `1` | **Media Video** | RFC 9221 Unreliable Datagrams *(ou registro em stream curto no fallback)* | Registro em stream TCP/TLS (`msg_type = 0x0800`) com descarte pré-socket | **`16.384 B` (`16 KiB`)** *(mín. `44 B`; quadro remontado `<= 8 MiB`)* |
| `2` | **Feedback, ClockSync & Heartbeat** | Stream confiável dedicado ao canal `2` *(datagramas reservados para extensão futura)* | Stream TLS multiplexado (`channel_id = 2`) | **`4.096 B` (`4 KiB`)** |
| `3` | **Remote Input** | Stream confiável ordenado dedicado ao canal `3` *(exige permissão ativa)* | Stream TLS multiplexado (`channel_id = 3`) | **`1.024 B` (`1 KiB`)** |

**Regras normativas de mapeamento:**

1. **`Heartbeat` (`0x0503`):** trafega **exclusivamente no `Channel 2`** na v1.0 (resolvendo a ambiguidade anterior `0 ou 2`).
2. **Datagramas de feedback:** reservados no desenho lógico para eventual extensão futura após `M1`, **não implementados na v1.0 inicial**.
3. **Separação entre `channel_id` lógico e Stream ID do QUIC:**
   - Identificadores lógicos (`0, 1, 2, 3`) **não são** números absolutos de streams QUIC (na RFC 9000 §2.1, streams bidirecionais iniciados pelo cliente são `0, 4, 8, ...` e pelo servidor são `1, 5, 9, ...`).
   - A camada de transporte futura vinculará cada stream QUIC dedicado a um único `channel_id` lógico via `StreamBindingMode::BoundSingleChannel(ChannelId)` após o primeiro registro válido (ou cabeçalho de abertura de stream). **Trocar `channel_id` no meio de um stream dedicado é erro fatal de framing (`ERR_INVALID_FRAMING`)**.
   - Em fallback TCP/TLS (`StreamBindingMode::Multiplexed`), múltiplos canais lógicos podem compartilhar a mesma conexão TCP/TLS usando o campo `channel_id` do cabeçalho de 8 bytes.

### 3.2 Cabeçalho Binário Fixo de Framing de Streams (8 bytes Big-Endian)

Toda mensagem em canal orientado a stream (`Channels 0, 2, 3` e registros `Channel 1` em stream/fallback TCP) é precedida por exatamente **8 bytes**:

| Offset | Tamanho | Campo | Tipo | Regra Normativa v1.0 |
|---:|---:|---|---|---|
| `0..3` | `4 B` | `frame_len` | `uint32` BE | Comprimento do payload em bytes (exclui os 8 bytes deste cabeçalho). Verificado **antes de alocar**: `Ch0 <= 65.536`, `Ch1: 44..=16.384`, `Ch2 <= 4.096`, `Ch3 <= 1.024`. |
| `4` | `1 B` | `channel_id` | `uint8` | Apenas `0`, `1`, `2` ou `3`; qualquer outro valor é rejeitado imediatamente (`ERR_INVALID_FRAMING`). |
| `5..6` | `2 B` | `msg_type` | `uint16` BE | Código numérico da mensagem (ver Seção 5). No `Channel 1`, exige `0x0800`. |
| `7` | `1 B` | `flags` | `uint8` | Bit `0` (`0x01`): `MUST_UNDERSTAND`. Bits `1..=7` (`0xFE`): **reservados** (emissor escreve `0`; receptor v1.0 rejeita se `(flags & 0xFE) != 0`). |

### 3.3 Framing Explícito de Mídia em Stream (`Channel 1`, `msg_type = 0x0800`)

Quando mídia de vídeo trafegar em fluxo orientado a bytes (ex.: fallback TCP/TLS 1.3 ou stream QUIC de mídia):

- Utiliza o **mesmo cabeçalho externo de 8 bytes** com `channel_id = 1` e `msg_type = 0x0800` (`MediaVideoFragment`, namespace reservado `0x0800..=0x08FF` sem colisão com `0x0100..=0x07FF`).
- `frame_len` contabiliza exatamente `44 + payload_len` (os 44 bytes do `VideoPacketHeader` + os bytes do fragmento).
- **Piso mínimo:** `frame_len >= 44` (rejeita com `ERR_INVALID_FRAMING` se menor).
- **Teto explícito do registro em stream:** **`16.384 B` (`16 KiB`)** incluindo os 44 bytes do `VideoPacketHeader` (logo, até `16.340 B` de fragmento por registro de stream; configurável até este teto). Registros maiores são rejeitados **antes de alocar** (`ERR_FRAME_TOO_LARGE`).
- **Flags externas:** bits reservados `1..=7` são rejeitados; `MUST_UNDERSTAND` (`0x01`) é aceito ou tratado de forma transparente apenas como flag externa válida de cabeçalho.

### 3.4 Requisitos do Decoder Incremental de Streams (`StreamFrameDecoder`)

O decoder incremental `StreamFrameDecoder` não pressupõe qualquer alinhamento entre chamadas `read()` do transporte e mensagens LBWP:

- Suporta cabeçalhos de 8 bytes fragmentados em 1..N entregas parciais.
- Suporta payloads fragmentados em entregas parciais.
- Suporta múltiplos registros completos ou parciais concatenados em um único buffer.
- Informa de forma inequívoca os bytes consumidos e o próximo estado (`Frame(RawFrame)` vs `NeedMoreData`).
- Detecta `UnexpectedEof` se a conexão encerrar no meio de um cabeçalho ou no meio de um payload.
- Rejeita `frame_len` excessivo, `channel_id` inválido, flags reservadas ou troca de canal no meio de stream **imediatamente após ler os 8 bytes de cabeçalho, antes de alocar o buffer de payload**.
- Após erro fatal de stream, o decoder permanece em estado travado (*poisoned*) e recusa leituras subsequentes sem reinterpretar bytes desalinhados.

---

## 4. Versão, Flags, Campos Reservados e Política de Extensibilidade

Resolvendo as contradições da versão inicial do rascunho:

1. **Campos e bits reservados na v1.0:**
   - **Emissor:** escreve obrigatoriamente **`0`** em todos os campos e bits reservados (`FrameHeader.flags & 0xFE`, `VideoPacketHeader.reserved`, `VideoPacketHeader.flags & 0xFFC0`, bits reservados de `Permissions`, `RoleFlags`, `InputCapabilities` e `modifiers_mask`).
   - **Receptor v1.0:** **rejeita** qualquer valor não zero nos campos e bits reservados acima (`ERR_INVALID_FRAMING` ou `ERR_UNSUPPORTED_FEATURE` conforme o campo).
2. **Mensagens desconhecidas (`msg_type` fora do catálogo v1.0):**
   - **Com `FLAG_MUST_UNDERSTAND` (`0x01`) ativo:** sempre **rejeitadas** com `ERR_UNSUPPORTED_FEATURE` (`4`, fatal no stream).
   - **Sem `FLAG_MUST_UNDERSTAND`:**
     - No ALPN de pareamento **`"lumabridge-pair/1"`** ou no **`Channel 1`**: **sempre rejeitadas** com `ERR_INVALID_FRAMING` (extensibilidade não pode enfraquecer o isolamento de pareamento nem corromper mídia).
     - No ALPN operacional **`"lumabridge/1"`** nos **canais `0`, `2` ou `3`**: podem ser **ignoradas com segurança** somente após validação completa do cabeçalho de 8 bytes, limites de tamanho do canal e estado autorizado da conexão (o payload é drenado/descartado sem alterar o estado da sessão e sem conceder permissões).
3. **Campos opcionais desconhecidos dentro de mapas CBOR conhecidos:**
   - Validados contra todas as restrições de `LBWP-CBOR-v1` (profundidade, tamanho, UTF-8, sem floats/tags/indefinidos, ordenação estrita) e descartados com limite de `16` campos desconhecidos por mapa. Nunca podem contornar validações de ALPN, canal, direção ou autorização.

---

## 5. Catálogo Completo de Mensagens (`msg_type`) e Schemas CDDL (RFC 8610)

> **Convenção para `M1.3`:** campos marcados com **`[M1.3-PROVISIONAL]`** definem apenas o envelope estrutural e seus limites sintáticos nesta etapa (`M1.2`). Seus formatos criptográficos exatos (transcript, TLS exporter label, DER vs raw SPKI, prova SPAKE2, assinaturas Ed25519) permanecem provisórios até a definição formal da `M1.3`.

### 5.1 Resumo do Catálogo de Identificadores

| Código | Mensagem | Canal | ALPN Permitido | Direção | Payload |
|---:|---|---:|---|---|---|
| `0x0100` | `PairHello` | `0` | `"lumabridge-pair/1"` | `Init ↔ Acc` | CBOR |
| `0x0101` | `PairSpakeMsg` | `0` | `"lumabridge-pair/1"` | `Init ↔ Acc` | CBOR |
| `0x0102` | `PairQrAuth` | `0` | `"lumabridge-pair/1"` | `Init → Acc` | CBOR |
| `0x0103` | `PairConfirm` | `0` | `"lumabridge-pair/1"` | `Acc → Init` | CBOR |
| `0x0104` | `PairCancel` | `0` | `"lumabridge-pair/1"` | `Init ↔ Acc` | CBOR |
| `0x0200` | `Hello` | `0` | `"lumabridge/1"` | `Init → Acc` | CBOR |
| `0x0201` | `HelloAck` | `0` | `"lumabridge/1"` | `Acc → Init` | CBOR |
| `0x0202` | `NodeCapabilities` | `0` | `"lumabridge/1"` | `Init ↔ Acc` | CBOR |
| `0x0300` | `SessionOpenRequest` | `0` | `"lumabridge/1"` | `Init ↔ Acc` | CBOR |
| `0x0301` | `SessionOpenResponse` | `0` | `"lumabridge/1"` | `Init ↔ Acc` | CBOR |
| `0x0302` | `DisplayConfigUpdate` | `0` | `"lumabridge/1"` | `Init ↔ Acc` | CBOR |
| `0x0303` | `SessionResumeRequest` | `0` | `"lumabridge/1"` | `Init → Acc` | CBOR |
| `0x0304` | `SessionResumeResponse` | `0` | `"lumabridge/1"` | `Acc → Init` | CBOR |
| `0x0305` | `SessionClose` | `0` | `"lumabridge/1"` | `Init ↔ Acc` | CBOR |
| `0x0400` | `PermissionUpgradeRequest` | `0` | `"lumabridge/1"` | `Init ↔ Acc` | CBOR |
| `0x0401` | `PermissionUpdate` | `0` | `"lumabridge/1"` | `Init ↔ Acc` | CBOR |
| `0x0500` | `MediaFeedback` | `2` | `"lumabridge/1"` | `Init ↔ Acc` | CBOR |
| `0x0501` | `ClockSyncPing` | `2` | `"lumabridge/1"` | `Init ↔ Acc` | CBOR |
| `0x0502` | `ClockSyncPong` | `2` | `"lumabridge/1"` | `Init ↔ Acc` | CBOR |
| `0x0503` | `Heartbeat` | `2` | `"lumabridge/1"` | `Init ↔ Acc` | CBOR |
| `0x0504` | `DiagnosticsSummary` | `0` | `"lumabridge/1"` | `Init ↔ Acc` | CBOR |
| `0x0600` | `InputBatch` | `3` | `"lumabridge/1"` | `Init ↔ Acc` | CBOR |
| `0x0700` | `ErrorNotice` | `0` | `"lumabridge-pair/1"` e `"lumabridge/1"` | `Init ↔ Acc` | CBOR |
| `0x0800` | `MediaVideoFragment` | `1` | `"lumabridge/1"` | `Init ↔ Acc` | Binário (`44 B + frag`) |

*(Nota de segurança de sessão: `SessionOpenRequest`..`DiagnosticsSummary` e `InputBatch` exigem handshake operacional concluído (`OperationalAuthenticated` / `OperationalSessionActive`) conforme matriz da Seção 9.)*

### 5.2 Tipos Comuns e Bitmasks (CDDL RFC 8610)

```cddl
device-id        = bstr .size 32
session-id       = uint .gt 0                  ; 1..=u64::MAX (0 proibido)
display-id       = 0..65534                    ; 0xFFFF reservado/invalido
u16              = 0..65535
u32              = 0..4294967295
u64              = uint .size 8

auth-mode        = 1 / 2                       ; 1=PinSpake2, 2=QrOutOfBand
spake-step       = 1 / 2                       ; 1=KeyExchange, 2=KeyConfirmation
pair-cancel-rsn  = 1..4                        ; 1=UserCancelled, 2=Timeout, 3=ProtocolError, 4=RateLimited
hello-status     = 0..3                        ; 0=Accepted, 1=UnsupportedVersion, 2=UnauthorizedPeer, 3=Busy
session-status   = 0..5                        ; 0=Accepted, 1=PermissionDenied, 2=DisplayUnavailable, 3=CodecNegotiationFailed, 4=RateLimited, 5=InvalidConfig
close-reason     = 1..6                        ; 1=UserRequested, 2=IdleTimeout, 3=TransportLost, 4=PeerRevoked, 5=ProtocolError, 6=Shutdown
display-action   = 1..3                        ; 1=Reconfigure, 2=Add, 3=Remove
codec-id         = 1..3                        ; 1=H264, 2=HEVC, 3=AV1
color-format     = 1..3                        ; 1=NV12_8BIT, 2=BGRA8, 3=P010_10BIT
display-mode     = 1 / 2                       ; 1=Mirror, 2=Extend
rotation-deg     = 0 / 90 / 180 / 270
latency-profile  = 1..3                        ; 1=LowLatency, 2=Balanced, 3=Quality
capture-mode     = 1..7                        ; 1=WinIdd, 2=WinWgc, 3=LinuxPipeWire, 4=LinuxCompositorVirtual, 5=LinuxX11Shm, 6=AndroidMediaProj, 7=Synthetic
os-platform      = 1..11                       ; 1=WinDwm .. 11=Other
permissions-mask = 0..127                      ; bits 0..6 validos na v1.0; bits 7..31 reservados (=0)
roles-mask       = 0..31                       ; bits 0..4 validos na v1.0; bits 5..31 reservados (=0)
input-caps-mask  = 0..15                       ; bits 0..3 validos na v1.0; bits 4..31 reservados (=0)
error-code       = 1..12                       ; Tabela da Secao 5.8
```

### 5.3 Schemas Normativos de Pareamento (`0x0100–0x0104`, `Channel 0`, ALPN `"lumabridge-pair/1"`)

```cddl
PairHello = {
  1 => 1..65535,                 ; protocol_major (obrig.)
  2 => 0..65535,                 ; protocol_minor (obrig.)
  3 => device-id,                ; device_id 32B (obrig.)
  4 => tstr .size (1..48),       ; friendly_name UTF-8 (obrig.)
  5 => auth-mode,                ; auth_mode (obrig.)
  6 => bstr .size (32..128),     ; spki_ed25519 [M1.3-PROVISIONAL] (obrig.)
}

PairSpakeMsg = {
  1 => uint .gt 0,               ; pairing_attempt_id (obrig.)
  2 => spake-step,               ; step (obrig.)
  3 => bstr .size (1..256),      ; spake_payload [M1.3-PROVISIONAL] (obrig., redigido em Debug)
  ? 4 => bstr .size (16..64),    ; key_confirmation [M1.3-PROVISIONAL] (obrig. se step==2, redigido em Debug)
}

PairQrAuth = {
  1 => uint .gt 0,               ; pairing_attempt_id (obrig.)
  2 => bstr .size (16..64),      ; one_time_pairing_token >= 128b [M1.3-PROVISIONAL] (obrig., redigido)
  3 => bstr .size (64..128),     ; initiator_signature Ed25519 [M1.3-PROVISIONAL] (obrig., redigido)
}

PairConfirm = {
  1 => uint .gt 0,               ; pairing_attempt_id (obrig.)
  2 => bool,                     ; accepted (obrig.)
  3 => permissions-mask,         ; granted_base_perms (obrig.; bits INPUT_* 0x0078 PROIBIDOS; ==0 se !accepted)
  ? 4 => bstr .size (64..128),   ; confirm_signature [M1.3-PROVISIONAL] (obrig. se accepted==true, redigido)
}

PairCancel = {
  ? 1 => uint .gt 0,             ; pairing_attempt_id (opc.)
  2 => pair-cancel-rsn,          ; reason_code (obrig.)
  ? 3 => tstr .size (0..128),    ; detail_ascii ASCII imprimivel (opc.)
}
```

**Regras semânticas e extensibilidade:**
- Em `PairConfirm`, permissões de entrada (`0x0078`) **nunca** podem ser concedidas no pareamento inicial; `accepted == false` exige `granted_base_perms == 0`.
- Campos desconhecidos opcionais dentro dos mapas `Pair*` são ignorados apenas após validação estrita de `LBWP-CBOR-v1` (sem permitir `msg_type` desconhecido no ALPN de pareamento).

### 5.4 Handshake Operacional e Capacidades (`0x0200–0x0202`, `Channel 0`, ALPN `"lumabridge/1"`)

```cddl
Hello = {
  1 => 1..65535,                 ; protocol_major (obrig.)
  2 => 0..65535,                 ; protocol_minor (obrig.)
  3 => device-id,                ; device_id 32B (obrig.)
  4 => tstr .size (1..32),       ; app_version UTF-8 (obrig.)
  5 => 1024..65536,              ; max_control_bytes (obrig.)
  6 => 4096..8388608,            ; max_frame_bytes (obrig.)
  7 => 512..65535,               ; preferred_mtu (obrig.)
}

HelloAck = {
  1 => 1..65535,                 ; negotiated_major (obrig.)
  2 => 0..65535,                 ; negotiated_minor (obrig.)
  3 => device-id,                ; device_id 32B (obrig.)
  4 => permissions-mask,         ; granted_stored_perms (obrig.; ==0 se status != Accepted)
  5 => hello-status,             ; status (obrig.)
  6 => 1024..65536,              ; max_control_bytes (obrig.)
  7 => 4096..8388608,            ; max_frame_bytes (obrig.)
  8 => 512..65535,               ; negotiated_mtu (obrig.)
}

CodecCapability = {
  1 => codec-id,                 ; codec_id (obrig.)
  2 => bool,                     ; can_encode (obrig.)
  3 => bool,                     ; can_decode (obrig.)
  4 => bool,                     ; hw_accelerated (obrig.)
  5 => 1..16384,                 ; max_width (obrig.)
  6 => 1..16384,                 ; max_height (obrig.)
  7 => 1..1000,                  ; max_fps_num (obrig.)
  8 => 1..1000,                  ; max_fps_den (obrig.)
  9 => 0..4,                     ; max_b_frames (obrig.; 0 em baixa latencia)
}

NodeCapabilities = {
  1 => roles-mask,               ; roles_mask (obrig.)
  2 => os-platform,              ; platform (obrig.)
  3 => [1*16 CodecCapability],   ; codecs (obrig., 1..=16)
  4 => 0..16,                    ; max_virtual_displays (obrig.)
  5 => bool,                     ; supports_scale (obrig.)
  6 => bool,                     ; supports_rotation (obrig.)
  7 => input-caps-mask,          ; input_caps_mask (obrig.)
}
```

### 5.5 Ciclo de Vida de Sessão e Displays (`0x0300–0x0305`, `Channel 0`, ALPN `"lumabridge/1"`)

```cddl
DisplayRequest = {
  1 => display-id,               ; display_id 0..=65534 (obrig.)
  2 => display-mode,             ; mode Mirror|Extend (obrig.)
  3 => 64..16384,                ; width (obrig.)
  4 => 64..16384,                ; height (obrig.)
  5 => 1..1000,                  ; fps_num (obrig.)
  6 => 1..1000,                  ; fps_den (obrig.)
  7 => 250..4000,                ; scale_milli (obrig.)
  8 => rotation-deg,             ; rotation_deg (obrig.)
  9 => [1*8 codec-id],           ; codec_pref (obrig., 1..=8)
  10 => 100000..1000000000,      ; max_bitrate_bps (obrig.)
  11 => latency-profile,         ; latency_profile (obrig.)
}

SessionOpenRequest = {
  1 => session-id,               ; session_id != 0 (obrig.)
  2 => [1*16 DisplayRequest],    ; displays (obrig., display_ids unicos)
  3 => permissions-mask,         ; requested_perms (obrig.)
}

ActiveDisplayConfig = {
  1 => display-id,               ; display_id (obrig.)
  2 => display-mode,             ; mode (obrig.)
  3 => 64..16384,                ; width (obrig.)
  4 => 64..16384,                ; height (obrig.)
  5 => 1..1000,                  ; fps_num (obrig.)
  6 => 1..1000,                  ; fps_den (obrig.)
  7 => 250..4000,                ; scale_milli (obrig.)
  8 => rotation-deg,             ; rotation_deg (obrig.)
  9 => codec-id,                 ; codec_id (obrig.)
  10 => color-format,            ; color_format (obrig.)
  11 => 100000..1000000000,      ; initial_bitrate_bps (obrig.)
  12 => capture-mode,            ; capture_mode (obrig.)
}

SessionOpenResponse = {
  1 => session-status,           ; status (obrig.)
  2 => session-id,               ; session_id != 0 (obrig.)
  ? 3 => bstr .size (16..64),    ; resume_token [M1.3-PROVISIONAL] (obrig. se status==0, redigido)
  4 => [0*16 ActiveDisplayConfig], ; active_displays (>=1 se status==0, 0 se rejeitado; display_ids unicos)
  5 => permissions-mask,         ; granted_perms (obrig.; ==0 se status!=0)
}

DisplayConfigUpdate = {
  1 => session-id,               ; session_id != 0 (obrig.)
  2 => uint .gt 0,               ; update_seq monotonico >=1 (obrig.)
  3 => display-id,               ; display_id 0..=65534 (obrig.)
  4 => display-action,           ; 1=Reconfigure, 2=Add, 3=Remove (obrig.)
  ? 5 => display-mode,           ; obrigatorio em Add
  ? 6 => 64..16384,              ; width (obrig. em Add)
  ? 7 => 64..16384,              ; height (obrig. em Add)
  ? 8 => 1..1000,                ; fps_num (obrig. em Add; exige fps_den)
  ? 9 => 1..1000,                ; fps_den (obrig. em Add; exige fps_num)
  ? 10 => 250..4000,             ; scale_milli
  ? 11 => rotation-deg,          ; rotation_deg
  ? 12 => -65536..65536,         ; pos_x (exige pos_y)
  ? 13 => -65536..65536,         ; pos_y (exige pos_x)
}

DisplayFrameCursor = {
  1 => display-id,               ; display_id (obrig.)
  2 => u32,                      ; last_good_frame_id (obrig.)
}

SessionResumeRequest = {
  1 => session-id,               ; session_id != 0 (obrig.)
  2 => bstr .size (16..64),      ; resume_token [M1.3-PROVISIONAL] (obrig., redigido)
  3 => [0*16 DisplayFrameCursor],; last_good_frames (obrig., display_ids unicos)
}

SessionResumeResponse = {
  1 => bool,                     ; accepted (obrig.)
  2 => session-id,               ; session_id != 0 (obrig.)
  3 => [0*16 ActiveDisplayConfig], ; preserved_displays (>=1 se accepted, 0 se rejeitado)
  4 => [0*16 display-id],        ; idr_requested_displays (obrig.)
}

SessionClose = {
  1 => session-id,               ; session_id != 0 (obrig.)
  2 => close-reason,             ; reason_code (obrig.)
  3 => bool,                     ; teardown_virtual_displays (obrig.)
}
```

### 5.6 Permissões e Autorização (`0x0400–0x0401`, `Channel 0`, ALPN `"lumabridge/1"`)

```cddl
PermissionUpgradeRequest = {
  1 => session-id,               ; session_id != 0 (obrig.)
  2 => uint .gt 0,               ; request_seq >=1 (obrig.)
  3 => 1..127,                   ; requested_perms nao-zero, bits 0..6 (obrig.)
  4 => tstr .size (0..128),      ; reason_text UTF-8 (obrig.)
}

PermissionUpdate = {
  1 => session-id,               ; session_id != 0 (obrig.)
  2 => uint .gt 0,               ; update_seq >=1 (obrig.)
  3 => permissions-mask,         ; effective_perms (0 permitido para revogacao total) (obrig.)
}
```

### 5.7 Feedback, ClockSync, Heartbeat, Telemetria e Entrada (`0x0500–0x0600`, ALPN `"lumabridge/1"`)

```cddl
MediaFeedback = {                ; Channel 2
  1 => session-id,               ; session_id != 0 (obrig.)
  2 => display-id,               ; display_id (obrig.)
  3 => u32,                      ; last_complete_frame_id (obrig.)
  4 => u32,                      ; last_displayed_frame_id (<= last_complete_frame_id) (obrig.)
  ? 5 => u16,                    ; broken_gop_id (opc.)
  6 => bool,                     ; request_idr (obrig.)
  7 => 0..10000000,              ; decode_p50_us (obrig.)
  8 => 0..10000000,              ; decode_p95_us (>= decode_p50_us) (obrig.)
  9 => 0..10000000,              ; present_p95_us (obrig.)
  10 => 0..1000000,              ; rx_fps_milli (obrig.)
  11 => 0..1000000,              ; packet_loss_ppm (obrig.)
  12 => 0..10000000,             ; jitter_us (obrig.)
  13 => 0..1000000000,           ; suggested_bitrate_bps (obrig.)
}

ClockSyncPing = {                ; Channel 2
  1 => uint .gt 0,               ; seq >=1 (obrig.)
  2 => u64,                      ; t1_client_mono_us (obrig.)
}

ClockSyncPong = {                ; Channel 2
  1 => uint .gt 0,               ; seq >=1 (obrig.)
  2 => u64,                      ; t1_client_mono_us (obrig.)
  3 => u64,                      ; t2_server_recv_us (obrig.)
  4 => u64,                      ; t3_server_send_us (>= t2_server_recv_us) (obrig.)
}

Heartbeat = {                    ; EXCLUSIVO Channel 2
  ? 1 => session-id,             ; session_id opcional (!= 0 se presente)
  2 => uint .gt 0,               ; seq >=1 (obrig.)
  3 => u64,                      ; uptime_ms (obrig.)
}

DiagnosticsSummary = {           ; Channel 0
  1 => session-id,               ; session_id != 0 (obrig.)
  2 => 1..3600000,               ; window_ms (obrig.)
  3 => 0..10000000,              ; e2e_p50_us (obrig.)
  4 => 0..10000000,              ; e2e_p95_us (>= e2e_p50_us) (obrig.)
  5 => 0..10000000,              ; e2e_p99_us (>= e2e_p95_us) (obrig.)
  6 => 0..10000,                 ; cpu_usage_bps (0.00%..=100.00%) (obrig.)
  7 => 0..10000,                 ; gpu_usage_bps (0.00%..=100.00%) (obrig.)
  8 => u64,                      ; ram_rss_kib (obrig.)
  9 => u64,                      ; backpressure_drops (obrig.)
  10 => bool,                    ; hw_accel_active (obrig.)
}

InputEvent = PointerMoveAbs / PointerButton / PointerScroll / KeyEvent / TouchContact / StylusEvent

PointerMoveAbs = { 1 => 1, 2 => u16, 3 => u16 }
PointerButton  = { 1 => 2, 2 => 0..31, 3 => bool }
PointerScroll  = { 1 => 3, 2 => -1000000..1000000, 3 => -1000000..1000000 }
KeyEvent       = { 1 => 4, 2 => u16, 3 => u16, 4 => bool, 5 => 0..255 }
TouchContact   = { 1 => 5, 2 => 0..255, 3 => 1..4, 4 => u16, 5 => u16, 6 => u16 }
StylusEvent    = { 1 => 6, 2 => u16, 3 => u16, 4 => u16, 5 => -90..90, 6 => -90..90, 7 => 0..15 }

InputBatch = {                   ; EXCLUSIVO Channel 3 (payload total <= 1.024 B)
  1 => session-id,               ; session_id != 0 (obrig.)
  2 => display-id,               ; display_id 0..=65534 (obrig.)
  3 => uint .gt 0,               ; input_seq >=1 monotonico (obrig.)
  4 => [1*32 InputEvent],        ; events 1..=32 (campos redigidos em Debug/logs)
}
```

### 5.8 Erros Estruturados (`0x0700`, `Channel 0`, ambos os ALPNs)

```cddl
ErrorNotice = {
  1 => 1..12,                    ; code (obrig.)
  2 => bool,                     ; fatal (obrig.)
  3 => u16,                      ; related_msg_type (0 se framing/desconhecido) (obrig.)
  4 => tstr .size (0..128),      ; context_ascii ASCII imprimivel 0x20..=0x7E sem segredos (obrig.)
}
```

| Código | Nome | Descrição Normativa |
|---:|---|---|
| `1` | `ERR_UNSUPPORTED_VERSION` | `protocol_major` incompatível no handshake. |
| `2` | `ERR_INVALID_FRAMING` | `magic_ver`, `channel_id`, `msg_type`, CBOR malformado, campo reservado não zero ou troca de canal em stream. |
| `3` | `ERR_FRAME_TOO_LARGE` | Payload excede teto do canal ou teto `8 MiB` do quadro. |
| `4` | `ERR_UNSUPPORTED_FEATURE` | Mensagem desconhecida com `MUST_UNDERSTAND` ou flag/capacidade não suportada. |
| `5` | `ERR_UNAUTHORIZED_PEER` | Certificado não presente ou revogado no Trust Store *(camada `M1.3`)*. |
| `6` | `ERR_PAIRING_CLOSED` | Tentativa em `"lumabridge-pair/1"` sem janela de pareamento aberta. |
| `7` | `ERR_PAIRING_FAILED` | Falha criptográfica SPAKE2/QR ou limite de tentativas excedido *(camada `M1.3`)*. |
| `8` | `ERR_PERMISSION_DENIED` | Captura, extensão ou evento de `InputBatch` sem permissão ativa correspondente. |
| `9` | `ERR_SESSION_NOT_FOUND` | `session_id` desconhecido, divergente ou expirado. |
| `10` | `ERR_DISPLAY_UNAVAILABLE` | `display_id` inválido/reservado (`0xFFFF`) ou indisponível. |
| `11` | `ERR_CODEC_NEGOTIATION_FAILED` | Nenhum codec/perfil compatível encontrado entre os nós. |
| `12` | `ERR_RATE_LIMITED` | Excesso de requisições de pareamento, controle, input ou pedidos de IDR. |

---

## 6. Formato de Pacote de Vídeo (`VideoPacketHeader` — 44 bytes Big-Endian)

Todo datagrama (ou payload de registro `Channel 1 / 0x0800` em stream) inicia com exatamente **44 bytes** em Big-Endian seguidos de `payload_len` bytes opacos do bitstream codificado (sem uso de `transmute`, `repr(packed)` ou casts de ponteiros):

| Offset | Tamanho | Campo | Tipo | Limite / Regra Normativa v1.0 |
|---:|---:|---|---|---|
| `0..1` | `2 B` | `magic_ver` | `uint16` BE | Fixo `0x4C42` (`'LB'`). Qualquer outro valor é descartado imediatamente. |
| `2..3` | `2 B` | `flags` | `uint16` BE | Bitmask v1.0 (`0x003F`). Bits `6..=15` (`0xFFC0`) são reservados (`0`) e **rejeitados** se não zero. |
| `4..11` | `8 B` | `session_id` | `uint64` BE | Deve ser `!= 0` e coincidir com a sessão ativa. |
| `12..13` | `2 B` | `display_id` | `uint16` BE | `0..=65534` (`0xFFFF` rejeitado). |
| `14` | `1 B` | `codec_id` | `uint8` | `1 = H264`, `2 = HEVC`, `3 = AV1`; outros valores rejeitados. |
| `15` | `1 B` | `reserved` | `uint8` | Deve ser **`0` na v1.0**; receptor v1.0 **rejeita** se `reserved != 0`. |
| `16..19` | `4 B` | `frame_id` | `uint32` BE | Monotônico `>= 1` por `(session_id, display_id)`. `0` é rejeitado. |
| `20..21` | `2 B` | `gop_id` | `uint16` BE | Identificador modular da cadeia de predição (`0..=65535`). |
| `22..23` | `2 B` | `frag_index` | `uint16` BE | Índice do fragmento (`0 <= frag_index < frag_count`). |
| `24..25` | `2 B` | `frag_count` | `uint16` BE | Total de fragmentos do quadro (`1 <= frag_count <= 4.096`). |
| `26..27` | `2 B` | `payload_len` | `uint16` BE | Deve coincidir com `packet.len() - 44` e respeitar o orçamento efetivo; `0` permitido **somente** com `FLAG_PROTECTED_BLANK`. |
| `28..35` | `8 B` | `capture_ts_us` | `uint64` BE | Timestamp monotônico da captura/aquisição na origem (`µs`). |
| `36..43` | `8 B` | `encode_done_ts_us` | `uint64` BE | Timestamp monotônico pós-encode (`µs`); **deve satisfazer `encode_done_ts_us >= capture_ts_us`**. |

### 6.1 Flags de Vídeo e Invariantes Entre Fragmentos

| Bitmask | Nome | Regra Normativa |
|---:|---|---|
| `0x0001` | `FLAG_KEYFRAME` | Quadro IDR / ponto limpo de acesso aleatório. Invariante no quadro. |
| `0x0002` | `FLAG_END_OF_FRAME` | Obrigatório **se e somente se** `frag_index == frag_count - 1`. |
| `0x0004` | `FLAG_HAS_CODEC_CONFIG` | Fragmento contém parâmetros de sequência inline (SPS/PPS/VPS); normalmente `frag_index == 0`. Não exigido invariante nos demais fragmentos. |
| `0x0008` | `FLAG_PROTECTED_BLANK` | Evento semântico de ocultação DRM/HDCP (Seção 10). Invariante no quadro. |
| `0x0010` | `FLAG_CHAIN_RESET` | Novo `gop_id` inicia cadeia limpa após recuperação; **exige `FLAG_KEYFRAME`**. Invariante no quadro. |
| `0x0020` | `FLAG_MIRROR_SOURCE` | Fonte é espelhamento (`1`) vs extensão virtual (`0`). Invariante no quadro. |
| `0xFFC0` | *(Reservado)* | Deve ser `0` na v1.0; qualquer bit setado é rejeitado. |

**Regras de consistência da remontagem:** todos os fragmentos de um mesmo `(session_id, display_id, frame_id)` devem coincidir exatamente em `codec_id`, `gop_id`, `frag_count`, `capture_ts_us`, `encode_done_ts_us` e na máscara de flags invariantes (`KEYFRAME | PROTECTED_BLANK | CHAIN_RESET | MIRROR_SOURCE = 0x0039`). Qualquer divergência invalida e descarta imediatamente toda a remontagem daquele `frame_id`.

---

## 7. Camadas de MTU, Fragmentação e Orçamento de Memória

### 7.1 Separação Normativa das 5 Camadas de MTU

1200 bytes de payload UDP **não** significam 1200 bytes disponíveis de aplicação LBWP. As camadas são estritamente separadas:

1. **MTU IP:** tamanho máximo do datagrama IP na interface (ex.: Ethernet `1500 B`, túnel seguro `1280 B`).
2. **Payload UDP:** `IP_MTU - cabeçalho IP (20/40 B) - cabeçalho UDP (8 B)`.
3. **Pacote QUIC (RFC 9000):** piso mínimo de transporte de `1200 B` para pacotes UDP carregando QUIC Initial/1-RTT.
4. **QUIC `DATAGRAM` Frame (RFC 9221):** limitado por `min(QUIC_packet_budget - QUIC_short_header - AEAD_tag - frame_header, peer_max_datagram_frame_size)`.
5. **Orçamento Efetivo de Pacote LBWP (`effective_lbwp_packet_budget`):** entregue explicitamente pelo módulo de transporte ao fragmentador (ou limitado ao teto `16.384 B` no framing de stream).

### 7.2 Fórmulas de Fragmentação (Aritmética Verificada)

- Piso mínimo obrigatório do orçamento de pacote LBWP: `45 B` (`44 B` de `VideoPacketHeader` + ao menos `1 B` de payload; para `ProtectedBlank`, `44 B`).
- `max_fragment_payload = min(effective_lbwp_packet_budget, negotiated_max_packet_bytes, u16::MAX as usize + 44) - 44`
- `max_representable_frame_bytes = min(8.388.608, 4.096 * max_fragment_payload)`
- Todos os cálculos usam aritmética verificada (`checked_sub`, `checked_mul`, `checked_div`).
- Se `frame_bytes == 0` (exceto `ProtectedBlank`) ou `frame_bytes > max_representable_frame_bytes`, o fragmentador **rejeita imediatamente antes de fragmentar** — **jamais trunca bitstreams**.
- `DPLPMTUD` (RFC 8899) pertence à futura camada de transporte e **não** é implementado na `M1.2`.

### 7.3 Orçamento de Remontagem e Limpeza Determinística

O receptor (`Reassembler`) aplica limites configuráveis **antes de alocar** memória para fragmentos:

| Limite | Padrão Inicial `M1.2` | Justificativa |
|---|---|---|
| `max_incomplete_frames_per_display` | **`4`** | Limita reordenação em voo e evita acúmulo de fila (*bufferbloat*). |
| `max_frame_bytes` | **`8 MiB` (`8.388.608 B`)** | Teto arquitetural por quadro codificado. |
| `max_display_bytes` | **`16 MiB` (`16.777.216 B`)** | Protege contra múltiplos quadros incompletos grandes em um mesmo display. |
| `max_session_bytes` | **`32 MiB` (`33.554.432 B`)** | Isola sessões concorrentes contra saturação cruzada. |
| `max_global_bytes` | **`64 MiB` (`67.108.864 B`)** *(experimental configurável)* | Permite até 2 sessões ativas em pico ou múltiplos displays sem risco de OOM em Android/embarcados; será reavaliado sob carga multi-sessão real em `M2+`. |
| `max_total_displays` | **`16`** | Impede criação ilimitada de tabelas por `(session_id, display_id)` forjados. |
| `max_pending_frames` | **`64`** | Limite global de estruturas de remontagem abertas simultaneamente. |
| `metadata_overhead_per_fragment_bytes` | **`64 B`** *(contabilizado explicitamente)* | Contabiliza entradas de mapa `BTreeMap<u16, Vec<u8>>` e descritores por fragmento contra os tetos de bytes. |
| `fragment_timeout_us` | **`150.000 µs` (`150 ms`)** | Expiração determinística por relógio monotônico do chamador. |

- **Sem pré-alocação baseada em `frag_count`:** o receptor **nunca** pré-aloca `8 MiB` nem `Vec` de `4.096` posições ao receber o primeiro fragmento. Os fragmentos são armazenados incrementalmente conforme chegam.
- **Liberação garantida:** conclusão, expiração, descarte por conflito/evicção, remoção de display ou encerramento da sessão liberam imediatamente todos os bytes e metadados contabilizados (`global_bytes == 0` quando vazio).
- **Separação de memória do consumidor:** após a conclusão da remontagem, o `Vec<u8>` consolidado (`ReassembledFrame`) é transferido ao consumidor e **deixa de integrar** o orçamento ativo de remontagem do `Reassembler`. O consumidor/núcleo (`ADR-0004`) é responsável por seu próprio orçamento pós-entrega até a decodificação.

---

## 8. Duplicação, Reordenação, Sequenciamento e Recuperação de GOP

1. **Fragmento duplicado idêntico:** ignorado idempotentemente sem dupla contabilização de bytes.
2. **Fragmento duplicado conflitante ou inconsistência de metadados:** se o payload divergir ou se `codec_id`, `gop_id`, `frag_count`, timestamps ou flags invariantes divergirem no mesmo `frame_id`, toda a remontagem daquele quadro é **invalidada e liberada imediatamente**, registrando evento de perda/corrupção para a máquina de recuperação.
3. **Fragmento atrasado de quadro já concluído ou descartado:** ignorado silenciosamente sem reabrir entrada de remontagem.
4. **Reordenação dentro da janela:** fragmentos fora de ordem dentro de um quadro e quadros fora de ordem dentro da janela de `4` quadros por display são tolerados. **A observação de um `frame_id` posterior não declara perda imediata do quadro anterior** enquanto este ainda puder completar dentro da janela e do timeout.
5. **Expiração (`expire(now_us)`):** conduzida por relógio monotônico fornecido pelo chamador (zero `sleep()` no protocolo); descarta quadros expirados e notifica a máquina de recuperação de GOP.
6. **Máquina de estados `AwaitingIdr` (`GopRecoveryStateMachine`):**
   - Mantém estado `InitialAwaitingIdr`, `Healthy`, `AwaitingIdr` ou `ProtectedBlanked`.
   - Em `Healthy`, se um quadro da cadeia atual expirar ou for descartado antes de completar, transiciona para **`AwaitingIdr`**, limpa quadros `P` dependentes em fila de reordenação, **não entrega** nenhum `P`-frame subsequente da cadeia quebrada ao consumidor e emite solicitação de IDR (`request_idr = true`) respeitando cooldown configurável (**padrão inicial `200 ms`**, dentro da faixa arquitetural `150–250 ms`).
   - A chegada de um novo **`IDR` íntegro (`FLAG_KEYFRAME`)** com `frame_id` válido recupera a cadeia e restaura o estado `Healthy`.
   - **Separação de responsabilidades:** `lumabridge-protocol` valida integridade estrutural de headers/fragmentos e cadeia lógica `frame_id`/`gop_id`; **não** decodifica nem valida sintaxe interna de bitstream H.264/HEVC/AV1.
7. **Sequenciamento e Wraparound:**
   - `frame_id` inicia em `1` e cresce estritamente por `(session_id, display_id)` **sem wraparound**; ao atingir `FRAME_ID_RENEWAL_THRESHOLD = u32::MAX - 10_000`, a camada de protocolo sinaliza `SessionRenewalRequired` para renovação controlada de `session_id`.
   - `gop_id` é modular em `u16` (`65535 -> 0`); a ordenação primária entre quadros usa exclusivamente `frame_id` (nunca comparação inteira ingênua de `gop_id`).
   - `input_seq`, `request_seq`, `update_seq`, `clock_sync_seq` e `heartbeat_seq` são contadores `u64` iniciados em `1` com rejeição de `0`, regressão/replay (`seq <= ultimo`) e exaustão em `u64::MAX` (`SequenceTracker`). *(Proteção criptográfica anti-replay e geração CSPRNG de identificadores pertencem à `M1.3`.)*

---

## 9. Matriz de Validação Contextual e Autorização

| Contexto (`ALPN`) | Fase da Conexão | Canal `0` | Canal `1` | Canal `2` | Canal `3` |
|---|---|---|---|---|---|
| `"lumabridge-pair/1"` | `PairingOpen` | `PairHello`, `PairSpakeMsg`, `PairQrAuth`, `PairConfirm`, `PairCancel`, `ErrorNotice` | **Rejeitado** (Fatal) | **Rejeitado** (Fatal) | **Rejeitado** (Fatal) |
| `"lumabridge/1"` | `OperationalHandshake` | `Hello`, `HelloAck`, `NodeCapabilities`, `ErrorNotice` | **Rejeitado** (Fatal) | `ClockSyncPing/Pong`, `Heartbeat` | **Rejeitado** (Fatal) |
| `"lumabridge/1"` | `OperationalAuthenticated` | Todas de `0x0200..=0x0401`, `0x0504`, `0x0700` *(exige sessão para `0x0302..0x0401`, `0x0504`)* | **Rejeitado** até `OperationalSessionActive` | `ClockSyncPing/Pong`, `Heartbeat` *(exige sessão para `MediaFeedback`)* | **Rejeitado** sem sessão + permissão |
| `"lumabridge/1"` | `OperationalSessionActive` | Controle de sessão, permissões, `DiagnosticsSummary`, `ErrorNotice` | `MediaVideoFragment (0x0800)` | `MediaFeedback`, `ClockSyncPing/Pong`, `Heartbeat` | `InputBatch (0x0600)` *(cada evento exige bit em `effective_perms`)* |

- **Invariante de entrada remota:** se qualquer evento em `InputBatch` exigir bit (`INPUT_POINTER = 0x08`, `INPUT_KEYBOARD = 0x10`, `INPUT_TOUCH = 0x20`, `INPUT_STYLUS = 0x40`) ausente em `effective_perms`, o lote é **rejeitado com `ERR_PERMISSION_DENIED` (`fatal = false`)** antes de tocar APIs nativas.

---

## 10. Conteúdo Protegido (`FLAG_PROTECTED_BLANK`)

Quando o emissor detectar conteúdo protegido por DRM/HDCP na origem, envia evento semântico explícito com:
- `flags`: `FLAG_PROTECTED_BLANK | FLAG_END_OF_FRAME` (`0x000A`, opcionalmente `| FLAG_MIRROR_SOURCE` `0x0020`). **Proibido** combinar com `FLAG_KEYFRAME`, `FLAG_HAS_CODEC_CONFIG` ou `FLAG_CHAIN_RESET`.
- `frag_count = 1`, `frag_index = 0`, `payload_len = 0` (pacote total exato de `44` bytes).

**Semântica obrigatória:**
- **Não** é tratado como perda de pacotes nem dispara `ERR_INVALID_FRAMING` por payload vazio.
- Descarta quadros anteriores incompletos no display, limpa quadros `P` em fila de reordenação e sinaliza `HideContentAndBlank` para ocultação imediata do último quadro exibido, impedindo vazamento de pixels protegidos.
- A exibição de vídeo normal retoma exclusivamente na chegada de um novo **IDR íntegro (`FLAG_KEYFRAME`)**.
- **Nota `M1.2`:** a fronteira `C ABI` da `M1.1` (`lumabridge-ffi`) **não** foi alterada nesta etapa apenas para aceitar buffers vazios.

---

## 11. Matriz de Erros, Segurança e Privacidade

| Classe de Erro | Origem | Ação Obrigatória | Resposta na Rede |
|---|---|---|---|
| **`FatalStream`** | `frame_len` acima do limite do canal, `channel_id` inválido, flags reservadas `!= 0`, troca de canal no stream, `MUST_UNDERSTAND` desconhecido, CBOR inválido em canal confiável, mensagem fora de ALPN/canal | Abortar parser do stream e encerrar conexão/stream | `ErrorNotice(fatal = true)` no `Channel 0` *(exceto se o próprio `ErrorNotice` estiver corrompido ou para evitar loop)* |
| **`DropDatagram`** | Datagrama de mídia `< 44 B`, `magic_ver != 0x4C42`, `reserved != 0`, flags de vídeo inválidas, `session_id` divergente, `payload_len` incompatível | Descartar datagrama silenciosamente e incrementar contador local | **Nenhuma resposta de erro por datagrama** *(previne amplificação)* |
| **`RejectFrame`** | Fragmento conflitante, estouro de orçamento de remontagem (`> 8 MiB` / `> 4` quadros / orçamento global), expiração | Descartar quadro incompleto, liberar orçamento imediatamente e acionar `AwaitingIdr` se afetar cadeia ativa | `MediaFeedback(request_idr = true)` respeitando cooldown (`200 ms`) |
| **`ContextualError`** | `InputBatch` sem permissão ativa ou `session_id` não ativo em comando não fatal | Descartar comando/evento antes de tocar APIs nativas | `ErrorNotice(ERR_PERMISSION_DENIED / ERR_SESSION_NOT_FOUND, fatal = false)` |

**Privacidade e saneamento:** `Debug`, `Display` e diagnósticos de `lumabridge-protocol` redigem explicitamente `spake_payload`, `key_confirmation`, `one_time_pairing_token`, assinaturas de pareamento, `resume_token`, todo o conteúdo de eventos de teclado/ponteiro/toque/caneta em `InputBatch` e os bytes de bitstream de vídeo.

---

## 12. Exemplos Hexadecimais e Golden Vectors Independentes

Todos os vetores abaixo são verificados byte a byte nos testes independentes em [`core/crates/lumabridge-protocol/tests/golden_vectors.rs`](../../core/crates/lumabridge-protocol/tests/golden_vectors.rs) e [`tests/corpus/golden_vectors.hex`](../../core/crates/lumabridge-protocol/tests/corpus/golden_vectors.hex):

1. **Stream `FrameHeader` (8 B — `Hello` `0x0200`, Ch `0`, `len=66`, `MUST_UNDERSTAND`):**
   `00 00 00 42 00 02 00 01`
2. **Stream `FrameHeader` (8 B — `MediaVideoFragment` `0x0800`, Ch `1`, `len=48`, `flags=0`):**
   `00 00 00 30 01 08 00 00`
3. **`VideoPacketHeader` (44 B — H.264 IDR frag `0/2`, `KEYFRAME | HAS_CODEC_CONFIG | CHAIN_RESET = 0x0015`, `payload_len=1156`):**
   `4C 42 00 15 01 02 03 04 05 06 07 08 00 00 01 00 00 00 00 01 00 01 00 00 00 02 04 84 00 00 00 00 00 0F 42 40 00 00 00 00 00 0F 4C 04`
4. **`VideoPacketHeader` (44 B — `ProtectedBlank`, `FLAG_PROTECTED_BLANK | FLAG_END_OF_FRAME = 0x000A`, `payload_len=0`):**
   `4C 42 00 0A 01 02 03 04 05 06 07 08 00 01 01 00 00 00 00 2A 00 03 00 00 00 01 00 00 00 00 00 00 00 1E 84 80 00 00 00 00 00 1E 84 E4`
5. **CBOR Determinístico `ClockSyncPing` (`0x0501`, `seq=1`, `t1_client_mono_us=1000`):**
   `A2 01 01 02 19 03 E8`
6. **CBOR Determinístico `PairCancel` (`0x0104`, `attempt=7`, `reason=UserCancelled(1)`, `detail="timeout"`):**
   `A3 01 07 02 01 03 67 74 69 6D 65 6F 75 74`
7. **CBOR Determinístico `ErrorNotice` (`0x0700`, `code=2`, `fatal=true`, `related=0x0300`, `context="bad_alpn"`):**
   `A4 01 02 02 F5 03 19 03 00 04 68 62 61 64 5F 61 6C 70 6E`

---

## 13. Limitações Atuais e Decisões Pendentes para a `M1.3`

Esta especificação (`M1.2`) **não implementa** e reserva formalmente para decisão/implementação na **`M1.3` (Segurança e Transporte)**:

1. **Transcript oficial de pareamento:** definição exata da serialização canônica de entradas do transcript SPAKE2/QR.
2. **Label TLS Exporter e Channel Binding:** escolha definitiva entre `EXPORTER-Channel-Binding` puro da **RFC 9266** vs exporter específico da aplicação (`EXPORTER-lumabridge-pair-v1` com contexto via RFC 8446 §7.5), evitando mistura semântica dos dois mecanismos.
3. **Domain separation:** rótulos criptográficos distintos para SPAKE2 key confirmation, assinatura QR, `resume_token` e chaves derivadas.
4. **Representação SPKI e formato de assinatura:** travar `SubjectPublicKeyInfo` DER (44 bytes Ed25519) vs chave crua (32 bytes) nos campos `spki_ed25519` e assinaturas de `PairQrAuth`/`PairConfirm`.
5. **Confirmação de chave SPAKE2 (RFC 9382):** algoritmo exato de MAC/HKDF para `key_confirmation`.
6. **Uso único e expiração de tokens:** ciclo de vida estrito de `one_time_pairing_token`, PINs CSPRNG e `resume_token`.
7. **Política de `0-RTT` e anti-replay operacional:** desabilitação de `0-RTT` para comandos mutantes/input/sessão e proteção criptográfica contra replay entre conexões.
