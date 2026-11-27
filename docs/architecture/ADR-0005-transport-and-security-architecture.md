# ADR-0005 - Arquitetura de transporte de rede, pareamento, segurança e recuperação de mídia

## Metadados

- **ID:** ADR-0005
- **Status:** Accepted *(qualificada empiricamente em M1.3.1, M1.4 e M1.5; sujeita ao gate de aprovação humana externa dos PRs empilhados #41/#43/#44 em `dev` e validação adicional em LAN real / `tc netem` na `M2`)*
- **Data:** 2026-11-23 *(atualizada em 2026-11-27 para fechamento da M1)*
- **Relações:**
  - Materializa os requisitos de conectividade e segurança da [ADR-0003 - Visão oficial da plataforma universal](./ADR-0003-universal-platform-vision.md).
  - Opera sobre a fronteira definida na [ADR-0004 - Linguagem do núcleo e fronteiras nativas](./ADR-0004-core-language-and-native-boundaries.md).
  - Especificação detalhada de mensagens em [wire-protocol-v1.md](../protocol/wire-protocol-v1.md) (`v1.0`).
  - Relatórios experimentais em [m1-4-transport-report.md](../transport/m1-4-transport-report.md) e [m1-5-integration-report.md](./m1-5-integration-report.md).

## Contexto

O LumaBridge Display precisa operar em redes Ethernet, Wi-Fi (5/6 GHz e redes compartilhadas potencialmente hostis), conexões IP diretas, enlaces USB compatíveis e, futuramente, conexões entre redes pela internet. Em contraste com o protocolo local `LBIF` (Named Pipe + `DuplicateHandle` + `IDXGIKeyedMutex`, restrito ao host Windows), o transporte remoto precisa equilibrar latência de sub-100 ms, segurança forte em redes não confiáveis e integridade visual sob perda de pacotes.

Duas falhas arquiteturais comuns precisam ser evitadas explicitamente desde o projeto:

1. **Bootstrap inseguro de mTLS:** não se pode iniciar uma sessão mTLS operacional confiando previamente em certificados desconhecidos e apenas "parear depois" — isso deixaria o primeiro contato vulnerável a ataques *Man-in-the-Middle* (MITM) ou violaria a semântica de mTLS estrito.
2. **Descarte ingênuo de quadros inter-preditos (P-frames):** descartar um quadro `P_k` arbitrário no emissor ou receptor e continuar decodificando `P_{k+1}` corrompe o buffer de referência do decodificador H.264/HEVC/AV1, produzindo artefatos visuais persistentes até o próximo keyframe periódico.

## Decisão proposta — Parte 1: Transporte de rede e recuperação de vídeo

### 1.1 Transportes candidatos

- **Candidato principal: `QUIC / TLS 1.3` (RFC 9000 + RFC 9221 Unreliable Datagrams):**
  - Multiplexação nativa de fluxos independentes sem *head-of-line (HOL) blocking* entre controle/sessão, feedback, input remoto e vídeo.
  - Entrega de vídeo preferencialmente em **datagramas não confiáveis (RFC 9221)** (ou streams efêmeros curtos com cancelamento rápido quando o ambiente restringir datagramas) para impedir que retransmissões de pacotes obsoletos bloqueiem quadros mais novos.
  - TLS 1.3 nativo obrigatório (criptografia autenticada AEAD + *forward secrecy*), *connection migration* para transições de interface (ex.: roaming Wi-Fi ↔ Ethernet) e suporte futuro a UDP hole punching em cenários WAN.
- **Alternativa obrigatória: `TCP / TLS 1.3` (com `TCP_NODELAY` e controle rígido de fila de aplicação):**
  - Destinado a ambientes corporativos/acadêmicos que bloqueiam tráfego UDP e a transportes estritamente orientados a fluxo TCP, como túneis de desenvolvimento `adb reverse` / `adb forward`.
  - Mantém exatamente o mesmo contrato lógico de mensagens e proteção TLS 1.3 do protocolo, mas exige política ainda mais agressiva de descarte **antes da escrita no socket** quando a janela TCP congestionar.

> **Status experimental:** A escolha híbrida com `QUIC / TLS 1.3` (datagramas RFC 9221 + streams confiáveis de controle/feedback/`ProtectedBlank`) e fallback `TCP / TLS 1.3` foi qualificada empiricamente nos benchmarks e testes da `M1.4` e `M1.5` ([m1-4-transport-report.md](../transport/m1-4-transport-report.md) e [m1-5-integration-report.md](./m1-5-integration-report.md)), promovendo esta ADR para `Accepted`; medições complementares em LAN física (`tc netem` 0,5%–5%) seguem no escopo da `M2`.

### 1.2 Framing, MTU, fragmentação e remontagem

- **Negociação e descoberta de MTU:**
  - Toda sessão inicia conservadoramente com payload máximo UDP seguro de **`1200 bytes`** (piso exigido pela RFC 9000 e seguro sobre túneis IPv4/IPv6/VPN sem fragmentação IP).
  - Quando ambos os lados operarem via QUIC em IP direto/LAN, utiliza-se DPLPMTUD (RFC 8899) para elevar opcionalmente o MTU efetivo (tipicamente até ~`1420–1460 bytes`) e consultar o orçamento `max_datagram_frame_size` exposto pelo peer na negociação RFC 9221.
- **Limites explícitos:**
  - Mensagem de controle confiável: máximo `64 KiB`.
  - Mensagem de feedback / sincronização de relógio: máximo `4 KiB`.
  - Mensagem de evento de entrada remota: máximo `1 KiB`.
  - Quadro de vídeo remontado máximo: `8 MiB` e no máximo `4.096` fragmentos por quadro (`frag_count`), evitando ataques de exaustão de memória no receptor.
- **Remontagem no receptor:**
  - Buffer de remontagem limitado a poucos quadros simultâneos (`<= 4` quadros em voo por `display_id`). Fragmentos pertencentes a quadros anteriores a um quadro mais novo já concluído (ou a um novo IDR completo) são descartados imediatamente.

### 1.3 Controle de congestionamento, taxa adaptativa e reconexão

- **Pacing e adaptação:** leituras periódicas de RTT, *pacing rate*, taxa de perda e fila de envio no transporte alimentam o controlador de bitrate do núcleo para ajustar dinamicamente o encoder (quando suportado por API dinâmica, como já previsto em `SupportsDynamicBitrateChange` no NVENC), evitando acúmulo de fila (*bufferbloat*).
- **Reconexão e limpeza de monitor virtual:**
  - Perdas breves de enlace acionam tentativa de retomada de sessão (`SessionResumeRequest` com token de sessão e janela de graça configurável, ex.: 15 s) antes de desmontar o monitor virtual no emissor — evitando rearranjo destrutivo de janelas em pequenas oscilações de Wi-Fi.
  - Expirado o timeout de heartbeat ou encerrada a sessão, o watchdog desmonta o monitor virtual e libera o pipeline GPU para nunca deixar monitores fantasmas.

### 1.4 Política de perda de dependências entre quadros (H.264 / HEVC / AV1)

Como o pipeline de baixa latência opera sem B-frames (`frameIntervalP = 1`, zero reordenação), a cadeia de predição segue `IDR_0 -> P_1 -> P_2 -> ... -> P_n` dentro de um mesmo `gop_id`:

1. **Invariante fundamental:** nunca entregar ao decodificador um quadro `P_{k+1}` se um quadro anterior da mesma cadeia (`P_k` ou `IDR_0`) tiver sido descartado ou perdido sem recuperação.
2. **Regra no Emissor (TX):**
   - Cada quadro recebe um `gop_id` monotônico incrementado a cada `IDR` e `frame_id` monotônico por `display_id`.
   - Se um quadro `P_k` precisar ser descartado na fila de envio por backpressure ou se o receptor reportar perda de `P_k`:
     - O emissor marca a cadeia atual (`gop_id`) como **quebrada (`chain_broken = true`)**.
     - Todos os quadros `P` subsequentes ainda dependentes daquela cadeia são suprimidos no envio (evitando desperdiçar banda com lixo visual indecodificável).
     - O núcleo solicita imediatamente um keyframe ao backend de encode (`RequestForceIdr` com headers de configuração inline, ex.: `repeatSPSPPS = 1`). O próximo quadro válido enviado inicia um novo `gop_id` em estado limpo.
3. **Regra no Receptor (RX):**
   - Ao detectar lacuna de `frame_id` ou expiração de remontagem de qualquer fragmento pertencente ao `gop_id` corrente:
     - O receptor transiciona para estado **`AwaitingIdr`**.
     - Mantém o **último quadro íntegro exibido na tela** (em vez de alimentar quadro corrompido ao decoder) e descarta qualquer pacote P do `gop_id` quebrado que chegue posteriormente.
     - Emite `MediaFeedback(request_idr = true, broken_gop_id, last_complete_frame_id)` com *rate-limit* (cooldown mínimo de `150–250 ms`) para evitar tempestade de keyframes em rajadas de perda.
     - A decodificação retoma no exato instante em que um novo `IDR` íntegro (com `CHAIN_RESET` / novo `gop_id`) é remontado.
4. **Evoluções pós-MVP previstas:**
   - **NACK seletivo (LAN de RTT muito baixo):** tolerar janela curta (ex.: 4–8 ms) para retransmitir 1–2 pacotes perdidos antes de declarar `gop_broken`, reduzindo quedas de fluidez por perda unitária.
   - **FEC leve adaptativo:** paridade XOR/Reed-Solomon opcional em Wi-Fi para recuperar perdas isoladas sem RTT de NACK.
   - **Reference Picture Invalidation (RPI) / Long-Term Reference (LTR) e Intra-Refresh (GDR):** quando ambos os codecs/drivers suportarem com previsibilidade, referenciar o último quadro confirmado pelo receptor em vez de exigir sempre um IDR completo de alto custo em banda.

---

## Decisão proposta — Parte 2: Pareamento, identidade, autenticação e autorização

O modelo de segurança separa rigorosamente o **estabelecimento inicial de confiança (Fase 1)** da **operação cotidiana autenticada (Fase 2)**, aplicando exclusivamente primitivas criptográficas padronizadas.

```mermaid
sequenceDiagram
    participant Init as Dispositivo Iniciador
    participant Acc as Dispositivo Aceitador

    Note over Init,Acc: FASE 1 - Primeiro Pareamento (ALPN "lumabridge-pair/1" - Bloqueia Midia e Input)
    Init->>Acc: Conexao TLS 1.3 (RFC 9846) com certificado Ed25519 (Peer = UnverifiedPeer)
    Note over Init,Acc: Ambos derivam tls_exporter = TLS-Exporter("EXPORTER-Channel-Binding", "", 32B — RFC 9266)
    alt Modo A - Pareamento via PIN (SPAKE2 RFC 9382 P256-SHA256-HKDF-HMAC)
        Note over Acc: Usuario abre janela de pareamento e gera PIN efemero CSPRNG (8 digitos, 90s)
        Init->>Acc: PairHello + Mensagem SPAKE2 com AAD CBOR deterministico ligado ao tls_exporter + SPKIs
        Acc->>Init: Mensagem SPAKE2 (pB)
        Init->>Acc: Confirmacao de chave RFC 9382 (cA)
        Acc->>Init: Confirmacao de chave RFC 9382 (cB) + PairConfirm apos aprovacao humana
    else Modo B - Pareamento via QR Code (Out-of-Band SPKI Pin + Token)
        Note over Acc: QR contem (spki_sha256_acc, pairing_token 32B CSPRNG, endpoints, expiracao)
        Init->>Init: Valida que spki_sha256 do certificado TLS == spki_sha256_acc ANTES de enviar segredo
        Init->>Acc: PairQrAuth(pairing_token, Sig_Ed25519_Init(dominio || contexto CBOR || tls_exporter || sha256(token)))
    end
    Note over Acc: Usuario aprova explicitamente nome + fingerprint do par (Permissao inicial max = VIEW_MIRROR; INPUT_* proibido)
    Acc->>Init: PairConfirm(granted_base_perms, confirm_signature)
    Note over Init,Acc: Persistir Ed25519 SPKI (44B DER) pinado em Trust Store seguro do SO e encerrar canal de pareamento

    Note over Init,Acc: FASE 2 - Sessoes Operacionais Subsequentes (ALPN "lumabridge/1")
    Init->>Acc: Handshake QUIC/TCP com mTLS estrito (SPKI validado contra Trust Store, sem pares nao confiaveis)
    Acc-->>Init: Aceita apenas se par cadastrado e nao revogado; caso contrario rejeita no handshake TLS
```

### 2.1 Estabelecimento inicial de canal criptografado e isolamento de ALPN

- **ALPNs estritamente segregados:**
  - `"lumabridge-pair/1"`: aceito **somente** quando o usuário abre explicitamente a janela de pareamento local (desabilitado por padrão em tempo normal). Rejeita qualquer mensagem operacional (`SessionOpen`, vídeo, captura, entrada remota).
  - `"lumabridge/1"`: aceito exclusivamente para dispositivos já pareados via **mTLS estrito**; rejeita no próprio handshake TLS qualquer certificado cujo SPKI não conste no *Trust Store* local ou esteja marcado como revogado.
- Toda sessão em `"lumabridge-pair/1"` inicia em TLS 1.3 com sigilo futuro (*forward secrecy*), mantendo o par classificado explicitamente como `UnverifiedPeer` até concluir a prova criptográfica contra MITM.

### 2.2 Verificação de identidade no primeiro pareamento (sem vulnerabilidade a MITM)

1. **Identidade criptográfica do nó:** cada instalação gera localmente um par de chaves assimétricas **Ed25519** de longo prazo (`RFC 8032`); sua representação canônica em fio/certificado é o `SubjectPublicKeyInfo` DER de **`44 bytes`** (`RFC 8410` / `RFC 9295`, OID `1.3.101.112` sem parâmetros) e o `device_id` público deriva do SHA-256 exato desses `44 bytes`.
2. **Channel Binding obrigatório (`RFC 9266`):** ambos os extremos exportam exatamente **`32 bytes`** da sessão TLS 1.3 corrente (`RFC 9846`, que substitui a histórica `RFC 8446`) utilizando estritamente o rótulo ASCII **`"EXPORTER-Channel-Binding"`** (sem `NUL`) e **contexto vazio (`""`)** após a conclusão do handshake (com *early exporter* proibido). Qualquer ataque MITM com dois handshakes TLS independentes produzirá valores `tls-exporter` diferentes nos dois lados. A separação de domínio entre pareamento SPAKE2, prova QR e confirmação final reside integralmente nos contextos CBOR determinísticos autenticados/assinados da aplicação, nunca alterando o rótulo da RFC 9266.
3. **Autenticação por código/PIN (`SPAKE2` — `RFC 9382` `P256-SHA256-HKDF-HMAC`):**
   - O aceitador gera PIN numérico efêmero via CSPRNG do SO (`8` dígitos preservando zeros à esquerda, amostragem sem viés, validade de `90 s`, uso único).
   - O protocolo **SPAKE2** (`RFC 9382`, pontos P-256 SEC1 não comprimidos de `65 bytes`, `w` derivado por `HKDF-SHA256` em `64 B` reduzido mod ordem `n`) roda vinculado via campo `AAD` ao contexto CBOR determinístico `"lumabridge.pair.spake2.aad.v1"` (contendo papéis, identidades, SPKIs, `pairing_attempt_id`, versão, ALPN e `tls-exporter`). Sem conhecer o PIN, um atacante ativo ou passivo não consegue completar a confirmação mútua de chave (`cA`/`cB` de `32 B`), e o vínculo com `tls-exporter` impede retransmissão entre duas conexões TLS distintas por um MITM.
4. **Autenticação por QR Code (canal visual fora de banda):**
   - O QR Code (`LBWP-QR-v1`) gerado pelo aceitador embute: `spki_sha256` do aceitador, `pairing_token` aleatório CSPRNG de **`32 bytes`** (`256 bits`), dicas de endpoint (IP/porta/mDNS, nunca prova de identidade) e timestamp de expiração.
   - O iniciador verifica o hash do SPKI TLS do aceitador contra `spki_sha256` do QR **antes** de transmitir qualquer credencial, garantindo autenticidade do servidor desde o handshake TLS. Em seguida prova posse de sua própria chave Ed25519 assinando o contexto CBOR `"lumabridge.pair.qr.auth.v1"` vinculado ao `tls-exporter`, `pairing_attempt_id`, SPKIs e `SHA-256(one_time_pairing_token)`.
5. **Confirmação humana final:** antes de gravar no Trust Store, o usuário aceita explicitamente o dispositivo mostrando nome amigável (explícito como não confiável) e fingerprint abreviado; mensagens `PairConfirm` recebidas da rede jamais simulam consentimento humano local.

### 2.3 Armazenamento seguro das identidades pareadas

- Chaves privadas Ed25519 locais e registros de pares confiáveis (`device_id`, `spki_sha256`, apelido, conjunto de permissões concedidas, timestamps de criação/uso, `auth_revision` e flag de revogação) são protegidos pelos cofres nativos de cada SO:
  - **Windows:** DPAPI (`CryptProtectData` com entropia de aplicação vinculada ao usuário) / Credential Manager e arquivo ACL restrito ao usuário atual.
  - **Linux:** Secret Service (`org.freedesktop.secrets` / `libsecret` integrado ao GNOME Keyring/KWallet), com fallback explícito para arquivo local `0600` cifrado com chave derivada por Argon2id (`RFC 9106`) condicionado à existência de segredo de desbloqueio adequado, salt único e parâmetros documentados quando em ambiente headless sem keyring.
  - **Android:** Android Keystore (protegido por TEE/StrongBox quando presente) cifrando armazenamento privado do aplicativo (`EncryptedSharedPreferences` / DataStore cifrado).
  - *(Nota de escopo `M1.3`: o crate `lumabridge-security` define as interfaces/contratos desses cofres nativos e um backend explícito em memória apenas para testes/desenvolvimento; a implementação e qualificação nos cofres reais do SO acompanham a integração operacional em `M3+`.)*

### 2.4 Autenticação mútua nas conexões posteriores

- Todas as conexões subsequentes utilizam ALPN `"lumabridge/1"` com TLS 1.3 mútuo (`mTLS`, `RFC 9846`), com TLS 1.2, `0-RTT` (*early data*) e *session resumption* TLS por tickets/PSK **desabilitados**, onde tanto cliente quanto servidor apresentam certificado X.509 v3 Ed25519 válido e assinam o *CertificateVerify* do TLS 1.3.
- O verificador de certificados customizado consulta exclusivamente o Trust Store de pares autorizados (sem confiar em CAs públicas genéricas), garantindo rejeição imediata de desconhecidos ou revogados na camada TLS.

### 2.5 Revogação, anti-replay, anti-brute-force e permissões separadas

- **Revogação:** ao revogar um dispositivo na UI/CLI local, sua entrada é marcada/removida do Trust Store, seus tokens de retomada (`ResumeToken` de `32 B` armazenados apenas em digest `SHA-256`) são invalidados e são emitidas ações tipadas para encerramento imediato das sessões ativas associadas (`SessionClose` + fechamento do transporte em `M1.4`/`M1.5`).
- **Proteção contra tentativas excessivas (brute-force):**
  - Limite máximo de 3 tentativas inválidas por PIN gerado; ao atingir o limite, o PIN é destruído imediatamente e novas tentativas sofrem backoff exponencial e orçamento global da janela de pareamento entre todos os endpoints concorrentes.
  - Endpoint de pareamento fechado por padrão fora de janela explícita iniciada pelo usuário.
- **Proteção contra repetição (anti-replay):**
  - Toda sessão TLS 1.3 (`RFC 9846`)/QUIC já garante proteção AEAD contra replay de pacotes na conexão.
  - Tokens QR, desafios SPAKE2 e `session_id` (`64 bits` CSPRNG não zero com detecção de colisão) têm validade estrita de uso único por tentativa/sessão; mensagens de controle e mudança de permissão carregam números de sequência monotônicos validados por sessão, e tokens de retomada operacionais exigem mTLS válido sem jamais restaurar permissões revogadas.
- **Autorização granular (`Deny-by-Default`):**
  - Permissões armazenadas e negociadas de forma ortogonal:
    - `VIEW_MIRROR` (ver espelhamento)
    - `EXTEND_DISPLAY` (receber área estendida)
    - `CAPTURE_CONTROL` (autorizar outro nó a solicitar captura local)
    - `INPUT_POINTER`, `INPUT_KEYBOARD`, `INPUT_TOUCH`, `INPUT_STYLUS` (injeção remota, todas **negadas por padrão**)
    - `AUDIO_STREAM` (futuro)
  - Solicitações de elevação de permissão em tempo de execução (`PermissionUpgradeRequest`) exigem aprovação local interativa explícita no dispositivo que será controlado ou capturado; eventos de input recebidos sem a permissão ativa correspondente na sessão são descartados imediatamente e registrados em auditoria sem conteúdo sensível.

### 2.6 Privacidade em logs e telemetria

- **Proibição absoluta:** logs de diagnóstico e relatórios JSON/Markdown jamais registram pixels da área de trabalho, teclas digitadas, coordenadas detalhadas associadas a conteúdo sensível, chaves privadas, segredos compartilhados, `tls_exporter`, `pairing_token` ou PINs.

## Consequências

### Positivas

- Elimina vulnerabilidades clássicas de pareamento ingênuo (TOFU silencioso ou mTLS com pares desconhecidos) usando padrões auditados (`TLS 1.3`, `RFC 9266`, `RFC 9382` SPAKE2, `Ed25519`).
- Impede corrupção progressiva do decodificador H.264/HEVC/AV1 sob perda de pacotes em redes Wi-Fi por meio da política consciente de `gop_id` / `AwaitingIdr` / `RequestForceIdr`.
- Mantém caminho claro para testes de benchmark entre QUIC e TCP/TLS antes de travar a decisão final.

### Custos e trade-offs

- Pares perdidos (reinstalação de SO ou remoção do Trust Store) exigem novo pareamento explícito por segurança.
- No modo `AwaitingIdr`, perdas irrecuperáveis em Wi-Fi congestionado causam breve congelamento até a chegada do próximo IDR, priorizando fidelidade visual e zero acúmulo de latência sobre artefatos corrompidos (mitigável em evoluções pós-MVP com NACK seletivo/FEC/LTR).
