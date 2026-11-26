# Especificação Normativa de Segurança e Pareamento — `lumabridge-security` (`M1.3`)

> **Escopo e limites arquiteturais:** Este documento define a arquitetura criptográfica, os contratos de identidade, channel binding, pareamento, autorização, tokens e revogação do crate [`lumabridge-security`](../../core/crates/lumabridge-security/Cargo.toml) (`#![forbid(unsafe_code)]`). Permanece desacoplado do transporte operacional (`QUIC`/`TCP`, reservados à `M1.4`) e da integração operacional de sessões (`M1.5`), mantendo [`ADR-0005`](../architecture/ADR-0005-transport-and-security-architecture.md) em **`Proposed`** e [`wire-protocol-v1.md`](../protocol/wire-protocol-v1.md) em **`Draft`**.

---

## 1. Referências Normativas

- **RFC 9846:** *The Transport Layer Security (TLS) Protocol Version 1.3* (julho de 2026; substitui formalmente a **RFC 8446**, preservada apenas para referência histórica).
- **RFC 9266:** *Channel Bindings for TLS 1.3* (`EXPORTER-Channel-Binding`, contexto vazio, saída de `32 bytes`).
- **RFC 9382:** *SPAKE2, a Password-Authenticated Key Exchange* (`P256-SHA256-HKDF-HMAC`, pontos SEC1 não comprimidos de `65 bytes`, confirmação mútua explícita).
- **RFC 8032:** *Edwards-Curve Digital Signature Algorithm (EdDSA)* (`Ed25519`: chave pública `32 B`, assinatura `64 B`).
- **RFC 8410** e **RFC 9295:** *Algorithm Identifiers and SubjectPublicKeyInfo for Ed25519* (`OID 1.3.101.112`, parâmetros ausentes, `44 bytes` DER canônicos).
- **RFC 8949:** *CBOR* §4.2.1 (*Core Deterministic Encoding Requirements*, perfil `LBWP-CBOR-v1`).
- **RFC 5869:** *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)*.
- **RFC 9106:** *Argon2 Memory-Hard Function* *(aplicável apenas como critério condicional futuro em cofres headless Linux quando houver segredo de desbloqueio adequado)*.

---

## 2. Threat Model (`M1.3`)

### 2.1 Superfície de Ameaças e Contramedidas

| Ameaça | Vetor / Ataque | Mitigação Normativa no `lumabridge-security` |
|---|---|---|
| **MITM no primeiro pareamento** | Atacante intercepta TLS `"lumabridge-pair/1"` terminando dois handshakes independentes | Binding criptográfico obrigatório via **`tls-exporter` (`RFC 9266`, `EXPORTER-Channel-Binding`, `32 B`)** autenticado no `AAD` do `SPAKE2` e nas assinaturas `Ed25519` de QR/confirm. Dois handshakes distintos produzem `tls-exporter` distintos. |
| **Impersonação / TOFU silencioso** | Peer apresenta certificado Ed25519 qualquer sem estar no Trust Store | `Operational` (`"lumabridge/1"`) rejeita no handshake mTLS qualquer certificado ausente ou revogado. Em `"lumabridge-pair/1"`, o peer permanece `UnverifiedPeer` (verificação explícita de `CertificateVerify`) até conclusão criptográfica + aprovação humana explícita. |
| **Downgrade de protocolo / TLS / modo** | Forçar TLS 1.2, ocultar `AuthMode` ou reduzir versão `LBWP` | `rustls` configurado estritamente para **TLS 1.3 apenas** (`tls12` desabilitado). Contexto assinado/autenticado fixa `protocol_major/minor`, `auth_mode` (`PinSpake2` vs `QrOutOfBand`), `alpn` e papéis `Initiator`/`Acceptor`. |
| **Replay e Reflection** | Reenviar `PairSpakeMsg`, `PairQrAuth`, `PairConfirm`, `SessionResumeRequest` ou refletir mensagem A->B de volta como B->A | Transcript inclui papéis explícitos (`Initiator` / `Acceptor`), `device_id`s ordenados por papel, `pairing_attempt_id` único e `tls-exporter` único por conexão; tokens QR/retomada têm **consumo atômico único**; contadores monotônicos via `SequenceTracker`. |
| **Unknown Key-Share / Troca de Papéis** | Associar chave derivada à identidade errada ou trocar `Initiator` por `Acceptor` | `idA`/`idB` canônicos e `AAD` SPAKE2 vinculam explicitamente `device_id_initiator`, `spki_initiator`, `device_id_acceptor` e `spki_acceptor`; mensagens `PairHello.spki_ed25519` devem coincidir byte-a-byte com o SPKI comprovado no canal TLS. |
| **Brute-force de PIN** | Testar PINs de 8 dígitos repetidamente ou em múltiplas sessões paralelas | Limite de **3 falhas por PIN** (destruição imediata após o 3º erro) + **orçamento global da janela de pareamento** independente de IP/endpoint + backoff exponencial limitado e evicção LRU. |
| **Tokens roubados & Corrida de consumo** | Uso concorrente de `QrToken` ou `ResumeToken` por duas threads/conexões | Consumo atômico via remoção em estrutura protegida (`remove`/compare-and-remove); `ResumeToken` armazenado apenas como digest `SHA-256(DOMAIN || token)` não recuperável e obrigatoriamente acoplado a **mTLS válido** da mesma `device_id` e `auth_revision`. |
| **Revogação vs Corrida de Autorização** | Cliente revogado tenta executar `InputBatch` ou usar `ResumeToken` em voo | Revogação incrementa estado terminal na identidade/revisão (`auth_revision`), invalida todos os `ResumeToken` do peer e emite ações tipadas de encerramento; validação de permissão exige correspondência com revisão vigente não revogada. |
| **Escalada de permissões** | Solicitar `INPUT_*` em `PairConfirm` ou aceitar `PermissionUpgradeRequest` vindo da rede | `PairConfirm` proíbe `INPUT_MASK` (`0x0078`) e limita padrão máximo inicial a `VIEW_MIRROR`; `PermissionUpgradeRequest` gera pendência exigindo aprovação local explícita e interseção de 5 fatores. |
| **Exaustão de recursos** | Flood de tentativas de pareamento, buckets de IP ou tokens pendentes | Tetos rígidos em número de janelas/tentativas ativas (`MAX_ACTIVE_PAIRING_ATTEMPTS`), entradas no rate limiter (`MAX_TRACKED_ENDPOINTS`), tokens ativos (`MAX_ACTIVE_TOKENS`) com expiração monotônica e limpeza determinística. |
| **Vazamento diagnóstico** | Logar PIN, semente Ed25519, `tls-exporter`, `QrToken`, `ResumeToken`, MACs ou keylog TLS | `Debug`/`Display` redigidos (`[REDACTED]`), `NoKeyLog` no `rustls`, `ZeroizeOnDrop` em segredos efêmeros/persistentes e testes com sentinelas sintéticas. |

### 2.2 Limites Reconhecidos (Sem Garantia Absoluta)
- **Comprometimento do SO ou da chave privada local:** se um atacante obtiver execução privilegiada ou acesso direto ao processo/memória/cofre do usuário local e extrair a chave privada Ed25519 ou os pixels capturados antes da proteção de cofre do SO (`M1.4+`), nenhuma criptografia de rede impede impersonação daquela máquina até revogação explícita nos pares remotos.
- **Cópias residuais em memória:** `zeroize` reduz a janela de exposição no heap/stack da aplicação, mas **não substitui** isolamento de processo nem impede dumps do kernel, páginas de swap não criptografadas ou otimizações de registradores anteriores à gravação.

---

## 3. Identidade Canônica, Certificados e Channel Binding

- **Ed25519 (`RFC 8032`):** chave pública bruta de **`32 bytes`**; assinatura exatamente **`64 bytes`** verificada via `verify_strict` (rejeitando maleabilidade e pontos de baixa ordem).
- **SPKI DER Canônico (`RFC 8410` / `RFC 9295`):** exatamente **`44 bytes`**:
  - Prefixo fixo de `12 bytes`: `30 2a 30 05 06 03 2b 65 70 03 21 00` (`SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING (0 unused bits) }`), **sem campo `parameters`** (`NULL` proibido), **sem bytes extras**, seguido dos `32 bytes` de chave pública válida.
  - **`device_id` (`[u8; 32]`):** `SHA-256(spki_der_44_bytes)`. Nome amigável (`friendly_name`) e endereço IP **nunca** são provas de identidade.
- **Perfil de Certificado X.509 (`RFC 5280` / `RFC 8410`):** X.509 **v3**, chave pública `Ed25519` (`1.3.101.112`, `44 B` DER canônico), assinatura própria `Ed25519` válida sobre `TBSCertificate` e janela temporal válida (`notBefore <= now <= notAfter`). CAs públicas genéricas são proibidas.
- **TLS 1.3 (`RFC 9846`) e Separação de ALPN:**
  - **`"lumabridge-pair/1"`:** canal restrito de pareamento sob janela explícita local; valida `CertificateVerify` e estrutura X.509 Ed25519, mas mantém o peer em **`UnverifiedPeer`** (jamais aprova assinatura às cegas e jamais promove para `TrustedPeer` só pelo certificado). Vincula obrigatoriamente `PairHello.spki_ed25519` ao SPKI autenticado no handshake TLS.
  - **`"lumabridge/1"`:** mTLS estrito mútuo contra `TrustStore` local (peer presente e não revogado; correspondência exata de SPKI e, quando conhecido, do `device_id` esperado). `Resumption` TLS (tickets/PSK) e `0-RTT` (`early_data`) **permanecem desabilitados**.
- **Channel Binding (`RFC 9266`):**
  - Rótulo ASCII exato **`"EXPORTER-Channel-Binding"`** (sem `NUL`), **contexto vazio (`b""`)**, saída de **`32 bytes`**, extraído **somente após handshake TLS 1.3 completo** (jamais *early exporter* nem chave de cifragem direta).
  - Abstração tipada `TlsChannelBinding` distingue `ChannelBindingSource::Tls13Exporter` (obtido de conexão TLS real autenticada) de `ChannelBindingSource::SyntheticTest` (restrito a testes). **Nunca** aceita valor enviado pelo peer como `tls-exporter` local. Um único fluxo de pareamento por conexão TLS; conclusão ou erro terminal encerra o canal.

---

## 4. Transcript Determinístico, Separação de Domínio, `SPAKE2` e Pareamento `QR`

### 4.1 Contexto Determinístico da Aplicação (`LBWP-CBOR-v1`) e Separação de Domínio
Toda prova criptográfica da aplicação usa codificação CBOR determinística (`LBWP-CBOR-v1` / RFC 8949 §4.2.1) prefixada por etiqueta ASCII de domínio estrita — eliminando concatenações ambíguas de campos de tamanho variável:
- `"lumabridge.pair.spake2.aad.v1"` — `AAD` passado à programação de chaves do `RFC 9382`: vincula `{ 1: major, 2: minor, 3: auth_mode=1, 4: alpn="lumabridge-pair/1", 5: attempt_id, 6: init_id, 7: init_spki, 8: acc_id, 9: acc_spki, 10: tls_channel_binding_32B }`.
- `"lumabridge.pair.qr.auth.v1"` — payload assinado por Ed25519 em `PairQrAuth.initiator_signature`: `{ 1: domain, 2: major, 3: minor, 4: auth_mode=2, 5: alpn, 6: attempt_id, 7: init_id, 8: init_spki, 9: acc_id, 10: acc_spki, 11: tls_cb_32B, 12: sha256(one_time_pairing_token) }`.
- `"lumabridge.pair.confirm.v1"` — payload assinado por Ed25519 em `PairConfirm.confirm_signature`: `{ 1: domain, 2: attempt_id, 3: auth_mode, 4: accepted, 5: granted_base_perms, 6: init_id, 7: init_spki, 8: acc_id, 9: acc_spki, 10: tls_cb_32B }`.
- `"lumabridge.session.resume.token.v1"` — domínio de hash de armazenamento do token de retomada opaco (`SHA-256(domain || raw_token_32B)`).

### 4.2 Pareamento PIN via `SPAKE2` (`RFC 9382`)
- **Ciphersuite:** **`P256-SHA256-HKDF-HMAC`** (grupo NIST P-256, codificação SEC1 não comprimida de **`65 bytes`** `0x04 || x || y`, constantes oficiais `M`/`N` da RFC 9382 §4, hash SHA-256, HKDF-SHA256 e HMAC-SHA256, `NH = 32`). Rejeita pontos inválidos, ponto identidade e codificações comprimidas/compactas não canônicas na fronteira `PairSpakeMsg`.
- **Conversão do PIN (`w`):** PIN CSPRNG de **8 dígitos ASCII** (`00000000..=99999999`, preservando zeros à esquerda, amostragem por rejeição sem viés sobre `u32`, validade de **90 s**):
  - `prk = HKDF-SHA256::extract(salt = b"lumabridge.pair.pin.salt.v1" || attempt_id_be64, ikm = pin_ascii_8bytes)`
  - `wide = HKDF-SHA256::expand(prk, info = b"lumabridge.pair.spake2.w.v1" || init_id || acc_id, len = 64)`
  - `w = P256Group::scalar_from_wide_bytes(wide)` (redução modular uniforme módulo ordem `n` de P-256).
- **Fluxo e identidades RFC 9382:** `Initiator` atua como **Party A** (`M`), `Acceptor` atua como **Party B** (`N`); `idA = "LB-INIT:" || init_id_32B`, `idB = "LB-ACC:" || acc_id_32B`; `AAD` = contexto determinístico CBOR `"lumabridge.pair.spake2.aad.v1"`. Usa integralmente o transcript `TT` (prefixos `u64` LE), o key schedule `Ke || Ka`, `KcA || KcB` e a confirmação mútua `cA` / `cB` (`32 B` cada) padronizados pela RFC 9382 §4 (comparação em tempo constante via `subtle::ConstantTimeEq`). Segredos efêmeros nunca são reutilizados e são zeroizados ao completar/cancelar/expirar.

### 4.3 Pareamento `QR` Out-of-Band
- **Payload QR versionado (`LBWP-QR-v1`, CBOR determinístico):** versão (`1`), `acceptor_device_id` (`32 B` SHA-256 SPKI), `one_time_pairing_token` (`32 B` CSPRNG), `endpoints` (dicas de conectividade — **nunca** prova de identidade), `expires_at_unix_s` / horizonte. Proibido vazar tokens em URLs ou logs.
- **Verificação antecipada no Iniciador:** antes de enviar `PairQrAuth`, o iniciador valida que `SHA-256(spki_tls_acceptor) == qr.acceptor_device_id`.
- **Consumo atômico no Aceitador:** valida janela aberta, expiração, correspondência de tentativas e remove atomicamente `one_time_pairing_token` (uso único) + verifica assinatura Ed25519 do iniciador sobre `"lumabridge.pair.qr.auth.v1"` vinculado ao `tls-exporter`.

---

## 5. Máquina de Estados, Aprovação Humana, Confiança, Autorização e Revogação

1. **Separação explícita de estados de pareamento:**
   `UnverifiedPeer` -> `CryptographicallyVerifiedPeer` -> `LocallyApprovedPeer` -> `TrustedPeer` -> `AuthenticatedSession` (via mTLS posterior).
2. **Invariante de aprovação humana (`HumanApprovalDecision`):** uma mensagem `PairConfirm` vinda da rede jamais simula consentimento local; a promoção para `LocallyApprovedPeer`/`TrustedPeer` exige entrada exclusiva por porta de aplicação local exibindo `friendly_name` não confiável claramente rotulado + `DeviceFingerprint` criptográfico.
3. **Consistência entre dois nós independentes:** pareamento não promete atomicidade distribuída impossível; o Aceitador persiste confiança apenas após aprovação local e antes/durante emissão de `PairConfirm`; se `PairConfirm` se perder na rede após aceitação local, o Iniciador não promove unilateralmente e uma nova tentativa/repareamento ou confirmação explícita reconcilia com segurança.
4. **Trust Store e Cofres Nativos:** `TrustStoreBackend` suporta inserção, consulta, atualização de revisão e revogação sem sobrescrita silenciosa de SPKI para o mesmo `device_id`. A `M1.3` entrega `InMemoryTrustStore` (explícito para testes/desenvolvimento) e interfaces/descritores para cofres nativos (**Windows DPAPI/Credential Manager**, **Linux Secret Service** com critério documentado de fallback headless Argon2id exigindo segredo de desbloqueio + salt `16 B` + parâmetros `RFC 9106`, e **Android Keystore**), sem declarar cofres nativos reais qualificados antes da integração de plataforma (`M3+`).
5. **Autorização (`Permissions`) e Revogação:**
   - Inicial em `PairConfirm`: teto padrão **`VIEW_MIRROR`** (`INPUT_*` proibido).
   - Efetiva na sessão = interseção de 5 conjuntos: **`local_policy & persisted_peer_perms & session_grant & requested_operation & negotiated_caps`**.
   - `PermissionUpgradeRequest` gera pendência vinculada à revisão vigente (`auth_revision`) e exige consentimento local explícito.
   - **Revogação** marca o registro como revogado, incrementa revisão, remove concessões/tokens de retomada e retorna ações tipadas (`DisconnectPeerSessions { device_id, reason: PeerRevoked }`) para execução pelo transporte em `M1.4`/`M1.5`.
6. **Tokens de Retomada (`ResumeToken`) & Anti-Replay:** tokens de `32 B` CSPRNG armazenados apenas via `SHA-256(DOMAIN || token)`, consumo único com rotação, vinculados a mTLS válido da mesma identidade e `auth_revision` (jamais restauram permissões revogadas), complementados por `SequenceTracker` monotônico por canal e registro de colisão de `session_id`.
