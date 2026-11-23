# Revisão de Licenciamento e Conformidade Legal — LumaBridge Display

> **Status da licença:** **`Apache-2.0` aprovada como licença candidata preferencial.** O arquivo `LICENSE` definitivo **ainda NÃO foi criado** no repositório; sua publicação depende da aprovação desta auditoria técnica/jurídica e da criação concomitante de `NOTICE` / `THIRD_PARTY_NOTICES.md`. Este documento constitui análise de engenharia e conformidade de software livre, devendo receber revisão jurídica formal caso o projeto venha a distribuir binários comerciais ou assinados em larga escala.

---

## 1. Inventário de Dependências Existentes e Planejadas

### 1.1 Dependências existentes (no repositório e nas branches de desenvolvimento Windows)

| Componente | Onde Existe | Licença Provável / Conhecida | Forma de Uso / Vínculo | Observação |
|---|---|---|---|---|
| **Windows SDK / WDK / UMDF / IddCx** (`wdf.h`, `IddCx.h`, `d3d11.lib`, `dxgi.lib`, `mfplat.lib`) | `origin/dev` (`windows/driver`) e branches M4 | Microsoft Windows SDK / WDK License | Headers em tempo de compilação + vínculo dinâmico com DLLs nativas do Windows do usuário | Padrão para software Windows; **não redistribuir** binários internos do SO/WDK fora do permitido pelo redistributable. |
| **MSVC C++ Runtime + Spectre libs** | Build Windows local | Microsoft Visual Studio Redistributable | Vínculo estático de runtime no driver UMDF (`/Qspectre`); dinâmico (`/MD`) ou redistribuível no host | Conformidade via uso legítimo de toolchain VS/WDK; em distribuição pública observar termos do MSVC Redistributable. |
| **`nvEncodeAPI.h`** (`FFmpeg/nv-codec-headers` `sdk/12.1`) | Branch `feature/windows-gpu-shared-textures-nvenc` (`windows/host/third_party/nvenc/`) | **MIT** *(verificado no cabeçalho do arquivo naquela branch)* | Header C puro incluído em compilação; `nvEncodeAPI64.dll` carregada dinamicamente do driver instalado no sistema (`LoadLibraryExW`) | Excelente padrão: **nenhuma DLL ou `.lib` proprietária da NVIDIA** é redistribuída no repositório. |

### 1.2 Dependências planejadas (Núcleo Multiplataforma, Vídeo, Transporte e Plataformas)

| Camada | Candidatos Principais | Licenças Típicas | Vínculo Pretendido |
|---|---|---|---|
| **Núcleo Rust (`M1`)** | `tokio`, `quinn`, `rustls`, `webpki`, `ed25519-dalek`, `spake2`, `prost`/`ciborium`, `mdns-sd` | Predominantemente **MIT OR Apache-2.0**; algumas crates cripto/FFI podem usar **ISC**, **BSD-3-Clause** ou **MPL-2.0** (ex.: `ring`/`aws-lc-rs`, `webpki`, `cbindgen`, `uniffi`) | Compilação estática no crate/biblioteca `lumabridge-core` |
| **Vídeo Hardware Windows (`M3`)** | **AMD AMF** headers, **Intel oneVPL** headers/dispatcher | **MIT** | Headers + carregamento dinâmico do runtime instalado pelo driver GPU do usuário (`amfrt64.dll`, runtime QSV/oneVPL) ou Media Foundation HW MFT do SO |
| **Linux Display & Captura (`M2`/`M4`)** | `wayland-client`, `pipewire` (`libpipewire`), `libxcb`/`libx11`, `libei`, `libva`, `vulkan-headers`, `SDL3` | **MIT** / **Expat** / **zlib** (`SDL3`) / **Apache-2.0** | Link dinâmico com bibliotecas de sistema da distribuição Linux |
| **Android (`M3`/`M5`)** | Android SDK/NDK, Kotlin stdlib, Jetpack Compose, `MediaCodec`, `MediaProjection`, `UsbManager` | **Apache-2.0** (+ termos Android SDK) | APIs do SO e bibliotecas Jetpack |
| **USB Alternativo (`M3` spike)** | `libusb` | **LGPL-2.1+** | **Obrigatório link dinâmico** (ou alternativo em Rust puro/`WinUSB` direto sem `libusb`) |
| **Fallback Software / Frameworks Opcionais** | `OpenH264`, `dav1d`, `SVT-AV1`, `FFmpeg`, `GStreamer`, `x264`, `x265` | Mistas (**BSD-2-Clause**, **BSD-3-Clause**, **LGPLv2.1+**, **GPLv2+**) | Análise diferenciada na Seção 2 e 3 abaixo |

---

## 2. Análise Jurídica Diferenciada por Tipo de Licença e Vínculo

Em vez de aplicar uma proibição genérica simplista a toda tecnologia associada a GPL/LGPL, cada classe de licença exige tratamento técnico distinto sob uma base principal **Apache-2.0**:

### 2.1 `Apache-2.0` como licença do projeto

- **Vantagens:**
  - Licença permissiva moderna amplamente aceita em ecossistemas open source, corporativos, Rust, Kotlin e Android.
  - Inclui **concessão explícita de patentes** dos contribuidores (Cláusula 3) com cláusula defensiva de retaliação — proteção superior à MIT/BSD para contribuições colaborativas.
  - Compatível com recebimento de dependências **MIT**, **BSD-2-Clause**, **BSD-3-Clause**, **ISC**, **zlib** e **MPL-2.0**.

### 2.2 Diferenciação `GPLv2` vs `GPLv3`

- **`GPLv2-only` (sem cláusula *or later*) vs `Apache-2.0`:**
  - São **mutuamente incompatíveis** quando combinadas no mesmo trabalho derivado distribuído (ex.: código vinculado no mesmo executável). Segundo a interpretação consolidada da FSF e da ASF, a cláusula de patentes da Apache-2.0 impõe restrições adicionais não aceitas pela GPLv2.
  - **Consequência prática:** qualquer biblioteca `GPLv2-only` (como determinados módulos de kernel/usuário ou bibliotecas antigas sem opção `v3`) **não pode** ser linkada (estática nem dinamicamente em um único programa distribuído) em binários distribuídos do LumaBridge sob Apache-2.0.
- **`GPLv3` (ou `GPLv2-or-later` usada sob `GPLv3`) vs `Apache-2.0`:**
  - São compatíveis em **direção única**: um projeto `GPLv3` pode incorporar código `Apache-2.0`, mas **a distribuição combinada inteira passa a ser regida pela `GPLv3`** (copyleft forte).
  - **Consequência prática:** bibliotecas GPLv3 como `libx264` (GPLv2+) ou `libx265` (GPLv2+) ou builds `FFmpeg --enable-gpl` não quebram a compatibilidade jurídica com código-fonte Apache-2.0 em si, mas **impedem distribuir o binário resultante sob termos puramente permissivos**. Por isso, **não** devem integrar os binários oficiais distribuídos do LumaBridge (podendo existir no máximo como plugins externos ou builds opcionais compilados pelo próprio usuário final sob GPLv3).

### 2.3 `LGPLv2.1` e `LGPLv3` (Ex.: FFmpeg LGPL, GStreamer core, `libusb`)

- **Compatibilidade com `Apache-2.0`:** é **juridicamente viável** distribuir uma aplicação principal `Apache-2.0` que utilize bibliotecas `LGPLv2.1` ou `LGPLv3` mantendo a licença permissiva do código próprio do LumaBridge, desde que cumpridos os requisitos da LGPL:
  1. **Linkagem dinâmica (`.dll` / `.so`) ou carregamento dinâmico (`dlopen`):** permite ao usuário final substituir ou atualizar a versão da biblioteca LGPL sem precisar recompilar o LumaBridge. *(Linkagem estática exigiria disponibilizar arquivos-objeto `.o`/`.obj` do LumaBridge para relinkagem pelo usuário, prática impraticável e desnecessária.)*
  2. **Avisos e acesso ao fonte LGPL:** incluir cópia da licença LGPL, avisos de copyright e disponibilizar/apontar o código-fonte exato da versão da biblioteca LGPL redistribuída junto ao instalador (ou usar a versão instalada pelo gerenciador de pacotes da distro no Linux, sem redistribuição direta no pacote LumaBridge).
  3. **Atenção especial ao Android / iOS:** em plataformas móveis onde redistribuir `.so` substituíveis em apps de loja ou fazer linkagem dinâmica tem limitações práticas (iOS proibia/restringe dylibs de terceiros historicamente), **evitar dependências LGPL no núcleo embarcado mobile** (`core/` + app Android).

### 2.4 `MPL-2.0` (ex.: crates Rust como `cbindgen`, `uniffi`, eventuais libs)

- **Copyleft fraco no nível de arquivo:** totalmente compatível com `Apache-2.0` no mesmo binário. Apenas modificações feitas dentro dos arquivos licenciados sob `MPL-2.0` precisam permanecer públicas sob `MPL-2.0`.
- Ferramentas de geração em tempo de build (`cbindgen`, `uniffi-bindgen`) em geral não licenciam o código-fonte gerado por seus templates sob copyleft, mas deve-se auditar versões de dependências a cada introdução no `Cargo.toml`.

### 2.5 Bibliotecas Opcionais, Processos Separados e Runtime do Sistema

- **Carregamento dinâmico opcional de runtimes do fabricante (`LoadLibraryExW` / `dlopen`):** componentes proprietários já instalados pelo fabricante no computador do usuário (`nvEncodeAPI64.dll`, `amfrt64.dll`, drivers Mesa/Intel VA-API, `MediaCodec`) **não são redistribuídos** pelo LumaBridge; apenas cabeçalhos MIT ou interfaces públicas documentadas do SO são usados em compilação.
- **Uso de CLI externa opcional / processos separados:** invocar ferramentas de sistema ou utilitários opcionais como subprocessos independentes não cria um único trabalho derivado linkado, mas caso o LumaBridge dependa estritamente deles em runtime, isso afeta a usabilidade e deve ser documentado separadamente.

---

## 3. Codecs Multimídia e Patentes (`H.264`, `HEVC`, `AV1`)

É indispensável distinguir **licença de copyright do código-fonte** de **licenciamento de patentes essenciais (SEPs)** de padrões de compressão de vídeo (MPEG-LA / Via LA / Access Advance):

1. **Delegação a aceleradores nativos do sistema operacional e hardware (estratégia principal):**
   - Ao usar **NVENC**, **AMD AMF**, **Intel oneVPL/QSV**, **Windows Media Foundation**, **Linux VA-API/Vulkan Video** e **Android MediaCodec**, o LumaBridge **não redistribui código de codificador/decodificador H.264 ou HEVC**; ele invoca o hardware e drivers licenciados já presentes no dispositivo do usuário. Isso reduz dramaticamente a superfície de risco e elimina necessidade de embutir `x264`/`x265`.
2. **Fallback Software H.264 (`OpenH264` — BSD-2-Clause):**
   - Para fallback diagnóstico ou ausência de hardware, recomenda-se usar **OpenH264** (`BSD-2-Clause`) utilizando o mecanismo de **download dinâmico em runtime do binário oficial pré-compilado pela Cisco** (quando habilitado pelo usuário), caso em que a própria Cisco assume os royalties de patente MPEG-LA dentro de seu programa público — evitando que o LumaBridge redistribua binários H.264 diretamente nos releases.
3. **AV1 (`dav1d` BSD-2-Clause / `SVT-AV1` BSD-3-Clause-Clear):**
   - O codec AV1 é regido pela licença de patentes *royalty-free* da **Alliance for Open Media (AOMedia)** e possui implementações em software rápidas sob licença BSD permissiva, tornando-se a melhor escolha para fallback software sem barreiras de patente quando disponível.
4. **HEVC (H.265) em software:**
   - Devido ao cenário fragmentado de pools de patentes HEVC, **não** incluir codificador/decodificador HEVC por software nos binários distribuídos oficiais do LumaBridge; suportar HEVC exclusivamente via aceleração nativa do SO/hardware já licenciada no dispositivo do usuário.

---

## 4. Política Recomendada e Checklist antes de Criar `LICENSE`

### Recomendação Oficial

1. **Adotar `Apache-2.0`** como licença oficial de todo o código-fonte do projeto LumaBridge Display, acompanhada de **DCO (`Developer Certificate of Origin` / `Signed-off-by`)** para contribuições externas em PRs (baixo atrito para contribuidores open source).
2. **Classificação obrigatória de dependências em 3 faixas (gate de CI futuro com `cargo-deny` / auditoria de dependências):**
   - **Faixa Verde (Permitida por padrão):** `MIT`, `BSD-2-Clause`, `BSD-3-Clause`, `Apache-2.0`, `ISC`, `Zlib`, `CC0-1.0` / `Unlicense`.
   - **Faixa Amarela (Permitida mediante revisão, link dinâmico e documentação em `THIRD_PARTY_NOTICES.md`):** `MPL-2.0`, `LGPL-2.1+` / `LGPL-3.0` (somente desktop via linkagem dinâmica ou carregamento runtime; evitada no núcleo mobile).
   - **Faixa Vermelha (Bloqueada nos binários oficiais distribuídos):** `GPLv2-only`, `GPLv3` (como dependência linkada), `AGPL`, código proprietário sem permissão explícita ou codecs HEVC software proprietários/patent-encumbered.

### Checklist antes do PR que criará `LICENSE`

- [ ] Aprovação humana da recomendação `Apache-2.0` + DCO neste documento.
- [ ] Conferência dos cabeçalhos em `windows/` e futuros módulos quanto a avisos de copyright consistentes.
- [ ] Criação simultânea de:
  - `LICENSE` (texto integral oficial Apache License 2.0 na raiz)
  - `NOTICE` (atribuição do projeto LumaBridge Display)
  - `THIRD_PARTY_NOTICES.md` (registrando `nvEncodeAPI.h` MIT de `FFmpeg/nv-codec-headers` quando `M4.2` for integrada, e futuras dependências)
  - Configuração de verificação automatizada de licenças (`cargo-deny` quando o workspace `core/` for criado em `M1`).
