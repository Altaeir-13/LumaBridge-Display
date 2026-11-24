# ADR-0003 - Visão oficial da plataforma universal LumaBridge Display

## Metadados

- **ID:** ADR-0003
- **Status:** Accepted
- **Data:** 2026-11-23
- **Relações:**
  - Supera parcialmente [ADR-0002 - Escopo técnico do MVP](./ADR-0002-mvp-technical-scope.md) (mantendo `Windows → Linux` apenas como primeiro fluxo funcional completo, e não mais como limite do produto).
  - Preserva a governança de branches definida em [ADR-0001 - Estratégia de branches e Pull Requests](./ADR-0001-branching-strategy.md).
  - Complementada por [ADR-0004 - Linguagem do núcleo e fronteiras nativas](./ADR-0004-core-language-and-native-boundaries.md) (`Proposed`) e [ADR-0005 - Arquitetura de transporte e segurança](./ADR-0005-transport-and-security-architecture.md) (`Proposed`).

## Contexto

O planejamento inicial do projeto ([REQUISITOS_LUMABRIDGE.md](../../REQUISITOS_LUMABRIDGE.md) e [ADR-0002](./ADR-0002-mvp-technical-scope.md)) foi estruturado para validar rapidamente um primeiro caso de uso concreto: PC Windows 11 com GPU NVIDIA RTX 3060 Ti estendendo a área de trabalho via driver IddCx para um laptop Arch Linux com Hyprland e decodificação VA-API.

Esse foco inicial cumpriu seu papel ao provar a viabilidade técnica do driver virtual Windows (`LumaBridgeIddDriver`), mas representava apenas a primeira implementação vertical de uma visão de produto mais ampla. Sem formalizar a visão definitiva agora, o protocolo de rede, a abstração de mídia e as interfaces internas correriam o risco de permanecer acoplados a um modelo unidirecional `Windows (NVENC) → Linux (VA-API)`.

## Decisão

Fica formalizada como definição oficial do projeto **LumaBridge Display**:

> **Plataforma open source, multiplataforma, bidirecional e independente de fabricantes para espelhamento, extensão real de desktop e interação remota autorizada entre dispositivos.**

### Requisitos permanentes do produto

1. **Plataformas prioritárias e expansão futura:**
   - Prioritárias: **Windows** (10/11 conforme compatibilidade efetiva de APIs, drivers e versões suportadas), **Linux com Wayland**, **Linux com X11/X.Org** e **Android**.
   - Expansão futura planejada: **macOS**, **iOS/iPadOS** e outras plataformas tecnicamente viáveis, respeitando suas restrições nativas de sandbox e APIs.
2. **Bidirecionalidade e papéis ortogonais:**
   - Qualquer dispositivo executa o conceito de **Nó LumaBridge** e pode assumir os papéis de **emissor**, **receptor** ou ambos simultaneamente, condicionado exclusivamente às capacidades efetivamente disponíveis no sistema operacional, compositor gráfico, permissões, drivers e hardware em execução.
3. **Separação estrita entre modos funcionais:**
   - **Espelhamento**, **extensão real de desktop na sessão ativa** e **interação remota** (mouse, teclado, toque, rolagem e caneta digital quando viável) são capacidades independentes.
   - A autorização para controlar remotamente ou capturar uma tela deve ser estritamente separada da autorização para visualizar vídeo recebido.
4. **Conectividade universal sem nuvem obrigatória:**
   - Suporte progressivo a Ethernet em rede local, Wi-Fi em rede local, conexões IP diretas entre dispositivos, USB quando existir transporte compatível (sem presumir USB-C como entrada física de vídeo) e conexões pela internet via travessia NAT/relay autenticado futuro.
   - O funcionamento local deve operar integralmente sem dependência de serviços em nuvem proprietários.
5. **Independência de fabricantes de hardware:**
   - Nenhum acelerador ou fabricante específico (como NVIDIA NVENC ou Intel VA-API) pode ser premissa obrigatória da plataforma; codecs, acelerações e formatos de superfície são negociados por sessão com fallback explícito quando viável.
6. **Segurança e autorização por design:**
   - Autenticação mútua pós-pareamento, criptografia de transporte, política negar por padrão (*deny-by-default*) e privacidade em logs fazem parte do núcleo arquitetural.
7. **Suporte progressivo a múltiplos displays e sessões:**
   - Protocolo, modelo de sessão e abstrações internas devem prever múltiplos monitores e múltiplos receptores por meio de identificadores explícitos (`session_id`, `display_id`) desde a v1, ainda que o MVP inicial ative um único display por sessão.
8. **Primeiro recorte vertical completo (`M2`):**
   - O fluxo `Windows → Linux` continua sendo a primeira entrega integrada completa do produto, mas não define nem limita a arquitetura multiplataforma.

### Preservação do investimento técnico existente

- O driver virtual Windows `LumaBridgeIddDriver` (C++/WDK/UMDF 2.31/IddCx 1.4), o pipeline D3D11/NVENC consolidado nas branches `fix/windows-idd-device-start`, `feature/windows-frame-extraction-ipc`, `feature/windows-gpu-shared-textures-nvenc` e `fix/m0-validation-gates-hardening` (`M4.1–M0.3`, consolidado localmente em `integration/m0-windows-closure` e ainda não integrado em `origin/dev`), os testes automatizados e o protocolo IPC local Windows (`LBIF` v1.0/v1.1) **serão integralmente preservados e reutilizados**.
- O driver IddCx permanece estritamente responsável por emulação de adaptador/monitor virtual e entrega local de quadros; **não** incorporará transporte remoto de rede nem lógica de codificação de vídeo.
- O protocolo de rede multiplataforma será independente do contrato IPC local `LBIF`.

## Invariantes e limites explícitos

1. **Receber vídeo ≠ criar monitor virtual:** um sistema que atua como receptor confiável não possui automaticamente capacidade técnica de criar um monitor virtual como emissor.
2. **Sessão isolada ≠ extensão da sessão ativa:** iniciar um servidor gráfico virtual separado (como `Xvfb` ou `Xdummy` no X11) ou exibir uma janela no receptor não comprova nem substitui a extensão real da área de trabalho da sessão gráfica ativa do usuário.
3. **Sem requisitos invasivos para operação básica:** o projeto não exigirá root (Android), desbloqueio de bootloader, desativação permanente de proteções do sistema operacional ou uso de APIs privadas não documentadas como condição para uso normal.
4. **Respeito a superfícies protegidas:** conteúdo protegido por DRM/HDCP continua explicitamente rejeitado sem exposição de pixels.
5. **Rastreabilidade de validação:** benchmarks sintéticos e testes unitários não substituem validação funcional real com drivers carregados e dispositivos reais em rede. Funcionalidades em branches ainda não integradas à `dev` devem permanecer explicitamente identificadas até seu merge e validação ao vivo.

## Consequências

### Positivas

- Evita acoplamento irreversível do protocolo de rede e dos módulos comuns às estruturas do Windows (`D3D11`, `DXGI_FORMAT`, `LUID`, `QPC`, `HANDLE`).
- Permite que o fluxo `Windows → Linux` avance aproveitando o investimento existente no `LumaBridgeIddDriver`, enquanto os contratos multiplataforma nascem preparados para Windows, Linux (Wayland e X11) e Android em ambos os sentidos.
- Estabelece critérios honestos na matriz de compatibilidade, diferenciando espelhamento de extensão real em cada ambiente gráfico.

### Custos e trade-offs

- Introduz abstrações explícitas de display, mídia, entrada e transporte antes do início do transporte LAN, aumentando a exigência de engenharia na fase `M1`.
- Exige manter uma matriz realista de capacidades por compositor Wayland, servidor X11, versão de Windows e modelo de restrição do Android.
