# LumaBridge Display // Design System

## 1. Propósito

Este documento define a direção visual e de experiência do usuário do LumaBridge Display.

O LumaBridge Display é uma aplicação técnica para transformar um laptop Linux em um monitor secundário real para um host Windows. A interface deve parecer uma ferramenta de sistema de baixa latência, com estética terminal cyberpunk, HUD operacional, leitura rápida de métricas e feedback claro de estado.

A inspiração visual vem de interfaces retrofuturistas, terminais, CRT, neon, scanlines e painéis de diagnóstico. Porém, diferente de um site-showcase, esta aplicação é uma ferramenta funcional. O design deve priorizar legibilidade, clareza operacional, baixa distração e segurança visual.

Regra principal:

> O conteúdo do monitor remoto deve permanecer visualmente fiel. Efeitos como scanlines, glitch, tint, bloom e distorção não devem ser aplicados por padrão sobre o vídeo recebido. Esses efeitos pertencem à interface, aos painéis, às telas de estado e ao overlay opcional de métricas.

---

## 2. Princípios de design

### 2.1 Clareza operacional antes de estética

A interface deve responder rapidamente a perguntas críticas:

- O host está online?
- O cliente está conectado?
- O Windows reconheceu o monitor virtual?
- O stream está ativo?
- Qual resolução, FPS, codec e bitrate estão em uso?
- Há perda, jitter, latência alta ou frames descartados?
- A sessão é pareada/autenticada?
- O usuário pode sair com segurança?

### 2.2 Cyberpunk contido

A estética cyberpunk deve aparecer em painéis de controle, logs, estados de conexão, overlay de métricas, telas de pareamento, telas de diagnóstico, loading/boot sequence e páginas de erro.

A estética não deve comprometer leitura de texto pequeno, contraste, operação em tela cheia, percepção do conteúdo transmitido, consumo de GPU/CPU ou acessibilidade mínima.

### 2.3 Interface como HUD técnico

A aplicação deve parecer um painel de operação de ponte de vídeo: status claros, códigos curtos, linguagem técnica, indicadores visuais discretos, logs estruturados, painéis modulares e estados de sessão explícitos.

### 2.4 Baixa latência visual

Animações devem ser leves, previsíveis e não bloqueantes. Nenhuma animação deve atrasar conexão, renderização, decode, encode ou atualização de métricas.

### 2.5 Modo MVP

No MVP, a interface pode ser CLI + arquivos de configuração + overlay simples. Mesmo assim, os nomes, mensagens, logs, cores e estados devem seguir este design system.

---

## 3. Personalidade visual

Nome visual da linguagem:

`BRIDGE_TERMINAL`

Descrição:

Uma interface de terminal operacional para streaming de display em baixa latência. Visual escuro, linhas finas neon, tipografia técnica, estados de sistema e estética de mainframe. A sensação desejada é de um painel de controle de infraestrutura gráfica, não de um dashboard corporativo genérico.

Palavras-chave:

- terminal;
- bridge;
- low latency;
- signal;
- sync;
- virtual display;
- HUD;
- neon;
- diagnostic;
- control room;
- mainframe;
- CRT discreto.

O tom visual deve comunicar precisão, controle, velocidade, estabilidade, tecnologia de baixo nível e risco técnico monitorado.

---

## 4. Paleta de cores

A paleta parte da inspiração de preto, neon pink e acid green, mas adiciona tons auxiliares para estados reais de produto: aviso, erro, informação, superfície e texto secundário.

### 4.1 Tokens principais

| Token | Hex | Uso |
|---|---:|---|
| `bg-core` | `#050507` | Fundo principal da aplicação |
| `bg-panel` | `#090910` | Painéis, cards e áreas de controle |
| `bg-elevated` | `#101018` | Painéis em destaque, modais e caixas de status |
| `border-muted` | `#242433` | Bordas discretas |
| `text-primary` | `#E8FFF8` | Texto principal |
| `text-secondary` | `#8EAFA7` | Texto auxiliar e descrições |
| `text-muted` | `#5E756F` | Labels secundários e metadados |
| `neon-pink` | `#FF00FF` | Acento primário, foco, heading, ação crítica de UI |
| `acid-green` | `#00FF66` | Status operacional, sucesso, stream ativo |
| `signal-cyan` | `#00D9FF` | Informação, rede, sincronização, transporte |
| `warning-amber` | `#FFB000` | Alerta, instabilidade, bitrate insuficiente |
| `danger-red` | `#FF355E` | Erro, desconexão, falha de driver ou autenticação |
| `video-safe-black` | `#000000` | Fundo ao redor do vídeo remoto |

### 4.2 Uso semântico

| Estado | Cor principal | Exemplo |
|---|---|---|
| Offline | `text-muted` | `HOST_OFFLINE` |
| Aguardando | `signal-cyan` | `AWAITING_CLIENT` |
| Pareando | `warning-amber` | `PAIRING_CODE_ACTIVE` |
| Conectado | `acid-green` | `CLIENT_CONNECTED` |
| Streaming | `acid-green` + pulso discreto | `STREAM_ACTIVE` |
| Instável | `warning-amber` | `JITTER_HIGH` |
| Erro | `danger-red` | `DRIVER_INIT_FAILED` |
| Ação/foco | `neon-pink` | botão ativo, foco de input |

### 4.3 Regras de aplicação

Não usar neon em grandes blocos de fundo. Neon deve ser usado em texto, borda, glow leve, foco e indicadores.

Não aplicar efeitos de tint, scanline ou glitch sobre o frame do monitor remoto por padrão.

O fundo principal deve ser quase preto, não obrigatoriamente preto puro. `#050507` reduz fadiga visual em uso prolongado.

O `acid-green` deve indicar operação saudável. O `neon-pink` deve guiar atenção e interação. O `signal-cyan` deve indicar rede/sincronização. O `warning-amber` e `danger-red` devem ser reservados para problemas reais.

---

## 5. Tipografia

### 5.1 Fontes recomendadas

| Fonte | Papel | Uso |
|---|---|---|
| `Share Tech Mono` | Fonte técnica principal | CLI, logs, métricas, labels, navegação |
| `Space Grotesk` | Fonte estrutural | Títulos de tela, botões, painéis |
| `VT323` | Fonte display opcional | Boot screen, splash, headings decorativos |

### 5.2 Fallbacks

Para web/Tauri:

```css
font-family: "Share Tech Mono", "JetBrains Mono", "Fira Code", monospace;
```

Para interfaces nativas:

- Linux: `JetBrains Mono`, `Fira Code`, `Noto Sans Mono`;
- Windows: `Cascadia Mono`, `Consolas`;
- fallback final: `monospace`.

### 5.3 Escala

| Nível | Desktop | Mobile | Fonte | Uso |
|---|---:|---:|---|---|
| Display | 72-96px | 48-64px | VT323/Space Grotesk | Splash, boot, branding |
| H1 | 40-56px | 32-40px | Space Grotesk | Título de tela |
| H2 | 28-36px | 24-28px | Space Grotesk | Seções |
| H3 | 20-24px | 18-20px | Space Grotesk | Cards |
| Body | 15-16px | 15-16px | Share Tech Mono | Texto comum |
| Label | 12-13px | 12px | Share Tech Mono | Métricas e campos |
| Micro | 10-11px | 10px | Share Tech Mono | Overlay compacto |

### 5.4 Convenções de texto

Preferir labels em uppercase técnico:

- `HOST_STATUS`
- `CLIENT_LINK`
- `VIRTUAL_DISPLAY`
- `ENCODER`
- `TRANSPORT`
- `FRAME_QUEUE`
- `LATENCY`
- `PACKET_LOSS`
- `DROPPED_FRAMES`

Mensagens de erro devem ser humanas o suficiente para ação.

Bom:

`DRIVER_INIT_FAILED // Verifique WDK, modo teste e instalação do driver.`

Ruim:

`Erro desconhecido.`

---

## 6. Layout e espaçamento

### 6.1 Grid base

A interface principal deve usar painéis modulares:

- margem externa: 24px desktop, 16px mobile;
- gap entre painéis: 16px;
- raio de borda: 0px ou 4px no máximo;
- bordas finas: 1px;
- painéis com fundo escuro e borda neon sutil.

### 6.2 Densidade

A interface deve ser densa, mas não ilegível. Métricas podem ser compactas; ações destrutivas e erros precisam de mais espaço visual.

### 6.3 Layout desktop sugerido

Para o host Windows:

```txt
┌────────────────────────────────────────────────────────────┐
│ Top Bar: LUMABRIDGE // HOST_CONTROL // STATUS              │
├───────────────┬───────────────────────────┬────────────────┤
│ Session       │ Virtual Display Preview   │ Metrics        │
│ Controls      │ / Status Panel            │                │
├───────────────┴───────────────────────────┴────────────────┤
│ Logs / Diagnostics                                          │
└────────────────────────────────────────────────────────────┘
```

Para o cliente Linux:

```txt
┌────────────────────────────────────────────────────────────┐
│ Fullscreen Video Surface                                    │
│                                                            │
│ [optional HUD overlay: FPS | BITRATE | LATENCY | LOSS]      │
└────────────────────────────────────────────────────────────┘
```

---

## 7. Componentes visuais

### 7.1 TerminalPanel

Container principal para conteúdo técnico.

Características:

- fundo `bg-panel`;
- borda `1px solid rgba(255, 0, 255, 0.22)`;
- hover opcional com borda `rgba(255, 0, 255, 0.45)`;
- título em `acid-green` ou `signal-cyan`;
- prefixo opcional: `$`, `>`, `//`, `[SYS]`;
- cantos retos.

Uso: logs, diagnóstico, configurações, status e mensagens de sessão.

### 7.2 StatusBadge

Pequeno indicador de estado.

Exemplos:

- `[ OFFLINE ]`
- `[ ONLINE ]`
- `[ PAIRING ]`
- `[ STREAMING ]`
- `[ DEGRADED ]`
- `[ ERROR ]`

Regras:

- sucesso: `acid-green`;
- informação: `signal-cyan`;
- alerta: `warning-amber`;
- erro: `danger-red`;
- estado neutro: `text-muted`.

### 7.3 MetricRow

Linha de métrica para painéis e overlay.

Campos:

- label;
- valor;
- unidade;
- tendência opcional;
- estado opcional.

Exemplos:

```txt
FPS              60.0
BITRATE          42.8 Mbps
LATENCY          18.4 ms
PACKET_LOSS       0.2 %
DROPPED_FRAMES       7
ENCODER          NVENC_H264
DECODER          VAAPI_H264
```

### 7.4 ActionButton

Botão de ação.

Tipos:

- primary: borda/texto `neon-pink`;
- success: borda/texto `acid-green`;
- warning: borda/texto `warning-amber`;
- danger: borda/texto `danger-red`.

Exemplos:

- `[ START_STREAM ]`
- `[ STOP_STREAM ]`
- `[ GENERATE_PAIRING_CODE ]`
- `[ REVOKE_CLIENT ]`
- `[ OPEN_DIAGNOSTICS ]`

Regras:

- botões devem ter foco de teclado visível;
- ação destrutiva deve exigir confirmação;
- `STOP_STREAM` deve ser sempre acessível durante streaming.

### 7.5 LogConsole

Console para logs estruturados.

Formato recomendado:

```txt
[12:04:01.231] [HOST] [INFO] virtual_display=ready mode=1920x1080@60
[12:04:01.512] [ENC]  [INFO] nvenc=h264 preset=low_latency
[12:04:02.018] [NET]  [WARN] jitter_ms=12.4 packet_loss=0.8%
[12:04:03.882] [CLNT] [OK]   decoder=vaapi_h264 render=wayland_fullscreen
```

Cores:

- `[INFO]`: `signal-cyan`;
- `[OK]`: `acid-green`;
- `[WARN]`: `warning-amber`;
- `[ERROR]`: `danger-red`.

### 7.6 HUDOverlay

Overlay opcional sobre o cliente fullscreen.

Regras críticas:

- deve ser desligável;
- não deve bloquear o vídeo;
- não deve capturar input indevidamente;
- não deve aplicar filtro sobre o frame do vídeo;
- deve ter opacidade baixa;
- deve ficar nos cantos, não no centro.

Layout sugerido:

```txt
┌──────────────────────────────┐
│ LUMABRIDGE // STREAM_ACTIVE  │
│ 1920x1080@60 | H264 | VAAPI  │
│ FPS 60.0 | LAT 18ms | LOSS 0 │
└──────────────────────────────┘
```

Posição padrão:

- canto superior esquerdo;
- margem 16px;
- largura máxima 360px;
- fundo `rgba(5, 5, 7, 0.72)`;
- borda `rgba(0, 255, 102, 0.35)`.

---

## 8. Telas previstas

### 8.1 Host Control

Objetivo: controlar o serviço host no Windows.

Conteúdo:

- status do driver;
- status do monitor virtual;
- resolução/FPS;
- encoder;
- bitrate;
- clientes conectados;
- botão iniciar/parar;
- logs.

Estados:

- `DRIVER_NOT_INSTALLED`;
- `DRIVER_READY`;
- `DISPLAY_ATTACHED`;
- `AWAITING_CLIENT`;
- `STREAMING`;
- `ERROR`.

### 8.2 Client Receiver

Objetivo: conectar o laptop Linux ao host e abrir o monitor em fullscreen.

Conteúdo:

- IP/host;
- status de conexão;
- decoder detectado;
- botão conectar;
- botão entrar fullscreen;
- diagnóstico VA-API;
- último host pareado.

Estados:

- `NO_HOST`;
- `CONNECTING`;
- `PAIRING_REQUIRED`;
- `CONNECTED`;
- `STREAMING`;
- `DEGRADED`;
- `DISCONNECTED`.

### 8.3 Pairing

Objetivo: parear cliente e host.

Host:

```txt
PAIRING_CODE
[ 483-921 ]

Expires in 02:00
Waiting for client...
```

Cliente:

```txt
ENTER_PAIRING_CODE
[ ___-___ ]

[ CONFIRM_PAIRING ]
```

Regras:

- código temporário;
- nunca exibir segredo persistente;
- logs não devem expor token;
- erro de código inválido deve ser claro.

### 8.4 Diagnostics

Objetivo: ajudar o usuário a diagnosticar ambiente.

Blocos:

- `WINDOWS_DRIVER`;
- `NVENC`;
- `VIRTUAL_DISPLAY`;
- `LAN_TRANSPORT`;
- `VAAPI`;
- `WAYLAND_FULLSCREEN`;
- `FIREWALL`;
- `LATENCY`.

Cada bloco deve ter status, descrição curta, ação recomendada e link para guia de setup quando existir.

### 8.5 Settings

Objetivo: editar parâmetros de runtime.

Campos:

- resolução;
- FPS;
- codec;
- bitrate;
- endereço do host;
- modo fullscreen;
- overlay ligado/desligado;
- atalhos;
- caminho de configuração;
- clientes pareados.

### 8.6 Error Screen

Objetivo: mostrar falha crítica sem ambiguidade.

Formato:

```txt
[ ERROR ] DRIVER_INIT_FAILED

O monitor virtual não pôde ser iniciado.

Possíveis causas:
- WDK/test mode não configurado.
- Driver não instalado.
- Serviço host sem permissão.
- Versão incompatível do Windows.

Ações:
[ OPEN_WINDOWS_SETUP_GUIDE ]
[ COPY_DIAGNOSTIC_LOG ]
[ RETRY ]
```

---

## 9. Estados visuais do sistema

| Estado | Visual | Animação |
|---|---|---|
| `BOOTING` | texto verde digitando | typewriter curto |
| `READY` | badge verde estável | nenhum ou pulso lento |
| `PAIRING` | badge amber | pulso lento |
| `CONNECTING` | cyan | spinner textual discreto |
| `STREAMING` | verde | pulso muito sutil |
| `DEGRADED` | amber | alerta sem piscar rápido |
| `ERROR` | vermelho | sem glitch excessivo |
| `STOPPING` | muted/cyan | progresso textual |

Evitar animações rápidas em erro. Erro precisa ser legível, não cinematográfico.

---

## 10. Animações e efeitos

### 10.1 Permitidos

- cursor piscando;
- typewriter em boot/logs curtos;
- scanline discreta em painéis;
- glow leve em headings e bordas;
- pulso lento em status;
- fade/slide leve em painéis;
- glitch curto apenas em transições de tela ou splash.

### 10.2 Restrições

Não usar efeitos contínuos pesados durante streaming.

Não usar matrix rain, partículas ou parallax em telas operacionais principais.

Não aplicar CRT bulge no vídeo remoto.

Não usar glitch contínuo em texto de erro, métricas ou logs.

Não usar animação que cause layout shift.

### 10.3 Duração recomendada

| Efeito | Duração |
|---|---:|
| Hover | 120-200ms |
| Fade de painel | 150-250ms |
| Typewriter boot | 10-15ms por caractere |
| Glitch pontual | 250-400ms |
| Pulso de status | 2-3s |
| Toast | 3-6s |

---

## 11. Overlay de métricas

O overlay é parte crítica do produto.

### 11.1 Métricas mínimas

- FPS;
- bitrate;
- latência aproximada;
- perda de pacotes;
- jitter;
- frames descartados;
- codec;
- decoder;
- resolução;
- estado da sessão.

### 11.2 Modo compacto

```txt
LB // 1080p60 // H264
FPS 60 | LAT 18ms | LOSS 0.1%
```

### 11.3 Modo expandido

```txt
LUMABRIDGE // STREAM_ACTIVE
MODE       1920x1080@60
ENCODER    NVENC_H264
DECODER    VAAPI_H264
BITRATE    42.8 Mbps
LATENCY    18.4 ms
JITTER      2.1 ms
LOSS        0.1 %
DROPPED       7
QUEUE        1f
```

### 11.4 Regras

- alternar overlay com atalho;
- permitir desligar completamente;
- fundo translúcido;
- não cobrir centro da tela;
- texto pequeno, mas legível;
- alerta amber/vermelho apenas quando necessário.

---

## 12. CLI e logs

Mesmo antes de existir UI gráfica, a CLI deve seguir a identidade visual do projeto.

### 12.1 Prefixos

```txt
[LB-HOST]
[LB-CLIENT]
[LB-DRIVER]
[LB-NET]
[LB-ENC]
[LB-DEC]
[LB-RENDER]
```

### 12.2 Exemplo host

```txt
LUMABRIDGE_HOST // BOOT
[OK] config_loaded path=./lumabridge.host.toml
[OK] driver_state=ready
[OK] virtual_display=attached mode=1920x1080@60
[OK] encoder=nvenc_h264
[WAIT] awaiting_client port=47777
```

### 12.3 Exemplo cliente

```txt
LUMABRIDGE_CLIENT // BOOT
[OK] wayland_session=hyprland
[OK] decoder=vaapi_h264
[INFO] connecting host=192.168.1.10:47777
[OK] session=connected
[OK] render=fullscreen
```

### 12.4 Erros

Erros devem incluir código, contexto, causa provável e próxima ação.

Exemplo:

```txt
[ERROR] VAAPI_DECODER_UNAVAILABLE
context=client_decode_init
cause="VA-API não encontrado ou driver Intel ausente"
next="Execute vainfo e consulte docs/setup/arch-linux-client.md"
```

---

## 13. Acessibilidade mínima

A estética neon não pode eliminar acessibilidade básica.

Requisitos:

- foco de teclado visível;
- contraste adequado para texto;
- não depender apenas de cor para estados;
- labels textuais junto com indicadores visuais;
- overlay desligável;
- animações reduzidas quando `prefers-reduced-motion` estiver ativo;
- textos de erro copiáveis;
- logs exportáveis;
- botões com estados claros.

### 13.1 Reduced motion

Quando movimento reduzido estiver ativo:

- desativar glitch;
- desativar parallax;
- reduzir pulse;
- remover scanline animada;
- manter apenas transições simples.

### 13.2 Conteúdo transmitido

A fidelidade do conteúdo remoto é uma regra de acessibilidade e usabilidade. O usuário pode arrastar documentos, IDEs, navegadores ou ferramentas para o monitor virtual. Portanto, o vídeo não deve receber filtro estilístico por padrão.

---

## 14. Responsividade

### 14.1 Host

A interface host deve funcionar em janela desktop normal, layout estreito, tela 1080p e escala de DPI do Windows.

### 14.2 Client

O cliente deve priorizar fullscreen. Em modo janela, deve preservar proporção do vídeo e permitir sair com atalho.

### 14.3 Breakpoints sugeridos para UI web/Tauri

| Breakpoint | Largura |
|---|---:|
| mobile | até 640px |
| tablet | 641-1024px |
| desktop | 1025-1440px |
| wide | acima de 1440px |

---

## 15. Ícones e linguagem visual

Ícones devem ser lineares, geométricos e simples.

Preferir:

- monitor;
- link;
- shield;
- network;
- chip;
- warning;
- terminal;
- play/stop;
- settings.

Evitar ilustrações grandes, mascotes, ícones coloridos demais, skeuomorfismo e glassmorphism forte.

---

## 16. Arquitetura visual por módulo

### 16.1 `lumabridge-host`

Usa Host Control, Settings, Pairing, Diagnostics e Logs.

Prioridade visual:

- status do driver;
- status do monitor virtual;
- cliente conectado;
- encoder;
- bitrate;
- stream start/stop.

### 16.2 `lumabridge-client`

Usa Client Receiver, Fullscreen Renderer, HUDOverlay, Error Screen e Diagnostics.

Prioridade visual:

- conexão;
- fullscreen;
- decoder;
- latência;
- sair com segurança.

### 16.3 `lumabridge-tools`

Usa CLI visual, relatórios em markdown/texto, tabelas de diagnóstico e exportação JSON opcional.

### 16.4 `docs`

Deve usar screenshots e exemplos textuais seguindo nomes e estados definidos neste documento.

---

## 17. Textos e nomenclatura

### 17.1 Nome do produto

Usar:

`LumaBridge Display`

Em CLI/logs:

`LUMABRIDGE`

Prefixos:

- `LB_HOST`
- `LB_CLIENT`
- `LB_DRIVER`
- `LB_STREAM`
- `LB_PAIRING`

### 17.2 Nomes de tela

- `HOST_CONTROL`
- `CLIENT_RECEIVER`
- `PAIRING`
- `DIAGNOSTICS`
- `SETTINGS`
- `STREAM_HUD`

### 17.3 Nomes de estado

- `HOST_OFFLINE`
- `HOST_READY`
- `DRIVER_READY`
- `VIRTUAL_DISPLAY_ATTACHED`
- `CLIENT_CONNECTED`
- `STREAM_ACTIVE`
- `STREAM_DEGRADED`
- `SESSION_AUTH_FAILED`
- `DRIVER_INIT_FAILED`
- `DECODER_UNAVAILABLE`
- `TRANSPORT_UNSTABLE`

---

## 18. O que evitar

Evitar:

- UI genérica clara/corporativa sem identidade;
- neon em excesso que dificulte leitura;
- aplicar efeito visual sobre vídeo remoto;
- animações permanentes durante streaming;
- erro sem ação recomendada;
- botões sem estado de foco;
- logs sem timestamp;
- métricas sem unidade;
- telas que escondem `STOP_STREAM`;
- dependência de mouse para ações essenciais;
- UI que bloqueia spikes técnicos ou MVP.

---

## 19. Critérios de aceite para implementação futura de UI

Uma tela ou componente segue este design system quando:

- usa tokens de cor definidos;
- preserva legibilidade;
- apresenta estado textual claro;
- não aplica filtros no vídeo remoto por padrão;
- suporta teclado;
- tem estados de erro e carregamento;
- mostra métricas com unidades;
- respeita reduced motion;
- mantém estética terminal/HUD sem prejudicar operação;
- atualiza documentação quando cria novo componente visual.

---

## 20. Escopo do MVP visual

No MVP, é suficiente entregar:

- CLI com mensagens padronizadas;
- logs estruturados;
- overlay de métricas compacto;
- tela/janela fullscreen limpa no cliente;
- mensagens de erro claras;
- configuração documentada.

Fora do MVP visual:

- dashboard completo;
- animações avançadas;
- particle systems;
- matrix rain;
- splash screen sofisticada;
- instalador visual;
- temas alternativos.

---

## 21. Referência estética adaptada

A referência cyberpunk original usa preto como fundo dominante, neon pink como acento primário, acid green como acento técnico, tipografia pixel/mono, CRT scanlines, glitch pontual, TerminalBlock, data readouts, status pulse e boot sequence.

No LumaBridge, esses elementos devem ser reinterpretados como interface operacional:

- `TerminalBlock` vira `TerminalPanel`;
- data readouts viram métricas reais de sessão;
- boot sequence vira inicialização host/client;
- status pulse vira indicador de streaming/conexão;
- CRT overlay vira textura opcional da interface, nunca filtro obrigatório sobre vídeo;
- glitch vira transição pontual, nunca efeito contínuo.

---

## 22. Issue sugerida

Título:

`Criar guia de design visual e experiência do usuário`

Labels sugeridas:

- `type:docs`
- `module:docs`
- `priority:P1`

Milestone sugerida:

`M0 - Repository and Planning`

Branch sugerida:

`docs/design-system`

Commit sugerido:

`docs(design): add product design guidelines`

PR sugerido:

`docs: add product design guidelines`

Base:

`dev`

Critérios de aceite:

- `docs/design/DESIGN.md` existe.
- O documento adapta a estética cyberpunk terminal para o LumaBridge.
- O documento cobre host, client, overlay, CLI, logs, estados e erros.
- O documento deixa explícito que o vídeo remoto não deve receber filtro visual por padrão.
- Nenhum código funcional é adicionado.
