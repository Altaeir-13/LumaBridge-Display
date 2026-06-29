# LumaBridge Display - Modularizacao

Este documento define os 7 modulos logicos do projeto. Cada modulo tem fronteiras explicitas para evitar PRs grandes, dependencias circulares e mistura de responsabilidades.

## 1. `lumabridge-protocol`

### Responsabilidade

Definir os contratos de comunicacao entre host e cliente.

### Pastas esperadas

- `protocol/include`
- `protocol/src`
- `protocol/tests`
- `docs/protocol`

### Tecnologias previstas

- C++20 ou Rust, conforme decisao futura do repositorio.
- Serializacao binaria ou schema estruturado definido por ADR posterior.
- Testes unitarios com Catch2, GoogleTest, doctest ou framework equivalente.

### Interfaces publicas futuras

- Mensagens de controle.
- Handshake e negociacao de versao.
- Capabilities de host e cliente.
- Configuracao de sessao.
- Anuncio de resolucao, FPS, codec e bitrate.
- Heartbeats.
- Erros estruturados.
- Estatisticas de FPS, bitrate, jitter, perda e latencia.
- Serializacao e desserializacao.

### Dependencias

- Nao deve depender de driver, NVENC, VA-API, Wayland ou UI.
- Pode depender de biblioteca pequena de serializacao/configuracao, se aprovada.

### Pertence ao modulo

- Versionamento do protocolo.
- Validacao de mensagens.
- Testes de compatibilidade.
- Modelos de pacotes de controle e metadados de video.

### Nao pertence ao modulo

- Driver virtual.
- Encode/decode.
- Renderizacao.
- Transporte concreto de baixo nivel.
- UI.

### Principais riscos

- Acoplar o protocolo a uma unica plataforma.
- Definir formato dificil de evoluir.
- Misturar controle, video e diagnostico sem limites claros.

### Testes necessarios

- Serializacao/desserializacao.
- Rejeicao de versao incompativel.
- Campos obrigatorios ausentes.
- Round-trip de mensagens.
- Compatibilidade com mensagens futuras ignoraveis.

### Criterios de aceite

- Mensagens base documentadas.
- Testes unitarios cobrindo handshake, erros e estatisticas.
- Contratos independentes de Windows/Linux.

### Issues relacionadas

- Issue 10, Issue 11, Issue 12, Issue 13, Issue 14.

## 2. `lumabridge-idd-driver`

### Responsabilidade

Criar e gerenciar o monitor virtual real no Windows usando o modelo oficial de Indirect Display Driver.

### Pastas esperadas

- `windows/driver`
- `windows/driver/tests`
- `windows/installer/dev-driver`
- `docs/setup/windows-host.md`

### Tecnologias previstas

- Microsoft Indirect Display Driver Model.
- IddCx.
- UMDF.
- WDK.
- C++17 ou C++20.
- Direct3D 11 como primeira opcao.

### Interfaces publicas futuras

- Instalacao/remocao em modo de desenvolvimento.
- Enumeracao de adaptador/monitor virtual.
- Exposicao de modos de video.
- Canal documentado para entregar ou disponibilizar frames ao host.
- Logs de driver e diagnostico.

### Dependencias

- Windows 11.
- Visual Studio 2022.
- Windows SDK.
- WDK.
- IddSample como referencia oficial, respeitando licenca.

### Pertence ao modulo

- Enumeracao do monitor virtual.
- Modos 720p60, 1080p60 e 1440p60.
- Validacao de que o Windows reconhece display adicional.
- Processamento inicial de swapchain no limite do driver.

### Nao pertence ao modulo

- Streaming.
- Encoder NVENC.
- Cliente Linux.
- UI final.
- Protocolo de rede.

### Principais riscos

- Maior risco tecnico do produto.
- Instabilidade do driver pode afetar o Windows.
- Assinatura de driver sera necessaria para distribuicao publica.
- Integracao incorreta pode produzir apenas captura de tela, nao monitor real.

### Testes necessarios

- Instalacao e remocao em ambiente de desenvolvimento.
- Windows lista monitor virtual.
- Modo estendido funciona.
- Modos de resolucao aparecem corretamente.
- Logs de erro sao claros.

### Criterios de aceite

- Monitor virtual aparece nas configuracoes do Windows.
- Usuario consegue estender area de trabalho.
- Driver pode ser instalado/removido em fluxo documentado de desenvolvimento.

### Issues relacionadas

- Issue 15, Issue 16, Issue 17, Issue 18, Issue 19.

## 3. `lumabridge-host`

### Responsabilidade

Executar a aplicacao host no Windows, processar frames do display virtual, codificar e enviar ao cliente.

### Pastas esperadas

- `windows/host`
- `windows/host/tests`
- `windows/host/config`
- `docs/setup/windows-host.md`

### Tecnologias previstas

- C++20.
- Direct3D 11.
- DXGI.
- NVIDIA Video Codec SDK.
- NVENC H.264 e HEVC opcional.
- Transporte LAN por UDP/RTP ou QUIC, decisao posterior.
- Logs estruturados.

### Interfaces publicas futuras

- CLI para iniciar/parar host.
- Arquivo de configuracao.
- API interna para receber textura/frame do driver.
- API interna para encoder.
- API interna de sessao e transporte.
- Metricas de pipeline.

### Dependencias

- `lumabridge-protocol`.
- `lumabridge-idd-driver` para frames reais.
- NVIDIA RTX 3060 Ti ou NVENC compativel.
- Windows 11.

### Pertence ao modulo

- Captura/recebimento de frames do monitor virtual.
- Conversao/pre-processamento para NVENC.
- Encode H.264 baixa latencia.
- Envio de stream.
- Controle de sessao.
- Metricas de encode, bitrate e latencia.

### Nao pertence ao modulo

- Implementacao do driver.
- Renderizacao no Linux.
- UI sofisticada.
- Decode VA-API.

### Principais riscos

- Copias GPU -> CPU podem destruir latencia.
- NVENC mal configurado aumenta atraso.
- Erros do driver precisam ser isolados para nao derrubar o host.
- Transporte inadequado pode acumular fila.

### Testes necessarios

- Encode de frames sinteticos.
- Deteccao de NVENC.
- Erro claro quando NVENC indisponivel.
- Envio de stream sintetico.
- Medicao de latencia de encode.

### Criterios de aceite

- Host inicia por CLI.
- Codifica H.264 via NVENC.
- Envia stream sintetico e depois frame real.
- Exibe metricas basicas.

### Issues relacionadas

- Issue 20, Issue 21, Issue 22, Issue 23, Issue 24, Issue 25.

## 4. `lumabridge-client`

### Responsabilidade

Executar o cliente Linux, conectar ao host, receber o stream, decodificar e renderizar em fullscreen.

### Pastas esperadas

- `linux/client`
- `linux/client/tests`
- `linux/packaging`
- `docs/setup/arch-linux-client.md`

### Tecnologias previstas

- C++20 ou Rust.
- FFmpeg/libavcodec com VA-API ou GStreamer com VA-API.
- SDL2 + OpenGL/EGL, wgpu ou Vulkan.
- Wayland/Hyprland.
- Logs estruturados.

### Interfaces publicas futuras

- CLI para conectar por IP.
- Configuracao de fullscreen e codec.
- Receiver de rede.
- Decoder H.264 VA-API.
- Renderizador fullscreen.
- Overlay de metricas.

### Dependencias

- `lumabridge-protocol`.
- Host transmitindo stream.
- Arch Linux.
- Hyprland/Wayland.
- `libva`, `intel-media-driver`, `ffmpeg`, `sdl2` ou stack equivalente.

### Pertence ao modulo

- Conexao com host.
- Recebimento de pacotes.
- Buffer minimo.
- Descarte de frames atrasados.
- Decode VA-API.
- Render fullscreen.
- Metricas do cliente.

### Nao pertence ao modulo

- Driver Windows.
- NVENC.
- Criacao de monitor virtual.
- UI final sofisticada.

### Principais riscos

- VA-API varia por hardware/driver.
- Wayland restringe input futuro.
- Fullscreen e frame pacing podem variar no Hyprland.
- Buffer excessivo aumenta latencia.

### Testes necessarios

- Decodificar sample H.264 via VA-API.
- Abrir janela fullscreen no Hyprland.
- Renderizar frames sinteticos.
- Receber stream sintetico.
- Descartar frames atrasados.

### Criterios de aceite

- Cliente conecta por IP manual.
- Renderiza fullscreen.
- Usa VA-API quando disponivel.
- Exibe metricas basicas.

### Issues relacionadas

- Issue 26, Issue 27, Issue 28, Issue 29, Issue 30, Issue 31.

## 5. `lumabridge-tools`

### Responsabilidade

Fornecer ferramentas auxiliares para diagnostico, medicao e validacao de ambiente.

### Pastas esperadas

- `tools/latency-tester`
- `tools/network-tester`
- `tools/codec-inspector`
- `scripts`
- `docs/troubleshooting.md`

### Tecnologias previstas

- C++/Rust/Python somente para ferramentas, conforme necessidade.
- Scripts de ambiente para Windows e Arch Linux.
- Logs e relatorios em formato textual ou JSON.

### Interfaces publicas futuras

- Teste de rede LAN.
- Inspecao de NVENC.
- Inspecao de VA-API.
- Medidor de latencia.
- Gerador de relatorio de diagnostico.

### Dependencias

- Pode consumir `lumabridge-protocol`.
- Pode chamar ferramentas do sistema, como `vainfo`, diagnosticos de NVIDIA e utilitarios de rede.

### Pertence ao modulo

- Diagnostico.
- Benchmarks simples.
- Relatorios de ambiente.
- Validacao de codecs.

### Nao pertence ao modulo

- Funcionalidade principal do host/cliente.
- Driver.
- UI final.

### Principais riscos

- Ferramentas virarem dependencia obrigatoria do runtime.
- Scripts alterarem ambiente sem confirmacao.
- Relatorios exporem chaves ou segredos.

### Testes necessarios

- Saida previsivel para ambiente valido e invalido.
- Nenhum segredo em logs.
- Relatorio identifica dependencias ausentes.

### Criterios de aceite

- Ferramentas ajudam a diagnosticar NVENC, VA-API, rede e latencia.
- Saidas sao documentadas.

### Issues relacionadas

- Issue 32, Issue 33, Issue 34.

## 6. `docs`

### Responsabilidade

Manter documentacao tecnica, guias, ADRs, planejamento e troubleshooting.

### Pastas esperadas

- `docs/planning`
- `docs/architecture`
- `docs/setup`
- `docs/protocol`
- `docs/troubleshooting.md`

### Tecnologias previstas

- Markdown.
- Mermaid para diagramas.
- ADRs numerados.

### Interfaces publicas futuras

- Plano de implementacao.
- Backlog e issues manuais.
- Guias de setup.
- Decisoes arquiteturais.
- Troubleshooting.

### Dependencias

- `REQUISITOS_LUMABRIDGE.md` como fonte de verdade inicial.
- Evidencias de spikes e testes futuros.

### Pertence ao modulo

- Documentacao do produto.
- ADRs.
- Roadmap.
- Guias de build/setup.
- Riscos e criterios de aceite.

### Nao pertence ao modulo

- Codigo funcional.
- CI executavel.
- Scripts de instalacao.

### Principais riscos

- Documentacao divergir do comportamento real.
- Backlog ficar generico demais.
- ADRs nao serem atualizadas quando decisoes mudarem.

### Testes necessarios

- Revisao humana.
- Links internos validos.
- Consistencia entre milestones, issues e modulos.

### Criterios de aceite

- Documentos obrigatorios existem.
- Plano permite implementacao por outro engenheiro sem decisoes abertas relevantes.

### Issues relacionadas

- Issue 1, Issue 2, Issue 3, Issue 4.

## 7. `.github`

### Responsabilidade

Definir governanca futura do repositorio no GitHub.

### Pastas esperadas

- `.github/ISSUE_TEMPLATE`
- `.github/PULL_REQUEST_TEMPLATE.md`
- `.github/workflows`
- `.github/CODEOWNERS` se houver equipe.

### Tecnologias previstas

- GitHub Issues.
- GitHub Pull Requests.
- GitHub Actions em fase posterior.
- Labels e milestones.

### Interfaces publicas futuras

- Templates de issue.
- Template de PR.
- Workflows de CI.
- Labels.
- Milestones.

### Dependencias

- Estrategia de branches aprovada.
- Backlog revisado.
- Repositorio Git inicializado e conectado ao remoto.

### Pertence ao modulo

- Governanca.
- Templates.
- Workflows.
- Labels.
- Milestones.

### Nao pertence ao modulo

- Codigo do produto.
- Driver.
- Host.
- Cliente.

### Principais riscos

- CI ser configurado antes de toolchain minima estar definida.
- Templates grandes demais reduzirem adesao.
- Labels inconsistentes com backlog.

### Testes necessarios

- Validar YAML de workflows quando criados.
- Validar templates com PR/issue de teste antes do uso amplo.
- Conferir labels e milestones contra planejamento.

### Criterios de aceite

- Labels e milestones documentadas.
- Templates planejados antes de issues reais.
- PRs futuros tem base `dev`.

### Issues relacionadas

- Issue 5, Issue 6, Issue 7, Issue 8, Issue 9.
