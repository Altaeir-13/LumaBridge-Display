# LumaBridge Display - Sequencia Operacional de Implementacao

Este documento define a ordem futura de execucao. Ele nao executa branches, commits, PRs, issues reais ou pushes.

## Etapa 1 - Planejamento e estrutura documental

- Issue correspondente: Issue 1.
- Branch sugerida: `docs/planning-foundation`.
- Arquivos esperados: `docs/planning/*`, `docs/architecture/ADR-0001-branching-strategy.md`, `docs/architecture/ADR-0002-mvp-technical-scope.md`.
- Commits esperados: `docs: add implementation planning documents`.
- Testes esperados: revisao de existencia, consistencia de modulos, milestones e riscos.
- Criterio para abrir PR futuro: documentos completos e revisados localmente.
- Criterio para merge futuro em `dev`: aprovacao humana e ausencia de escopo funcional.
- Bloqueios: repositorio Git ainda nao inicializado localmente.
- Proxima etapa: templates do GitHub.

## Etapa 2 - Templates do GitHub

- Issue correspondente: Issue 5.
- Branch sugerida: `infra/github-templates`.
- Arquivos esperados: `.github/ISSUE_TEMPLATE/*`, `.github/PULL_REQUEST_TEMPLATE.md`.
- Commits esperados: `infra: add github issue and pull request templates`.
- Testes esperados: revisar se templates exigem issue, escopo, testes, riscos e evidencias.
- Criterio para abrir PR futuro: templates pequenos e alinhados ao backlog.
- Criterio para merge futuro em `dev`: templates aprovados.
- Bloqueios: M0 revisada.
- Proxima etapa: labels e milestones no GitHub.

## Etapa 3 - CI planejado

- Issue correspondente: Issue 8.
- Branch sugerida: `infra/ci-plan`.
- Arquivos esperados: `.github/workflows/README.md` ou workflow inicial nao bloqueante.
- Commits esperados: `infra: document initial ci strategy`.
- Testes esperados: validar YAML somente quando workflow real existir.
- Criterio para abrir PR futuro: estrategia clara para Linux, Windows, lint e testes.
- Criterio para merge futuro em `dev`: nao quebrar desenvolvimento inicial.
- Bloqueios: toolchain ainda nao definida.
- Proxima etapa: spikes tecnicos isolados.

## Etapa 4 - Spike IddCx

- Issue correspondente: Issue 15.
- Branch sugerida: `spike/windows-idd-monitor`.
- Arquivos esperados: `windows/driver/*`, docs de evidencias.
- Commits esperados: `spike(driver): validate iddcx virtual monitor`.
- Testes esperados: Windows reconhece monitor 1080p60 em ambiente de desenvolvimento.
- Criterio para abrir PR futuro: evidencia manual anexada.
- Criterio para merge futuro em `dev`: decisao humana; spikes podem ser documentais ou descartaveis.
- Bloqueios: Visual Studio 2022, Windows SDK, WDK.
- Proxima etapa: spike NVENC.

## Etapa 5 - Spike NVENC

- Issue correspondente: Issue 20.
- Branch sugerida: `spike/windows-nvenc-encoder`.
- Arquivos esperados: `windows/host/spikes/nvenc/*`, docs de evidencias.
- Commits esperados: `spike(host): validate nvenc h264 synthetic frames`.
- Testes esperados: codificar frames sinteticos H.264 e registrar tempo de encode.
- Criterio para abrir PR futuro: logs mostram NVENC ativo ou erro claro.
- Criterio para merge futuro em `dev`: spike documentado.
- Bloqueios: NVIDIA Video Codec SDK e driver NVIDIA.
- Proxima etapa: spike VA-API.

## Etapa 6 - Spike VA-API

- Issue correspondente: Issue 26.
- Branch sugerida: `spike/linux-vaapi-decoder`.
- Arquivos esperados: `linux/client/spikes/vaapi/*`, docs de evidencias.
- Commits esperados: `spike(client): validate vaapi h264 decode`.
- Testes esperados: decodificar sample H.264 via VA-API no Arch Linux.
- Criterio para abrir PR futuro: logs indicam hardware decode ou fallback diagnostico.
- Criterio para merge futuro em `dev`: spike documentado.
- Bloqueios: `libva`, `intel-media-driver`, FFmpeg/GStreamer.
- Proxima etapa: spike de transporte LAN.

## Etapa 7 - Spike de transporte LAN

- Issue correspondente: Issue 32.
- Branch sugerida: `spike/lan-transport`.
- Arquivos esperados: `tools/network-tester/*`.
- Commits esperados: `spike(tools): validate low latency lan transport`.
- Testes esperados: envio de payload sintetico com sequencia, timestamp e perda simulada.
- Criterio para abrir PR futuro: metricas basicas registradas.
- Criterio para merge futuro em `dev`: resultado orienta ADR de transporte.
- Bloqueios: decisao inicial UDP/RTP ou QUIC.
- Proxima etapa: fundacao do protocolo.

## Etapa 8 - Fundacao do protocolo

- Issue correspondente: Issue 10.
- Branch sugerida: `feature/protocol-foundation`.
- Arquivos esperados: `protocol/include`, `protocol/src`, `protocol/tests`, `docs/protocol`.
- Commits esperados: `feat(protocol): add base protocol messages`.
- Testes esperados: serializacao, versao, capabilities, erros e estatisticas.
- Criterio para abrir PR futuro: testes unitarios passam.
- Criterio para merge futuro em `dev`: API documentada e revisada.
- Bloqueios: escolha de linguagem/build.
- Proxima etapa: driver virtual Windows.

## Etapa 9 - Driver virtual Windows

- Issue correspondente: Issue 16.
- Branch sugerida: `feature/windows-idd-driver`.
- Arquivos esperados: `windows/driver`, `windows/installer/dev-driver`, docs de setup.
- Commits esperados: `feat(driver): add initial iddcx virtual monitor`.
- Testes esperados: monitor virtual aparece no Windows e modo estendido funciona.
- Criterio para abrir PR futuro: evidencia manual e riscos documentados.
- Criterio para merge futuro em `dev`: revisao cuidadosa por risco alto.
- Bloqueios: WDK, permissao de modo teste, ambiente Windows.
- Proxima etapa: host Windows.

## Etapa 10 - Host Windows

- Issue correspondente: Issue 21.
- Branch sugerida: `feature/windows-host-cli`.
- Arquivos esperados: `windows/host`, configuracao, logs.
- Commits esperados: `feat(host): add minimal windows host cli`.
- Testes esperados: host inicia, carrega configuracao e registra estado.
- Criterio para abrir PR futuro: CLI minima isolada.
- Criterio para merge futuro em `dev`: sem dependencia obrigatoria de UI.
- Bloqueios: build system.
- Proxima etapa: pipeline NVENC e transporte.

## Etapa 11 - Cliente Linux

- Issue correspondente: Issue 27.
- Branch sugerida: `feature/linux-client-cli`.
- Arquivos esperados: `linux/client`, configuracao, logs.
- Commits esperados: `feat(client): add minimal linux client cli`.
- Testes esperados: cliente inicia, carrega configuracao e tenta conexao por IP.
- Criterio para abrir PR futuro: comportamento verificavel sem host real.
- Criterio para merge futuro em `dev`: logs claros.
- Bloqueios: build system e dependencias Linux.
- Proxima etapa: render e decode.

## Etapa 12 - Integracao LAN

- Issue correspondente: Issue 35.
- Branch sugerida: `feature/lan-mvp-integration`.
- Arquivos esperados: host, client, protocol, docs de teste manual.
- Commits esperados: `feat(integration): stream virtual display over lan`.
- Testes esperados: janela no monitor virtual aparece no cliente fullscreen.
- Criterio para abrir PR futuro: evidencia de teste manual com metricas.
- Criterio para merge futuro em `dev`: criterios P0 do MVP atendidos.
- Bloqueios: driver, host, cliente e protocolo.
- Proxima etapa: pareamento e seguranca.

## Etapa 13 - Pareamento e seguranca

- Issue correspondente: Issue 39.
- Branch sugerida: `feature/pairing-code`.
- Arquivos esperados: host/client/protocol/docs.
- Commits esperados: `feat(security): add pairing code flow`.
- Testes esperados: cliente nao pareado rejeitado, segredo armazenado localmente.
- Criterio para abrir PR futuro: sem segredos em logs.
- Criterio para merge futuro em `dev`: revisao de seguranca.
- Bloqueios: sessao integrada.
- Proxima etapa: metricas e UX.

## Etapa 14 - Metricas

- Issue correspondente: Issue 38.
- Branch sugerida: `feature/session-metrics`.
- Arquivos esperados: host/client/tools/docs.
- Commits esperados: `feat(metrics): add session metrics overlay and logs`.
- Testes esperados: FPS, bitrate, jitter, perda e latencia aproximada.
- Criterio para abrir PR futuro: metricas reproduziveis.
- Criterio para merge futuro em `dev`: nomes e unidades documentados.
- Bloqueios: pipeline de stream.
- Proxima etapa: UX e empacotamento.

## Etapa 15 - UX e empacotamento

- Issue correspondente: Issue 42.
- Branch sugerida: `feature/runtime-config`.
- Arquivos esperados: docs de setup, scripts de desenvolvimento, configuracao.
- Commits esperados: `feat(config): add runtime configuration files`.
- Testes esperados: usuario inicia host e cliente sem editar codigo.
- Criterio para abrir PR futuro: setup reproduzivel.
- Criterio para merge futuro em `dev`: documentacao completa.
- Bloqueios: MVP integrado.
- Proxima etapa: otimizacao.

## Etapa 16 - Otimizacao

- Issue correspondente: Issue 46.
- Branch sugerida: `feature/latency-reporting`.
- Arquivos esperados: tools, host, client, docs de performance.
- Commits esperados: `feat(metrics): add end to end latency report`.
- Testes esperados: relatorio de latencia em LAN cabeada e Wi-Fi bom.
- Criterio para abrir PR futuro: metricas comparaveis antes/depois.
- Criterio para merge futuro em `dev`: sem regressao funcional.
- Bloqueios: MVP integrado.
- Proxima etapa: release final.

## Etapa 17 - Release final

- Issue correspondente: Issue 50.
- Branch sugerida: `release/mvp-candidate`.
- Arquivos esperados: release notes, checklist, docs finais.
- Commits esperados: `docs: prepare mvp release candidate`.
- Testes esperados: checklist completo de MVP.
- Criterio para abrir PR futuro: `dev` estabilizada.
- Criterio para merge futuro em `main`: aprovacao humana e release funcional.
- Bloqueios: criterios de MVP completos.
- Proxima etapa: merge futuro em `main`, fora desta fase.
