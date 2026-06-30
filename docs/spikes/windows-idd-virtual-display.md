# Spike: Windows virtual display com IddCx

Data: 2026-06-30

Branch: `spike/windows-idd-virtual-display`

Issue planejada: Investigar criacao de monitor virtual no Windows com IddCx.

## 1. Objetivo do spike

Validar a viabilidade inicial de criar um monitor virtual real no Windows para o LumaBridge Display usando Microsoft Indirect Display Driver Model, IddCx, UMDF e WDK.

Este spike nao implementa o driver final. A saida esperada e uma conclusao tecnica sobre o ambiente local, os requisitos minimos, a referencia oficial a estudar e o formato recomendado para a futura estrutura `windows/driver`.

## 2. Contexto tecnico

O LumaBridge Display precisa que o Windows 11 reconheca um monitor virtual adicional. Esse requisito e diferente de capturar ou espelhar a tela principal. O driver deve expor um display real para o sistema operacional, permitir modo estendido e entregar frames do monitor virtual para um pipeline futuro de host.

Escopo deste spike:

- Investigar a base tecnica do driver virtual Windows.
- Verificar disponibilidade local de Visual Studio, Windows SDK, WDK, MSBuild e CMake.
- Documentar como o IddSample deve orientar a implementacao futura.
- Propor a estrutura inicial do modulo `lumabridge-idd-driver`.

Fora do escopo deste spike:

- Implementar host Windows.
- Implementar cliente Linux.
- Implementar protocolo.
- Implementar streaming.
- Implementar NVENC.
- Criar instalador.
- Assinar driver para producao.
- Copiar codigo proprietario ou codigo incompatibilidade de licenca.

## 3. Papel do IddCx

IddCx, ou Indirect Display Driver Class Extension, e a extensao de classe usada por drivers de display indireto no Windows. Ela permite implementar um driver UMDF que representa um adaptador/display virtual sem depender de um conector fisico.

No LumaBridge Display, o papel esperado do IddCx e:

- Registrar um adaptador de display indireto.
- Criar e expor um monitor virtual.
- Anunciar modos de video iniciais, como 1280x720@60, 1920x1080@60 e, futuramente, 2560x1440@60.
- Receber/processar swapchains entregues pelo sistema para o display virtual.
- Permitir que o host futuro consuma frames do display virtual sem capturar a tela principal.

O driver nao deve conter:

- Transporte de rede.
- Encoder NVENC.
- Logica do cliente Linux.
- Protocolo host-cliente.
- UI.

## 4. Requisitos de ambiente

Ambiente minimo recomendado para continuar a implementacao real do driver:

- Windows 11.
- Visual Studio 2022 ou Build Tools equivalentes completos.
- MSBuild acessivel, preferencialmente via Developer Command Prompt.
- Windows SDK compativel.
- Windows Driver Kit instalado.
- Headers e bibliotecas UMDF/WDF.
- Header `IddCx.h` disponivel.
- Ferramentas WDK como `inf2cat.exe` e `stampinf.exe`.
- Permissao para usar modo de teste em ambiente de desenvolvimento.
- Acesso ao Microsoft IddSample como referencia oficial.

CMake pode ser usado para partes auxiliares do repositorio, mas projetos de driver Windows normalmente tambem exigem integracao com MSBuild/Visual Studio/WDK.

## 5. Resultado da verificacao do ambiente

Comandos executados:

- `git status --short --branch`
- `git fetch origin`
- `git pull --ff-only origin dev`
- `rg --files`
- leitura de `README.md`
- leitura de `docs/planning/IMPLEMENTATION_PLAN.md`
- leitura de `docs/planning/MODULE_BREAKDOWN.md`
- leitura de `docs/planning/IMPLEMENTATION_SEQUENCE.md`
- leitura de `docs/architecture/ADR-0002-mvp-technical-scope.md`
- leitura de `docs/design/DESIGN.md`
- verificacao local de Visual Studio, Windows SDK, WDK, MSBuild, CMake, compilador e headers IddCx/WDF

Resultado observado:

| Item | Resultado |
|---|---|
| Sistema operacional | Microsoft Windows 11 Pro, versao 10.0.26200, 64 bits |
| `vswhere.exe` | Encontrado em `C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe` |
| Visual Studio / Build Tools | Instancia `VisualStudio/18.6.1+11819.183` em `C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools` |
| Estado da instancia VS | `isComplete=false`, `isLaunchable=false` |
| MSBuild no PATH | Nao encontrado |
| `cl.exe` no PATH | Nao encontrado |
| `link.exe` no PATH | Nao encontrado |
| CMake no PATH | Nao encontrado |
| Ninja no PATH | Nao encontrado |
| Windows Kits root | Existe em `C:\Program Files (x86)\Windows Kits\10` |
| SDK include version | `10.0.26100.0` |
| `IddCx.h` | Nao encontrado |
| `Wdf.h` | Nao encontrado |
| `inf2cat.exe` | Nao encontrado |
| `stampinf.exe` | Nao encontrado |
| `devcon.exe` | Nao encontrado |
| `WindowsSdkDir` | Variavel nao definida |
| `WDKContentRoot` | Variavel nao definida |
| `VCToolsInstallDir` | Variavel nao definida |

Conclusao da verificacao:

- O ambiente atual tem Windows 11 e uma instalacao parcial/incompleta de Build Tools.
- O Windows Kits root existe, mas nao ha sinais suficientes de WDK instalado.
- O header `IddCx.h` nao foi encontrado.
- Headers WDF/UMDF relevantes nao foram encontrados.
- Ferramentas WDK nao foram encontradas.
- MSBuild, CMake e compilador C++ nao estao acessiveis no PATH.

Portanto, o ambiente atual nao esta pronto para compilar ou validar um driver IddCx.

## 6. Estudo do IddSample

Referencia oficial a usar:

- Microsoft Windows Driver Samples - Indirect Display Driver Sample (IddSample)
- Repositorio/conteudo oficial da Microsoft Windows Driver Samples

O IddSample deve ser tratado como referencia tecnica oficial para entender:

- Inicializacao de um driver IDD/IddCx.
- Criacao do adaptador indireto.
- Enumeracao de monitor virtual.
- Definicao de modos de video.
- Tratamento de callbacks do IddCx.
- Processamento de swapchain.
- Estrutura de arquivos `.inf`, projeto, sources e configuracao WDK.

Regras para uso:

- Nao copiar codigo sem revisar licenca e compatibilidade.
- Documentar qualquer trecho ou ideia reutilizada.
- Preferir implementacao propria do LumaBridge, orientada pela arquitetura do projeto.
- Manter o driver separado de host, protocolo, streaming e UI.

## 7. Estrutura proposta para `windows/driver`

Como o WDK nao esta disponivel neste ambiente, nenhum scaffold foi criado nesta etapa. A estrutura abaixo e uma proposta para a proxima etapa, quando o ambiente estiver pronto:

```text
windows/
  driver/
    README.md
    LumaBridgeIddDriver.sln
    LumaBridgeIddDriver/
      LumaBridgeIddDriver.vcxproj
      Driver.cpp
      Driver.h
      Adapter.cpp
      Adapter.h
      Monitor.cpp
      Monitor.h
      SwapChainProcessor.cpp
      SwapChainProcessor.h
      Trace.h
      LumaBridgeIddDriver.inf
      LumaBridgeIddDriver.idl
    tests/
      README.md
```

Responsabilidades sugeridas:

- `Driver.*`: entrada UMDF, inicializacao e ciclo de vida do driver.
- `Adapter.*`: adaptador indireto e callbacks IddCx de adaptador.
- `Monitor.*`: monitor virtual, modos expostos e estado de conexao.
- `SwapChainProcessor.*`: recebimento e processamento inicial de swapchain.
- `Trace.h`: logging/tracing do driver.
- `.inf`: instalacao de desenvolvimento do driver.

Essa estrutura ainda precisa ser validada contra o IddSample e contra a forma recomendada pelo WDK instalado.

## 8. Riscos tecnicos

- IddCx e o maior risco tecnico do produto, porque sem monitor virtual real o LumaBridge vira apenas screen sharing.
- Driver mal implementado pode afetar estabilidade do Windows.
- Assinatura de driver sera necessaria para distribuicao publica.
- Instalacao em modo teste exige cuidado e documentacao clara.
- Processamento incorreto de swapchain pode criar copias GPU -> CPU desnecessarias.
- O limite entre driver e host precisa ser bem definido para nao misturar streaming no driver.
- A falta de WDK local bloqueia validacao real neste momento.
- O IddSample deve ser usado como referencia oficial, mas nao como copia cega.

## 9. Limitacoes deste spike

- Nao houve build de driver.
- Nao houve instalacao de driver.
- Nao houve validacao visual em Configuracoes do Windows.
- Nao houve enumeracao de monitor virtual.
- Nao houve teste de modo estendido.
- Nao houve processamento real de swapchain.
- Nao foi criado scaffold em `windows/driver` porque o WDK nao foi encontrado.

## 10. Proximos passos

1. Instalar ou reparar Visual Studio Build Tools/Visual Studio com componentes C++ completos.
2. Instalar Windows SDK compativel.
3. Instalar Windows Driver Kit compativel.
4. Confirmar que `IddCx.h`, `Wdf.h`, `inf2cat.exe` e `stampinf.exe` estao disponiveis.
5. Confirmar que MSBuild e compilador C++ funcionam em Developer Command Prompt.
6. Baixar/abrir o IddSample oficial da Microsoft para estudo.
7. Criar um scaffold minimo em `windows/driver` somente apos toolchain validada.
8. Documentar o fluxo de instalacao de desenvolvimento em `docs/setup/windows-host.md`.
9. Executar um novo spike ou continuar este spike para validar monitor virtual 1080p60.

## 11. Conclusao do spike

Resultado: bloqueado por ambiente local incompleto.

O Windows 11 esta disponivel, mas a toolchain necessaria para driver IddCx nao esta pronta. O WDK nao foi detectado porque `IddCx.h`, `Wdf.h` e ferramentas como `inf2cat.exe` e `stampinf.exe` nao foram encontrados. Alem disso, MSBuild, CMake e o compilador C++ nao estao acessiveis no PATH.

Decisao tomada neste spike:

- Nao criar scaffold de driver ainda.
- Nao inventar implementacao sem WDK.
- Registrar requisitos, riscos e estrutura proposta.
- Tratar a instalacao/validacao da toolchain WDK como proxima dependencia antes de qualquer codigo em `windows/driver`.
