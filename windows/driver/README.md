# LumaBridge IDD Driver Scaffold

## Objetivo do modulo

`windows/driver` sera o modulo responsavel pelo futuro driver de monitor virtual do LumaBridge Display no Windows.

O objetivo tecnico do modulo e permitir que o Windows reconheca um monitor virtual real, usando o modelo oficial de Indirect Display Driver. Este scaffold cria apenas o ponto documental inicial do modulo. Ele nao cria driver funcional, nao registra adaptador, nao enumera monitor e nao processa frames.

## Relacao com IddCx

IddCx, ou Indirect Display Driver Class Extension, e a extensao de classe usada por drivers de display indireto no Windows.

No LumaBridge Display, IddCx deve orientar a implementacao futura para:

- registrar um adaptador de display indireto;
- expor um monitor virtual ao Windows;
- declarar modos de video iniciais;
- receber callbacks do sistema operacional;
- receber uma swapchain em etapa futura;
- manter a responsabilidade de driver separada de host, protocolo, streaming e NVENC.

O Microsoft IddSample pode ser usado como referencia conceitual para estrutura e fluxo do driver, mas nenhum codigo foi copiado neste scaffold.

## Relacao com WDK

O driver futuro deve ser construido com Visual Studio/Build Tools, MSVC, Windows SDK e Windows Driver Kit alinhados.

O ambiente validado na preparacao da issue #12 usa:

- Visual Studio Build Tools 18.x / VS2026.
- MSVC `14.51.36231`.
- Windows SDK ativo `10.0.28000.0`.
- WDK/ferramentas e headers da familia `10.0.28000.0`.
- `IddCx.h` disponivel no Windows Kits.
- `Wdf.h` disponivel no Windows Kits.
- `stampinf.exe` disponivel no Developer Command Prompt.
- `Inf2Cat.exe` disponivel por caminho completo no Windows Kits.

Detalhes do ambiente estao documentados em `docs/setup/windows-wdk-environment.md`.

## Escopo atual do scaffold

Este scaffold inclui somente:

- a pasta `windows/driver`;
- este `README.md`;
- documentacao do spike em `docs/spikes/windows-idd-driver-scaffold.md`.

Foi avaliado que ainda nao e tecnicamente seguro criar arquivos `.vcxproj`, `.sln`, `.inf`, `.cpp`, `.h`, `.props` ou `.targets` nesta etapa, porque isso sugeriria um projeto de driver compilavel sem uma fundacao minima de codigo, INF e configuracao WDK revisada.

## Fora do escopo

Este scaffold nao inclui:

- driver funcional;
- criacao de monitor virtual;
- enumeracao de adaptador;
- processamento de swapchain;
- instalacao ou remocao de driver;
- modo de teste do Windows;
- assinatura de driver;
- host Windows;
- client Linux;
- protocolo;
- streaming;
- NVENC;
- instalador;
- codigo copiado do IddSample.

## Estrutura planejada

Estrutura futura esperada, ainda nao criada neste spike:

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

Responsabilidades planejadas:

- `Driver.*`: entrada UMDF, inicializacao e ciclo de vida do driver.
- `Adapter.*`: adaptador indireto e callbacks IddCx de adaptador.
- `Monitor.*`: monitor virtual, modos expostos e estado de conexao.
- `SwapChainProcessor.*`: recebimento e processamento inicial de swapchain em etapa futura.
- `Trace.h`: logging/tracing do driver.
- `.inf`: instalacao de desenvolvimento do driver em etapa futura.

## Comandos de build esperados

Nao ha comando de build funcional neste scaffold, porque ainda nao existe solucao, projeto, INF ou codigo de driver.

Quando o projeto de driver existir, a validacao devera ser feita em Developer Command Prompt ou Developer PowerShell com o ambiente do Visual Studio carregado. O ambiente validado na issue #12 usa:

```bat
cmd.exe /c ""C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 -no_logo"
```

Comandos esperados para uma etapa futura:

```bat
where.exe msbuild
where.exe cl
where.exe link
where.exe stampinf
msbuild windows\driver\LumaBridgeIddDriver.sln /p:Configuration=Debug /p:Platform=x64
"C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x86\Inf2Cat.exe" /?
```

Observacao: `Inf2Cat.exe` foi encontrado por caminho completo, mas nao no PATH do Developer Command Prompt.

## Limitacoes

- Este scaffold nao prova compilacao de driver.
- Este scaffold nao prova instalacao de driver.
- Este scaffold nao prova que o Windows reconhece monitor virtual.
- Este scaffold nao ativa modo de teste.
- Este scaffold nao valida `.inf`.
- Este scaffold nao inclui codigo C++.
- Este scaffold nao inclui dependencias do host.

## Proximos passos

1. Revisar o IddSample apenas como referencia conceitual e respeitando licenca.
2. Definir a estrutura minima de solucao/projeto WDK antes de criar `.sln`, `.vcxproj` ou `.inf`.
3. Criar uma issue separada para a fundacao compilavel do driver.
4. Nessa issue futura, adicionar codigo minimo, INF de desenvolvimento e build MSBuild.
5. Somente depois validar instalacao em ambiente de desenvolvimento e enumeracao de monitor virtual.
