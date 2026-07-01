# LumaBridge IDD Driver

## Objetivo do modulo

`windows/driver` e o modulo reservado para o futuro driver de monitor virtual do LumaBridge Display no Windows.

Nesta etapa, o modulo contem uma fundacao minima compilavel com WDK/UMDF/IddCx. Ela valida a estrutura de build do driver, mas nao cria monitor virtual funcional.

## Escopo atual

Incluido agora:

- solucao Visual Studio/MSBuild;
- projeto WDK UMDF x64;
- entrada `DriverEntry` minima;
- chamada minima a `WdfDriverCreate`;
- callback `LumaBridgeEvtDeviceAdd` como stub;
- include de `wdf.h` e `IddCx.h`;
- INF minimo de desenvolvimento;
- `.gitignore` local para artefatos de build.

Nao incluido:

- inicializacao de IddCx;
- criacao de adapter;
- criacao de monitor virtual;
- modos de video;
- processamento de swapchain;
- instalacao de driver;
- assinatura de driver;
- host, client, protocolo, streaming ou NVENC.

## Estrutura

```text
windows/
  driver/
    .gitignore
    README.md
    LumaBridgeIddDriver.sln
    LumaBridgeIddDriver/
      LumaBridgeIddDriver.vcxproj
      LumaBridgeIddDriver.vcxproj.filters
      Driver.cpp
      Driver.h
      LumaBridgeIddDriver.inf
```

## Requisitos

Ambiente validado em `docs/setup/windows-wdk-environment.md`:

- Visual Studio Build Tools 18.x / VS2026;
- MSVC `14.51.36231`;
- Windows SDK `10.0.28000.0`;
- WDK `10.0.28000.0`;
- `WindowsUserModeDriver10.0`;
- UMDF 2.35;
- IddCx 1.4;
- Developer Command Prompt ou Developer PowerShell com ambiente do Visual Studio carregado.

## Como abrir e buildar

Ambiente usado para validacao:

```bat
cmd.exe /c ""C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 -no_logo"
```

Validar ferramentas:

```bat
where.exe msbuild
where.exe cl
where.exe link
where.exe stampinf
where.exe inf2cat
```

Observacao: `Inf2Cat.exe` pode nao estar no PATH. O caminho completo validado e:

```text
C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x86\Inf2Cat.exe
```

Build esperado:

```bat
msbuild windows\driver\LumaBridgeIddDriver.sln /p:Configuration=Debug /p:Platform=x64 /p:WindowsTargetPlatformVersion=10.0.28000.0
```

Resultado validado neste spike:

```text
LumaBridgeIddDriver.vcxproj -> windows\driver\x64\Debug\LumaBridgeIddDriver.dll
Inf2Cat task was skipped as there were no inf files to process
DrvCat task was skipped as there was no catalog file to process
```

Artefatos locais esperados, quando o build passa:

```text
windows/driver/x64/Debug/
```

Esses artefatos sao ignorados por `windows/driver/.gitignore` e nao devem ser commitados.

## Decisoes de build

- `IDDCX_VERSION=1.4` foi configurado como `IDDCX_VERSION_MAJOR=1` e `IDDCX_VERSION_MINOR=4`, pois o header `IddCxFuncEnum.h` do WDK 10.0.28000.0 exige essas macros.
- `Windows.h` e incluido antes de `wdf.h` e `IddCx.h` para disponibilizar tipos basicos usados pela cadeia de headers do SDK/IddCx.
- O warning `C4471` emitido por `WudfWdm.h` no UMDF 2.35 foi suprimido especificamente no projeto.
- `Driver_SpectreMitigation=false` evita exigir as bibliotecas Spectre opcionais do MSVC neste spike.
- `EnableTestSign=false` e `SignMode=Off` mantem assinatura fora do escopo.
- O INF minimo acompanha o projeto como arquivo de desenvolvimento e nao e empacotado/instalado nesta etapa.

## Limites da fundacao compilavel

O codigo atual valida somente a base de build:

- `DriverEntry` inicializa `WDF_DRIVER_CONFIG`;
- `DriverEntry` chama `WdfDriverCreate`;
- `LumaBridgeEvtDeviceAdd` retorna `STATUS_NOT_IMPLEMENTED`;
- `IddCx.h` e incluido para validar disponibilidade de headers/propriedades WDK.

O codigo atual nao chama APIs IddCx e nao deve ser instalado como driver funcional.

## Proximos passos

1. Criar uma issue separada para inicializacao IddCx minima.
2. Definir adapter e monitor virtual somente nessa issue futura.
3. Validar build e INF antes de qualquer instalacao.
4. Documentar fluxo de instalacao de desenvolvimento separadamente.
5. Manter host, client, protocolo, streaming e NVENC fora do driver.
