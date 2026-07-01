# Spike: Fundacao compilavel do driver IddCx

Data: 2026-07-01
Branch: `spike/windows-idd-build-foundation`

## Objetivo

Criar uma fundacao minima compilavel para o futuro driver IddCx do LumaBridge Display em `windows/driver`.

Este spike valida a estrutura de build WDK/UMDF/IddCx. Ele nao implementa monitor virtual funcional, nao inicializa IddCx e nao instala nem assina driver.

## Ambiente usado

- Windows: `Microsoft Windows [versao 10.0.26200.8655]`.
- Visual Studio Build Tools: familia 18.x / VS2026.
- MSBuild: `C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe`.
- MSVC: `C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe`.
- Linker: `C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe`.
- Windows SDK/WDK: `10.0.28000.0`.
- Toolset: `WindowsUserModeDriver10.0`.
- UMDF: 2.35.
- IddCx: 1.4.
- `stampinf.exe`: `C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x64\stampinf.exe`.
- `where.exe inf2cat`: nao encontrou no PATH do Developer Prompt.
- `Inf2Cat.exe` validado por caminho completo: `C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x86\Inf2Cat.exe`.

Headers verificados:

- `C:\Program Files (x86)\Windows Kits\10\Include\10.0.28000.0\um\iddcx\1.4\IddCx.h`.
- `C:\Program Files (x86)\Windows Kits\10\Include\wdf\umdf\2.35\wdf.h`.

## Arquivos criados ou alterados

- `windows/driver/.gitignore`.
- `windows/driver/README.md`.
- `windows/driver/LumaBridgeIddDriver.sln`.
- `windows/driver/LumaBridgeIddDriver/LumaBridgeIddDriver.vcxproj`.
- `windows/driver/LumaBridgeIddDriver/LumaBridgeIddDriver.vcxproj.filters`.
- `windows/driver/LumaBridgeIddDriver/Driver.cpp`.
- `windows/driver/LumaBridgeIddDriver/Driver.h`.
- `windows/driver/LumaBridgeIddDriver/LumaBridgeIddDriver.inf`.
- `docs/spikes/windows-idd-build-foundation.md`.

## Comandos executados

Git inicial:

```bat
git status --short --branch
git branch --show-current
git fetch origin
git checkout dev
git pull origin dev
git checkout -b spike/windows-idd-build-foundation
```

Validacao de ambiente:

```bat
where.exe msbuild
where.exe cl
where.exe link
where.exe stampinf
where.exe inf2cat
```

Validacao de `Inf2Cat.exe` por caminho completo:

```powershell
Test-Path "C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x86\Inf2Cat.exe"
```

Build final:

```bat
msbuild windows\driver\LumaBridgeIddDriver.sln /p:Configuration=Debug /p:Platform=x64 /p:WindowsTargetPlatformVersion=10.0.28000.0 /v:minimal
```

## Resultado da build

Resultado final: aprovado.

O MSBuild retornou codigo 0 e gerou a DLL em Debug x64:

```text
windows\driver\x64\Debug\LumaBridgeIddDriver.dll
```

Saida relevante:

```text
Building 'LumaBridgeIddDriver' with toolset 'WindowsUserModeDriver10.0' and the 'Desktop' target platform.
LumaBridgeIddDriver.vcxproj -> windows\driver\x64\Debug\LumaBridgeIddDriver.dll
Inf2Cat task was skipped as there were no inf files to process
DrvCat task was skipped as there was no catalog file to process
```

Artefatos locais gerados e ignorados pelo `.gitignore`:

- `windows/driver/x64/Debug/LumaBridgeIddDriver.dll`.
- `windows/driver/x64/Debug/LumaBridgeIddDriver.exp`.
- `windows/driver/x64/Debug/LumaBridgeIddDriver.lib`.
- `windows/driver/x64/Debug/LumaBridgeIddDriver.pdb`.
- arquivos intermediarios em `windows/driver/x64/Debug/LumaBridgeIddDriver/`.

Esses artefatos nao devem ser adicionados ao commit.

## Erros encontrados e resolucao

1. `MSB8040`: o toolset pediu bibliotecas Spectre opcionais.
   - Resolucao: `Driver_SpectreMitigation=false` no projeto, pois este spike valida fundacao de build e nao depende dessas bibliotecas opcionais.

2. Erros em `winioctl.h` por tipos basicos nao definidos na cadeia de includes.
   - Resolucao: incluir `Windows.h` antes de `wdf.h` e `IddCx.h`.

3. `C1189: IDDCX_VERSION_MAJOR is not defined` em `IddCxFuncEnum.h`.
   - Resolucao: configurar IddCx 1.4 como `IDDCX_VERSION_MAJOR=1` e `IDDCX_VERSION_MINOR=4` em `PreprocessorDefinitions`, forma compativel com o WDK `10.0.28000.0`.

4. `C4471` em `WudfWdm.h` tratado como erro pelo WDK.
   - Resolucao: suprimir especificamente `C4471` no projeto, sem desabilitar warnings globalmente.

5. `SignTool error: No file digest algorithm specified` no passo automatico de assinatura.
   - Resolucao: `EnableTestSign=false` e `SignMode=Off`. Assinatura esta fora do escopo e nao foi executada no build aprovado.

## Limitacoes

- `LumaBridgeEvtDeviceAdd` retorna `STATUS_NOT_IMPLEMENTED`.
- Nenhuma API IddCx e inicializada.
- Nenhum adapter IddCx e criado.
- Nenhum monitor virtual e criado.
- Nenhum swapchain e processado.
- Nenhuma captura, streaming, host, client, protocolo ou NVENC foi implementado.
- O INF e minimo e acompanha o projeto como arquivo de desenvolvimento; nao foi instalado, assinado ou empacotado como driver funcional.
- O IddSample da Microsoft foi usado somente como referencia conceitual; nenhum arquivo ou bloco de implementacao foi copiado.

## Conclusao

Aprovado.

A fundacao minima WDK/UMDF/IddCx compila em `Debug|x64` e gera `LumaBridgeIddDriver.dll`. O build valida MSBuild, MSVC, linker, headers WDF/IddCx e toolset `WindowsUserModeDriver10.0` no ambiente Build Tools 18.x com SDK/WDK `10.0.28000.0`.

## Proximos passos

1. Criar issue separada para inicializacao IddCx minima.
2. Avaliar quando o INF deve passar de arquivo de desenvolvimento para pacote validado por Inf2Cat.
3. Definir fluxo de instalacao somente em spike futuro, com decisao explicita sobre assinatura/test signing.
4. Manter host, client, protocolo, streaming e NVENC fora do driver.
