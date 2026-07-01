# Ambiente Windows para WDK e IddCx

## 1. Objetivo

Este documento registra a preparacao do ambiente Windows para desenvolvimento futuro do driver virtual do LumaBridge Display com WDK, UMDF/WDF e IddCx.

A validacao aqui serve apenas para confirmar que as ferramentas base estao disponiveis. Esta issue nao implementa driver funcional nem cria scaffold de driver.

## 2. Relacao com a issue #10

A issue #10, registrada no spike `docs/spikes/windows-idd-virtual-display.md`, identificou que o ambiente Windows ainda nao estava pronto para validar IddCx.

Naquele momento, o spike registrou os seguintes bloqueios:

- Visual Studio Build Tools estava parcial ou incompleto.
- `msbuild`, `cl`, `link`, `cmake` e `ninja` nao estavam acessiveis no PATH.
- `IddCx.h` nao foi encontrado.
- `Wdf.h` nao foi encontrado.
- `inf2cat.exe` nao foi encontrado.
- `stampinf.exe` nao foi encontrado.
- `WDKContentRoot`, `WindowsSdkDir` e `VCToolsInstallDir` nao estavam definidos no terminal usado.

Esta issue #12 retoma esse bloqueio e documenta o estado atual do ambiente.

## 3. Escopo da issue #12

O escopo desta issue e preparar e documentar o ambiente Windows para desenvolvimento futuro de driver.

Dentro do escopo:

- Verificar Visual Studio ou Build Tools.
- Verificar workload C++ e MSVC.
- Verificar Windows SDK e Windows Driver Kit.
- Verificar `msbuild`, `cl`, `link`, `cmake`, `ninja`, `inf2cat` e `stampinf`.
- Verificar `IddCx.h` e `Wdf.h`.
- Registrar evidencias e resultado.

Fora do escopo:

- Implementar driver virtual.
- Criar scaffold funcional em `windows/driver`.
- Implementar host.
- Implementar client.
- Implementar protocolo.
- Implementar streaming.
- Implementar NVENC.
- Criar instalador.
- Assinar driver.

## 4. Ambiente antes da correcao

Estado registrado pelo spike da issue #10:

| Item | Estado |
|---|---|
| Sistema operacional | Windows disponivel, build 26200 registrado no spike |
| Visual Studio / Build Tools | Instancia Build Tools 18.x detectada, mas incompleta naquele momento |
| SDK detectado | Include `10.0.26100.0` detectado |
| `msbuild` | Nao encontrado no PATH usado pelo spike |
| `cl` | Nao encontrado no PATH usado pelo spike |
| `link` | Nao encontrado no PATH usado pelo spike |
| `cmake` | Nao encontrado no PATH usado pelo spike |
| `ninja` | Nao encontrado no PATH usado pelo spike |
| `IddCx.h` | Nao encontrado |
| `Wdf.h` | Nao encontrado |
| `inf2cat.exe` | Nao encontrado |
| `stampinf.exe` | Nao encontrado |

Estado do PATH global nesta verificacao da issue #12:

| Comando | Resultado |
|---|---|
| `where.exe vswhere` | Nao encontrado no PATH global |
| `where.exe msbuild` | Nao encontrado no PATH global |
| `where.exe cl` | Nao encontrado no PATH global |
| `where.exe link` | Nao encontrado no PATH global |
| `where.exe cmake` | Nao encontrado no PATH global |
| `where.exe ninja` | Nao encontrado no PATH global |
| `where.exe inf2cat` | Nao encontrado no PATH global |
| `where.exe stampinf` | Nao encontrado no PATH global |

O PATH global nao e o ambiente correto para compilar driver. A validacao relevante deve ser feita em Developer Command Prompt ou Developer PowerShell com o ambiente do Visual Studio carregado.

## 5. Acoes realizadas

Nao foi executada instalacao manual, reparo via GUI, assinatura, criacao de driver ou alteracao de componentes do sistema nesta branch.

O ambiente atual ja apresenta Visual Studio Build Tools e Windows Kits instalados. A verificacao confirmou os seguintes componentes:

| Componente | Resultado |
|---|---|
| Visual Studio Installer | `C:\Program Files (x86)\Microsoft Visual Studio\Installer\vs_installer.exe` |
| `vswhere.exe` | `C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe` |
| Build Tools | Visual Studio Build Tools 18.7.3, `VisualStudio/18.7.3+11925.98` |
| Caminho Build Tools | `C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools` |
| Estado Build Tools | `isComplete=true`, `isLaunchable=true`, `isRebootRequired=false` |
| Workload C++ | `Microsoft.VisualStudio.Workload.VCTools` encontrado |
| MSVC | `14.51.36231` |
| Windows SDK ativo no Developer Prompt | `10.0.28000.0` |
| Familia WDK validada | `10.0.28000.0` |
| CMake | Instalado junto ao Build Tools |
| Ninja | Instalado junto ao Build Tools |

Tambem existem diretorios do Windows Kits para `10.0.26100.0`, mas a validacao aprovada desta issue usa a familia ativa `10.0.28000.0`, alinhada ao Build Tools 18.x/VS2026.

Nao houve reinicializacao necessaria nesta etapa.

## 6. Ambiente apos correcao

Sistema operacional observado:

| Campo | Resultado |
|---|---|
| `WindowsProductName` | `Windows 10 Pro` |
| `WindowsVersion` | `2009` |
| `OsBuildNumber` | `26200` |

Ambiente correto usado para validacao:

```bat
cmd.exe /c ""C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 -no_logo"
```

Variaveis relevantes no Developer Command Prompt:

| Variavel | Resultado |
|---|---|
| `WindowsSdkDir` | `C:\Program Files (x86)\Windows Kits\10\` |
| `WindowsSDKVersion` | `10.0.28000.0\` |
| `VCToolsInstallDir` | `C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.51.36231\` |
| `WDKContentRoot` | Nao definida |

Resultados de `where.exe` no Developer Command Prompt:

| Comando | Resultado |
|---|---|
| `where.exe msbuild` | `C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe`; `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe` |
| `where.exe cl` | `C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe` |
| `where.exe link` | `C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe` |
| `where.exe cmake` | `C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe` |
| `where.exe ninja` | `C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe` |
| `where.exe inf2cat` | Nao encontrado no PATH do Developer Command Prompt |
| `where.exe stampinf` | `C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x64\stampinf.exe`; `C:\Program Files (x86)\Windows Kits\10\bin\x64\stampinf.exe` |

`Inf2Cat.exe` nao esta no PATH do Developer Command Prompt, mas foi encontrado por caminho completo oficial no Windows Kits:

```text
C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x86\Inf2Cat.exe
```

Headers e ferramentas WDK encontrados por busca direta:

| Item | Caminhos encontrados |
|---|---|
| `IddCx.h` | `C:\Program Files (x86)\Windows Kits\10\Include\10.0.28000.0\um\iddcx\1.0\IddCx.h`; `1.2`; `1.3`; `1.4`; `1.6`; `1.7`; `1.8`; `1.9`; `1.10`; `1.11` |
| `Wdf.h` | `C:\Program Files (x86)\Windows Kits\10\Include\wdf\kmdf\1.15` ate `1.35`; `C:\Program Files (x86)\Windows Kits\10\Include\wdf\umdf\2.15` ate `2.35` |
| `Inf2Cat.exe` | `C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x86\Inf2Cat.exe` |
| `stampinf.exe` | `C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x64\stampinf.exe`; tambem em `x86` e `arm64` |

Alinhamento observado:

- Build Tools 18.x/VS2026 esta instalado e completo.
- Developer Command Prompt seleciona `WindowsSDKVersion=10.0.28000.0`.
- `IddCx.h`, `Inf2Cat.exe` e `stampinf.exe` foram encontrados na familia `10.0.28000.0`.
- `Wdf.h` foi encontrado na raiz WDF do Windows Kits.
- A familia `10.0.26100.0` tambem existe no Windows Kits, mas nao foi usada como familia ativa nesta validacao.

## 7. Resultado

Resultado: aprovado.

Motivo:

- `msbuild`, `cl` e `link` funcionam no Developer Command Prompt.
- `IddCx.h` foi encontrado.
- `Wdf.h` foi encontrado.
- `stampinf.exe` foi encontrado.
- `Inf2Cat.exe` foi encontrado por caminho completo oficial no Windows Kits.
- O ambiente validado esta alinhado em Build Tools 18.x/VS2026 com SDK/WDK `10.0.28000.0`.

Observacao: `Inf2Cat.exe` nao esta no PATH do Developer Command Prompt. Isso nao bloqueia esta issue porque o executavel foi encontrado por caminho completo na familia WDK validada. Ao usar `Inf2Cat.exe` em uma etapa futura, chamar o caminho completo ou ajustar o ambiente de build explicitamente.

## 8. Proximos passos

Com o ambiente aprovado, o proximo passo deve ser retomar a validacao pratica de IddCx em uma nova issue ou spike.

Essa etapa futura pode criar um scaffold minimo em `windows/driver`, desde que a issue correspondente permita isso explicitamente. O scaffold deve continuar separado de host, client, protocolo, streaming, NVENC, instalador e assinatura.

## 9. Fora do escopo

Esta issue nao realizou:

- Driver funcional.
- Scaffold funcional de driver.
- Host.
- Client.
- Protocolo.
- Streaming.
- NVENC.
- Instalador.
- Assinatura de driver.
- Alteracao direta em `main`.
