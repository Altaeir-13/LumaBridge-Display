# Spike: Validacao da inicializacao minima do driver com DriverEntry e WdfDriverCreate

Data: 2026-11-18
Branch: `spike/windows-idd-driver-entry-validation`
Base validada: `4f814f8` (`dev`, integrada via PR #17 / issue #16)
Issue relacionada: #18

## 1. Objetivo

Validar formalmente os criterios de aceite da issue #18 sobre a entrada minima WDF/UMDF (`DriverEntry`, `WDF_DRIVER_CONFIG_INIT`, `WdfDriverCreate` e stub controlado `LumaBridgeEvtDeviceAdd`) no codigo ja integrado a `dev` pelo PR #17 (`4f814f8`), sem duplicar codigo nem antecipar inicializacao IddCx neste registro documental.

## 2. O que foi validado em `DriverEntry` e `LumaBridgeEvtDeviceAdd` (`4f814f8`)

Inspecao direta de `windows/driver/LumaBridgeIddDriver/Driver.h` e `windows/driver/LumaBridgeIddDriver/Driver.cpp` na base `dev` (`4f814f8`):

- `Driver.h` declara `EVT_WDF_DRIVER_DEVICE_ADD LumaBridgeEvtDeviceAdd;` e inclui `<Windows.h>`, `<wdf.h>` e `<IddCx.h>`.
- `DriverEntry` utiliza linkage `extern "C"` com assinatura `NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)`.
- `WDF_DRIVER_CONFIG_INIT(&config, LumaBridgeEvtDeviceAdd)` inicializa a estrutura de configuracao WDF antes da criacao do objeto driver.
- `WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE)` registra o driver no framework WDF/UMDF (`WdfDriverStubUm.lib`).
- `LumaBridgeEvtDeviceAdd` recebe `WDFDRIVER` e `PWDFDEVICE_INIT` e retorna `STATUS_NOT_IMPLEMENTED` como stub controlado, sem inicializar dispositivo nem APIs IddCx neste estagio.

### O que ainda nao foi inicializado na base `4f814f8`

Conforme o escopo da issue #18:

- Nenhuma chamada a `IddCxDeviceInitConfig`, `IddCxDeviceInitialize`, `IddCxAdapterInitAsync` ou callbacks IddCx.
- Nenhum `WDFDEVICE`, adaptador indireto, monitor virtual, lista de modos ou swapchain.
- Nenhuma instalacao, assinatura de driver, host, cliente, protocolo, streaming ou NVENC.

*(Nota de continuidade: a evolucao funcional subsequente da inicializacao de dispositivo e adaptador IddCx esta tratada em entrega separada na issue #19 / PR #22.)*

## 3. Verificacao dos criterios de aceite da issue #18

| Criterio de aceite | Situacao em `4f814f8` + esta entrega |
|---|---|
| `DriverEntry` implementado de forma coerente com WDF/UMDF | Atendido em `Driver.cpp` (`4f814f8`); exportacao `FxDriverEntryUm` confirmada |
| `WDF_DRIVER_CONFIG_INIT` usado corretamente | Atendido em `Driver.cpp:12` (`4f814f8`) |
| `WdfDriverCreate` chamado corretamente | Atendido em `Driver.cpp:14-19` (`4f814f8`) |
| `LumaBridgeEvtDeviceAdd` existe e permanece como stub controlado | Atendido em `Driver.cpp:22-33` retornando `STATUS_NOT_IMPLEMENTED` |
| Nenhuma funcionalidade IddCx real inicializada nesta base | Confirmado na base `4f814f8` |
| Build `Debug|x64` passa com MSBuild | Revalidado nesta branch com codigo de saida `0` |
| `windows/driver/README.md` atualizado, se necessario | Ja contemplava `DriverEntry`, `WDF_DRIVER_CONFIG_INIT`, `WdfDriverCreate` e stub `LumaBridgeEvtDeviceAdd` em `4f814f8`; mantido sem duplicacao |
| `docs/spikes/windows-idd-driver-entry-validation.md` criado | Atendido nesta entrega |
| Nenhum driver instalado ou assinado | Confirmado |
| Nenhum host/client/protocolo/streaming/NVENC implementado | Confirmado |
| `main` nao foi alterada | Confirmado (`origin/main` em `95f0ed4`) |

## 4. Evidencias de build e inspecao binaria

Comando MSBuild executado na branch `spike/windows-idd-driver-entry-validation` (sobre a base `4f814f8`):

```bat
msbuild windows\driver\LumaBridgeIddDriver.sln /t:Rebuild /p:Configuration=Debug /p:Platform=x64 /p:WindowsTargetPlatformVersion=10.0.28000.0 /v:minimal
```

Resultado observado:

- Codigo de saida `0`, sem erros de compilacao ou ligacao.
- Artefato gerado localmente (ignorado por `windows/driver/.gitignore`): `windows\driver\x64\Debug\LumaBridgeIddDriver.dll`.
- `dumpbin.exe /exports windows\driver\x64\Debug\LumaBridgeIddDriver.dll` confirmou exportacao de `FxDriverEntryUm` no ordinal `1` (RVA `00001180`), demonstrando ligacao correta com o entrypoint UMDF (`WdfDriverStubUm.lib`).

## 5. Conclusao

**Aprovado.** Os criterios tecnicos e documentais da issue #18 estao integralmente atendidos e rastreados sem duplicacao de codigo, preparando a integracao limpa da evolucao seguinte (issue #19 / PR #22).
