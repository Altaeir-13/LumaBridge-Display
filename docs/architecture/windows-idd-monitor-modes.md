# Modos de Video e Negociacao do Monitor Virtual no Windows (IddCx)

Data: 2026-11-18
Branch: `feature/windows-idd-monitor-modes`
Issue relacionada: #25 (Milestone M3 - Windows Virtual Display)

## 1. Estrategia adotada

O driver `LumaBridgeIddDriver` (UMDF 2.31 / IddCx 1.4+) adota a estrategia de **modos padrao fornecidos pelo driver sem bloco EDID** (`IDDCX_MONITOR_DESCRIPTION_TYPE_EDID` com `DataSize = 0` e `pData = nullptr`):

- O monitor virtual nao depende de um bloco EDID sintetico fixo de 128 bytes.
- `EvtIddCxMonitorGetDefaultDescriptionModes` fornece os modos padrao do monitor com `IDDCX_MONITOR_MODE_ORIGIN_DRIVER` e sinaliza o modo preferencial.
- `EvtIddCxMonitorQueryTargetModes` expoe os modos de destino (`IDDCX_TARGET_MODE`) suportados pelo pipeline do adaptador dentro de `kMaxDisplayPipelineRate`.
- `EvtIddCxParseMonitorDescription` valida argumentos de entrada (`STATUS_INVALID_PARAMETER` para ponteiros nulos, buffer nulo com contagem > 0 ou `DataSize > 0` com `pData == nullptr`) e recusa explicitamente o parsing com `STATUS_NOT_SUPPORTED` nesta etapa do MVP.
- `EvtIddCxAdapterCommitModes` valida o estado do ciclo de vida do adaptador, o limite de paths (`PathCount <= kMaxMonitorsSupported`), `MonitorObject != nullptr` e verifica que todo path ativo (`IDDCX_PATH_FLAGS_ACTIVE`) utilize um `DISPLAYCONFIG_VIDEO_SIGNAL_INFO` com `vSyncFreqDivider == 1` (atualizacao 1:1) e correspondencia exata de todos os timings com um modo anunciado pelo driver.

## 2. Decisao sobre EDID

Foram avaliadas duas alternativas para a entrega MVP:

1. **EDID sintetico + `EvtIddCxParseMonitorDescription`:** requer geracao e manutencao de descritores binarios CEA/VESA, checksum e blocos de extensao, sem ganho funcional para o MVP SDR progressivo.
2. **Sem EDID (`IDDCX_MONITOR_DESCRIPTION_TYPE_EDID` com `DataSize = 0` e `pData = nullptr`) + `EvtIddCxMonitorGetDefaultDescriptionModes`:** contrato nativo do IddCx 1.4 onde o driver declara diretamente os `IDDCX_MONITOR_MODE` com `IDDCX_MONITOR_MODE_ORIGIN_DRIVER` e o indice preferencial.

Selecionou-se a **alternativa 2** por simplicidade, menor superficie de erro e aderencia direta ao modelo de display virtual por software. Caso uma entrega futura necessite capacidades avancadas (como metadados HDR ou passthrough de EDID fisico), `EvtIddCxParseMonitorDescription` podera ser estendido sem alterar a arquitetura de `MonitorModes`.

## 3. Modos suportados no MVP

Todos os modos do MVP sao **SDR**, **progressivos** (`DISPLAYCONFIG_SCANLINE_ORDERING_PROGRESSIVE`) e **60 Hz exatos**, sem HDR, VRR ou modos entrelacados:

| Modo | Resolucao ativa | Resolucao total (CTA-861) | Refresh (`vSyncFreq`) | `hSyncFreq` | Pixel clock (`pixelRate`) | `RequiredBandwidth` (px/s) | Preferencial |
|---|---|---|---|---|---|---|---|
| 720p60 (CTA-861 VIC 4) | `1280 x 720` | `1650 x 750` | `60 / 1` Hz | `45000 / 1` Hz | `74,250,000` Hz (`74.25 MHz`) | `55,296,000` | Nao |
| 1080p60 (CTA-861 VIC 16) | `1920 x 1080` | `2200 x 1125` | `60 / 1` Hz | `67500 / 1` Hz | `148,500,000` Hz (`148.50 MHz`) | `124,416,000` | Sim (`idx = 1`) |

### Avaliacao de 2560 x 1440 @ 60 Hz

`kMaxDisplayPipelineRate` permanece dimensionado em `2560 * 1440 * 60 = 221,184,000` px/s para preservar headroom do adaptador. Entretanto, `2560x1440@60` **nao** e anunciado nesta entrega MVP para evitar prometer resolucoes acima de 1080p antes da validacao de captura/swapchain e throughput de encoding/rede.

## 4. Estruturas de dados

No modulo `windows/driver/LumaBridgeIddDriver/MonitorModes.h` / `MonitorModes.cpp`:

- `VideoModeSpec`: representacao canonica independente de WDF/IddCx contendo dimensoes ativas/totais, racionais `VSync` e `HSync`, `PixelRateHz`, `RequiredBandwidth`, `ScanlineOrdering` e flag `IsPreferred`.
- `ModeBufferNegotiationResult`: encapsula `Status` (`STATUS_SUCCESS`, `STATUS_BUFFER_TOO_SMALL`, `STATUS_INVALID_PARAMETER`, `STATUS_INSUFFICIENT_RESOURCES`), `OutputCount` e `PreferredIndex`.

Mapeamento para estruturas IddCx 1.4 em `Adapter.cpp`:

- `IDDCX_MONITOR_MODE`: `Size = sizeof(IDDCX_MONITOR_MODE)`, `Origin = IDDCX_MONITOR_MODE_ORIGIN_DRIVER`, `MonitorVideoSignalInfo` preenchido via `FillMonitorModeVideoSignalInfo` (`AdditionalSignalInfo.vSyncFreqDivider = 0`, conforme contrato de modo de monitor no IddCx).
- `IDDCX_TARGET_MODE`: `Size = sizeof(IDDCX_TARGET_MODE)`, `TargetVideoSignalInfo.targetVideoSignalInfo` preenchido via `FillTargetModeVideoSignalInfo` (`AdditionalSignalInfo.vSyncFreqDivider = 1` para atualizacao 1:1 do desktop; divisor `0` e proibido em target modes e `IDDCX_PATH`), `RequiredBandwidth = ActiveWidth * ActiveHeight * 60`.

## 5. Calculos e timings

As relacoes matematicas verificadas em tempo de validacao (`ValidateVideoModeSpec`, `ValidateMonitorModeVideoSignalInfo` e `ValidateTargetModeVideoSignalInfo`) garantem consistencia exata sem overflow em `uint64_t` (`SafeMultiplyU64` / `SafeMultiply3U64`) e correspondencia estrita com os modos anunciados:

- `0 < ActiveWidth <= TotalWidth` e `0 < ActiveHeight <= TotalHeight`
- `VSyncDenominator > 0`, `HSyncDenominator > 0` e `VSyncNumerator / VSyncDenominator == 60`
- `AdditionalSignalInfo.vSyncFreqDivider == 0` para `IDDCX_MONITOR_MODE` e `AdditionalSignalInfo.vSyncFreqDivider == 1` para `IDDCX_TARGET_MODE` / `IDDCX_PATH` ativo em `CommitModes`
- `AdditionalSignalInfo.videoStandard == 255` (`D3DKMDT_VSS_OTHER`)
- `PixelRateHz == TotalWidth * TotalHeight * 60`
- `HSyncFreq == TotalHeight * 60`
- `RequiredBandwidth == ActiveWidth * ActiveHeight * 60 <= maxPipelineRate`
- Correspondencia exata (`MatchesExactModeTiming`) com um modo retornado por `GetSupportedMvpVideoModes(maxPipelineRate, ...)` (rejeitando timings arbitrarios mesmo para resolucoes 720p/1080p)
- Deduplicacao garantida por `AreEquivalentVideoModes` antes de expor a tabela de modos.

### Compatibilidade UMDF / IddCx com Windows 11 21H2+

- Conforme `WindowsDriver.UserMode.LateEvaluation.props` (WDK `10.0.28000.0`), `UMDF 2.31` tem suporte a partir do Windows 10 2004 (`19041`, `_NT_TARGET_VERSION_WIN10_VB`) e `UMDF_MINIMUM_VERSION_REQUIRED=25` (`2.25`). No Windows 11 21H2 (`22000`, plataforma minima declarada em `LumaBridgeIddDriver.inf`), o sistema inbox fornece UMDF `2.33` e `IddCx 1.6+`, plenamente retrocompativeis com `UMDF 2.31` / `IddCx 1.4` (`IddCx0102`).

## 6. Contratos dos callbacks IddCx

| Callback | Comportamento implementado |
|---|---|
| `EvtIddCxParseMonitorDescription` | Valida ponteiros, buffer e `MonitorDescription` (`STATUS_INVALID_PARAMETER`), zera saidas (`OutputCount = 0`, `PreferredMonitorModeIdx = NO_PREFERRED_MODE`) e retorna `STATUS_NOT_SUPPORTED`. |
| `EvtIddCxMonitorGetDefaultDescriptionModes` | Valida `MonitorObject`/`pInArgs`/`pOutArgs`. Em consulta preliminar (`InputCount == 0`), retorna `STATUS_SUCCESS` com `DefaultMonitorModeBufferOutputCount = 2` e `PreferredMonitorModeIdx = 1`. Em buffer `> 0` e `< 2`, retorna `STATUS_BUFFER_TOO_SMALL` com `OutputCount = 2` e `PreferredMonitorModeIdx = NO_PREFERRED_MODE` sem gravar no buffer. Em buffer `>= 2`, preenche os 2 modos `IDDCX_MONITOR_MODE` com `vSyncFreqDivider = 0` e retorna `STATUS_SUCCESS`. |
| `EvtIddCxMonitorQueryTargetModes` | Valida `MonitorObject`/`pInArgs`/`pOutArgs`. Segue a mesma semantica de consulta preliminar (`STATUS_SUCCESS` com `OutputCount = 2`), buffer insuficiente (`STATUS_BUFFER_TOO_SMALL`) e preenchimento completo (`IDDCX_TARGET_MODE` com `vSyncFreqDivider = 1` e `RequiredBandwidth`). |
| `EvtIddCxAdapterCommitModes` | Valida `PathCount <= kMaxMonitorsSupported`, `MonitorObject != nullptr` e estado do adaptador via `TransitionOnCommitModes`; para cada `IDDCX_PATH` com `IDDCX_PATH_FLAGS_ACTIVE`, exige `ValidateTargetModeVideoSignalInfo` (`vSyncFreqDivider == 1` e timings identicos a um modo anunciado dentro de `kMaxDisplayPipelineRate`), retornando `STATUS_INVALID_PARAMETER` se invalido. |

## 7. Limitacoes e seguranca do monitor virtual

- **Nenhum monitor e anunciado ao Windows nesta entrega:** `IddCxMonitorCreate` e `IddCxMonitorArrival` nao sao chamados enquanto o pipeline minimo de swapchain/D3D11 nao estiver implementado.
- `LumaBridgeEvtMonitorAssignSwapChain` permanece como stub defensivo retornando `STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN` apenas por seguranca de contrato caso venha a ser acionado futuramente, nunca como substituto de processamento de frames.

## 8. Resultados dos testes

- `MonitorModesTests.exe`: **12 testes unitarios deterministicos** aprovados (`0` falhas), cobrindo 720p60, 1080p60, modo preferencial, calculos de frequencia/pixel rate, separacao de `vSyncFreqDivider` (`0` vs `1`), rejeicao de timings nao anunciados no commit, resolucoes/frequencias invalidas, limite de banda do adaptador, consulta preliminar de quantidade, buffer insuficiente, overflow aritmetico e ausencia de duplicatas.
- `AdapterLifecycleTests.exe`: **16 testes unitarios** aprovados (`0` falhas).
- `DriverPackageValidationTests.exe`: **5 testes de empacotamento** aprovados (`0` falhas).
- `MSBuild` `Debug|x64` e `Release|x64`: **0 erros, 0 warnings** (incluindo `StampInf`, `InfVerif`, `Inf2Cat` e `DrvCat`).

## 9. Dependencias para criacao efetiva do monitor

1. Implementar gerenciamento de objetos `IDDCX_MONITOR` e chamada controlada de `IddCxMonitorCreate` / `IddCxMonitorArrival` / `IddCxMonitorDeparture`.
2. Implementar pipeline minimo de swapchain (`EvtIddCxMonitorAssignSwapChain` / `EvtIddCxMonitorUnassignSwapChain`) com dispositivo Direct3D 11 e loop de aquisicao de frames.
3. Reativar mitigacao Spectre (issue #20) e realizar assinatura de teste controlada antes de instalar/carregar no `WUDFHost.exe`.
