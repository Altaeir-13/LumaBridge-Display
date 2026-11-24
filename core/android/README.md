# Android ARM64 & UniFFI Portability Qualification (M1.1 / M1.1.1 PoC)

Este diretório documenta a qualificação de compilação cruzada Android ARM64 (`aarch64-linux-android`) e geração real de bindings Kotlin via `uniffi` prevista na [ADR-0004](../../docs/architecture/ADR-0004-core-language-and-native-boundaries.md) (`Accepted`).

> [!NOTE]
> Artefatos binários gerados (`.so`, `.kt` de build) ficam em `core/target/` ou em diretórios temporários fora do repositório e **não** são versionados no Git.

## Estados de Qualificação Android

- `KOTLIN_BINDINGS_GENERATED = True`
- `KOTLIN_BINDINGS_FULL_COMPILATION_VERIFIED = False`
- `ANDROID_DEVICE_RUNTIME_TESTED = False`

## Toolchain e Versões Utilizadas na Validação

- Rust target: `aarch64-linux-android` (`rustc 1.100.0`, lockfile estrito `--locked`)
- Android NDK local (Windows): `28.2.13676358` (`<ANDROID_NDK_HOME>`)
- Android NDK no runner CI Linux (`ubuntu-24.04`): `30.0.16248370` *(resolvido via `ANDROID_NDK_LATEST_HOME`)*
- Android API level: `29` (`arm64-v8a`)
- Orquestrador NDK: `cargo-ndk 4.1.2`
- Bindgen Kotlin: `uniffi` / `uniffi-cli` (`0.32.2`, feature opcional `uniffi-cli`)

## Reprodução Local (Sem Alterar PATH Global)

```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
$env:ANDROID_NDK_HOME = "<ANDROID_SDK>\ndk\28.2.13676358"
$env:ANDROID_NDK_ROOT = $env:ANDROID_NDK_HOME

Push-Location core
# 1. Cross-build Android ARM64 (cdylib com scaffolding UniFFI e --locked)
cargo ndk -t arm64-v8a -P 29 -- build --locked -p lumabridge-ffi --features uniffi --release

# 2. Inspeção ELF e símbolos dinâmicos via llvm-readelf do NDK
& "$env:ANDROID_NDK_HOME\toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-readelf.exe" `
  -h -d target/aarch64-linux-android/release/liblumabridge_ffi.so

# 3. Geração de bindings Kotlin a partir da .so em --library mode
cargo run --locked -p lumabridge-ffi --features uniffi-cli `
  --bin uniffi-bindgen -- generate `
  --library target/aarch64-linux-android/release/liblumabridge_ffi.so `
  --language kotlin --out-dir "$env:TEMP\m11-kotlin-out" --no-format
Pop-Location
```

## Evidências Observadas na PoC (`M1.1.1`)

1. **Artefato ELF (`core/target/aarch64-linux-android/release/liblumabridge_ffi.so`):**
   - Tamanho observado em `M1.1.1`: `697.544` bytes *(PoC inicial `M1.1`: `688.920` bytes)*
   - Classe / Arquitetura / Tipo: `ELF64`, little-endian, `Machine: AArch64`, `Type: DYN (Shared object file)`
   - Dependências dinâmicas (`DT_NEEDED`): apenas `libdl.so` e `libc.so`
   - Símbolos exportados: entradas da C ABI (`lb_core_create`, `lb_core_start`, `lb_core_simulate_disconnect`, `lb_core_get_last_error`, etc.) e símbolos UniFFI (`uniffi_lumabridge_ffi_*`, `ffi_lumabridge_ffi_*`)
   - Isolamento de fault-injection: `lb_core_poc_trigger_panic` **ausente** na `.so` padrão

2. **Bindings Kotlin (`uniffi/lumabridge_ffi/lumabridge_ffi.kt`):**
   - Arquivo gerado diretamente da `.so`: `1.765` linhas (`66.553` bytes)
   - Superfície Kotlin gerada: `FfiPocSessionInterface`, `FfiPocSession` (`Disposable`, `AutoCloseable`), `FfiPocMetrics`, `FfiPocCodec`, `FfiPocState`, `FfiPocException`, além de `ffiPocAbiVersionString`, `start()`, `stop()`, `metrics()` e `submitSyntheticEncodedFrame(...)`
   - Limite transparente de compilação Kotlin e execução em dispositivo: esta PoC verifica apenas a compilação `.so` ARM64, a inspeção ELF/símbolos e a **geração de fonte Kotlin** via `uniffi-bindgen`. O código Kotlin gerado requer dependência JNA (`com.sun.jna.*`) e APIs Android configuradas via projeto Gradle; portanto, a compilação completa para bytecode e a execução em dispositivo físico ou emulador Android permanecem pendentes (`KOTLIN_BINDINGS_FULL_COMPILATION_VERIFIED = False`, `ANDROID_DEVICE_RUNTIME_TESTED = False`) e serão executadas na etapa dedicada ao receptor Android após `M1`.
