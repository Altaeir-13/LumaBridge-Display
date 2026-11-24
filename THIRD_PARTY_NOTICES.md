# Third-Party Notices — LumaBridge Display

LumaBridge Display's own original source code and documentation are licensed under the **Apache License, Version 2.0** (see [LICENSE](LICENSE)). Not all files in this repository are licensed under Apache-2.0: incorporated third-party components remain subject to their respective upstream licenses and copyright notices, which are preserved verbatim below.

---

## 1. Incorporated Third-Party Components

### 1.1 NVIDIA Video Codec SDK Header (`nvEncodeAPI.h` via `FFmpeg/nv-codec-headers`)

- **Component Name:** `nvEncodeAPI.h` (NVIDIA Video Codec SDK / NVENC API C Header)
- **Repository Location:** [`windows/host/third_party/nvenc/nvEncodeAPI.h`](windows/host/third_party/nvenc/nvEncodeAPI.h)
- **Verifiable Upstream Origin:**
  - Repository: `https://github.com/FFmpeg/nv-codec-headers`
  - Branch / Tag: `sdk/12.1`
  - File path: `include/ffnvcodec/nvEncodeAPI.h`
  - Upstream reference URL: `https://github.com/FFmpeg/nv-codec-headers/blob/sdk/12.1/include/ffnvcodec/nvEncodeAPI.h`
  - Verified upstream commit on `sdk/12.1`: `610325d019ad75248aa6e7abe0f4909d2ac6bc69`
  - Verified Git blob SHA-1 match (`origin/dev` vs upstream `sdk/12.1`): `f91ec9ad3b7303bcbb66f7265ab0c1341971d247`
  - File SHA-256 (working tree): `FFD219487ABA9F2318989EB62657AAE2F7EE984DFEA6D245F81AE4F29D21C153`
- **Version:** NVENC API `12.1` (`NVENCAPI_MAJOR_VERSION 12`, `NVENCAPI_MINOR_VERSION 1`)
- **Copyright Holder:** `Copyright (c) 2010-2023 NVIDIA Corporation`
- **Applicable License:** MIT License *(applies to `nvEncodeAPI.h` only)*
- **Attribution Obligations:** The above copyright notice and MIT permission notice must be included in all copies or substantial portions of the file.
- **Required License Text (verbatim from [`windows/host/third_party/nvenc/nvEncodeAPI.h`](windows/host/third_party/nvenc/nvEncodeAPI.h#L1-L26)):**

```text
/*
 * This copyright notice applies to this header file only:
 *
 * Copyright (c) 2010-2023 NVIDIA Corporation
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the software, and to permit persons to whom the
 * software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */
```

- **Known Distribution Limitations:**
  - Only the MIT-licensed C API header is tracked in this repository.
  - **No proprietary NVIDIA `.dll` or `.lib` files** are tracked or redistributed in this repository.
  - At runtime, `lumabridge-host.exe` dynamically loads `nvEncodeAPI64.dll` from the user's already-installed NVIDIA display driver in `System32` via `LoadLibraryExW(..., LOAD_LIBRARY_SEARCH_SYSTEM32)` (`windows/host/NvencH264Encoder.cpp`).

---

## 2. Provenance Audit of External Sample References

*(Engineering and historical provenance review of repository headers, Git commits, and verifiable upstream artifacts — this record does not constitute an absolute legal proof of chain-of-title or formal legal counsel.)*

### 2.1 Microsoft `Windows-driver-samples` / `IddSampleDriver`

- **Audit Result:** **No source files, headers, INF templates, or EDID byte arrays from Microsoft `Windows-driver-samples` (`IddSampleDriver`) are incorporated into this repository.**
- **Verified Implementation Details:**
  - All files under [`windows/driver/LumaBridgeIddDriver/`](windows/driver/LumaBridgeIddDriver/) (`Driver.h/.cpp`, `Adapter.h/.cpp`, `AdapterStateMachine.h`, `DiagnosticStageConfig.h`, `VirtualMonitor.h/.cpp`, `MonitorModes.h/.cpp`, `SwapChainProcessor.h/.cpp`, `FrameExtractor.h/.cpp`, `SharedTexturePool.h/.cpp`, `FrameIpcProtocol.h`, `FrameTransport.h/.cpp`, `Trace.h`, `LumaBridgeIddDriver.inf`) were authored for LumaBridge Display without copied Microsoft sample blocks or sample copyright headers.
  - `VirtualMonitorManager` / `IddCxVirtualMonitorBackend` explicitly avoids copying sample EDID byte arrays by declaring `IDDCX_MONITOR_DESCRIPTION_TYPE_EDID` with `DataSize = 0` and `pData = nullptr` (`windows/driver/LumaBridgeIddDriver/Adapter.cpp`, `VirtualMonitor.h`), while [`MonitorModes.cpp`](windows/driver/LumaBridgeIddDriver/MonitorModes.cpp) uses standard CTA-861 VIC 4 (`1280x720@60`) and VIC 16 (`1920x1080@60`) timings.
  - [`windows/driver/scripts/Prepare-IddSampleReference.ps1`](windows/driver/scripts/Prepare-IddSampleReference.ps1) is an optional standalone diagnostic script that downloads `microsoft/Windows-driver-samples` (`video/IndirectDisplay`) solely into an isolated temporary directory strictly outside the repository (`Assert-LumaBridgeIsolatedStagingDirectory`) for side-by-side experimental control comparison (`docs/diagnostics/windows-idd-start-failure-investigation.md`), without incorporating or committing any Microsoft sample files into LumaBridge Display.

---

## 3. External Build-Time, Runtime, and CI Dependencies (Not Redistributed)

The following external dependencies are used during compilation, testing, CI execution, or system runtime on the user's host, and are **not tracked or redistributed** in source form inside this repository:

| Dependency | Usage Context | Applicable Terms / Notes |
|---|---|---|
| **Microsoft Windows SDK & Windows Driver Kit (WDK)** (`wdf.h`, `IddCx.h`, `d3d11.lib`, `dxgi.lib`, `mfplat.lib`, `mfuuid.lib`, `wmcodecdspuuid.lib`, `crypt32.lib`, `wintrust.lib`, `signtool.exe`, `Inf2Cat.exe`, `InfVerif.exe`, `devcon.exe`) | Compile-time headers/import libraries and local WDK driver packaging/signing tools | Subject to Microsoft Windows SDK / WDK license terms. Windows inbox OS DLLs (`WUDFx02000.dll`, `IddCx.dll`, `d3d11.dll`, `dxgi.dll`, `mfplat.dll`, `msmpeg2vdec.dll`) reside on the target OS and are not redistributed. |
| **Microsoft Visual Studio / MSVC Build Tools & Spectre Libraries** | C++17 / C++20 compilation, static CRT/Spectre linking in UMDF driver (`/Qspectre`), and host executable build | Subject to Microsoft Visual Studio / MSVC Redistributable license terms if compiled binaries are distributed publicly in future releases. |
| **NVIDIA `nvEncodeAPI64.dll`** | Optional dynamic runtime loading by `lumabridge-host.exe` on systems with NVIDIA GPUs | Proprietary component provided by the end user's NVIDIA graphics driver installation; never redistributed by LumaBridge Display. |
| **GitHub Actions (`actions/checkout`, `actions/upload-artifact`)** | Hosted CI workflows in `.github/workflows/` (pinned by full commit SHA) | CI automation only (MIT License upstream); not incorporated into LumaBridge runtime artifacts. |
| **Rust Toolchain, `cbindgen`, `cargo-deny`, `cargo-ndk`** (`core/`) | Host compiler, C header generator (`MPL-2.0`), dependency compliance checker (`Apache-2.0 OR MIT`), and Android NDK Cargo wrapper (`Apache-2.0 OR MIT`) | Build-time tooling only; not redistributed in source or binary form inside this repository. Default `lumabridge-core` and `lumabridge-ffi` builds have zero external runtime crate dependencies. |
| **`uniffi` / `uniffi-bindgen` (`0.32.2`, optional `uniffi` / `uniffi-cli` features)** | Optional Kotlin/Android binding scaffolding and host bindgen CLI in `core/crates/lumabridge-ffi` | Upstream **MPL-2.0** license; disabled under default features (`default = []`) and excluded from the Windows MSVC `cdylib` emitter path. Audited via `core/deny.toml` and [`docs/planning/LICENSE_COMPLIANCE_REVIEW.md`](docs/planning/LICENSE_COMPLIANCE_REVIEW.md). |
| **Android NDK (`28.2.13676358`, `aarch64-linux-android`)** | Cross-compilation toolchain for optional Android `arm64-v8a` verification (`core/android/README.md`) | Subject to Android NDK license terms; generated `.so` and Kotlin files are excluded from Git tracking. |

For ongoing dependency classification policy (Green/Yellow/Red license tiers and multimedia patent considerations), see [`docs/planning/LICENSE_COMPLIANCE_REVIEW.md`](docs/planning/LICENSE_COMPLIANCE_REVIEW.md).
