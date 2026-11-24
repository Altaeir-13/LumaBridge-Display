// SPDX-License-Identifier: Apache-2.0
#pragma once

namespace lumabridge::host {

// Isolated opt-in M1.1 FFI PoC self-test invoked only when built with
// LUMABRIDGE_ENABLE_FFI_POC and run with --ffi-poc-selftest.
int RunLumaBridgeFfiPocSelfTest() noexcept;

} // namespace lumabridge::host
