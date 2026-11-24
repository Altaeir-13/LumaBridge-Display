#pragma once

#include <cstdint>

#ifndef LUMABRIDGE_DIAGNOSTIC_STAGE
#define LUMABRIDGE_DIAGNOSTIC_STAGE 6
#endif

static_assert(
    LUMABRIDGE_DIAGNOSTIC_STAGE >= 1 && LUMABRIDGE_DIAGNOSTIC_STAGE <= 6,
    "LUMABRIDGE_DIAGNOSTIC_STAGE must be between 1 and 6.");

namespace lumabridge::driver {

/// Active compile-time diagnostic stage (1..6; Stage 6 = full implementation).
inline constexpr uint32_t kActiveDiagnosticStage = static_cast<uint32_t>(LUMABRIDGE_DIAGNOSTIC_STAGE);

/// Compile-time feature gates for incremental UMDF/IddCx diagnostic isolation.
struct DiagnosticStageCapabilities
{
    bool EnableCoreWdfAndIddCxAdapterInit{false};
    bool EnableAdapterStateMachineAndSync{false};
    bool EnableTraceLoggingAndRegistryBreadcrumbs{false};
    bool EnableVirtualMonitor{false};
    bool EnableSwapChainProcessor{false};
    bool EnableFullHostTelemetry{false};
};

/// Returns the capability set enabled for a given diagnostic build stage (1..6).
constexpr DiagnosticStageCapabilities
GetDiagnosticStageCapabilities(
    uint32_t stage
    ) noexcept
{
    return DiagnosticStageCapabilities{
        stage >= 1U,
        stage >= 2U,
        stage >= 3U,
        stage >= 4U,
        stage >= 5U,
        stage >= 6U};
}

/// Models IddCx.dll (10.0.26100.9818) Validate(IDDCX_ADAPTER_CAPS) TransmissionType validation.
/// Runtime accepts [1..8] and 0xFFFFFFFF (IDDCX_TRANSMISSION_TYPE_OTHER); rejects 0 and 9 (NETWORK_OTHER).
constexpr bool
IsSupportedIddCxRuntimeTransmissionType(
    uint32_t transmissionType
    ) noexcept
{
    if (transmissionType == 0U)
    {
        return false;
    }

    return static_cast<uint32_t>(transmissionType - 9U) > 0xFFFFFFF5U;
}

} // namespace lumabridge::driver
