#pragma once

#ifndef WIN32_NO_STATUS
#define WIN32_NO_STATUS
#define LUMABRIDGE_MONMODES_DEFINED_WIN32_NO_STATUS
#endif
#include <Windows.h>
#ifdef LUMABRIDGE_MONMODES_DEFINED_WIN32_NO_STATUS
#undef WIN32_NO_STATUS
#undef LUMABRIDGE_MONMODES_DEFINED_WIN32_NO_STATUS
#endif

#include <ntstatus.h>

#include <cstddef>
#include <cstdint>

typedef LONG NTSTATUS;

namespace lumabridge::driver {

inline constexpr uint32_t kDefaultRefreshRateHz = 60;
inline constexpr uint32_t kMaxSupportedVideoModes = 2;
inline constexpr uint64_t kMaxDisplayPipelineRate = 2560ULL * 1440ULL * 60ULL;
inline constexpr uint32_t kNoPreferredModeIndex = 0xffffffffU;
inline constexpr uint32_t kMonitorModeVSyncDivider = 0U;
inline constexpr uint32_t kTargetModeVSyncDivider = 1U;

/// Canonical description of a progressive SDR virtual monitor video mode.
struct VideoModeSpec
{
    uint32_t ActiveWidth{0};
    uint32_t ActiveHeight{0};
    uint32_t TotalWidth{0};
    uint32_t TotalHeight{0};
    uint32_t VSyncNumerator{0};
    uint32_t VSyncDenominator{0};
    uint32_t HSyncNumerator{0};
    uint32_t HSyncDenominator{0};
    uint64_t PixelRateHz{0};
    uint64_t RequiredBandwidth{0};
    DISPLAYCONFIG_SCANLINE_ORDERING ScanlineOrdering{DISPLAYCONFIG_SCANLINE_ORDERING_UNSPECIFIED};
    bool IsPreferred{false};
};

/// Result of negotiating a mode buffer (preliminary count query, insufficient buffer, or populated output).
struct ModeBufferNegotiationResult
{
    NTSTATUS Status{STATUS_UNSUCCESSFUL};
    uint32_t OutputCount{0};
    uint32_t PreferredIndex{kNoPreferredModeIndex};
};

/// Safely multiplies two 64-bit unsigned integers, returning false on overflow.
bool
SafeMultiplyU64(
    uint64_t a,
    uint64_t b,
    uint64_t& outProduct
    ) noexcept;

/// Safely multiplies three 64-bit unsigned integers, returning false on overflow.
bool
SafeMultiply3U64(
    uint64_t a,
    uint64_t b,
    uint64_t c,
    uint64_t& outProduct
    ) noexcept;

/// Validates a VideoModeSpec against progressive SDR MVP rules, exact timing math, overflow, and pipeline rate.
bool
ValidateVideoModeSpec(
    const VideoModeSpec& spec,
    uint64_t maxPipelineRate
    ) noexcept;

/// Validates a DISPLAYCONFIG_VIDEO_SIGNAL_INFO for IDDCX_MONITOR_MODE (requires vSyncFreqDivider == 0
/// and exact match with an advertised MVP video mode).
bool
ValidateMonitorModeVideoSignalInfo(
    const DISPLAYCONFIG_VIDEO_SIGNAL_INFO& signalInfo,
    uint64_t maxPipelineRate
    ) noexcept;

/// Validates a DISPLAYCONFIG_VIDEO_SIGNAL_INFO for IDDCX_TARGET_MODE / IDDCX_PATH (requires
/// vSyncFreqDivider == 1 for 1:1 desktop updates and exact match with an advertised MVP video mode).
bool
ValidateTargetModeVideoSignalInfo(
    const DISPLAYCONFIG_VIDEO_SIGNAL_INFO& signalInfo,
    uint64_t maxPipelineRate
    ) noexcept;

/// Returns true if two VideoModeSpec entries represent the same resolution and refresh rate.
bool
AreEquivalentVideoModes(
    const VideoModeSpec& lhs,
    const VideoModeSpec& rhs
    ) noexcept;

/// Populates a DISPLAYCONFIG_VIDEO_SIGNAL_INFO for IDDCX_MONITOR_MODE (vSyncFreqDivider = 0).
bool
FillMonitorModeVideoSignalInfo(
    const VideoModeSpec& spec,
    DISPLAYCONFIG_VIDEO_SIGNAL_INFO& outSignalInfo
    ) noexcept;

/// Populates a DISPLAYCONFIG_VIDEO_SIGNAL_INFO for IDDCX_TARGET_MODE (vSyncFreqDivider = 1).
bool
FillTargetModeVideoSignalInfo(
    const VideoModeSpec& spec,
    DISPLAYCONFIG_VIDEO_SIGNAL_INFO& outSignalInfo
    ) noexcept;

/// Returns the canonical MVP video mode list (720p60 and 1080p60) and preferred index (1080p60),
/// verifying all entries against maxPipelineRate and ensuring no duplicates exist.
bool
GetSupportedMvpVideoModes(
    uint64_t maxPipelineRate,
    VideoModeSpec (&outModes)[kMaxSupportedVideoModes],
    uint32_t& outCount,
    uint32_t& outPreferredIndex
    ) noexcept;

/// Negotiates mode count/copy semantics for IddCx mode query callbacks.
ModeBufferNegotiationResult
NegotiateModeBuffer(
    uint32_t inputCount,
    bool hasOutputBuffer,
    uint64_t maxPipelineRate,
    VideoModeSpec* outModes
    ) noexcept;

} // namespace lumabridge::driver
