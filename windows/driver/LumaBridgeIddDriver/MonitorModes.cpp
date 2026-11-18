#include "MonitorModes.h"

#include <limits>

namespace lumabridge::driver {

namespace {

// CTA-861 VIC 4 (1280x720 @ 60 Hz progressive, 1650x750 total, 74.25 MHz pixel clock).
constexpr VideoModeSpec kMode720p60{
    1280,
    720,
    1650,
    750,
    60,
    1,
    45000,
    1,
    74250000ULL,
    1280ULL * 720ULL * 60ULL,
    DISPLAYCONFIG_SCANLINE_ORDERING_PROGRESSIVE,
    false};

// CTA-861 VIC 16 (1920x1080 @ 60 Hz progressive, 2200x1125 total, 148.50 MHz pixel clock).
constexpr VideoModeSpec kMode1080p60{
    1920,
    1080,
    2200,
    1125,
    60,
    1,
    67500,
    1,
    148500000ULL,
    1920ULL * 1080ULL * 60ULL,
    DISPLAYCONFIG_SCANLINE_ORDERING_PROGRESSIVE,
    true};

constexpr uint32_t kVideoStandardOther = 255; // D3DKMDT_VSS_OTHER

bool
IsSupportedMvpResolution(
    uint32_t width,
    uint32_t height
    ) noexcept
{
    return (width == 1280U && height == 720U) ||
           (width == 1920U && height == 1080U);
}

bool
MatchesExactModeTiming(
    const VideoModeSpec& lhs,
    const VideoModeSpec& rhs
    ) noexcept
{
    return lhs.ActiveWidth == rhs.ActiveWidth &&
           lhs.ActiveHeight == rhs.ActiveHeight &&
           lhs.TotalWidth == rhs.TotalWidth &&
           lhs.TotalHeight == rhs.TotalHeight &&
           lhs.VSyncNumerator == rhs.VSyncNumerator &&
           lhs.VSyncDenominator == rhs.VSyncDenominator &&
           lhs.HSyncNumerator == rhs.HSyncNumerator &&
           lhs.HSyncDenominator == rhs.HSyncDenominator &&
           lhs.PixelRateHz == rhs.PixelRateHz &&
           lhs.RequiredBandwidth == rhs.RequiredBandwidth &&
           lhs.ScanlineOrdering == rhs.ScanlineOrdering;
}

bool
MatchesAdvertisedMvpVideoMode(
    const VideoModeSpec& candidate,
    uint64_t maxPipelineRate
    ) noexcept
{
    VideoModeSpec advertised[kMaxSupportedVideoModes]{};
    uint32_t count = 0;
    uint32_t preferredIdx = kNoPreferredModeIndex;
    if (!GetSupportedMvpVideoModes(maxPipelineRate, advertised, count, preferredIdx))
    {
        return false;
    }

    for (uint32_t i = 0; i < count; ++i)
    {
        if (MatchesExactModeTiming(advertised[i], candidate))
        {
            return true;
        }
    }
    return false;
}

bool
ValidateSignalInfoForDivider(
    const DISPLAYCONFIG_VIDEO_SIGNAL_INFO& signalInfo,
    uint32_t expectedVSyncDivider,
    uint64_t maxPipelineRate
    ) noexcept
{
    if (signalInfo.vSyncFreq.Denominator == 0 || signalInfo.hSyncFreq.Denominator == 0)
    {
        return false;
    }

    if (signalInfo.AdditionalSignalInfo.vSyncFreqDivider != expectedVSyncDivider)
    {
        return false;
    }

    if (signalInfo.AdditionalSignalInfo.videoStandard != kVideoStandardOther)
    {
        return false;
    }

    const uint64_t refreshHz =
        static_cast<uint64_t>(signalInfo.vSyncFreq.Numerator) / signalInfo.vSyncFreq.Denominator;

    uint64_t requiredBandwidth = 0;
    if (!SafeMultiply3U64(
            signalInfo.activeSize.cx,
            signalInfo.activeSize.cy,
            refreshHz,
            requiredBandwidth))
    {
        return false;
    }

    VideoModeSpec spec{};
    spec.ActiveWidth = signalInfo.activeSize.cx;
    spec.ActiveHeight = signalInfo.activeSize.cy;
    spec.TotalWidth = signalInfo.totalSize.cx;
    spec.TotalHeight = signalInfo.totalSize.cy;
    spec.VSyncNumerator = signalInfo.vSyncFreq.Numerator;
    spec.VSyncDenominator = signalInfo.vSyncFreq.Denominator;
    spec.HSyncNumerator = signalInfo.hSyncFreq.Numerator;
    spec.HSyncDenominator = signalInfo.hSyncFreq.Denominator;
    spec.PixelRateHz = signalInfo.pixelRate;
    spec.RequiredBandwidth = requiredBandwidth;
    spec.ScanlineOrdering = signalInfo.scanLineOrdering;

    return ValidateVideoModeSpec(spec, maxPipelineRate) &&
           MatchesAdvertisedMvpVideoMode(spec, maxPipelineRate);
}

bool
FillSignalInfoWithDivider(
    const VideoModeSpec& spec,
    uint32_t vSyncDivider,
    DISPLAYCONFIG_VIDEO_SIGNAL_INFO& outSignalInfo
    ) noexcept
{
    if (!ValidateVideoModeSpec(spec, (std::numeric_limits<uint64_t>::max)()))
    {
        return false;
    }

    outSignalInfo = {};
    outSignalInfo.pixelRate = spec.PixelRateHz;
    outSignalInfo.hSyncFreq.Numerator = spec.HSyncNumerator;
    outSignalInfo.hSyncFreq.Denominator = spec.HSyncDenominator;
    outSignalInfo.vSyncFreq.Numerator = spec.VSyncNumerator;
    outSignalInfo.vSyncFreq.Denominator = spec.VSyncDenominator;
    outSignalInfo.activeSize.cx = spec.ActiveWidth;
    outSignalInfo.activeSize.cy = spec.ActiveHeight;
    outSignalInfo.totalSize.cx = spec.TotalWidth;
    outSignalInfo.totalSize.cy = spec.TotalHeight;
    outSignalInfo.AdditionalSignalInfo.videoStandard = kVideoStandardOther;
    outSignalInfo.AdditionalSignalInfo.vSyncFreqDivider = vSyncDivider;
    outSignalInfo.scanLineOrdering = spec.ScanlineOrdering;
    return true;
}

} // namespace

bool
SafeMultiplyU64(
    uint64_t a,
    uint64_t b,
    uint64_t& outProduct
    ) noexcept
{
    if (a == 0 || b == 0)
    {
        outProduct = 0;
        return true;
    }

    if (a > (std::numeric_limits<uint64_t>::max)() / b)
    {
        return false;
    }

    outProduct = a * b;
    return true;
}

bool
SafeMultiply3U64(
    uint64_t a,
    uint64_t b,
    uint64_t c,
    uint64_t& outProduct
    ) noexcept
{
    uint64_t partial = 0;
    if (!SafeMultiplyU64(a, b, partial))
    {
        return false;
    }

    return SafeMultiplyU64(partial, c, outProduct);
}

bool
ValidateVideoModeSpec(
    const VideoModeSpec& spec,
    uint64_t maxPipelineRate
    ) noexcept
{
    if (spec.ActiveWidth == 0 || spec.ActiveHeight == 0 ||
        spec.TotalWidth == 0 || spec.TotalHeight == 0)
    {
        return false;
    }

    if (spec.ActiveWidth > spec.TotalWidth || spec.ActiveHeight > spec.TotalHeight)
    {
        return false;
    }

    if (!IsSupportedMvpResolution(spec.ActiveWidth, spec.ActiveHeight))
    {
        return false;
    }

    if (spec.ScanlineOrdering != DISPLAYCONFIG_SCANLINE_ORDERING_PROGRESSIVE)
    {
        return false;
    }

    if (spec.VSyncDenominator == 0 || spec.HSyncDenominator == 0)
    {
        return false;
    }

    // MVP supports fixed 60 Hz SDR only.
    if (spec.VSyncNumerator == 0 ||
        (spec.VSyncNumerator % spec.VSyncDenominator) != 0 ||
        (spec.VSyncNumerator / spec.VSyncDenominator) != kDefaultRefreshRateHz)
    {
        return false;
    }

    const uint64_t refreshHz = spec.VSyncNumerator / spec.VSyncDenominator;

    uint64_t expectedPixelRate = 0;
    if (!SafeMultiply3U64(spec.TotalWidth, spec.TotalHeight, refreshHz, expectedPixelRate))
    {
        return false;
    }

    if (expectedPixelRate == 0 || spec.PixelRateHz != expectedPixelRate)
    {
        return false;
    }

    uint64_t expectedHSyncTotal = 0;
    if (!SafeMultiplyU64(spec.TotalHeight, refreshHz, expectedHSyncTotal))
    {
        return false;
    }

    if ((spec.HSyncNumerator % spec.HSyncDenominator) != 0 ||
        (spec.HSyncNumerator / spec.HSyncDenominator) != expectedHSyncTotal)
    {
        return false;
    }

    uint64_t expectedBandwidth = 0;
    if (!SafeMultiply3U64(spec.ActiveWidth, spec.ActiveHeight, refreshHz, expectedBandwidth))
    {
        return false;
    }

    if (spec.RequiredBandwidth != expectedBandwidth || spec.RequiredBandwidth > maxPipelineRate)
    {
        return false;
    }

    return true;
}

bool
ValidateMonitorModeVideoSignalInfo(
    const DISPLAYCONFIG_VIDEO_SIGNAL_INFO& signalInfo,
    uint64_t maxPipelineRate
    ) noexcept
{
    return ValidateSignalInfoForDivider(signalInfo, kMonitorModeVSyncDivider, maxPipelineRate);
}

bool
ValidateTargetModeVideoSignalInfo(
    const DISPLAYCONFIG_VIDEO_SIGNAL_INFO& signalInfo,
    uint64_t maxPipelineRate
    ) noexcept
{
    return ValidateSignalInfoForDivider(signalInfo, kTargetModeVSyncDivider, maxPipelineRate);
}

bool
AreEquivalentVideoModes(
    const VideoModeSpec& lhs,
    const VideoModeSpec& rhs
    ) noexcept
{
    if (lhs.VSyncDenominator == 0 || rhs.VSyncDenominator == 0)
    {
        return false;
    }

    const uint64_t lhsScaled = static_cast<uint64_t>(lhs.VSyncNumerator) * rhs.VSyncDenominator;
    const uint64_t rhsScaled = static_cast<uint64_t>(rhs.VSyncNumerator) * lhs.VSyncDenominator;

    return lhs.ActiveWidth == rhs.ActiveWidth &&
           lhs.ActiveHeight == rhs.ActiveHeight &&
           lhsScaled == rhsScaled;
}

bool
FillMonitorModeVideoSignalInfo(
    const VideoModeSpec& spec,
    DISPLAYCONFIG_VIDEO_SIGNAL_INFO& outSignalInfo
    ) noexcept
{
    return FillSignalInfoWithDivider(spec, kMonitorModeVSyncDivider, outSignalInfo);
}

bool
FillTargetModeVideoSignalInfo(
    const VideoModeSpec& spec,
    DISPLAYCONFIG_VIDEO_SIGNAL_INFO& outSignalInfo
    ) noexcept
{
    return FillSignalInfoWithDivider(spec, kTargetModeVSyncDivider, outSignalInfo);
}

bool
GetSupportedMvpVideoModes(
    uint64_t maxPipelineRate,
    VideoModeSpec (&outModes)[kMaxSupportedVideoModes],
    uint32_t& outCount,
    uint32_t& outPreferredIndex
    ) noexcept
{
    outCount = 0;
    outPreferredIndex = kNoPreferredModeIndex;

    const VideoModeSpec candidates[kMaxSupportedVideoModes] = {kMode720p60, kMode1080p60};
    for (uint32_t i = 0; i < kMaxSupportedVideoModes; ++i)
    {
        if (!ValidateVideoModeSpec(candidates[i], maxPipelineRate))
        {
            continue;
        }

        bool duplicate = false;
        for (uint32_t existing = 0; existing < outCount; ++existing)
        {
            if (AreEquivalentVideoModes(outModes[existing], candidates[i]))
            {
                duplicate = true;
                break;
            }
        }

        if (duplicate)
        {
            continue;
        }

        outModes[outCount] = candidates[i];
        if (candidates[i].IsPreferred)
        {
            outPreferredIndex = outCount;
        }
        ++outCount;
    }

    return outCount > 0;
}

ModeBufferNegotiationResult
NegotiateModeBuffer(
    uint32_t inputCount,
    bool hasOutputBuffer,
    uint64_t maxPipelineRate,
    VideoModeSpec* outModes
    ) noexcept
{
    ModeBufferNegotiationResult result{};

    if (inputCount > 0 && (!hasOutputBuffer || outModes == nullptr))
    {
        result.Status = STATUS_INVALID_PARAMETER;
        return result;
    }

    VideoModeSpec supportedModes[kMaxSupportedVideoModes]{};
    uint32_t supportedCount = 0;
    uint32_t preferredIndex = kNoPreferredModeIndex;
    if (!GetSupportedMvpVideoModes(maxPipelineRate, supportedModes, supportedCount, preferredIndex))
    {
        result.Status = STATUS_INSUFFICIENT_RESOURCES;
        return result;
    }

    // Preliminary count query: IddCx passes InputCount == 0 (with or without a NULL buffer).
    if (inputCount == 0)
    {
        result.OutputCount = supportedCount;
        result.PreferredIndex = preferredIndex;
        result.Status = STATUS_SUCCESS;
        return result;
    }

    if (inputCount < supportedCount)
    {
        result.OutputCount = supportedCount;
        result.PreferredIndex = kNoPreferredModeIndex;
        result.Status = STATUS_BUFFER_TOO_SMALL;
        return result;
    }

    for (uint32_t i = 0; i < supportedCount; ++i)
    {
        outModes[i] = supportedModes[i];
    }

    result.OutputCount = supportedCount;
    result.PreferredIndex = preferredIndex;
    result.Status = STATUS_SUCCESS;
    return result;
}

} // namespace lumabridge::driver
