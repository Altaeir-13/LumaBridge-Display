#include "../LumaBridgeIddDriver/MonitorModes.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>

namespace {

int g_TestsRun = 0;
int g_TestsFailed = 0;

void
CheckCondition(
    bool condition,
    const char* expression,
    int line
    ) noexcept
{
    if (!condition)
    {
        ++g_TestsFailed;
        std::printf("[FAIL] line %d: %s\n", line, expression);
    }
}

#define EXPECT_TRUE(expr) CheckCondition((expr), #expr, __LINE__)
#define EXPECT_EQ(actual, expected) CheckCondition(((actual) == (expected)), #actual " == " #expected, __LINE__)

using namespace lumabridge::driver;

VideoModeSpec
MakeValid1080p60Spec() noexcept
{
    VideoModeSpec spec{};
    spec.ActiveWidth = 1920;
    spec.ActiveHeight = 1080;
    spec.TotalWidth = 2200;
    spec.TotalHeight = 1125;
    spec.VSyncNumerator = 60;
    spec.VSyncDenominator = 1;
    spec.HSyncNumerator = 67500;
    spec.HSyncDenominator = 1;
    spec.PixelRateHz = 148500000ULL;
    spec.RequiredBandwidth = 1920ULL * 1080ULL * 60ULL;
    spec.ScanlineOrdering = DISPLAYCONFIG_SCANLINE_ORDERING_PROGRESSIVE;
    spec.IsPreferred = true;
    return spec;
}

void
TestValidate720p60Mode()
{
    VideoModeSpec modes[kMaxSupportedVideoModes]{};
    uint32_t count = 0;
    uint32_t preferredIdx = kNoPreferredModeIndex;

    EXPECT_TRUE(GetSupportedMvpVideoModes(kMaxDisplayPipelineRate, modes, count, preferredIdx));
    EXPECT_EQ(count, static_cast<uint32_t>(2));

    const VideoModeSpec& m = modes[0];
    EXPECT_EQ(m.ActiveWidth, static_cast<uint32_t>(1280));
    EXPECT_EQ(m.ActiveHeight, static_cast<uint32_t>(720));
    EXPECT_EQ(m.TotalWidth, static_cast<uint32_t>(1650));
    EXPECT_EQ(m.TotalHeight, static_cast<uint32_t>(750));
    EXPECT_EQ(m.VSyncNumerator, static_cast<uint32_t>(60));
    EXPECT_EQ(m.VSyncDenominator, static_cast<uint32_t>(1));
    EXPECT_EQ(m.HSyncNumerator, static_cast<uint32_t>(45000));
    EXPECT_EQ(m.HSyncDenominator, static_cast<uint32_t>(1));
    EXPECT_EQ(m.PixelRateHz, 74250000ULL);
    EXPECT_EQ(m.RequiredBandwidth, 1280ULL * 720ULL * 60ULL);
    EXPECT_EQ(m.ScanlineOrdering, DISPLAYCONFIG_SCANLINE_ORDERING_PROGRESSIVE);
    EXPECT_TRUE(!m.IsPreferred);
    EXPECT_TRUE(ValidateVideoModeSpec(m, kMaxDisplayPipelineRate));
}

void
TestValidate1080p60Mode()
{
    VideoModeSpec modes[kMaxSupportedVideoModes]{};
    uint32_t count = 0;
    uint32_t preferredIdx = kNoPreferredModeIndex;

    EXPECT_TRUE(GetSupportedMvpVideoModes(kMaxDisplayPipelineRate, modes, count, preferredIdx));
    EXPECT_EQ(count, static_cast<uint32_t>(2));

    const VideoModeSpec& m = modes[1];
    EXPECT_EQ(m.ActiveWidth, static_cast<uint32_t>(1920));
    EXPECT_EQ(m.ActiveHeight, static_cast<uint32_t>(1080));
    EXPECT_EQ(m.TotalWidth, static_cast<uint32_t>(2200));
    EXPECT_EQ(m.TotalHeight, static_cast<uint32_t>(1125));
    EXPECT_EQ(m.VSyncNumerator, static_cast<uint32_t>(60));
    EXPECT_EQ(m.VSyncDenominator, static_cast<uint32_t>(1));
    EXPECT_EQ(m.HSyncNumerator, static_cast<uint32_t>(67500));
    EXPECT_EQ(m.HSyncDenominator, static_cast<uint32_t>(1));
    EXPECT_EQ(m.PixelRateHz, 148500000ULL);
    EXPECT_EQ(m.RequiredBandwidth, 1920ULL * 1080ULL * 60ULL);
    EXPECT_EQ(m.ScanlineOrdering, DISPLAYCONFIG_SCANLINE_ORDERING_PROGRESSIVE);
    EXPECT_TRUE(m.IsPreferred);
    EXPECT_TRUE(ValidateVideoModeSpec(m, kMaxDisplayPipelineRate));
}

void
TestPreferredModeIs1080p60()
{
    VideoModeSpec modes[kMaxSupportedVideoModes]{};
    uint32_t count = 0;
    uint32_t preferredIdx = kNoPreferredModeIndex;

    EXPECT_TRUE(GetSupportedMvpVideoModes(kMaxDisplayPipelineRate, modes, count, preferredIdx));
    EXPECT_EQ(preferredIdx, static_cast<uint32_t>(1));
    EXPECT_EQ(modes[preferredIdx].ActiveWidth, static_cast<uint32_t>(1920));
    EXPECT_EQ(modes[preferredIdx].ActiveHeight, static_cast<uint32_t>(1080));
}

void
TestFrequencyAndPixelRateCalculations()
{
    VideoModeSpec spec = MakeValid1080p60Spec();

    DISPLAYCONFIG_VIDEO_SIGNAL_INFO monitorSignalInfo{};
    EXPECT_TRUE(FillMonitorModeVideoSignalInfo(spec, monitorSignalInfo));
    EXPECT_EQ(monitorSignalInfo.pixelRate, 2200ULL * 1125ULL * 60ULL);
    EXPECT_EQ(monitorSignalInfo.hSyncFreq.Numerator, static_cast<UINT32>(1125U * 60U));
    EXPECT_EQ(monitorSignalInfo.hSyncFreq.Denominator, static_cast<UINT32>(1U));
    EXPECT_EQ(monitorSignalInfo.vSyncFreq.Numerator, static_cast<UINT32>(60U));
    EXPECT_EQ(monitorSignalInfo.vSyncFreq.Denominator, static_cast<UINT32>(1U));
    EXPECT_EQ(monitorSignalInfo.AdditionalSignalInfo.vSyncFreqDivider, static_cast<UINT32>(0U));
    EXPECT_TRUE(ValidateMonitorModeVideoSignalInfo(monitorSignalInfo, kMaxDisplayPipelineRate));

    DISPLAYCONFIG_VIDEO_SIGNAL_INFO targetSignalInfo{};
    EXPECT_TRUE(FillTargetModeVideoSignalInfo(spec, targetSignalInfo));
    EXPECT_EQ(targetSignalInfo.AdditionalSignalInfo.vSyncFreqDivider, static_cast<UINT32>(1U));
    EXPECT_TRUE(ValidateTargetModeVideoSignalInfo(targetSignalInfo, kMaxDisplayPipelineRate));

    // Corrupt pixelRate so it no longer matches totalWidth * totalHeight * refreshHz.
    VideoModeSpec badPixelRate = spec;
    badPixelRate.PixelRateHz += 1;
    EXPECT_TRUE(!ValidateVideoModeSpec(badPixelRate, kMaxDisplayPipelineRate));

    // Corrupt hSyncFreq so it no longer matches totalHeight * refreshHz.
    VideoModeSpec badHSync = spec;
    badHSync.HSyncNumerator += 1;
    EXPECT_TRUE(!ValidateVideoModeSpec(badHSync, kMaxDisplayPipelineRate));
}

void
TestRejectsInvalidAndUnsupportedResolutions()
{
    VideoModeSpec spec = MakeValid1080p60Spec();

    // Zero active dimensions.
    {
        VideoModeSpec bad = spec;
        bad.ActiveWidth = 0;
        EXPECT_TRUE(!ValidateVideoModeSpec(bad, kMaxDisplayPipelineRate));
    }
    {
        VideoModeSpec bad = spec;
        bad.ActiveHeight = 0;
        EXPECT_TRUE(!ValidateVideoModeSpec(bad, kMaxDisplayPipelineRate));
    }

    // Active dimensions exceeding total dimensions.
    {
        VideoModeSpec bad = spec;
        bad.TotalWidth = bad.ActiveWidth - 1;
        EXPECT_TRUE(!ValidateVideoModeSpec(bad, kMaxDisplayPipelineRate));
    }
    {
        VideoModeSpec bad = spec;
        bad.TotalHeight = bad.ActiveHeight - 1;
        EXPECT_TRUE(!ValidateVideoModeSpec(bad, kMaxDisplayPipelineRate));
    }

    // Unsupported resolution (2560x1440 is intentionally deferred out of MVP required modes).
    {
        VideoModeSpec bad = spec;
        bad.ActiveWidth = 2560;
        bad.ActiveHeight = 1440;
        bad.TotalWidth = 2720;
        bad.TotalHeight = 1481;
        bad.HSyncNumerator = 1481 * 60;
        bad.PixelRateHz = 2720ULL * 1481ULL * 60ULL;
        bad.RequiredBandwidth = 2560ULL * 1440ULL * 60ULL;
        EXPECT_TRUE(!ValidateVideoModeSpec(bad, kMaxDisplayPipelineRate));
    }
}

void
TestRejectsInvalidRefreshRatesAndScanlineOrdering()
{
    VideoModeSpec spec = MakeValid1080p60Spec();

    // 0 Hz and 30 Hz and 120 Hz rejected in MVP.
    const uint32_t badRates[] = {0U, 30U, 120U};
    for (uint32_t badHz : badRates)
    {
        VideoModeSpec bad = spec;
        bad.VSyncNumerator = badHz;
        bad.HSyncNumerator = bad.TotalHeight * badHz;
        bad.PixelRateHz = static_cast<uint64_t>(bad.TotalWidth) * bad.TotalHeight * badHz;
        bad.RequiredBandwidth = static_cast<uint64_t>(bad.ActiveWidth) * bad.ActiveHeight * badHz;
        EXPECT_TRUE(!ValidateVideoModeSpec(bad, kMaxDisplayPipelineRate));
    }

    // Zero denominator rejected.
    {
        VideoModeSpec bad = spec;
        bad.VSyncDenominator = 0;
        EXPECT_TRUE(!ValidateVideoModeSpec(bad, kMaxDisplayPipelineRate));
    }

    // Interlaced scanline ordering rejected.
    {
        VideoModeSpec bad = spec;
        bad.ScanlineOrdering = DISPLAYCONFIG_SCANLINE_ORDERING_INTERLACED;
        EXPECT_TRUE(!ValidateVideoModeSpec(bad, kMaxDisplayPipelineRate));
    }

    // Non-zero vSyncFreqDivider in IDDCX_MONITOR_MODE rejected; divider != 1 in IDDCX_TARGET_MODE rejected.
    {
        DISPLAYCONFIG_VIDEO_SIGNAL_INFO monitorSignalInfo{};
        EXPECT_TRUE(FillMonitorModeVideoSignalInfo(spec, monitorSignalInfo));
        monitorSignalInfo.AdditionalSignalInfo.vSyncFreqDivider = 1;
        EXPECT_TRUE(!ValidateMonitorModeVideoSignalInfo(monitorSignalInfo, kMaxDisplayPipelineRate));

        DISPLAYCONFIG_VIDEO_SIGNAL_INFO targetSignalInfo{};
        EXPECT_TRUE(FillTargetModeVideoSignalInfo(spec, targetSignalInfo));
        targetSignalInfo.AdditionalSignalInfo.vSyncFreqDivider = 2;
        EXPECT_TRUE(!ValidateTargetModeVideoSignalInfo(targetSignalInfo, kMaxDisplayPipelineRate));
    }
}

void
TestEnforcesAdapterPipelineBandwidthLimit()
{
    const uint64_t rate720p60 = 1280ULL * 720ULL * 60ULL;
    const uint64_t rate1080p60 = 1920ULL * 1080ULL * 60ULL;

    // Limit below 1080p60 but >= 720p60 should yield only 720p60 with no preferred 1080p60.
    {
        VideoModeSpec modes[kMaxSupportedVideoModes]{};
        uint32_t count = 0;
        uint32_t preferredIdx = kNoPreferredModeIndex;
        EXPECT_TRUE(GetSupportedMvpVideoModes(rate1080p60 - 1, modes, count, preferredIdx));
        EXPECT_EQ(count, static_cast<uint32_t>(1));
        EXPECT_EQ(modes[0].ActiveWidth, static_cast<uint32_t>(1280));
        EXPECT_EQ(preferredIdx, kNoPreferredModeIndex);
    }

    // Limit below 720p60 should fail to produce any mode.
    {
        VideoModeSpec modes[kMaxSupportedVideoModes]{};
        uint32_t count = 0;
        uint32_t preferredIdx = kNoPreferredModeIndex;
        EXPECT_TRUE(!GetSupportedMvpVideoModes(rate720p60 - 1, modes, count, preferredIdx));
        EXPECT_EQ(count, static_cast<uint32_t>(0));
    }
}

void
TestNegotiateModeBufferCountQueryAndInsufficientBuffer()
{
    // Preliminary count query with nullptr buffer and 0 input count.
    {
        const auto res = NegotiateModeBuffer(0, false, kMaxDisplayPipelineRate, nullptr);
        EXPECT_EQ(res.Status, STATUS_SUCCESS);
        EXPECT_EQ(res.OutputCount, static_cast<uint32_t>(2));
        EXPECT_EQ(res.PreferredIndex, static_cast<uint32_t>(1));
    }

    // Preliminary count query with non-null buffer but 0 input count.
    {
        VideoModeSpec modes[kMaxSupportedVideoModes]{};
        const auto res = NegotiateModeBuffer(0, true, kMaxDisplayPipelineRate, modes);
        EXPECT_EQ(res.Status, STATUS_SUCCESS);
        EXPECT_EQ(res.OutputCount, static_cast<uint32_t>(2));
        EXPECT_EQ(res.PreferredIndex, static_cast<uint32_t>(1));
    }

    // Insufficient buffer (1 < 2) must return STATUS_BUFFER_TOO_SMALL and not overwrite output.
    {
        VideoModeSpec modes[kMaxSupportedVideoModes]{};
        modes[0].ActiveWidth = 0xDEADBEEFU;
        const auto res = NegotiateModeBuffer(1, true, kMaxDisplayPipelineRate, modes);
        EXPECT_EQ(res.Status, STATUS_BUFFER_TOO_SMALL);
        EXPECT_EQ(res.OutputCount, static_cast<uint32_t>(2));
        EXPECT_EQ(res.PreferredIndex, kNoPreferredModeIndex);
        EXPECT_EQ(modes[0].ActiveWidth, static_cast<uint32_t>(0xDEADBEEFU));
    }

    // Non-zero input count with nullptr buffer must return STATUS_INVALID_PARAMETER.
    {
        const auto res = NegotiateModeBuffer(2, false, kMaxDisplayPipelineRate, nullptr);
        EXPECT_EQ(res.Status, STATUS_INVALID_PARAMETER);
        EXPECT_EQ(res.OutputCount, static_cast<uint32_t>(0));
        EXPECT_EQ(res.PreferredIndex, kNoPreferredModeIndex);
    }

    // Exact buffer size (2) succeeds and populates modes.
    {
        VideoModeSpec modes[kMaxSupportedVideoModes]{};
        const auto res = NegotiateModeBuffer(2, true, kMaxDisplayPipelineRate, modes);
        EXPECT_EQ(res.Status, STATUS_SUCCESS);
        EXPECT_EQ(res.OutputCount, static_cast<uint32_t>(2));
        EXPECT_EQ(res.PreferredIndex, static_cast<uint32_t>(1));
        EXPECT_EQ(modes[0].ActiveWidth, static_cast<uint32_t>(1280));
        EXPECT_EQ(modes[1].ActiveWidth, static_cast<uint32_t>(1920));
    }
}

void
TestRejectsArithmeticOverflowInTimingAndBandwidth()
{
    uint64_t product = 0;
    const uint64_t u64Max = (std::numeric_limits<uint64_t>::max)();
    EXPECT_TRUE(!SafeMultiplyU64(u64Max, 2ULL, product));
    EXPECT_TRUE(!SafeMultiply3U64(0x10000000ULL, 0x10000000ULL, 0x1000ULL, product));
    EXPECT_TRUE(SafeMultiply3U64(2200ULL, 1125ULL, 60ULL, product));
    EXPECT_EQ(product, 148500000ULL);

    DISPLAYCONFIG_VIDEO_SIGNAL_INFO overflowSignal{};
    overflowSignal.activeSize.cx = 1920;
    overflowSignal.activeSize.cy = 1080;
    overflowSignal.totalSize.cx = 0xFFFFFFFFU;
    overflowSignal.totalSize.cy = 0xFFFFFFFFU;
    overflowSignal.vSyncFreq.Numerator = 60;
    overflowSignal.vSyncFreq.Denominator = 1;
    overflowSignal.hSyncFreq.Numerator = 67500;
    overflowSignal.hSyncFreq.Denominator = 1;
    overflowSignal.AdditionalSignalInfo.videoStandard = 255;
    overflowSignal.AdditionalSignalInfo.vSyncFreqDivider = 1;
    overflowSignal.scanLineOrdering = DISPLAYCONFIG_SCANLINE_ORDERING_PROGRESSIVE;
    EXPECT_TRUE(!ValidateTargetModeVideoSignalInfo(overflowSignal, u64Max));
}

void
TestSupportedModesContainNoDuplicates()
{
    VideoModeSpec modes[kMaxSupportedVideoModes]{};
    uint32_t count = 0;
    uint32_t preferredIdx = kNoPreferredModeIndex;

    EXPECT_TRUE(GetSupportedMvpVideoModes(kMaxDisplayPipelineRate, modes, count, preferredIdx));
    EXPECT_EQ(count, static_cast<uint32_t>(2));

    for (uint32_t i = 0; i < count; ++i)
    {
        for (uint32_t j = i + 1; j < count; ++j)
        {
            EXPECT_TRUE(!AreEquivalentVideoModes(modes[i], modes[j]));
        }
    }
}

void
TestMonitorAndTargetModesEnforceDistinctVSyncDividers()
{
    VideoModeSpec modes[kMaxSupportedVideoModes]{};
    uint32_t count = 0;
    uint32_t preferredIdx = kNoPreferredModeIndex;
    EXPECT_TRUE(GetSupportedMvpVideoModes(kMaxDisplayPipelineRate, modes, count, preferredIdx));
    EXPECT_EQ(count, static_cast<uint32_t>(2));

    for (uint32_t i = 0; i < count; ++i)
    {
        DISPLAYCONFIG_VIDEO_SIGNAL_INFO monitorSignal{};
        EXPECT_TRUE(FillMonitorModeVideoSignalInfo(modes[i], monitorSignal));
        EXPECT_EQ(monitorSignal.AdditionalSignalInfo.vSyncFreqDivider, static_cast<UINT32>(0U));
        EXPECT_TRUE(ValidateMonitorModeVideoSignalInfo(monitorSignal, kMaxDisplayPipelineRate));
        EXPECT_TRUE(!ValidateTargetModeVideoSignalInfo(monitorSignal, kMaxDisplayPipelineRate));

        DISPLAYCONFIG_VIDEO_SIGNAL_INFO targetSignal{};
        EXPECT_TRUE(FillTargetModeVideoSignalInfo(modes[i], targetSignal));
        EXPECT_EQ(targetSignal.AdditionalSignalInfo.vSyncFreqDivider, static_cast<UINT32>(1U));
        EXPECT_TRUE(ValidateTargetModeVideoSignalInfo(targetSignal, kMaxDisplayPipelineRate));
        EXPECT_TRUE(!ValidateMonitorModeVideoSignalInfo(targetSignal, kMaxDisplayPipelineRate));
    }
}

void
TestCommitValidationRejectsUnadvertisedTimingsWithMatchingActiveResolution()
{
    // Active resolution matches 1080p60, but total timings (2000x1100) do not match CTA-861 VIC 16 (2200x1125).
    VideoModeSpec unadvertised{};
    unadvertised.ActiveWidth = 1920;
    unadvertised.ActiveHeight = 1080;
    unadvertised.TotalWidth = 2000;
    unadvertised.TotalHeight = 1100;
    unadvertised.VSyncNumerator = 60;
    unadvertised.VSyncDenominator = 1;
    unadvertised.HSyncNumerator = 1100U * 60U;
    unadvertised.HSyncDenominator = 1;
    unadvertised.PixelRateHz = 2000ULL * 1100ULL * 60ULL;
    unadvertised.RequiredBandwidth = 1920ULL * 1080ULL * 60ULL;
    unadvertised.ScanlineOrdering = DISPLAYCONFIG_SCANLINE_ORDERING_PROGRESSIVE;

    EXPECT_TRUE(ValidateVideoModeSpec(unadvertised, kMaxDisplayPipelineRate));

    DISPLAYCONFIG_VIDEO_SIGNAL_INFO targetSignal{};
    EXPECT_TRUE(FillTargetModeVideoSignalInfo(unadvertised, targetSignal));
    EXPECT_TRUE(!ValidateTargetModeVideoSignalInfo(targetSignal, kMaxDisplayPipelineRate));

    DISPLAYCONFIG_VIDEO_SIGNAL_INFO monitorSignal{};
    EXPECT_TRUE(FillMonitorModeVideoSignalInfo(unadvertised, monitorSignal));
    EXPECT_TRUE(!ValidateMonitorModeVideoSignalInfo(monitorSignal, kMaxDisplayPipelineRate));
}

template <typename Fn>
void
RunTest(
    const char* name,
    Fn fn
    )
{
    ++g_TestsRun;
    const int failuresBefore = g_TestsFailed;
    fn();
    if (g_TestsFailed == failuresBefore)
    {
        std::printf("[PASS] %s\n", name);
    }
    else
    {
        std::printf("[FAIL] %s\n", name);
    }
}

} // namespace

int
main()
{
    RunTest("Validate720p60Mode", TestValidate720p60Mode);
    RunTest("Validate1080p60Mode", TestValidate1080p60Mode);
    RunTest("PreferredModeIs1080p60", TestPreferredModeIs1080p60);
    RunTest("FrequencyAndPixelRateCalculations", TestFrequencyAndPixelRateCalculations);
    RunTest("RejectsInvalidAndUnsupportedResolutions", TestRejectsInvalidAndUnsupportedResolutions);
    RunTest("RejectsInvalidRefreshRatesAndScanlineOrdering", TestRejectsInvalidRefreshRatesAndScanlineOrdering);
    RunTest("EnforcesAdapterPipelineBandwidthLimit", TestEnforcesAdapterPipelineBandwidthLimit);
    RunTest("NegotiateModeBufferCountQueryAndInsufficientBuffer", TestNegotiateModeBufferCountQueryAndInsufficientBuffer);
    RunTest("RejectsArithmeticOverflowInTimingAndBandwidth", TestRejectsArithmeticOverflowInTimingAndBandwidth);
    RunTest("SupportedModesContainNoDuplicates", TestSupportedModesContainNoDuplicates);
    RunTest("MonitorAndTargetModesEnforceDistinctVSyncDividers", TestMonitorAndTargetModesEnforceDistinctVSyncDividers);
    RunTest("CommitValidationRejectsUnadvertisedTimingsWithMatchingActiveResolution", TestCommitValidationRejectsUnadvertisedTimingsWithMatchingActiveResolution);

    std::printf("Summary: %d tests run, %d assertion failures.\n", g_TestsRun, g_TestsFailed);
    return (g_TestsFailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
