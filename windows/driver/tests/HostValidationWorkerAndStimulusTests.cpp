#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>
#include <d3d11.h>
#include <dxgi1_4.h>
#include <mfapi.h>
#include <mferror.h>

#include "../../host/AsyncH264ValidationWorker.h"
#include "../../host/FrameConsumer.h"
#include "../../host/H264BitstreamValidator.h"
#include "../../host/HostGateEvaluator.h"
#include "../../host/NvencH264Encoder.h"
#include "../../host/VirtualDisplayStimulus.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <mutex>
#include <new>
#include <string>
#include <thread>
#include <vector>

using namespace lumabridge::host;

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

EncodedFramePacket
MakeSyntheticAnnexBPacket(
    uint64_t seq,
    uint32_t presNum,
    uint32_t width,
    uint32_t height,
    bool isKey,
    uint8_t markerByte = 0xAAU
    )
{
    EncodedFramePacket pkt{};
    pkt.FrameSequence = seq;
    pkt.PresentationFrameNumber = presNum;
    pkt.Width = width;
    pkt.Height = height;
    pkt.IsKeyFrame = isKey;
    pkt.QpcFrequency = 10000000ULL;
    // Valid Annex-B SPS (NAL 7), PPS (NAL 8), and IDR (NAL 5) or P-slice (NAL 1) + unique payload marker.
    pkt.Bitstream = {
        0x00U, 0x00U, 0x00U, 0x01U, 0x67U, 0x42U, 0xC0U, 0x28U,
        0x00U, 0x00U, 0x00U, 0x01U, 0x68U, 0xCEU, 0x38U, 0x80U,
        0x00U, 0x00U, 0x00U, 0x01U, static_cast<uint8_t>(isKey ? 0x65U : 0x41U),
        0x88U, static_cast<uint8_t>(seq & 0xFFU), markerByte
    };
    return pkt;
}

class MockH264Decoder final : public IH264Decoder
{
public:
    HRESULT NextInitHr{S_OK};
    HRESULT SecondInitHr{S_OK};
    HRESULT NextDecodeHr{S_OK};
    HRESULT NextDrainHr{S_OK};
    bool ReturnTailOnDrain{false};
    uint32_t DecodeDelayMs{0U};
    uint32_t DrainDelayMs{0U};
    bool BlockOnFirstDecode{false};

    mutable std::mutex Mutex{};
    std::condition_variable BlockCv{};
    bool ReleaseBlockedDecode{false};
    uint32_t InitCallCount{0U};
    uint32_t ShutdownCallCount{0U};
    std::vector<uint32_t> ObservedFrameNumbers{};
    std::vector<uint8_t> ObservedMarkerBytes{};
    bool ProduceEmptyFrameOnly{false};

    void UnblockDecode() noexcept
    {
        std::lock_guard<std::mutex> lock(Mutex);
        ReleaseBlockedDecode = true;
        BlockCv.notify_all();
    }

    HRESULT Initialize(
        uint32_t width,
        uint32_t height,
        uint32_t targetFps = 60U
        ) noexcept override
    {
        (void)width;
        (void)height;
        (void)targetFps;
        std::lock_guard<std::mutex> lock(Mutex);
        ++InitCallCount;
        const DWORD tid = GetCurrentThreadId();
        m_lifecycle.OwnerThreadId = tid;
        ++m_lifecycle.ComInitCount;
        m_lifecycle.ComInitThreadId = tid;
        ++m_lifecycle.MfStartupCount;

        const HRESULT hr = (InitCallCount == 1U) ? NextInitHr : SecondInitHr;
        if (SUCCEEDED(hr))
        {
            m_initialized = true;
        }
        return hr;
    }

    void Shutdown() noexcept override
    {
        std::lock_guard<std::mutex> lock(Mutex);
        const bool hadActive = (m_lifecycle.OwnerThreadId != 0U) || m_initialized ||
                               (m_lifecycle.ComInitCount > m_lifecycle.ComUninitCount) ||
                               (m_lifecycle.MfStartupCount > m_lifecycle.MfShutdownCount);
        const DWORD tid = GetCurrentThreadId();
        if (m_lifecycle.MfShutdownCount < m_lifecycle.MfStartupCount)
        {
            ++m_lifecycle.MfShutdownCount;
        }
        if (m_lifecycle.ComUninitCount < m_lifecycle.ComInitCount)
        {
            ++m_lifecycle.ComUninitCount;
            m_lifecycle.ComUninitThreadId = tid;
            if (m_lifecycle.ComInitThreadId != 0U && tid != m_lifecycle.ComInitThreadId)
            {
                m_lifecycle.ComThreadAffinityPreserved = false;
            }
        }
        if (hadActive)
        {
            ++ShutdownCallCount;
            m_lifecycle.ShutdownThreadId = tid;
            if (m_lifecycle.OwnerThreadId != 0U && tid != m_lifecycle.OwnerThreadId)
            {
                m_lifecycle.ShutdownThreadAffinityPreserved = false;
            }
        }
        m_initialized = false;
    }

    bool IsInitialized() const noexcept override
    {
        std::lock_guard<std::mutex> lock(Mutex);
        return m_initialized;
    }

    std::string GetDecoderName() const noexcept override
    {
        return "MockH264Decoder";
    }

    HRESULT DecodePacket(
        const uint8_t* annexBBytes,
        size_t annexBSizeBytes,
        uint32_t presentationFrameNumber,
        std::vector<DecodedNv12Frame>& outDecodedFrames
        ) noexcept override
    {
        outDecodedFrames.clear();
        uint32_t delayMs = 0U;
        HRESULT hr = S_OK;
        bool shouldBlock = false;
        {
            std::unique_lock<std::mutex> lock(Mutex);
            ObservedFrameNumbers.push_back(presentationFrameNumber);
            if (annexBBytes != nullptr && annexBSizeBytes > 0U)
            {
                ObservedMarkerBytes.push_back(annexBBytes[annexBSizeBytes - 1U]);
            }
            delayMs = DecodeDelayMs;
            hr = NextDecodeHr;
            shouldBlock = BlockOnFirstDecode && !ReleaseBlockedDecode;
            if (shouldBlock)
            {
                BlockCv.wait(lock, [this]() { return ReleaseBlockedDecode; });
                delayMs = DecodeDelayMs;
                hr = NextDecodeHr;
            }
        }

        if (delayMs > 0U)
        {
            Sleep(delayMs);
        }
        if (FAILED(hr))
        {
            return hr;
        }

        DecodedNv12Frame f{};
        f.Width = 1920U;
        f.Height = 1080U;
        f.FrameNumber = presentationFrameNumber;
        if (!ProduceEmptyFrameOnly)
        {
            f.StrideBytes = 1920U;
        }
        outDecodedFrames.push_back(std::move(f));
        return S_OK;
    }

    HRESULT Drain(
        std::vector<DecodedNv12Frame>& outDecodedFrames
        ) noexcept override
    {
        outDecodedFrames.clear();
        uint32_t delayMs = 0U;
        HRESULT hr = S_OK;
        bool addTail = false;
        {
            std::lock_guard<std::mutex> lock(Mutex);
            delayMs = DrainDelayMs;
            hr = NextDrainHr;
            addTail = ReturnTailOnDrain;
        }
        if (delayMs > 0U)
        {
            Sleep(delayMs);
        }
        if (FAILED(hr))
        {
            return hr;
        }
        if (addTail)
        {
            DecodedNv12Frame f{};
            f.Width = 1920U;
            f.Height = 1080U;
            f.FrameNumber = 9999U;
            outDecodedFrames.push_back(std::move(f));
        }
        return S_OK;
    }

    DecoderLifecycleDiagnostics GetLifecycleDiagnostics() const noexcept override
    {
        std::lock_guard<std::mutex> lock(Mutex);
        return m_lifecycle;
    }

private:
    bool m_initialized{false};
    DecoderLifecycleDiagnostics m_lifecycle{};
};

class ThrowingWorkerHooks final : public IH264WorkerHooks
{
public:
    bool ThrowBadAllocOnEnqueue{true};

    void OnBeforeQueuePush() override
    {
        if (ThrowBadAllocOnEnqueue)
        {
            throw std::bad_alloc();
        }
    }
};

class MockStimulusPresenter final : public IStimulusPresenterBackend
{
public:
    std::deque<HRESULT> InitResults{};
    std::deque<HRESULT> PresentResults{};
    HRESULT DefaultInitResult{S_OK};
    HRESULT DefaultPresentResult{S_OK};
    bool SlowPresent1200Us{true};
    uint32_t InitCallCount{0U};
    uint32_t PresentCallCount{0U};
    uint32_t ResetCallCount{0U};
    std::mutex Mutex{};

    HRESULT Initialize(
        HWND hwnd,
        uint32_t width,
        uint32_t height,
        HANDLE& outWaitableObject,
        std::string& outError
        ) noexcept override
    {
        (void)hwnd;
        (void)width;
        (void)height;
        outWaitableObject = nullptr;
        outError.clear();
        std::lock_guard<std::mutex> lock(Mutex);
        ++InitCallCount;
        HRESULT hr = DefaultInitResult;
        if (!InitResults.empty())
        {
            hr = InitResults.front();
            InitResults.pop_front();
        }
        if (FAILED(hr))
        {
            outError = "Mock DXGI Initialize injected failure.";
        }
        return hr;
    }

    HRESULT PresentFrame(
        uint64_t tickSeq,
        uint32_t width,
        uint32_t height,
        bool occludedTestOnly,
        bool& outRenderedFrame
        ) noexcept override
    {
        (void)tickSeq;
        (void)width;
        (void)height;
        (void)occludedTestOnly;
        if (SlowPresent1200Us)
        {
            Sleep(2U);
        }
        std::lock_guard<std::mutex> lock(Mutex);
        ++PresentCallCount;
        HRESULT hr = DefaultPresentResult;
        if (!PresentResults.empty())
        {
            hr = PresentResults.front();
            PresentResults.pop_front();
        }
        outRenderedFrame = SUCCEEDED(hr) && (hr != DXGI_STATUS_OCCLUDED);
        return hr;
    }

    void Reset() noexcept override
    {
        std::lock_guard<std::mutex> lock(Mutex);
        ++ResetCallCount;
    }
};

bool
StatsEqual(
    const LatencySummaryStats& a,
    const LatencySummaryStats& b
    ) noexcept
{
    return a.Available == b.Available &&
           a.PercentilesAvailable == b.PercentilesAvailable &&
           a.PercentilesAreEstimated == b.PercentilesAreEstimated &&
           a.PercentileMethod == b.PercentileMethod &&
           a.SampleCount == b.SampleCount &&
           a.StoredSampleCount == b.StoredSampleCount &&
           a.SamplesTruncated == b.SamplesTruncated &&
           a.ReservoirSampled == b.ReservoirSampled &&
           a.MinUs == b.MinUs &&
           a.AvgUs == b.AvgUs &&
           a.MaxUs == b.MaxUs &&
           a.P50Us == b.P50Us &&
           a.P95Us == b.P95Us &&
           a.P99Us == b.P99Us &&
           a.LastUs == b.LastUs;
}

void
RunP0ANoPerPacketConsolidationAndFinalConsolidationOnly()
{
    MockH264Decoder mockDec;
    H264StreamValidationSession session(&mockDec);
    session.Configure(true, 60U, false);
    EXPECT_EQ(session.PrewarmDecoder(1920U, 1080U, 60U), S_OK);

    for (uint32_t i = 1U; i <= 120U; ++i)
    {
        const EncodedFramePacket pkt = MakeSyntheticAnnexBPacket(i, i, 1920U, 1080U, i == 1U);
        session.SubmitPacket(pkt);
        EXPECT_EQ(session.GetLatencyConsolidationCount(), 0ULL);
        const H264ValidationSummary mid = session.GetSummary();
        EXPECT_TRUE(!mid.MftDecodeLatencyUs.PercentilesAvailable);
        EXPECT_EQ(mid.MftDecodeLatencyUs.SampleCount, 0ULL);
    }

    session.Finish();
    EXPECT_EQ(session.GetLatencyConsolidationCount(), 1ULL);
    const H264ValidationSummary fin = session.GetSummary();
    EXPECT_TRUE(fin.Passed);
    EXPECT_TRUE(fin.MftDecodeLatencyUs.Available);
    EXPECT_TRUE(fin.MftDecodeLatencyUs.PercentilesAvailable);
    EXPECT_TRUE(!fin.MftDecodeLatencyUs.PercentilesAreEstimated);
    EXPECT_EQ(fin.MftDecodeLatencyUs.PercentileMethod, LatencyPercentileMethod::ExactPopulation);
    EXPECT_EQ(fin.MftDecodeLatencyUs.SampleCount, 120ULL);
    EXPECT_EQ(fin.MftDecodeLatencyUs.StoredSampleCount, 120ULL);
    EXPECT_TRUE(!fin.MftDecodeLatencyUs.SamplesTruncated);
    EXPECT_TRUE(!fin.MftDecodeLatencyUs.ReservoirSampled);
    session.Shutdown();
}

void
RunP0AStatisticalEquivalenceWithM021Tracker()
{
    std::vector<uint64_t> values;
    values.reserve(5000U);
    for (uint64_t i = 0ULL; i < 5000ULL; ++i)
    {
        values.push_back(120ULL + ((i * 7919ULL) % 9500ULL));
    }

    ReservoirLatencyAccumulator singleConsolidation;
    ReservoirLatencyAccumulator perStepCheck;
    LatencySummaryStats lastPerStep{};
    for (uint64_t v : values)
    {
        singleConsolidation.Record(v);
        perStepCheck.Record(v);
        lastPerStep = perStepCheck.Summarize();
    }
    const LatencySummaryStats finalOnly = singleConsolidation.Summarize();
    EXPECT_TRUE(StatsEqual(finalOnly, lastPerStep));

    // Also verify exact nearest-rank math against direct sort.
    std::vector<uint64_t> sorted = values;
    std::sort(sorted.begin(), sorted.end());
    uint64_t sum = 0ULL;
    for (uint64_t v : sorted)
    {
        sum += v;
    }
    EXPECT_EQ(finalOnly.MinUs, sorted.front());
    EXPECT_EQ(finalOnly.MaxUs, sorted.back());
    EXPECT_EQ(finalOnly.AvgUs, sum / sorted.size());
    EXPECT_EQ(finalOnly.SampleCount, 5000ULL);
    EXPECT_EQ(finalOnly.StoredSampleCount, 5000ULL);
    EXPECT_EQ(finalOnly.PercentileMethod, LatencyPercentileMethod::ExactPopulation);

    const size_t idx50 = ((50U * sorted.size() + 99U) / 100U) - 1U;
    const size_t idx95 = ((95U * sorted.size() + 99U) / 100U) - 1U;
    const size_t idx99 = ((99U * sorted.size() + 99U) / 100U) - 1U;
    EXPECT_EQ(finalOnly.P50Us, sorted[idx50]);
    EXPECT_EQ(finalOnly.P95Us, sorted[idx95]);
    EXPECT_EQ(finalOnly.P99Us, sorted[idx99]);
}

void
RunP0AScaleBoundaries1800_10800_65536_65537_216000()
{
    static constexpr size_t kCounts[] = {1800U, 10800U, 65536U, 65537U, 216000U};
    for (size_t count : kCounts)
    {
        // 1. Validate ReservoirLatencyAccumulator across all 5 synthetic sample scales.
        ReservoirLatencyAccumulator tracker;
        uint64_t expectedSum = 0ULL;
        uint64_t expectedMin = UINT64_MAX;
        uint64_t expectedMax = 0ULL;
        for (size_t i = 0U; i < count; ++i)
        {
            const uint64_t v = 50ULL + ((static_cast<uint64_t>(i) * 3571ULL) % 20000ULL);
            tracker.Record(v);
            expectedSum += v;
            expectedMin = (std::min)(expectedMin, v);
            expectedMax = (std::max)(expectedMax, v);
        }
        const LatencySummaryStats stats = tracker.Summarize();
        const bool expectReservoir = (count > ReservoirLatencyAccumulator::kDefaultMaxStoredSamples);
        EXPECT_TRUE(stats.Available);
        EXPECT_TRUE(stats.PercentilesAvailable);
        EXPECT_EQ(stats.PercentilesAreEstimated, expectReservoir);
        EXPECT_EQ(stats.SamplesTruncated, expectReservoir);
        EXPECT_EQ(stats.ReservoirSampled, expectReservoir);
        EXPECT_EQ(
            stats.PercentileMethod,
            expectReservoir
                ? LatencyPercentileMethod::ReservoirSampledEstimate_AlgorithmR
                : LatencyPercentileMethod::ExactPopulation);
        EXPECT_EQ(stats.SampleCount, static_cast<uint64_t>(count));
        EXPECT_EQ(
            stats.StoredSampleCount,
            static_cast<uint64_t>(expectReservoir ? ReservoirLatencyAccumulator::kDefaultMaxStoredSamples : count));
        EXPECT_EQ(stats.MinUs, expectedMin);
        EXPECT_EQ(stats.MaxUs, expectedMax);
        EXPECT_EQ(stats.AvgUs, expectedSum / count);
        EXPECT_TRUE(stats.P50Us >= stats.MinUs && stats.P50Us <= stats.P95Us);
        EXPECT_TRUE(stats.P95Us <= stats.P99Us && stats.P99Us <= stats.MaxUs);

        // 2. Validate H264StreamValidationSession end-to-end with single final consolidation at all 5 scales.
        MockH264Decoder mockDec;
        mockDec.ProduceEmptyFrameOnly = true;
        H264StreamValidationSession session(&mockDec);
        session.Configure(true, 60U, false);
        EXPECT_EQ(session.PrewarmDecoder(1920U, 1080U, 60U), S_OK);
        const EncodedFramePacket keyPkt = MakeSyntheticAnnexBPacket(1ULL, 1U, 1920U, 1080U, true);
        const EncodedFramePacket pPkt = MakeSyntheticAnnexBPacket(2ULL, 2U, 1920U, 1080U, false);
        for (size_t i = 0U; i < count; ++i)
        {
            session.SubmitPacket(i == 0U ? keyPkt : pPkt);
        }
        EXPECT_EQ(session.GetLatencyConsolidationCount(), 0ULL);
        session.Finish();
        EXPECT_EQ(session.GetLatencyConsolidationCount(), 1ULL);
        const H264ValidationSummary s = session.GetSummary();
        EXPECT_TRUE(s.Passed);
        EXPECT_EQ(s.PacketsInspected, static_cast<uint64_t>(count));
        EXPECT_EQ(s.FramesDecoded, static_cast<uint64_t>(count));
        EXPECT_EQ(s.MftDecodeLatencyUs.SampleCount, static_cast<uint64_t>(count));
        EXPECT_EQ(s.MftDecodeLatencyUs.PercentilesAreEstimated, expectReservoir);
        EXPECT_EQ(s.MftDecodeLatencyUs.SamplesTruncated, expectReservoir);
        EXPECT_EQ(s.MftDecodeLatencyUs.ReservoirSampled, expectReservoir);
        EXPECT_EQ(
            s.MftDecodeLatencyUs.PercentileMethod,
            expectReservoir
                ? LatencyPercentileMethod::ReservoirSampledEstimate_AlgorithmR
                : LatencyPercentileMethod::ExactPopulation);
        session.Shutdown();
    }
}

void
RunP0AZeroPacketsAndNullPercentileSemantics()
{
    MockH264Decoder mockDec;
    H264StreamValidationSession session(&mockDec);
    session.Configure(true, 60U, false);
    session.Finish();
    EXPECT_EQ(session.GetLatencyConsolidationCount(), 1ULL);
    const H264ValidationSummary s = session.GetSummary();
    EXPECT_TRUE(!s.Passed);
    EXPECT_EQ(s.PacketsInspected, 0ULL);
    EXPECT_EQ(s.FramesDecoded, 0ULL);
    EXPECT_TRUE(!s.MftDecodeLatencyUs.Available);
    EXPECT_TRUE(!s.MftDecodeLatencyUs.PercentilesAvailable);
    EXPECT_TRUE(!s.MftDecodeLatencyUs.PercentilesAreEstimated);
    EXPECT_EQ(s.MftDecodeLatencyUs.PercentileMethod, LatencyPercentileMethod::NotAvailable);
    EXPECT_EQ(s.MftDecodeLatencyUs.SampleCount, 0ULL);
    EXPECT_EQ(s.MftDecodeLatencyUs.StoredSampleCount, 0ULL);
    EXPECT_TRUE(!s.MftDecodeLatencyUs.SamplesTruncated);
    EXPECT_TRUE(!s.MftDecodeLatencyUs.ReservoirSampled);
    session.Shutdown();
}

void
RunP0ADecodeFailureAndDrainFailureMetrics()
{
    {
        MockH264Decoder mockDec;
        mockDec.NextDecodeHr = E_FAIL;
        H264StreamValidationSession session(&mockDec);
        session.Configure(true, 60U, false);
        EXPECT_EQ(session.PrewarmDecoder(1920U, 1080U, 60U), S_OK);
        session.SubmitPacket(MakeSyntheticAnnexBPacket(1ULL, 1U, 1920U, 1080U, true));
        EXPECT_EQ(session.GetLatencyConsolidationCount(), 0ULL);
        session.Finish();
        EXPECT_EQ(session.GetLatencyConsolidationCount(), 1ULL);
        const H264ValidationSummary s = session.GetSummary();
        EXPECT_TRUE(!s.Passed);
        EXPECT_EQ(s.DecodeFailures, 1ULL);
        EXPECT_EQ(s.LastHResult, E_FAIL);
        EXPECT_TRUE(s.MftDecodeLatencyUs.PercentilesAvailable);
        EXPECT_EQ(s.MftDecodeLatencyUs.SampleCount, 1ULL);
        session.Shutdown();
    }

    {
        MockH264Decoder mockDec;
        mockDec.NextDrainHr = E_UNEXPECTED;
        H264StreamValidationSession session(&mockDec);
        session.Configure(true, 60U, false);
        EXPECT_EQ(session.PrewarmDecoder(1920U, 1080U, 60U), S_OK);
        session.SubmitPacket(MakeSyntheticAnnexBPacket(1ULL, 1U, 1920U, 1080U, true));
        session.Finish();
        const H264ValidationSummary s = session.GetSummary();
        EXPECT_TRUE(session.HasDrainFailure());
        EXPECT_TRUE(!s.Passed);
        EXPECT_EQ(s.LastHResult, E_UNEXPECTED);
        session.Shutdown();
    }
}

void
RunP0CStartSuccessThenTerminalRuntimeError()
{
    MockStimulusPresenter mock;
    mock.PresentResults = {S_OK, S_OK, DXGI_ERROR_DEVICE_REMOVED};
    mock.DefaultPresentResult = DXGI_ERROR_DEVICE_REMOVED;
    mock.InitResults = {S_OK, E_FAIL};
    mock.DefaultInitResult = E_FAIL;

    VirtualDisplayStimulus stim;
    VirtualDisplayStimulusConfig cfg{};
    cfg.TargetFps = 60U;
    cfg.Backend = StimulusBackend::D3d11DxgiVSync;
    cfg.UseExplicitRectForTestOnly = true;
    cfg.ExplicitTestRect = RECT{0L, 0L, 320L, 240L};
    cfg.CustomDxgiPresenter = &mock;
    cfg.MaxConsecutiveDeviceLosses = 1U;

    EXPECT_TRUE(stim.Start(cfg));
    Sleep(200U);
    stim.Stop();

    const StimulusMetricsSnapshot snap = stim.GetMetricsSnapshot();
    EXPECT_TRUE(snap.Started);
    EXPECT_TRUE(snap.TerminalFailure);
    EXPECT_TRUE(!snap.CompletedCleanly);
    EXPECT_TRUE(FAILED(snap.LastHResult));
    EXPECT_TRUE(!snap.ErrorMessage.empty());
    EXPECT_TRUE(snap.PresentSucceeded >= 2ULL);
    EXPECT_TRUE(snap.PresentFailures >= 1ULL);
}

void
RunP0CInitializationFailurePreservesHResult()
{
    MockStimulusPresenter mock;
    mock.DefaultInitResult = DXGI_ERROR_UNSUPPORTED;

    VirtualDisplayStimulus stim;
    VirtualDisplayStimulusConfig cfg{};
    cfg.TargetFps = 60U;
    cfg.Backend = StimulusBackend::D3d11DxgiVSync;
    cfg.UseExplicitRectForTestOnly = true;
    cfg.ExplicitTestRect = RECT{0L, 0L, 320L, 240L};
    cfg.CustomDxgiPresenter = &mock;

    EXPECT_TRUE(!stim.Start(cfg));
    const StimulusMetricsSnapshot snap = stim.GetMetricsSnapshot();
    EXPECT_TRUE(!snap.Started);
    EXPECT_TRUE(!snap.CompletedCleanly);
    EXPECT_TRUE(snap.TerminalFailure);
    EXPECT_EQ(snap.LastHResult, DXGI_ERROR_UNSUPPORTED);
    EXPECT_TRUE(!snap.ErrorMessage.empty());
    EXPECT_TRUE(!snap.FallbackFromDxgiOccurred);
    EXPECT_EQ(snap.BackendActive, std::string("D3d11DxgiVSync"));
}

void
RunP0CNormalStopCompletedCleanly()
{
    MockStimulusPresenter mock;
    VirtualDisplayStimulus stim;
    VirtualDisplayStimulusConfig cfg{};
    cfg.TargetFps = 60U;
    cfg.Backend = StimulusBackend::D3d11DxgiVSync;
    cfg.UseExplicitRectForTestOnly = true;
    cfg.ExplicitTestRect = RECT{0L, 0L, 320L, 240L};
    cfg.CustomDxgiPresenter = &mock;

    EXPECT_TRUE(stim.Start(cfg));
    Sleep(200U);
    stim.Stop();

    const StimulusMetricsSnapshot snap = stim.GetMetricsSnapshot();
    EXPECT_TRUE(snap.Started);
    EXPECT_TRUE(snap.StopRequested);
    EXPECT_TRUE(!snap.TerminalFailure);
    EXPECT_TRUE(snap.CompletedCleanly);
    EXPECT_EQ(snap.LastHResult, S_OK);
    EXPECT_TRUE(snap.ErrorMessage.empty());
    EXPECT_TRUE(snap.PresentSucceeded >= 5ULL);
    EXPECT_EQ(snap.BackendActive, std::string("D3d11DxgiVSync"));
    EXPECT_TRUE(!snap.FallbackFromDxgiOccurred);
}

void
RunP0CTemporaryOcclusionRecoveredIsClean()
{
    MockStimulusPresenter mock;
    mock.PresentResults = {S_OK, DXGI_STATUS_OCCLUDED, DXGI_STATUS_OCCLUDED, S_OK};
    mock.DefaultPresentResult = S_OK;

    VirtualDisplayStimulus stim;
    VirtualDisplayStimulusConfig cfg{};
    cfg.TargetFps = 60U;
    cfg.Backend = StimulusBackend::D3d11DxgiVSync;
    cfg.UseExplicitRectForTestOnly = true;
    cfg.ExplicitTestRect = RECT{0L, 0L, 320L, 240L};
    cfg.CustomDxgiPresenter = &mock;

    EXPECT_TRUE(stim.Start(cfg));
    Sleep(250U);
    stim.Stop();

    const StimulusMetricsSnapshot snap = stim.GetMetricsSnapshot();
    EXPECT_TRUE(snap.PresentOccluded >= 2ULL);
    EXPECT_TRUE(snap.PresentSucceeded >= 5ULL);
    EXPECT_TRUE(!snap.TerminalFailure);
    EXPECT_TRUE(snap.CompletedCleanly);
    EXPECT_EQ(snap.LastHResult, S_OK);
    EXPECT_TRUE(snap.ErrorMessage.empty());
    EXPECT_TRUE(!snap.FallbackFromDxgiOccurred);
    EXPECT_EQ(snap.BackendActive, std::string("D3d11DxgiVSync"));
}

void
RunP0CPersistentOcclusionExplicitDxgiFailsWithoutFallback()
{
    MockStimulusPresenter mock;
    mock.DefaultPresentResult = DXGI_STATUS_OCCLUDED;

    VirtualDisplayStimulus stim;
    VirtualDisplayStimulusConfig cfg{};
    cfg.TargetFps = 60U;
    cfg.Backend = StimulusBackend::D3d11DxgiVSync;
    cfg.UseExplicitRectForTestOnly = true;
    cfg.ExplicitTestRect = RECT{0L, 0L, 320L, 240L};
    cfg.CustomDxgiPresenter = &mock;
    cfg.PersistentOcclusionThresholdTicks = 2U;

    EXPECT_TRUE(stim.Start(cfg));
    Sleep(200U);
    stim.Stop();

    const StimulusMetricsSnapshot snap = stim.GetMetricsSnapshot();
    EXPECT_EQ(snap.BackendRequested, std::string("D3d11DxgiVSync"));
    EXPECT_EQ(snap.BackendActive, std::string("D3d11DxgiVSync"));
    EXPECT_TRUE(!snap.FallbackFromDxgiOccurred);
    EXPECT_EQ(snap.PresentSucceeded, 0ULL);
    EXPECT_TRUE(snap.PresentOccluded >= 2ULL);
    EXPECT_TRUE(snap.TerminalFailure);
    EXPECT_TRUE(!snap.CompletedCleanly);
    EXPECT_EQ(snap.LastHResult, DXGI_STATUS_OCCLUDED);
    EXPECT_TRUE(!snap.ErrorMessage.empty());
}

void
RunP0CSwapChainRecreationRecoveredAndDefinitiveFailure()
{
    // (a) Single transient device loss recovers via swapchain recreation cleanly.
    {
        MockStimulusPresenter mock;
        mock.InitResults = {S_OK, S_OK};
        mock.DefaultInitResult = S_OK;
        mock.PresentResults = {S_OK, DXGI_ERROR_DEVICE_REMOVED, S_OK};
        mock.DefaultPresentResult = S_OK;

        VirtualDisplayStimulus stim;
        VirtualDisplayStimulusConfig cfg{};
        cfg.TargetFps = 60U;
        cfg.Backend = StimulusBackend::D3d11DxgiVSync;
        cfg.UseExplicitRectForTestOnly = true;
        cfg.ExplicitTestRect = RECT{0L, 0L, 320L, 240L};
        cfg.CustomDxgiPresenter = &mock;

        EXPECT_TRUE(stim.Start(cfg));
        Sleep(250U);
        stim.Stop();

        const StimulusMetricsSnapshot snap = stim.GetMetricsSnapshot();
        EXPECT_TRUE(snap.SwapChainRecreations >= 1ULL);
        EXPECT_TRUE(snap.PresentFailures >= 1ULL);
        EXPECT_TRUE(snap.PresentSucceeded >= 5ULL);
        EXPECT_TRUE(!snap.TerminalFailure);
        EXPECT_TRUE(snap.CompletedCleanly);
        EXPECT_EQ(snap.LastHResult, S_OK);
    }

    // (b) Definitive swapchain recreation failure propagates error HRESULT cleanly.
    {
        MockStimulusPresenter mock;
        mock.InitResults = {S_OK, E_OUTOFMEMORY};
        mock.DefaultInitResult = E_OUTOFMEMORY;
        mock.PresentResults = {S_OK, DXGI_ERROR_DEVICE_RESET};
        mock.DefaultPresentResult = S_OK;

        VirtualDisplayStimulus stim;
        VirtualDisplayStimulusConfig cfg{};
        cfg.TargetFps = 60U;
        cfg.Backend = StimulusBackend::D3d11DxgiVSync;
        cfg.UseExplicitRectForTestOnly = true;
        cfg.ExplicitTestRect = RECT{0L, 0L, 320L, 240L};
        cfg.CustomDxgiPresenter = &mock;

        EXPECT_TRUE(stim.Start(cfg));
        Sleep(200U);
        stim.Stop();

        const StimulusMetricsSnapshot snap = stim.GetMetricsSnapshot();
        EXPECT_TRUE(snap.TerminalFailure);
        EXPECT_TRUE(!snap.CompletedCleanly);
        EXPECT_EQ(snap.LastHResult, E_OUTOFMEMORY);
        EXPECT_TRUE(!snap.FallbackFromDxgiOccurred);
        EXPECT_TRUE(!snap.ErrorMessage.empty());
    }
}

void
RunP0CExplicitDxgiNeverFallsBackToGdi()
{
    MockStimulusPresenter mock;
    mock.InitResults = {S_OK};
    mock.DefaultPresentResult = E_ACCESSDENIED;

    VirtualDisplayStimulus stim;
    VirtualDisplayStimulusConfig cfg{};
    cfg.TargetFps = 60U;
    cfg.Backend = StimulusBackend::D3d11DxgiVSync;
    cfg.UseExplicitRectForTestOnly = true;
    cfg.ExplicitTestRect = RECT{0L, 0L, 320L, 240L};
    cfg.CustomDxgiPresenter = &mock;
    cfg.MaxConsecutivePresentFailures = 3U;

    EXPECT_TRUE(stim.Start(cfg));
    Sleep(200U);
    stim.Stop();

    const StimulusMetricsSnapshot snap = stim.GetMetricsSnapshot();
    EXPECT_TRUE(!snap.FallbackFromDxgiOccurred);
    EXPECT_TRUE(snap.BackendActive != std::string("GdiLegacy"));
    EXPECT_TRUE(snap.TerminalFailure);
    EXPECT_TRUE(!snap.CompletedCleanly);
    EXPECT_EQ(snap.LastHResult, E_ACCESSDENIED);
}

void
RunP0CAutoModeAuthorizedFallbackToGdi()
{
    MockStimulusPresenter mock;
    mock.DefaultInitResult = DXGI_ERROR_UNSUPPORTED;

    VirtualDisplayStimulus stim;
    VirtualDisplayStimulusConfig cfg{};
    cfg.TargetFps = 60U;
    cfg.Backend = StimulusBackend::Auto;
    cfg.UseExplicitRectForTestOnly = true;
    cfg.ExplicitTestRect = RECT{0L, 0L, 320L, 240L};
    cfg.CustomDxgiPresenter = &mock;

    EXPECT_TRUE(stim.Start(cfg));
    Sleep(200U);
    stim.Stop();

    const StimulusMetricsSnapshot snap = stim.GetMetricsSnapshot();
    EXPECT_EQ(snap.BackendRequested, std::string("Auto"));
    EXPECT_EQ(snap.BackendActive, std::string("GdiLegacy"));
    EXPECT_TRUE(snap.FallbackFromDxgiOccurred);
    EXPECT_TRUE(!snap.FallbackReason.empty());
    EXPECT_TRUE(snap.PresentSucceeded >= 5ULL);
    EXPECT_TRUE(!snap.TerminalFailure);
    EXPECT_TRUE(snap.CompletedCleanly);
}

void
RunP0DNormalStartStopAndConsistentAccounting()
{
    MockH264Decoder mockDec;
    H264StreamValidationSession session(&mockDec);
    session.Configure(true, 60U, false);
    H264WorkerConfig wCfg{};
    AsyncH264ValidationWorker worker(session, wCfg);

    EXPECT_TRUE(worker.Start(1920U, 1080U, 60U));
    for (uint32_t i = 1U; i <= 25U; ++i)
    {
        EXPECT_EQ(
            worker.Enqueue(MakeSyntheticAnnexBPacket(i, i, 1920U, 1080U, i == 1U)),
            H264WorkerEnqueueStatus::Enqueued);
    }
    worker.StopAndDrain(false);

    const H264WorkerMetricsSnapshot m = worker.GetMetricsSnapshot();
    EXPECT_TRUE(m.Enabled);
    EXPECT_TRUE(m.Healthy);
    EXPECT_EQ(m.CompletionState, H264WorkerCompletionState::NormalShutdown);
    EXPECT_EQ(m.PacketsEnqueued, 25ULL);
    EXPECT_EQ(m.PacketsDequeued, 25ULL);
    EXPECT_EQ(m.PacketsProcessed, 25ULL);
    EXPECT_EQ(m.PacketsRejected, 0ULL);
    EXPECT_EQ(m.QueueRemainingAtExit, 0ULL);
    EXPECT_EQ(m.WorkerFailureCount, 0ULL);
    EXPECT_TRUE(m.ComBalanced);
    EXPECT_EQ(worker.GetFinalSessionSummary().FramesDecoded, 25ULL);
}

void
RunP0DFifoOrderAndMoveBufferOwnership()
{
    MockH264Decoder mockDec;
    H264StreamValidationSession session(&mockDec);
    session.Configure(true, 60U, false);
    AsyncH264ValidationWorker worker(session);
    EXPECT_TRUE(worker.Start(1920U, 1080U, 60U));

    std::vector<uint8_t> expectedMarkers;
    for (uint32_t i = 1U; i <= 40U; ++i)
    {
        const uint8_t marker = static_cast<uint8_t>(0x30U + (i % 71U));
        expectedMarkers.push_back(marker);
        EncodedFramePacket pkt = MakeSyntheticAnnexBPacket(i, i * 2U, 1920U, 1080U, i == 1U, marker);
        EXPECT_TRUE(!pkt.Bitstream.empty());
        const H264WorkerEnqueueStatus st = worker.Enqueue(std::move(pkt));
        EXPECT_EQ(st, H264WorkerEnqueueStatus::Enqueued);
        // Moved-from vector buffer must no longer retain pixel/NAL storage in producer.
        EXPECT_TRUE(pkt.Bitstream.empty());
    }
    worker.StopAndDrain(false);

    const H264WorkerMetricsSnapshot m = worker.GetMetricsSnapshot();
    EXPECT_TRUE(m.Healthy);
    EXPECT_EQ(mockDec.ObservedFrameNumbers.size(), static_cast<size_t>(40U));
    EXPECT_EQ(mockDec.ObservedMarkerBytes.size(), static_cast<size_t>(40U));
    for (size_t i = 0U; i < 40U; ++i)
    {
        EXPECT_EQ(mockDec.ObservedFrameNumbers[i], static_cast<uint32_t>((i + 1U) * 2U));
        EXPECT_EQ(mockDec.ObservedMarkerBytes[i], expectedMarkers[i]);
    }
}

void
RunP0DQueueSaturationAndBackpressureWait()
{
    MockH264Decoder mockDec;
    mockDec.DecodeDelayMs = 8U;
    H264StreamValidationSession session(&mockDec);
    session.Configure(true, 60U, false);
    H264WorkerConfig wCfg{};
    wCfg.MaxQueueCapacity = 4U;
    wCfg.EnqueueTimeoutMs = 2000U;
    wCfg.DrainWaitTimeoutMs = 5000U;
    AsyncH264ValidationWorker worker(session, wCfg);

    EXPECT_TRUE(worker.Start(1920U, 1080U, 60U));
    for (uint32_t i = 1U; i <= 16U; ++i)
    {
        EXPECT_EQ(
            worker.Enqueue(MakeSyntheticAnnexBPacket(i, i, 1920U, 1080U, i == 1U)),
            H264WorkerEnqueueStatus::Enqueued);
    }
    worker.StopAndDrain(false);

    const H264WorkerMetricsSnapshot m = worker.GetMetricsSnapshot();
    EXPECT_TRUE(m.Healthy);
    EXPECT_EQ(m.CompletionState, H264WorkerCompletionState::NormalShutdown);
    EXPECT_EQ(m.QueuePeakDepth, 4ULL);
    EXPECT_TRUE(m.QueueFullWaitCount >= 1ULL);
    EXPECT_EQ(m.QueueWaitTimeoutCount, 0ULL);
    EXPECT_EQ(m.PacketsRejected, 0ULL);
    EXPECT_EQ(m.PacketsEnqueued, 16ULL);
    EXPECT_EQ(m.PacketsProcessed, 16ULL);
}

void
RunP0DEnqueueTimeoutPropagatesToMetricsAndGates()
{
    MockH264Decoder mockDec;
    mockDec.BlockOnFirstDecode = true;
    H264StreamValidationSession session(&mockDec);
    session.Configure(true, 60U, false);
    H264WorkerConfig wCfg{};
    wCfg.MaxQueueCapacity = 2U;
    wCfg.EnqueueTimeoutMs = 40U;
    wCfg.DrainWaitTimeoutMs = 2000U;
    AsyncH264ValidationWorker worker(session, wCfg);

    EXPECT_TRUE(worker.Start(1920U, 1080U, 60U));
    bool sawTimeout = false;
    for (uint32_t i = 1U; i <= 6U; ++i)
    {
        const H264WorkerEnqueueStatus st =
            worker.Enqueue(MakeSyntheticAnnexBPacket(i, i, 1920U, 1080U, i == 1U));
        if (st == H264WorkerEnqueueStatus::TimedOutQueueFull)
        {
            sawTimeout = true;
            break;
        }
    }
    EXPECT_TRUE(sawTimeout);

    mockDec.UnblockDecode();
    worker.StopAndDrain(false);

    const H264WorkerMetricsSnapshot m = worker.GetMetricsSnapshot();
    EXPECT_TRUE(!m.Healthy);
    EXPECT_EQ(m.CompletionState, H264WorkerCompletionState::EnqueueTimeout);
    EXPECT_TRUE(m.QueueWaitTimeoutCount >= 1ULL);
    EXPECT_TRUE(m.PacketsRejected >= 1ULL);
    EXPECT_TRUE(m.WorkerFailureCount >= 1ULL);
    EXPECT_EQ(m.LastHResult, HRESULT_FROM_WIN32(ERROR_TIMEOUT));

    HostConsumerConfig cCfg{};
    cCfg.MinFrames = 1ULL;
    HostConsumerMetricsSnapshot cSnap{};
    cSnap.FramesValid = 3ULL;
    cSnap.FrameTargetReached = true;
    cSnap.TotalConnectedDurationUs = 1000000ULL;
    StimulusMetricsSnapshot stimSnap{};
    NvencMetricsSnapshot nvSnap{};
    HostGateConfig gCfg{};
    gCfg.VerifyH264Decode = true;
    const HostGateEvaluation eval = EvaluateHostGates(
        cCfg, cSnap, stimSnap, nvSnap, worker.GetFinalSessionSummary(), m, gCfg, false, S_OK, S_OK);
    EXPECT_TRUE(!eval.H264DecodeOk);
    EXPECT_TRUE(!eval.OverallExitOk);
}

void
RunP0DDecoderPrewarmInitFailure()
{
    MockH264Decoder mockDec;
    mockDec.NextInitHr = MF_E_UNSUPPORTED_BYTESTREAM_TYPE;
    H264StreamValidationSession session(&mockDec);
    session.Configure(true, 60U, false);
    H264WorkerConfig wCfg{};
    wCfg.AllowSynchronousFallback = false;
    AsyncH264ValidationWorker worker(session, wCfg);

    EXPECT_TRUE(!worker.Start(1920U, 1080U, 60U));
    EXPECT_EQ(
        worker.Enqueue(MakeSyntheticAnnexBPacket(1ULL, 1U, 1920U, 1080U, true)),
        H264WorkerEnqueueStatus::RejectedWorkerFailed);
    worker.StopAndDrain(false);

    const H264WorkerMetricsSnapshot m = worker.GetMetricsSnapshot();
    EXPECT_TRUE(!m.Healthy);
    EXPECT_EQ(m.CompletionState, H264WorkerCompletionState::StartFailed);
    EXPECT_EQ(m.LastHResult, MF_E_UNSUPPORTED_BYTESTREAM_TYPE);
    EXPECT_TRUE(m.WorkerFailureCount >= 1ULL);
    EXPECT_EQ(m.PacketsRejected, 1ULL);
    EXPECT_TRUE(m.ComBalanced);
}

void
RunP0DEnqueueAllocationExceptionNoSilentDrop()
{
    MockH264Decoder mockDec;
    ThrowingWorkerHooks hooks;
    H264StreamValidationSession session(&mockDec);
    session.Configure(true, 60U, false);
    AsyncH264ValidationWorker worker(session, H264WorkerConfig{}, &hooks);

    EXPECT_TRUE(worker.Start(1920U, 1080U, 60U));
    const H264WorkerEnqueueStatus st =
        worker.Enqueue(MakeSyntheticAnnexBPacket(1ULL, 1U, 1920U, 1080U, true));
    EXPECT_EQ(st, H264WorkerEnqueueStatus::AllocationFailed);
    worker.StopAndDrain(false);

    const H264WorkerMetricsSnapshot m = worker.GetMetricsSnapshot();
    EXPECT_TRUE(!m.Healthy);
    EXPECT_EQ(m.PacketsRejected, 1ULL);
    EXPECT_EQ(m.WorkerFailureCount, 1ULL);
    EXPECT_EQ(m.LastHResult, E_OUTOFMEMORY);
    EXPECT_EQ(m.CompletionState, H264WorkerCompletionState::EnqueueRejected);
}

void
RunP0DDecodeFailureDuringProcessing()
{
    MockH264Decoder mockDec;
    mockDec.NextDecodeHr = E_FAIL;
    H264StreamValidationSession session(&mockDec);
    session.Configure(true, 60U, false);
    AsyncH264ValidationWorker worker(session);

    EXPECT_TRUE(worker.Start(1920U, 1080U, 60U));
    EXPECT_EQ(
        worker.Enqueue(MakeSyntheticAnnexBPacket(1ULL, 1U, 1920U, 1080U, true)),
        H264WorkerEnqueueStatus::Enqueued);
    worker.StopAndDrain(false);

    const H264WorkerMetricsSnapshot m = worker.GetMetricsSnapshot();
    const H264ValidationSummary s = worker.GetFinalSessionSummary();
    EXPECT_TRUE(!m.Healthy);
    EXPECT_EQ(m.CompletionState, H264WorkerCompletionState::DecodeError);
    EXPECT_TRUE(m.WorkerFailureCount >= 1ULL);
    EXPECT_EQ(m.LastHResult, E_FAIL);
    EXPECT_EQ(s.DecodeFailures, 1ULL);
    EXPECT_TRUE(!s.Passed);
}

void
RunP0DEnqueueAfterStopRequestedExplicitlyRejected()
{
    MockH264Decoder mockDec;
    H264StreamValidationSession session(&mockDec);
    session.Configure(true, 60U, false);
    AsyncH264ValidationWorker worker(session);

    EXPECT_EQ(
        worker.Enqueue(MakeSyntheticAnnexBPacket(1ULL, 1U, 1920U, 1080U, true)),
        H264WorkerEnqueueStatus::RejectedNotStarted);
    const H264WorkerMetricsSnapshot preStartSnap = worker.GetMetricsSnapshot();
    EXPECT_TRUE(!preStartSnap.Healthy);
    EXPECT_EQ(preStartSnap.PacketsRejected, 1ULL);
    EXPECT_EQ(preStartSnap.WorkerFailureCount, 1ULL);

    EXPECT_TRUE(worker.Start(1920U, 1080U, 60U));
    EXPECT_EQ(
        worker.Enqueue(MakeSyntheticAnnexBPacket(2ULL, 2U, 1920U, 1080U, true)),
        H264WorkerEnqueueStatus::Enqueued);
    worker.StopAndDrain(false);

    const H264WorkerEnqueueStatus lateSt =
        worker.Enqueue(MakeSyntheticAnnexBPacket(3ULL, 3U, 1920U, 1080U, false));
    EXPECT_EQ(lateSt, H264WorkerEnqueueStatus::RejectedNotStarted);

    const H264WorkerMetricsSnapshot m = worker.GetMetricsSnapshot();
    EXPECT_TRUE(!m.Healthy);
    EXPECT_EQ(m.PacketsRejected, 1ULL);
    EXPECT_EQ(m.WorkerFailureCount, 1ULL);
    EXPECT_EQ(m.CompletionState, H264WorkerCompletionState::EnqueueRejected);
}

void
RunP0DDrainWithPendingPacketsProcessesAll()
{
    MockH264Decoder mockDec;
    mockDec.DecodeDelayMs = 4U;
    mockDec.ReturnTailOnDrain = true;
    H264StreamValidationSession session(&mockDec);
    session.Configure(true, 60U, false);
    H264WorkerConfig wCfg{};
    wCfg.MaxQueueCapacity = 64U;
    wCfg.DrainWaitTimeoutMs = 5000U;
    AsyncH264ValidationWorker worker(session, wCfg);

    EXPECT_TRUE(worker.Start(1920U, 1080U, 60U));
    for (uint32_t i = 1U; i <= 20U; ++i)
    {
        EXPECT_EQ(
            worker.Enqueue(MakeSyntheticAnnexBPacket(i, i, 1920U, 1080U, i == 1U)),
            H264WorkerEnqueueStatus::Enqueued);
    }
    worker.StopAndDrain(false);

    const H264WorkerMetricsSnapshot m = worker.GetMetricsSnapshot();
    const H264ValidationSummary s = worker.GetFinalSessionSummary();
    EXPECT_TRUE(m.Healthy);
    EXPECT_EQ(m.CompletionState, H264WorkerCompletionState::NormalShutdown);
    EXPECT_TRUE(m.QueuePendingAtShutdown >= 1ULL);
    EXPECT_EQ(m.QueueRemainingAtExit, 0ULL);
    EXPECT_EQ(m.PacketsEnqueued, 20ULL);
    EXPECT_EQ(m.PacketsDequeued, 20ULL);
    EXPECT_EQ(m.PacketsProcessed, 20ULL);
    EXPECT_EQ(s.FramesDecoded, 21ULL); // 20 packets + 1 drained tail frame
}

void
RunP0DDrainFailureAndDrainDeadlineExceeded()
{
    // (a) Drain() returns failure -> CompletionState::DrainFailed.
    {
        MockH264Decoder mockDec;
        mockDec.NextDrainHr = E_FAIL;
        H264StreamValidationSession session(&mockDec);
        session.Configure(true, 60U, false);
        AsyncH264ValidationWorker worker(session);
        EXPECT_TRUE(worker.Start(1920U, 1080U, 60U));
        EXPECT_EQ(
            worker.Enqueue(MakeSyntheticAnnexBPacket(1ULL, 1U, 1920U, 1080U, true)),
            H264WorkerEnqueueStatus::Enqueued);
        worker.StopAndDrain(false);

        const H264WorkerMetricsSnapshot m = worker.GetMetricsSnapshot();
        EXPECT_TRUE(!m.Healthy);
        EXPECT_EQ(m.CompletionState, H264WorkerCompletionState::DrainFailed);
        EXPECT_EQ(m.LastHResult, E_FAIL);
    }

    // (b) Slow Drain() exceeds DrainWaitTimeoutMs -> DrainDeadlineExceeded + clean join() without detach.
    {
        MockH264Decoder mockDec;
        mockDec.DrainDelayMs = 150U;
        H264StreamValidationSession session(&mockDec);
        session.Configure(true, 60U, false);
        H264WorkerConfig wCfg{};
        wCfg.DrainWaitTimeoutMs = 30U;
        AsyncH264ValidationWorker worker(session, wCfg);
        EXPECT_TRUE(worker.Start(1920U, 1080U, 60U));
        EXPECT_EQ(
            worker.Enqueue(MakeSyntheticAnnexBPacket(1ULL, 1U, 1920U, 1080U, true)),
            H264WorkerEnqueueStatus::Enqueued);
        worker.StopAndDrain(false);

        const H264WorkerMetricsSnapshot m = worker.GetMetricsSnapshot();
        EXPECT_TRUE(!m.Healthy);
        EXPECT_TRUE(m.DrainDeadlineExceeded);
        EXPECT_EQ(m.CompletionState, H264WorkerCompletionState::DrainFailed);
        EXPECT_TRUE(m.ComBalanced);
    }
}

void
RunP0DWatchdogForcedTerminationState()
{
    MockH264Decoder mockDec;
    H264StreamValidationSession session(&mockDec);
    session.Configure(true, 60U, false);
    AsyncH264ValidationWorker worker(session);

    EXPECT_TRUE(worker.Start(1920U, 1080U, 60U));
    EXPECT_EQ(
        worker.Enqueue(MakeSyntheticAnnexBPacket(1ULL, 1U, 1920U, 1080U, true)),
        H264WorkerEnqueueStatus::Enqueued);
    worker.StopAndDrain(true);

    const H264WorkerMetricsSnapshot m = worker.GetMetricsSnapshot();
    EXPECT_TRUE(!m.Healthy);
    EXPECT_EQ(m.CompletionState, H264WorkerCompletionState::WatchdogForcedTermination);
}

void
RunP0DErrorAndExplicitDxgiGatePropagation()
{
    HostConsumerConfig cCfg{};
    cCfg.MinFrames = 1ULL;
    cCfg.RequireFrameTarget = true;

    HostConsumerMetricsSnapshot cSnap{};
    cSnap.FramesValid = 60ULL;
    cSnap.FrameTargetReached = true;
    cSnap.HostProcessExitedNormally = true;
    cSnap.TransportHealthy = true;
    cSnap.TotalConnectedDurationUs = 1000000ULL;

    NvencMetricsSnapshot nvSnap{};
    nvSnap.NvencFramesSubmitted = 60ULL;
    nvSnap.NvencFramesEncoded = 60ULL;
    nvSnap.TotalBitstreamBytes = 1000000ULL;

    H264ValidationSummary h264Snap{};
    h264Snap.Enabled = true;
    h264Snap.Passed = true;
    h264Snap.StructuralDecodeValidated = true;
    h264Snap.FramesDecoded = 60ULL;

    H264WorkerMetricsSnapshot cleanWorker{};
    cleanWorker.Enabled = true;
    cleanWorker.Healthy = true;
    cleanWorker.ComBalanced = true;
    cleanWorker.PacketsEnqueued = 60ULL;
    cleanWorker.PacketsProcessed = 60ULL;
    cleanWorker.CompletionState = H264WorkerCompletionState::NormalShutdown;

    StimulusMetricsSnapshot goodDxgi{};
    goodDxgi.Requested = true;
    goodDxgi.VirtualDisplayIdentified = true;
    goodDxgi.Started = true;
    goodDxgi.CompletedCleanly = true;
    goodDxgi.TerminalFailure = false;
    goodDxgi.LastHResult = S_OK;
    goodDxgi.DisplayDeviceName = L"\\\\.\\DISPLAY10";
    goodDxgi.IdentificationSource = "IndirectWiredMatch";
    goodDxgi.BackendRequested = "D3d11DxgiVSync";
    goodDxgi.BackendActive = "D3d11DxgiVSync";
    goodDxgi.FallbackFromDxgiOccurred = false;
    goodDxgi.PresentSucceeded = 60ULL;

    HostGateConfig gCfg{};
    gCfg.RequireVirtualStimulus = true;
    gCfg.RequestedStimulusBackend = StimulusBackend::D3d11DxgiVSync;
    gCfg.VerifyH264Decode = true;
    gCfg.RequireNvenc = true;

    const HostGateEvaluation cleanEval = EvaluateHostGates(
        cCfg, cSnap, goodDxgi, nvSnap, h264Snap, cleanWorker, gCfg, false, S_OK, S_OK);
    EXPECT_TRUE(cleanEval.StimulusOk);
    EXPECT_TRUE(cleanEval.H264DecodeOk);
    EXPECT_TRUE(cleanEval.OverallExitOk);

    // GDI fallback rejected under explicit DXGI.
    StimulusMetricsSnapshot fallbackStim = goodDxgi;
    fallbackStim.BackendActive = "GdiLegacy";
    fallbackStim.FallbackFromDxgiOccurred = true;
    const HostGateEvaluation fallbackEval = EvaluateHostGates(
        cCfg, cSnap, fallbackStim, nvSnap, h264Snap, cleanWorker, gCfg, false, S_OK, S_OK);
    EXPECT_TRUE(!fallbackEval.StimulusOk);
    EXPECT_TRUE(!fallbackEval.OverallExitOk);

    // Zero presents rejected under explicit DXGI.
    StimulusMetricsSnapshot zeroPres = goodDxgi;
    zeroPres.PresentSucceeded = 0ULL;
    const HostGateEvaluation zeroPresEval = EvaluateHostGates(
        cCfg, cSnap, zeroPres, nvSnap, h264Snap, cleanWorker, gCfg, false, S_OK, S_OK);
    EXPECT_TRUE(!zeroPresEval.StimulusOk);
    EXPECT_TRUE(!zeroPresEval.OverallExitOk);

    // Unhealthy worker rejected even if H264 summary Passed is true.
    H264WorkerMetricsSnapshot badWorker = cleanWorker;
    badWorker.PacketsRejected = 1ULL;
    badWorker.WorkerFailureCount = 1ULL;
    badWorker.Healthy = false;
    badWorker.CompletionState = H264WorkerCompletionState::EnqueueRejected;
    const HostGateEvaluation badWorkerEval = EvaluateHostGates(
        cCfg, cSnap, goodDxgi, nvSnap, h264Snap, badWorker, gCfg, false, S_OK, S_OK);
    EXPECT_TRUE(!badWorkerEval.H264DecodeOk);
    EXPECT_TRUE(!badWorkerEval.OverallExitOk);
}

void
RunP0DFinalConsolidationBeforeGateAndJson()
{
    MockH264Decoder mockDec;
    H264StreamValidationSession session(&mockDec);
    session.Configure(true, 60U, false);
    AsyncH264ValidationWorker worker(session);

    EXPECT_TRUE(worker.Start(1920U, 1080U, 60U));
    for (uint32_t i = 1U; i <= 10U; ++i)
    {
        EXPECT_EQ(
            worker.Enqueue(MakeSyntheticAnnexBPacket(i, i, 1920U, 1080U, i == 1U)),
            H264WorkerEnqueueStatus::Enqueued);
    }
    worker.StopAndDrain(false);

    EXPECT_EQ(session.GetLatencyConsolidationCount(), 1ULL);
    const H264ValidationSummary summary = worker.GetFinalSessionSummary();
    EXPECT_TRUE(summary.MftDecodeLatencyUs.PercentilesAvailable);
    EXPECT_EQ(summary.MftDecodeLatencyUs.SampleCount, 10ULL);
    EXPECT_EQ(summary.FramesDecoded, 10ULL);
}

void
RunP0DRealMftDecoderComAndMfThreadBalance()
{
    H264StreamValidationSession session;
    session.Configure(true, 60U, false);
    AsyncH264ValidationWorker worker(session);

    EXPECT_TRUE(worker.Start(1920U, 1080U, 60U));
    worker.StopAndDrain(false);

    const H264WorkerMetricsSnapshot m = worker.GetMetricsSnapshot();
    EXPECT_TRUE(m.ComBalanced);
    EXPECT_TRUE(m.WorkerThreadId != 0U);
    EXPECT_EQ(m.WorkerComInitCount, 1U);
    EXPECT_EQ(m.WorkerComUninitCount, 1U);
    EXPECT_EQ(m.WorkerComInitThreadId, m.WorkerThreadId);
    EXPECT_EQ(m.WorkerComUninitThreadId, m.WorkerThreadId);
    EXPECT_TRUE(m.DecoderLifecycle.ComBalanced());
    EXPECT_TRUE(m.DecoderLifecycle.MfBalanced());
    EXPECT_TRUE(m.DecoderLifecycle.ShutdownOnOwnerThread());
    EXPECT_TRUE(m.DecoderLifecycle.MfStartupCount >= 1U);
    EXPECT_EQ(m.DecoderLifecycle.OwnerThreadId, m.WorkerThreadId);
    EXPECT_EQ(m.DecoderLifecycle.ShutdownThreadId, m.WorkerThreadId);
    EXPECT_EQ(m.DecoderLifecycle.ComInitCount, 1U);
    EXPECT_EQ(m.DecoderLifecycle.ComUninitCount, 1U);
    EXPECT_EQ(m.DecoderLifecycle.ComInitThreadId, m.WorkerThreadId);
    EXPECT_EQ(m.DecoderLifecycle.ComUninitThreadId, m.WorkerThreadId);
}

void
RunP0DExplicitSynchronousFallbackLifecycleBalanced()
{
    // Run on a dedicated fresh OS thread so caller-thread COM MTA init starts cleanly at S_OK.
    bool threadChecksOk = false;
    std::thread syncThread([&threadChecksOk]() {
        MockH264Decoder mockDec;
        mockDec.NextInitHr = MF_E_TOPO_CODEC_NOT_FOUND;
        mockDec.SecondInitHr = S_OK;
        H264StreamValidationSession session(&mockDec);
        session.Configure(true, 60U, false);

        H264WorkerConfig wCfg{};
        wCfg.AllowSynchronousFallback = true;
        AsyncH264ValidationWorker worker(session, wCfg);

        const bool startOk = worker.Start(1920U, 1080U, 60U);
        const H264WorkerEnqueueStatus st1 =
            worker.Enqueue(MakeSyntheticAnnexBPacket(1ULL, 1U, 1920U, 1080U, true));
        const H264WorkerEnqueueStatus st2 =
            worker.Enqueue(MakeSyntheticAnnexBPacket(2ULL, 2U, 1920U, 1080U, false));
        worker.StopAndDrain(false);

        const H264WorkerMetricsSnapshot m = worker.GetMetricsSnapshot();
        const DWORD callerTid = GetCurrentThreadId();
        threadChecksOk =
            startOk &&
            (st1 == H264WorkerEnqueueStatus::ProcessedSynchronously) &&
            (st2 == H264WorkerEnqueueStatus::ProcessedSynchronously) &&
            m.Healthy &&
            (m.CompletionState == H264WorkerCompletionState::NormalShutdown) &&
            (m.PacketsEnqueued == 2ULL) &&
            (m.PacketsProcessed == 2ULL) &&
            (m.PacketsRejected == 0ULL) &&
            (m.WorkerFailureCount == 0ULL) &&
            m.ComBalanced &&
            (m.WorkerComInitCount == 1U) &&
            (m.WorkerComUninitCount == 1U) &&
            (m.WorkerComInitThreadId == callerTid) &&
            (m.WorkerComUninitThreadId == callerTid) &&
            (m.DecoderLifecycle.OwnerThreadId == callerTid) &&
            (m.DecoderLifecycle.ShutdownThreadId == callerTid) &&
            m.DecoderLifecycle.ShutdownOnOwnerThread();
    });
    syncThread.join();
    EXPECT_TRUE(threadChecksOk);
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
    RunTest("P0A_NoPerPacketConsolidationAndFinalConsolidationOnly", RunP0ANoPerPacketConsolidationAndFinalConsolidationOnly);
    RunTest("P0A_StatisticalEquivalenceWithM021Tracker", RunP0AStatisticalEquivalenceWithM021Tracker);
    RunTest("P0A_ScaleBoundaries1800_10800_65536_65537_216000", RunP0AScaleBoundaries1800_10800_65536_65537_216000);
    RunTest("P0A_ZeroPacketsAndNullPercentileSemantics", RunP0AZeroPacketsAndNullPercentileSemantics);
    RunTest("P0A_DecodeFailureAndDrainFailureMetrics", RunP0ADecodeFailureAndDrainFailureMetrics);

    RunTest("P0C_StartSuccessThenTerminalRuntimeError", RunP0CStartSuccessThenTerminalRuntimeError);
    RunTest("P0C_InitializationFailurePreservesHResult", RunP0CInitializationFailurePreservesHResult);
    RunTest("P0C_NormalStopCompletedCleanly", RunP0CNormalStopCompletedCleanly);
    RunTest("P0C_TemporaryOcclusionRecoveredIsClean", RunP0CTemporaryOcclusionRecoveredIsClean);
    RunTest("P0C_PersistentOcclusionExplicitDxgiFailsWithoutFallback", RunP0CPersistentOcclusionExplicitDxgiFailsWithoutFallback);
    RunTest("P0C_SwapChainRecreationRecoveredAndDefinitiveFailure", RunP0CSwapChainRecreationRecoveredAndDefinitiveFailure);
    RunTest("P0C_ExplicitDxgiNeverFallsBackToGdi", RunP0CExplicitDxgiNeverFallsBackToGdi);
    RunTest("P0C_AutoModeAuthorizedFallbackToGdi", RunP0CAutoModeAuthorizedFallbackToGdi);

    RunTest("P0D_NormalStartStopAndConsistentAccounting", RunP0DNormalStartStopAndConsistentAccounting);
    RunTest("P0D_FifoOrderAndMoveBufferOwnership", RunP0DFifoOrderAndMoveBufferOwnership);
    RunTest("P0D_QueueSaturationAndBackpressureWait", RunP0DQueueSaturationAndBackpressureWait);
    RunTest("P0D_EnqueueTimeoutPropagatesToMetricsAndGates", RunP0DEnqueueTimeoutPropagatesToMetricsAndGates);
    RunTest("P0D_DecoderPrewarmInitFailure", RunP0DDecoderPrewarmInitFailure);
    RunTest("P0D_EnqueueAllocationExceptionNoSilentDrop", RunP0DEnqueueAllocationExceptionNoSilentDrop);
    RunTest("P0D_DecodeFailureDuringProcessing", RunP0DDecodeFailureDuringProcessing);
    RunTest("P0D_EnqueueAfterStopRequestedExplicitlyRejected", RunP0DEnqueueAfterStopRequestedExplicitlyRejected);
    RunTest("P0D_DrainWithPendingPacketsProcessesAll", RunP0DDrainWithPendingPacketsProcessesAll);
    RunTest("P0D_DrainFailureAndDrainDeadlineExceeded", RunP0DDrainFailureAndDrainDeadlineExceeded);
    RunTest("P0D_WatchdogForcedTerminationState", RunP0DWatchdogForcedTerminationState);
    RunTest("P0D_ErrorAndExplicitDxgiGatePropagation", RunP0DErrorAndExplicitDxgiGatePropagation);
    RunTest("P0D_FinalConsolidationBeforeGateAndJson", RunP0DFinalConsolidationBeforeGateAndJson);
    RunTest("P0D_RealMftDecoderComAndMfThreadBalance", RunP0DRealMftDecoderComAndMfThreadBalance);
    RunTest("P0D_ExplicitSynchronousFallbackLifecycleBalanced", RunP0DExplicitSynchronousFallbackLifecycleBalanced);

    std::printf("Summary: %d tests run, %d assertion failures.\n", g_TestsRun, g_TestsFailed);
    return (g_TestsFailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
