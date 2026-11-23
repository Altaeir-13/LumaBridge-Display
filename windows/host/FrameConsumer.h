#pragma once

#include <Windows.h>
#include <d3d11_1.h>
#include <dxgi1_4.h>
#include <wrl/client.h>

#include "../driver/LumaBridgeIddDriver/FrameIpcProtocol.h"

#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace lumabridge::host {

enum class HostTransportPreference : uint32_t
{
    Auto = 0U,
    GpuSharedOnly = 1U,
    CpuStagingOnly = 2U,
};

inline const char*
HostTransportPreferenceToString(
    HostTransportPreference pref
    ) noexcept
{
    switch (pref)
    {
    case HostTransportPreference::Auto:
        return "Auto";
    case HostTransportPreference::GpuSharedOnly:
        return "GpuSharedOnly";
    case HostTransportPreference::CpuStagingOnly:
        return "CpuStagingOnly";
    default:
        return "Unknown";
    }
}

enum class HostExitReason : uint32_t
{
    None = 0,
    FrameTargetReached = 1,
    DurationElapsed = 2,
    StopRequested = 3,
    PeerDisconnected = 4,
    ConnectFailed = 5,
    FatalIoTimeout = 6,
    FatalProtocolError = 7,
    FatalIntegrityError = 8,
    OutOfMemory = 9,
    AdapterMismatch = 10,
    GpuResourceError = 11,
};

inline const char*
HostExitReasonToString(
    HostExitReason reason
    ) noexcept
{
    switch (reason)
    {
    case HostExitReason::None:
        return "None";
    case HostExitReason::FrameTargetReached:
        return "FrameTargetReached";
    case HostExitReason::DurationElapsed:
        return "DurationElapsed";
    case HostExitReason::StopRequested:
        return "StopRequested";
    case HostExitReason::PeerDisconnected:
        return "PeerDisconnected";
    case HostExitReason::ConnectFailed:
        return "ConnectFailed";
    case HostExitReason::FatalIoTimeout:
        return "FatalIoTimeout";
    case HostExitReason::FatalProtocolError:
        return "FatalProtocolError";
    case HostExitReason::FatalIntegrityError:
        return "FatalIntegrityError";
    case HostExitReason::OutOfMemory:
        return "OutOfMemory";
    case HostExitReason::AdapterMismatch:
        return "AdapterMismatch";
    case HostExitReason::GpuResourceError:
        return "GpuResourceError";
    default:
        return "Unknown";
    }
}

struct LatencySummaryStats
{
    uint64_t SampleCount{0ULL};
    uint64_t MinUs{0ULL};
    uint64_t AvgUs{0ULL};
    uint64_t MaxUs{0ULL};
    uint64_t P50Us{0ULL};
    uint64_t P95Us{0ULL};
    uint64_t P99Us{0ULL};
    uint64_t LastUs{0ULL};
};

struct HostFpsBreakdown
{
    double AverageExecutionFps{0.0};
    double ConnectedFps{0.0};
    double ObservedActiveFps{0.0};
    double SustainedLiveFps{0.0};
    bool FpsSampleSufficient{false};
};

struct ValidatedFrameIntervals
{
    bool Valid{false};
    bool QpcFrequencyMismatch{false};
    bool OutOfOrderTimestamps{false};
    bool PreConnectQueued{false};
    bool HasPresentToExtract{false};
    uint64_t PresentToExtractUs{0ULL};
    uint64_t CopyUs{0ULL};
    uint64_t QueueWaitUs{0ULL};
    uint64_t IpcTransitUs{0ULL};
    uint64_t HostVerifyAckUs{0ULL};
    uint64_t EndToEndUs{0ULL};
};

LatencySummaryStats
ComputeLatencySummary(
    const std::vector<uint64_t>& samples,
    uint64_t lastUs
    ) noexcept;

ValidatedFrameIntervals
ComputeValidatedFrameIntervals(
    const ipc::FrameIpcFrameHeader& header,
    uint64_t recvPayloadQpc,
    uint64_t ackCompleteQpc,
    uint64_t consumerQpcFreq,
    bool sentAck
    ) noexcept;

HostFpsBreakdown
ComputeHostFpsBreakdown(
    uint64_t framesValid,
    uint64_t liveFramesValid,
    uint64_t totalExecutionDurationUs,
    uint64_t totalConnectedDurationUs,
    uint64_t firstValidFrameQpc,
    uint64_t lastValidFrameQpc,
    uint64_t firstLiveFrameQpc,
    uint64_t lastLiveFrameQpc,
    uint64_t qpcFreq
    ) noexcept;

/// Configuration for the local Windows host IPC frame consumer.
struct HostConsumerConfig
{
    std::wstring PipeName{ipc::kDefaultFrameIpcPipeName};
    DWORD ConnectTimeoutMs{3000U};
    DWORD IoTimeoutMs{ipc::kDefaultIpcIoTimeoutMs};
    uint64_t MaxFrames{0ULL};
    uint64_t MinFrames{0ULL};
    uint32_t MaxDurationMs{0U};
    bool RequireFrameTarget{false};
    bool VerifySyntheticPattern{false};
    bool AutoReconnect{false};
    bool SendAck{true};
    HostTransportPreference TransportPreference{HostTransportPreference::Auto};
    bool AllowCpuFallback{true};
    bool HasForcedAdapterLuid{false};
    LUID ForcedAdapterLuid{0, 0};
    bool AllowWarpAdapterFallbackForSyntheticLuid{true};
    bool SimulateInvalidSharedHandleForTesting{false};
    DWORD SimulatedAckDelayMsForTesting{0U};
    bool SimulateDisconnectWhileHoldingMutexForTesting{false};
};

/// Synchronized runtime statistics observed by lumabridge-host.
struct HostConsumerMetricsSnapshot
{
    bool Connected{false};
    uint64_t SessionId{0ULL};
    uint32_t ServerProcessId{0U};
    int32_t AdapterLuidLow{0};
    int32_t AdapterLuidHigh{0};
    uint32_t ServerMaxQueueDepth{0U};
    uint64_t ConnectCount{0ULL};
    uint64_t ReconnectCount{0ULL};
    uint64_t DisconnectCount{0ULL};
    uint64_t SessionsCompleted{0ULL};
    uint64_t FramesReceived{0ULL};
    uint64_t FramesValid{0ULL};
    uint64_t LiveFramesReceived{0ULL};
    uint64_t PreConnectFramesReceived{0ULL};
    uint64_t MaxFramesPerSession{0ULL};
    uint64_t MinFramesPerSession{0ULL};
    uint64_t BytesReceived{0ULL};
    uint64_t SequenceGapsDetected{0ULL};
    uint64_t ChecksumMismatches{0ULL};
    uint64_t SyntheticPatternMismatches{0ULL};
    uint64_t ProtocolErrors{0ULL};
    uint64_t RecoverableIoTimeouts{0ULL};
    uint64_t FatalIoTimeouts{0ULL};
    uint64_t PartialMessageTimeouts{0ULL};
    uint64_t FatalIpcErrors{0ULL};
    uint64_t TimestampMeasurementErrors{0ULL};
    uint64_t LastFrameSequence{0ULL};
    uint32_t LastPresentationFrameNumber{0U};
    uint32_t LastFrameWidth{0U};
    uint32_t LastFrameHeight{0U};
    uint32_t LastPixelFormat{0U};
    uint32_t LastFrameChecksumCrc32{0U};
    uint64_t QpcFrequency{10000000ULL};
    uint64_t TotalExecutionDurationUs{0ULL};
    uint64_t TotalConnectedDurationUs{0ULL};
    uint64_t TotalIdleWaitDurationUs{0ULL};
    uint64_t LastEndToEndLatencyUs{0ULL};
    uint64_t TotalEndToEndLatencyUs{0ULL};
    uint64_t AvgEndToEndLatencyUs{0ULL};
    uint64_t MaxEndToEndLatencyUs{0ULL};
    uint64_t LastIpcTransitLatencyUs{0ULL};
    double ReceiveFps{0.0};
    double AverageExecutionFps{0.0};
    double ConnectedFps{0.0};
    double ObservedActiveFps{0.0};
    double SustainedLiveFps{0.0};
    bool FpsSampleSufficient{false};
    HostExitReason ExitReason{HostExitReason::None};
    bool HostProcessExitedNormally{false};
    bool TransportHealthy{true};
    bool FrameTargetReached{false};
    bool MinFramesReached{false};
    HRESULT LastErrorHResult{S_OK};
    HRESULT LastRecoverableTimeoutHResult{S_OK};
    ipc::FrameIpcStatus LastProtocolStatus{ipc::FrameIpcStatus::Ok};

    LatencySummaryStats CopyLatency{};
    LatencySummaryStats PresentToExtractLatency{};
    LatencySummaryStats QueueWaitLatency{};
    LatencySummaryStats LiveQueueWaitLatency{};
    LatencySummaryStats IpcTransitLatency{};
    LatencySummaryStats HostVerifyAckLatency{};
    LatencySummaryStats EndToEndLatency{};
    LatencySummaryStats LiveEndToEndLatency{};
    LatencySummaryStats InterFrameInterval{};
    LatencySummaryStats GpuSyncWaitLatency{};

    ipc::FrameIpcTransportMode NegotiatedTransportMode{ipc::FrameIpcTransportMode::CpuStagingPipe};
    bool FallbackToCpuActivated{false};
    uint32_t SharedTexturePoolSize{0U};
    uint32_t SharedTexturePoolPeakUsage{0U};
    uint64_t GpuFramesOpened{0ULL};
    uint64_t GpuFramesDropped{0ULL};
    uint64_t GpuSharedOpenFailures{0ULL};
    uint64_t GpuSyncTimeouts{0ULL};
    uint64_t AdapterMismatchErrors{0ULL};
    uint64_t CpuStagingReadsPerformed{0ULL};
};

/// Overlapped local Named Pipe client that authenticates to LumaBridgeIddDriver,
/// consumes extracted pixel frames, verifies framing/CRC32 integrity, and emits ACKs.
class FrameConsumer final
{
public:
    explicit FrameConsumer(
        const HostConsumerConfig& config = {}
        ) noexcept;
    ~FrameConsumer();

    FrameConsumer(const FrameConsumer&) = delete;
    FrameConsumer& operator=(const FrameConsumer&) = delete;

    HRESULT Connect(
        DWORD timeoutMs,
        HANDLE stopEvent = nullptr
        ) noexcept;

    HRESULT ReceiveNextFrame(
        ipc::FrameIpcFrameHeader& outHeader,
        std::vector<uint8_t>& outPixels,
        DWORD timeoutMs,
        HANDLE stopEvent = nullptr
        ) noexcept;

    HRESULT ReceiveNextGpuOrCpuFrame(
        bool& outIsGpuFrame,
        ipc::FrameIpcGpuFrameHeader& outGpuHeader,
        ipc::FrameIpcFrameHeader& outCpuHeader,
        std::vector<uint8_t>& outCpuPixels,
        DWORD timeoutMs,
        HANDLE stopEvent = nullptr
        ) noexcept;

    HRESULT RunLoop(
        HANDLE stopEvent = nullptr,
        const std::function<void(const ipc::FrameIpcFrameHeader&, const std::vector<uint8_t>&)>& onFrame = nullptr,
        const std::function<void(
            const ipc::FrameIpcGpuFrameHeader&,
            ID3D11Device*,
            ID3D11DeviceContext*,
            ID3D11Texture2D*)>& onGpuFrame = nullptr
        ) noexcept;

    void Disconnect() noexcept;

    HostConsumerMetricsSnapshot GetMetricsSnapshot() const noexcept;

    ID3D11Device* GetD3d11Device() const noexcept { return m_d3dDevice.Get(); }
    ID3D11DeviceContext* GetD3d11Context() const noexcept { return m_d3dContext.Get(); }
    ID3D11Texture2D* GetWorkingGpuTexture() const noexcept { return m_hostGpuWorkingTexture.Get(); }

private:
    static constexpr size_t kMaxStoredLatencySamples = 65536U;

    struct HostSharedSlotCacheEntry
    {
        uint32_t SlotGeneration{0U};
        HANDLE DuplicatedNtHandle{nullptr};
        Microsoft::WRL::ComPtr<ID3D11Texture2D> SharedTexture{};
        Microsoft::WRL::ComPtr<IDXGIKeyedMutex> KeyedMutex{};

        void Reset() noexcept
        {
            KeyedMutex.Reset();
            SharedTexture.Reset();
            if (DuplicatedNtHandle != nullptr && DuplicatedNtHandle != INVALID_HANDLE_VALUE)
            {
                CloseHandle(DuplicatedNtHandle);
            }
            DuplicatedNtHandle = nullptr;
            SlotGeneration = 0U;
        }
    };

    HRESULT EnsureD3d11DeviceForAdapterLuid(LUID serverAdapterLuid) noexcept;
    HRESULT EnsureHostWorkingTexture(uint32_t width, uint32_t height, DXGI_FORMAT format) noexcept;
    HRESULT VerifyWorkingGpuTextureSyntheticPattern(
        uint32_t presentationFrameNumber,
        uint32_t width,
        uint32_t height,
        DXGI_FORMAT format,
        bool& outMatches
        ) noexcept;
    void ClearGpuSharedResources() noexcept;
    HRESULT SendGpuFrameAck(
        uint64_t frameSequence,
        uint32_t presentationFrameNumber,
        ipc::FrameIpcStatus status,
        uint16_t slotIndex,
        uint16_t slotGeneration,
        uint32_t gpuSyncWaitUs,
        uint64_t receiveQpc,
        HANDLE stopEvent
        ) noexcept;

    struct LatencyAccumulator
    {
        std::vector<uint64_t> Samples{};
        uint64_t Count{0ULL};
        uint64_t TotalUs{0ULL};
        uint64_t MinUs{0ULL};
        uint64_t MaxUs{0ULL};
        uint64_t LastUs{0ULL};

        void Record(uint64_t valueUs) noexcept
        {
            if (Count == 0ULL || valueUs < MinUs)
            {
                MinUs = valueUs;
            }
            if (valueUs > MaxUs)
            {
                MaxUs = valueUs;
            }
            TotalUs += valueUs;
            LastUs = valueUs;
            ++Count;

            if (Samples.size() < kMaxStoredLatencySamples)
            {
                try
                {
                    Samples.push_back(valueUs);
                }
                catch (...)
                {
                }
            }
        }

        LatencySummaryStats Summarize() const noexcept
        {
            LatencySummaryStats summary = ComputeLatencySummary(Samples, LastUs);
            summary.SampleCount = Count;
            if (Count > 0ULL)
            {
                summary.MinUs = MinUs;
                summary.MaxUs = MaxUs;
                summary.AvgUs = TotalUs / Count;
            }
            return summary;
        }
    };

    void ClosePipeAndResetConnectionState(bool sendDisconnectNotice) noexcept;
    void UpdateDerivedFpsAndLatenciesLocked(uint64_t nowQpc, uint64_t executionStartQpc) noexcept;

    HostConsumerConfig m_config{};
    mutable SRWLOCK m_metricsLock{SRWLOCK_INIT};
    HostConsumerMetricsSnapshot m_metrics{};
    HANDLE m_pipeHandle{INVALID_HANDLE_VALUE};
    HANDLE m_ioEvent{nullptr};
    uint64_t m_sessionId{0ULL};
    uint64_t m_qpcFreq{10000000ULL};
    uint64_t m_executionStartQpc{0ULL};
    uint64_t m_sessionConnectQpc{0ULL};
    uint64_t m_accumulatedConnectedTicks{0ULL};
    uint64_t m_currentSessionFrames{0ULL};
    uint64_t m_firstValidFrameQpc{0ULL};
    uint64_t m_lastValidFrameQpc{0ULL};
    uint64_t m_firstLiveFrameQpc{0ULL};
    uint64_t m_lastLiveFrameQpc{0ULL};
    uint64_t m_prevValidRecvQpc{0ULL};

    LatencyAccumulator m_copyLat{};
    LatencyAccumulator m_presentToExtractLat{};
    LatencyAccumulator m_queueWaitLat{};
    LatencyAccumulator m_liveQueueWaitLat{};
    LatencyAccumulator m_ipcTransitLat{};
    LatencyAccumulator m_hostVerifyAckLat{};
    LatencyAccumulator m_endToEndLat{};
    LatencyAccumulator m_liveEndToEndLat{};
    LatencyAccumulator m_interFrameLat{};
    LatencyAccumulator m_gpuSyncWaitLat{};

    Microsoft::WRL::ComPtr<ID3D11Device> m_d3dDevice{};
    Microsoft::WRL::ComPtr<ID3D11Device1> m_d3dDevice1{};
    Microsoft::WRL::ComPtr<ID3D11DeviceContext> m_d3dContext{};
    Microsoft::WRL::ComPtr<ID3D11Texture2D> m_hostGpuWorkingTexture{};
    Microsoft::WRL::ComPtr<ID3D11Texture2D> m_diagnosticStagingTexture{};
    LUID m_boundAdapterLuid{0, 0};
    bool m_hasBoundD3dDevice{false};
    uint32_t m_workingWidth{0U};
    uint32_t m_workingHeight{0U};
    DXGI_FORMAT m_workingFormat{DXGI_FORMAT_UNKNOWN};
    uint32_t m_stagingWidth{0U};
    uint32_t m_stagingHeight{0U};
    DXGI_FORMAT m_stagingFormat{DXGI_FORMAT_UNKNOWN};
    std::array<HostSharedSlotCacheEntry, ipc::kMaxSharedTexturePoolSize> m_sharedSlotCache{};
    std::array<bool, ipc::kMaxSharedTexturePoolSize> m_slotSeenInSession{};
};

} // namespace lumabridge::host
