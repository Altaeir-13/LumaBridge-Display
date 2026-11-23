#pragma once

#include <Windows.h>

#include "../driver/LumaBridgeIddDriver/FrameIpcProtocol.h"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace lumabridge::host {

/// Configuration for the local Windows host IPC frame consumer.
struct HostConsumerConfig
{
    std::wstring PipeName{ipc::kDefaultFrameIpcPipeName};
    DWORD ConnectTimeoutMs{3000U};
    DWORD IoTimeoutMs{ipc::kDefaultIpcIoTimeoutMs};
    uint64_t MaxFrames{0ULL};
    uint32_t MaxDurationMs{0U};
    bool VerifySyntheticPattern{false};
    bool AutoReconnect{false};
    bool SendAck{true};
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
    uint64_t FramesReceived{0ULL};
    uint64_t BytesReceived{0ULL};
    uint64_t SequenceGapsDetected{0ULL};
    uint64_t ChecksumMismatches{0ULL};
    uint64_t SyntheticPatternMismatches{0ULL};
    uint64_t ProtocolErrors{0ULL};
    uint64_t LastFrameSequence{0ULL};
    uint32_t LastPresentationFrameNumber{0U};
    uint32_t LastFrameWidth{0U};
    uint32_t LastFrameHeight{0U};
    uint32_t LastPixelFormat{0U};
    uint32_t LastFrameChecksumCrc32{0U};
    uint64_t LastEndToEndLatencyUs{0ULL};
    uint64_t TotalEndToEndLatencyUs{0ULL};
    uint64_t AvgEndToEndLatencyUs{0ULL};
    uint64_t MaxEndToEndLatencyUs{0ULL};
    uint64_t LastIpcTransitLatencyUs{0ULL};
    double ReceiveFps{0.0};
    HRESULT LastErrorHResult{S_OK};
    ipc::FrameIpcStatus LastProtocolStatus{ipc::FrameIpcStatus::Ok};
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

    HRESULT RunLoop(
        HANDLE stopEvent = nullptr,
        const std::function<void(const ipc::FrameIpcFrameHeader&, const std::vector<uint8_t>&)>& onFrame = nullptr
        ) noexcept;

    void Disconnect() noexcept;

    HostConsumerMetricsSnapshot GetMetricsSnapshot() const noexcept;

private:
    void ClosePipeAndResetConnectionState(bool sendDisconnectNotice) noexcept;

    HostConsumerConfig m_config{};
    mutable SRWLOCK m_metricsLock{SRWLOCK_INIT};
    HostConsumerMetricsSnapshot m_metrics{};
    HANDLE m_pipeHandle{INVALID_HANDLE_VALUE};
    HANDLE m_ioEvent{nullptr};
    uint64_t m_sessionId{0ULL};
    uint64_t m_qpcFreq{10000000ULL};
    uint64_t m_firstFrameQpc{0ULL};
};

} // namespace lumabridge::host
