#pragma once

#include "SwapChainProcessor.h"
#include "FrameIpcProtocol.h"
#include "FrameExtractor.h"

#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <memory>

namespace lumabridge::driver {

inline constexpr size_t kMaxSupportedQueueDepth = 16U;
inline constexpr size_t kMaxSupportedPoolSize = 20U;
inline constexpr DWORD kMinIpcIoTimeoutMs = 50U;
inline constexpr DWORD kMaxIpcIoTimeoutMs = 5000U;

/// Configuration for the bounded local Named Pipe IPC transport server.
struct FrameTransportConfig
{
    FrameTransportConfig() noexcept
    {
        SetPipeName(ipc::kDefaultFrameIpcPipeName);
    }

    void SetPipeName(const wchar_t* pipeName) noexcept
    {
        if (pipeName == nullptr)
        {
            PipeName[0] = L'\0';
            return;
        }
        (void)wcsncpy_s(PipeName, ARRAYSIZE(PipeName), pipeName, _TRUNCATE);
    }

    void SetAuthorizedUserSid(const wchar_t* sidString) noexcept
    {
        if (sidString == nullptr)
        {
            AuthorizedUserSid[0] = L'\0';
            return;
        }
        (void)wcsncpy_s(AuthorizedUserSid, ARRAYSIZE(AuthorizedUserSid), sidString, _TRUNCATE);
    }

    void SetAllowedClientSessionId(DWORD sessionId) noexcept
    {
        HasExplicitAllowedSessionId = true;
        AllowedClientSessionId = sessionId;
    }

    wchar_t PipeName[260]{};
    wchar_t AuthorizedUserSid[128]{};
    size_t MaxQueueDepth{ipc::kDefaultMaxFrameQueueDepth};
    size_t BufferPoolSize{ipc::kDefaultFrameBufferPoolSize};
    DWORD IoTimeoutMs{ipc::kDefaultIpcIoTimeoutMs};
    LUID AdapterLuid{0, 0};
    bool RequireClientAck{true};
    bool RestrictDaclToAuthorizedSid{false};
    bool AllowSameUserAccess{true};
    bool AllowBuiltinAdmins{true};
    bool AllowActiveConsoleInteractiveUser{true};
    bool RequireMatchingClientSession{true};
    bool HasExplicitAllowedSessionId{false};
    DWORD AllowedClientSessionId{0U};
    DWORD MinimumIntegrityRid{SECURITY_MANDATORY_MEDIUM_RID};
};

/// Thread-safe snapshot of bounded queue and local IPC delivery metrics.
struct FrameTransportMetricsSnapshot
{
    bool Running{false};
    uint32_t QueueDepth{0U};
    uint32_t PeakQueueDepth{0U};
    uint32_t ActiveHostConnections{0U};
    uint64_t ActiveSessionId{0ULL};
    uint64_t FramesEnqueued{0ULL};
    uint64_t FramesDroppedByBackpressure{0ULL};
    uint64_t FramesDelivered{0ULL};
    uint64_t FrameTransportFailures{0ULL};
    uint64_t ClientConnectionsAccepted{0ULL};
    uint64_t ClientConnectionsRejected{0ULL};
    uint64_t ClientDisconnects{0ULL};
    uint64_t LastDeliveredFrameSequence{0ULL};
    uint64_t LastDeliveryLatencyUs{0ULL};
    uint64_t TotalDeliveryLatencyUs{0ULL};
    uint64_t AvgDeliveryLatencyUs{0ULL};
    uint64_t MaxDeliveryLatencyUs{0ULL};
    HRESULT LastTransportError{S_OK};
};

/// Fixed-capacity ring buffer of unique_ptr<ExtractedFrameBuffer> (exception-free for UMDF).
template <size_t Capacity>
class BoundedBufferRing final
{
public:
    bool Empty() const noexcept { return m_count == 0U; }
    size_t Size() const noexcept { return m_count; }

    bool PushBack(std::unique_ptr<ExtractedFrameBuffer> item) noexcept
    {
        if (m_count >= Capacity || item == nullptr)
        {
            return false;
        }
        const size_t idx = (m_head + m_count) % Capacity;
        m_items[idx] = std::move(item);
        ++m_count;
        return true;
    }

    std::unique_ptr<ExtractedFrameBuffer> PopFront() noexcept
    {
        if (m_count == 0U)
        {
            return nullptr;
        }
        std::unique_ptr<ExtractedFrameBuffer> item = std::move(m_items[m_head]);
        m_head = (m_head + 1U) % Capacity;
        --m_count;
        return item;
    }

    void FreeAllPixelStorage() noexcept
    {
        for (size_t i = 0U; i < m_count; ++i)
        {
            const size_t idx = (m_head + i) % Capacity;
            if (m_items[idx] != nullptr)
            {
                m_items[idx]->ResetMetadataAndFreePixels();
            }
        }
    }

    void Clear() noexcept
    {
        while (m_count > 0U)
        {
            m_items[m_head].reset();
            m_head = (m_head + 1U) % Capacity;
            --m_count;
        }
        m_head = 0U;
    }

private:
    std::unique_ptr<ExtractedFrameBuffer> m_items[Capacity]{};
    size_t m_head{0U};
    size_t m_count{0U};
};

/// Bounded drop-oldest frame queue and overlapped local Named Pipe server.
/// Lock ordering: m_lifecycleLock -> m_queueLock / m_metricsLock (never held across I/O or waits).
class FrameIpcServer final
{
public:
    FrameIpcServer() noexcept = default;
    ~FrameIpcServer();

    FrameIpcServer(const FrameIpcServer&) = delete;
    FrameIpcServer& operator=(const FrameIpcServer&) = delete;

    /// Creates the secured Named Pipe endpoint, initializes the reusable buffer pool,
    /// and starts the dedicated IPC transport worker thread.
    HRESULT Start(
        const FrameTransportConfig& config
        ) noexcept;

    /// Signals cooperative cancellation, cancels pending overlapped pipe I/O,
    /// joins the transport thread, closes handles, and frees queued/pooled buffers.
    void Stop() noexcept;

    /// Returns true when the IPC server is active and not stopping.
    bool IsRunning() const noexcept;

    /// Obtains a reusable frame buffer slot without blocking on IPC.
    /// Evicts the oldest queued frame if all pool slots are currently occupied.
    std::unique_ptr<ExtractedFrameBuffer> AcquireBufferSlot() noexcept;

    /// Returns an unused or rejected buffer slot back to the reusable pool.
    void RecycleBufferSlot(
        std::unique_ptr<ExtractedFrameBuffer> slot
        ) noexcept;

    /// Enqueues an extracted frame using a bounded drop-oldest policy when full.
    HRESULT EnqueueFrame(
        std::unique_ptr<ExtractedFrameBuffer> frame,
        bool& outEvictedOldest
        ) noexcept;

    /// Recycles all currently queued frames back into the pool without disconnecting the host.
    void FlushQueue() noexcept;

    /// Returns a synchronized snapshot of queue and IPC delivery metrics.
    FrameTransportMetricsSnapshot GetMetricsSnapshot() const noexcept;

private:
    static DWORD WINAPI WorkerThreadProc(LPVOID context) noexcept;

    void WorkerLoop() noexcept;

    bool PopNextQueuedFrame(
        std::unique_ptr<ExtractedFrameBuffer>& outFrame
        ) noexcept;

    void ClearAllBuffersLocked() noexcept;

    HRESULT CreateSecuredPipeHandle(
        const FrameTransportConfig& config,
        ScopedWin32Handle& outPipeHandle
        ) noexcept;

    ipc::FrameIpcStatus VerifyConnectedClientIdentity(
        HANDLE pipeHandle,
        const ipc::FrameIpcClientHello& clientHello
        ) const noexcept;

    mutable SRWLOCK m_lifecycleLock{SRWLOCK_INIT};
    mutable SRWLOCK m_queueLock{SRWLOCK_INIT};
    mutable SRWLOCK m_metricsLock{SRWLOCK_INIT};

    FrameTransportConfig m_config{};
    size_t m_effectiveMaxQueueDepth{ipc::kDefaultMaxFrameQueueDepth};
    size_t m_effectiveMaxPoolSize{ipc::kDefaultFrameBufferPoolSize};
    size_t m_totalPoolSlots{0U};

    volatile LONG m_running{0};
    volatile LONG m_stopRequested{0};
    volatile LONG64 m_nextSessionId{0};

    ScopedWin32Handle m_pipeHandle{};
    ScopedWin32Handle m_stopEvent{};
    ScopedWin32Handle m_frameAvailableEvent{};
    ScopedWin32Handle m_workerThread{};

    BoundedBufferRing<kMaxSupportedQueueDepth> m_queue{};
    BoundedBufferRing<kMaxSupportedPoolSize> m_freePool{};

    FrameTransportMetricsSnapshot m_queueMetrics{};
    FrameTransportMetricsSnapshot m_transportMetrics{};
};

} // namespace lumabridge::driver
