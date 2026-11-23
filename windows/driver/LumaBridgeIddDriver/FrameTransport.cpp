#include "FrameTransport.h"

#include <sddl.h>
#include <stdio.h>

#include <cstring>
#include <new>

namespace lumabridge::driver {

namespace {

class ExclusiveLock final
{
public:
    explicit ExclusiveLock(SRWLOCK* lock) noexcept
        : m_lock(lock)
    {
        if (m_lock != nullptr)
        {
            AcquireSRWLockExclusive(m_lock);
        }
    }

    ~ExclusiveLock()
    {
        if (m_lock != nullptr)
        {
            ReleaseSRWLockExclusive(m_lock);
        }
    }

    ExclusiveLock(const ExclusiveLock&) = delete;
    ExclusiveLock& operator=(const ExclusiveLock&) = delete;

private:
    SRWLOCK* m_lock;
};

class SharedLock final
{
public:
    explicit SharedLock(SRWLOCK* lock) noexcept
        : m_lock(lock)
    {
        if (m_lock != nullptr)
        {
            AcquireSRWLockShared(m_lock);
        }
    }

    ~SharedLock()
    {
        if (m_lock != nullptr)
        {
            ReleaseSRWLockShared(m_lock);
        }
    }

    SharedLock(const SharedLock&) = delete;
    SharedLock& operator=(const SharedLock&) = delete;

private:
    SRWLOCK* m_lock;
};

struct LocalFreeGuard final
{
    HLOCAL Ptr{nullptr};

    ~LocalFreeGuard()
    {
        if (Ptr != nullptr)
        {
            LocalFree(Ptr);
            Ptr = nullptr;
        }
    }
};

uint64_t
QueryCurrentQpc() noexcept
{
    LARGE_INTEGER li{};
    (void)QueryPerformanceCounter(&li);
    return (li.QuadPart > 0) ? static_cast<uint64_t>(li.QuadPart) : 0ULL;
}

uint64_t
QueryQpcFrequencySafe() noexcept
{
    LARGE_INTEGER li{};
    (void)QueryPerformanceFrequency(&li);
    return (li.QuadPart > 0) ? static_cast<uint64_t>(li.QuadPart) : 10000000ULL;
}

HRESULT
LastWin32HResult() noexcept
{
    const DWORD err = GetLastError();
    return (err != ERROR_SUCCESS) ? HRESULT_FROM_WIN32(err) : E_FAIL;
}

bool
IsPeerDisconnectWin32Error(
    DWORD err
    ) noexcept
{
    return err == ERROR_BROKEN_PIPE ||
           err == ERROR_NO_DATA ||
           err == ERROR_PIPE_NOT_CONNECTED;
}

DWORD
WaitOverlappedWithStop(
    HANDLE pipeHandle,
    OVERLAPPED& ov,
    HANDLE stopEvent,
    DWORD initialErr,
    DWORD timeoutMs,
    DWORD& outBytesTransferred
    ) noexcept
{
    outBytesTransferred = 0U;
    if (initialErr == ERROR_PIPE_CONNECTED)
    {
        return ERROR_SUCCESS;
    }
    if (initialErr != ERROR_IO_PENDING)
    {
        return initialErr;
    }

    const HANDLE handles[2] = {ov.hEvent, stopEvent};
    const DWORD waitResult = WaitForMultipleObjects(2U, handles, FALSE, timeoutMs);
    if (waitResult == WAIT_OBJECT_0)
    {
        if (GetOverlappedResult(pipeHandle, &ov, &outBytesTransferred, FALSE) != FALSE)
        {
            return ERROR_SUCCESS;
        }
        return GetLastError();
    }

    // Drain any in-flight overlapped IRP before OVERLAPPED goes out of scope.
    (void)CancelIoEx(pipeHandle, &ov);
    DWORD cancelledBytes = 0U;
    (void)GetOverlappedResult(pipeHandle, &ov, &cancelledBytes, TRUE);

    if (waitResult == WAIT_OBJECT_0 + 1)
    {
        return ERROR_OPERATION_ABORTED;
    }
    if (waitResult == WAIT_TIMEOUT)
    {
        return ERROR_TIMEOUT;
    }
    return ERROR_GEN_FAILURE;
}

DWORD
ConnectPipeOverlapped(
    HANDLE pipeHandle,
    HANDLE ioEvent,
    HANDLE stopEvent
    ) noexcept
{
    (void)ResetEvent(ioEvent);
    OVERLAPPED ov{};
    ov.hEvent = ioEvent;

    if (ConnectNamedPipe(pipeHandle, &ov) != FALSE)
    {
        return ERROR_SUCCESS;
    }

    const DWORD err = GetLastError();
    if (err == ERROR_PIPE_CONNECTED)
    {
        return ERROR_SUCCESS;
    }

    DWORD unusedBytes = 0U;
    return WaitOverlappedWithStop(pipeHandle, ov, stopEvent, err, INFINITE, unusedBytes);
}

DWORD
ReadExactOverlapped(
    HANDLE pipeHandle,
    HANDLE ioEvent,
    HANDLE stopEvent,
    void* buffer,
    size_t totalBytes,
    DWORD timeoutMs
    ) noexcept
{
    if (buffer == nullptr && totalBytes > 0U)
    {
        return ERROR_INVALID_PARAMETER;
    }

    uint8_t* dst = static_cast<uint8_t*>(buffer);
    size_t offset = 0U;
    while (offset < totalBytes)
    {
        if (WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0)
        {
            return ERROR_OPERATION_ABORTED;
        }

        (void)ResetEvent(ioEvent);
        OVERLAPPED ov{};
        ov.hEvent = ioEvent;

        const size_t remaining = totalBytes - offset;
        const DWORD chunkSize = static_cast<DWORD>((remaining > 0x00100000U) ? 0x00100000U : remaining);
        DWORD bytesRead = 0U;
        if (ReadFile(pipeHandle, dst + offset, chunkSize, &bytesRead, &ov) != FALSE)
        {
            if (bytesRead == 0U)
            {
                return ERROR_BROKEN_PIPE;
            }
            offset += static_cast<size_t>(bytesRead);
            continue;
        }

        const DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING)
        {
            return err;
        }

        DWORD overlappedBytes = 0U;
        const DWORD waitErr = WaitOverlappedWithStop(
            pipeHandle,
            ov,
            stopEvent,
            err,
            timeoutMs,
            overlappedBytes);
        if (waitErr != ERROR_SUCCESS)
        {
            return waitErr;
        }
        if (overlappedBytes == 0U)
        {
            return ERROR_BROKEN_PIPE;
        }
        offset += static_cast<size_t>(overlappedBytes);
    }

    return ERROR_SUCCESS;
}

DWORD
WriteExactOverlapped(
    HANDLE pipeHandle,
    HANDLE ioEvent,
    HANDLE stopEvent,
    const void* buffer,
    size_t totalBytes,
    DWORD timeoutMs
    ) noexcept
{
    if (buffer == nullptr && totalBytes > 0U)
    {
        return ERROR_INVALID_PARAMETER;
    }

    const uint8_t* src = static_cast<const uint8_t*>(buffer);
    size_t offset = 0U;
    while (offset < totalBytes)
    {
        if (WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0)
        {
            return ERROR_OPERATION_ABORTED;
        }

        (void)ResetEvent(ioEvent);
        OVERLAPPED ov{};
        ov.hEvent = ioEvent;

        const size_t remaining = totalBytes - offset;
        const DWORD chunkSize = static_cast<DWORD>((remaining > 0x00100000U) ? 0x00100000U : remaining);
        DWORD bytesWritten = 0U;
        if (WriteFile(pipeHandle, src + offset, chunkSize, &bytesWritten, &ov) != FALSE)
        {
            if (bytesWritten == 0U)
            {
                return ERROR_BROKEN_PIPE;
            }
            offset += static_cast<size_t>(bytesWritten);
            continue;
        }

        const DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING)
        {
            return err;
        }

        DWORD overlappedBytes = 0U;
        const DWORD waitErr = WaitOverlappedWithStop(
            pipeHandle,
            ov,
            stopEvent,
            err,
            timeoutMs,
            overlappedBytes);
        if (waitErr != ERROR_SUCCESS)
        {
            return waitErr;
        }
        if (overlappedBytes == 0U)
        {
            return ERROR_BROKEN_PIPE;
        }
        offset += static_cast<size_t>(overlappedBytes);
    }

    return ERROR_SUCCESS;
}

bool
QueryCurrentProcessUserSidString(
    wchar_t* outSidBuf,
    size_t outSidBufChars
    ) noexcept
{
    if (outSidBuf == nullptr || outSidBufChars == 0U)
    {
        return false;
    }
    outSidBuf[0] = L'\0';

    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) == FALSE)
    {
        return false;
    }
    ScopedWin32Handle tokenGuard(token);

    uint8_t stackTokenBuf[256]{};
    DWORD requiredSize = sizeof(stackTokenBuf);
    if (GetTokenInformation(
            tokenGuard.Get(),
            TokenUser,
            stackTokenBuf,
            requiredSize,
            &requiredSize) == FALSE)
    {
        return false;
    }

    const TOKEN_USER* tokenUser = reinterpret_cast<const TOKEN_USER*>(stackTokenBuf);
    LPWSTR sidStr = nullptr;
    if (ConvertSidToStringSidW(tokenUser->User.Sid, &sidStr) == FALSE || sidStr == nullptr)
    {
        return false;
    }
    LocalFreeGuard sidGuard{sidStr};

    const errno_t copyErr = wcsncpy_s(outSidBuf, outSidBufChars, sidStr, _TRUNCATE);
    return (copyErr == 0) && (outSidBuf[0] != L'\0');
}

} // namespace

FrameIpcServer::~FrameIpcServer()
{
    Stop();
}

HRESULT
FrameIpcServer::CreateSecuredPipeHandle(
    const wchar_t* pipeName,
    bool allowSameUserAccess,
    ScopedWin32Handle& outPipeHandle
    ) noexcept
{
    outPipeHandle.Reset();

    if (pipeName == nullptr || pipeName[0] == L'\0')
    {
        return E_INVALIDARG;
    }

    // Deny Network (NU) and Anonymous (AN) logons; grant full control to SYSTEM, Administrators,
    // and LOCAL SERVICE (WUDFHost.exe); grant read/write to Interactive Users (lumabridge-host.exe);
    // and set Medium Mandatory Label (ME) so non-elevated interactive host processes can write
    // frames/ACKs to a pipe hosted by LOCAL SERVICE while blocking Low/AppContainer integrity levels.
    static constexpr wchar_t kBaseDacl[] =
        L"D:P(D;;GA;;;NU)(D;;GA;;;AN)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;LS)(A;;GRGW;;;IU)";
    static constexpr wchar_t kMediumLabelSacl[] = L"S:(ML;;NW;;;ME)";

    wchar_t userSidBuf[128]{};
    const bool hasUserSid = allowSameUserAccess &&
        QueryCurrentProcessUserSidString(userSidBuf, ARRAYSIZE(userSidBuf));

    wchar_t sddlBuf[512]{};
    const int formatted = hasUserSid
        ? _snwprintf_s(
              sddlBuf,
              ARRAYSIZE(sddlBuf),
              _TRUNCATE,
              L"%ls(A;;GA;;;%ls)%ls",
              kBaseDacl,
              userSidBuf,
              kMediumLabelSacl)
        : _snwprintf_s(
              sddlBuf,
              ARRAYSIZE(sddlBuf),
              _TRUNCATE,
              L"%ls%ls",
              kBaseDacl,
              kMediumLabelSacl);

    if (formatted <= 0)
    {
        return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
    }

    PSECURITY_DESCRIPTOR rawSd = nullptr;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddlBuf,
            SDDL_REVISION_1,
            &rawSd,
            nullptr) == FALSE ||
        rawSd == nullptr)
    {
        return LastWin32HResult();
    }
    LocalFreeGuard sdGuard{rawSd};

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = rawSd;
    sa.bInheritHandle = FALSE;

    constexpr DWORD kPipeBufferBytes = 1024U * 1024U;
    const HANDLE pipe = CreateNamedPipeW(
        pipeName,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1U,
        kPipeBufferBytes,
        65536U,
        0U,
        &sa);

    if (pipe == INVALID_HANDLE_VALUE)
    {
        return LastWin32HResult();
    }

    outPipeHandle.Reset(pipe);
    return S_OK;
}

HRESULT
FrameIpcServer::Start(
    const FrameTransportConfig& config
    ) noexcept
{
    ExclusiveLock lifecycleGuard(&m_lifecycleLock);

    if (InterlockedCompareExchange(&m_running, 0, 0) != 0)
    {
        return S_OK;
    }

    if (config.PipeName[0] == L'\0')
    {
        return E_INVALIDARG;
    }

    const size_t clampedQueueDepth = (config.MaxQueueDepth == 0U)
        ? 1U
        : ((config.MaxQueueDepth > kMaxSupportedQueueDepth) ? kMaxSupportedQueueDepth : config.MaxQueueDepth);
    size_t clampedPoolSize = (config.BufferPoolSize < clampedQueueDepth + 2U)
        ? (clampedQueueDepth + 2U)
        : config.BufferPoolSize;
    if (clampedPoolSize > kMaxSupportedPoolSize)
    {
        clampedPoolSize = kMaxSupportedPoolSize;
    }

    ScopedWin32Handle pipeHandle;
    const HRESULT pipeHr = CreateSecuredPipeHandle(
        config.PipeName,
        config.AllowSameUserAccess,
        pipeHandle);
    if (FAILED(pipeHr))
    {
        ExclusiveLock metricsGuard(&m_metricsLock);
        m_transportMetrics.LastTransportError = pipeHr;
        return pipeHr;
    }

    ScopedWin32Handle stopEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!stopEvent.IsValid())
    {
        return LastWin32HResult();
    }

    ScopedWin32Handle frameEvent(CreateEventW(nullptr, FALSE, FALSE, nullptr));
    if (!frameEvent.IsValid())
    {
        return LastWin32HResult();
    }

    {
        ExclusiveLock queueGuard(&m_queueLock);
        ClearAllBuffersLocked();

        for (size_t i = 0U; i < clampedPoolSize; ++i)
        {
            std::unique_ptr<ExtractedFrameBuffer> slot(new (std::nothrow) ExtractedFrameBuffer());
            if (slot == nullptr || !m_freePool.PushBack(std::move(slot)))
            {
                ClearAllBuffersLocked();
                return E_OUTOFMEMORY;
            }
        }

        m_effectiveMaxQueueDepth = clampedQueueDepth;
        m_effectiveMaxPoolSize = clampedPoolSize;
        m_totalPoolSlots = clampedPoolSize;
        m_queueMetrics = {};
        m_queueMetrics.Running = true;
    }

    {
        ExclusiveLock metricsGuard(&m_metricsLock);
        m_transportMetrics = {};
        m_transportMetrics.Running = true;
    }

    m_config = config;
    if (m_config.IoTimeoutMs == 0U)
    {
        m_config.IoTimeoutMs = ipc::kDefaultIpcIoTimeoutMs;
    }

    m_pipeHandle = std::move(pipeHandle);
    m_stopEvent = std::move(stopEvent);
    m_frameAvailableEvent = std::move(frameEvent);
    InterlockedExchange(&m_stopRequested, 0);
    InterlockedExchange(&m_running, 1);

    DWORD workerTid = 0U;
    ScopedWin32Handle workerThread(CreateThread(
        nullptr,
        0,
        &FrameIpcServer::WorkerThreadProc,
        this,
        0,
        &workerTid));
    if (!workerThread.IsValid())
    {
        const HRESULT threadHr = LastWin32HResult();
        InterlockedExchange(&m_running, 0);
        InterlockedExchange(&m_stopRequested, 1);
        m_pipeHandle.Reset();
        m_stopEvent.Reset();
        m_frameAvailableEvent.Reset();
        {
            ExclusiveLock queueGuard(&m_queueLock);
            ClearAllBuffersLocked();
            m_queueMetrics.Running = false;
        }
        {
            ExclusiveLock metricsGuard(&m_metricsLock);
            m_transportMetrics.Running = false;
            m_transportMetrics.LastTransportError = threadHr;
        }
        return threadHr;
    }

    m_workerThread = std::move(workerThread);
    return S_OK;
}

void
FrameIpcServer::Stop() noexcept
{
    ExclusiveLock lifecycleGuard(&m_lifecycleLock);

    InterlockedExchange(&m_stopRequested, 1);
    if (m_stopEvent.IsValid())
    {
        (void)SetEvent(m_stopEvent.Get());
    }
    if (m_frameAvailableEvent.IsValid())
    {
        (void)SetEvent(m_frameAvailableEvent.Get());
    }

    if (m_workerThread.IsValid())
    {
        (void)WaitForSingleObject(m_workerThread.Get(), INFINITE);
        m_workerThread.Reset();
    }

    InterlockedExchange(&m_running, 0);
    m_pipeHandle.Reset();
    m_stopEvent.Reset();
    m_frameAvailableEvent.Reset();

    {
        ExclusiveLock queueGuard(&m_queueLock);
        ClearAllBuffersLocked();
        m_queueMetrics.Running = false;
        m_queueMetrics.QueueDepth = 0U;
    }

    {
        ExclusiveLock metricsGuard(&m_metricsLock);
        m_transportMetrics.Running = false;
        m_transportMetrics.ActiveHostConnections = 0U;
        m_transportMetrics.ActiveSessionId = 0ULL;
    }
}

bool
FrameIpcServer::IsRunning() const noexcept
{
    return InterlockedCompareExchange(const_cast<volatile LONG*>(&m_running), 0, 0) != 0 &&
           InterlockedCompareExchange(const_cast<volatile LONG*>(&m_stopRequested), 0, 0) == 0;
}

std::unique_ptr<ExtractedFrameBuffer>
FrameIpcServer::AcquireBufferSlot() noexcept
{
    {
        ExclusiveLock queueGuard(&m_queueLock);
        if (!m_freePool.Empty())
        {
            auto slot = m_freePool.PopFront();
            if (slot != nullptr)
            {
                slot->ResetMetadataKeepCapacity();
                return slot;
            }
        }

        if (m_totalPoolSlots < m_effectiveMaxPoolSize)
        {
            ++m_totalPoolSlots;
        }
        else if (!m_queue.Empty())
        {
            auto evicted = m_queue.PopFront();
            ++m_queueMetrics.FramesDroppedByBackpressure;
            m_queueMetrics.QueueDepth = static_cast<uint32_t>(m_queue.Size());
            if (evicted != nullptr)
            {
                evicted->ResetMetadataKeepCapacity();
                return evicted;
            }
        }
    }

    return std::unique_ptr<ExtractedFrameBuffer>(new (std::nothrow) ExtractedFrameBuffer());
}

void
FrameIpcServer::RecycleBufferSlot(
    std::unique_ptr<ExtractedFrameBuffer> slot
    ) noexcept
{
    if (slot == nullptr)
    {
        return;
    }

    slot->ResetMetadataKeepCapacity();

    ExclusiveLock queueGuard(&m_queueLock);
    if (InterlockedCompareExchange(&m_running, 0, 0) == 0)
    {
        return;
    }

    if (m_freePool.Size() < m_effectiveMaxPoolSize)
    {
        (void)m_freePool.PushBack(std::move(slot));
    }
}

HRESULT
FrameIpcServer::EnqueueFrame(
    std::unique_ptr<ExtractedFrameBuffer> frame,
    bool& outEvictedOldest
    ) noexcept
{
    outEvictedOldest = false;
    if (frame == nullptr)
    {
        return E_INVALIDARG;
    }

    if (!IsRunning())
    {
        RecycleBufferSlot(std::move(frame));
        return E_ABORT;
    }

    HANDLE eventToSignal = nullptr;
    {
        ExclusiveLock queueGuard(&m_queueLock);
        if (!IsRunning())
        {
            return E_ABORT;
        }

        while (m_queue.Size() >= m_effectiveMaxQueueDepth)
        {
            auto evicted = m_queue.PopFront();
            ++m_queueMetrics.FramesDroppedByBackpressure;
            outEvictedOldest = true;

            if (evicted != nullptr && m_freePool.Size() < m_effectiveMaxPoolSize)
            {
                evicted->ResetMetadataKeepCapacity();
                (void)m_freePool.PushBack(std::move(evicted));
            }
        }

        if (!m_queue.PushBack(std::move(frame)))
        {
            return E_OUTOFMEMORY;
        }

        const uint32_t depth = static_cast<uint32_t>(m_queue.Size());
        m_queueMetrics.QueueDepth = depth;
        if (depth > m_queueMetrics.PeakQueueDepth)
        {
            m_queueMetrics.PeakQueueDepth = depth;
        }
        ++m_queueMetrics.FramesEnqueued;
        eventToSignal = m_frameAvailableEvent.Get();
    }

    if (eventToSignal != nullptr)
    {
        (void)SetEvent(eventToSignal);
    }

    return S_OK;
}

void
FrameIpcServer::FlushQueue() noexcept
{
    ExclusiveLock queueGuard(&m_queueLock);
    while (!m_queue.Empty())
    {
        auto item = m_queue.PopFront();
        if (item != nullptr && m_freePool.Size() < m_effectiveMaxPoolSize)
        {
            item->ResetMetadataKeepCapacity();
            (void)m_freePool.PushBack(std::move(item));
        }
    }
    m_queueMetrics.QueueDepth = 0U;
}

FrameTransportMetricsSnapshot
FrameIpcServer::GetMetricsSnapshot() const noexcept
{
    FrameTransportMetricsSnapshot queueSnap{};
    {
        SharedLock queueGuard(&m_queueLock);
        queueSnap = m_queueMetrics;
    }

    FrameTransportMetricsSnapshot combined{};
    {
        SharedLock metricsGuard(&m_metricsLock);
        combined = m_transportMetrics;
    }

    combined.Running = queueSnap.Running;
    combined.QueueDepth = queueSnap.QueueDepth;
    combined.PeakQueueDepth = queueSnap.PeakQueueDepth;
    combined.FramesEnqueued = queueSnap.FramesEnqueued;
    combined.FramesDroppedByBackpressure = queueSnap.FramesDroppedByBackpressure;
    return combined;
}

bool
FrameIpcServer::PopNextQueuedFrame(
    std::unique_ptr<ExtractedFrameBuffer>& outFrame
    ) noexcept
{
    outFrame.reset();
    ExclusiveLock queueGuard(&m_queueLock);
    if (m_queue.Empty())
    {
        m_queueMetrics.QueueDepth = 0U;
        return false;
    }

    outFrame = m_queue.PopFront();
    m_queueMetrics.QueueDepth = static_cast<uint32_t>(m_queue.Size());
    return outFrame != nullptr;
}

void
FrameIpcServer::ClearAllBuffersLocked() noexcept
{
    m_queue.Clear();
    m_freePool.Clear();
    m_totalPoolSlots = 0U;
}

DWORD WINAPI
FrameIpcServer::WorkerThreadProc(
    LPVOID context
    ) noexcept
{
    auto* self = static_cast<FrameIpcServer*>(context);
    if (self == nullptr)
    {
        return ERROR_INVALID_PARAMETER;
    }
    self->WorkerLoop();
    return 0U;
}

void
FrameIpcServer::WorkerLoop() noexcept
{
    const HANDLE pipeHandle = m_pipeHandle.Get();
    const HANDLE stopEvent = m_stopEvent.Get();
    const HANDLE frameEvent = m_frameAvailableEvent.Get();
    if (pipeHandle == nullptr || stopEvent == nullptr || frameEvent == nullptr)
    {
        return;
    }

    ScopedWin32Handle ioEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!ioEvent.IsValid())
    {
        ExclusiveLock metricsGuard(&m_metricsLock);
        m_transportMetrics.LastTransportError = LastWin32HResult();
        return;
    }

    const uint64_t qpcFreq = QueryQpcFrequencySafe();

    while (InterlockedCompareExchange(&m_stopRequested, 0, 0) == 0)
    {
        const DWORD connectErr = ConnectPipeOverlapped(pipeHandle, ioEvent.Get(), stopEvent);
        if (connectErr == ERROR_OPERATION_ABORTED ||
            InterlockedCompareExchange(&m_stopRequested, 0, 0) != 0)
        {
            break;
        }
        if (connectErr != ERROR_SUCCESS)
        {
            {
                ExclusiveLock metricsGuard(&m_metricsLock);
                ++m_transportMetrics.FrameTransportFailures;
                m_transportMetrics.LastTransportError = HRESULT_FROM_WIN32(connectErr);
            }
            (void)DisconnectNamedPipe(pipeHandle);
            continue;
        }

        ipc::FrameIpcClientHello clientHello{};
        const DWORD helloReadErr = ReadExactOverlapped(
            pipeHandle,
            ioEvent.Get(),
            stopEvent,
            &clientHello,
            sizeof(clientHello),
            m_config.IoTimeoutMs);
        if (helloReadErr != ERROR_SUCCESS)
        {
            if (helloReadErr != ERROR_OPERATION_ABORTED)
            {
                ExclusiveLock metricsGuard(&m_metricsLock);
                ++m_transportMetrics.ClientConnectionsRejected;
                ++m_transportMetrics.FrameTransportFailures;
                m_transportMetrics.LastTransportError = HRESULT_FROM_WIN32(helloReadErr);
            }
            (void)DisconnectNamedPipe(pipeHandle);
            continue;
        }

        ipc::FrameIpcStatus validationStatus = ipc::ValidateClientHello(
            &clientHello,
            sizeof(clientHello),
            m_config.ExpectedClientAuthToken);

        if (validationStatus == ipc::FrameIpcStatus::Ok)
        {
            ULONG osClientPid = 0U;
            if (GetNamedPipeClientProcessId(pipeHandle, &osClientPid) == FALSE ||
                osClientPid == 0U ||
                clientHello.ClientProcessId != static_cast<uint32_t>(osClientPid))
            {
                validationStatus = ipc::FrameIpcStatus::UnauthorizedClient;
            }
        }

        ipc::FrameIpcServerHello serverHello{};
        serverHello.Envelope = ipc::InitEnvelope(
            ipc::FrameIpcMessageType::ServerHello,
            static_cast<uint32_t>(sizeof(ipc::FrameIpcServerHello)));
        serverHello.Status = static_cast<uint32_t>(validationStatus);
        serverHello.ServerProcessId = GetCurrentProcessId();
        serverHello.AdapterLuidLow = static_cast<int32_t>(m_config.AdapterLuid.LowPart);
        serverHello.AdapterLuidHigh = static_cast<int32_t>(m_config.AdapterLuid.HighPart);
        serverHello.MaxQueueDepth = static_cast<uint32_t>(m_effectiveMaxQueueDepth);

        if (validationStatus != ipc::FrameIpcStatus::Ok)
        {
            serverHello.SessionId = 0ULL;
            const DWORD rejectWriteTimeoutMs = (m_config.IoTimeoutMs < 100U) ? m_config.IoTimeoutMs : 100U;
            (void)WriteExactOverlapped(
                pipeHandle,
                ioEvent.Get(),
                stopEvent,
                &serverHello,
                sizeof(serverHello),
                rejectWriteTimeoutMs);
            {
                ExclusiveLock metricsGuard(&m_metricsLock);
                ++m_transportMetrics.ClientConnectionsRejected;
                ++m_transportMetrics.FrameTransportFailures;
                m_transportMetrics.LastTransportError =
                    (validationStatus == ipc::FrameIpcStatus::UnauthorizedClient)
                    ? E_ACCESSDENIED
                    : E_INVALIDARG;
            }
            (void)DisconnectNamedPipe(pipeHandle);
            continue;
        }

        const uint64_t sessionId = static_cast<uint64_t>(InterlockedIncrement64(&m_nextSessionId));
        serverHello.SessionId = sessionId;

        const DWORD helloWriteErr = WriteExactOverlapped(
            pipeHandle,
            ioEvent.Get(),
            stopEvent,
            &serverHello,
            sizeof(serverHello),
            m_config.IoTimeoutMs);
        if (helloWriteErr != ERROR_SUCCESS)
        {
            if (helloWriteErr != ERROR_OPERATION_ABORTED)
            {
                ExclusiveLock metricsGuard(&m_metricsLock);
                ++m_transportMetrics.FrameTransportFailures;
                m_transportMetrics.LastTransportError = HRESULT_FROM_WIN32(helloWriteErr);
            }
            (void)DisconnectNamedPipe(pipeHandle);
            continue;
        }

        {
            ExclusiveLock metricsGuard(&m_metricsLock);
            ++m_transportMetrics.ClientConnectionsAccepted;
            m_transportMetrics.ActiveHostConnections = 1U;
            m_transportMetrics.ActiveSessionId = sessionId;
        }

        bool disconnectedByPeer = false;
        while (InterlockedCompareExchange(&m_stopRequested, 0, 0) == 0)
        {
            std::unique_ptr<ExtractedFrameBuffer> frame;
            if (!PopNextQueuedFrame(frame))
            {
                const HANDLE waitHandles[2] = {frameEvent, stopEvent};
                const DWORD waitRes = WaitForMultipleObjects(2U, waitHandles, FALSE, 250U);
                if (waitRes == WAIT_OBJECT_0 + 1)
                {
                    break;
                }
                if (waitRes == WAIT_TIMEOUT || waitRes == WAIT_OBJECT_0)
                {
                    DWORD availBytes = 0U;
                    if (PeekNamedPipe(pipeHandle, nullptr, 0U, nullptr, &availBytes, nullptr) == FALSE)
                    {
                        disconnectedByPeer = true;
                        break;
                    }
                    if (availBytes >= sizeof(ipc::FrameIpcEnvelope))
                    {
                        ipc::FrameIpcDisconnectNotice notice{};
                        const DWORD noticeErr = ReadExactOverlapped(
                            pipeHandle,
                            ioEvent.Get(),
                            stopEvent,
                            &notice,
                            sizeof(notice),
                            50U);
                        if (noticeErr == ERROR_SUCCESS || IsPeerDisconnectWin32Error(noticeErr))
                        {
                            disconnectedByPeer = true;
                            break;
                        }
                    }
                }
                continue;
            }

            const size_t payloadBytes = frame->Pixels.size();
            if (payloadBytes == 0U || payloadBytes > ipc::kMaxFramePayloadBytes)
            {
                RecycleBufferSlot(std::move(frame));
                continue;
            }

            ipc::FrameIpcFrameHeader header{};
            header.Envelope = ipc::InitEnvelope(
                ipc::FrameIpcMessageType::FrameHeader,
                static_cast<uint32_t>(sizeof(ipc::FrameIpcFrameHeader)));
            header.SessionId = sessionId;
            header.FrameSequence = frame->FrameSequence;
            header.PresentationFrameNumber = frame->PresentationFrameNumber;
            header.Width = frame->Width;
            header.Height = frame->Height;
            header.RowPitchBytes = frame->RowPitchBytes;
            header.PixelFormat = frame->Format;
            header.Flags = frame->Flags;
            header.DirtyRectCount = frame->DirtyRectCount;
            header.MoveRegionCount = frame->MoveRegionCount;
            header.PresentDisplayQpcTime = frame->PresentDisplayQpcTime;
            header.ExtractCompleteQpcTime = frame->ExtractCompleteQpcTime;
            header.ServerSendQpcTime = QueryCurrentQpc();
            header.QpcFrequency = (frame->QpcFrequency > 0ULL) ? frame->QpcFrequency : qpcFreq;
            header.PayloadSizeBytes = static_cast<uint32_t>(payloadBytes);
            header.PayloadCrc32 = frame->PayloadCrc32;

            const uint64_t sentSeq = frame->FrameSequence;
            const uint64_t extractQpc = frame->ExtractCompleteQpcTime;
            const uint64_t frameQpcFreq = header.QpcFrequency;

            DWORD ioErr = WriteExactOverlapped(
                pipeHandle,
                ioEvent.Get(),
                stopEvent,
                &header,
                sizeof(header),
                m_config.IoTimeoutMs);
            if (ioErr == ERROR_SUCCESS)
            {
                ioErr = WriteExactOverlapped(
                    pipeHandle,
                    ioEvent.Get(),
                    stopEvent,
                    frame->Pixels.data(),
                    payloadBytes,
                    m_config.IoTimeoutMs);
            }

            RecycleBufferSlot(std::move(frame));

            if (ioErr != ERROR_SUCCESS)
            {
                if (ioErr == ERROR_OPERATION_ABORTED)
                {
                    break;
                }
                {
                    ExclusiveLock metricsGuard(&m_metricsLock);
                    ++m_transportMetrics.FrameTransportFailures;
                    m_transportMetrics.LastTransportError = HRESULT_FROM_WIN32(ioErr);
                }
                disconnectedByPeer = true;
                break;
            }

            if (m_config.RequireClientAck)
            {
                ipc::FrameIpcFrameAck ack{};
                const DWORD ackErr = ReadExactOverlapped(
                    pipeHandle,
                    ioEvent.Get(),
                    stopEvent,
                    &ack,
                    sizeof(ack),
                    m_config.IoTimeoutMs);
                if (ackErr != ERROR_SUCCESS)
                {
                    if (ackErr == ERROR_OPERATION_ABORTED)
                    {
                        break;
                    }
                    {
                        ExclusiveLock metricsGuard(&m_metricsLock);
                        ++m_transportMetrics.FrameTransportFailures;
                        m_transportMetrics.LastTransportError = HRESULT_FROM_WIN32(ackErr);
                    }
                    disconnectedByPeer = true;
                    break;
                }

                const ipc::FrameIpcStatus ackStatus = ipc::ValidateFrameAck(&ack, sizeof(ack), sessionId);
                if (ackStatus != ipc::FrameIpcStatus::Ok || ack.FrameSequence != sentSeq)
                {
                    {
                        ExclusiveLock metricsGuard(&m_metricsLock);
                        ++m_transportMetrics.FrameTransportFailures;
                        m_transportMetrics.LastTransportError = E_FAIL;
                    }
                    disconnectedByPeer = true;
                    break;
                }
            }

            const uint64_t deliveredQpc = QueryCurrentQpc();
            const uint64_t deliveryTicks = (deliveredQpc >= extractQpc) ? (deliveredQpc - extractQpc) : 0ULL;
            const uint64_t deliveryLatencyUs =
                (deliveryTicks * 1000000ULL) / ((frameQpcFreq > 0ULL) ? frameQpcFreq : qpcFreq);

            {
                ExclusiveLock metricsGuard(&m_metricsLock);
                ++m_transportMetrics.FramesDelivered;
                m_transportMetrics.LastDeliveredFrameSequence = sentSeq;
                m_transportMetrics.LastDeliveryLatencyUs = deliveryLatencyUs;
                m_transportMetrics.TotalDeliveryLatencyUs += deliveryLatencyUs;
                m_transportMetrics.AvgDeliveryLatencyUs =
                    m_transportMetrics.TotalDeliveryLatencyUs / m_transportMetrics.FramesDelivered;
                if (deliveryLatencyUs > m_transportMetrics.MaxDeliveryLatencyUs)
                {
                    m_transportMetrics.MaxDeliveryLatencyUs = deliveryLatencyUs;
                }
            }
        }

        if (!disconnectedByPeer && InterlockedCompareExchange(&m_stopRequested, 0, 0) != 0)
        {
            ipc::FrameIpcDisconnectNotice notice{};
            notice.Envelope = ipc::InitEnvelope(
                ipc::FrameIpcMessageType::DisconnectNotice,
                static_cast<uint32_t>(sizeof(ipc::FrameIpcDisconnectNotice)));
            notice.SessionId = sessionId;
            notice.ReasonCode = static_cast<uint32_t>(ipc::FrameIpcStatus::ServerStopping);

            OVERLAPPED ov{};
            ov.hEvent = ioEvent.Get();
            (void)ResetEvent(ioEvent.Get());
            DWORD unusedWritten = 0U;
            if (WriteFile(pipeHandle, &notice, sizeof(notice), &unusedWritten, &ov) == FALSE &&
                GetLastError() == ERROR_IO_PENDING)
            {
                (void)WaitForSingleObject(ioEvent.Get(), 50U);
                (void)CancelIoEx(pipeHandle, &ov);
                (void)GetOverlappedResult(pipeHandle, &ov, &unusedWritten, TRUE);
            }
        }

        (void)DisconnectNamedPipe(pipeHandle);

        {
            ExclusiveLock metricsGuard(&m_metricsLock);
            ++m_transportMetrics.ClientDisconnects;
            m_transportMetrics.ActiveHostConnections = 0U;
            m_transportMetrics.ActiveSessionId = 0ULL;
        }
    }
}

} // namespace lumabridge::driver
