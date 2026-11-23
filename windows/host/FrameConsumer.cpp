#include "FrameConsumer.h"

#include <algorithm>
#include <cstring>
#include <new>

namespace lumabridge::host {

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

bool
IsStopSignaled(
    HANDLE stopEvent
    ) noexcept
{
    return (stopEvent != nullptr) && (WaitForSingleObject(stopEvent, 0U) == WAIT_OBJECT_0);
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
WaitOverlappedWithOptionalStop(
    HANDLE pipeHandle,
    OVERLAPPED& ov,
    HANDLE stopEvent,
    DWORD initialErr,
    DWORD timeoutMs,
    DWORD& outBytesTransferred
    ) noexcept
{
    outBytesTransferred = 0U;
    if (initialErr != ERROR_IO_PENDING)
    {
        return initialErr;
    }

    DWORD waitResult = WAIT_FAILED;
    if (stopEvent != nullptr)
    {
        const HANDLE handles[2] = {ov.hEvent, stopEvent};
        waitResult = WaitForMultipleObjects(2U, handles, FALSE, timeoutMs);
    }
    else
    {
        waitResult = WaitForSingleObject(ov.hEvent, timeoutMs);
    }

    if (waitResult == WAIT_OBJECT_0)
    {
        if (GetOverlappedResult(pipeHandle, &ov, &outBytesTransferred, FALSE) != FALSE)
        {
            return ERROR_SUCCESS;
        }
        return GetLastError();
    }

    (void)CancelIoEx(pipeHandle, &ov);
    DWORD cancelledBytes = 0U;
    const BOOL gotCancelledResult = GetOverlappedResult(pipeHandle, &ov, &cancelledBytes, TRUE);

    if (stopEvent != nullptr && waitResult == WAIT_OBJECT_0 + 1)
    {
        return ERROR_OPERATION_ABORTED;
    }
    if (waitResult == WAIT_TIMEOUT)
    {
        if (gotCancelledResult != FALSE && cancelledBytes > 0U)
        {
            outBytesTransferred = cancelledBytes;
            return ERROR_SUCCESS;
        }
        return ERROR_TIMEOUT;
    }
    return ERROR_GEN_FAILURE;
}

DWORD
ReadExactOverlapped(
    HANDLE pipeHandle,
    HANDLE ioEvent,
    HANDLE stopEvent,
    void* buffer,
    size_t totalBytes,
    DWORD timeoutMs,
    size_t& outBytesTransferred
    ) noexcept
{
    outBytesTransferred = 0U;
    if (buffer == nullptr && totalBytes > 0U)
    {
        return ERROR_INVALID_PARAMETER;
    }

    uint8_t* dst = static_cast<uint8_t*>(buffer);
    size_t offset = 0U;
    while (offset < totalBytes)
    {
        if (IsStopSignaled(stopEvent))
        {
            outBytesTransferred = offset;
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
                outBytesTransferred = offset;
                return ERROR_BROKEN_PIPE;
            }
            offset += static_cast<size_t>(bytesRead);
            continue;
        }

        const DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING)
        {
            outBytesTransferred = offset;
            return err;
        }

        DWORD overlappedBytes = 0U;
        const DWORD waitErr = WaitOverlappedWithOptionalStop(
            pipeHandle,
            ov,
            stopEvent,
            err,
            timeoutMs,
            overlappedBytes);
        if (waitErr != ERROR_SUCCESS)
        {
            outBytesTransferred = offset + static_cast<size_t>(overlappedBytes);
            return waitErr;
        }
        if (overlappedBytes == 0U)
        {
            outBytesTransferred = offset;
            return ERROR_BROKEN_PIPE;
        }
        offset += static_cast<size_t>(overlappedBytes);
    }

    outBytesTransferred = offset;
    return ERROR_SUCCESS;
}

DWORD
WriteExactOverlapped(
    HANDLE pipeHandle,
    HANDLE ioEvent,
    HANDLE stopEvent,
    const void* buffer,
    size_t totalBytes,
    DWORD timeoutMs,
    size_t& outBytesTransferred
    ) noexcept
{
    outBytesTransferred = 0U;
    if (buffer == nullptr && totalBytes > 0U)
    {
        return ERROR_INVALID_PARAMETER;
    }

    const uint8_t* src = static_cast<const uint8_t*>(buffer);
    size_t offset = 0U;
    while (offset < totalBytes)
    {
        if (IsStopSignaled(stopEvent))
        {
            outBytesTransferred = offset;
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
                outBytesTransferred = offset;
                return ERROR_BROKEN_PIPE;
            }
            offset += static_cast<size_t>(bytesWritten);
            continue;
        }

        const DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING)
        {
            outBytesTransferred = offset;
            return err;
        }

        DWORD overlappedBytes = 0U;
        const DWORD waitErr = WaitOverlappedWithOptionalStop(
            pipeHandle,
            ov,
            stopEvent,
            err,
            timeoutMs,
            overlappedBytes);
        if (waitErr != ERROR_SUCCESS)
        {
            outBytesTransferred = offset + static_cast<size_t>(overlappedBytes);
            return waitErr;
        }
        if (overlappedBytes == 0U)
        {
            outBytesTransferred = offset;
            return ERROR_BROKEN_PIPE;
        }
        offset += static_cast<size_t>(overlappedBytes);
    }

    outBytesTransferred = offset;
    return ERROR_SUCCESS;
}

size_t
NearestRankIndex(
    size_t sampleCount,
    size_t percentile
    ) noexcept
{
    if (sampleCount == 0U)
    {
        return 0U;
    }
    const size_t rank = (percentile * sampleCount + 99U) / 100U;
    if (rank == 0U)
    {
        return 0U;
    }
    const size_t idx = rank - 1U;
    return (idx < sampleCount) ? idx : (sampleCount - 1U);
}

} // namespace

LatencySummaryStats
ComputeLatencySummary(
    const std::vector<uint64_t>& samples,
    uint64_t lastUs
    ) noexcept
{
    LatencySummaryStats out{};
    out.LastUs = lastUs;
    if (samples.empty())
    {
        return out;
    }

    std::vector<uint64_t> sorted;
    try
    {
        sorted = samples;
    }
    catch (...)
    {
        return out;
    }

    std::sort(sorted.begin(), sorted.end());
    uint64_t sum = 0ULL;
    for (uint64_t v : sorted)
    {
        sum += v;
    }

    const size_t n = sorted.size();
    out.SampleCount = static_cast<uint64_t>(n);
    out.MinUs = sorted.front();
    out.MaxUs = sorted.back();
    out.AvgUs = sum / n;
    out.P50Us = sorted[NearestRankIndex(n, 50U)];
    out.P95Us = sorted[NearestRankIndex(n, 95U)];
    out.P99Us = sorted[NearestRankIndex(n, 99U)];
    return out;
}

ValidatedFrameIntervals
ComputeValidatedFrameIntervals(
    const ipc::FrameIpcFrameHeader& header,
    uint64_t recvPayloadQpc,
    uint64_t ackCompleteQpc,
    uint64_t consumerQpcFreq,
    bool sentAck
    ) noexcept
{
    ValidatedFrameIntervals out{};
    out.PreConnectQueued =
        ((header.Flags & static_cast<uint32_t>(ipc::FrameIpcFlags::PreConnectQueuedFrame)) != 0U);

    if (header.QpcFrequency == 0ULL ||
        consumerQpcFreq == 0ULL ||
        header.QpcFrequency != consumerQpcFreq)
    {
        out.Valid = false;
        out.QpcFrequencyMismatch = true;
        return out;
    }

    if (header.ExtractCompleteQpcTime == 0ULL ||
        header.ServerSendQpcTime == 0ULL ||
        recvPayloadQpc == 0ULL ||
        header.ServerSendQpcTime < header.ExtractCompleteQpcTime ||
        recvPayloadQpc < header.ServerSendQpcTime ||
        (sentAck && ackCompleteQpc < recvPayloadQpc) ||
        (!sentAck && ackCompleteQpc != 0ULL && ackCompleteQpc < recvPayloadQpc) ||
        (header.PresentDisplayQpcTime > 0ULL &&
         header.ExtractCompleteQpcTime < header.PresentDisplayQpcTime))
    {
        out.Valid = false;
        out.OutOfOrderTimestamps = true;
        return out;
    }

    const uint64_t freq = consumerQpcFreq;
    out.Valid = true;
    out.CopyUs = ipc::UnpackCopyLatencyUsFromFlags(header.Flags);
    out.QueueWaitUs = ((header.ServerSendQpcTime - header.ExtractCompleteQpcTime) * 1000000ULL) / freq;
    out.IpcTransitUs = ((recvPayloadQpc - header.ServerSendQpcTime) * 1000000ULL) / freq;
    if (ackCompleteQpc >= recvPayloadQpc)
    {
        out.HostVerifyAckUs = ((ackCompleteQpc - recvPayloadQpc) * 1000000ULL) / freq;
    }
    out.EndToEndUs = ((recvPayloadQpc - header.ExtractCompleteQpcTime) * 1000000ULL) / freq;
    if (header.PresentDisplayQpcTime > 0ULL)
    {
        out.HasPresentToExtract = true;
        out.PresentToExtractUs =
            ((header.ExtractCompleteQpcTime - header.PresentDisplayQpcTime) * 1000000ULL) / freq;
    }

    return out;
}

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
    ) noexcept
{
    HostFpsBreakdown out{};
    if (totalExecutionDurationUs > 0ULL && framesValid > 0ULL)
    {
        const double execSec = static_cast<double>(totalExecutionDurationUs) / 1000000.0;
        out.AverageExecutionFps = static_cast<double>(framesValid) / execSec;
    }
    if (totalConnectedDurationUs > 0ULL && framesValid > 0ULL)
    {
        const double connSec = static_cast<double>(totalConnectedDurationUs) / 1000000.0;
        out.ConnectedFps = static_cast<double>(framesValid) / connSec;
    }

    const uint64_t activeSpanUs = ipc::ComputeQpcElapsedUs(firstValidFrameQpc, lastValidFrameQpc, qpcFreq);
    if (framesValid >= 5ULL && activeSpanUs >= 50000ULL)
    {
        out.FpsSampleSufficient = true;
        const double activeSec = static_cast<double>(activeSpanUs) / 1000000.0;
        out.ObservedActiveFps = static_cast<double>(framesValid - 1ULL) / activeSec;
    }

    const uint64_t liveSpanUs = ipc::ComputeQpcElapsedUs(firstLiveFrameQpc, lastLiveFrameQpc, qpcFreq);
    if (liveFramesValid >= 5ULL && liveSpanUs >= 50000ULL)
    {
        const double liveSec = static_cast<double>(liveSpanUs) / 1000000.0;
        out.SustainedLiveFps = static_cast<double>(liveFramesValid - 1ULL) / liveSec;
    }

    return out;
}

FrameConsumer::FrameConsumer(
    const HostConsumerConfig& config
    ) noexcept
    : m_config(config),
      m_qpcFreq(QueryQpcFrequencySafe())
{
    if (m_config.PipeName.empty())
    {
        m_config.PipeName = ipc::kDefaultFrameIpcPipeName;
    }
    if (m_config.IoTimeoutMs == 0U)
    {
        m_config.IoTimeoutMs = ipc::kDefaultIpcIoTimeoutMs;
    }
    m_metrics.QpcFrequency = m_qpcFreq;
}

FrameConsumer::~FrameConsumer()
{
    Disconnect();
    if (m_ioEvent != nullptr)
    {
        CloseHandle(m_ioEvent);
        m_ioEvent = nullptr;
    }
}

void
FrameConsumer::UpdateDerivedFpsAndLatenciesLocked(
    uint64_t nowQpc,
    uint64_t executionStartQpc
    ) noexcept
{
    if (executionStartQpc > 0ULL && nowQpc >= executionStartQpc)
    {
        m_metrics.TotalExecutionDurationUs = ipc::ComputeQpcElapsedUs(executionStartQpc, nowQpc, m_qpcFreq);
    }

    uint64_t connectedTicks = m_accumulatedConnectedTicks;
    if (m_metrics.Connected && m_sessionConnectQpc > 0ULL && nowQpc >= m_sessionConnectQpc)
    {
        connectedTicks += (nowQpc - m_sessionConnectQpc);
    }
    m_metrics.TotalConnectedDurationUs = (connectedTicks * 1000000ULL) / m_qpcFreq;

    const HostFpsBreakdown fps = ComputeHostFpsBreakdown(
        m_metrics.FramesValid,
        m_metrics.LiveFramesReceived,
        m_metrics.TotalExecutionDurationUs,
        m_metrics.TotalConnectedDurationUs,
        m_firstValidFrameQpc,
        m_lastValidFrameQpc,
        m_firstLiveFrameQpc,
        m_lastLiveFrameQpc,
        m_qpcFreq);
    m_metrics.AverageExecutionFps = fps.AverageExecutionFps;
    m_metrics.ConnectedFps = fps.ConnectedFps;
    m_metrics.ObservedActiveFps = fps.ObservedActiveFps;
    m_metrics.SustainedLiveFps = fps.SustainedLiveFps;
    m_metrics.FpsSampleSufficient = fps.FpsSampleSufficient;
    m_metrics.ReceiveFps = fps.FpsSampleSufficient ? fps.ObservedActiveFps : fps.AverageExecutionFps;

    m_metrics.CopyLatency = m_copyLat.Summarize();
    m_metrics.PresentToExtractLatency = m_presentToExtractLat.Summarize();
    m_metrics.QueueWaitLatency = m_queueWaitLat.Summarize();
    m_metrics.LiveQueueWaitLatency = m_liveQueueWaitLat.Summarize();
    m_metrics.IpcTransitLatency = m_ipcTransitLat.Summarize();
    m_metrics.HostVerifyAckLatency = m_hostVerifyAckLat.Summarize();
    m_metrics.EndToEndLatency = m_endToEndLat.Summarize();
    m_metrics.LiveEndToEndLatency = m_liveEndToEndLat.Summarize();
    m_metrics.InterFrameInterval = m_interFrameLat.Summarize();
}

HRESULT
FrameConsumer::Connect(
    DWORD timeoutMs,
    HANDLE stopEvent
    ) noexcept
{
    ClosePipeAndResetConnectionState(false);

    if (m_ioEvent == nullptr)
    {
        m_ioEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (m_ioEvent == nullptr)
        {
            const HRESULT hr = HRESULT_FROM_WIN32(GetLastError());
            ExclusiveLock lock(&m_metricsLock);
            m_metrics.LastErrorHResult = hr;
            m_metrics.TransportHealthy = false;
            return hr;
        }
    }

    const ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>(timeoutMs);
    HANDLE openedPipe = INVALID_HANDLE_VALUE;
    DWORD lastOpenErr = ERROR_FILE_NOT_FOUND;

    for (;;)
    {
        if (IsStopSignaled(stopEvent))
        {
            const HRESULT hr = HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED);
            ExclusiveLock lock(&m_metricsLock);
            m_metrics.LastErrorHResult = hr;
            return hr;
        }

        openedPipe = CreateFileW(
            m_config.PipeName.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0U,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            nullptr);
        if (openedPipe != INVALID_HANDLE_VALUE)
        {
            break;
        }

        lastOpenErr = GetLastError();
        if (lastOpenErr != ERROR_PIPE_BUSY && lastOpenErr != ERROR_FILE_NOT_FOUND)
        {
            const HRESULT hr = HRESULT_FROM_WIN32(lastOpenErr);
            ExclusiveLock lock(&m_metricsLock);
            if (lastOpenErr == ERROR_ACCESS_DENIED)
            {
                m_metrics.LastProtocolStatus = ipc::FrameIpcStatus::UnauthorizedClient;
            }
            m_metrics.LastErrorHResult = hr;
            m_metrics.TransportHealthy = false;
            return hr;
        }

        const ULONGLONG now = GetTickCount64();
        if (now >= deadline)
        {
            const HRESULT hr = HRESULT_FROM_WIN32(
                (lastOpenErr == ERROR_PIPE_BUSY) ? ERROR_TIMEOUT : lastOpenErr);
            ExclusiveLock lock(&m_metricsLock);
            m_metrics.LastErrorHResult = hr;
            return hr;
        }

        const DWORD remaining = static_cast<DWORD>(deadline - now);
        if (lastOpenErr == ERROR_PIPE_BUSY)
        {
            const DWORD waitPipeMs = (remaining > 100U) ? 100U : remaining;
            (void)WaitNamedPipeW(m_config.PipeName.c_str(), waitPipeMs);
        }
        else
        {
            const DWORD sleepMs = (remaining > 15U) ? 15U : remaining;
            if (stopEvent != nullptr)
            {
                if (WaitForSingleObject(stopEvent, sleepMs) == WAIT_OBJECT_0)
                {
                    const HRESULT hr = HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED);
                    ExclusiveLock lock(&m_metricsLock);
                    m_metrics.LastErrorHResult = hr;
                    return hr;
                }
            }
            else
            {
                Sleep(sleepMs);
            }
        }
    }

    m_pipeHandle = openedPipe;

    DWORD clientSessionId = 0U;
    if (ProcessIdToSessionId(GetCurrentProcessId(), &clientSessionId) == FALSE)
    {
        const HRESULT hr = HRESULT_FROM_WIN32(GetLastError());
        ClosePipeAndResetConnectionState(false);
        ExclusiveLock lock(&m_metricsLock);
        m_metrics.LastErrorHResult = hr;
        m_metrics.TransportHealthy = false;
        return hr;
    }

    ipc::FrameIpcClientHello clientHello{};
    clientHello.Envelope = ipc::InitEnvelope(
        ipc::FrameIpcMessageType::ClientHello,
        static_cast<uint32_t>(sizeof(ipc::FrameIpcClientHello)));
    clientHello.ClientProcessId = GetCurrentProcessId();
    clientHello.ClientSessionId = static_cast<uint32_t>(clientSessionId);
    clientHello.ClientCapabilities = 1U;

    size_t helloWritten = 0U;
    const DWORD writeErr = WriteExactOverlapped(
        m_pipeHandle,
        m_ioEvent,
        stopEvent,
        &clientHello,
        sizeof(clientHello),
        m_config.IoTimeoutMs,
        helloWritten);
    if (writeErr != ERROR_SUCCESS)
    {
        const HRESULT hr = HRESULT_FROM_WIN32(writeErr);
        ClosePipeAndResetConnectionState(false);
        ExclusiveLock lock(&m_metricsLock);
        if (writeErr == ERROR_TIMEOUT)
        {
            ++m_metrics.FatalIoTimeouts;
            if (helloWritten > 0U && helloWritten < sizeof(clientHello))
            {
                ++m_metrics.PartialMessageTimeouts;
            }
        }
        else if (writeErr != ERROR_OPERATION_ABORTED)
        {
            ++m_metrics.FatalIpcErrors;
        }
        m_metrics.LastErrorHResult = hr;
        m_metrics.TransportHealthy = false;
        return hr;
    }

    ipc::FrameIpcServerHello serverHello{};
    size_t serverHelloRead = 0U;
    const DWORD readErr = ReadExactOverlapped(
        m_pipeHandle,
        m_ioEvent,
        stopEvent,
        &serverHello,
        sizeof(serverHello),
        m_config.IoTimeoutMs,
        serverHelloRead);
    if (readErr != ERROR_SUCCESS)
    {
        const HRESULT hr = HRESULT_FROM_WIN32(readErr);
        ClosePipeAndResetConnectionState(false);
        ExclusiveLock lock(&m_metricsLock);
        if (readErr == ERROR_TIMEOUT)
        {
            ++m_metrics.FatalIoTimeouts;
            if (serverHelloRead > 0U && serverHelloRead < sizeof(serverHello))
            {
                ++m_metrics.PartialMessageTimeouts;
            }
        }
        else if (readErr != ERROR_OPERATION_ABORTED)
        {
            ++m_metrics.FatalIpcErrors;
        }
        m_metrics.LastErrorHResult = hr;
        m_metrics.TransportHealthy = false;
        return hr;
    }

    const ipc::FrameIpcStatus status = ipc::ValidateServerHello(&serverHello, sizeof(serverHello));
    if (status != ipc::FrameIpcStatus::Ok)
    {
        const HRESULT hr = (status == ipc::FrameIpcStatus::UnauthorizedClient)
            ? E_ACCESSDENIED
            : E_FAIL;
        ClosePipeAndResetConnectionState(false);
        ExclusiveLock lock(&m_metricsLock);
        ++m_metrics.ProtocolErrors;
        m_metrics.LastProtocolStatus = status;
        m_metrics.LastErrorHResult = hr;
        m_metrics.TransportHealthy = false;
        return hr;
    }

    m_sessionId = serverHello.SessionId;
    m_sessionConnectQpc = QueryCurrentQpc();
    m_currentSessionFrames = 0ULL;

    {
        ExclusiveLock lock(&m_metricsLock);
        m_metrics.Connected = true;
        m_metrics.SessionId = serverHello.SessionId;
        m_metrics.ServerProcessId = serverHello.ServerProcessId;
        m_metrics.AdapterLuidLow = serverHello.AdapterLuidLow;
        m_metrics.AdapterLuidHigh = serverHello.AdapterLuidHigh;
        m_metrics.ServerMaxQueueDepth = serverHello.MaxQueueDepth;
        if (m_metrics.ConnectCount > 0ULL)
        {
            ++m_metrics.ReconnectCount;
        }
        ++m_metrics.ConnectCount;
        m_metrics.LastProtocolStatus = ipc::FrameIpcStatus::Ok;
        m_metrics.LastErrorHResult = S_OK;
    }

    return S_OK;
}

HRESULT
FrameConsumer::ReceiveNextFrame(
    ipc::FrameIpcFrameHeader& outHeader,
    std::vector<uint8_t>& outPixels,
    DWORD timeoutMs,
    HANDLE stopEvent
    ) noexcept
{
    outHeader = {};
    outPixels.clear();

    if (m_pipeHandle == INVALID_HANDLE_VALUE || m_ioEvent == nullptr || m_sessionId == 0ULL)
    {
        return E_NOT_VALID_STATE;
    }

    const uint64_t envWaitStartQpc = QueryCurrentQpc();
    ipc::FrameIpcEnvelope env{};
    size_t envBytesRead = 0U;
    const DWORD envErr = ReadExactOverlapped(
        m_pipeHandle,
        m_ioEvent,
        stopEvent,
        &env,
        sizeof(env),
        timeoutMs,
        envBytesRead);
    if (envErr != ERROR_SUCCESS)
    {
        const uint64_t waitDoneQpc = QueryCurrentQpc();
        const uint64_t waitUs = ipc::ComputeQpcElapsedUs(envWaitStartQpc, waitDoneQpc, m_qpcFreq);
        const HRESULT hr = HRESULT_FROM_WIN32(envErr);

        if (envErr == ERROR_TIMEOUT && envBytesRead == 0U)
        {
            // Normal idle timeout at frame message boundary (0 bytes consumed): stream remains synchronized.
            ExclusiveLock lock(&m_metricsLock);
            ++m_metrics.RecoverableIoTimeouts;
            m_metrics.TotalIdleWaitDurationUs += waitUs;
            m_metrics.LastRecoverableTimeoutHResult = hr;
            return hr;
        }

        if (envErr == ERROR_OPERATION_ABORTED && envBytesRead == 0U)
        {
            return hr;
        }

        ClosePipeAndResetConnectionState(false);
        ExclusiveLock lock(&m_metricsLock);
        if (envErr == ERROR_TIMEOUT)
        {
            // Partial envelope consumed before timeout: closing pipe prevents frame desync.
            ++m_metrics.FatalIoTimeouts;
            ++m_metrics.PartialMessageTimeouts;
            ++m_metrics.FatalIpcErrors;
            m_metrics.TransportHealthy = false;
        }
        else if (IsPeerDisconnectWin32Error(envErr))
        {
            ++m_metrics.DisconnectCount;
            if (envBytesRead > 0U)
            {
                ++m_metrics.FatalIpcErrors;
                m_metrics.TransportHealthy = false;
            }
        }
        else if (envErr != ERROR_OPERATION_ABORTED)
        {
            ++m_metrics.FatalIpcErrors;
            m_metrics.TransportHealthy = false;
        }
        m_metrics.LastErrorHResult = hr;
        return hr;
    }

    if (env.Magic == ipc::kFrameIpcMagic &&
        env.MessageType == static_cast<uint16_t>(ipc::FrameIpcMessageType::DisconnectNotice) &&
        env.HeaderSizeBytes == sizeof(ipc::FrameIpcDisconnectNotice))
    {
        ipc::FrameIpcDisconnectNotice notice{};
        std::memcpy(&notice.Envelope, &env, sizeof(env));
        size_t noticeBytesRead = 0U;
        (void)ReadExactOverlapped(
            m_pipeHandle,
            m_ioEvent,
            stopEvent,
            reinterpret_cast<uint8_t*>(&notice) + sizeof(env),
            sizeof(notice) - sizeof(env),
            50U,
            noticeBytesRead);
        ClosePipeAndResetConnectionState(false);
        ExclusiveLock lock(&m_metricsLock);
        ++m_metrics.DisconnectCount;
        return S_FALSE;
    }

    if (env.Magic != ipc::kFrameIpcMagic ||
        env.VersionMajor != ipc::kFrameIpcProtocolVersionMajor ||
        env.VersionMinor != ipc::kFrameIpcProtocolVersionMinor ||
        env.MessageType != static_cast<uint16_t>(ipc::FrameIpcMessageType::FrameHeader) ||
        env.HeaderSizeBytes != sizeof(ipc::FrameIpcFrameHeader))
    {
        const ipc::FrameIpcStatus badStatus =
            (env.Magic != ipc::kFrameIpcMagic) ? ipc::FrameIpcStatus::InvalidMagic :
            ((env.VersionMajor != ipc::kFrameIpcProtocolVersionMajor ||
              env.VersionMinor != ipc::kFrameIpcProtocolVersionMinor)
                ? ipc::FrameIpcStatus::VersionMismatch
                : ipc::FrameIpcStatus::InvalidLength);
        ClosePipeAndResetConnectionState(false);
        ExclusiveLock lock(&m_metricsLock);
        ++m_metrics.ProtocolErrors;
        ++m_metrics.FatalIpcErrors;
        m_metrics.TransportHealthy = false;
        m_metrics.LastProtocolStatus = badStatus;
        m_metrics.LastErrorHResult = E_FAIL;
        return E_FAIL;
    }

    std::memcpy(&outHeader.Envelope, &env, sizeof(env));
    size_t hdrBytesRead = 0U;
    const DWORD hdrErr = ReadExactOverlapped(
        m_pipeHandle,
        m_ioEvent,
        stopEvent,
        reinterpret_cast<uint8_t*>(&outHeader) + sizeof(env),
        sizeof(outHeader) - sizeof(env),
        m_config.IoTimeoutMs,
        hdrBytesRead);
    if (hdrErr != ERROR_SUCCESS)
    {
        const HRESULT hr = HRESULT_FROM_WIN32(hdrErr);
        ClosePipeAndResetConnectionState(false);
        ExclusiveLock lock(&m_metricsLock);
        if (hdrErr == ERROR_TIMEOUT)
        {
            ++m_metrics.FatalIoTimeouts;
            ++m_metrics.PartialMessageTimeouts;
        }
        if (hdrErr != ERROR_OPERATION_ABORTED)
        {
            ++m_metrics.FatalIpcErrors;
            m_metrics.TransportHealthy = false;
        }
        m_metrics.LastErrorHResult = hr;
        return hr;
    }

    const ipc::FrameIpcStatus headerStatus = ipc::ValidateFrameHeader(
        &outHeader,
        sizeof(outHeader),
        m_sessionId);
    if (headerStatus != ipc::FrameIpcStatus::Ok)
    {
        ClosePipeAndResetConnectionState(false);
        ExclusiveLock lock(&m_metricsLock);
        ++m_metrics.ProtocolErrors;
        ++m_metrics.FatalIpcErrors;
        m_metrics.TransportHealthy = false;
        m_metrics.LastProtocolStatus = headerStatus;
        m_metrics.LastErrorHResult = E_INVALIDARG;
        return E_INVALIDARG;
    }

    try
    {
        outPixels.resize(outHeader.PayloadSizeBytes);
    }
    catch (const std::bad_alloc&)
    {
        ClosePipeAndResetConnectionState(false);
        ExclusiveLock lock(&m_metricsLock);
        ++m_metrics.FatalIpcErrors;
        m_metrics.TransportHealthy = false;
        m_metrics.LastErrorHResult = E_OUTOFMEMORY;
        return E_OUTOFMEMORY;
    }

    size_t payloadBytesRead = 0U;
    const DWORD payloadErr = ReadExactOverlapped(
        m_pipeHandle,
        m_ioEvent,
        stopEvent,
        outPixels.data(),
        outPixels.size(),
        m_config.IoTimeoutMs,
        payloadBytesRead);
    if (payloadErr != ERROR_SUCCESS)
    {
        const HRESULT hr = HRESULT_FROM_WIN32(payloadErr);
        ClosePipeAndResetConnectionState(false);
        ExclusiveLock lock(&m_metricsLock);
        if (payloadErr == ERROR_TIMEOUT)
        {
            ++m_metrics.FatalIoTimeouts;
            ++m_metrics.PartialMessageTimeouts;
        }
        if (payloadErr != ERROR_OPERATION_ABORTED)
        {
            ++m_metrics.FatalIpcErrors;
            m_metrics.TransportHealthy = false;
        }
        m_metrics.LastErrorHResult = hr;
        return hr;
    }

    const uint64_t recvPayloadQpc = QueryCurrentQpc();
    const uint32_t actualCrc = ipc::ComputeFrameCrc32(outPixels.data(), outPixels.size());
    const bool crcOk = (actualCrc == outHeader.PayloadCrc32);
    bool patternOk = true;
    if (m_config.VerifySyntheticPattern)
    {
        patternOk = ipc::VerifySyntheticTestPatternBgra8(
            outHeader.PresentationFrameNumber,
            outHeader.Width,
            outHeader.Height,
            outPixels.data(),
            outPixels.size());
    }

    if (m_config.SendAck)
    {
        ipc::FrameIpcFrameAck ack{};
        ack.Envelope = ipc::InitEnvelope(
            ipc::FrameIpcMessageType::FrameAck,
            static_cast<uint32_t>(sizeof(ipc::FrameIpcFrameAck)));
        ack.SessionId = m_sessionId;
        ack.FrameSequence = outHeader.FrameSequence;
        ack.PresentationFrameNumber = outHeader.PresentationFrameNumber;
        ack.Status = static_cast<uint32_t>(
            crcOk ? ipc::FrameIpcStatus::Ok : ipc::FrameIpcStatus::ChecksumMismatch);
        ack.HostReceiveQpcTime = recvPayloadQpc;

        size_t ackBytesWritten = 0U;
        const DWORD ackErr = WriteExactOverlapped(
            m_pipeHandle,
            m_ioEvent,
            stopEvent,
            &ack,
            sizeof(ack),
            m_config.IoTimeoutMs,
            ackBytesWritten);
        if (ackErr != ERROR_SUCCESS)
        {
            const HRESULT hr = HRESULT_FROM_WIN32(ackErr);
            ClosePipeAndResetConnectionState(false);
            ExclusiveLock lock(&m_metricsLock);
            if (ackErr == ERROR_TIMEOUT)
            {
                ++m_metrics.FatalIoTimeouts;
            }
            if (ackErr != ERROR_OPERATION_ABORTED)
            {
                ++m_metrics.FatalIpcErrors;
                m_metrics.TransportHealthy = false;
            }
            m_metrics.LastErrorHResult = hr;
            return hr;
        }
    }

    const uint64_t ackCompleteQpc = QueryCurrentQpc();
    const ValidatedFrameIntervals intervals = ComputeValidatedFrameIntervals(
        outHeader,
        recvPayloadQpc,
        ackCompleteQpc,
        m_qpcFreq,
        m_config.SendAck);

    {
        ExclusiveLock lock(&m_metricsLock);
        if (m_metrics.LastFrameSequence != 0ULL &&
            outHeader.FrameSequence > (m_metrics.LastFrameSequence + 1ULL))
        {
            m_metrics.SequenceGapsDetected += (outHeader.FrameSequence - m_metrics.LastFrameSequence - 1ULL);
        }

        ++m_metrics.FramesReceived;
        ++m_currentSessionFrames;
        if (m_currentSessionFrames > m_metrics.MaxFramesPerSession)
        {
            m_metrics.MaxFramesPerSession = m_currentSessionFrames;
        }
        m_metrics.BytesReceived += static_cast<uint64_t>(outPixels.size()) + sizeof(outHeader);

        if (!crcOk)
        {
            ++m_metrics.ChecksumMismatches;
            m_metrics.LastProtocolStatus = ipc::FrameIpcStatus::ChecksumMismatch;
            m_metrics.TransportHealthy = false;
        }
        if (!patternOk)
        {
            ++m_metrics.SyntheticPatternMismatches;
            m_metrics.TransportHealthy = false;
        }

        const bool frameValid = crcOk && patternOk;
        if (frameValid)
        {
            ++m_metrics.FramesValid;
            if (m_firstValidFrameQpc == 0ULL)
            {
                m_firstValidFrameQpc = recvPayloadQpc;
            }
            m_lastValidFrameQpc = recvPayloadQpc;

            if (intervals.PreConnectQueued)
            {
                ++m_metrics.PreConnectFramesReceived;
            }
            else
            {
                ++m_metrics.LiveFramesReceived;
                if (m_firstLiveFrameQpc == 0ULL)
                {
                    m_firstLiveFrameQpc = recvPayloadQpc;
                }
                m_lastLiveFrameQpc = recvPayloadQpc;
            }

            if (m_prevValidRecvQpc > 0ULL)
            {
                if (recvPayloadQpc >= m_prevValidRecvQpc)
                {
                    m_interFrameLat.Record(
                        ipc::ComputeQpcElapsedUs(m_prevValidRecvQpc, recvPayloadQpc, m_qpcFreq));
                }
                else
                {
                    ++m_metrics.TimestampMeasurementErrors;
                }
            }
            m_prevValidRecvQpc = recvPayloadQpc;
        }

        m_metrics.LastFrameSequence = outHeader.FrameSequence;
        m_metrics.LastPresentationFrameNumber = outHeader.PresentationFrameNumber;
        m_metrics.LastFrameWidth = outHeader.Width;
        m_metrics.LastFrameHeight = outHeader.Height;
        m_metrics.LastPixelFormat = outHeader.PixelFormat;
        m_metrics.LastFrameChecksumCrc32 = actualCrc;

        if (!intervals.Valid)
        {
            ++m_metrics.TimestampMeasurementErrors;
        }
        else
        {
            m_copyLat.Record(intervals.CopyUs);
            if (intervals.HasPresentToExtract)
            {
                m_presentToExtractLat.Record(intervals.PresentToExtractUs);
            }
            m_queueWaitLat.Record(intervals.QueueWaitUs);
            m_ipcTransitLat.Record(intervals.IpcTransitUs);
            m_hostVerifyAckLat.Record(intervals.HostVerifyAckUs);
            m_endToEndLat.Record(intervals.EndToEndUs);

            if (!intervals.PreConnectQueued)
            {
                m_liveQueueWaitLat.Record(intervals.QueueWaitUs);
                m_liveEndToEndLat.Record(intervals.EndToEndUs);
            }

            m_metrics.LastEndToEndLatencyUs = intervals.EndToEndUs;
            m_metrics.TotalEndToEndLatencyUs += intervals.EndToEndUs;
            m_metrics.AvgEndToEndLatencyUs =
                (m_endToEndLat.Count > 0ULL) ? (m_metrics.TotalEndToEndLatencyUs / m_endToEndLat.Count) : 0ULL;
            if (intervals.EndToEndUs > m_metrics.MaxEndToEndLatencyUs)
            {
                m_metrics.MaxEndToEndLatencyUs = intervals.EndToEndUs;
            }
            m_metrics.LastIpcTransitLatencyUs = intervals.IpcTransitUs;
        }

        UpdateDerivedFpsAndLatenciesLocked(ackCompleteQpc, m_executionStartQpc);
    }

    if (!crcOk)
    {
        return HRESULT_FROM_WIN32(ERROR_CRC);
    }

    return S_OK;
}

HRESULT
FrameConsumer::RunLoop(
    HANDLE stopEvent,
    const std::function<void(const ipc::FrameIpcFrameHeader&, const std::vector<uint8_t>&)>& onFrame
    ) noexcept
{
    const ULONGLONG startTick = GetTickCount64();
    const uint64_t execStartQpc = QueryCurrentQpc();
    m_executionStartQpc = execStartQpc;

    std::vector<uint8_t> pixels;
    HRESULT finalHr = S_OK;
    HostExitReason finalReason = HostExitReason::None;
    bool normalExit = false;

    for (;;)
    {
        if (IsStopSignaled(stopEvent))
        {
            finalReason = HostExitReason::StopRequested;
            normalExit = true;
            break;
        }

        DWORD stepTimeoutMs = m_config.IoTimeoutMs;
        if (m_config.MaxDurationMs > 0U)
        {
            const ULONGLONG elapsedMs = GetTickCount64() - startTick;
            if (elapsedMs >= static_cast<ULONGLONG>(m_config.MaxDurationMs))
            {
                finalReason = HostExitReason::DurationElapsed;
                normalExit = true;
                break;
            }
            const ULONGLONG remainingMs = static_cast<ULONGLONG>(m_config.MaxDurationMs) - elapsedMs;
            if (remainingMs < static_cast<ULONGLONG>(stepTimeoutMs))
            {
                stepTimeoutMs = static_cast<DWORD>(remainingMs > 0ULL ? remainingMs : 1ULL);
            }
        }

        if (m_pipeHandle == INVALID_HANDLE_VALUE)
        {
            const DWORD connectTimeout = (m_config.MaxDurationMs > 0U && stepTimeoutMs < m_config.ConnectTimeoutMs)
                ? stepTimeoutMs
                : m_config.ConnectTimeoutMs;
            const HRESULT connectHr = Connect(connectTimeout, stopEvent);
            if (FAILED(connectHr))
            {
                finalHr = connectHr;
                finalReason = (connectHr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED))
                    ? HostExitReason::StopRequested
                    : HostExitReason::ConnectFailed;
                if (!m_config.AutoReconnect || IsStopSignaled(stopEvent))
                {
                    break;
                }
                if (stopEvent != nullptr)
                {
                    if (WaitForSingleObject(stopEvent, 100U) == WAIT_OBJECT_0)
                    {
                        finalReason = HostExitReason::StopRequested;
                        normalExit = true;
                        finalHr = S_OK;
                        break;
                    }
                }
                else
                {
                    Sleep(100U);
                }
                continue;
            }
        }

        ipc::FrameIpcFrameHeader header{};
        const HRESULT recvHr = ReceiveNextFrame(
            header,
            pixels,
            stepTimeoutMs,
            stopEvent);
        const bool stillConnected = (m_pipeHandle != INVALID_HANDLE_VALUE && m_sessionId != 0ULL);

        if (recvHr == HRESULT_FROM_WIN32(ERROR_TIMEOUT) && stillConnected)
        {
            continue;
        }
        if (recvHr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED))
        {
            finalReason = HostExitReason::StopRequested;
            normalExit = true;
            break;
        }
        if (recvHr == S_FALSE)
        {
            finalHr = S_OK;
            finalReason = HostExitReason::PeerDisconnected;
            if (!m_config.AutoReconnect || IsStopSignaled(stopEvent))
            {
                normalExit = true;
                break;
            }
            continue;
        }
        if (FAILED(recvHr))
        {
            finalHr = recvHr;
            if (recvHr == HRESULT_FROM_WIN32(ERROR_TIMEOUT))
            {
                finalReason = HostExitReason::FatalIoTimeout;
            }
            else if (recvHr == HRESULT_FROM_WIN32(ERROR_CRC))
            {
                finalReason = HostExitReason::FatalIntegrityError;
            }
            else if (recvHr == E_OUTOFMEMORY)
            {
                finalReason = HostExitReason::OutOfMemory;
            }
            else if (recvHr == E_FAIL || recvHr == E_INVALIDARG)
            {
                finalReason = HostExitReason::FatalProtocolError;
            }
            else
            {
                finalReason = HostExitReason::PeerDisconnected;
            }

            if (!m_config.AutoReconnect || IsStopSignaled(stopEvent))
            {
                break;
            }
            continue;
        }

        if (onFrame)
        {
            onFrame(header, pixels);
        }

        const HostConsumerMetricsSnapshot snap = GetMetricsSnapshot();
        if (m_config.MaxFrames > 0ULL && snap.FramesValid >= m_config.MaxFrames)
        {
            finalHr = S_OK;
            finalReason = HostExitReason::FrameTargetReached;
            normalExit = true;
            break;
        }
    }

    if (normalExit)
    {
        if (finalReason == HostExitReason::DurationElapsed && m_metrics.ConnectCount == 0ULL && FAILED(finalHr))
        {
            finalReason = HostExitReason::ConnectFailed;
            normalExit = false;
        }
        else if (finalReason == HostExitReason::DurationElapsed && m_metrics.ConnectCount > 0ULL && m_metrics.TransportHealthy)
        {
            finalHr = S_OK;
        }
        else if (finalReason == HostExitReason::DurationElapsed && !m_metrics.TransportHealthy)
        {
            normalExit = false;
        }
    }

    Disconnect();

    const uint64_t endQpc = QueryCurrentQpc();
    {
        ExclusiveLock lock(&m_metricsLock);
        UpdateDerivedFpsAndLatenciesLocked(endQpc, execStartQpc);
        m_metrics.ExitReason = finalReason;
        m_metrics.HostProcessExitedNormally = normalExit;
        m_metrics.FrameTargetReached =
            (m_config.MaxFrames > 0ULL) && (m_metrics.FramesValid >= m_config.MaxFrames);
        m_metrics.MinFramesReached = (m_metrics.FramesValid >= m_config.MinFrames);
        if (m_metrics.FatalIoTimeouts > 0ULL ||
            m_metrics.FatalIpcErrors > 0ULL ||
            m_metrics.ProtocolErrors > 0ULL ||
            m_metrics.ChecksumMismatches > 0ULL ||
            m_metrics.SyntheticPatternMismatches > 0ULL)
        {
            m_metrics.TransportHealthy = false;
        }
    }

    return finalHr;
}

void
FrameConsumer::Disconnect() noexcept
{
    ClosePipeAndResetConnectionState(true);
}

void
FrameConsumer::ClosePipeAndResetConnectionState(
    bool sendDisconnectNotice
    ) noexcept
{
    const bool hadSession = (m_sessionId != 0ULL) || (m_pipeHandle != INVALID_HANDLE_VALUE);
    if (m_pipeHandle != INVALID_HANDLE_VALUE)
    {
        if (sendDisconnectNotice && m_sessionId != 0ULL && m_ioEvent != nullptr)
        {
            ipc::FrameIpcDisconnectNotice notice{};
            notice.Envelope = ipc::InitEnvelope(
                ipc::FrameIpcMessageType::DisconnectNotice,
                static_cast<uint32_t>(sizeof(ipc::FrameIpcDisconnectNotice)));
            notice.SessionId = m_sessionId;
            notice.ReasonCode = static_cast<uint32_t>(ipc::FrameIpcStatus::Ok);

            OVERLAPPED ov{};
            ov.hEvent = m_ioEvent;
            (void)ResetEvent(m_ioEvent);
            DWORD written = 0U;
            if (WriteFile(m_pipeHandle, &notice, sizeof(notice), &written, &ov) == FALSE &&
                GetLastError() == ERROR_IO_PENDING)
            {
                (void)WaitForSingleObject(m_ioEvent, 50U);
                (void)CancelIoEx(m_pipeHandle, &ov);
                (void)GetOverlappedResult(m_pipeHandle, &ov, &written, TRUE);
            }
        }

        CloseHandle(m_pipeHandle);
        m_pipeHandle = INVALID_HANDLE_VALUE;
    }

    const uint64_t nowQpc = QueryCurrentQpc();
    if (m_sessionConnectQpc > 0ULL && nowQpc >= m_sessionConnectQpc)
    {
        m_accumulatedConnectedTicks += (nowQpc - m_sessionConnectQpc);
    }
    m_sessionConnectQpc = 0ULL;
    m_sessionId = 0ULL;

    if (hadSession)
    {
        ExclusiveLock lock(&m_metricsLock);
        if (m_metrics.Connected)
        {
            ++m_metrics.SessionsCompleted;
            if (m_metrics.SessionsCompleted == 1ULL || m_currentSessionFrames < m_metrics.MinFramesPerSession)
            {
                m_metrics.MinFramesPerSession = m_currentSessionFrames;
            }
            if (m_currentSessionFrames > m_metrics.MaxFramesPerSession)
            {
                m_metrics.MaxFramesPerSession = m_currentSessionFrames;
            }
        }
        m_metrics.Connected = false;
        UpdateDerivedFpsAndLatenciesLocked(nowQpc, m_executionStartQpc);
    }
}

HostConsumerMetricsSnapshot
FrameConsumer::GetMetricsSnapshot() const noexcept
{
    const uint64_t nowQpc = QueryCurrentQpc();
    SharedLock lock(&m_metricsLock);
    HostConsumerMetricsSnapshot snap = m_metrics;
    if (m_executionStartQpc > 0ULL && nowQpc >= m_executionStartQpc)
    {
        snap.TotalExecutionDurationUs = ipc::ComputeQpcElapsedUs(m_executionStartQpc, nowQpc, m_qpcFreq);
    }
    uint64_t connTicks = m_accumulatedConnectedTicks;
    if (snap.Connected && m_sessionConnectQpc > 0ULL && nowQpc >= m_sessionConnectQpc)
    {
        connTicks += (nowQpc - m_sessionConnectQpc);
    }
    snap.TotalConnectedDurationUs = (connTicks * 1000000ULL) / m_qpcFreq;
    return snap;
}

} // namespace lumabridge::host
