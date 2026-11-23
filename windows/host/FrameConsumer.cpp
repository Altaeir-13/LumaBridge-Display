#include "FrameConsumer.h"

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
    (void)GetOverlappedResult(pipeHandle, &ov, &cancelledBytes, TRUE);

    if (stopEvent != nullptr && waitResult == WAIT_OBJECT_0 + 1)
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
        if (IsStopSignaled(stopEvent))
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
        const DWORD waitErr = WaitOverlappedWithOptionalStop(
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
        if (IsStopSignaled(stopEvent))
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
        const DWORD waitErr = WaitOverlappedWithOptionalStop(
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

} // namespace

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
        return hr;
    }

    ipc::FrameIpcClientHello clientHello{};
    clientHello.Envelope = ipc::InitEnvelope(
        ipc::FrameIpcMessageType::ClientHello,
        static_cast<uint32_t>(sizeof(ipc::FrameIpcClientHello)));
    clientHello.ClientProcessId = GetCurrentProcessId();
    clientHello.ClientSessionId = static_cast<uint32_t>(clientSessionId);
    clientHello.ClientCapabilities = 1U;

    const DWORD writeErr = WriteExactOverlapped(
        m_pipeHandle,
        m_ioEvent,
        stopEvent,
        &clientHello,
        sizeof(clientHello),
        m_config.IoTimeoutMs);
    if (writeErr != ERROR_SUCCESS)
    {
        const HRESULT hr = HRESULT_FROM_WIN32(writeErr);
        ClosePipeAndResetConnectionState(false);
        ExclusiveLock lock(&m_metricsLock);
        m_metrics.LastErrorHResult = hr;
        return hr;
    }

    ipc::FrameIpcServerHello serverHello{};
    const DWORD readErr = ReadExactOverlapped(
        m_pipeHandle,
        m_ioEvent,
        stopEvent,
        &serverHello,
        sizeof(serverHello),
        m_config.IoTimeoutMs);
    if (readErr != ERROR_SUCCESS)
    {
        const HRESULT hr = HRESULT_FROM_WIN32(readErr);
        ClosePipeAndResetConnectionState(false);
        ExclusiveLock lock(&m_metricsLock);
        m_metrics.LastErrorHResult = hr;
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
        return hr;
    }

    m_sessionId = serverHello.SessionId;
    m_firstFrameQpc = 0ULL;

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

    ipc::FrameIpcEnvelope env{};
    const DWORD envErr = ReadExactOverlapped(
        m_pipeHandle,
        m_ioEvent,
        stopEvent,
        &env,
        sizeof(env),
        timeoutMs);
    if (envErr != ERROR_SUCCESS)
    {
        const HRESULT hr = HRESULT_FROM_WIN32(envErr);
        if (envErr != ERROR_TIMEOUT && envErr != ERROR_OPERATION_ABORTED)
        {
            ClosePipeAndResetConnectionState(false);
        }
        ExclusiveLock lock(&m_metricsLock);
        m_metrics.LastErrorHResult = hr;
        return hr;
    }

    if (env.Magic == ipc::kFrameIpcMagic &&
        env.MessageType == static_cast<uint16_t>(ipc::FrameIpcMessageType::DisconnectNotice) &&
        env.HeaderSizeBytes == sizeof(ipc::FrameIpcDisconnectNotice))
    {
        ipc::FrameIpcDisconnectNotice notice{};
        std::memcpy(&notice.Envelope, &env, sizeof(env));
        (void)ReadExactOverlapped(
            m_pipeHandle,
            m_ioEvent,
            stopEvent,
            reinterpret_cast<uint8_t*>(&notice) + sizeof(env),
            sizeof(notice) - sizeof(env),
            50U);
        ClosePipeAndResetConnectionState(false);
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
        m_metrics.LastProtocolStatus = badStatus;
        m_metrics.LastErrorHResult = E_FAIL;
        return E_FAIL;
    }

    std::memcpy(&outHeader.Envelope, &env, sizeof(env));
    const DWORD hdrErr = ReadExactOverlapped(
        m_pipeHandle,
        m_ioEvent,
        stopEvent,
        reinterpret_cast<uint8_t*>(&outHeader) + sizeof(env),
        sizeof(outHeader) - sizeof(env),
        m_config.IoTimeoutMs);
    if (hdrErr != ERROR_SUCCESS)
    {
        const HRESULT hr = HRESULT_FROM_WIN32(hdrErr);
        ClosePipeAndResetConnectionState(false);
        ExclusiveLock lock(&m_metricsLock);
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
        return E_OUTOFMEMORY;
    }

    const DWORD payloadErr = ReadExactOverlapped(
        m_pipeHandle,
        m_ioEvent,
        stopEvent,
        outPixels.data(),
        outPixels.size(),
        m_config.IoTimeoutMs);
    if (payloadErr != ERROR_SUCCESS)
    {
        const HRESULT hr = HRESULT_FROM_WIN32(payloadErr);
        ClosePipeAndResetConnectionState(false);
        ExclusiveLock lock(&m_metricsLock);
        m_metrics.LastErrorHResult = hr;
        return hr;
    }

    const uint64_t recvQpc = QueryCurrentQpc();
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
        ack.HostReceiveQpcTime = recvQpc;

        const DWORD ackErr = WriteExactOverlapped(
            m_pipeHandle,
            m_ioEvent,
            stopEvent,
            &ack,
            sizeof(ack),
            m_config.IoTimeoutMs);
        if (ackErr != ERROR_SUCCESS)
        {
            const HRESULT hr = HRESULT_FROM_WIN32(ackErr);
            ClosePipeAndResetConnectionState(false);
            ExclusiveLock lock(&m_metricsLock);
            m_metrics.LastErrorHResult = hr;
            return hr;
        }
    }

    const uint64_t effectiveQpcFreq = (outHeader.QpcFrequency > 0ULL) ? outHeader.QpcFrequency : m_qpcFreq;
    const uint64_t endToEndTicks = (outHeader.ExtractCompleteQpcTime > 0ULL && recvQpc >= outHeader.ExtractCompleteQpcTime)
        ? (recvQpc - outHeader.ExtractCompleteQpcTime)
        : 0ULL;
    const uint64_t endToEndUs = (endToEndTicks * 1000000ULL) / effectiveQpcFreq;
    const uint64_t transitTicks = (outHeader.ServerSendQpcTime > 0ULL && recvQpc >= outHeader.ServerSendQpcTime)
        ? (recvQpc - outHeader.ServerSendQpcTime)
        : 0ULL;
    const uint64_t transitUs = (transitTicks * 1000000ULL) / effectiveQpcFreq;

    if (m_firstFrameQpc == 0ULL)
    {
        m_firstFrameQpc = recvQpc;
    }

    {
        ExclusiveLock lock(&m_metricsLock);
        if (m_metrics.LastFrameSequence != 0ULL &&
            outHeader.FrameSequence > (m_metrics.LastFrameSequence + 1ULL))
        {
            m_metrics.SequenceGapsDetected += (outHeader.FrameSequence - m_metrics.LastFrameSequence - 1ULL);
        }

        ++m_metrics.FramesReceived;
        m_metrics.BytesReceived += static_cast<uint64_t>(outPixels.size()) + sizeof(outHeader);
        if (!crcOk)
        {
            ++m_metrics.ChecksumMismatches;
            m_metrics.LastProtocolStatus = ipc::FrameIpcStatus::ChecksumMismatch;
        }
        if (!patternOk)
        {
            ++m_metrics.SyntheticPatternMismatches;
        }

        m_metrics.LastFrameSequence = outHeader.FrameSequence;
        m_metrics.LastPresentationFrameNumber = outHeader.PresentationFrameNumber;
        m_metrics.LastFrameWidth = outHeader.Width;
        m_metrics.LastFrameHeight = outHeader.Height;
        m_metrics.LastPixelFormat = outHeader.PixelFormat;
        m_metrics.LastFrameChecksumCrc32 = actualCrc;
        m_metrics.LastEndToEndLatencyUs = endToEndUs;
        m_metrics.TotalEndToEndLatencyUs += endToEndUs;
        m_metrics.AvgEndToEndLatencyUs = m_metrics.TotalEndToEndLatencyUs / m_metrics.FramesReceived;
        if (endToEndUs > m_metrics.MaxEndToEndLatencyUs)
        {
            m_metrics.MaxEndToEndLatencyUs = endToEndUs;
        }
        m_metrics.LastIpcTransitLatencyUs = transitUs;

        const uint64_t elapsedTicks = (recvQpc > m_firstFrameQpc) ? (recvQpc - m_firstFrameQpc) : 0ULL;
        if (elapsedTicks > 0ULL)
        {
            const double elapsedSec = static_cast<double>(elapsedTicks) / static_cast<double>(m_qpcFreq);
            m_metrics.ReceiveFps = static_cast<double>(m_metrics.FramesReceived) / elapsedSec;
        }
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
    std::vector<uint8_t> pixels;
    HRESULT finalHr = S_OK;

    for (;;)
    {
        if (IsStopSignaled(stopEvent))
        {
            break;
        }

        DWORD stepTimeoutMs = m_config.IoTimeoutMs;
        if (m_config.MaxDurationMs > 0U)
        {
            const ULONGLONG elapsedMs = GetTickCount64() - startTick;
            if (elapsedMs >= static_cast<ULONGLONG>(m_config.MaxDurationMs))
            {
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
                if (!m_config.AutoReconnect || IsStopSignaled(stopEvent))
                {
                    break;
                }
                if (stopEvent != nullptr)
                {
                    if (WaitForSingleObject(stopEvent, 100U) == WAIT_OBJECT_0)
                    {
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
        if (recvHr == HRESULT_FROM_WIN32(ERROR_TIMEOUT))
        {
            continue;
        }
        if (recvHr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED))
        {
            break;
        }
        if (recvHr == S_FALSE || FAILED(recvHr))
        {
            finalHr = (recvHr == S_FALSE) ? S_OK : recvHr;
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
        if (m_config.MaxFrames > 0ULL && snap.FramesReceived >= m_config.MaxFrames)
        {
            finalHr = S_OK;
            break;
        }
    }

    Disconnect();
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

    m_sessionId = 0ULL;
    ExclusiveLock lock(&m_metricsLock);
    m_metrics.Connected = false;
}

HostConsumerMetricsSnapshot
FrameConsumer::GetMetricsSnapshot() const noexcept
{
    SharedLock lock(&m_metricsLock);
    return m_metrics;
}

} // namespace lumabridge::host
