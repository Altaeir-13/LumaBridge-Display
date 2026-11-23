#include "FrameConsumer.h"

#include <algorithm>
#include <cstring>
#include <new>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

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

class ScopedKeyedMutexRelease final
{
public:
    ScopedKeyedMutexRelease(IDXGIKeyedMutex* mutex, UINT64 releaseKey) noexcept
        : m_mutex(mutex),
          m_releaseKey(releaseKey)
    {
    }

    ~ScopedKeyedMutexRelease()
    {
        ReleaseNow();
    }

    HRESULT ReleaseNow() noexcept
    {
        if (m_mutex != nullptr)
        {
            IDXGIKeyedMutex* mutex = m_mutex;
            m_mutex = nullptr;
            return mutex->ReleaseSync(m_releaseKey);
        }
        return S_OK;
    }

    ScopedKeyedMutexRelease(const ScopedKeyedMutexRelease&) = delete;
    ScopedKeyedMutexRelease& operator=(const ScopedKeyedMutexRelease&) = delete;

private:
    IDXGIKeyedMutex* m_mutex{nullptr};
    UINT64 m_releaseKey{0ULL};
};

} // namespace

LatencySummaryStats
ComputeLatencySummary(
    const std::vector<uint64_t>& samples,
    uint64_t lastUs
    ) noexcept
{
    LatencySummaryStats out{};
    out.Available = false;
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
    out.Available = (n > 0U);
    out.SampleCount = static_cast<uint64_t>(n);
    out.StoredSampleCount = static_cast<uint64_t>(n);
    out.SamplesTruncated = false;
    out.ReservoirSampled = false;
    out.MinUs = sorted.front();
    out.MaxUs = sorted.back();
    out.AvgUs = sum / n;
    out.P50Us = sorted[NearestRankIndex(n, 50U)];
    out.P95Us = sorted[NearestRankIndex(n, 95U)];
    out.P99Us = sorted[NearestRankIndex(n, 99U)];
    return out;
}

LatencySummaryStats
ReservoirLatencyAccumulator::Summarize() const noexcept
{
    LatencySummaryStats summary = ComputeLatencySummary(Samples, LastUs);
    summary.SampleCount = Count;
    summary.StoredSampleCount = static_cast<uint64_t>(Samples.size());
    summary.SamplesTruncated = (Count > static_cast<uint64_t>(Samples.size()));
    summary.ReservoirSampled = UsedReservoirSampling;
    summary.Available = (Count > 0ULL);
    if (Count > 0ULL)
    {
        summary.MinUs = MinUs;
        summary.MaxUs = MaxUs;
        summary.AvgUs = TotalUs / Count;
    }
    return summary;
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
    static constexpr uint64_t kMaxPlausibleStageDurationUs = 30000000ULL;

    ValidatedFrameIntervals out{};
    out.PreConnectQueued =
        ((header.Flags & static_cast<uint32_t>(ipc::FrameIpcFlags::PreConnectQueuedFrame)) != 0U);

    if (header.QpcFrequency == 0ULL ||
        consumerQpcFreq == 0ULL ||
        header.QpcFrequency != consumerQpcFreq)
    {
        out.Valid = false;
        out.CoreTimestampsValid = false;
        out.QpcFrequencyMismatch = true;
        out.IncompatibleTimestampUnits = true;
        return out;
    }

    if (header.ExtractCompleteQpcTime == 0ULL ||
        header.ServerSendQpcTime == 0ULL ||
        recvPayloadQpc == 0ULL)
    {
        out.Valid = false;
        out.CoreTimestampsValid = false;
        out.MissingCoreTimestamp = true;
        return out;
    }

    if (header.ServerSendQpcTime < header.ExtractCompleteQpcTime ||
        recvPayloadQpc < header.ServerSendQpcTime ||
        (sentAck && ackCompleteQpc < recvPayloadQpc) ||
        (!sentAck && ackCompleteQpc != 0ULL && ackCompleteQpc < recvPayloadQpc))
    {
        out.Valid = false;
        out.CoreTimestampsValid = false;
        out.FutureTimestampDetected = true;
        out.OutOfOrderTimestamps = true;
        return out;
    }

    const uint64_t freq = consumerQpcFreq;
    const uint64_t queueWaitUs = ipc::ComputeQpcElapsedUs(header.ExtractCompleteQpcTime, header.ServerSendQpcTime, freq);
    const uint64_t ipcTransitUs = ipc::ComputeQpcElapsedUs(header.ServerSendQpcTime, recvPayloadQpc, freq);
    const uint64_t hostVerifyAckUs = (ackCompleteQpc >= recvPayloadQpc)
        ? ipc::ComputeQpcElapsedUs(recvPayloadQpc, ackCompleteQpc, freq)
        : 0ULL;
    const uint64_t endToEndUs = ipc::ComputeQpcElapsedUs(header.ExtractCompleteQpcTime, recvPayloadQpc, freq);

    if (queueWaitUs > kMaxPlausibleStageDurationUs ||
        ipcTransitUs > kMaxPlausibleStageDurationUs ||
        hostVerifyAckUs > kMaxPlausibleStageDurationUs ||
        endToEndUs > kMaxPlausibleStageDurationUs)
    {
        out.Valid = false;
        out.CoreTimestampsValid = false;
        out.IncompatibleTimestampUnits = true;
        return out;
    }

    out.CoreTimestampsValid = true;
    out.CopyUs = ipc::UnpackCopyLatencyUsFromFlags(header.Flags);
    out.QueueWaitUs = queueWaitUs;
    out.IpcTransitUs = ipcTransitUs;
    out.HostVerifyAckUs = hostVerifyAckUs;
    out.EndToEndUs = endToEndUs;

    if (header.PresentDisplayQpcTime == 0ULL)
    {
        out.PresentTimestampMissing = true;
        out.PresentTimestampAvailable = false;
        out.HasPresentToExtract = false;
        out.Valid = true;
        return out;
    }

    if (header.ExtractCompleteQpcTime < header.PresentDisplayQpcTime)
    {
        out.FutureTimestampDetected = true;
        out.OutOfOrderTimestamps = true;
        out.PresentTimestampAvailable = false;
        out.HasPresentToExtract = false;
        out.Valid = false;
        return out;
    }

    const uint64_t presentToExtractUs =
        ipc::ComputeQpcElapsedUs(header.PresentDisplayQpcTime, header.ExtractCompleteQpcTime, freq);
    if (presentToExtractUs > kMaxPlausibleStageDurationUs)
    {
        out.IncompatibleTimestampUnits = true;
        out.PresentTimestampAvailable = false;
        out.HasPresentToExtract = false;
        out.Valid = false;
        return out;
    }

    out.PresentTimestampAvailable = true;
    out.HasPresentToExtract = true;
    out.PresentToExtractUs = presentToExtractUs;
    out.Valid = true;
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
    ClearGpuSharedResources();
    m_diagnosticStagingTexture.Reset();
    m_hostGpuWorkingTexture.Reset();
    m_d3dContext.Reset();
    m_d3dDevice1.Reset();
    m_d3dDevice.Reset();
    if (m_ioEvent != nullptr)
    {
        CloseHandle(m_ioEvent);
        m_ioEvent = nullptr;
    }
}

void
FrameConsumer::ClearGpuSharedResources() noexcept
{
    for (auto& entry : m_sharedSlotCache)
    {
        entry.Reset();
    }
    m_slotSeenInSession.fill(false);
}

HRESULT
FrameConsumer::EnsureD3d11DeviceForAdapterLuid(
    LUID serverAdapterLuid
    ) noexcept
{
    const LUID expectedLuid = m_config.HasForcedAdapterLuid ? m_config.ForcedAdapterLuid : serverAdapterLuid;
    if (m_config.HasForcedAdapterLuid &&
        (m_config.ForcedAdapterLuid.LowPart != serverAdapterLuid.LowPart ||
         m_config.ForcedAdapterLuid.HighPart != serverAdapterLuid.HighPart))
    {
        return DXGI_ERROR_INVALID_CALL;
    }

    if (m_hasBoundD3dDevice &&
        m_d3dDevice != nullptr &&
        m_d3dDevice1 != nullptr &&
        m_d3dContext != nullptr &&
        m_boundAdapterLuid.LowPart == expectedLuid.LowPart &&
        m_boundAdapterLuid.HighPart == expectedLuid.HighPart &&
        SUCCEEDED(m_d3dDevice->GetDeviceRemovedReason()))
    {
        return S_OK;
    }

    ClearGpuSharedResources();
    m_diagnosticStagingTexture.Reset();
    m_hostGpuWorkingTexture.Reset();
    m_d3dContext.Reset();
    m_d3dDevice1.Reset();
    m_d3dDevice.Reset();
    m_hasBoundD3dDevice = false;
    m_workingWidth = 0U;
    m_workingHeight = 0U;
    m_workingFormat = DXGI_FORMAT_UNKNOWN;
    m_stagingWidth = 0U;
    m_stagingHeight = 0U;
    m_stagingFormat = DXGI_FORMAT_UNKNOWN;

    static constexpr D3D_FEATURE_LEVEL kLevels[] = {
        D3D_FEATURE_LEVEL_11_1,
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_1,
        D3D_FEATURE_LEVEL_10_0};

    Microsoft::WRL::ComPtr<IDXGIFactory4> dxgiFactory;
    HRESULT hr = CreateDXGIFactory1(IID_PPV_ARGS(&dxgiFactory));
    if (FAILED(hr) || dxgiFactory == nullptr)
    {
        return FAILED(hr) ? hr : E_FAIL;
    }

    Microsoft::WRL::ComPtr<IDXGIAdapter1> targetAdapter;
    const bool hasNonZeroLuid = (expectedLuid.LowPart != 0UL || expectedLuid.HighPart != 0L);
    if (hasNonZeroLuid)
    {
        hr = dxgiFactory->EnumAdapterByLuid(expectedLuid, IID_PPV_ARGS(&targetAdapter));
        if (FAILED(hr) || targetAdapter == nullptr)
        {
            if (!m_config.AllowWarpAdapterFallbackForSyntheticLuid)
            {
                return FAILED(hr) ? hr : DXGI_ERROR_NOT_FOUND;
            }
            targetAdapter.Reset();
        }
    }

    D3D_FEATURE_LEVEL selectedLevel = D3D_FEATURE_LEVEL_11_0;
    Microsoft::WRL::ComPtr<ID3D11Device> device;
    Microsoft::WRL::ComPtr<ID3D11DeviceContext> context;

    if (targetAdapter != nullptr)
    {
        hr = D3D11CreateDevice(
            targetAdapter.Get(),
            D3D_DRIVER_TYPE_UNKNOWN,
            nullptr,
            D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
            kLevels,
            ARRAYSIZE(kLevels),
            D3D11_SDK_VERSION,
            &device,
            &selectedLevel,
            &context);
        if (FAILED(hr))
        {
            hr = D3D11CreateDevice(
                targetAdapter.Get(),
                D3D_DRIVER_TYPE_UNKNOWN,
                nullptr,
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                kLevels,
                ARRAYSIZE(kLevels),
                D3D11_SDK_VERSION,
                &device,
                &selectedLevel,
                &context);
        }
    }
    else
    {
        hr = D3D11CreateDevice(
            nullptr,
            D3D_DRIVER_TYPE_HARDWARE,
            nullptr,
            D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
            kLevels,
            ARRAYSIZE(kLevels),
            D3D11_SDK_VERSION,
            &device,
            &selectedLevel,
            &context);
        if (FAILED(hr))
        {
            hr = D3D11CreateDevice(
                nullptr,
                D3D_DRIVER_TYPE_HARDWARE,
                nullptr,
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                kLevels,
                ARRAYSIZE(kLevels),
                D3D11_SDK_VERSION,
                &device,
                &selectedLevel,
                &context);
        }
        if (FAILED(hr) && m_config.AllowWarpAdapterFallbackForSyntheticLuid)
        {
            hr = D3D11CreateDevice(
                nullptr,
                D3D_DRIVER_TYPE_WARP,
                nullptr,
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                kLevels,
                ARRAYSIZE(kLevels),
                D3D11_SDK_VERSION,
                &device,
                &selectedLevel,
                &context);
        }
    }

    if (FAILED(hr) || device == nullptr || context == nullptr)
    {
        return FAILED(hr) ? hr : E_FAIL;
    }

    Microsoft::WRL::ComPtr<ID3D11Device1> device1;
    hr = device.As(&device1);
    if (FAILED(hr) || device1 == nullptr)
    {
        return FAILED(hr) ? hr : E_NOINTERFACE;
    }

    LUID actualBoundLuid = expectedLuid;
    Microsoft::WRL::ComPtr<IDXGIDevice> dxgiDev;
    Microsoft::WRL::ComPtr<IDXGIAdapter> boundAdapter;
    if (SUCCEEDED(device.As(&dxgiDev)) && dxgiDev != nullptr &&
        SUCCEEDED(dxgiDev->GetAdapter(&boundAdapter)) && boundAdapter != nullptr)
    {
        DXGI_ADAPTER_DESC desc{};
        if (SUCCEEDED(boundAdapter->GetDesc(&desc)))
        {
            actualBoundLuid = desc.AdapterLuid;
        }
    }

    m_d3dDevice = device;
    m_d3dDevice1 = device1;
    m_d3dContext = context;
    m_boundAdapterLuid = actualBoundLuid;
    m_hasBoundD3dDevice = true;
    return S_OK;
}

HRESULT
FrameConsumer::PrewarmD3d11Device() noexcept
{
    if (m_config.TransportPreference == HostTransportPreference::CpuStagingOnly)
    {
        return S_FALSE;
    }

    if (m_hasBoundD3dDevice &&
        m_d3dDevice != nullptr &&
        m_d3dDevice1 != nullptr &&
        m_d3dContext != nullptr &&
        SUCCEEDED(m_d3dDevice->GetDeviceRemovedReason()))
    {
        return S_OK;
    }

    if (m_config.HasForcedAdapterLuid)
    {
        return EnsureD3d11DeviceForAdapterLuid(m_config.ForcedAdapterLuid);
    }

    Microsoft::WRL::ComPtr<IDXGIFactory1> factory;
    LUID preferredLuid{0, 0};
    if (SUCCEEDED(CreateDXGIFactory1(IID_PPV_ARGS(&factory))) && factory != nullptr)
    {
        for (UINT idx = 0U;; ++idx)
        {
            Microsoft::WRL::ComPtr<IDXGIAdapter1> adapter;
            if (factory->EnumAdapters1(idx, &adapter) != S_OK || adapter == nullptr)
            {
                break;
            }
            DXGI_ADAPTER_DESC1 desc{};
            if (SUCCEEDED(adapter->GetDesc1(&desc)))
            {
                if ((desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) != 0U)
                {
                    continue;
                }
                if (desc.VendorId == 0x10DEU)
                {
                    preferredLuid = desc.AdapterLuid;
                    break;
                }
                if (preferredLuid.LowPart == 0UL && preferredLuid.HighPart == 0L)
                {
                    preferredLuid = desc.AdapterLuid;
                }
            }
        }
    }

    return EnsureD3d11DeviceForAdapterLuid(preferredLuid);
}

HRESULT
FrameConsumer::EnsureHostWorkingTexture(
    uint32_t width,
    uint32_t height,
    DXGI_FORMAT format
    ) noexcept
{
    if (m_d3dDevice == nullptr)
    {
        return E_NOT_VALID_STATE;
    }

    if (m_hostGpuWorkingTexture != nullptr &&
        m_workingWidth == width &&
        m_workingHeight == height &&
        m_workingFormat == format)
    {
        return S_OK;
    }

    m_hostGpuWorkingTexture.Reset();
    m_workingWidth = 0U;
    m_workingHeight = 0U;
    m_workingFormat = DXGI_FORMAT_UNKNOWN;

    D3D11_TEXTURE2D_DESC desc{};
    desc.Width = width;
    desc.Height = height;
    desc.MipLevels = 1U;
    desc.ArraySize = 1U;
    desc.Format = format;
    desc.SampleDesc.Count = 1U;
    desc.SampleDesc.Quality = 0U;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE | D3D11_BIND_RENDER_TARGET;

    Microsoft::WRL::ComPtr<ID3D11Texture2D> working;
    HRESULT hr = m_d3dDevice->CreateTexture2D(&desc, nullptr, &working);
    if (FAILED(hr) || working == nullptr)
    {
        desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        hr = m_d3dDevice->CreateTexture2D(&desc, nullptr, &working);
        if (FAILED(hr) || working == nullptr)
        {
            return FAILED(hr) ? hr : E_OUTOFMEMORY;
        }
    }

    m_hostGpuWorkingTexture = working;
    m_workingWidth = width;
    m_workingHeight = height;
    m_workingFormat = format;
    return S_OK;
}

HRESULT
FrameConsumer::VerifyWorkingGpuTextureSyntheticPattern(
    uint32_t presentationFrameNumber,
    uint32_t width,
    uint32_t height,
    DXGI_FORMAT format,
    bool& outMatches
    ) noexcept
{
    outMatches = false;
    if (m_d3dDevice == nullptr || m_d3dContext == nullptr || m_hostGpuWorkingTexture == nullptr)
    {
        return E_NOT_VALID_STATE;
    }

    if (m_diagnosticStagingTexture == nullptr ||
        m_stagingWidth != width ||
        m_stagingHeight != height ||
        m_stagingFormat != format)
    {
        m_diagnosticStagingTexture.Reset();
        m_stagingWidth = 0U;
        m_stagingHeight = 0U;
        m_stagingFormat = DXGI_FORMAT_UNKNOWN;

        D3D11_TEXTURE2D_DESC stDesc{};
        stDesc.Width = width;
        stDesc.Height = height;
        stDesc.MipLevels = 1U;
        stDesc.ArraySize = 1U;
        stDesc.Format = format;
        stDesc.SampleDesc.Count = 1U;
        stDesc.Usage = D3D11_USAGE_STAGING;
        stDesc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;

        HRESULT hr = m_d3dDevice->CreateTexture2D(&stDesc, nullptr, &m_diagnosticStagingTexture);
        if (FAILED(hr) || m_diagnosticStagingTexture == nullptr)
        {
            return FAILED(hr) ? hr : E_OUTOFMEMORY;
        }
        m_stagingWidth = width;
        m_stagingHeight = height;
        m_stagingFormat = format;
    }

    m_d3dContext->CopyResource(m_diagnosticStagingTexture.Get(), m_hostGpuWorkingTexture.Get());

    D3D11_MAPPED_SUBRESOURCE mapped{};
    HRESULT mapHr = m_d3dContext->Map(m_diagnosticStagingTexture.Get(), 0U, D3D11_MAP_READ, 0U, &mapped);
    if (FAILED(mapHr))
    {
        return mapHr;
    }

    uint32_t rowPitch = 0U;
    uint32_t payloadBytes = 0U;
    if (!ipc::ComputeTightRowPitchBytes(width, rowPitch) ||
        !ipc::ComputeValidatedFramePayloadBytes(width, height, rowPitch, payloadBytes) ||
        mapped.pData == nullptr ||
        mapped.RowPitch < rowPitch)
    {
        m_d3dContext->Unmap(m_diagnosticStagingTexture.Get(), 0U);
        return E_FAIL;
    }

    std::vector<uint8_t> packed;
    try
    {
        packed.resize(payloadBytes);
    }
    catch (const std::bad_alloc&)
    {
        m_d3dContext->Unmap(m_diagnosticStagingTexture.Get(), 0U);
        return E_OUTOFMEMORY;
    }

    const uint8_t* src = static_cast<const uint8_t*>(mapped.pData);
    for (uint32_t y = 0U; y < height; ++y)
    {
        std::memcpy(
            packed.data() + static_cast<size_t>(y) * rowPitch,
            src + static_cast<size_t>(y) * mapped.RowPitch,
            rowPitch);
    }
    m_d3dContext->Unmap(m_diagnosticStagingTexture.Get(), 0U);

    {
        ExclusiveLock lock(&m_metricsLock);
        ++m_metrics.CpuStagingReadsPerformed;
    }

    outMatches = ipc::VerifySyntheticTestPatternBgra8(
        presentationFrameNumber,
        width,
        height,
        packed.data(),
        packed.size());
    return S_OK;
}

HRESULT
FrameConsumer::SendGpuFrameAck(
    uint64_t frameSequence,
    uint32_t presentationFrameNumber,
    ipc::FrameIpcStatus status,
    uint16_t slotIndex,
    uint16_t slotGeneration,
    uint32_t gpuSyncWaitUs,
    uint64_t receiveQpc,
    HANDLE stopEvent
    ) noexcept
{
    ipc::FrameIpcFrameAck ack{};
    ack.Envelope = ipc::InitEnvelope(
        ipc::FrameIpcMessageType::FrameAck,
        static_cast<uint32_t>(sizeof(ipc::FrameIpcFrameAck)),
        ipc::kFrameIpcProtocolVersionMinorV1_1);
    ack.SessionId = m_sessionId;
    ack.FrameSequence = frameSequence;
    ack.PresentationFrameNumber = presentationFrameNumber;
    ack.Status = static_cast<uint32_t>(status);
    ack.HostReceiveQpcTime = receiveQpc;
    ack.Reserved1 = ipc::PackGpuFrameAckData(slotIndex, slotGeneration, gpuSyncWaitUs);

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
        return HRESULT_FROM_WIN32(ackErr);
    }
    return S_OK;
}

void
FrameConsumer::PopulateLatencySummariesLocked(
    HostConsumerMetricsSnapshot& dst
    ) const noexcept
{
    dst.CopyLatency = m_copyLat.Summarize();
    dst.PresentToExtractLatency = m_presentToExtractLat.Summarize();
    dst.QueueWaitLatency = m_queueWaitLat.Summarize();
    dst.LiveQueueWaitLatency = m_liveQueueWaitLat.Summarize();
    dst.IpcTransitLatency = m_ipcTransitLat.Summarize();
    dst.HostVerifyAckLatency = m_hostVerifyAckLat.Summarize();
    dst.EndToEndLatency = m_endToEndLat.Summarize();
    dst.LiveEndToEndLatency = m_liveEndToEndLat.Summarize();
    dst.InterFrameInterval = m_interFrameLat.Summarize();
    dst.InterFrameJitter = m_interFrameJitterLat.Summarize();
    dst.GpuSyncWaitLatency = m_gpuSyncWaitLat.Summarize();
    dst.HostGpuCopyLatency = m_hostGpuCopyLat.Summarize();
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

    m_metrics.CoreTimestampCoveragePercent = (m_metrics.FramesReceived > 0ULL)
        ? (static_cast<double>(m_metrics.ValidCoreTimestampSamples) * 100.0) / static_cast<double>(m_metrics.FramesReceived)
        : 0.0;
    m_metrics.LiveTimestampCoveragePercent = (m_metrics.LiveFramesReceived > 0ULL)
        ? (static_cast<double>(m_metrics.ValidLiveTimestampSamples) * 100.0) / static_cast<double>(m_metrics.LiveFramesReceived)
        : 0.0;
    m_metrics.PresentTimestampCoveragePercent = (m_metrics.FramesReceived > 0ULL)
        ? (static_cast<double>(m_metrics.ValidPresentTimestampSamples) * 100.0) / static_cast<double>(m_metrics.FramesReceived)
        : 0.0;
}

void
FrameConsumer::RecordFrameMetricsAndTimestampsLocked(
    uint64_t frameSequence,
    uint32_t presentationFrameNumber,
    uint32_t width,
    uint32_t height,
    uint32_t pixelFormat,
    uint32_t payloadCrc32,
    uint64_t bytesReceivedIncrement,
    bool crcOk,
    bool patternOk,
    uint64_t presentDisplayQpc,
    uint64_t extractCompleteQpc,
    uint64_t serverSendQpc,
    uint64_t recvCompleteQpc,
    uint64_t ackCompleteQpc,
    const ValidatedFrameIntervals& intervals,
    bool hasGpuSyncSample,
    uint64_t gpuSyncWaitUs,
    bool hasHostGpuCopySample,
    uint64_t hostGpuCopyUs
    ) noexcept
{
    if (m_metrics.LastFrameSequence != 0ULL)
    {
        if (frameSequence <= m_metrics.LastFrameSequence)
        {
            ++m_metrics.OutOfOrderSequenceCount;
        }
        else if (frameSequence > (m_metrics.LastFrameSequence + 1ULL))
        {
            m_metrics.SequenceGapsDetected += (frameSequence - m_metrics.LastFrameSequence - 1ULL);
        }
    }

    ++m_metrics.FramesReceived;
    ++m_currentSessionFrames;
    if (m_currentSessionFrames > m_metrics.MaxFramesPerSession)
    {
        m_metrics.MaxFramesPerSession = m_currentSessionFrames;
    }
    m_metrics.BytesReceived += bytesReceivedIncrement;

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
            m_firstValidFrameQpc = recvCompleteQpc;
        }
        m_lastValidFrameQpc = recvCompleteQpc;

        if (intervals.PreConnectQueued)
        {
            ++m_metrics.PreConnectFramesReceived;
        }
        else
        {
            ++m_metrics.LiveFramesReceived;
            if (m_firstLiveFrameQpc == 0ULL)
            {
                m_firstLiveFrameQpc = recvCompleteQpc;
            }
            m_lastLiveFrameQpc = recvCompleteQpc;
        }

        if (m_prevValidRecvQpc > 0ULL)
        {
            if (recvCompleteQpc >= m_prevValidRecvQpc)
            {
                const uint64_t intervalUs =
                    ipc::ComputeQpcElapsedUs(m_prevValidRecvQpc, recvCompleteQpc, m_qpcFreq);
                m_interFrameLat.Record(intervalUs);
                if (m_hasPrevInterFrameInterval)
                {
                    const uint64_t jitterUs = (intervalUs >= m_prevInterFrameIntervalUs)
                        ? (intervalUs - m_prevInterFrameIntervalUs)
                        : (m_prevInterFrameIntervalUs - intervalUs);
                    m_interFrameJitterLat.Record(jitterUs);
                }
                m_prevInterFrameIntervalUs = intervalUs;
                m_hasPrevInterFrameInterval = true;
            }
            else
            {
                ++m_metrics.NonMonotonicTimestampCount;
                ++m_metrics.TimestampMeasurementErrors;
            }
        }
        m_prevValidRecvQpc = recvCompleteQpc;
    }

    m_metrics.LastFrameSequence = frameSequence;
    m_metrics.LastPresentationFrameNumber = presentationFrameNumber;
    m_metrics.LastFrameWidth = width;
    m_metrics.LastFrameHeight = height;
    m_metrics.LastPixelFormat = pixelFormat;
    m_metrics.LastFrameChecksumCrc32 = payloadCrc32;
    m_lastFrameRecvQpc = recvCompleteQpc;

    if (hasGpuSyncSample)
    {
        m_gpuSyncWaitLat.Record(gpuSyncWaitUs);
    }
    if (hasHostGpuCopySample)
    {
        m_hostGpuCopyLat.Record(hostGpuCopyUs);
    }

    bool nonMonotonicProducerTs = false;
    if (intervals.CoreTimestampsValid)
    {
        if ((m_prevSessionExtractQpc > 0ULL && extractCompleteQpc < m_prevSessionExtractQpc) ||
            (m_prevSessionServerSendQpc > 0ULL && serverSendQpc < m_prevSessionServerSendQpc) ||
            (intervals.PresentTimestampAvailable && m_prevSessionPresentQpc > 0ULL && presentDisplayQpc < m_prevSessionPresentQpc))
        {
            nonMonotonicProducerTs = true;
        }
        m_prevSessionExtractQpc = extractCompleteQpc;
        m_prevSessionServerSendQpc = serverSendQpc;
        if (intervals.PresentTimestampAvailable)
        {
            m_prevSessionPresentQpc = presentDisplayQpc;
        }
    }

    if (intervals.PresentTimestampMissing)
    {
        ++m_metrics.MissingPresentTimestampCount;
    }

    if (nonMonotonicProducerTs)
    {
        ++m_metrics.NonMonotonicTimestampCount;
    }

    if (!intervals.Valid || nonMonotonicProducerTs)
    {
        ++m_metrics.TimestampMeasurementErrors;
        if (intervals.QpcFrequencyMismatch)
        {
            ++m_metrics.QpcFrequencyMismatchCount;
        }
        if (intervals.MissingCoreTimestamp)
        {
            ++m_metrics.MissingCoreTimestampCount;
        }
        if (intervals.FutureTimestampDetected)
        {
            ++m_metrics.FutureTimestampErrorCount;
        }
        if (intervals.IncompatibleTimestampUnits)
        {
            ++m_metrics.IncompatibleTimestampUnitsCount;
        }
    }
    else
    {
        ++m_metrics.ValidCoreTimestampSamples;
        m_copyLat.Record(intervals.CopyUs);
        if (intervals.HasPresentToExtract)
        {
            ++m_metrics.ValidPresentTimestampSamples;
            m_presentToExtractLat.Record(intervals.PresentToExtractUs);
        }
        m_queueWaitLat.Record(intervals.QueueWaitUs);
        m_ipcTransitLat.Record(intervals.IpcTransitUs);
        m_hostVerifyAckLat.Record(intervals.HostVerifyAckUs);
        m_endToEndLat.Record(intervals.EndToEndUs);

        if (!intervals.PreConnectQueued)
        {
            ++m_metrics.ValidLiveTimestampSamples;
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

HRESULT
FrameConsumer::Connect(
    DWORD timeoutMs,
    HANDLE stopEvent
    ) noexcept
{
    ClosePipeAndResetConnectionState(false);

    if (m_config.TransportPreference != HostTransportPreference::CpuStagingOnly && !m_hasBoundD3dDevice)
    {
        (void)PrewarmD3d11Device();
    }

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

        const DWORD sqosFlags =
            (m_config.TransportPreference == HostTransportPreference::CpuStagingOnly)
                ? (SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION)
                : (SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION);

        openedPipe = CreateFileW(
            m_config.PipeName.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0U,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | sqosFlags,
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

    const bool requestGpu = (m_config.TransportPreference != HostTransportPreference::CpuStagingOnly);
    uint32_t clientCaps = 0U;
    if (requestGpu)
    {
        clientCaps |= static_cast<uint32_t>(ipc::FrameIpcCapabilities::GpuSharedNtHandle);
    }
    if (m_config.TransportPreference != HostTransportPreference::GpuSharedOnly || m_config.AllowCpuFallback)
    {
        clientCaps |= static_cast<uint32_t>(ipc::FrameIpcCapabilities::CpuStagingRawPixels);
        if (requestGpu && m_config.AllowCpuFallback)
        {
            clientCaps |= static_cast<uint32_t>(ipc::FrameIpcCapabilities::GpuFallbackToCpuStaging);
        }
    }

    ipc::FrameIpcClientHello clientHello{};
    clientHello.Envelope = ipc::InitEnvelope(
        ipc::FrameIpcMessageType::ClientHello,
        static_cast<uint32_t>(sizeof(ipc::FrameIpcClientHello)),
        requestGpu ? ipc::kFrameIpcProtocolVersionMinorV1_1 : ipc::kFrameIpcProtocolVersionMinor);
    clientHello.ClientProcessId = GetCurrentProcessId();
    clientHello.ClientSessionId = static_cast<uint32_t>(clientSessionId);
    clientHello.ClientCapabilities = clientCaps;

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

    const uint32_t negotiatedCaps = ipc::UnpackServerHelloCapabilities(serverHello.Reserved1);
    const uint32_t negotiatedPoolSize = ipc::UnpackServerHelloSharedPoolSize(serverHello.Reserved1);
    const bool serverAgreedGpu =
        (negotiatedCaps & static_cast<uint32_t>(ipc::FrameIpcCapabilities::GpuSharedNtHandle)) != 0U;
    const LUID serverAdapterLuid{
        static_cast<DWORD>(serverHello.AdapterLuidLow),
        static_cast<LONG>(serverHello.AdapterLuidHigh)};

    if (m_config.HasForcedAdapterLuid &&
        (m_config.ForcedAdapterLuid.LowPart != serverAdapterLuid.LowPart ||
         m_config.ForcedAdapterLuid.HighPart != serverAdapterLuid.HighPart))
    {
        ClosePipeAndResetConnectionState(false);
        ExclusiveLock lock(&m_metricsLock);
        ++m_metrics.AdapterMismatchErrors;
        ++m_metrics.ProtocolErrors;
        m_metrics.LastProtocolStatus = ipc::FrameIpcStatus::AdapterLuidMismatch;
        m_metrics.LastErrorHResult = DXGI_ERROR_INVALID_CALL;
        m_metrics.TransportHealthy = false;
        return DXGI_ERROR_INVALID_CALL;
    }

    if (m_config.TransportPreference == HostTransportPreference::GpuSharedOnly && !serverAgreedGpu)
    {
        ClosePipeAndResetConnectionState(false);
        ExclusiveLock lock(&m_metricsLock);
        ++m_metrics.ProtocolErrors;
        m_metrics.LastProtocolStatus = ipc::FrameIpcStatus::VersionMismatch;
        m_metrics.LastErrorHResult = DXGI_ERROR_UNSUPPORTED;
        m_metrics.TransportHealthy = false;
        return DXGI_ERROR_UNSUPPORTED;
    }

    bool activeGpuMode = serverAgreedGpu;
    bool fallbackActivated = false;
    if (activeGpuMode)
    {
        const HRESULT d3dHr = EnsureD3d11DeviceForAdapterLuid(serverAdapterLuid);
        if (FAILED(d3dHr))
        {
            if (m_config.AllowCpuFallback &&
                (negotiatedCaps & static_cast<uint32_t>(ipc::FrameIpcCapabilities::CpuStagingRawPixels)) != 0U &&
                m_config.TransportPreference != HostTransportPreference::GpuSharedOnly)
            {
                activeGpuMode = false;
                fallbackActivated = true;
            }
            else
            {
                ClosePipeAndResetConnectionState(false);
                ExclusiveLock lock(&m_metricsLock);
                ++m_metrics.AdapterMismatchErrors;
                m_metrics.LastProtocolStatus = ipc::FrameIpcStatus::AdapterLuidMismatch;
                m_metrics.LastErrorHResult = d3dHr;
                m_metrics.TransportHealthy = false;
                return d3dHr;
            }
        }
    }
    else if (requestGpu && m_config.AllowCpuFallback)
    {
        fallbackActivated = true;
    }

    m_sessionId = serverHello.SessionId;
    m_sessionConnectQpc = QueryCurrentQpc();
    m_currentSessionFrames = 0ULL;
    m_prevSessionExtractQpc = 0ULL;
    m_prevSessionServerSendQpc = 0ULL;
    m_prevSessionPresentQpc = 0ULL;
    m_slotSeenInSession.fill(false);

    {
        ExclusiveLock lock(&m_metricsLock);
        m_metrics.Connected = true;
        m_metrics.SessionId = serverHello.SessionId;
        m_metrics.ServerProcessId = serverHello.ServerProcessId;
        m_metrics.AdapterLuidLow = serverHello.AdapterLuidLow;
        m_metrics.AdapterLuidHigh = serverHello.AdapterLuidHigh;
        m_metrics.ServerMaxQueueDepth = serverHello.MaxQueueDepth;
        m_metrics.NegotiatedTransportMode = activeGpuMode
            ? ipc::FrameIpcTransportMode::GpuSharedNtHandle
            : ipc::FrameIpcTransportMode::CpuStagingPipe;
        m_metrics.FallbackToCpuActivated = fallbackActivated;
        if (negotiatedPoolSize > 0U)
        {
            m_metrics.SharedTexturePoolSize = negotiatedPoolSize;
        }
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
    bool isGpu = false;
    ipc::FrameIpcGpuFrameHeader gpuHeader{};
    return ReceiveNextGpuOrCpuFrame(
        isGpu,
        gpuHeader,
        outHeader,
        outPixels,
        timeoutMs,
        stopEvent);
}

HRESULT
FrameConsumer::ReceiveNextGpuOrCpuFrame(
    bool& outIsGpuFrame,
    ipc::FrameIpcGpuFrameHeader& outGpuHeader,
    ipc::FrameIpcFrameHeader& outHeader,
    std::vector<uint8_t>& outPixels,
    DWORD timeoutMs,
    HANDLE stopEvent
    ) noexcept
{
    outIsGpuFrame = false;
    outGpuHeader = {};
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

    if (env.Magic == ipc::kFrameIpcMagic &&
        env.VersionMajor == ipc::kFrameIpcProtocolVersionMajor &&
        env.VersionMinor == ipc::kFrameIpcProtocolVersionMinorV1_1 &&
        env.MessageType == static_cast<uint16_t>(ipc::FrameIpcMessageType::GpuFrameHeader) &&
        env.HeaderSizeBytes == sizeof(ipc::FrameIpcGpuFrameHeader))
    {
        std::memcpy(&outGpuHeader.Envelope, &env, sizeof(env));
        size_t gpuHdrBytesRead = 0U;
        const DWORD hdrErr = ReadExactOverlapped(
            m_pipeHandle,
            m_ioEvent,
            stopEvent,
            reinterpret_cast<uint8_t*>(&outGpuHeader) + sizeof(env),
            sizeof(outGpuHeader) - sizeof(env),
            m_config.IoTimeoutMs,
            gpuHdrBytesRead);
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

        const ipc::FrameIpcStatus gpuHdrStatus = ipc::ValidateGpuFrameHeader(
            &outGpuHeader,
            sizeof(outGpuHeader),
            m_sessionId);
        if (gpuHdrStatus != ipc::FrameIpcStatus::Ok)
        {
            ClosePipeAndResetConnectionState(false);
            ExclusiveLock lock(&m_metricsLock);
            ++m_metrics.ProtocolErrors;
            ++m_metrics.FatalIpcErrors;
            m_metrics.TransportHealthy = false;
            m_metrics.LastProtocolStatus = gpuHdrStatus;
            m_metrics.LastErrorHResult = E_INVALIDARG;
            return E_INVALIDARG;
        }

        const uint64_t recvHeaderQpc = QueryCurrentQpc();
        const LUID hdrLuid{
            static_cast<DWORD>(outGpuHeader.AdapterLuidLow),
            static_cast<LONG>(outGpuHeader.AdapterLuidHigh)};
        if (m_config.HasForcedAdapterLuid &&
            (hdrLuid.LowPart != m_config.ForcedAdapterLuid.LowPart ||
             hdrLuid.HighPart != m_config.ForcedAdapterLuid.HighPart))
        {
            (void)SendGpuFrameAck(
                outGpuHeader.FrameSequence,
                outGpuHeader.PresentationFrameNumber,
                ipc::FrameIpcStatus::AdapterLuidMismatch,
                static_cast<uint16_t>(outGpuHeader.SlotIndex),
                static_cast<uint16_t>(outGpuHeader.SlotGeneration),
                0U,
                recvHeaderQpc,
                stopEvent);
            ClosePipeAndResetConnectionState(false);
            ExclusiveLock lock(&m_metricsLock);
            ++m_metrics.AdapterMismatchErrors;
            ++m_metrics.ProtocolErrors;
            m_metrics.LastProtocolStatus = ipc::FrameIpcStatus::AdapterLuidMismatch;
            m_metrics.LastErrorHResult = DXGI_ERROR_INVALID_CALL;
            m_metrics.TransportHealthy = false;
            return DXGI_ERROR_INVALID_CALL;
        }

        const HRESULT devHr = EnsureD3d11DeviceForAdapterLuid(hdrLuid);
        if (FAILED(devHr))
        {
            (void)SendGpuFrameAck(
                outGpuHeader.FrameSequence,
                outGpuHeader.PresentationFrameNumber,
                ipc::FrameIpcStatus::DeviceRemoved,
                static_cast<uint16_t>(outGpuHeader.SlotIndex),
                static_cast<uint16_t>(outGpuHeader.SlotGeneration),
                0U,
                recvHeaderQpc,
                stopEvent);
            ClosePipeAndResetConnectionState(false);
            ExclusiveLock lock(&m_metricsLock);
            ++m_metrics.FatalIpcErrors;
            m_metrics.LastProtocolStatus = ipc::FrameIpcStatus::DeviceRemoved;
            m_metrics.LastErrorHResult = devHr;
            m_metrics.TransportHealthy = false;
            return devHr;
        }

        const uint32_t slotIdx = outGpuHeader.SlotIndex;
        HostSharedSlotCacheEntry& cacheEntry = m_sharedSlotCache[slotIdx];
        const bool isNewHandleFlag =
            (outGpuHeader.SyncAndFallbackFlags & static_cast<uint32_t>(ipc::FrameIpcGpuFrameFlags::NewHandleDuplicated)) != 0U;

        if (m_config.SimulateInvalidSharedHandleForTesting)
        {
            if (isNewHandleFlag && outGpuHeader.DuplicatedNtHandleValue != 0ULL)
            {
                const HANDLE leakedDup = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(outGpuHeader.DuplicatedNtHandleValue));
                if (leakedDup != nullptr && leakedDup != INVALID_HANDLE_VALUE)
                {
                    CloseHandle(leakedDup);
                }
            }
            (void)SendGpuFrameAck(
                outGpuHeader.FrameSequence,
                outGpuHeader.PresentationFrameNumber,
                ipc::FrameIpcStatus::ResourceOpenFailed,
                static_cast<uint16_t>(slotIdx),
                static_cast<uint16_t>(outGpuHeader.SlotGeneration),
                0U,
                recvHeaderQpc,
                stopEvent);
            ClosePipeAndResetConnectionState(false);
            ExclusiveLock lock(&m_metricsLock);
            ++m_metrics.GpuSharedOpenFailures;
            ++m_metrics.FatalIpcErrors;
            m_metrics.LastProtocolStatus = ipc::FrameIpcStatus::ResourceOpenFailed;
            m_metrics.LastErrorHResult = E_HANDLE;
            m_metrics.TransportHealthy = false;
            return E_HANDLE;
        }

        if (isNewHandleFlag || cacheEntry.SlotGeneration != outGpuHeader.SlotGeneration || cacheEntry.SharedTexture == nullptr)
        {
            const HANDLE incomingHandle =
                reinterpret_cast<HANDLE>(static_cast<uintptr_t>(outGpuHeader.DuplicatedNtHandleValue));
            if (incomingHandle == nullptr || incomingHandle == INVALID_HANDLE_VALUE)
            {
                (void)SendGpuFrameAck(
                    outGpuHeader.FrameSequence,
                    outGpuHeader.PresentationFrameNumber,
                    ipc::FrameIpcStatus::ResourceOpenFailed,
                    static_cast<uint16_t>(slotIdx),
                    static_cast<uint16_t>(outGpuHeader.SlotGeneration),
                    0U,
                    recvHeaderQpc,
                    stopEvent);
                ClosePipeAndResetConnectionState(false);
                ExclusiveLock lock(&m_metricsLock);
                ++m_metrics.GpuSharedOpenFailures;
                ++m_metrics.FatalIpcErrors;
                m_metrics.LastProtocolStatus = ipc::FrameIpcStatus::ResourceOpenFailed;
                m_metrics.LastErrorHResult = E_HANDLE;
                m_metrics.TransportHealthy = false;
                return E_HANDLE;
            }

            cacheEntry.Reset();
            cacheEntry.DuplicatedNtHandle = incomingHandle;

            Microsoft::WRL::ComPtr<ID3D11Texture2D> openedTex;
            const HRESULT openHr = m_d3dDevice1->OpenSharedResource1(incomingHandle, IID_PPV_ARGS(&openedTex));
            if (FAILED(openHr) || openedTex == nullptr)
            {
                cacheEntry.Reset();
                (void)SendGpuFrameAck(
                    outGpuHeader.FrameSequence,
                    outGpuHeader.PresentationFrameNumber,
                    ipc::FrameIpcStatus::ResourceOpenFailed,
                    static_cast<uint16_t>(slotIdx),
                    static_cast<uint16_t>(outGpuHeader.SlotGeneration),
                    0U,
                    recvHeaderQpc,
                    stopEvent);
                ClosePipeAndResetConnectionState(false);
                ExclusiveLock lock(&m_metricsLock);
                ++m_metrics.GpuSharedOpenFailures;
                ++m_metrics.FatalIpcErrors;
                m_metrics.LastProtocolStatus = ipc::FrameIpcStatus::ResourceOpenFailed;
                m_metrics.LastErrorHResult = FAILED(openHr) ? openHr : E_FAIL;
                m_metrics.TransportHealthy = false;
                return FAILED(openHr) ? openHr : E_FAIL;
            }

            Microsoft::WRL::ComPtr<IDXGIKeyedMutex> keyedMutex;
            const HRESULT kmHr = openedTex.As(&keyedMutex);
            if (FAILED(kmHr) || keyedMutex == nullptr)
            {
                cacheEntry.Reset();
                (void)SendGpuFrameAck(
                    outGpuHeader.FrameSequence,
                    outGpuHeader.PresentationFrameNumber,
                    ipc::FrameIpcStatus::ResourceOpenFailed,
                    static_cast<uint16_t>(slotIdx),
                    static_cast<uint16_t>(outGpuHeader.SlotGeneration),
                    0U,
                    recvHeaderQpc,
                    stopEvent);
                ClosePipeAndResetConnectionState(false);
                ExclusiveLock lock(&m_metricsLock);
                ++m_metrics.GpuSharedOpenFailures;
                ++m_metrics.FatalIpcErrors;
                m_metrics.LastProtocolStatus = ipc::FrameIpcStatus::ResourceOpenFailed;
                m_metrics.LastErrorHResult = FAILED(kmHr) ? kmHr : E_NOINTERFACE;
                m_metrics.TransportHealthy = false;
                return FAILED(kmHr) ? kmHr : E_NOINTERFACE;
            }

            cacheEntry.SharedTexture = openedTex;
            cacheEntry.KeyedMutex = keyedMutex;
            cacheEntry.SlotGeneration = outGpuHeader.SlotGeneration;

            ExclusiveLock lock(&m_metricsLock);
            ++m_metrics.GpuFramesOpened;
        }

        if (!m_slotSeenInSession[slotIdx])
        {
            m_slotSeenInSession[slotIdx] = true;
            uint32_t activeSlots = 0U;
            for (bool seen : m_slotSeenInSession)
            {
                if (seen)
                {
                    ++activeSlots;
                }
            }
            ExclusiveLock lock(&m_metricsLock);
            if (activeSlots > m_metrics.SharedTexturePoolPeakUsage)
            {
                m_metrics.SharedTexturePoolPeakUsage = activeSlots;
            }
        }

        const uint64_t syncWaitStartQpc = QueryCurrentQpc();
        const HRESULT acqSyncHr = cacheEntry.KeyedMutex->AcquireSync(
            outGpuHeader.KeyedMutexAcquireKey,
            outGpuHeader.KeyedMutexTimeoutMs);
        const uint64_t syncWaitEndQpc = QueryCurrentQpc();
        const uint64_t syncWaitUs64 = ipc::ComputeQpcElapsedUs(syncWaitStartQpc, syncWaitEndQpc, m_qpcFreq);
        const uint32_t syncWaitUs32 = (syncWaitUs64 > 0xFFFFFFFFULL) ? 0xFFFFFFFFU : static_cast<uint32_t>(syncWaitUs64);

        if (acqSyncHr != S_OK)
        {
            cacheEntry.Reset();
            (void)SendGpuFrameAck(
                outGpuHeader.FrameSequence,
                outGpuHeader.PresentationFrameNumber,
                ipc::FrameIpcStatus::GpuSyncTimeout,
                static_cast<uint16_t>(slotIdx),
                static_cast<uint16_t>(outGpuHeader.SlotGeneration),
                syncWaitUs32,
                syncWaitEndQpc,
                stopEvent);
            ClosePipeAndResetConnectionState(false);
            ExclusiveLock lock(&m_metricsLock);
            ++m_metrics.GpuSyncTimeouts;
            ++m_metrics.FatalIpcErrors;
            m_metrics.LastProtocolStatus = ipc::FrameIpcStatus::GpuSyncTimeout;
            m_metrics.LastErrorHResult = (acqSyncHr == static_cast<HRESULT>(WAIT_TIMEOUT))
                ? HRESULT_FROM_WIN32(ERROR_TIMEOUT)
                : E_FAIL;
            m_metrics.TransportHealthy = false;
            return m_metrics.LastErrorHResult;
        }

        if (m_config.SimulateDisconnectWhileHoldingMutexForTesting)
        {
            // Deliberately abort connection while holding KeyedMutex so tests prove driver slot recovery.
            ClosePipeAndResetConnectionState(false);
            return HRESULT_FROM_WIN32(ERROR_CONNECTION_ABORTED);
        }

        bool patternOk = true;
        const uint64_t hostGpuCopyStartQpc = QueryCurrentQpc();
        HRESULT gpuWorkHr = EnsureHostWorkingTexture(
            outGpuHeader.Width,
            outGpuHeader.Height,
            static_cast<DXGI_FORMAT>(outGpuHeader.PixelFormat));
        if (SUCCEEDED(gpuWorkHr))
        {
            ScopedKeyedMutexRelease mutexReleaseGuard(
                cacheEntry.KeyedMutex.Get(),
                outGpuHeader.KeyedMutexReleaseKey);
            m_d3dContext->CopyResource(m_hostGpuWorkingTexture.Get(), cacheEntry.SharedTexture.Get());
            const HRESULT relHr = mutexReleaseGuard.ReleaseNow();
            if (FAILED(relHr))
            {
                gpuWorkHr = relHr;
            }
        }
        else
        {
            (void)cacheEntry.KeyedMutex->ReleaseSync(outGpuHeader.KeyedMutexReleaseKey);
        }
        const uint64_t hostGpuCopyEndQpc = QueryCurrentQpc();
        const uint64_t hostGpuCopyUs = ipc::ComputeQpcElapsedUs(hostGpuCopyStartQpc, hostGpuCopyEndQpc, m_qpcFreq);

        if (FAILED(gpuWorkHr))
        {
            cacheEntry.Reset();
            (void)SendGpuFrameAck(
                outGpuHeader.FrameSequence,
                outGpuHeader.PresentationFrameNumber,
                ipc::FrameIpcStatus::DeviceRemoved,
                static_cast<uint16_t>(slotIdx),
                static_cast<uint16_t>(outGpuHeader.SlotGeneration),
                syncWaitUs32,
                QueryCurrentQpc(),
                stopEvent);
            ClosePipeAndResetConnectionState(false);
            ExclusiveLock lock(&m_metricsLock);
            ++m_metrics.FatalIpcErrors;
            m_metrics.LastErrorHResult = gpuWorkHr;
            m_metrics.TransportHealthy = false;
            return gpuWorkHr;
        }

        if (m_config.VerifySyntheticPattern)
        {
            const HRESULT patHr = VerifyWorkingGpuTextureSyntheticPattern(
                outGpuHeader.PresentationFrameNumber,
                outGpuHeader.Width,
                outGpuHeader.Height,
                static_cast<DXGI_FORMAT>(outGpuHeader.PixelFormat),
                patternOk);
            if (FAILED(patHr))
            {
                patternOk = false;
            }
        }

        if (m_config.SimulatedAckDelayMsForTesting > 0U)
        {
            Sleep(m_config.SimulatedAckDelayMsForTesting);
        }

        const uint64_t recvCompleteQpc = QueryCurrentQpc();
        if (m_config.SendAck)
        {
            const HRESULT ackSendHr = SendGpuFrameAck(
                outGpuHeader.FrameSequence,
                outGpuHeader.PresentationFrameNumber,
                ipc::FrameIpcStatus::Ok,
                static_cast<uint16_t>(slotIdx),
                static_cast<uint16_t>(outGpuHeader.SlotGeneration),
                syncWaitUs32,
                recvCompleteQpc,
                stopEvent);
            if (FAILED(ackSendHr))
            {
                ClosePipeAndResetConnectionState(false);
                ExclusiveLock lock(&m_metricsLock);
                if (ackSendHr == HRESULT_FROM_WIN32(ERROR_TIMEOUT))
                {
                    ++m_metrics.FatalIoTimeouts;
                }
                if (ackSendHr != HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED))
                {
                    ++m_metrics.FatalIpcErrors;
                    m_metrics.TransportHealthy = false;
                }
                m_metrics.LastErrorHResult = ackSendHr;
                return ackSendHr;
            }
        }

        const uint64_t ackCompleteQpc = QueryCurrentQpc();
        ipc::FrameIpcFrameHeader synthHdr{};
        synthHdr.Envelope = outGpuHeader.Envelope;
        synthHdr.SessionId = outGpuHeader.SessionId;
        synthHdr.FrameSequence = outGpuHeader.FrameSequence;
        synthHdr.PresentationFrameNumber = outGpuHeader.PresentationFrameNumber;
        synthHdr.Width = outGpuHeader.Width;
        synthHdr.Height = outGpuHeader.Height;
        synthHdr.RowPitchBytes = outGpuHeader.Width * ipc::kBytesPerPixelBgra8;
        synthHdr.PixelFormat = outGpuHeader.PixelFormat;
        synthHdr.Flags = outGpuHeader.Flags;
        synthHdr.PresentDisplayQpcTime = outGpuHeader.PresentDisplayQpcTime;
        synthHdr.ExtractCompleteQpcTime = outGpuHeader.ExtractCompleteQpcTime;
        synthHdr.ServerSendQpcTime = outGpuHeader.ServerSendQpcTime;
        synthHdr.QpcFrequency = outGpuHeader.QpcFrequency;

        const ValidatedFrameIntervals intervals = ComputeValidatedFrameIntervals(
            synthHdr,
            recvCompleteQpc,
            ackCompleteQpc,
            m_qpcFreq,
            m_config.SendAck);

        {
            ExclusiveLock lock(&m_metricsLock);
            RecordFrameMetricsAndTimestampsLocked(
                outGpuHeader.FrameSequence,
                outGpuHeader.PresentationFrameNumber,
                outGpuHeader.Width,
                outGpuHeader.Height,
                outGpuHeader.PixelFormat,
                0U,
                static_cast<uint64_t>(sizeof(outGpuHeader)),
                true,
                patternOk,
                outGpuHeader.PresentDisplayQpcTime,
                outGpuHeader.ExtractCompleteQpcTime,
                outGpuHeader.ServerSendQpcTime,
                recvCompleteQpc,
                ackCompleteQpc,
                intervals,
                true,
                syncWaitUs64,
                true,
                hostGpuCopyUs);
        }

        outIsGpuFrame = true;
        return S_OK;
    }

    if (env.Magic != ipc::kFrameIpcMagic ||
        env.VersionMajor != ipc::kFrameIpcProtocolVersionMajor ||
        !ipc::IsSupportedProtocolMinorVersion(env.VersionMinor) ||
        env.MessageType != static_cast<uint16_t>(ipc::FrameIpcMessageType::FrameHeader) ||
        env.HeaderSizeBytes != sizeof(ipc::FrameIpcFrameHeader))
    {
        const ipc::FrameIpcStatus badStatus =
            (env.Magic != ipc::kFrameIpcMagic) ? ipc::FrameIpcStatus::InvalidMagic :
            ((env.VersionMajor != ipc::kFrameIpcProtocolVersionMajor ||
              !ipc::IsSupportedProtocolMinorVersion(env.VersionMinor))
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
        RecordFrameMetricsAndTimestampsLocked(
            outHeader.FrameSequence,
            outHeader.PresentationFrameNumber,
            outHeader.Width,
            outHeader.Height,
            outHeader.PixelFormat,
            actualCrc,
            static_cast<uint64_t>(outPixels.size()) + sizeof(outHeader),
            crcOk,
            patternOk,
            outHeader.PresentDisplayQpcTime,
            outHeader.ExtractCompleteQpcTime,
            outHeader.ServerSendQpcTime,
            recvPayloadQpc,
            ackCompleteQpc,
            intervals,
            false,
            0ULL,
            false,
            0ULL);
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
    const std::function<void(const ipc::FrameIpcFrameHeader&, const std::vector<uint8_t>&)>& onFrame,
    const std::function<void(
        const ipc::FrameIpcGpuFrameHeader&,
        ID3D11Device*,
        ID3D11DeviceContext*,
        ID3D11Texture2D*)>& onGpuFrame
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

        bool isGpuFrame = false;
        ipc::FrameIpcGpuFrameHeader gpuHeader{};
        ipc::FrameIpcFrameHeader header{};
        const HRESULT recvHr = ReceiveNextGpuOrCpuFrame(
            isGpuFrame,
            gpuHeader,
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
            const HostConsumerMetricsSnapshot errSnap = GetMetricsSnapshot();
            if (recvHr == HRESULT_FROM_WIN32(ERROR_TIMEOUT))
            {
                finalReason = (errSnap.LastProtocolStatus == ipc::FrameIpcStatus::GpuSyncTimeout)
                    ? HostExitReason::GpuResourceError
                    : HostExitReason::FatalIoTimeout;
            }
            else if (recvHr == HRESULT_FROM_WIN32(ERROR_CRC))
            {
                finalReason = HostExitReason::FatalIntegrityError;
            }
            else if (recvHr == E_OUTOFMEMORY)
            {
                finalReason = HostExitReason::OutOfMemory;
            }
            else if (errSnap.LastProtocolStatus == ipc::FrameIpcStatus::AdapterLuidMismatch)
            {
                finalReason = HostExitReason::AdapterMismatch;
            }
            else if (errSnap.LastProtocolStatus == ipc::FrameIpcStatus::ResourceOpenFailed ||
                     errSnap.LastProtocolStatus == ipc::FrameIpcStatus::DeviceRemoved)
            {
                finalReason = HostExitReason::GpuResourceError;
            }
            else if (recvHr == E_FAIL || recvHr == E_INVALIDARG || recvHr == E_HANDLE)
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

        if (isGpuFrame)
        {
            if (onGpuFrame)
            {
                onGpuFrame(
                    gpuHeader,
                    m_d3dDevice.Get(),
                    m_d3dContext.Get(),
                    m_hostGpuWorkingTexture.Get());
            }
        }
        else if (onFrame)
        {
            onFrame(header, pixels);
        }

        uint64_t framesValidNow = 0ULL;
        {
            SharedLock lock(&m_metricsLock);
            framesValidNow = m_metrics.FramesValid;
        }
        if (m_config.MaxFrames > 0ULL && framesValidNow >= m_config.MaxFrames)
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
        PopulateLatencySummariesLocked(m_metrics);
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
    ClearGpuSharedResources();

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
    PopulateLatencySummariesLocked(snap);
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
