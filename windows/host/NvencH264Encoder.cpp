#include "NvencH264Encoder.h"

#include <algorithm>
#include <cstring>

namespace lumabridge::host {

namespace {

using PFN_NvEncodeAPIGetMaxSupportedVersion = NVENCSTATUS(NVENCAPI*)(uint32_t*);
using PFN_NvEncodeAPICreateInstance = NVENCSTATUS(NVENCAPI*)(NV_ENCODE_API_FUNCTION_LIST*);

uint64_t
QueryQpcNow() noexcept
{
    LARGE_INTEGER li{};
    (void)QueryPerformanceCounter(&li);
    return (li.QuadPart > 0) ? static_cast<uint64_t>(li.QuadPart) : 0ULL;
}

uint64_t
QueryQpcFreqSafe() noexcept
{
    LARGE_INTEGER li{};
    (void)QueryPerformanceFrequency(&li);
    return (li.QuadPart > 0) ? static_cast<uint64_t>(li.QuadPart) : 10000000ULL;
}

bool
IsDeviceRemovedHr(HRESULT hr) noexcept
{
    return hr == DXGI_ERROR_DEVICE_REMOVED ||
           hr == DXGI_ERROR_DEVICE_RESET ||
           hr == DXGI_ERROR_DEVICE_HUNG ||
           hr == DXGI_ERROR_DRIVER_INTERNAL_ERROR;
}

HRESULT
HResultFromNvencStatus(NVENCSTATUS st) noexcept
{
    switch (st)
    {
    case NV_ENC_SUCCESS:
        return S_OK;
    case NV_ENC_ERR_NO_ENCODE_DEVICE:
    case NV_ENC_ERR_UNSUPPORTED_DEVICE:
    case NV_ENC_ERR_DEVICE_NOT_EXIST:
        return DXGI_ERROR_UNSUPPORTED;
    case NV_ENC_ERR_INVALID_PARAM:
        return E_INVALIDARG;
    case NV_ENC_ERR_OUT_OF_MEMORY:
        return E_OUTOFMEMORY;
    case NV_ENC_ERR_ENCODER_BUSY:
        return HRESULT_FROM_WIN32(ERROR_BUSY);
    case NV_ENC_ERR_UNSUPPORTED_PARAM:
        return DXGI_ERROR_UNSUPPORTED;
    default:
        return E_FAIL;
    }
}

const char*
NvencBufferFormatName(NV_ENC_BUFFER_FORMAT fmt) noexcept
{
    switch (fmt)
    {
    case NV_ENC_BUFFER_FORMAT_ARGB:
        return "ARGB";
    case NV_ENC_BUFFER_FORMAT_ABGR:
        return "ABGR";
    case NV_ENC_BUFFER_FORMAT_NV12:
        return "NV12";
    default:
        return "Unknown";
    }
}

class ScopedNvencUnmap final
{
public:
    ScopedNvencUnmap(
        const NV_ENCODE_API_FUNCTION_LIST* fn,
        void* encoder,
        NV_ENC_INPUT_PTR mappedPtr
        ) noexcept
        : m_fn(fn),
          m_encoder(encoder),
          m_mappedPtr(mappedPtr)
    {
    }

    ~ScopedNvencUnmap()
    {
        UnmapNow();
    }

    void UnmapNow() noexcept
    {
        if (m_fn != nullptr && m_encoder != nullptr && m_mappedPtr != nullptr && m_fn->nvEncUnmapInputResource != nullptr)
        {
            (void)m_fn->nvEncUnmapInputResource(m_encoder, m_mappedPtr);
            m_mappedPtr = nullptr;
        }
    }

    ScopedNvencUnmap(const ScopedNvencUnmap&) = delete;
    ScopedNvencUnmap& operator=(const ScopedNvencUnmap&) = delete;

private:
    const NV_ENCODE_API_FUNCTION_LIST* m_fn;
    void* m_encoder;
    NV_ENC_INPUT_PTR m_mappedPtr;
};

class ScopedNvencUnlockBitstream final
{
public:
    ScopedNvencUnlockBitstream(
        const NV_ENCODE_API_FUNCTION_LIST* fn,
        void* encoder,
        NV_ENC_OUTPUT_PTR bitstreamBuffer
        ) noexcept
        : m_fn(fn),
          m_encoder(encoder),
          m_bitstreamBuffer(bitstreamBuffer)
    {
    }

    ~ScopedNvencUnlockBitstream()
    {
        UnlockNow();
    }

    void UnlockNow() noexcept
    {
        if (m_fn != nullptr && m_encoder != nullptr && m_bitstreamBuffer != nullptr && m_fn->nvEncUnlockBitstream != nullptr)
        {
            (void)m_fn->nvEncUnlockBitstream(m_encoder, m_bitstreamBuffer);
            m_bitstreamBuffer = nullptr;
        }
    }

    ScopedNvencUnlockBitstream(const ScopedNvencUnlockBitstream&) = delete;
    ScopedNvencUnlockBitstream& operator=(const ScopedNvencUnlockBitstream&) = delete;

private:
    const NV_ENCODE_API_FUNCTION_LIST* m_fn;
    void* m_encoder;
    NV_ENC_OUTPUT_PTR m_bitstreamBuffer;
};

} // namespace

void
EncodedFrameQueue::SetCapacity(size_t maxDepth) noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_maxDepth = (maxDepth == 0U) ? 1U : maxDepth;
    while (m_queue.size() > m_maxDepth)
    {
        m_queue.pop_front();
    }
}

size_t
EncodedFrameQueue::Capacity() const noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_maxDepth;
}

size_t
EncodedFrameQueue::Size() const noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_queue.size();
}

bool
EncodedFrameQueue::PushDropOldest(EncodedFramePacket&& packet) noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    bool dropped = false;
    while (m_queue.size() >= m_maxDepth)
    {
        m_queue.pop_front();
        dropped = true;
    }
    try
    {
        m_queue.push_back(std::move(packet));
    }
    catch (...)
    {
    }
    return dropped;
}

bool
EncodedFrameQueue::TryPop(EncodedFramePacket& outPacket) noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_queue.empty())
    {
        return false;
    }
    outPacket = std::move(m_queue.front());
    m_queue.pop_front();
    return true;
}

void
EncodedFrameQueue::Clear() noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_queue.clear();
}

void
NvencH264Encoder::LatencyStatTracker::Record(uint64_t v) noexcept
{
    if (Count == 0ULL || v < MinVal)
    {
        MinVal = v;
    }
    if (v > MaxVal)
    {
        MaxVal = v;
    }
    Total += v;
    LastVal = v;
    ++Count;
    if (Samples.size() < 65536U)
    {
        try
        {
            Samples.push_back(v);
        }
        catch (...)
        {
        }
    }
}

LatencySummaryStats
NvencH264Encoder::LatencyStatTracker::Summarize() const noexcept
{
    LatencySummaryStats s = ComputeLatencySummary(Samples, LastVal);
    s.SampleCount = Count;
    if (Count > 0ULL)
    {
        s.MinUs = MinVal;
        s.MaxUs = MaxVal;
        s.AvgUs = Total / Count;
    }
    return s;
}

void
NvencH264Encoder::LatencyStatTracker::Reset() noexcept
{
    Samples.clear();
    Count = 0ULL;
    Total = 0ULL;
    MinVal = 0ULL;
    MaxVal = 0ULL;
    LastVal = 0ULL;
}

NvencH264Encoder::~NvencH264Encoder()
{
    Shutdown();
}

bool
NvencH264Encoder::IsSupportedSourceDxgiFormat(DXGI_FORMAT format) noexcept
{
    return format == DXGI_FORMAT_B8G8R8A8_UNORM ||
           format == DXGI_FORMAT_B8G8R8A8_UNORM_SRGB ||
           format == DXGI_FORMAT_R8G8B8A8_UNORM ||
           format == DXGI_FORMAT_R8G8B8A8_UNORM_SRGB;
}

HRESULT
NvencH264Encoder::LoadNvencLibraryAndFunctionList() noexcept
{
    if (m_nvencModule == nullptr)
    {
        m_nvencModule = LoadLibraryExW(L"nvEncodeAPI64.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (m_nvencModule == nullptr)
        {
            const DWORD err = GetLastError();
            return (err != ERROR_SUCCESS) ? HRESULT_FROM_WIN32(err) : HRESULT_FROM_WIN32(ERROR_MOD_NOT_FOUND);
        }
    }

    const auto pGetMaxVer = reinterpret_cast<PFN_NvEncodeAPIGetMaxSupportedVersion>(
        GetProcAddress(m_nvencModule, "NvEncodeAPIGetMaxSupportedVersion"));
    const auto pCreateInst = reinterpret_cast<PFN_NvEncodeAPICreateInstance>(
        GetProcAddress(m_nvencModule, "NvEncodeAPICreateInstance"));
    if (pGetMaxVer == nullptr || pCreateInst == nullptr)
    {
        return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
    }

    uint32_t driverMaxApi = 0U;
    NVENCSTATUS st = pGetMaxVer(&driverMaxApi);
    if (st != NV_ENC_SUCCESS)
    {
        m_metrics.LastNvencStatus = st;
        return HResultFromNvencStatus(st);
    }

    const uint32_t driverMajor = (driverMaxApi >> 4U);
    const uint32_t driverMinor = (driverMaxApi & 0xFU);
    m_capabilities.RuntimeLibraryLoaded = true;
    m_capabilities.DriverMaxApiVersionMajor = driverMajor;
    m_capabilities.DriverMaxApiVersionMinor = driverMinor;

    // Require driver support >= NVENC SDK 12.1 (major 12, minor 1).
    if (driverMajor < NVENCAPI_MAJOR_VERSION ||
        (driverMajor == NVENCAPI_MAJOR_VERSION && driverMinor < NVENCAPI_MINOR_VERSION))
    {
        m_metrics.LastNvencStatus = NV_ENC_ERR_INVALID_VERSION;
        return DXGI_ERROR_UNSUPPORTED;
    }

    std::memset(&m_nvencFn, 0, sizeof(m_nvencFn));
    m_nvencFn.version = NV_ENCODE_API_FUNCTION_LIST_VER;
    st = pCreateInst(&m_nvencFn);
    if (st != NV_ENC_SUCCESS || m_nvencFn.nvEncOpenEncodeSessionEx == nullptr)
    {
        m_metrics.LastNvencStatus = st;
        return HResultFromNvencStatus(st);
    }

    return S_OK;
}

HRESULT
NvencH264Encoder::QueryEncoderCapabilities(NvencCapabilitiesSnapshot& outCaps) noexcept
{
    if (m_encoder == nullptr || m_nvencFn.nvEncGetEncodeGUIDCount == nullptr)
    {
        return E_NOT_VALID_STATE;
    }

    uint32_t guidCount = 0U;
    NVENCSTATUS st = m_nvencFn.nvEncGetEncodeGUIDCount(m_encoder, &guidCount);
    if (st != NV_ENC_SUCCESS || guidCount == 0U)
    {
        m_metrics.LastNvencStatus = st;
        return HResultFromNvencStatus(st);
    }

    std::vector<GUID> guids(guidCount);
    uint32_t retrievedCount = 0U;
    st = m_nvencFn.nvEncGetEncodeGUIDs(m_encoder, guids.data(), guidCount, &retrievedCount);
    if (st != NV_ENC_SUCCESS)
    {
        m_metrics.LastNvencStatus = st;
        return HResultFromNvencStatus(st);
    }

    bool hasH264 = false;
    for (uint32_t i = 0U; i < retrievedCount; ++i)
    {
        if (std::memcmp(&guids[i], &NV_ENC_CODEC_H264_GUID, sizeof(GUID)) == 0)
        {
            hasH264 = true;
            break;
        }
    }
    outCaps.H264Supported = hasH264;
    if (!hasH264)
    {
        return DXGI_ERROR_UNSUPPORTED;
    }

    uint32_t fmtCount = 0U;
    if (m_nvencFn.nvEncGetInputFormatCount(m_encoder, NV_ENC_CODEC_H264_GUID, &fmtCount) == NV_ENC_SUCCESS && fmtCount > 0U)
    {
        std::vector<NV_ENC_BUFFER_FORMAT> fmts(fmtCount);
        uint32_t actualFmts = 0U;
        if (m_nvencFn.nvEncGetInputFormats(m_encoder, NV_ENC_CODEC_H264_GUID, fmts.data(), fmtCount, &actualFmts) == NV_ENC_SUCCESS)
        {
            for (uint32_t i = 0U; i < actualFmts; ++i)
            {
                if (fmts[i] == NV_ENC_BUFFER_FORMAT_ARGB)
                {
                    outCaps.SupportsArgbInput = true;
                }
                else if (fmts[i] == NV_ENC_BUFFER_FORMAT_ABGR)
                {
                    outCaps.SupportsAbgrInput = true;
                }
                else if (fmts[i] == NV_ENC_BUFFER_FORMAT_NV12)
                {
                    outCaps.SupportsNv12Input = true;
                }
            }
        }
    }

    auto queryCap = [&](NV_ENC_CAPS capId) noexcept -> int32_t {
        NV_ENC_CAPS_PARAM param{};
        param.version = NV_ENC_CAPS_PARAM_VER;
        param.capsToQuery = capId;
        int32_t val = 0;
        if (m_nvencFn.nvEncGetEncodeCaps(m_encoder, NV_ENC_CODEC_H264_GUID, &param, &val) == NV_ENC_SUCCESS)
        {
            return val;
        }
        return 0;
    };

    outCaps.MaxWidth = static_cast<uint32_t>(std::max<int32_t>(0, queryCap(NV_ENC_CAPS_WIDTH_MAX)));
    outCaps.MaxHeight = static_cast<uint32_t>(std::max<int32_t>(0, queryCap(NV_ENC_CAPS_HEIGHT_MAX)));
    outCaps.MaxBFrames = queryCap(NV_ENC_CAPS_NUM_MAX_BFRAMES);
    outCaps.SupportsDynamicResolutionChange = (queryCap(NV_ENC_CAPS_SUPPORT_DYN_RES_CHANGE) != 0);
    outCaps.SupportsDynamicBitrateChange = (queryCap(NV_ENC_CAPS_SUPPORT_DYN_BITRATE_CHANGE) != 0);
    return S_OK;
}

bool
NvencH264Encoder::ProbeAvailability(
    ID3D11Device* d3dDevice,
    NvencCapabilitiesSnapshot& outCapabilities,
    NVENCSTATUS* outNvencStatus
    ) noexcept
{
    outCapabilities = {};
    if (outNvencStatus != nullptr)
    {
        *outNvencStatus = NV_ENC_SUCCESS;
    }
    if (d3dDevice == nullptr)
    {
        return false;
    }

    NvencH264Encoder probe;
    const HRESULT loadHr = probe.LoadNvencLibraryAndFunctionList();
    outCapabilities = probe.m_capabilities;
    if (FAILED(loadHr))
    {
        if (outNvencStatus != nullptr)
        {
            *outNvencStatus = probe.m_metrics.LastNvencStatus;
        }
        return false;
    }

    NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS openParams{};
    openParams.version = NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS_VER;
    openParams.deviceType = NV_ENC_DEVICE_TYPE_DIRECTX;
    openParams.device = d3dDevice;
    openParams.apiVersion = NVENCAPI_VERSION;

    void* session = nullptr;
    const NVENCSTATUS openSt = probe.m_nvencFn.nvEncOpenEncodeSessionEx(&openParams, &session);
    if (openSt != NV_ENC_SUCCESS || session == nullptr)
    {
        if (outNvencStatus != nullptr)
        {
            *outNvencStatus = openSt;
        }
        return false;
    }

    probe.m_encoder = session;
    probe.m_capabilities.SessionOpened = true;
    const HRESULT capsHr = probe.QueryEncoderCapabilities(probe.m_capabilities);
    outCapabilities = probe.m_capabilities;
    if (outNvencStatus != nullptr)
    {
        *outNvencStatus = probe.m_metrics.LastNvencStatus;
    }

    (void)probe.m_nvencFn.nvEncDestroyEncoder(session);
    probe.m_encoder = nullptr;
    probe.Shutdown();
    return SUCCEEDED(capsHr) && outCapabilities.H264Supported;
}

HRESULT
NvencH264Encoder::Initialize(
    ID3D11Device* d3dDevice,
    ID3D11DeviceContext* d3dContext,
    const NvencEncoderConfig& config
    ) noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    ReleaseSessionObjectsPreserveStats();

    if (d3dDevice == nullptr || d3dContext == nullptr || config.Width == 0U || config.Height == 0U)
    {
        m_metrics.LastHResult = E_INVALIDARG;
        return E_INVALIDARG;
    }

    m_qpcFrequency = QueryQpcFreqSafe();
    m_config = config;
    if (m_config.TargetFps == 0U)
    {
        m_config.TargetFps = 60U;
    }
    if (m_config.BitrateBps == 0U)
    {
        m_config.BitrateBps = 15000000U;
    }
    if (m_config.MaxBitrateBps < m_config.BitrateBps)
    {
        m_config.MaxBitrateBps = m_config.BitrateBps;
    }
    if (m_config.GopLength == 0U)
    {
        m_config.GopLength = 120U;
    }
    m_encodedQueue.SetCapacity(m_config.MaxEncodedQueueDepth);

    const HRESULT loadHr = LoadNvencLibraryAndFunctionList();
    if (FAILED(loadHr))
    {
        m_metrics.LastHResult = loadHr;
        m_metrics.Capabilities = m_capabilities;
        return loadHr;
    }

    m_d3dDevice = d3dDevice;
    m_d3dContext = d3dContext;

    NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS openParams{};
    openParams.version = NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS_VER;
    openParams.deviceType = NV_ENC_DEVICE_TYPE_DIRECTX;
    openParams.device = d3dDevice;
    openParams.apiVersion = NVENCAPI_VERSION;

    NVENCSTATUS st = m_nvencFn.nvEncOpenEncodeSessionEx(&openParams, &m_encoder);
    if (st != NV_ENC_SUCCESS || m_encoder == nullptr)
    {
        m_metrics.LastNvencStatus = st;
        m_metrics.LastHResult = HResultFromNvencStatus(st);
        ReleaseSessionObjectsPreserveStats();
        return m_metrics.LastHResult;
    }
    m_capabilities.SessionOpened = true;

    const HRESULT capsHr = QueryEncoderCapabilities(m_capabilities);
    if (FAILED(capsHr))
    {
        m_metrics.LastHResult = capsHr;
        m_metrics.Capabilities = m_capabilities;
        ReleaseSessionObjectsPreserveStats();
        return capsHr;
    }

    if ((m_capabilities.MaxWidth > 0U && m_config.Width > m_capabilities.MaxWidth) ||
        (m_capabilities.MaxHeight > 0U && m_config.Height > m_capabilities.MaxHeight))
    {
        m_metrics.LastHResult = DXGI_ERROR_UNSUPPORTED;
        m_metrics.Capabilities = m_capabilities;
        ReleaseSessionObjectsPreserveStats();
        return DXGI_ERROR_UNSUPPORTED;
    }

    NV_ENC_PRESET_CONFIG presetConfig{};
    presetConfig.version = NV_ENC_PRESET_CONFIG_VER;
    presetConfig.presetCfg.version = NV_ENC_CONFIG_VER;
    const NV_ENC_TUNING_INFO tuningInfo = m_config.LowLatencyTuning
        ? NV_ENC_TUNING_INFO_ULTRA_LOW_LATENCY
        : NV_ENC_TUNING_INFO_HIGH_QUALITY;

    st = m_nvencFn.nvEncGetEncodePresetConfigEx(
        m_encoder,
        NV_ENC_CODEC_H264_GUID,
        NV_ENC_PRESET_P1_GUID,
        tuningInfo,
        &presetConfig);
    if (st != NV_ENC_SUCCESS)
    {
        m_metrics.LastNvencStatus = st;
        m_metrics.LastHResult = HResultFromNvencStatus(st);
        ReleaseSessionObjectsPreserveStats();
        return m_metrics.LastHResult;
    }

    NV_ENC_CONFIG encodeCfg = presetConfig.presetCfg;
    encodeCfg.version = NV_ENC_CONFIG_VER;
    encodeCfg.profileGUID = NV_ENC_H264_PROFILE_HIGH_GUID;
    encodeCfg.gopLength = m_config.GopLength;
    encodeCfg.frameIntervalP = 1; // 0 B-frames for minimum encode/decode latency.
    encodeCfg.rcParams.rateControlMode = NV_ENC_PARAMS_RC_CBR;
    encodeCfg.rcParams.averageBitRate = m_config.BitrateBps;
    encodeCfg.rcParams.maxBitRate = m_config.MaxBitrateBps;
    encodeCfg.rcParams.vbvBufferSize = std::max<uint32_t>(
        m_config.BitrateBps / m_config.TargetFps,
        m_config.BitrateBps / 120U);
    encodeCfg.rcParams.vbvInitialDelay = encodeCfg.rcParams.vbvBufferSize;
    encodeCfg.rcParams.enableLookahead = 0U;
    encodeCfg.rcParams.zeroReorderDelay = 1U;
    encodeCfg.encodeCodecConfig.h264Config.idrPeriod = m_config.GopLength;
    encodeCfg.encodeCodecConfig.h264Config.repeatSPSPPS = m_config.RepeatSpsPpsEveryIdr ? 1U : 0U;
    encodeCfg.encodeCodecConfig.h264Config.chromaFormatIDC = 1U;
    encodeCfg.encodeCodecConfig.h264Config.sliceMode = 0U;
    encodeCfg.encodeCodecConfig.h264Config.sliceModeData = 0U;

    NV_ENC_INITIALIZE_PARAMS initParams{};
    initParams.version = NV_ENC_INITIALIZE_PARAMS_VER;
    initParams.encodeGUID = NV_ENC_CODEC_H264_GUID;
    initParams.presetGUID = NV_ENC_PRESET_P1_GUID;
    initParams.encodeWidth = m_config.Width;
    initParams.encodeHeight = m_config.Height;
    initParams.darWidth = m_config.Width;
    initParams.darHeight = m_config.Height;
    initParams.frameRateNum = m_config.TargetFps;
    initParams.frameRateDen = 1U;
    initParams.enableEncodeAsync = 0U;
    initParams.enablePTD = 1U;
    initParams.maxEncodeWidth = m_config.Width;
    initParams.maxEncodeHeight = m_config.Height;
    initParams.tuningInfo = tuningInfo;
    initParams.encodeConfig = &encodeCfg;

    st = m_nvencFn.nvEncInitializeEncoder(m_encoder, &initParams);
    if (st != NV_ENC_SUCCESS)
    {
        m_metrics.LastNvencStatus = st;
        m_metrics.LastHResult = HResultFromNvencStatus(st);
        ReleaseSessionObjectsPreserveStats();
        return m_metrics.LastHResult;
    }

    NV_ENC_CREATE_BITSTREAM_BUFFER createBs{};
    createBs.version = NV_ENC_CREATE_BITSTREAM_BUFFER_VER;
    st = m_nvencFn.nvEncCreateBitstreamBuffer(m_encoder, &createBs);
    if (st != NV_ENC_SUCCESS || createBs.bitstreamBuffer == nullptr)
    {
        m_metrics.LastNvencStatus = st;
        m_metrics.LastHResult = HResultFromNvencStatus(st);
        ReleaseSessionObjectsPreserveStats();
        return m_metrics.LastHResult;
    }

    m_bitstreamBuffer = createBs.bitstreamBuffer;
    m_initialized = true;
    m_forceIdrNextFrame = true;
    m_firstEncodedQpc = 0ULL;
    m_lastEncodedQpc = 0ULL;

    m_metrics.Initialized = true;
    m_metrics.DeviceRemovedOrReset = false;
    m_metrics.Width = m_config.Width;
    m_metrics.Height = m_config.Height;
    m_metrics.TargetFps = m_config.TargetFps;
    m_metrics.ConfiguredBitrateBps = m_config.BitrateBps;
    m_metrics.LastNvencStatus = NV_ENC_SUCCESS;
    m_metrics.LastHResult = S_OK;
    m_metrics.Capabilities = m_capabilities;
    return S_OK;
}

void
NvencH264Encoder::ReleaseSessionObjectsPreserveStats() noexcept
{
    if (m_encoder != nullptr)
    {
        if (m_registeredResource != nullptr && m_nvencFn.nvEncUnregisterResource != nullptr)
        {
            (void)m_nvencFn.nvEncUnregisterResource(m_encoder, m_registeredResource);
            m_registeredResource = nullptr;
        }
        if (m_bitstreamBuffer != nullptr && m_nvencFn.nvEncDestroyBitstreamBuffer != nullptr)
        {
            (void)m_nvencFn.nvEncDestroyBitstreamBuffer(m_encoder, m_bitstreamBuffer);
            m_bitstreamBuffer = nullptr;
        }
        if (m_nvencFn.nvEncDestroyEncoder != nullptr)
        {
            (void)m_nvencFn.nvEncDestroyEncoder(m_encoder);
        }
        m_encoder = nullptr;
    }

    m_videoProcessor.Reset();
    m_videoProcEnum.Reset();
    m_videoContext.Reset();
    m_videoDevice.Reset();
    m_encoderInputTexture.Reset();
    m_d3dContext.Reset();
    m_d3dDevice.Reset();
    m_vpWidth = 0U;
    m_vpHeight = 0U;
    m_activeNvencInputFormat = NV_ENC_BUFFER_FORMAT_UNDEFINED;
    m_activeSourceFormat = DXGI_FORMAT_UNKNOWN;
    m_initialized = false;
    m_metrics.Initialized = false;
}

void
NvencH264Encoder::Shutdown() noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    ReleaseSessionObjectsPreserveStats();
    m_encodedQueue.Clear();
    if (m_nvencModule != nullptr)
    {
        FreeLibrary(m_nvencModule);
        m_nvencModule = nullptr;
    }
    std::memset(&m_nvencFn, 0, sizeof(m_nvencFn));
}

HRESULT
NvencH264Encoder::ReconstructSession(
    ID3D11Device* d3dDevice,
    ID3D11DeviceContext* d3dContext,
    const NvencEncoderConfig* newConfig
    ) noexcept
{
    NvencEncoderConfig targetCfg{};
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        targetCfg = (newConfig != nullptr) ? *newConfig : m_config;
        ++m_metrics.NvencEncoderResets;
    }
    return Initialize(d3dDevice, d3dContext, targetCfg);
}

void
NvencH264Encoder::RequestForceIdrOnNextFrame() noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_forceIdrNextFrame = true;
}

HRESULT
NvencH264Encoder::EnsureVideoProcessorForNv12(
    uint32_t width,
    uint32_t height,
    DXGI_FORMAT srcFormat
    ) noexcept
{
    (void)srcFormat;
    if (m_d3dDevice == nullptr || m_d3dContext == nullptr)
    {
        return E_NOT_VALID_STATE;
    }

    if (m_videoProcessor != nullptr && m_vpWidth == width && m_vpHeight == height)
    {
        return S_OK;
    }

    m_videoProcessor.Reset();
    m_videoProcEnum.Reset();

    if (m_videoDevice == nullptr)
    {
        HRESULT hr = m_d3dDevice.As(&m_videoDevice);
        if (FAILED(hr) || m_videoDevice == nullptr)
        {
            return FAILED(hr) ? hr : E_NOINTERFACE;
        }
    }
    if (m_videoContext == nullptr)
    {
        HRESULT hr = m_d3dContext.As(&m_videoContext);
        if (FAILED(hr) || m_videoContext == nullptr)
        {
            return FAILED(hr) ? hr : E_NOINTERFACE;
        }
    }

    D3D11_VIDEO_PROCESSOR_CONTENT_DESC contentDesc{};
    contentDesc.InputFrameFormat = D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE;
    contentDesc.InputWidth = width;
    contentDesc.InputHeight = height;
    contentDesc.OutputWidth = width;
    contentDesc.OutputHeight = height;
    contentDesc.Usage = D3D11_VIDEO_USAGE_OPTIMAL_SPEED;

    HRESULT hr = m_videoDevice->CreateVideoProcessorEnumerator(&contentDesc, &m_videoProcEnum);
    if (FAILED(hr) || m_videoProcEnum == nullptr)
    {
        return FAILED(hr) ? hr : E_FAIL;
    }

    hr = m_videoDevice->CreateVideoProcessor(m_videoProcEnum.Get(), 0U, &m_videoProcessor);
    if (FAILED(hr) || m_videoProcessor == nullptr)
    {
        return FAILED(hr) ? hr : E_FAIL;
    }

    m_vpWidth = width;
    m_vpHeight = height;
    return S_OK;
}

HRESULT
NvencH264Encoder::EnsureRegisteredInputResource(
    uint32_t width,
    uint32_t height,
    DXGI_FORMAT srcFormat,
    NV_ENC_BUFFER_FORMAT targetNvencFormat
    ) noexcept
{
    if (m_encoder == nullptr || m_d3dDevice == nullptr)
    {
        return E_NOT_VALID_STATE;
    }

    if (m_registeredResource != nullptr &&
        m_encoderInputTexture != nullptr &&
        m_activeNvencInputFormat == targetNvencFormat &&
        m_activeSourceFormat == srcFormat)
    {
        return S_OK;
    }

    if (m_registeredResource != nullptr && m_nvencFn.nvEncUnregisterResource != nullptr)
    {
        (void)m_nvencFn.nvEncUnregisterResource(m_encoder, m_registeredResource);
        m_registeredResource = nullptr;
    }
    m_encoderInputTexture.Reset();

    DXGI_FORMAT texFormat = DXGI_FORMAT_B8G8R8A8_UNORM;
    UINT bindFlags = D3D11_BIND_RENDER_TARGET | D3D11_BIND_SHADER_RESOURCE;
    if (targetNvencFormat == NV_ENC_BUFFER_FORMAT_NV12)
    {
        texFormat = DXGI_FORMAT_NV12;
        bindFlags = D3D11_BIND_RENDER_TARGET;
    }
    else if (targetNvencFormat == NV_ENC_BUFFER_FORMAT_ABGR)
    {
        texFormat = DXGI_FORMAT_R8G8B8A8_UNORM;
    }

    D3D11_TEXTURE2D_DESC desc{};
    desc.Width = width;
    desc.Height = height;
    desc.MipLevels = 1U;
    desc.ArraySize = 1U;
    desc.Format = texFormat;
    desc.SampleDesc.Count = 1U;
    desc.SampleDesc.Quality = 0U;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = bindFlags;

    HRESULT hr = m_d3dDevice->CreateTexture2D(&desc, nullptr, &m_encoderInputTexture);
    if (FAILED(hr) || m_encoderInputTexture == nullptr)
    {
        return FAILED(hr) ? hr : E_OUTOFMEMORY;
    }

    NV_ENC_REGISTER_RESOURCE reg{};
    reg.version = NV_ENC_REGISTER_RESOURCE_VER;
    reg.resourceType = NV_ENC_INPUT_RESOURCE_TYPE_DIRECTX;
    reg.width = width;
    reg.height = height;
    reg.pitch = 0U;
    reg.subResourceIndex = 0U;
    reg.resourceToRegister = m_encoderInputTexture.Get();
    reg.bufferFormat = targetNvencFormat;
    reg.bufferUsage = NV_ENC_INPUT_IMAGE;

    const NVENCSTATUS st = m_nvencFn.nvEncRegisterResource(m_encoder, &reg);
    if (st != NV_ENC_SUCCESS || reg.registeredResource == nullptr)
    {
        m_encoderInputTexture.Reset();
        m_metrics.LastNvencStatus = st;
        return HResultFromNvencStatus(st);
    }

    m_registeredResource = reg.registeredResource;
    m_activeNvencInputFormat = targetNvencFormat;
    m_activeSourceFormat = srcFormat;
    m_capabilities.SelectedInputFormatName = NvencBufferFormatName(targetNvencFormat);
    m_metrics.Capabilities = m_capabilities;
    return S_OK;
}

HRESULT
NvencH264Encoder::PrepareInputTextureOnGpu(
    ID3D11Texture2D* srcTexture,
    uint32_t width,
    uint32_t height,
    DXGI_FORMAT srcFormat,
    NV_ENC_BUFFER_FORMAT targetNvencFormat
    ) noexcept
{
    if (m_hooks != nullptr)
    {
        const HRESULT hookHr = m_hooks->OnPreGpuFormatPrepare(srcTexture);
        if (FAILED(hookHr))
        {
            return hookHr;
        }
    }

    if (targetNvencFormat != NV_ENC_BUFFER_FORMAT_NV12)
    {
        m_d3dContext->CopyResource(m_encoderInputTexture.Get(), srcTexture);
        return S_OK;
    }

    HRESULT hr = EnsureVideoProcessorForNv12(width, height, srcFormat);
    if (FAILED(hr))
    {
        return hr;
    }

    D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC ivDesc{};
    ivDesc.FourCC = 0U;
    ivDesc.ViewDimension = D3D11_VPIV_DIMENSION_TEXTURE2D;
    ivDesc.Texture2D.MipSlice = 0U;
    ivDesc.Texture2D.ArraySlice = 0U;

    Microsoft::WRL::ComPtr<ID3D11VideoProcessorInputView> inputView;
    hr = m_videoDevice->CreateVideoProcessorInputView(srcTexture, m_videoProcEnum.Get(), &ivDesc, &inputView);
    if (FAILED(hr) || inputView == nullptr)
    {
        return FAILED(hr) ? hr : E_FAIL;
    }

    D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC ovDesc{};
    ovDesc.ViewDimension = D3D11_VPOV_DIMENSION_TEXTURE2D;
    ovDesc.Texture2D.MipSlice = 0U;

    Microsoft::WRL::ComPtr<ID3D11VideoProcessorOutputView> outputView;
    hr = m_videoDevice->CreateVideoProcessorOutputView(m_encoderInputTexture.Get(), m_videoProcEnum.Get(), &ovDesc, &outputView);
    if (FAILED(hr) || outputView == nullptr)
    {
        return FAILED(hr) ? hr : E_FAIL;
    }

    D3D11_VIDEO_PROCESSOR_STREAM stream{};
    stream.Enable = TRUE;
    stream.pInputSurface = inputView.Get();

    hr = m_videoContext->VideoProcessorBlt(m_videoProcessor.Get(), outputView.Get(), 0U, 1U, &stream);
    return hr;
}

HRESULT
NvencH264Encoder::EncodeGpuTexture(
    ID3D11Texture2D* sourceGpuTexture,
    uint64_t frameSequence,
    uint32_t presentationFrameNumber,
    uint64_t presentDisplayQpcTime,
    uint64_t extractCompleteQpcTime,
    uint64_t qpcFrequency,
    EncodedFramePacket* outPacketCopy
    ) noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_initialized || m_encoder == nullptr || m_d3dDevice == nullptr || m_d3dContext == nullptr)
    {
        m_metrics.LastHResult = E_NOT_VALID_STATE;
        return E_NOT_VALID_STATE;
    }
    if (sourceGpuTexture == nullptr)
    {
        m_metrics.LastHResult = E_INVALIDARG;
        return E_INVALIDARG;
    }

    const HRESULT removedReason = m_d3dDevice->GetDeviceRemovedReason();
    if (IsDeviceRemovedHr(removedReason))
    {
        m_metrics.DeviceRemovedOrReset = true;
        m_metrics.LastHResult = removedReason;
        return removedReason;
    }

    D3D11_TEXTURE2D_DESC srcDesc{};
    sourceGpuTexture->GetDesc(&srcDesc);
    if (!IsSupportedSourceDxgiFormat(srcDesc.Format))
    {
        m_metrics.LastHResult = DXGI_ERROR_UNSUPPORTED;
        return DXGI_ERROR_UNSUPPORTED;
    }
    if (srcDesc.Width != m_config.Width || srcDesc.Height != m_config.Height)
    {
        // Dimension mismatch requires session reinitialization/reconfiguration.
        m_metrics.LastHResult = E_INVALIDARG;
        return E_INVALIDARG;
    }

    NV_ENC_BUFFER_FORMAT targetFmt = NV_ENC_BUFFER_FORMAT_UNDEFINED;
    if (m_config.ColorMode == NvencColorConversionMode::GpuVideoProcessorNv12)
    {
        targetFmt = m_capabilities.SupportsNv12Input ? NV_ENC_BUFFER_FORMAT_NV12 : NV_ENC_BUFFER_FORMAT_UNDEFINED;
    }
    else if (m_config.ColorMode == NvencColorConversionMode::DirectArgb)
    {
        if (srcDesc.Format == DXGI_FORMAT_R8G8B8A8_UNORM || srcDesc.Format == DXGI_FORMAT_R8G8B8A8_UNORM_SRGB)
        {
            targetFmt = m_capabilities.SupportsAbgrInput ? NV_ENC_BUFFER_FORMAT_ABGR : NV_ENC_BUFFER_FORMAT_NV12;
        }
        else
        {
            targetFmt = m_capabilities.SupportsArgbInput ? NV_ENC_BUFFER_FORMAT_ARGB : NV_ENC_BUFFER_FORMAT_NV12;
        }
    }
    else
    {
        if ((srcDesc.Format == DXGI_FORMAT_B8G8R8A8_UNORM || srcDesc.Format == DXGI_FORMAT_B8G8R8A8_UNORM_SRGB) &&
            m_capabilities.SupportsArgbInput)
        {
            targetFmt = NV_ENC_BUFFER_FORMAT_ARGB;
        }
        else if ((srcDesc.Format == DXGI_FORMAT_R8G8B8A8_UNORM || srcDesc.Format == DXGI_FORMAT_R8G8B8A8_UNORM_SRGB) &&
                 m_capabilities.SupportsAbgrInput)
        {
            targetFmt = NV_ENC_BUFFER_FORMAT_ABGR;
        }
        else if (m_capabilities.SupportsNv12Input)
        {
            targetFmt = NV_ENC_BUFFER_FORMAT_NV12;
        }
    }

    if (targetFmt == NV_ENC_BUFFER_FORMAT_UNDEFINED)
    {
        m_metrics.LastHResult = DXGI_ERROR_UNSUPPORTED;
        return DXGI_ERROR_UNSUPPORTED;
    }

    HRESULT hr = EnsureRegisteredInputResource(srcDesc.Width, srcDesc.Height, srcDesc.Format, targetFmt);
    if (FAILED(hr))
    {
        m_metrics.LastHResult = hr;
        return hr;
    }

    const uint64_t encodeStartQpc = QueryQpcNow();
    hr = PrepareInputTextureOnGpu(sourceGpuTexture, srcDesc.Width, srcDesc.Height, srcDesc.Format, targetFmt);
    if (FAILED(hr))
    {
        if (IsDeviceRemovedHr(hr) || IsDeviceRemovedHr(m_d3dDevice->GetDeviceRemovedReason()))
        {
            m_metrics.DeviceRemovedOrReset = true;
        }
        m_metrics.LastHResult = hr;
        return hr;
    }

    NV_ENC_MAP_INPUT_RESOURCE mapRes{};
    mapRes.version = NV_ENC_MAP_INPUT_RESOURCE_VER;
    mapRes.registeredResource = m_registeredResource;
    NVENCSTATUS st = m_nvencFn.nvEncMapInputResource(m_encoder, &mapRes);
    if (st != NV_ENC_SUCCESS || mapRes.mappedResource == nullptr)
    {
        m_metrics.LastNvencStatus = st;
        m_metrics.LastHResult = HResultFromNvencStatus(st);
        return m_metrics.LastHResult;
    }
    ScopedNvencUnmap unmapGuard(&m_nvencFn, m_encoder, mapRes.mappedResource);

    NV_ENC_PIC_PARAMS picParams{};
    picParams.version = NV_ENC_PIC_PARAMS_VER;
    picParams.inputWidth = srcDesc.Width;
    picParams.inputHeight = srcDesc.Height;
    picParams.inputPitch = srcDesc.Width;
    picParams.inputBuffer = mapRes.mappedResource;
    picParams.outputBitstream = m_bitstreamBuffer;
    picParams.bufferFmt = mapRes.mappedBufferFmt;
    picParams.pictureStruct = NV_ENC_PIC_STRUCT_FRAME;
    picParams.inputTimeStamp = frameSequence;
    picParams.frameIdx = static_cast<uint32_t>(frameSequence);
    if (m_forceIdrNextFrame)
    {
        picParams.encodePicFlags = NV_ENC_PIC_FLAG_FORCEIDR | NV_ENC_PIC_FLAG_OUTPUT_SPSPPS;
    }

    ++m_metrics.NvencFramesSubmitted;
    if (m_hooks != nullptr)
    {
        const NVENCSTATUS hookSt = m_hooks->OnPreEncodePicture(frameSequence, picParams);
        if (hookSt != NV_ENC_SUCCESS)
        {
            st = hookSt;
        }
    }
    if (st == NV_ENC_SUCCESS)
    {
        st = m_nvencFn.nvEncEncodePicture(m_encoder, &picParams);
    }

    if (st == NV_ENC_ERR_ENCODER_BUSY)
    {
        ++m_metrics.NvencDroppedFrames;
        m_metrics.LastNvencStatus = st;
        m_metrics.LastHResult = HResultFromNvencStatus(st);
        return m_metrics.LastHResult;
    }
    if (st != NV_ENC_SUCCESS && st != NV_ENC_ERR_NEED_MORE_INPUT)
    {
        m_metrics.LastNvencStatus = st;
        m_metrics.LastHResult = HResultFromNvencStatus(st);
        if (IsDeviceRemovedHr(m_d3dDevice->GetDeviceRemovedReason()))
        {
            m_metrics.DeviceRemovedOrReset = true;
            m_metrics.LastHResult = m_d3dDevice->GetDeviceRemovedReason();
        }
        return m_metrics.LastHResult;
    }

    m_forceIdrNextFrame = false;

    NV_ENC_LOCK_BITSTREAM lockBs{};
    lockBs.version = NV_ENC_LOCK_BITSTREAM_VER;
    lockBs.outputBitstream = m_bitstreamBuffer;
    lockBs.doNotWait = 0U;
    st = m_nvencFn.nvEncLockBitstream(m_encoder, &lockBs);
    if (st != NV_ENC_SUCCESS || lockBs.bitstreamBufferPtr == nullptr || lockBs.bitstreamSizeInBytes == 0U)
    {
        m_metrics.LastNvencStatus = st;
        m_metrics.LastHResult = HResultFromNvencStatus(st);
        return m_metrics.LastHResult;
    }

    EncodedFramePacket pkt{};
    pkt.FrameSequence = frameSequence;
    pkt.PresentationFrameNumber = presentationFrameNumber;
    pkt.Width = srcDesc.Width;
    pkt.Height = srcDesc.Height;
    pkt.PictureType = static_cast<uint32_t>(lockBs.pictureType);
    pkt.IsKeyFrame = (lockBs.pictureType == NV_ENC_PIC_TYPE_IDR || lockBs.pictureType == NV_ENC_PIC_TYPE_I);
    pkt.PresentDisplayQpcTime = presentDisplayQpcTime;
    pkt.ExtractCompleteQpcTime = extractCompleteQpcTime;
    pkt.QpcFrequency = (qpcFrequency > 0ULL) ? qpcFrequency : m_qpcFrequency;

    {
        ScopedNvencUnlockBitstream unlockGuard(&m_nvencFn, m_encoder, m_bitstreamBuffer);
        try
        {
            pkt.Bitstream.resize(lockBs.bitstreamSizeInBytes);
            std::memcpy(pkt.Bitstream.data(), lockBs.bitstreamBufferPtr, lockBs.bitstreamSizeInBytes);
        }
        catch (...)
        {
            m_metrics.LastHResult = E_OUTOFMEMORY;
            return E_OUTOFMEMORY;
        }
    }

    unmapGuard.UnmapNow();

    const uint64_t bitstreamReadyQpc = QueryQpcNow();
    const uint64_t effectiveFreq = (pkt.QpcFrequency > 0ULL) ? pkt.QpcFrequency : m_qpcFrequency;
    const uint64_t encodeLatencyUs = ((bitstreamReadyQpc >= encodeStartQpc)
        ? ((bitstreamReadyQpc - encodeStartQpc) * 1000000ULL) / effectiveFreq
        : 0ULL);

    pkt.BitstreamReadyQpcTime = bitstreamReadyQpc;
    pkt.EncodeLatencyUs = encodeLatencyUs;

    if (outPacketCopy != nullptr)
    {
        try
        {
            *outPacketCopy = pkt;
        }
        catch (...)
        {
        }
    }

    const uint32_t pktSizeBytes = static_cast<uint32_t>(pkt.Bitstream.size());
    const bool queueDropped = m_encodedQueue.PushDropOldest(std::move(pkt));
    if (queueDropped)
    {
        ++m_metrics.EncodedQueueDrops;
    }

    ++m_metrics.NvencFramesEncoded;
    if (pkt.IsKeyFrame)
    {
        ++m_metrics.NvencKeyFramesEncoded;
    }
    m_metrics.TotalBitstreamBytes += pktSizeBytes;
    m_metrics.LastEncodedFrameSizeBytes = pktSizeBytes;
    m_metrics.EncodedQueueDepth = m_encodedQueue.Size();
    if (m_metrics.EncodedQueueDepth > m_metrics.EncodedQueuePeakDepth)
    {
        m_metrics.EncodedQueuePeakDepth = m_metrics.EncodedQueueDepth;
    }
    m_metrics.LastNvencStatus = NV_ENC_SUCCESS;
    m_metrics.LastHResult = S_OK;

    if (m_firstEncodedQpc == 0ULL)
    {
        m_firstEncodedQpc = bitstreamReadyQpc;
    }
    m_lastEncodedQpc = bitstreamReadyQpc;
    if (m_metrics.NvencFramesEncoded >= 2ULL && m_lastEncodedQpc > m_firstEncodedQpc)
    {
        const double spanSec =
            static_cast<double>(m_lastEncodedQpc - m_firstEncodedQpc) / static_cast<double>(effectiveFreq);
        if (spanSec > 0.001)
        {
            m_metrics.EncoderOutputFps = static_cast<double>(m_metrics.NvencFramesEncoded - 1ULL) / spanSec;
            m_metrics.NvencBitrateBps = static_cast<uint64_t>(
                (static_cast<double>(m_metrics.TotalBitstreamBytes) * 8.0) / spanSec);
        }
    }

    m_encodeLatencyTracker.Record(encodeLatencyUs);
    m_packetSizeTracker.Record(pktSizeBytes);
    if (presentDisplayQpcTime > 0ULL && bitstreamReadyQpc >= presentDisplayQpcTime)
    {
        m_presentToBitstreamTracker.Record(((bitstreamReadyQpc - presentDisplayQpcTime) * 1000000ULL) / effectiveFreq);
    }
    if (extractCompleteQpcTime > 0ULL && bitstreamReadyQpc >= extractCompleteQpcTime)
    {
        m_extractToBitstreamTracker.Record(((bitstreamReadyQpc - extractCompleteQpcTime) * 1000000ULL) / effectiveFreq);
    }

    m_metrics.EncodeLatencyUs = m_encodeLatencyTracker.Summarize();
    m_metrics.EncodedFrameSizeBytes = m_packetSizeTracker.Summarize();
    m_metrics.PresentToBitstreamLatencyUs = m_presentToBitstreamTracker.Summarize();
    m_metrics.ExtractToBitstreamLatencyUs = m_extractToBitstreamTracker.Summarize();
    return S_OK;
}

bool
NvencH264Encoder::TryPopEncodedFrame(EncodedFramePacket& outPacket) noexcept
{
    return m_encodedQueue.TryPop(outPacket);
}

void
NvencH264Encoder::SetHooks(INvencApiHooks* hooks) noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_hooks = hooks;
}

NvencMetricsSnapshot
NvencH264Encoder::GetMetricsSnapshot() const noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    NvencMetricsSnapshot snap = m_metrics;
    snap.EncodedQueueDepth = m_encodedQueue.Size();
    return snap;
}

bool
NvencH264Encoder::IsInitialized() const noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_initialized;
}

} // namespace lumabridge::host
