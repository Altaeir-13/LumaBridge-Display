#pragma once

#include <Windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <wrl/client.h>

#include "FrameConsumer.h"
#include "third_party/nvenc/nvEncodeAPI.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

namespace lumabridge::host {

enum class NvencColorConversionMode : uint32_t
{
    Auto = 0U,
    DirectArgb = 1U,
    GpuVideoProcessorNv12 = 2U,
};

struct NvencEncoderConfig
{
    uint32_t Width{1920U};
    uint32_t Height{1080U};
    uint32_t TargetFps{60U};
    uint32_t BitrateBps{15000000U};
    uint32_t MaxBitrateBps{20000000U};
    uint32_t GopLength{120U};
    bool LowLatencyTuning{true};
    bool RepeatSpsPpsEveryIdr{true};
    NvencColorConversionMode ColorMode{NvencColorConversionMode::Auto};
    size_t MaxEncodedQueueDepth{8U};
};

struct NvencCapabilitiesSnapshot
{
    bool RuntimeLibraryLoaded{false};
    bool SessionOpened{false};
    bool H264Supported{false};
    bool SupportsArgbInput{false};
    bool SupportsAbgrInput{false};
    bool SupportsNv12Input{false};
    bool SupportsDynamicResolutionChange{false};
    bool SupportsDynamicBitrateChange{false};
    uint32_t DriverMaxApiVersionMajor{0U};
    uint32_t DriverMaxApiVersionMinor{0U};
    uint32_t MaxWidth{0U};
    uint32_t MaxHeight{0U};
    int32_t MaxBFrames{0};
    std::string SelectedInputFormatName{"None"};
};

struct EncodedFramePacket
{
    uint64_t FrameSequence{0ULL};
    uint32_t PresentationFrameNumber{0U};
    uint32_t Width{0U};
    uint32_t Height{0U};
    bool IsKeyFrame{false};
    uint64_t PresentDisplayQpcTime{0ULL};
    uint64_t ExtractCompleteQpcTime{0ULL};
    uint64_t BitstreamReadyQpcTime{0ULL};
    uint64_t QpcFrequency{10000000ULL};
    uint64_t EncodeLatencyUs{0ULL};
    uint32_t PictureType{0U};
    std::vector<uint8_t> Bitstream{};
};

class EncodedFrameQueue final
{
public:
    EncodedFrameQueue() noexcept = default;

    void SetCapacity(size_t maxDepth) noexcept;
    size_t Capacity() const noexcept;
    size_t Size() const noexcept;

    /// Pushes packet using drop-oldest policy when full; returns true if an older packet was evicted.
    bool PushDropOldest(EncodedFramePacket&& packet) noexcept;

    /// Pops oldest queued packet; returns false if empty.
    bool TryPop(EncodedFramePacket& outPacket) noexcept;

    void Clear() noexcept;

private:
    mutable std::mutex m_mutex{};
    std::deque<EncodedFramePacket> m_queue{};
    size_t m_maxDepth{8U};
};

struct NvencMetricsSnapshot
{
    bool Initialized{false};
    bool DeviceRemovedOrReset{false};
    uint32_t Width{0U};
    uint32_t Height{0U};
    uint32_t TargetFps{60U};
    uint32_t ConfiguredBitrateBps{0U};
    uint64_t NvencBitrateBps{0ULL};
    double EncoderOutputFps{0.0};
    uint64_t NvencFramesSubmitted{0ULL};
    uint64_t NvencFramesEncoded{0ULL};
    uint64_t NvencKeyFramesEncoded{0ULL};
    uint64_t NvencDroppedFrames{0ULL};
    uint64_t NvencEncoderResets{0ULL};
    uint64_t EncodedQueueDrops{0ULL};
    uint64_t EncodedQueueDepth{0ULL};
    uint64_t EncodedQueuePeakDepth{0ULL};
    uint64_t TotalBitstreamBytes{0ULL};
    uint32_t LastEncodedFrameSizeBytes{0U};
    NVENCSTATUS LastNvencStatus{NV_ENC_SUCCESS};
    HRESULT LastHResult{S_OK};
    NvencCapabilitiesSnapshot Capabilities{};
    LatencySummaryStats EncodeLatencyUs{};
    LatencySummaryStats EncodedFrameSizeBytes{};
    LatencySummaryStats PresentToBitstreamLatencyUs{};
    LatencySummaryStats ExtractToBitstreamLatencyUs{};
};

/// Testability seam for injecting NVENC runtime faults (encoder busy, device removed, etc.).
class INvencApiHooks
{
public:
    virtual ~INvencApiHooks() = default;

    virtual NVENCSTATUS OnPreEncodePicture(
        uint64_t frameSequence,
        NV_ENC_PIC_PARAMS& picParams
        ) noexcept
    {
        (void)frameSequence;
        (void)picParams;
        return NV_ENC_SUCCESS;
    }

    virtual HRESULT OnPreGpuFormatPrepare(
        ID3D11Texture2D* sourceTexture
        ) noexcept
    {
        (void)sourceTexture;
        return S_OK;
    }
};

/// Direct3D 11 -> NVIDIA NVENC H.264 encoder with GPU color conversion (ID3D11VideoProcessor BGRA8->NV12),
/// zero-B-frame ultra-low-latency tuning, dynamic reconfiguration, and bounded encoded frame queue.
class NvencH264Encoder final
{
public:
    NvencH264Encoder() noexcept = default;
    ~NvencH264Encoder();

    NvencH264Encoder(const NvencH264Encoder&) = delete;
    NvencH264Encoder& operator=(const NvencH264Encoder&) = delete;

    /// Probes nvEncodeAPI64.dll and GPU capabilities without retaining an active encode session.
    static bool ProbeAvailability(
        ID3D11Device* d3dDevice,
        NvencCapabilitiesSnapshot& outCapabilities,
        NVENCSTATUS* outNvencStatus = nullptr
        ) noexcept;

    /// Initializes an H.264 NVENC session bound to d3dDevice and d3dContext.
    HRESULT Initialize(
        ID3D11Device* d3dDevice,
        ID3D11DeviceContext* d3dContext,
        const NvencEncoderConfig& config
        ) noexcept;

    /// Tears down all NVENC buffers, registered resources, session, and D3D11 video processor resources.
    void Shutdown() noexcept;

    /// Reconstructs the NVENC session after device reset/reconfiguration while preserving cumulative metrics.
    HRESULT ReconstructSession(
        ID3D11Device* d3dDevice,
        ID3D11DeviceContext* d3dContext,
        const NvencEncoderConfig* newConfig = nullptr
        ) noexcept;

    /// Forces the next submitted frame to encode as an IDR keyframe with inline SPS/PPS headers.
    void RequestForceIdrOnNextFrame() noexcept;

    /// Encodes a GPU-resident D3D11 Texture2D frame, pushing the produced Annex-B H.264 packet into the queue.
    HRESULT EncodeGpuTexture(
        ID3D11Texture2D* sourceGpuTexture,
        uint64_t frameSequence,
        uint32_t presentationFrameNumber,
        uint64_t presentDisplayQpcTime,
        uint64_t extractCompleteQpcTime,
        uint64_t qpcFrequency,
        EncodedFramePacket* outPacketCopy = nullptr
        ) noexcept;

    bool TryPopEncodedFrame(EncodedFramePacket& outPacket) noexcept;

    void SetHooks(INvencApiHooks* hooks) noexcept;
    NvencMetricsSnapshot GetMetricsSnapshot() const noexcept;
    bool IsInitialized() const noexcept;

private:
    static bool IsSupportedSourceDxgiFormat(DXGI_FORMAT format) noexcept;
    HRESULT LoadNvencLibraryAndFunctionList() noexcept;
    HRESULT QueryEncoderCapabilities(NvencCapabilitiesSnapshot& outCaps) noexcept;
    HRESULT EnsureVideoProcessorForNv12(uint32_t width, uint32_t height, DXGI_FORMAT srcFormat) noexcept;
    HRESULT EnsureRegisteredInputResource(
        uint32_t width,
        uint32_t height,
        DXGI_FORMAT srcFormat,
        NV_ENC_BUFFER_FORMAT targetNvencFormat
        ) noexcept;
    HRESULT PrepareInputTextureOnGpu(
        ID3D11Texture2D* srcTexture,
        uint32_t width,
        uint32_t height,
        DXGI_FORMAT srcFormat,
        NV_ENC_BUFFER_FORMAT targetNvencFormat
        ) noexcept;
    void ReleaseSessionObjectsPreserveStats() noexcept;

    struct LatencyStatTracker
    {
        std::vector<uint64_t> Samples{};
        uint64_t Count{0ULL};
        uint64_t Total{0ULL};
        uint64_t MinVal{0ULL};
        uint64_t MaxVal{0ULL};
        uint64_t LastVal{0ULL};

        void Record(uint64_t v) noexcept;
        LatencySummaryStats Summarize() const noexcept;
        void Reset() noexcept;
    };

    mutable std::mutex m_mutex{};
    INvencApiHooks* m_hooks{nullptr};

    HMODULE m_nvencModule{nullptr};
    NV_ENCODE_API_FUNCTION_LIST m_nvencFn{};
    void* m_encoder{nullptr};
    NV_ENC_OUTPUT_PTR m_bitstreamBuffer{nullptr};
    NV_ENC_REGISTERED_PTR m_registeredResource{nullptr};

    Microsoft::WRL::ComPtr<ID3D11Device> m_d3dDevice{};
    Microsoft::WRL::ComPtr<ID3D11DeviceContext> m_d3dContext{};
    Microsoft::WRL::ComPtr<ID3D11Texture2D> m_encoderInputTexture{};
    Microsoft::WRL::ComPtr<ID3D11VideoDevice> m_videoDevice{};
    Microsoft::WRL::ComPtr<ID3D11VideoContext> m_videoContext{};
    Microsoft::WRL::ComPtr<ID3D11VideoProcessorEnumerator> m_videoProcEnum{};
    Microsoft::WRL::ComPtr<ID3D11VideoProcessor> m_videoProcessor{};
    uint32_t m_vpWidth{0U};
    uint32_t m_vpHeight{0U};

    NvencEncoderConfig m_config{};
    NvencCapabilitiesSnapshot m_capabilities{};
    NV_ENC_BUFFER_FORMAT m_activeNvencInputFormat{NV_ENC_BUFFER_FORMAT_UNDEFINED};
    DXGI_FORMAT m_activeSourceFormat{DXGI_FORMAT_UNKNOWN};
    bool m_initialized{false};
    bool m_forceIdrNextFrame{true};
    uint64_t m_firstEncodedQpc{0ULL};
    uint64_t m_lastEncodedQpc{0ULL};
    uint64_t m_qpcFrequency{10000000ULL};

    EncodedFrameQueue m_encodedQueue{};
    NvencMetricsSnapshot m_metrics{};
    LatencyStatTracker m_encodeLatencyTracker{};
    LatencyStatTracker m_packetSizeTracker{};
    LatencyStatTracker m_presentToBitstreamTracker{};
    LatencyStatTracker m_extractToBitstreamTracker{};
};

} // namespace lumabridge::host
