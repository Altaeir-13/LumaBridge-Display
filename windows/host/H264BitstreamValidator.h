#pragma once

#include <Windows.h>

#include "../driver/LumaBridgeIddDriver/FrameIpcProtocol.h"
#include "NvencH264Encoder.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace lumabridge::host {

struct H264NalSummary
{
    uint32_t TotalNalUnits{0U};
    uint32_t SpsCount{0U};
    uint32_t PpsCount{0U};
    uint32_t IdrSliceCount{0U};
    uint32_t NonIdrSliceCount{0U};
    uint32_t AudOrSeiOrOtherCount{0U};
    bool HasValidStartCodePrefix{false};
};

struct DecodedNv12Frame
{
    uint32_t Width{0U};
    uint32_t Height{0U};
    uint32_t StrideBytes{0U};
    uint32_t FrameNumber{0U};
    uint64_t SampleTime100Ns{0ULL};
    std::vector<uint8_t> Nv12Bytes{};
};

struct PsnrVerificationResult
{
    bool Valid{false};
    bool Passed{false};
    double YPsnrDb{0.0};
    double UvPsnrDb{0.0};
    double AvgPsnrDb{0.0};
    double MinPsnrDb{0.0};
    std::string MatchedColorMatrix{"None"};
};

struct H264ValidationSummary
{
    bool Enabled{false};
    bool DecoderInitialized{false};
    std::string DecoderName{"None"};
    uint64_t PacketsInspected{0ULL};
    uint64_t FramesDecoded{0ULL};
    uint64_t NalParseFailures{0ULL};
    uint64_t DecodeFailures{0ULL};
    uint64_t PsnrPassCount{0ULL};
    uint64_t PsnrFailCount{0ULL};
    uint64_t SpsCount{0ULL};
    uint64_t PpsCount{0ULL};
    uint64_t IdrCount{0ULL};
    uint64_t NonIdrCount{0ULL};
    double MinYPsnrDb{0.0};
    double AvgYPsnrDb{0.0};
    double MinUvPsnrDb{0.0};
    double AvgUvPsnrDb{0.0};
    bool Passed{false};
    HRESULT LastHResult{S_OK};
};

enum class ColorMatrixStandard : uint32_t
{
    Bt601Limited = 0U,
    Bt709Limited = 1U,
};

/// Inspects an H.264 Annex-B byte stream and counts SPS (7), PPS (8), IDR (5), and Non-IDR (1) NAL units.
bool InspectH264AnnexBNals(
    const uint8_t* data,
    size_t sizeBytes,
    H264NalSummary& outSummary
    ) noexcept;

/// Generates a tightly packed NV12 reference buffer from the deterministic synthetic BGRA8 test pattern.
bool GenerateSyntheticTestPatternNv12Reference(
    uint32_t frameNumber,
    uint32_t width,
    uint32_t height,
    ColorMatrixStandard matrix,
    std::vector<uint8_t>& outNv12Bytes
    ) noexcept;

/// Computes PSNR between a decoded NV12 frame and a reference NV12 buffer (same tight dimensions).
bool ComputeNv12Psnr(
    const DecodedNv12Frame& decodedFrame,
    const uint8_t* referenceNv12Bytes,
    size_t referenceSizeBytes,
    double& outYPsnrDb,
    double& outUvPsnrDb
    ) noexcept;

/// Verifies a decoded NV12 frame against the synthetic test pattern of frameNumber (evaluates BT.601 & BT.709).
PsnrVerificationResult VerifyDecodedNv12AgainstSyntheticBgra8(
    uint32_t frameNumber,
    const DecodedNv12Frame& decodedFrame,
    double minRequiredPsnrDb = 25.0
    ) noexcept;

/// Independent CPU/Media Foundation H.264 decoder (CLSID_CMSH264DecoderMFT with MFTEnumEx fallback).
class H264IndependentDecoder final
{
public:
    H264IndependentDecoder() noexcept;
    ~H264IndependentDecoder();

    H264IndependentDecoder(const H264IndependentDecoder&) = delete;
    H264IndependentDecoder& operator=(const H264IndependentDecoder&) = delete;

    HRESULT Initialize(
        uint32_t width,
        uint32_t height,
        uint32_t targetFps = 60U
        ) noexcept;

    void Shutdown() noexcept;

    bool IsInitialized() const noexcept;
    std::string GetDecoderName() const noexcept;

    /// Submits one Annex-B frame packet to the independent H.264 decoder and collects any immediately produced NV12 frames.
    HRESULT DecodePacket(
        const uint8_t* annexBBytes,
        size_t annexBSizeBytes,
        uint32_t presentationFrameNumber,
        std::vector<DecodedNv12Frame>& outDecodedFrames
        ) noexcept;

    /// Drains all buffered frames from the decoder at end of stream.
    HRESULT Drain(
        std::vector<DecodedNv12Frame>& outDecodedFrames
        ) noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl{};
};

/// Accumulates NAL inspection, Media Foundation decode, and optional synthetic PSNR checks over a stream.
class H264StreamValidationSession final
{
public:
    void Configure(
        bool enabled,
        uint32_t targetFps,
        bool verifySyntheticPsnr,
        double minPsnrDb = 25.0
        ) noexcept;

    void SubmitPacket(const EncodedFramePacket& packet) noexcept;
    void Finish() noexcept;
    void Shutdown() noexcept;

    H264ValidationSummary GetSummary() const noexcept;

private:
    void ProcessDecodedFrames(const std::vector<DecodedNv12Frame>& frames) noexcept;

    bool m_enabled{false};
    bool m_verifySyntheticPsnr{false};
    uint32_t m_targetFps{60U};
    double m_minPsnrDb{25.0};
    uint32_t m_width{0U};
    uint32_t m_height{0U};
    double m_sumYPsnrDb{0.0};
    double m_sumUvPsnrDb{0.0};
    uint64_t m_psnrSamples{0ULL};
    H264IndependentDecoder m_decoder{};
    H264ValidationSummary m_summary{};
};

} // namespace lumabridge::host
