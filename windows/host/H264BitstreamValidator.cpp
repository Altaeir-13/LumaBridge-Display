#include "H264BitstreamValidator.h"

#include <codecapi.h>
#include <mfapi.h>
#include <mferror.h>
#include <mfidl.h>
#include <mftransform.h>
#include <objbase.h>
#include <wmcodecdsp.h>
#include <wrl/client.h>

#include <algorithm>
#include <cmath>
#include <cstring>

namespace lumabridge::host {

namespace {

using Microsoft::WRL::ComPtr;

uint8_t
ClampByteFromDouble(double value) noexcept
{
    if (value <= 0.0)
    {
        return 0U;
    }
    if (value >= 255.0)
    {
        return 255U;
    }
    return static_cast<uint8_t>(std::lround(value));
}

void
ComputeYuvPixel(
    uint8_t r,
    uint8_t g,
    uint8_t b,
    ColorMatrixStandard matrix,
    uint8_t& outY,
    uint8_t& outU,
    uint8_t& outV
    ) noexcept
{
    const double rd = static_cast<double>(r);
    const double gd = static_cast<double>(g);
    const double bd = static_cast<double>(b);

    if (matrix == ColorMatrixStandard::Bt709Limited)
    {
        const double y = 16.0 + (219.0 / 255.0) * (0.2126 * rd + 0.7152 * gd + 0.0722 * bd);
        const double u = 128.0 + (224.0 / 255.0) * (-0.1145721061 * rd - 0.3854278939 * gd + 0.5 * bd);
        const double v = 128.0 + (224.0 / 255.0) * (0.5 * rd - 0.4541529083 * gd - 0.0458470917 * bd);
        outY = ClampByteFromDouble(y);
        outU = ClampByteFromDouble(u);
        outV = ClampByteFromDouble(v);
    }
    else
    {
        const double y = 16.0 + (219.0 / 255.0) * (0.2990 * rd + 0.5870 * gd + 0.1140 * bd);
        const double u = 128.0 + (224.0 / 255.0) * (-0.168735892 * rd - 0.331264108 * gd + 0.5 * bd);
        const double v = 128.0 + (224.0 / 255.0) * (0.5 * rd - 0.418687589 * gd - 0.081312411 * bd);
        outY = ClampByteFromDouble(y);
        outU = ClampByteFromDouble(u);
        outV = ClampByteFromDouble(v);
    }
}

double
ComputePlanePsnrDb(
    const uint8_t* a,
    const uint8_t* b,
    size_t count
    ) noexcept
{
    if (a == nullptr || b == nullptr || count == 0U)
    {
        return 0.0;
    }

    uint64_t sumSq = 0ULL;
    for (size_t i = 0U; i < count; ++i)
    {
        const int32_t diff = static_cast<int32_t>(a[i]) - static_cast<int32_t>(b[i]);
        sumSq += static_cast<uint64_t>(diff * diff);
    }

    if (sumSq == 0ULL)
    {
        return 99.0;
    }

    const double mse = static_cast<double>(sumSq) / static_cast<double>(count);
    return 10.0 * std::log10((255.0 * 255.0) / mse);
}

bool
IsStartCodeAt(
    const uint8_t* data,
    size_t sizeBytes,
    size_t offset,
    size_t& outPrefixLen
    ) noexcept
{
    if (offset + 3U <= sizeBytes &&
        data[offset] == 0x00U &&
        data[offset + 1U] == 0x00U &&
        data[offset + 2U] == 0x01U)
    {
        outPrefixLen = 3U;
        return true;
    }

    if (offset + 4U <= sizeBytes &&
        data[offset] == 0x00U &&
        data[offset + 1U] == 0x00U &&
        data[offset + 2U] == 0x00U &&
        data[offset + 3U] == 0x01U)
    {
        outPrefixLen = 4U;
        return true;
    }

    outPrefixLen = 0U;
    return false;
}

std::string
NarrowFromWide(const wchar_t* wide) noexcept
{
    if (wide == nullptr || wide[0] == L'\0')
    {
        return {};
    }
    const int needed = WideCharToMultiByte(CP_UTF8, 0U, wide, -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 1)
    {
        return {};
    }
    std::string out(static_cast<size_t>(needed - 1), '\0');
    (void)WideCharToMultiByte(CP_UTF8, 0U, wide, -1, out.data(), needed, nullptr, nullptr);
    return out;
}

} // namespace

bool
InspectH264AnnexBNals(
    const uint8_t* data,
    size_t sizeBytes,
    H264NalSummary& outSummary
    ) noexcept
{
    outSummary = {};
    if (data == nullptr || sizeBytes < 4U)
    {
        return false;
    }

    size_t firstPrefixLen = 0U;
    if (IsStartCodeAt(data, sizeBytes, 0U, firstPrefixLen))
    {
        outSummary.HasValidStartCodePrefix = true;
    }

    size_t pos = 0U;
    while (pos + 3U <= sizeBytes)
    {
        size_t prefixLen = 0U;
        if (!IsStartCodeAt(data, sizeBytes, pos, prefixLen))
        {
            ++pos;
            continue;
        }

        const size_t nalHeaderOffset = pos + prefixLen;
        if (nalHeaderOffset < sizeBytes)
        {
            const uint8_t nalHeader = data[nalHeaderOffset];
            const uint8_t forbiddenBit = (nalHeader >> 7U) & 0x01U;
            const uint8_t nalType = nalHeader & 0x1FU;
            if (forbiddenBit == 0U && nalType > 0U)
            {
                ++outSummary.TotalNalUnits;
                switch (nalType)
                {
                case 7U:
                    ++outSummary.SpsCount;
                    break;
                case 8U:
                    ++outSummary.PpsCount;
                    break;
                case 5U:
                    ++outSummary.IdrSliceCount;
                    break;
                case 1U:
                    ++outSummary.NonIdrSliceCount;
                    break;
                default:
                    ++outSummary.AudOrSeiOrOtherCount;
                    break;
                }
            }
        }

        pos = nalHeaderOffset + 1U;
    }

    return outSummary.TotalNalUnits > 0U &&
           (outSummary.IdrSliceCount > 0U || outSummary.NonIdrSliceCount > 0U);
}

bool
GenerateSyntheticTestPatternNv12Reference(
    uint32_t frameNumber,
    uint32_t width,
    uint32_t height,
    ColorMatrixStandard matrix,
    std::vector<uint8_t>& outNv12Bytes
    ) noexcept
{
    outNv12Bytes.clear();
    if (width == 0U || height == 0U || (width % 2U) != 0U || (height % 2U) != 0U)
    {
        return false;
    }

    std::vector<uint8_t> bgra;
    uint32_t rowPitch = 0U;
    uint32_t bgraBytes = 0U;
    if (!lumabridge::ipc::ComputeTightRowPitchBytes(width, rowPitch) ||
        !lumabridge::ipc::ComputeValidatedFramePayloadBytes(width, height, rowPitch, bgraBytes))
    {
        return false;
    }

    bgra.resize(bgraBytes);
    if (!lumabridge::ipc::GenerateSyntheticTestPatternBgra8(
            frameNumber,
            width,
            height,
            bgra.data(),
            bgra.size()))
    {
        return false;
    }

    const size_t yPlaneBytes = static_cast<size_t>(width) * static_cast<size_t>(height);
    const size_t uvPlaneBytes = yPlaneBytes / 2U;
    outNv12Bytes.resize(yPlaneBytes + uvPlaneBytes);

    uint8_t* yDst = outNv12Bytes.data();
    uint8_t* uvDst = outNv12Bytes.data() + yPlaneBytes;

    for (uint32_t y = 0U; y < height; ++y)
    {
        const uint8_t* srcRow = bgra.data() + static_cast<size_t>(y) * rowPitch;
        uint8_t* dstRow = yDst + static_cast<size_t>(y) * width;
        for (uint32_t x = 0U; x < width; ++x)
        {
            const uint8_t b = srcRow[static_cast<size_t>(x) * 4U + 0U];
            const uint8_t g = srcRow[static_cast<size_t>(x) * 4U + 1U];
            const uint8_t r = srcRow[static_cast<size_t>(x) * 4U + 2U];
            uint8_t yVal = 0U;
            uint8_t uUnused = 0U;
            uint8_t vUnused = 0U;
            ComputeYuvPixel(r, g, b, matrix, yVal, uUnused, vUnused);
            dstRow[x] = yVal;
        }
    }

    for (uint32_t y = 0U; y < height; y += 2U)
    {
        const uint8_t* row0 = bgra.data() + static_cast<size_t>(y) * rowPitch;
        const uint8_t* row1 = bgra.data() + static_cast<size_t>(y + 1U) * rowPitch;
        uint8_t* uvRow = uvDst + static_cast<size_t>(y / 2U) * width;

        for (uint32_t x = 0U; x < width; x += 2U)
        {
            const size_t off0 = static_cast<size_t>(x) * 4U;
            const size_t off1 = static_cast<size_t>(x + 1U) * 4U;

            const uint32_t sumB = static_cast<uint32_t>(row0[off0 + 0U]) +
                                  static_cast<uint32_t>(row0[off1 + 0U]) +
                                  static_cast<uint32_t>(row1[off0 + 0U]) +
                                  static_cast<uint32_t>(row1[off1 + 0U]);
            const uint32_t sumG = static_cast<uint32_t>(row0[off0 + 1U]) +
                                  static_cast<uint32_t>(row0[off1 + 1U]) +
                                  static_cast<uint32_t>(row1[off0 + 1U]) +
                                  static_cast<uint32_t>(row1[off1 + 1U]);
            const uint32_t sumR = static_cast<uint32_t>(row0[off0 + 2U]) +
                                  static_cast<uint32_t>(row0[off1 + 2U]) +
                                  static_cast<uint32_t>(row1[off0 + 2U]) +
                                  static_cast<uint32_t>(row1[off1 + 2U]);

            const uint8_t avgB = static_cast<uint8_t>((sumB + 2U) / 4U);
            const uint8_t avgG = static_cast<uint8_t>((sumG + 2U) / 4U);
            const uint8_t avgR = static_cast<uint8_t>((sumR + 2U) / 4U);

            uint8_t yUnused = 0U;
            uint8_t uVal = 0U;
            uint8_t vVal = 0U;
            ComputeYuvPixel(avgR, avgG, avgB, matrix, yUnused, uVal, vVal);
            uvRow[x + 0U] = uVal;
            uvRow[x + 1U] = vVal;
        }
    }

    return true;
}

bool
ComputeNv12Psnr(
    const DecodedNv12Frame& decodedFrame,
    const uint8_t* referenceNv12Bytes,
    size_t referenceSizeBytes,
    double& outYPsnrDb,
    double& outUvPsnrDb
    ) noexcept
{
    outYPsnrDb = 0.0;
    outUvPsnrDb = 0.0;

    if (referenceNv12Bytes == nullptr ||
        decodedFrame.Width == 0U ||
        decodedFrame.Height == 0U ||
        decodedFrame.StrideBytes < decodedFrame.Width)
    {
        return false;
    }

    const size_t yCount = static_cast<size_t>(decodedFrame.Width) * static_cast<size_t>(decodedFrame.Height);
    const size_t uvCount = yCount / 2U;
    if (referenceSizeBytes < yCount + uvCount ||
        decodedFrame.Nv12Bytes.size() < yCount + uvCount)
    {
        return false;
    }

    if (decodedFrame.StrideBytes == decodedFrame.Width)
    {
        outYPsnrDb = ComputePlanePsnrDb(decodedFrame.Nv12Bytes.data(), referenceNv12Bytes, yCount);
        outUvPsnrDb = ComputePlanePsnrDb(
            decodedFrame.Nv12Bytes.data() + yCount,
            referenceNv12Bytes + yCount,
            uvCount);
        return true;
    }

    uint64_t ySumSq = 0ULL;
    for (uint32_t y = 0U; y < decodedFrame.Height; ++y)
    {
        const uint8_t* decRow = decodedFrame.Nv12Bytes.data() + static_cast<size_t>(y) * decodedFrame.StrideBytes;
        const uint8_t* refRow = referenceNv12Bytes + static_cast<size_t>(y) * decodedFrame.Width;
        for (uint32_t x = 0U; x < decodedFrame.Width; ++x)
        {
            const int32_t diff = static_cast<int32_t>(decRow[x]) - static_cast<int32_t>(refRow[x]);
            ySumSq += static_cast<uint64_t>(diff * diff);
        }
    }
    outYPsnrDb = (ySumSq == 0ULL)
        ? 99.0
        : 10.0 * std::log10((255.0 * 255.0) / (static_cast<double>(ySumSq) / static_cast<double>(yCount)));

    uint64_t uvSumSq = 0ULL;
    const uint8_t* decUvBase =
        decodedFrame.Nv12Bytes.data() + static_cast<size_t>(decodedFrame.Height) * decodedFrame.StrideBytes;
    const uint8_t* refUvBase = referenceNv12Bytes + yCount;
    for (uint32_t y = 0U; y < decodedFrame.Height / 2U; ++y)
    {
        const uint8_t* decRow = decUvBase + static_cast<size_t>(y) * decodedFrame.StrideBytes;
        const uint8_t* refRow = refUvBase + static_cast<size_t>(y) * decodedFrame.Width;
        for (uint32_t x = 0U; x < decodedFrame.Width; ++x)
        {
            const int32_t diff = static_cast<int32_t>(decRow[x]) - static_cast<int32_t>(refRow[x]);
            uvSumSq += static_cast<uint64_t>(diff * diff);
        }
    }
    outUvPsnrDb = (uvSumSq == 0ULL)
        ? 99.0
        : 10.0 * std::log10((255.0 * 255.0) / (static_cast<double>(uvSumSq) / static_cast<double>(uvCount)));

    return true;
}

PsnrVerificationResult
VerifyDecodedNv12AgainstSyntheticBgra8(
    uint32_t frameNumber,
    const DecodedNv12Frame& decodedFrame,
    double minRequiredPsnrDb
    ) noexcept
{
    PsnrVerificationResult result{};
    std::vector<uint8_t> ref601;
    std::vector<uint8_t> ref709;

    double y601 = 0.0;
    double uv601 = 0.0;
    const bool ok601 =
        GenerateSyntheticTestPatternNv12Reference(
            frameNumber,
            decodedFrame.Width,
            decodedFrame.Height,
            ColorMatrixStandard::Bt601Limited,
            ref601) &&
        ComputeNv12Psnr(decodedFrame, ref601.data(), ref601.size(), y601, uv601);

    double y709 = 0.0;
    double uv709 = 0.0;
    const bool ok709 =
        GenerateSyntheticTestPatternNv12Reference(
            frameNumber,
            decodedFrame.Width,
            decodedFrame.Height,
            ColorMatrixStandard::Bt709Limited,
            ref709) &&
        ComputeNv12Psnr(decodedFrame, ref709.data(), ref709.size(), y709, uv709);

    if (!ok601 && !ok709)
    {
        return result;
    }

    const double avg601 = 0.5 * (y601 + uv601);
    const double avg709 = 0.5 * (y709 + uv709);
    result.Valid = true;
    if (ok709 && (!ok601 || avg709 > avg601))
    {
        result.YPsnrDb = y709;
        result.UvPsnrDb = uv709;
        result.AvgPsnrDb = avg709;
        result.MinPsnrDb = (std::min)(y709, uv709);
        result.MatchedColorMatrix = "BT709";
    }
    else
    {
        result.YPsnrDb = y601;
        result.UvPsnrDb = uv601;
        result.AvgPsnrDb = avg601;
        result.MinPsnrDb = (std::min)(y601, uv601);
        result.MatchedColorMatrix = "BT601";
    }

    result.Passed = (result.YPsnrDb >= minRequiredPsnrDb && result.UvPsnrDb >= minRequiredPsnrDb);
    return result;
}

struct H264IndependentDecoder::Impl final
{
    bool ComInitializedBySelf{false};
    bool MfStarted{false};
    bool Initialized{false};
    uint32_t Width{0U};
    uint32_t Height{0U};
    uint32_t CodedWidth{0U};
    uint32_t CodedHeight{0U};
    uint32_t OutputStrideBytes{0U};
    uint32_t OutputBufferSizeBytes{0U};
    uint32_t TargetFps{60U};
    bool MftProvidesSamples{false};
    std::string DecoderName{"None"};
    ComPtr<IMFTransform> Decoder{};

    HRESULT ConfigureOutputNv12Type() noexcept
    {
        if (Decoder == nullptr)
        {
            return E_NOT_VALID_STATE;
        }

        for (DWORD idx = 0U;; ++idx)
        {
            ComPtr<IMFMediaType> availType;
            const HRESULT enumHr = Decoder->GetOutputAvailableType(0U, idx, &availType);
            if (enumHr == MF_E_NO_MORE_TYPES)
            {
                return MF_E_INVALIDMEDIATYPE;
            }
            if (FAILED(enumHr) || availType == nullptr)
            {
                return FAILED(enumHr) ? enumHr : E_FAIL;
            }

            GUID subType = GUID_NULL;
            if (SUCCEEDED(availType->GetGUID(MF_MT_SUBTYPE, &subType)) &&
                subType == MFVideoFormat_NV12)
            {
                const HRESULT setHr = Decoder->SetOutputType(0U, availType.Get(), 0U);
                if (FAILED(setHr))
                {
                    return setHr;
                }

                UINT32 cw = Width;
                UINT32 ch = Height;
                (void)MFGetAttributeSize(availType.Get(), MF_MT_FRAME_SIZE, &cw, &ch);
                CodedWidth = (cw >= Width) ? cw : Width;
                CodedHeight = (ch >= Height) ? ch : Height;

                UINT32 defaultStride = 0U;
                if (SUCCEEDED(availType->GetUINT32(MF_MT_DEFAULT_STRIDE, &defaultStride)) &&
                    static_cast<int32_t>(defaultStride) > 0)
                {
                    OutputStrideBytes = defaultStride;
                }
                else
                {
                    LONG signedStride = 0;
                    if (SUCCEEDED(MFGetStrideForBitmapInfoHeader(
                            MFVideoFormat_NV12.Data1,
                            static_cast<DWORD>(CodedWidth),
                            &signedStride)) &&
                        signedStride > 0)
                    {
                        OutputStrideBytes = static_cast<uint32_t>(signedStride);
                    }
                    else
                    {
                        OutputStrideBytes = CodedWidth;
                    }
                }

                MFT_OUTPUT_STREAM_INFO outStreamInfo{};
                const HRESULT infoHr = Decoder->GetOutputStreamInfo(0U, &outStreamInfo);
                if (SUCCEEDED(infoHr))
                {
                    MftProvidesSamples =
                        (outStreamInfo.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES) != 0U;
                    const uint32_t minNv12Bytes = OutputStrideBytes * CodedHeight * 3U / 2U;
                    OutputBufferSizeBytes = (std::max)(
                        static_cast<uint32_t>(outStreamInfo.cbSize),
                        minNv12Bytes);
                }
                else
                {
                    MftProvidesSamples = false;
                    OutputBufferSizeBytes = OutputStrideBytes * CodedHeight * 3U / 2U;
                }

                return S_OK;
            }
        }
    }

    HRESULT ExtractNv12FrameFromSample(
        IMFSample* sample,
        DecodedNv12Frame& outFrame
        ) noexcept
    {
        if (sample == nullptr)
        {
            return E_INVALIDARG;
        }

        LONGLONG sampleTime100Ns = 0LL;
        if (SUCCEEDED(sample->GetSampleTime(&sampleTime100Ns)) && sampleTime100Ns >= 0LL)
        {
            outFrame.SampleTime100Ns = static_cast<uint64_t>(sampleTime100Ns);
            outFrame.FrameNumber = static_cast<uint32_t>(sampleTime100Ns / 10000LL);
        }

        ComPtr<IMFMediaBuffer> buffer;
        HRESULT hr = sample->ConvertToContiguousBuffer(&buffer);
        if (FAILED(hr) || buffer == nullptr)
        {
            return FAILED(hr) ? hr : E_FAIL;
        }

        outFrame.Width = Width;
        outFrame.Height = Height;
        outFrame.StrideBytes = Width;
        const size_t dstYBytes = static_cast<size_t>(Width) * static_cast<size_t>(Height);
        const size_t dstUvBytes = dstYBytes / 2U;
        outFrame.Nv12Bytes.resize(dstYBytes + dstUvBytes);

        ComPtr<IMF2DBuffer> buffer2d;
        if (SUCCEEDED(buffer.As(&buffer2d)) && buffer2d != nullptr)
        {
            BYTE* scanline0 = nullptr;
            LONG pitch = 0;
            hr = buffer2d->Lock2D(&scanline0, &pitch);
            if (SUCCEEDED(hr) && scanline0 != nullptr && pitch > 0)
            {
                const uint32_t effectiveCodedH = (CodedHeight >= Height) ? CodedHeight : Height;
                for (uint32_t y = 0U; y < Height; ++y)
                {
                    std::memcpy(
                        outFrame.Nv12Bytes.data() + static_cast<size_t>(y) * Width,
                        scanline0 + static_cast<size_t>(y) * static_cast<size_t>(pitch),
                        Width);
                }

                const BYTE* uvSrcBase =
                    scanline0 + static_cast<size_t>(effectiveCodedH) * static_cast<size_t>(pitch);
                uint8_t* uvDstBase = outFrame.Nv12Bytes.data() + dstYBytes;
                for (uint32_t y = 0U; y < Height / 2U; ++y)
                {
                    std::memcpy(
                        uvDstBase + static_cast<size_t>(y) * Width,
                        uvSrcBase + static_cast<size_t>(y) * static_cast<size_t>(pitch),
                        Width);
                }

                (void)buffer2d->Unlock2D();
                return S_OK;
            }
            if (SUCCEEDED(hr))
            {
                (void)buffer2d->Unlock2D();
            }
        }

        BYTE* data = nullptr;
        DWORD maxLen = 0U;
        DWORD curLen = 0U;
        hr = buffer->Lock(&data, &maxLen, &curLen);
        if (FAILED(hr) || data == nullptr)
        {
            return FAILED(hr) ? hr : E_FAIL;
        }

        const uint32_t stride = (OutputStrideBytes >= Width) ? OutputStrideBytes : Width;
        uint32_t effectiveCodedH = (CodedHeight >= Height) ? CodedHeight : Height;
        const size_t requiredWithCodedH =
            (static_cast<size_t>(effectiveCodedH) + static_cast<size_t>(Height / 2U) - 1U) * stride + Width;
        if (static_cast<size_t>(curLen) < requiredWithCodedH)
        {
            effectiveCodedH = Height;
        }

        const size_t minNeeded =
            (static_cast<size_t>(effectiveCodedH) + static_cast<size_t>(Height / 2U) - 1U) * stride + Width;
        if (static_cast<size_t>(curLen) < minNeeded)
        {
            (void)buffer->Unlock();
            return MF_E_BUFFERTOOSMALL;
        }

        for (uint32_t y = 0U; y < Height; ++y)
        {
            std::memcpy(
                outFrame.Nv12Bytes.data() + static_cast<size_t>(y) * Width,
                data + static_cast<size_t>(y) * stride,
                Width);
        }

        const BYTE* uvSrcBase = data + static_cast<size_t>(effectiveCodedH) * stride;
        uint8_t* uvDstBase = outFrame.Nv12Bytes.data() + dstYBytes;
        for (uint32_t y = 0U; y < Height / 2U; ++y)
        {
            std::memcpy(
                uvDstBase + static_cast<size_t>(y) * Width,
                uvSrcBase + static_cast<size_t>(y) * stride,
                Width);
        }

        (void)buffer->Unlock();
        return S_OK;
    }

    HRESULT DrainAvailableOutputs(std::vector<DecodedNv12Frame>& outDecodedFrames) noexcept
    {
        if (Decoder == nullptr)
        {
            return E_NOT_VALID_STATE;
        }

        for (;;)
        {
            ComPtr<IMFSample> outSample;
            MFT_OUTPUT_DATA_BUFFER outputBuffer{};
            outputBuffer.dwStreamID = 0U;

            if (!MftProvidesSamples)
            {
                HRESULT hr = MFCreateSample(&outSample);
                if (FAILED(hr) || outSample == nullptr)
                {
                    return FAILED(hr) ? hr : E_OUTOFMEMORY;
                }

                ComPtr<IMFMediaBuffer> memBuf;
                hr = MFCreateMemoryBuffer(OutputBufferSizeBytes, &memBuf);
                if (FAILED(hr) || memBuf == nullptr)
                {
                    return FAILED(hr) ? hr : E_OUTOFMEMORY;
                }
                hr = outSample->AddBuffer(memBuf.Get());
                if (FAILED(hr))
                {
                    return hr;
                }
                outputBuffer.pSample = outSample.Get();
            }

            DWORD status = 0U;
            const HRESULT procHr = Decoder->ProcessOutput(0U, 1U, &outputBuffer, &status);
            ComPtr<IMFCollection> eventsHolder;
            if (outputBuffer.pEvents != nullptr)
            {
                eventsHolder.Attach(outputBuffer.pEvents);
            }

            if (procHr == MF_E_TRANSFORM_NEED_MORE_INPUT)
            {
                return S_OK;
            }

            if (procHr == MF_E_TRANSFORM_STREAM_CHANGE)
            {
                const HRESULT reconfHr = ConfigureOutputNv12Type();
                if (FAILED(reconfHr))
                {
                    return reconfHr;
                }
                continue;
            }

            if (FAILED(procHr))
            {
                return procHr;
            }

            IMFSample* producedSample = outputBuffer.pSample;
            ComPtr<IMFSample> mftOwnedSample;
            if (MftProvidesSamples && producedSample != nullptr)
            {
                mftOwnedSample.Attach(producedSample);
            }

            if (producedSample != nullptr)
            {
                DecodedNv12Frame decoded;
                const HRESULT extHr = ExtractNv12FrameFromSample(producedSample, decoded);
                if (FAILED(extHr))
                {
                    return extHr;
                }
                outDecodedFrames.push_back(std::move(decoded));
            }
        }
    }

    void Cleanup() noexcept
    {
        if (Decoder != nullptr)
        {
            (void)Decoder->ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0U);
            (void)Decoder->ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0U);
            Decoder.Reset();
        }
        if (MfStarted)
        {
            (void)MFShutdown();
            MfStarted = false;
        }
        if (ComInitializedBySelf)
        {
            CoUninitialize();
            ComInitializedBySelf = false;
        }
        Initialized = false;
        Width = 0U;
        Height = 0U;
        CodedWidth = 0U;
        CodedHeight = 0U;
        OutputStrideBytes = 0U;
        OutputBufferSizeBytes = 0U;
        MftProvidesSamples = false;
        DecoderName = "None";
    }
};

H264IndependentDecoder::H264IndependentDecoder() noexcept
    : m_impl(std::make_unique<Impl>())
{
}

H264IndependentDecoder::~H264IndependentDecoder()
{
    Shutdown();
}

HRESULT
H264IndependentDecoder::Initialize(
    uint32_t width,
    uint32_t height,
    uint32_t targetFps
    ) noexcept
{
    Shutdown();

    if (width == 0U || height == 0U || (width % 2U) != 0U || (height % 2U) != 0U)
    {
        return E_INVALIDARG;
    }

    const HRESULT comHr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (SUCCEEDED(comHr))
    {
        m_impl->ComInitializedBySelf = true;
    }
    else if (comHr != RPC_E_CHANGED_MODE)
    {
        return comHr;
    }

    HRESULT hr = MFStartup(MF_VERSION, MFSTARTUP_LITE);
    if (FAILED(hr))
    {
        m_impl->Cleanup();
        return hr;
    }
    m_impl->MfStarted = true;
    m_impl->Width = width;
    m_impl->Height = height;
    m_impl->CodedWidth = width;
    m_impl->CodedHeight = height;
    m_impl->TargetFps = (targetFps > 0U) ? targetFps : 60U;

    hr = CoCreateInstance(
        CLSID_CMSH264DecoderMFT,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(&m_impl->Decoder));
    if (SUCCEEDED(hr) && m_impl->Decoder != nullptr)
    {
        m_impl->DecoderName = "Microsoft H.264 Video Decoder MFT";
    }
    else
    {
        MFT_REGISTER_TYPE_INFO inTypeInfo{};
        inTypeInfo.guidMajorType = MFMediaType_Video;
        inTypeInfo.guidSubtype = MFVideoFormat_H264;

        MFT_REGISTER_TYPE_INFO outTypeInfo{};
        outTypeInfo.guidMajorType = MFMediaType_Video;
        outTypeInfo.guidSubtype = MFVideoFormat_NV12;

        IMFActivate** activates = nullptr;
        UINT32 count = 0U;
        hr = MFTEnumEx(
            MFT_CATEGORY_VIDEO_DECODER,
            MFT_ENUM_FLAG_SYNCMFT | MFT_ENUM_FLAG_LOCALMFT | MFT_ENUM_FLAG_SORTANDFILTER,
            &inTypeInfo,
            &outTypeInfo,
            &activates,
            &count);
        if (SUCCEEDED(hr) && activates != nullptr && count > 0U)
        {
            for (UINT32 i = 0U; i < count && m_impl->Decoder == nullptr; ++i)
            {
                if (SUCCEEDED(activates[i]->ActivateObject(IID_PPV_ARGS(&m_impl->Decoder))) &&
                    m_impl->Decoder != nullptr)
                {
                    wchar_t* friendlyName = nullptr;
                    UINT32 nameLen = 0U;
                    if (SUCCEEDED(activates[i]->GetAllocatedString(
                            MFT_FRIENDLY_NAME_Attribute,
                            &friendlyName,
                            &nameLen)) &&
                        friendlyName != nullptr)
                    {
                        m_impl->DecoderName = NarrowFromWide(friendlyName);
                        CoTaskMemFree(friendlyName);
                    }
                    else
                    {
                        m_impl->DecoderName = "MFTEnumEx H.264 Decoder";
                    }
                }
            }
            for (UINT32 i = 0U; i < count; ++i)
            {
                if (activates[i] != nullptr)
                {
                    activates[i]->Release();
                }
            }
            CoTaskMemFree(activates);
        }
    }

    if (m_impl->Decoder == nullptr)
    {
        m_impl->Cleanup();
        return FAILED(hr) ? hr : REGDB_E_CLASSNOTREG;
    }

    // Request low-latency mode on CMSH264DecoderMFT so 0-B-frame streams emit without buffering delay.
    ComPtr<ICodecAPI> codecApi;
    if (SUCCEEDED(m_impl->Decoder.As(&codecApi)) && codecApi != nullptr)
    {
        VARIANT lowLatency{};
        lowLatency.vt = VT_BOOL;
        lowLatency.boolVal = VARIANT_TRUE;
        (void)codecApi->SetValue(&CODECAPI_AVLowLatencyMode, &lowLatency);
    }

    ComPtr<IMFMediaType> inputType;
    hr = MFCreateMediaType(&inputType);
    if (FAILED(hr) || inputType == nullptr)
    {
        m_impl->Cleanup();
        return FAILED(hr) ? hr : E_OUTOFMEMORY;
    }

    hr = inputType->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
    if (SUCCEEDED(hr))
    {
        hr = inputType->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_H264);
    }
    if (SUCCEEDED(hr))
    {
        hr = MFSetAttributeSize(inputType.Get(), MF_MT_FRAME_SIZE, width, height);
    }
    if (SUCCEEDED(hr))
    {
        hr = MFSetAttributeRatio(inputType.Get(), MF_MT_FRAME_RATE, m_impl->TargetFps, 1U);
    }
    if (SUCCEEDED(hr))
    {
        hr = inputType->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive);
    }
    if (SUCCEEDED(hr))
    {
        hr = m_impl->Decoder->SetInputType(0U, inputType.Get(), 0U);
    }
    if (FAILED(hr))
    {
        m_impl->Cleanup();
        return hr;
    }

    hr = m_impl->ConfigureOutputNv12Type();
    if (FAILED(hr))
    {
        m_impl->Cleanup();
        return hr;
    }

    hr = m_impl->Decoder->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0U);
    if (SUCCEEDED(hr))
    {
        hr = m_impl->Decoder->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0U);
    }
    if (FAILED(hr))
    {
        m_impl->Cleanup();
        return hr;
    }

    m_impl->Initialized = true;
    return S_OK;
}

void
H264IndependentDecoder::Shutdown() noexcept
{
    if (m_impl != nullptr)
    {
        m_impl->Cleanup();
    }
}

bool
H264IndependentDecoder::IsInitialized() const noexcept
{
    return m_impl != nullptr && m_impl->Initialized;
}

std::string
H264IndependentDecoder::GetDecoderName() const noexcept
{
    return (m_impl != nullptr) ? m_impl->DecoderName : std::string("None");
}

HRESULT
H264IndependentDecoder::DecodePacket(
    const uint8_t* annexBBytes,
    size_t annexBSizeBytes,
    uint32_t presentationFrameNumber,
    std::vector<DecodedNv12Frame>& outDecodedFrames
    ) noexcept
{
    if (m_impl == nullptr || !m_impl->Initialized || m_impl->Decoder == nullptr)
    {
        return E_NOT_VALID_STATE;
    }
    if (annexBBytes == nullptr || annexBSizeBytes == 0U || annexBSizeBytes > MAXDWORD)
    {
        return E_INVALIDARG;
    }

    ComPtr<IMFSample> inSample;
    HRESULT hr = MFCreateSample(&inSample);
    if (FAILED(hr) || inSample == nullptr)
    {
        return FAILED(hr) ? hr : E_OUTOFMEMORY;
    }

    ComPtr<IMFMediaBuffer> inBuffer;
    hr = MFCreateMemoryBuffer(static_cast<DWORD>(annexBSizeBytes), &inBuffer);
    if (FAILED(hr) || inBuffer == nullptr)
    {
        return FAILED(hr) ? hr : E_OUTOFMEMORY;
    }

    BYTE* dst = nullptr;
    hr = inBuffer->Lock(&dst, nullptr, nullptr);
    if (FAILED(hr) || dst == nullptr)
    {
        return FAILED(hr) ? hr : E_FAIL;
    }
    std::memcpy(dst, annexBBytes, annexBSizeBytes);
    (void)inBuffer->Unlock();
    (void)inBuffer->SetCurrentLength(static_cast<DWORD>(annexBSizeBytes));

    (void)inSample->AddBuffer(inBuffer.Get());
    const LONGLONG pts100Ns = static_cast<LONGLONG>(presentationFrameNumber) * 10000LL;
    (void)inSample->SetSampleTime(pts100Ns);
    (void)inSample->SetSampleDuration(10000LL);

    hr = m_impl->Decoder->ProcessInput(0U, inSample.Get(), 0U);
    if (hr == MF_E_NOTACCEPTING)
    {
        const HRESULT drainHr = m_impl->DrainAvailableOutputs(outDecodedFrames);
        if (FAILED(drainHr))
        {
            return drainHr;
        }
        hr = m_impl->Decoder->ProcessInput(0U, inSample.Get(), 0U);
    }
    if (FAILED(hr))
    {
        return hr;
    }

    return m_impl->DrainAvailableOutputs(outDecodedFrames);
}

HRESULT
H264IndependentDecoder::Drain(
    std::vector<DecodedNv12Frame>& outDecodedFrames
    ) noexcept
{
    if (m_impl == nullptr || !m_impl->Initialized || m_impl->Decoder == nullptr)
    {
        return E_NOT_VALID_STATE;
    }

    (void)m_impl->Decoder->ProcessMessage(MFT_MESSAGE_COMMAND_DRAIN, 0U);
    return m_impl->DrainAvailableOutputs(outDecodedFrames);
}

void
H264StreamValidationSession::Configure(
    bool enabled,
    uint32_t targetFps,
    bool verifySyntheticPsnr,
    double minPsnrDb
    ) noexcept
{
    Shutdown();
    m_enabled = enabled;
    m_targetFps = (targetFps > 0U) ? targetFps : 60U;
    m_verifySyntheticPsnr = verifySyntheticPsnr;
    m_minPsnrDb = minPsnrDb;
    m_summary = {};
    m_summary.Enabled = enabled;
    m_summary.ValidationMode = !enabled
        ? std::string("Disabled")
        : (verifySyntheticPsnr
            ? std::string("StructuralDecode+SyntheticPsnr")
            : std::string("StructuralDecodeOnly"));
}

HRESULT
H264StreamValidationSession::PrewarmDecoder(
    uint32_t width,
    uint32_t height,
    uint32_t targetFps
    ) noexcept
{
    if (!m_enabled)
    {
        return S_OK;
    }
    if (width == 0U || height == 0U)
    {
        return E_INVALIDARG;
    }

    const uint32_t effectiveFps = (targetFps > 0U) ? targetFps : m_targetFps;
    if (m_decoder.IsInitialized() && m_width == width && m_height == height)
    {
        m_summary.DecoderInitialized = true;
        m_summary.DecoderName = m_decoder.GetDecoderName();
        return S_OK;
    }

    if (m_decoder.IsInitialized())
    {
        std::vector<DecodedNv12Frame> tail;
        if (SUCCEEDED(m_decoder.Drain(tail)))
        {
            ProcessDecodedFrames(tail);
        }
        m_decoder.Shutdown();
        m_width = 0U;
        m_height = 0U;
    }

    const HRESULT initHr = m_decoder.Initialize(width, height, effectiveFps);
    m_summary.DecoderInitialized = SUCCEEDED(initHr) && m_decoder.IsInitialized();
    m_summary.DecoderName = m_decoder.GetDecoderName();
    if (SUCCEEDED(initHr) && m_decoder.IsInitialized())
    {
        m_width = width;
        m_height = height;
    }
    else
    {
        m_summary.LastHResult = initHr;
    }
    return initHr;
}

void
H264StreamValidationSession::ProcessDecodedFrames(
    const std::vector<DecodedNv12Frame>& frames
    ) noexcept
{
    for (const DecodedNv12Frame& frame : frames)
    {
        ++m_summary.FramesDecoded;
        if (!m_verifySyntheticPsnr)
        {
            continue;
        }

        const PsnrVerificationResult psnr =
            VerifyDecodedNv12AgainstSyntheticBgra8(frame.FrameNumber, frame, m_minPsnrDb);
        if (!psnr.Valid)
        {
            ++m_summary.PsnrFailCount;
            continue;
        }

        if (m_summary.MatchedColorMatrix == "None" || m_summary.MatchedColorMatrix.empty())
        {
            m_summary.MatchedColorMatrix = psnr.MatchedColorMatrix;
        }
        else if (m_summary.MatchedColorMatrix != psnr.MatchedColorMatrix &&
                 m_summary.MatchedColorMatrix != "Mixed")
        {
            m_summary.MatchedColorMatrix = "Mixed";
        }

        if (m_psnrSamples == 0ULL || psnr.YPsnrDb < m_summary.MinYPsnrDb)
        {
            m_summary.MinYPsnrDb = psnr.YPsnrDb;
        }
        if (m_psnrSamples == 0ULL || psnr.UvPsnrDb < m_summary.MinUvPsnrDb)
        {
            m_summary.MinUvPsnrDb = psnr.UvPsnrDb;
        }
        if (m_psnrSamples == 0ULL || psnr.MinPsnrDb < m_summary.MinCombinedPsnrDb)
        {
            m_summary.MinCombinedPsnrDb = psnr.MinPsnrDb;
        }

        m_sumYPsnrDb += psnr.YPsnrDb;
        m_sumUvPsnrDb += psnr.UvPsnrDb;
        m_sumCombinedPsnrDb += psnr.AvgPsnrDb;
        ++m_psnrSamples;
        m_summary.AvgYPsnrDb = m_sumYPsnrDb / static_cast<double>(m_psnrSamples);
        m_summary.AvgUvPsnrDb = m_sumUvPsnrDb / static_cast<double>(m_psnrSamples);
        m_summary.AvgCombinedPsnrDb = m_sumCombinedPsnrDb / static_cast<double>(m_psnrSamples);

        if (psnr.Passed)
        {
            ++m_summary.PsnrPassCount;
        }
        else
        {
            ++m_summary.PsnrFailCount;
        }
    }
}

void
H264StreamValidationSession::SubmitPacket(
    const EncodedFramePacket& packet
    ) noexcept
{
    if (!m_enabled)
    {
        return;
    }

    ++m_summary.PacketsInspected;

    H264NalSummary nalSummary{};
    if (!InspectH264AnnexBNals(packet.Bitstream.data(), packet.Bitstream.size(), nalSummary) ||
        (packet.IsKeyFrame && nalSummary.IdrSliceCount == 0U))
    {
        ++m_summary.NalParseFailures;
    }
    else
    {
        m_summary.SpsCount += nalSummary.SpsCount;
        m_summary.PpsCount += nalSummary.PpsCount;
        m_summary.IdrCount += nalSummary.IdrSliceCount;
        m_summary.NonIdrCount += nalSummary.NonIdrSliceCount;
    }

    if (!m_decoder.IsInitialized() || m_width != packet.Width || m_height != packet.Height)
    {
        if (m_decoder.IsInitialized())
        {
            std::vector<DecodedNv12Frame> tail;
            if (SUCCEEDED(m_decoder.Drain(tail)))
            {
                ProcessDecodedFrames(tail);
            }
        }

        const HRESULT initHr = m_decoder.Initialize(packet.Width, packet.Height, m_targetFps);
        m_summary.DecoderInitialized = SUCCEEDED(initHr) && m_decoder.IsInitialized();
        m_summary.DecoderName = m_decoder.GetDecoderName();
        if (FAILED(initHr))
        {
            m_summary.LastHResult = initHr;
            ++m_summary.DecodeFailures;
            return;
        }
        m_width = packet.Width;
        m_height = packet.Height;
    }

    std::vector<DecodedNv12Frame> decoded;
    const HRESULT decHr = m_decoder.DecodePacket(
        packet.Bitstream.data(),
        packet.Bitstream.size(),
        packet.PresentationFrameNumber,
        decoded);
    if (FAILED(decHr))
    {
        m_summary.LastHResult = decHr;
        ++m_summary.DecodeFailures;
        return;
    }

    ProcessDecodedFrames(decoded);
}

void
H264StreamValidationSession::Finish() noexcept
{
    if (!m_enabled)
    {
        return;
    }

    if (m_decoder.IsInitialized())
    {
        std::vector<DecodedNv12Frame> tail;
        const HRESULT drainHr = m_decoder.Drain(tail);
        if (FAILED(drainHr) && drainHr != E_NOT_VALID_STATE)
        {
            m_summary.LastHResult = drainHr;
            ++m_summary.DecodeFailures;
        }
        else
        {
            ProcessDecodedFrames(tail);
        }
    }

    const bool structuralOk =
        m_summary.Enabled &&
        m_summary.DecoderInitialized &&
        m_summary.PacketsInspected > 0ULL &&
        m_summary.FramesDecoded > 0ULL &&
        m_summary.NalParseFailures == 0ULL &&
        m_summary.DecodeFailures == 0ULL &&
        m_summary.SpsCount > 0ULL &&
        m_summary.PpsCount > 0ULL &&
        m_summary.IdrCount > 0ULL;

    m_summary.StructuralDecodeValidated = structuralOk;
    m_summary.FidelityPsnrValidated =
        structuralOk &&
        m_verifySyntheticPsnr &&
        m_summary.PsnrPassCount > 0ULL &&
        m_summary.PsnrFailCount == 0ULL;
    m_summary.Passed =
        structuralOk &&
        (!m_verifySyntheticPsnr || m_summary.FidelityPsnrValidated);
}

void
H264StreamValidationSession::Shutdown() noexcept
{
    m_decoder.Shutdown();
    m_width = 0U;
    m_height = 0U;
    m_sumYPsnrDb = 0.0;
    m_sumUvPsnrDb = 0.0;
    m_sumCombinedPsnrDb = 0.0;
    m_psnrSamples = 0ULL;
}

H264ValidationSummary
H264StreamValidationSession::GetSummary() const noexcept
{
    return m_summary;
}

} // namespace lumabridge::host
