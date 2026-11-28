// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <d3d11.h>
#include <cstdint>

#include "NvencH264Encoder.h"

namespace lumabridge::host {

/// Platform-native GPU frame consumer boundary matching UNIVERSAL_ROADMAP M2 (`IVideoFrameSource`).
class IVideoFrameSource {
public:
    virtual ~IVideoFrameSource() = default;
    virtual HostConsumerMetricsSnapshot GetMetricsSnapshot() const noexcept = 0;
};

/// Platform-native GPU video encoder boundary matching UNIVERSAL_ROADMAP M2 (`IVideoEncoder`).
class IVideoEncoder {
public:
    virtual ~IVideoEncoder() = default;
    virtual HRESULT EncodeGpuTexture(
        ID3D11Texture2D* sourceGpuTexture,
        uint64_t frameSequence,
        uint32_t presentationFrameNumber,
        uint64_t presentDisplayQpcTime,
        uint64_t extractCompleteQpcTime,
        uint64_t qpcFrequency) noexcept = 0;
    virtual bool TryPopEncodedFrame(EncodedFramePacket& outPacket) noexcept = 0;
    virtual void RequestForceIdr() noexcept = 0;
    virtual HRESULT SetTargetBitrateBps(uint32_t targetBitrateBps) noexcept = 0;
};

/// Concrete zero-CPU-readback NVENC adapter behind `IVideoEncoder`.
class NvencVideoEncoderAdapter final : public IVideoEncoder {
public:
    explicit NvencVideoEncoderAdapter(NvencH264Encoder& encoder) noexcept
        : m_encoder(encoder)
    {
    }

    HRESULT EncodeGpuTexture(
        ID3D11Texture2D* sourceGpuTexture,
        uint64_t frameSequence,
        uint32_t presentationFrameNumber,
        uint64_t presentDisplayQpcTime,
        uint64_t extractCompleteQpcTime,
        uint64_t qpcFrequency) noexcept override
    {
        return m_encoder.EncodeGpuTexture(
            sourceGpuTexture,
            frameSequence,
            presentationFrameNumber,
            presentDisplayQpcTime,
            extractCompleteQpcTime,
            qpcFrequency);
    }

    bool TryPopEncodedFrame(EncodedFramePacket& outPacket) noexcept override
    {
        return m_encoder.TryPopEncodedFrame(outPacket);
    }

    void RequestForceIdr() noexcept override
    {
        m_encoder.RequestForceIdrOnNextFrame();
    }

    HRESULT SetTargetBitrateBps(uint32_t targetBitrateBps) noexcept override
    {
        return m_encoder.UpdateDynamicBitrate(targetBitrateBps);
    }

private:
    NvencH264Encoder& m_encoder;
};

} // namespace lumabridge::host
