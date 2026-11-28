// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace lumabridge::linux_rx {

struct DecodedRgbaFrame {
    uint32_t width{0U};
    uint32_t height{0U};
    uint32_t pitchBytes{0U};
    std::vector<uint8_t> bgraPixels{};
};

struct DecoderStats {
    bool vaapiActive{false};
    std::string backendName{"uninitialized"};
    uint64_t framesDecoded{0ULL};
    uint64_t decodeErrors{0ULL};
};

/// Real FFmpeg libavcodec H.264 Annex-B decoder prioritizing Intel/AMD VA-API HW decode.
/// Software fallback is strictly refused unless `allowSwFallback` is explicitly enabled.
class VaapiH264Decoder final {
public:
    VaapiH264Decoder() noexcept = default;
    ~VaapiH264Decoder() noexcept;

    VaapiH264Decoder(const VaapiH264Decoder&) = delete;
    VaapiH264Decoder& operator=(const VaapiH264Decoder&) = delete;

    bool Initialize(bool allowSwFallback, const std::string& vaapiDevicePath, std::string& outError);
    bool DecodePacket(
        const uint8_t* annexBData,
        size_t sizeBytes,
        std::vector<DecodedRgbaFrame>& outFrames,
        std::string& outError);
    void Shutdown() noexcept;

    DecoderStats GetStats() const noexcept { return m_stats; }

private:
    struct Impl;
    Impl* m_impl{nullptr};
    DecoderStats m_stats{};
};

} // namespace lumabridge::linux_rx
