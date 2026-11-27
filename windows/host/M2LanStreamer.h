// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <string>

#include "NvencH264Encoder.h"

namespace lumabridge::host {

struct M2LanStreamConfig {
    std::string friendlyName{"Win11-NVENC-Host"};
    std::string transport{"quic-datagram"};
    std::string pairAddr{};
    std::string opAddr{};
    std::string pin{};
    std::string peerDeviceIdHex{};
    uint16_t width{1920U};
    uint16_t height{1080U};
    uint16_t fps{60U};
    uint32_t initialBitrateBps{15000000U};
};

#ifdef LUMABRIDGE_ENABLE_FFI_POC

/// Manages live encrypted LAN streaming (SPAKE2 + mTLS + QUIC/TCP) from Windows Host GPU NVENC
/// output over `lumabridge_ffi.dll` (`lb_node_host_*`).
class M2LanStreamer final {
public:
    M2LanStreamer() noexcept = default;
    ~M2LanStreamer() noexcept;

    M2LanStreamer(const M2LanStreamer&) = delete;
    M2LanStreamer& operator=(const M2LanStreamer&) = delete;

    bool Start(const M2LanStreamConfig& cfg) noexcept;
    bool SubmitEncodedPacket(
        const EncodedFramePacket& pkt,
        uint64_t qpcFreq,
        uint64_t startQpc,
        bool* outForceIdr,
        uint32_t* outNewBitrateBps,
        bool* outSessionClosed) noexcept;
    bool SendProtectedBlank(uint64_t tsUs) noexcept;
    void Stop() noexcept;

    bool IsRunning() const noexcept;

private:
    struct Impl;
    Impl* m_impl{nullptr};
};

/// Real GPU D3D11 + RTX NVENC -> QUIC/TLS 1.3 -> MF MFT Decode + Bitrate Reconf + ProtectedBlank loopback test.
int RunM2NvencLoopbackSelfTest() noexcept;

#else

class M2LanStreamer final {
public:
    bool Start(const M2LanStreamConfig&) noexcept { return false; }
    bool SubmitEncodedPacket(const EncodedFramePacket&, uint64_t, uint64_t, bool*, uint32_t*, bool*) noexcept {
        return false;
    }
    bool SendProtectedBlank(uint64_t) noexcept { return false; }
    void Stop() noexcept {}
    bool IsRunning() const noexcept { return false; }
};

inline int RunM2NvencLoopbackSelfTest() noexcept { return 1; }

#endif

} // namespace lumabridge::host
