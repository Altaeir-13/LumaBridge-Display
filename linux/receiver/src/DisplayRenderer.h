// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <string>

#include "VaapiH264Decoder.h"

namespace lumabridge::linux_rx {

enum class DisplayBackend {
    Wayland = 0,
    X11 = 1,
    Headless = 2,
};

struct HudTelemetryOverlay {
    std::string transport{"quic-datagram"};
    std::string displayBackend{"wayland"};
    std::string decodeBackend{"vaapi"};
    uint32_t width{1920U};
    uint32_t height{1080U};
    uint64_t framesDelivered{0ULL};
    uint64_t framesDecoded{0ULL};
    uint64_t droppedFrames{0ULL};
    uint64_t protectedBlanks{0ULL};
    uint64_t clockSyncRttUs{0ULL};
    uint64_t e2eP95Us{0ULL};
    bool blankActive{false};
};

/// Pure unit-testable Wayland vs X11 vs Headless selector.
DisplayBackend DetectDisplayBackend(const char* waylandDisplay, const char* x11Display, bool forceHeadless) noexcept;
const char* DisplayBackendName(DisplayBackend backend) noexcept;

/// Renders clean 5x7 monochrome/tinted `BRIDGE_TERMINAL` diagnostic telemetry HUD onto a BGRA8 buffer.
void RenderBridgeTerminalHud(
    uint8_t* bgraPixels,
    uint32_t width,
    uint32_t height,
    uint32_t pitchBytes,
    const HudTelemetryOverlay& hud) noexcept;

/// Low-latency SDL2 presenter supporting native Wayland (`SDL_VIDEODRIVER=wayland`), X11, and Headless.
class DisplayRenderer final {
public:
    DisplayRenderer() noexcept = default;
    ~DisplayRenderer() noexcept;

    DisplayRenderer(const DisplayRenderer&) = delete;
    DisplayRenderer& operator=(const DisplayRenderer&) = delete;

    bool Initialize(
        uint32_t width,
        uint32_t height,
        bool fullscreen,
        bool vsync,
        bool overlayEnabled,
        bool forceHeadless,
        std::string& outError);

    /// Returns false only if a fatal renderer error occurred; `outQuitRequested` turns true on Esc/Ctrl+Shift+Q/Close.
    bool PresentFrame(
        DecodedRgbaFrame& frame,
        const HudTelemetryOverlay& hud,
        bool& outQuitRequested,
        uint64_t& outPresentUs,
        std::string& outError);

    bool PresentProtectedBlank(
        const HudTelemetryOverlay& hud,
        bool& outQuitRequested,
        std::string& outError);

    bool PumpEvents(bool& outQuitRequested);
    void Shutdown() noexcept;

    DisplayBackend Backend() const noexcept { return m_backend; }
    bool IsOverlayEnabled() const noexcept { return m_overlayEnabled; }
    uint64_t ProtectedBlanksPresented() const noexcept { return m_blanksPresented; }

private:
    struct Impl;
    Impl* m_impl{nullptr};
    DisplayBackend m_backend{DisplayBackend::Headless};
    bool m_overlayEnabled{false};
    uint32_t m_width{1920U};
    uint32_t m_height{1080U};
    uint64_t m_blanksPresented{0ULL};
};

} // namespace lumabridge::linux_rx
