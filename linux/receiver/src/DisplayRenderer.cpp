// SPDX-License-Identifier: Apache-2.0
#include "DisplayRenderer.h"

#include <SDL2/SDL.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace lumabridge::linux_rx {
namespace {

struct Glyph5x7 {
    char ch;
    uint8_t cols[5];
};

// Minimal crisp 5x7 ASCII font for BRIDGE_TERMINAL diagnostic HUD (zero external font deps).
constexpr Glyph5x7 kFont5x7[] = {
    {' ', {0x00, 0x00, 0x00, 0x00, 0x00}},
    {'-', {0x08, 0x08, 0x08, 0x08, 0x08}},
    {'_', {0x40, 0x40, 0x40, 0x40, 0x40}},
    {':', {0x00, 0x14, 0x00, 0x00, 0x00}},
    {'/', {0x20, 0x10, 0x08, 0x04, 0x02}},
    {'.', {0x00, 0x40, 0x00, 0x00, 0x00}},
    {'=', {0x14, 0x14, 0x14, 0x14, 0x14}},
    {'0', {0x3E, 0x51, 0x49, 0x45, 0x3E}},
    {'1', {0x00, 0x42, 0x7F, 0x40, 0x00}},
    {'2', {0x42, 0x61, 0x51, 0x49, 0x46}},
    {'3', {0x21, 0x41, 0x45, 0x4B, 0x31}},
    {'4', {0x18, 0x14, 0x12, 0x7F, 0x10}},
    {'5', {0x27, 0x45, 0x45, 0x45, 0x39}},
    {'6', {0x3C, 0x4A, 0x49, 0x49, 0x30}},
    {'7', {0x01, 0x71, 0x09, 0x05, 0x03}},
    {'8', {0x36, 0x49, 0x49, 0x49, 0x36}},
    {'9', {0x06, 0x49, 0x49, 0x29, 0x1E}},
    {'A', {0x7E, 0x11, 0x11, 0x11, 0x7E}},
    {'B', {0x7F, 0x49, 0x49, 0x49, 0x36}},
    {'C', {0x3E, 0x41, 0x41, 0x41, 0x22}},
    {'D', {0x7F, 0x41, 0x41, 0x22, 0x1C}},
    {'E', {0x7F, 0x49, 0x49, 0x49, 0x41}},
    {'F', {0x7F, 0x09, 0x09, 0x09, 0x01}},
    {'G', {0x3E, 0x41, 0x49, 0x49, 0x7A}},
    {'H', {0x7F, 0x08, 0x08, 0x08, 0x7F}},
    {'I', {0x00, 0x41, 0x7F, 0x41, 0x00}},
    {'K', {0x7F, 0x08, 0x14, 0x22, 0x41}},
    {'L', {0x7F, 0x40, 0x40, 0x40, 0x40}},
    {'M', {0x7F, 0x02, 0x0C, 0x02, 0x7F}},
    {'N', {0x7F, 0x04, 0x08, 0x10, 0x7F}},
    {'O', {0x3E, 0x41, 0x41, 0x41, 0x3E}},
    {'P', {0x7F, 0x09, 0x09, 0x09, 0x06}},
    {'Q', {0x3E, 0x41, 0x51, 0x21, 0x5E}},
    {'R', {0x7F, 0x09, 0x19, 0x29, 0x46}},
    {'S', {0x46, 0x49, 0x49, 0x49, 0x31}},
    {'T', {0x01, 0x01, 0x7F, 0x01, 0x01}},
    {'U', {0x3F, 0x40, 0x40, 0x40, 0x3F}},
    {'V', {0x1F, 0x20, 0x40, 0x20, 0x1F}},
    {'W', {0x3F, 0x40, 0x38, 0x40, 0x3F}},
    {'X', {0x63, 0x14, 0x08, 0x14, 0x63}},
    {'Y', {0x07, 0x08, 0x70, 0x08, 0x07}},
    {'Z', {0x61, 0x51, 0x49, 0x45, 0x43}},
};

const uint8_t* LookupGlyph(char c) noexcept {
    const char up = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    for (const auto& g : kFont5x7) {
        if (g.ch == up) {
            return g.cols;
        }
    }
    return kFont5x7[0].cols;
}

void DrawHudString(
    uint8_t* bgraPixels,
    uint32_t imgW,
    uint32_t imgH,
    uint32_t pitchBytes,
    uint32_t originX,
    uint32_t originY,
    const char* text) noexcept
{
    uint32_t cursorX = originX;
    for (const char* p = text; *p != '\0'; ++p) {
        if (cursorX + 6U >= imgW) {
            break;
        }
        const uint8_t* cols = LookupGlyph(*p);
        for (uint32_t cx = 0U; cx < 5U; ++cx) {
            for (uint32_t ry = 0U; ry < 7U; ++ry) {
                const uint32_t py = originY + ry;
                if (py >= imgH) {
                    continue;
                }
                if (((cols[cx] >> ry) & 0x01U) != 0U) {
                    uint8_t* dst = bgraPixels + static_cast<size_t>(py) * pitchBytes + static_cast<size_t>(cursorX + cx) * 4U;
                    dst[0] = 0x90U; // B
                    dst[1] = 0xFFU; // G
                    dst[2] = 0x20U; // R (phosphor cyan-green terminal)
                    dst[3] = 0xFFU; // A
                }
            }
        }
        cursorX += 6U;
    }
}

} // namespace

DisplayBackend DetectDisplayBackend(const char* waylandDisplay, const char* x11Display, bool forceHeadless) noexcept {
    if (forceHeadless) {
        return DisplayBackend::Headless;
    }
    if (waylandDisplay != nullptr && waylandDisplay[0] != '\0') {
        return DisplayBackend::Wayland;
    }
    if (x11Display != nullptr && x11Display[0] != '\0') {
        return DisplayBackend::X11;
    }
    return DisplayBackend::Headless;
}

const char* DisplayBackendName(DisplayBackend backend) noexcept {
    switch (backend) {
    case DisplayBackend::Wayland:
        return "wayland";
    case DisplayBackend::X11:
        return "x11";
    case DisplayBackend::Headless:
    default:
        return "headless";
    }
}

void RenderBridgeTerminalHud(
    uint8_t* bgraPixels,
    uint32_t width,
    uint32_t height,
    uint32_t pitchBytes,
    const HudTelemetryOverlay& hud) noexcept
{
    if (bgraPixels == nullptr || width < 320U || height < 120U) {
        return;
    }
    const uint32_t boxX = 12U;
    const uint32_t boxY = 12U;
    const uint32_t boxW = (std::min)(width - 24U, 420U);
    const uint32_t boxH = 54U;

    for (uint32_t y = boxY; y < boxY + boxH && y < height; ++y) {
        uint8_t* row = bgraPixels + static_cast<size_t>(y) * pitchBytes;
        for (uint32_t x = boxX; x < boxX + boxW && x < width; ++x) {
            uint8_t* px = row + static_cast<size_t>(x) * 4U;
            // Semi-transparent dark terminal backdrop
            px[0] = static_cast<uint8_t>(px[0] / 3U);
            px[1] = static_cast<uint8_t>(px[1] / 3U);
            px[2] = static_cast<uint8_t>(px[2] / 3U);
            px[3] = 0xFFU;
        }
    }

    char line1[96]{};
    char line2[96]{};
    char line3[96]{};
    std::snprintf(
        line1,
        sizeof(line1),
        "BRIDGE_TERMINAL  %s  %s/%s",
        hud.blankActive ? "PROTECTED_BLANK" : "LIVE",
        hud.displayBackend.c_str(),
        hud.decodeBackend.c_str());
    std::snprintf(
        line2,
        sizeof(line2),
        "NET:%s  RES:%ux%u  RX:%llu  DEC:%llu",
        hud.transport.c_str(),
        hud.width,
        hud.height,
        static_cast<unsigned long long>(hud.framesDelivered),
        static_cast<unsigned long long>(hud.framesDecoded));
    std::snprintf(
        line3,
        sizeof(line3),
        "DROP:%llu  BLANK:%llu  RTT_US:%llu  P95_US:%llu",
        static_cast<unsigned long long>(hud.droppedFrames),
        static_cast<unsigned long long>(hud.protectedBlanks),
        static_cast<unsigned long long>(hud.clockSyncRttUs),
        static_cast<unsigned long long>(hud.e2eP95Us));

    DrawHudString(bgraPixels, width, height, pitchBytes, boxX + 8U, boxY + 8U, line1);
    DrawHudString(bgraPixels, width, height, pitchBytes, boxX + 8U, boxY + 22U, line2);
    DrawHudString(bgraPixels, width, height, pitchBytes, boxX + 8U, boxY + 36U, line3);
}

struct DisplayRenderer::Impl {
    SDL_Window* window{nullptr};
    SDL_Renderer* renderer{nullptr};
    SDL_Texture* texture{nullptr};
    uint32_t texW{0U};
    uint32_t texH{0U};
    std::vector<uint8_t> blankBgra{};
};

DisplayRenderer::~DisplayRenderer() noexcept {
    Shutdown();
}

bool DisplayRenderer::Initialize(
    uint32_t width,
    uint32_t height,
    bool fullscreen,
    bool vsync,
    bool overlayEnabled,
    bool forceHeadless,
    std::string& outError)
{
    Shutdown();
    m_width = width;
    m_height = height;
    m_overlayEnabled = overlayEnabled;
    m_blanksPresented = 0ULL;
    m_backend = DetectDisplayBackend(std::getenv("WAYLAND_DISPLAY"), std::getenv("DISPLAY"), forceHeadless);

    auto* impl = new Impl();
    impl->blankBgra.assign(static_cast<size_t>(width) * static_cast<size_t>(height) * 4U, 0U);
    for (size_t i = 3; i < impl->blankBgra.size(); i += 4) {
        impl->blankBgra[i] = 0xFFU;
    }

    if (m_backend == DisplayBackend::Headless) {
        m_impl = impl;
        return true;
    }

    if (m_backend == DisplayBackend::Wayland && std::getenv("SDL_VIDEODRIVER") == nullptr) {
        SDL_SetHint(SDL_HINT_VIDEODRIVER, "wayland,x11");
    }
    if (SDL_Init(SDL_INIT_VIDEO) != 0) {
        delete impl;
        outError = std::string("SDL_Init(SDL_INIT_VIDEO) failed: ") + SDL_GetError();
        return false;
    }

    uint32_t winFlags = SDL_WINDOW_SHOWN | SDL_WINDOW_RESIZABLE;
    if (fullscreen) {
        winFlags |= SDL_WINDOW_FULLSCREEN_DESKTOP | SDL_WINDOW_BORDERLESS;
    }
    const int winW = fullscreen ? static_cast<int>(width) : static_cast<int>((std::min)(width, 1280U));
    const int winH = fullscreen ? static_cast<int>(height) : static_cast<int>((std::min)(height, 720U));
    impl->window = SDL_CreateWindow(
        "LumaBridge Display Receiver",
        SDL_WINDOWPOS_CENTERED,
        SDL_WINDOWPOS_CENTERED,
        winW,
        winH,
        winFlags);
    if (impl->window == nullptr) {
        SDL_Quit();
        delete impl;
        outError = std::string("SDL_CreateWindow failed: ") + SDL_GetError();
        return false;
    }

    const uint32_t renFlags = vsync ? (SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC) : SDL_RENDERER_ACCELERATED;
    impl->renderer = SDL_CreateRenderer(impl->window, -1, renFlags);
    if (impl->renderer == nullptr) {
        impl->renderer = SDL_CreateRenderer(impl->window, -1, SDL_RENDERER_SOFTWARE);
    }
    if (impl->renderer == nullptr) {
        SDL_DestroyWindow(impl->window);
        SDL_Quit();
        delete impl;
        outError = std::string("SDL_CreateRenderer failed: ") + SDL_GetError();
        return false;
    }

    m_impl = impl;
    return true;
}

bool DisplayRenderer::PumpEvents(bool& outQuitRequested) {
    outQuitRequested = false;
    if (m_backend == DisplayBackend::Headless || m_impl == nullptr) {
        return true;
    }
    SDL_Event ev{};
    while (SDL_PollEvent(&ev) != 0) {
        if (ev.type == SDL_QUIT) {
            outQuitRequested = true;
            return true;
        }
        if (ev.type == SDL_KEYDOWN) {
            const SDL_Keycode sym = ev.key.keysym.sym;
            const uint16_t mod = ev.key.keysym.mod;
            if (sym == SDLK_ESCAPE ||
                (sym == SDLK_q && (mod & KMOD_CTRL) != 0 && (mod & KMOD_SHIFT) != 0)) {
                outQuitRequested = true;
                return true;
            }
            if (sym == SDLK_F12) {
                m_overlayEnabled = !m_overlayEnabled;
            }
        }
    }
    return true;
}

bool DisplayRenderer::PresentFrame(
    DecodedRgbaFrame& frame,
    const HudTelemetryOverlay& hud,
    bool& outQuitRequested,
    uint64_t& outPresentUs,
    std::string& outError)
{
    outPresentUs = 0ULL;
    if (m_impl == nullptr) {
        outError = "DisplayRenderer not initialized";
        return false;
    }

    const auto t0 = std::chrono::steady_clock::now();
    if (m_overlayEnabled) {
        RenderBridgeTerminalHud(
            frame.bgraPixels.data(),
            frame.width,
            frame.height,
            frame.pitchBytes,
            hud);
    }

    if (m_backend != DisplayBackend::Headless) {
        bool stepQuit = false;
        PumpEvents(stepQuit);
        if (stepQuit) {
            outQuitRequested = true;
        }
        if (m_impl->texture == nullptr ||
            m_impl->texW != frame.width ||
            m_impl->texH != frame.height) {
            if (m_impl->texture != nullptr) {
                SDL_DestroyTexture(m_impl->texture);
            }
            m_impl->texture = SDL_CreateTexture(
                m_impl->renderer,
                SDL_PIXELFORMAT_ARGB8888,
                SDL_TEXTUREACCESS_STREAMING,
                static_cast<int>(frame.width),
                static_cast<int>(frame.height));
            m_impl->texW = frame.width;
            m_impl->texH = frame.height;
            if (m_impl->texture == nullptr) {
                outError = std::string("SDL_CreateTexture failed: ") + SDL_GetError();
                return false;
            }
        }
        SDL_UpdateTexture(
            m_impl->texture,
            nullptr,
            frame.bgraPixels.data(),
            static_cast<int>(frame.pitchBytes));
        SDL_RenderClear(m_impl->renderer);
        SDL_RenderCopy(m_impl->renderer, m_impl->texture, nullptr, nullptr);
        SDL_RenderPresent(m_impl->renderer);
    }
    const auto t1 = std::chrono::steady_clock::now();
    outPresentUs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
    return true;
}

bool DisplayRenderer::PresentProtectedBlank(
    const HudTelemetryOverlay& hud,
    bool& outQuitRequested,
    std::string& outError)
{
    if (m_impl == nullptr) {
        outError = "DisplayRenderer not initialized";
        return false;
    }
    ++m_blanksPresented;
    DecodedRgbaFrame blank{};
    blank.width = m_width;
    blank.height = m_height;
    blank.pitchBytes = m_width * 4U;
    blank.bgraPixels = m_impl->blankBgra;
    HudTelemetryOverlay hudCopy = hud;
    hudCopy.blankActive = true;
    uint64_t presUs = 0ULL;
    return PresentFrame(blank, hudCopy, outQuitRequested, presUs, outError);
}

void DisplayRenderer::Shutdown() noexcept {
    if (m_impl == nullptr) {
        return;
    }
    if (m_impl->texture != nullptr) {
        SDL_DestroyTexture(m_impl->texture);
    }
    if (m_impl->renderer != nullptr) {
        SDL_DestroyRenderer(m_impl->renderer);
    }
    if (m_impl->window != nullptr) {
        SDL_DestroyWindow(m_impl->window);
    }
    if (m_backend != DisplayBackend::Headless) {
        SDL_Quit();
    }
    delete m_impl;
    m_impl = nullptr;
}

} // namespace lumabridge::linux_rx
