// SPDX-License-Identifier: Apache-2.0
#include "../src/Config.h"
#include "../src/DisplayRenderer.h"
#include "../src/VaapiH264Decoder.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <vector>

using namespace lumabridge::linux_rx;

#define LB_TEST_CHECK(expr)                                                               \
    do {                                                                                  \
        if (!(expr)) {                                                                    \
            std::fprintf(stderr, "[FAIL] %s:%d: %s\n", __FILE__, __LINE__, #expr);        \
            return 1;                                                                     \
        }                                                                                 \
    } while (false)

int main() {
    // 1. Config persistence & validation tests
    {
        ReceiverConfig cfg{};
        cfg.friendlyName = "ArchHyprlandLaptop";
        cfg.transport = "quic-datagram";
        cfg.bindAddr = "0.0.0.0:4242";
        cfg.width = 1920U;
        cfg.height = 1080U;
        cfg.fps = 60U;
        cfg.overlay = true;
        cfg.allowSwFallback = false;

        std::string err{};
        const std::string path =
            "/tmp/lumabridge_rx_unit_test_" + std::to_string(static_cast<long long>(::getpid())) + ".conf";
        LB_TEST_CHECK(SaveReceiverConfigFile(path, cfg, err));

        ReceiverConfig loaded{};
        LB_TEST_CHECK(LoadReceiverConfigFile(path, loaded, err));
        LB_TEST_CHECK(loaded.friendlyName == cfg.friendlyName);
        LB_TEST_CHECK(loaded.transport == cfg.transport);
        LB_TEST_CHECK(loaded.bindAddr == cfg.bindAddr);
        LB_TEST_CHECK(loaded.width == 1920U && loaded.height == 1080U && loaded.fps == 60U);
        LB_TEST_CHECK(loaded.overlay);
        LB_TEST_CHECK(!loaded.allowSwFallback);
        std::remove(path.c_str());

        ReceiverConfig bad{};
        bad.width = 100U;
        LB_TEST_CHECK(!ValidateReceiverConfig(bad, err));
    }

    // 2. Display backend auto-detection (Wayland vs X11 vs Headless)
    LB_TEST_CHECK(DetectDisplayBackend("wayland-1", ":0", false) == DisplayBackend::Wayland);
    LB_TEST_CHECK(DetectDisplayBackend("", ":0", false) == DisplayBackend::X11);
    LB_TEST_CHECK(DetectDisplayBackend(nullptr, nullptr, false) == DisplayBackend::Headless);
    LB_TEST_CHECK(DetectDisplayBackend("wayland-1", ":0", true) == DisplayBackend::Headless);

    // 3. BRIDGE_TERMINAL HUD rasterizer & ProtectedBlank black clear
    {
        constexpr uint32_t w = 640U;
        constexpr uint32_t h = 240U;
        std::vector<uint8_t> fb(w * h * 4U, 0x10U);
        HudTelemetryOverlay hud{};
        hud.transport = "quic-datagram";
        hud.displayBackend = "wayland";
        hud.decodeBackend = "vaapi";
        hud.width = 1920U;
        hud.height = 1080U;
        hud.framesDelivered = 120U;
        hud.framesDecoded = 120U;
        RenderBridgeTerminalHud(fb.data(), w, h, w * 4U, hud);

        bool foundHudPixel = false;
        for (size_t i = 0; i < fb.size(); i += 4) {
            if (fb[i + 1] == 0xFFU && fb[i] == 0x90U) {
                foundHudPixel = true;
                break;
            }
        }
        LB_TEST_CHECK(foundHudPixel);

        DisplayRenderer headless{};
        std::string err{};
        LB_TEST_CHECK(headless.Initialize(w, h, false, false, true, true, err));
        bool quit = false;
        LB_TEST_CHECK(headless.PresentProtectedBlank(hud, quit, err));
        LB_TEST_CHECK(headless.ProtectedBlanksPresented() == 1ULL);
        headless.Shutdown();
    }

    // 4. Decoder diagnostic safety & real SW fallback initialization check
    {
        VaapiH264Decoder dec{};
        std::string err{};
        if (!dec.Initialize(false, "", err)) {
            LB_TEST_CHECK(err.find("VA-API") != std::string::npos);
        } else {
            LB_TEST_CHECK(dec.GetStats().vaapiActive);
            dec.Shutdown();
        }
        LB_TEST_CHECK(dec.Initialize(true, "", err));
        LB_TEST_CHECK(!dec.GetStats().backendName.empty());
        dec.Shutdown();
    }

    std::printf("[PASS] lumabridge-linux-receiver-tests (4/4)\n");
    return 0;
}
