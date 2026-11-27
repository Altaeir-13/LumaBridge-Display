// SPDX-License-Identifier: Apache-2.0
#include "Config.h"
#include "DisplayRenderer.h"
#include "VaapiH264Decoder.h"
#include "lumabridge_ffi.h"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <vector>

namespace {

std::atomic<bool> g_StopRequested{false};

extern "C" void HandlePosixSignal(int) {
    g_StopRequested.store(true, std::memory_order_release);
}

template <typename T>
LbAbiHeader MakeAbiHeader() noexcept {
    LbAbiHeader hdr{};
    hdr.abi_major = LB_FFI_ABI_MAJOR;
    hdr.abi_minor = LB_FFI_ABI_MINOR;
    hdr.struct_size = static_cast<uint32_t>(sizeof(T));
    hdr.reserved = 0U;
    return hdr;
}

uint32_t MapTransportKind(const std::string& transport) noexcept {
    if (transport == "quic-stream") {
        return static_cast<uint32_t>(LB_NODE_TRANSPORT_KIND_QUIC_STREAM);
    }
    if (transport == "tcp-tls") {
        return static_cast<uint32_t>(LB_NODE_TRANSPORT_KIND_TCP_TLS);
    }
    return static_cast<uint32_t>(LB_NODE_TRANSPORT_KIND_QUIC_DATAGRAM);
}

bool WriteTextFileAtomically(const std::string& path, const std::string& content, bool restrictPerms) {
    const std::string tmpPath = path + ".tmp";
    {
        std::ofstream ofs(tmpPath, std::ios::out | std::ios::trunc);
        if (!ofs.is_open()) {
            return false;
        }
        ofs << content;
        if (!ofs.good()) {
            return false;
        }
    }
    if (restrictPerms) {
        (void)::chmod(tmpPath.c_str(), S_IRUSR | S_IWUSR);
    }
    return std::rename(tmpPath.c_str(), path.c_str()) == 0;
}

} // namespace

int main(int argc, char** argv) {
    using namespace lumabridge::linux_rx;

    std::signal(SIGINT, HandlePosixSignal);
    std::signal(SIGTERM, HandlePosixSignal);

    ReceiverConfig cfg{};
    bool showHelp = false;
    std::string err{};
    if (!ParseReceiverCliArgs(argc, argv, cfg, showHelp, err)) {
        std::fprintf(stderr, "[LB-LINUX-RX] Argument error: %s\n", err.c_str());
        return 2;
    }
    if (showHelp) {
        PrintReceiverUsage();
        return 0;
    }

    VaapiH264Decoder decoder;
    if (!decoder.Initialize(cfg.allowSwFallback, cfg.vaapiDevice, err)) {
        std::fprintf(stderr, "[LB-LINUX-RX] Decoder init error: %s\n", err.c_str());
        return 1;
    }

    DisplayRenderer renderer;
    if (!renderer.Initialize(
            cfg.width,
            cfg.height,
            cfg.fullscreen,
            cfg.vsync,
            cfg.overlay,
            cfg.headless,
            err)) {
        std::fprintf(stderr, "[LB-LINUX-RX] Display renderer init error: %s\n", err.c_str());
        decoder.Shutdown();
        return 1;
    }

    LbNodeConfig nodeCfg{};
    nodeCfg.abi = MakeAbiHeader<LbNodeConfig>();
    nodeCfg.role = static_cast<uint32_t>(LB_NODE_ROLE_CONTROLLER);
    nodeCfg.transport_kind = MapTransportKind(cfg.transport);
    nodeCfg.max_virtual_displays = 1U;
    nodeCfg.heartbeat_timeout_ms = 8000U;
    std::memcpy(nodeCfg.friendly_name, cfg.friendlyName.data(), cfg.friendlyName.size());
    nodeCfg.friendly_name_len = static_cast<uint32_t>(cfg.friendlyName.size());

    LbNodeHandle* node = nullptr;
    if (lb_node_create(&nodeCfg, &node) != LB_STATUS_OK || node == nullptr) {
        std::fprintf(stderr, "[LB-LINUX-RX] lb_node_create failed.\n");
        renderer.Shutdown();
        decoder.Shutdown();
        return 1;
    }

    LbReceiverStartConfig startCfg{};
    startCfg.abi = MakeAbiHeader<LbReceiverStartConfig>();
    startCfg.transport_kind = nodeCfg.transport_kind;
    std::memcpy(startCfg.bind_addr_utf8, cfg.bindAddr.data(), cfg.bindAddr.size());
    startCfg.bind_addr_len = static_cast<uint32_t>(cfg.bindAddr.size());
    startCfg.width = cfg.width;
    startCfg.height = cfg.height;
    startCfg.fps_num = cfg.fps;
    startCfg.fps_den = 1U;
    startCfg.enable_mdns = cfg.enableMdns ? 1U : 0U;

    LbReceiverSessionHandle* rxSess = nullptr;
    if (lb_node_receiver_start(node, &startCfg, &rxSess) != LB_STATUS_OK || rxSess == nullptr) {
        std::fprintf(stderr, "[LB-LINUX-RX] lb_node_receiver_start failed on %s.\n", cfg.bindAddr.c_str());
        (void)lb_node_destroy(node);
        renderer.Shutdown();
        decoder.Shutdown();
        return 1;
    }

    LbReceiverEndpoints ep{};
    ep.abi = MakeAbiHeader<LbReceiverEndpoints>();
    if (lb_node_receiver_get_endpoints(rxSess, &ep) != LB_STATUS_OK) {
        (void)lb_node_receiver_stop(rxSess);
        (void)lb_node_destroy(node);
        renderer.Shutdown();
        decoder.Shutdown();
        return 1;
    }

    const std::string readyLine =
        std::string(reinterpret_cast<const char*>(ep.pair_addr_utf8)) + "|" +
        std::string(reinterpret_cast<const char*>(ep.op_addr_utf8)) + "|" +
        std::string(reinterpret_cast<const char*>(ep.device_id_hex)) + "|" +
        std::string(reinterpret_cast<const char*>(ep.pin_ascii));

    if (!cfg.endpointOut.empty()) {
        if (!WriteTextFileAtomically(cfg.endpointOut, readyLine, true)) {
            std::fprintf(stderr, "[LB-LINUX-RX] Failed writing --endpoint-out.\n");
            (void)lb_node_receiver_stop(rxSess);
            (void)lb_node_destroy(node);
            renderer.Shutdown();
            decoder.Shutdown();
            return 1;
        }
    } else {
        std::printf("[LB-LINUX-RX] Ready transport=%s pair=%s op=%s pin=%s device_id=%.12s... display=%s decode=%s\n",
                    cfg.transport.c_str(),
                    reinterpret_cast<const char*>(ep.pair_addr_utf8),
                    reinterpret_cast<const char*>(ep.op_addr_utf8),
                    reinterpret_cast<const char*>(ep.pin_ascii),
                    reinterpret_cast<const char*>(ep.device_id_hex),
                    DisplayBackendName(renderer.Backend()),
                    decoder.GetStats().backendName.c_str());
        std::fflush(stdout);
    }

    bool quitRequested = false;
    while (!g_StopRequested.load(std::memory_order_acquire) && !quitRequested) {
        LbReceiverMediaEvent evt{};
        evt.abi = MakeAbiHeader<LbReceiverMediaEvent>();
        if (lb_node_receiver_poll_event(rxSess, 25U, &evt) != LB_STATUS_OK) {
            break;
        }

        LbNodeTelemetry tel{};
        tel.abi = MakeAbiHeader<LbNodeTelemetry>();
        (void)lb_node_receiver_get_telemetry(rxSess, &tel);

        const DecoderStats decStats = decoder.GetStats();
        HudTelemetryOverlay hud{};
        hud.transport = cfg.transport;
        hud.displayBackend = DisplayBackendName(renderer.Backend());
        hud.decodeBackend = decStats.backendName;
        hud.width = cfg.width;
        hud.height = cfg.height;
        hud.framesDelivered = tel.frames_delivered;
        hud.framesDecoded = decStats.framesDecoded;
        hud.droppedFrames = tel.dropped_frames;
        hud.protectedBlanks = tel.protected_blanks;
        hud.clockSyncRttUs = tel.clock_sync_rtt_us;
        hud.e2eP95Us = tel.e2e_p95_us;

        if (evt.kind == static_cast<uint32_t>(LB_RECEIVER_EVENT_KIND_NONE)) {
            (void)renderer.PumpEvents(quitRequested);
            continue;
        }
        if (evt.kind == static_cast<uint32_t>(LB_RECEIVER_EVENT_KIND_SESSION_CLOSED)) {
            break;
        }
        if (evt.kind == static_cast<uint32_t>(LB_RECEIVER_EVENT_KIND_PROTECTED_BLANK)) {
            std::string presErr{};
            if (!renderer.PresentProtectedBlank(hud, quitRequested, presErr)) {
                std::fprintf(stderr, "[LB-LINUX-RX] PresentProtectedBlank error: %s\n", presErr.c_str());
                break;
            }
            if (cfg.maxFrames > 0ULL && tel.frames_delivered >= cfg.maxFrames) {
                break;
            }
            continue;
        }
        if (evt.kind == static_cast<uint32_t>(LB_RECEIVER_EVENT_KIND_VIDEO_FRAME)) {
            std::vector<uint8_t> annexb{};
            if (evt.payload.data != nullptr && evt.payload.len > 0U) {
                annexb.assign(evt.payload.data, evt.payload.data + evt.payload.len);
            }
            (void)lb_core_release_buffer(&evt.payload);

            if (!annexb.empty()) {
                const auto d0 = std::chrono::steady_clock::now();
                std::vector<DecodedRgbaFrame> decodedFrames{};
                std::string decErr{};
                if (!decoder.DecodePacket(annexb.data(), annexb.size(), decodedFrames, decErr)) {
                    std::fprintf(stderr, "[LB-LINUX-RX] Decode warning on frame %u: %s\n", evt.frame_id, decErr.c_str());
                }
                const auto d1 = std::chrono::steady_clock::now();
                const uint64_t decUs = static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::microseconds>(d1 - d0).count());

                uint64_t presUs = 0ULL;
                for (auto& df : decodedFrames) {
                    hud.framesDecoded = decoder.GetStats().framesDecoded;
                    hud.width = df.width;
                    hud.height = df.height;
                    std::string presErr{};
                    if (!renderer.PresentFrame(df, hud, quitRequested, presUs, presErr)) {
                        std::fprintf(stderr, "[LB-LINUX-RX] Present error: %s\n", presErr.c_str());
                        quitRequested = true;
                        break;
                    }
                }
                (void)lb_node_receiver_record_timing(rxSess, decUs, presUs);
            }

            if (cfg.maxFrames > 0ULL &&
                tel.frames_delivered >= cfg.maxFrames &&
                decoder.GetStats().framesDecoded > 0ULL) {
                // Keep polling briefly up to 200ms in case ProtectedBlank follows immediately.
                LbReceiverMediaEvent tailEvt{};
                tailEvt.abi = MakeAbiHeader<LbReceiverMediaEvent>();
                if (lb_node_receiver_poll_event(rxSess, 150U, &tailEvt) == LB_STATUS_OK &&
                    tailEvt.kind == static_cast<uint32_t>(LB_RECEIVER_EVENT_KIND_PROTECTED_BLANK)) {
                    std::string presErr{};
                    (void)renderer.PresentProtectedBlank(hud, quitRequested, presErr);
                } else if (tailEvt.payload.release != nullptr) {
                    (void)lb_core_release_buffer(&tailEvt.payload);
                }
                break;
            }
        }
    }

    char coreJsonBuf[8192]{};
    size_t coreJsonLen = 0U;
    const LbStatus exportSt = lb_node_receiver_export_telemetry_json(
        rxSess,
        reinterpret_cast<uint8_t*>(coreJsonBuf),
        sizeof(coreJsonBuf) - 1U,
        &coreJsonLen);

    const DecoderStats finalDec = decoder.GetStats();
    const DisplayBackend finalDisp = renderer.Backend();
    const uint64_t finalBlanks = renderer.ProtectedBlanksPresented();

    (void)lb_node_receiver_stop(rxSess);
    (void)lb_node_destroy(node);
    renderer.Shutdown();
    decoder.Shutdown();

    const std::string coreJson =
        (exportSt == LB_STATUS_OK && coreJsonLen > 0U && coreJsonLen < sizeof(coreJsonBuf))
            ? std::string(coreJsonBuf, coreJsonLen)
            : "{}";
    std::string combinedReport = "{\n";
    combinedReport += "  \"display_backend\": \"" + std::string(DisplayBackendName(finalDisp)) + "\",\n";
    combinedReport += "  \"decode_backend\": \"" + finalDec.backendName + "\",\n";
    combinedReport += "  \"vaapi_active\": " + std::string(finalDec.vaapiActive ? "true" : "false") + ",\n";
    combinedReport += "  \"frames_decoded\": " + std::to_string(finalDec.framesDecoded) + ",\n";
    combinedReport += "  \"decode_errors\": " + std::to_string(finalDec.decodeErrors) + ",\n";
    combinedReport += "  \"protected_blanks_rendered\": " + std::to_string(finalBlanks) + ",\n";
    combinedReport += "  \"core_telemetry\": " + coreJson + "\n";
    combinedReport += "}\n";

    if (!cfg.jsonReport.empty()) {
        if (!WriteTextFileAtomically(cfg.jsonReport, combinedReport, false)) {
            std::fprintf(stderr, "[LB-LINUX-RX] Failed writing --json-report.\n");
            return 1;
        }
    } else {
        std::printf("%s", combinedReport.c_str());
    }
    return 0;
}
