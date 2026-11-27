// SPDX-License-Identifier: Apache-2.0
#include "Config.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <unordered_set>

namespace lumabridge::linux_rx {
namespace {

std::string Trim(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start])) != 0) {
        ++start;
    }
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1])) != 0) {
        --end;
    }
    return s.substr(start, end - start);
}

std::string ToLowerAscii(std::string s) {
    for (char& ch : s) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return s;
}

bool ParseBoolStr(const std::string& raw, bool& outVal) {
    const std::string lower = ToLowerAscii(Trim(raw));
    if (lower == "true" || lower == "1" || lower == "yes") {
        outVal = true;
        return true;
    }
    if (lower == "false" || lower == "0" || lower == "no") {
        outVal = false;
        return true;
    }
    return false;
}

bool ParseU32Str(const std::string& raw, uint32_t& outVal) {
    const std::string t = Trim(raw);
    if (t.empty()) {
        return false;
    }
    for (char ch : t) {
        if (!std::isdigit(static_cast<unsigned char>(ch))) {
            return false;
        }
    }
    try {
        const unsigned long v = std::stoul(t);
        if (v > 0xFFFFFFFFUL) {
            return false;
        }
        outVal = static_cast<uint32_t>(v);
        return true;
    } catch (...) {
        return false;
    }
}

bool ParseU64Str(const std::string& raw, uint64_t& outVal) {
    const std::string t = Trim(raw);
    if (t.empty()) {
        return false;
    }
    for (char ch : t) {
        if (!std::isdigit(static_cast<unsigned char>(ch))) {
            return false;
        }
    }
    try {
        outVal = std::stoull(t);
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace

bool ValidateReceiverConfig(const ReceiverConfig& cfg, std::string& outError) {
    if (cfg.friendlyName.empty() || cfg.friendlyName.size() > 48 ||
        cfg.friendlyName.find('\n') != std::string::npos ||
        cfg.friendlyName.find('\r') != std::string::npos) {
        outError = "friendly_name must be 1..=48 bytes without newlines";
        return false;
    }
    if (cfg.transport != "quic-datagram" && cfg.transport != "quic-stream" && cfg.transport != "tcp-tls") {
        outError = "transport must be quic-datagram, quic-stream, or tcp-tls";
        return false;
    }
    if (cfg.bindAddr.empty() || cfg.bindAddr.size() > 63 || cfg.bindAddr.find(':') == std::string::npos) {
        outError = "bind_addr must be host:port under 64 bytes";
        return false;
    }
    if (cfg.width < 320 || cfg.width > 7680 || cfg.height < 240 || cfg.height > 4320) {
        outError = "resolution outside 320x240..=7680x4320";
        return false;
    }
    if (cfg.fps < 1 || cfg.fps > 240) {
        outError = "fps outside 1..=240";
        return false;
    }
    return true;
}

bool LoadReceiverConfigFile(const std::string& path, ReceiverConfig& inOutCfg, std::string& outError) {
    std::ifstream ifs(path);
    if (!ifs.is_open()) {
        outError = "failed opening config file";
        return false;
    }
    std::unordered_set<std::string> seen;
    std::string line;
    uint32_t lineNum = 0;
    while (std::getline(ifs, line)) {
        ++lineNum;
        const std::string trimmed = Trim(line);
        if (trimmed.empty() || trimmed[0] == '#' || trimmed[0] == ';') {
            continue;
        }
        const size_t eq = trimmed.find('=');
        if (eq == std::string::npos) {
            outError = "malformed config line without '=' at line " + std::to_string(lineNum);
            return false;
        }
        const std::string key = ToLowerAscii(Trim(trimmed.substr(0, eq)));
        const std::string val = Trim(trimmed.substr(eq + 1));
        if (!seen.insert(key).second) {
            outError = "duplicate config key: " + key;
            return false;
        }
        if (key == "friendly_name") {
            inOutCfg.friendlyName = val;
        } else if (key == "transport") {
            inOutCfg.transport = ToLowerAscii(val);
        } else if (key == "bind_addr") {
            inOutCfg.bindAddr = val;
        } else if (key == "width") {
            uint32_t v = 0;
            if (!ParseU32Str(val, v) || v > 65535U) {
                outError = "invalid width in config";
                return false;
            }
            inOutCfg.width = static_cast<uint16_t>(v);
        } else if (key == "height") {
            uint32_t v = 0;
            if (!ParseU32Str(val, v) || v > 65535U) {
                outError = "invalid height in config";
                return false;
            }
            inOutCfg.height = static_cast<uint16_t>(v);
        } else if (key == "fps") {
            uint32_t v = 0;
            if (!ParseU32Str(val, v) || v > 65535U) {
                outError = "invalid fps in config";
                return false;
            }
            inOutCfg.fps = static_cast<uint16_t>(v);
        } else if (key == "fullscreen") {
            if (!ParseBoolStr(val, inOutCfg.fullscreen)) {
                outError = "invalid fullscreen boolean";
                return false;
            }
        } else if (key == "overlay") {
            if (!ParseBoolStr(val, inOutCfg.overlay)) {
                outError = "invalid overlay boolean";
                return false;
            }
        } else if (key == "vsync") {
            if (!ParseBoolStr(val, inOutCfg.vsync)) {
                outError = "invalid vsync boolean";
                return false;
            }
        } else if (key == "allow_sw_decode_fallback") {
            if (!ParseBoolStr(val, inOutCfg.allowSwFallback)) {
                outError = "invalid allow_sw_decode_fallback boolean";
                return false;
            }
        } else if (key == "mdns") {
            if (!ParseBoolStr(val, inOutCfg.enableMdns)) {
                outError = "invalid mdns boolean";
                return false;
            }
        } else if (key == "vaapi_device") {
            inOutCfg.vaapiDevice = val;
        } else if (key == "role" || key == "bitrate_bps") {
            // Shared keys tolerated for unified key=value files
        } else {
            outError = "unknown config key: " + key;
            return false;
        }
    }
    return ValidateReceiverConfig(inOutCfg, outError);
}

bool SaveReceiverConfigFile(const std::string& path, const ReceiverConfig& cfg, std::string& outError) {
    if (!ValidateReceiverConfig(cfg, outError)) {
        return false;
    }
    const std::string tmpPath = path + ".tmp";
    {
        std::ofstream ofs(tmpPath, std::ios::out | std::ios::trunc);
        if (!ofs.is_open()) {
            outError = "failed opening temp config file for writing";
            return false;
        }
        ofs << "role=receiver\n"
            << "friendly_name=" << cfg.friendlyName << "\n"
            << "transport=" << cfg.transport << "\n"
            << "bind_addr=" << cfg.bindAddr << "\n"
            << "width=" << cfg.width << "\n"
            << "height=" << cfg.height << "\n"
            << "fps=" << cfg.fps << "\n"
            << "fullscreen=" << (cfg.fullscreen ? "true" : "false") << "\n"
            << "overlay=" << (cfg.overlay ? "true" : "false") << "\n"
            << "vsync=" << (cfg.vsync ? "true" : "false") << "\n"
            << "allow_sw_decode_fallback=" << (cfg.allowSwFallback ? "true" : "false") << "\n"
            << "mdns=" << (cfg.enableMdns ? "true" : "false") << "\n";
        if (!cfg.vaapiDevice.empty()) {
            ofs << "vaapi_device=" << cfg.vaapiDevice << "\n";
        }
        if (!ofs.good()) {
            outError = "failed writing config file";
            return false;
        }
    }
    if (std::rename(tmpPath.c_str(), path.c_str()) != 0) {
        outError = "failed finalizing config file rename";
        return false;
    }
    return true;
}

bool ParseReceiverCliArgs(int argc, char** argv, ReceiverConfig& outCfg, bool& outHelp, std::string& outError) {
    outHelp = false;
    // First pass: load --config if present so CLI flags override persisted settings.
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::string(argv[i]) == "--config") {
            outCfg.configFile = argv[i + 1];
            if (!LoadReceiverConfigFile(outCfg.configFile, outCfg, outError)) {
                return false;
            }
            break;
        }
    }

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto needVal = [&](const char* flag, std::string& dst) -> bool {
            if (i + 1 >= argc) {
                outError = std::string("missing value for ") + flag;
                return false;
            }
            dst = argv[++i];
            return true;
        };

        if (arg == "--help" || arg == "-h") {
            outHelp = true;
            return true;
        } else if (arg == "--config") {
            std::string dummy;
            if (!needVal("--config", dummy)) return false;
        } else if (arg == "--friendly-name") {
            if (!needVal("--friendly-name", outCfg.friendlyName)) return false;
        } else if (arg == "--transport") {
            if (!needVal("--transport", outCfg.transport)) return false;
        } else if (arg == "--bind") {
            if (!needVal("--bind", outCfg.bindAddr)) return false;
        } else if (arg == "--width") {
            std::string v;
            uint32_t num = 0;
            if (!needVal("--width", v) || !ParseU32Str(v, num) || num > 65535U) {
                outError = "invalid --width";
                return false;
            }
            outCfg.width = static_cast<uint16_t>(num);
        } else if (arg == "--height") {
            std::string v;
            uint32_t num = 0;
            if (!needVal("--height", v) || !ParseU32Str(v, num) || num > 65535U) {
                outError = "invalid --height";
                return false;
            }
            outCfg.height = static_cast<uint16_t>(num);
        } else if (arg == "--fps") {
            std::string v;
            uint32_t num = 0;
            if (!needVal("--fps", v) || !ParseU32Str(v, num) || num > 65535U) {
                outError = "invalid --fps";
                return false;
            }
            outCfg.fps = static_cast<uint16_t>(num);
        } else if (arg == "--fullscreen") {
            outCfg.fullscreen = true;
        } else if (arg == "--windowed") {
            outCfg.fullscreen = false;
        } else if (arg == "--overlay") {
            outCfg.overlay = true;
        } else if (arg == "--vsync") {
            outCfg.vsync = true;
        } else if (arg == "--no-vsync") {
            outCfg.vsync = false;
        } else if (arg == "--allow-sw-fallback") {
            outCfg.allowSwFallback = true;
        } else if (arg == "--headless") {
            outCfg.headless = true;
        } else if (arg == "--mdns") {
            outCfg.enableMdns = true;
        } else if (arg == "--max-frames") {
            std::string v;
            if (!needVal("--max-frames", v) || !ParseU64Str(v, outCfg.maxFrames)) {
                outError = "invalid --max-frames";
                return false;
            }
        } else if (arg == "--vaapi-device") {
            if (!needVal("--vaapi-device", outCfg.vaapiDevice)) return false;
        } else if (arg == "--endpoint-out") {
            if (!needVal("--endpoint-out", outCfg.endpointOut)) return false;
        } else if (arg == "--json-report") {
            if (!needVal("--json-report", outCfg.jsonReport)) return false;
        } else {
            outError = "unknown argument: " + arg;
            return false;
        }
    }
    return ValidateReceiverConfig(outCfg, outError);
}

void PrintReceiverUsage() {
    std::printf(
        "lumabridge-linux-receiver - M2 Native Linux Receiver (VA-API + Wayland/X11 + LBWP v1)\n"
        "Options:\n"
        "  --bind <ip:port>           Listen IP:port (default: 0.0.0.0:0)\n"
        "  --transport <mode>         quic-datagram | quic-stream | tcp-tls\n"
        "  --friendly-name <name>     Endpoint display name (1..=48 bytes)\n"
        "  --width <px> --height <px> --fps <n>  Expected display mode\n"
        "  --fullscreen | --windowed  Borderless fullscreen (default) or windowed\n"
        "  --overlay                  Show BRIDGE_TERMINAL telemetry HUD (F12 toggles)\n"
        "  --vsync | --no-vsync       Toggle presentation vsync\n"
        "  --allow-sw-fallback        Allow software H.264 decode strictly for diagnostics\n"
        "  --headless                 Disable GUI window creation (CI / automated testing)\n"
        "  --mdns                     Enable LAN _lumabridge._udp.local advertisement\n"
        "  --vaapi-device <path>      Optional DRM render node (e.g. /dev/dri/renderD128)\n"
        "  --max-frames <n>           Exit cleanly after N delivered frames (0 = unlimited)\n"
        "  --config <path>            Load persistent key=value configuration\n"
        "  --endpoint-out <path>      Atomically write pair|op|device_id|pin rendezvous line\n"
        "  --json-report <path>       Write privacy-sanitized JSON telemetry summary\n");
}

} // namespace lumabridge::linux_rx
