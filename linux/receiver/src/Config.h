// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <string>

namespace lumabridge::linux_rx {

struct ReceiverConfig {
    std::string friendlyName{"LumaBridge-Linux-Rx"};
    std::string transport{"quic-datagram"};
    std::string bindAddr{"0.0.0.0:0"};
    uint16_t width{1920U};
    uint16_t height{1080U};
    uint16_t fps{60U};
    bool fullscreen{true};
    bool overlay{false};
    bool vsync{true};
    bool allowSwFallback{false};
    bool headless{false};
    bool enableMdns{false};
    bool ciAutoApprovePairing{false};
    uint64_t maxFrames{0ULL};
    std::string vaapiDevice{};
    std::string endpointOut{};
    std::string jsonReport{};
    std::string configFile{};
};

bool ValidateReceiverConfig(const ReceiverConfig& cfg, std::string& outError);
bool LoadReceiverConfigFile(const std::string& path, ReceiverConfig& inOutCfg, std::string& outError);
bool SaveReceiverConfigFile(const std::string& path, const ReceiverConfig& cfg, std::string& outError);
bool ParseReceiverCliArgs(int argc, char** argv, ReceiverConfig& outCfg, bool& outHelp, std::string& outError);
void PrintReceiverUsage();

} // namespace lumabridge::linux_rx
