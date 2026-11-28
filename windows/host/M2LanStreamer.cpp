// SPDX-License-Identifier: Apache-2.0
#include "M2LanStreamer.h"

#ifdef LUMABRIDGE_ENABLE_FFI_POC

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include <wrl/client.h>

#include "H264BitstreamValidator.h"
#include "HostVideoPipeline.h"
#include "lumabridge_ffi.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

namespace lumabridge::host {
namespace {

template <typename T>
LbAbiHeader MakeAbiHeader() noexcept {
    LbAbiHeader hdr{};
    hdr.abi_major = LB_FFI_ABI_MAJOR;
    hdr.abi_minor = LB_FFI_ABI_MINOR;
    hdr.struct_size = static_cast<uint32_t>(sizeof(T));
    hdr.reserved = 0U;
    return hdr;
}

uint32_t MapTransportString(const std::string& transport) noexcept {
    if (transport == "quic-stream") {
        return static_cast<uint32_t>(LB_NODE_TRANSPORT_KIND_QUIC_STREAM);
    }
    if (transport == "tcp-tls") {
        return static_cast<uint32_t>(LB_NODE_TRANSPORT_KIND_TCP_TLS);
    }
    return static_cast<uint32_t>(LB_NODE_TRANSPORT_KIND_QUIC_DATAGRAM);
}

uint64_t QueryQpcNow() noexcept {
    LARGE_INTEGER li{};
    (void)QueryPerformanceCounter(&li);
    return (li.QuadPart > 0) ? static_cast<uint64_t>(li.QuadPart) : 0ULL;
}

uint64_t QueryQpcFreqSafe() noexcept {
    LARGE_INTEGER li{};
    (void)QueryPerformanceFrequency(&li);
    return (li.QuadPart > 0) ? static_cast<uint64_t>(li.QuadPart) : 10000000ULL;
}

} // namespace

struct M2LanStreamer::Impl {
    LbNodeHandle* node{nullptr};
    LbHostSessionHandle* session{nullptr};
    uint32_t nextFrameId{1U};
    uint16_t gopId{1U};
    uint32_t lastAppliedBitrateBps{15000000U};
    std::chrono::steady_clock::time_point lastReconfAt{};
};

M2LanStreamer::~M2LanStreamer() noexcept {
    Stop();
}

bool M2LanStreamer::Start(const M2LanStreamConfig& cfg) noexcept {
    Stop();
    if (cfg.pairAddr.empty() || cfg.opAddr.empty() || cfg.pin.empty() ||
        cfg.pairAddr.size() > 64 || cfg.opAddr.size() > 64 || cfg.pin.size() > 16 ||
        cfg.friendlyName.empty() || cfg.friendlyName.size() > 48 ||
        (!cfg.peerDeviceIdHex.empty() && cfg.peerDeviceIdHex.size() != 64)) {
        std::fprintf(stderr, "[M2-LAN] Invalid host LAN configuration.\n");
        return false;
    }

    auto* impl = new (std::nothrow) Impl();
    if (impl == nullptr) {
        return false;
    }

    LbNodeConfig nodeCfg{};
    nodeCfg.abi = MakeAbiHeader<LbNodeConfig>();
    nodeCfg.role = static_cast<uint32_t>(LB_NODE_ROLE_HOST);
    nodeCfg.transport_kind = MapTransportString(cfg.transport);
    nodeCfg.max_virtual_displays = 1U;
    nodeCfg.heartbeat_timeout_ms = 8000U;
    std::memcpy(nodeCfg.friendly_name, cfg.friendlyName.data(), cfg.friendlyName.size());
    nodeCfg.friendly_name_len = static_cast<uint32_t>(cfg.friendlyName.size());

    if (lb_node_create(&nodeCfg, &impl->node) != LB_STATUS_OK || impl->node == nullptr) {
        delete impl;
        std::fprintf(stderr, "[M2-LAN] lb_node_create failed.\n");
        return false;
    }

    LbHostConnectConfig connCfg{};
    connCfg.abi = MakeAbiHeader<LbHostConnectConfig>();
    connCfg.transport_kind = nodeCfg.transport_kind;
    std::memcpy(connCfg.pair_addr_utf8, cfg.pairAddr.data(), cfg.pairAddr.size());
    connCfg.pair_addr_len = static_cast<uint32_t>(cfg.pairAddr.size());
    std::memcpy(connCfg.op_addr_utf8, cfg.opAddr.data(), cfg.opAddr.size());
    connCfg.op_addr_len = static_cast<uint32_t>(cfg.opAddr.size());
    std::memcpy(connCfg.pin_ascii, cfg.pin.data(), cfg.pin.size());
    connCfg.pin_len = static_cast<uint32_t>(cfg.pin.size());
    if (!cfg.peerDeviceIdHex.empty()) {
        std::memcpy(connCfg.peer_device_id_hex, cfg.peerDeviceIdHex.data(), cfg.peerDeviceIdHex.size());
        connCfg.peer_device_id_len = static_cast<uint32_t>(cfg.peerDeviceIdHex.size());
    }
    connCfg.width = cfg.width;
    connCfg.height = cfg.height;
    connCfg.fps_num = cfg.fps;
    connCfg.fps_den = 1U;
    connCfg.initial_bitrate_bps = cfg.initialBitrateBps;
    connCfg.timeout_ms = 10000U;

    const LbStatus connectSt = lb_node_host_connect(impl->node, &connCfg, &impl->session);
    SecureZeroMemory(connCfg.pin_ascii, sizeof(connCfg.pin_ascii));
    connCfg.pin_len = 0U;
    if (connectSt != LB_STATUS_OK || impl->session == nullptr) {
        (void)lb_node_destroy(impl->node);
        delete impl;
        std::fprintf(stderr, "[M2-LAN] lb_node_host_connect failed (pairing/mTLS handshake error).\n");
        return false;
    }

    impl->lastAppliedBitrateBps = cfg.initialBitrateBps;
    impl->lastReconfAt = std::chrono::steady_clock::now();
    m_impl = impl;
    return true;
}

bool M2LanStreamer::SubmitEncodedPacket(
    const EncodedFramePacket& pkt,
    uint64_t qpcFreq,
    uint64_t startQpc,
    bool* outForceIdr,
    uint32_t* outNewBitrateBps,
    bool* outSessionClosed) noexcept
{
    if (outForceIdr != nullptr) *outForceIdr = false;
    if (outNewBitrateBps != nullptr) *outNewBitrateBps = 0U;
    if (outSessionClosed != nullptr) *outSessionClosed = false;

    if (m_impl == nullptr || m_impl->session == nullptr || pkt.Bitstream.empty()) {
        return false;
    }

    if (pkt.IsKeyFrame && m_impl->nextFrameId > 1U) {
        m_impl->gopId = static_cast<uint16_t>(
            (m_impl->gopId >= 0xFFFFU) ? 1U : (static_cast<uint32_t>(m_impl->gopId) + 1U));
    }

    const uint64_t safeFreq = (qpcFreq > 0ULL) ? qpcFreq : 10000000ULL;
    const uint64_t relTicks = (pkt.BitstreamReadyQpcTime >= startQpc) ? (pkt.BitstreamReadyQpcTime - startQpc) : 0ULL;
    const uint64_t doneUs = (relTicks * 1000000ULL) / safeFreq;
    const uint64_t encUs = pkt.EncodeLatencyUs;
    const uint64_t capUs = (doneUs >= encUs) ? (doneUs - encUs) : 0ULL;

    LbEncodedFrameMeta meta{};
    meta.abi = MakeAbiHeader<LbEncodedFrameMeta>();
    meta.session_id = 1ULL;
    meta.capture_ts_us = capUs;
    meta.encode_done_ts_us = (doneUs >= capUs) ? doneUs : capUs;
    meta.submit_qpc_ticks = pkt.BitstreamReadyQpcTime;
    meta.codec = static_cast<uint32_t>(LB_ENCODED_CODEC_H264_ANNEX_B);
    meta.flags = pkt.IsKeyFrame ? 1U : 0U;
    meta.frame_id = m_impl->nextFrameId++;
    meta.display_id = 0U;
    meta.gop_id = m_impl->gopId;

    const LbStatus st = lb_node_host_submit_h264(
        m_impl->session,
        &meta,
        pkt.Bitstream.data(),
        pkt.Bitstream.size());
    if (st != LB_STATUS_OK) {
        if (outSessionClosed != nullptr &&
            (st == LB_STATUS_INVALID_STATE || st == LB_STATUS_FAULTED)) {
            *outSessionClosed = true;
        }
        return false;
    }

    LbNodeTelemetry tel{};
    tel.abi = MakeAbiHeader<LbNodeTelemetry>();
    LbHostFeedback fb{};
    fb.abi = MakeAbiHeader<LbHostFeedback>();
    if (lb_node_host_get_telemetry(m_impl->session, &tel, &fb) == LB_STATUS_OK) {
        if (outForceIdr != nullptr && fb.force_idr_requested != 0U) {
            *outForceIdr = true;
        }
        if (outSessionClosed != nullptr && fb.session_closed != 0U) {
            *outSessionClosed = true;
        }
        if (outNewBitrateBps != nullptr && fb.recommended_bitrate_bps >= 1000000U) {
            const uint32_t cur = m_impl->lastAppliedBitrateBps;
            const uint32_t diff = (fb.recommended_bitrate_bps > cur)
                ? (fb.recommended_bitrate_bps - cur)
                : (cur - fb.recommended_bitrate_bps);
            const auto elapsed = std::chrono::steady_clock::now() - m_impl->lastReconfAt;
            if ((diff * 10U) >= cur && elapsed >= std::chrono::milliseconds(500)) {
                m_impl->lastAppliedBitrateBps = fb.recommended_bitrate_bps;
                m_impl->lastReconfAt = std::chrono::steady_clock::now();
                *outNewBitrateBps = fb.recommended_bitrate_bps;
            }
        }
    }
    return true;
}

bool M2LanStreamer::SendProtectedBlank(uint64_t tsUs) noexcept {
    if (m_impl == nullptr || m_impl->session == nullptr) {
        return false;
    }
    return lb_node_host_send_protected_blank(
               m_impl->session,
               0U,
               m_impl->nextFrameId++,
               m_impl->gopId,
               tsUs) == LB_STATUS_OK;
}

void M2LanStreamer::Stop() noexcept {
    if (m_impl == nullptr) {
        return;
    }
    if (m_impl->session != nullptr) {
        (void)lb_node_host_close(m_impl->session);
        m_impl->session = nullptr;
    }
    if (m_impl->node != nullptr) {
        (void)lb_node_destroy(m_impl->node);
        m_impl->node = nullptr;
    }
    delete m_impl;
    m_impl = nullptr;
}

bool M2LanStreamer::IsRunning() const noexcept {
    return m_impl != nullptr && m_impl->session != nullptr;
}

int RunM2NvencLoopbackSelfTest() noexcept {
    LbGlobalResourceCounters before{};
    before.abi = MakeAbiHeader<LbGlobalResourceCounters>();
    if (lb_core_get_global_resource_counters(&before) != LB_STATUS_OK) {
        std::fprintf(stderr, "[M2-NVENC-SELFTEST] Failed reading initial FFI counters.\n");
        return EXIT_FAILURE;
    }

    Microsoft::WRL::ComPtr<ID3D11Device> d3dDevice;
    Microsoft::WRL::ComPtr<ID3D11DeviceContext> d3dContext;
    const D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0};
    D3D_FEATURE_LEVEL actualLevel{};
    HRESULT hr = D3D11CreateDevice(
        nullptr,
        D3D_DRIVER_TYPE_HARDWARE,
        nullptr,
        D3D11_CREATE_DEVICE_BGRA_SUPPORT,
        levels,
        ARRAYSIZE(levels),
        D3D11_SDK_VERSION,
        &d3dDevice,
        &actualLevel,
        &d3dContext);
    if (FAILED(hr) || d3dDevice == nullptr || d3dContext == nullptr) {
        std::fprintf(stderr, "[M2-NVENC-SELFTEST] BLOCKED_BY_ENVIRONMENT: D3D11 hardware device unavailable (hr=0x%08lX).\n",
                     static_cast<unsigned long>(hr));
        return 2;
    }

    constexpr uint32_t kWidth = 1920U;
    constexpr uint32_t kHeight = 1080U;
    constexpr uint32_t kFps = 60U;
    constexpr uint32_t kTotalFrames = 60U;

    NvencH264Encoder encoder;
    NvencEncoderConfig encCfg{};
    encCfg.Width = kWidth;
    encCfg.Height = kHeight;
    encCfg.TargetFps = kFps;
    encCfg.BitrateBps = 12000000U;
    encCfg.MaxBitrateBps = 16000000U;
    encCfg.GopLength = 60U;
    encCfg.LowLatencyTuning = true;
    encCfg.RepeatSpsPpsEveryIdr = true;

    hr = encoder.Initialize(d3dDevice.Get(), d3dContext.Get(), encCfg);
    if (FAILED(hr)) {
        std::fprintf(stderr, "[M2-NVENC-SELFTEST] BLOCKED_BY_ENVIRONMENT: NVENC Initialize failed (hr=0x%08lX).\n",
                     static_cast<unsigned long>(hr));
        return 2;
    }
    NvencVideoEncoderAdapter encAdapter(encoder);

    D3D11_TEXTURE2D_DESC texDesc{};
    texDesc.Width = kWidth;
    texDesc.Height = kHeight;
    texDesc.MipLevels = 1U;
    texDesc.ArraySize = 1U;
    texDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    texDesc.SampleDesc.Count = 1U;
    texDesc.Usage = D3D11_USAGE_DEFAULT;
    texDesc.BindFlags = D3D11_BIND_RENDER_TARGET | D3D11_BIND_SHADER_RESOURCE;

    Microsoft::WRL::ComPtr<ID3D11Texture2D> gpuTex;
    hr = d3dDevice->CreateTexture2D(&texDesc, nullptr, &gpuTex);
    Microsoft::WRL::ComPtr<ID3D11RenderTargetView> rtv;
    if (SUCCEEDED(hr) && gpuTex != nullptr) {
        hr = d3dDevice->CreateRenderTargetView(gpuTex.Get(), nullptr, &rtv);
    }
    if (FAILED(hr) || gpuTex == nullptr || rtv == nullptr) {
        encoder.Shutdown();
        std::fprintf(stderr, "[M2-NVENC-SELFTEST] Failed creating D3D11 GPU render target texture.\n");
        return EXIT_FAILURE;
    }

    // Start local Receiver over real QUIC/TLS 1.3.
    LbNodeConfig rxNodeCfg{};
    rxNodeCfg.abi = MakeAbiHeader<LbNodeConfig>();
    rxNodeCfg.role = static_cast<uint32_t>(LB_NODE_ROLE_CONTROLLER);
    rxNodeCfg.transport_kind = static_cast<uint32_t>(LB_NODE_TRANSPORT_KIND_QUIC_DATAGRAM);
    rxNodeCfg.max_virtual_displays = 1U;
    rxNodeCfg.heartbeat_timeout_ms = 8000U;
    const char* rxName = "M2SelftestRx";
    std::memcpy(rxNodeCfg.friendly_name, rxName, std::strlen(rxName));
    rxNodeCfg.friendly_name_len = static_cast<uint32_t>(std::strlen(rxName));

    LbNodeHandle* rxNode = nullptr;
    if (lb_node_create(&rxNodeCfg, &rxNode) != LB_STATUS_OK || rxNode == nullptr) {
        encoder.Shutdown();
        return EXIT_FAILURE;
    }

    LbReceiverStartConfig rxStart{};
    rxStart.abi = MakeAbiHeader<LbReceiverStartConfig>();
    rxStart.transport_kind = rxNodeCfg.transport_kind;
    const char* bindIp = "127.0.0.1:0";
    std::memcpy(rxStart.bind_addr_utf8, bindIp, std::strlen(bindIp));
    rxStart.bind_addr_len = static_cast<uint32_t>(std::strlen(bindIp));
    rxStart.width = static_cast<uint16_t>(kWidth);
    rxStart.height = static_cast<uint16_t>(kHeight);
    rxStart.fps_num = static_cast<uint16_t>(kFps);
    rxStart.fps_den = 1U;
    rxStart.enable_mdns = 0U;

    LbReceiverSessionHandle* rxSess = nullptr;
    if (lb_node_receiver_start(rxNode, &rxStart, &rxSess) != LB_STATUS_OK || rxSess == nullptr) {
        (void)lb_node_destroy(rxNode);
        encoder.Shutdown();
        return EXIT_FAILURE;
    }

    LbReceiverEndpoints ep{};
    ep.abi = MakeAbiHeader<LbReceiverEndpoints>();
    if (lb_node_receiver_get_endpoints(rxSess, &ep) != LB_STATUS_OK) {
        (void)lb_node_receiver_stop(rxSess);
        (void)lb_node_destroy(rxNode);
        encoder.Shutdown();
        return EXIT_FAILURE;
    }

    M2LanStreamConfig streamCfg{};
    streamCfg.friendlyName = "M2SelftestHost";
    streamCfg.transport = "quic-datagram";
    streamCfg.pairAddr = reinterpret_cast<const char*>(ep.pair_addr_utf8);
    streamCfg.opAddr = reinterpret_cast<const char*>(ep.op_addr_utf8);
    streamCfg.pin = reinterpret_cast<const char*>(ep.pin_ascii);
    streamCfg.peerDeviceIdHex = reinterpret_cast<const char*>(ep.device_id_hex);
    streamCfg.width = static_cast<uint16_t>(kWidth);
    streamCfg.height = static_cast<uint16_t>(kHeight);
    streamCfg.fps = static_cast<uint16_t>(kFps);
    streamCfg.initialBitrateBps = encCfg.BitrateBps;

    M2LanStreamer streamer;
    if (!streamer.Start(streamCfg)) {
        (void)lb_node_receiver_stop(rxSess);
        (void)lb_node_destroy(rxNode);
        encoder.Shutdown();
        return EXIT_FAILURE;
    }

    H264StreamValidationSession decoderValidator;
    decoderValidator.Configure(true, kFps, false, 25.0);
    (void)decoderValidator.PrewarmDecoder(kWidth, kHeight, kFps);

    const uint64_t qpcFreq = QueryQpcFreqSafe();
    const uint64_t startQpc = QueryQpcNow();
    bool bitrateReconfOk = false;
    bool gotBlank = false;
    uint32_t rxFrames = 0U;

    std::thread rxThread([&]() {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(8);
        while (std::chrono::steady_clock::now() < deadline && !gotBlank) {
            LbReceiverMediaEvent evt{};
            evt.abi = MakeAbiHeader<LbReceiverMediaEvent>();
            if (lb_node_receiver_poll_event(rxSess, 50U, &evt) != LB_STATUS_OK) {
                break;
            }
            if (evt.kind == static_cast<uint32_t>(LB_RECEIVER_EVENT_KIND_VIDEO_FRAME)) {
                EncodedFramePacket decPkt{};
                decPkt.FrameSequence = evt.frame_id;
                decPkt.PresentationFrameNumber = evt.frame_id;
                decPkt.Width = kWidth;
                decPkt.Height = kHeight;
                decPkt.IsKeyFrame = (evt.video_flags & 0x01U) != 0U;
                decPkt.Bitstream.assign(evt.payload.data, evt.payload.data + evt.payload.len);
                (void)lb_core_release_buffer(&evt.payload);

                const uint64_t t0 = QueryQpcNow();
                decoderValidator.SubmitPacket(decPkt);
                const uint64_t t1 = QueryQpcNow();
                const uint64_t decUs = (t1 >= t0) ? ((t1 - t0) * 1000000ULL) / qpcFreq : 0ULL;
                // No physical swapchain presentation in headless loopback selftest -> report present_us=0 (Unavailable).
                (void)lb_node_receiver_record_timing(rxSess, decUs, 0ULL);
                ++rxFrames;
            } else if (evt.kind == static_cast<uint32_t>(LB_RECEIVER_EVENT_KIND_PROTECTED_BLANK)) {
                gotBlank = true;
            } else if (evt.kind == static_cast<uint32_t>(LB_RECEIVER_EVENT_KIND_SESSION_CLOSED)) {
                break;
            }
        }
    });

    for (uint32_t idx = 0U; idx < kTotalFrames; ++idx) {
        const float t = static_cast<float>(idx) / static_cast<float>(kTotalFrames);
        const FLOAT clearColor[4] = {0.1f + 0.7f * t, 0.25f, 0.9f - 0.6f * t, 1.0f};
        d3dContext->ClearRenderTargetView(rtv.Get(), clearColor);

        if (idx == 20U) {
            bitrateReconfOk = SUCCEEDED(encAdapter.SetTargetBitrateBps(8000000U));
        }
        if (idx == 40U) {
            encAdapter.RequestForceIdr();
        }

        const uint64_t qNow = QueryQpcNow();
        if (FAILED(encAdapter.EncodeGpuTexture(gpuTex.Get(), idx + 1ULL, idx + 1U, qNow, qNow, qpcFreq))) {
            std::fprintf(stderr, "[M2-NVENC-SELFTEST] NVENC encode failed at frame %u.\n", idx + 1U);
            break;
        }
        EncodedFramePacket pkt{};
        while (encAdapter.TryPopEncodedFrame(pkt)) {
            (void)streamer.SubmitEncodedPacket(pkt, qpcFreq, startQpc, nullptr, nullptr, nullptr);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(4));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    const uint64_t blankUs = ((QueryQpcNow() - startQpc) * 1000000ULL) / qpcFreq;
    const bool sentBlank = streamer.SendProtectedBlank(blankUs);
    rxThread.join();

    decoderValidator.Finish();
    const H264ValidationSummary decSummary = decoderValidator.GetSummary();
    const NvencMetricsSnapshot encSnap = encoder.GetMetricsSnapshot();

    char rxJson[4096]{};
    size_t rxJsonLen = 0U;
    const LbStatus exportSt = lb_node_receiver_export_telemetry_json(
        rxSess,
        reinterpret_cast<uint8_t*>(rxJson),
        sizeof(rxJson) - 1U,
        &rxJsonLen);

    streamer.Stop();
    (void)lb_node_receiver_stop(rxSess);
    (void)lb_node_destroy(rxNode);
    decoderValidator.Shutdown();
    encoder.Shutdown();

    LbGlobalResourceCounters after{};
    after.abi = MakeAbiHeader<LbGlobalResourceCounters>();
    (void)lb_core_get_global_resource_counters(&after);

    const bool ok = bitrateReconfOk &&
                    sentBlank &&
                    gotBlank &&
                    encSnap.NvencFramesEncoded >= 58ULL &&
                    rxFrames >= 50U &&
                    decSummary.Passed &&
                    decSummary.IdrCount >= 2ULL &&
                    decSummary.NalParseFailures == 0ULL &&
                    decSummary.DecodeFailures == 0ULL &&
                    after.active_instances == before.active_instances &&
                    after.in_flight_buffers == before.in_flight_buffers &&
                    after.rust_buffers_allocated == after.rust_buffers_released;

    std::printf(
        "[M2-NVENC-SELFTEST] %s encoded=%llu rx_delivered=%u decoded=%llu idr=%llu reconf_bps=%u blank=%u enc_avg_us=%llu enc_p95_us=%llu dec_avg_us=%llu leaked_bufs=%lld\n",
        ok ? "PASS" : "FAIL",
        static_cast<unsigned long long>(encSnap.NvencFramesEncoded),
        rxFrames,
        static_cast<unsigned long long>(decSummary.FramesDecoded),
        static_cast<unsigned long long>(decSummary.IdrCount),
        encSnap.ConfiguredBitrateBps,
        gotBlank ? 1U : 0U,
        static_cast<unsigned long long>(encSnap.EncodeLatencyUs.AvgUs),
        static_cast<unsigned long long>(encSnap.EncodeLatencyUs.P95Us),
        static_cast<unsigned long long>(decSummary.MftDecodeLatencyUs.AvgUs),
        static_cast<long long>(after.rust_buffers_allocated - after.rust_buffers_released));
    if (exportSt == LB_STATUS_OK && rxJsonLen > 0U && rxJsonLen < sizeof(rxJson)) {
        rxJson[rxJsonLen] = '\0';
        std::printf("[M2-NVENC-SELFTEST] RX_JSON=%s\n", rxJson);
    }
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}

} // namespace lumabridge::host

#endif
