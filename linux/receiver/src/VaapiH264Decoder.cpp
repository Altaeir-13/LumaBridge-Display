// SPDX-License-Identifier: Apache-2.0
#include "VaapiH264Decoder.h"

extern "C" {
#include <libavcodec/avcodec.h>
#include <libavutil/hwcontext.h>
#include <libavutil/imgutils.h>
#include <libavutil/pixfmt.h>
#include <libswscale/swscale.h>
}

#include <climits>
#include <cstring>

namespace lumabridge::linux_rx {
namespace {

enum AVPixelFormat GetVaapiHwFormat(AVCodecContext* ctx, const enum AVPixelFormat* pixFmts) {
    for (const enum AVPixelFormat* p = pixFmts; *p != AV_PIX_FMT_NONE; ++p) {
        if (*p == AV_PIX_FMT_VAAPI) {
            return *p;
        }
    }
    const bool allowSw = (ctx != nullptr && ctx->opaque != nullptr)
        ? *static_cast<const bool*>(ctx->opaque)
        : false;
    return allowSw ? pixFmts[0] : AV_PIX_FMT_NONE;
}

std::string FfmpegErrStr(int errnum) {
    char buf[AV_ERROR_MAX_STRING_SIZE]{};
    av_strerror(errnum, buf, sizeof(buf));
    return std::string(buf);
}

} // namespace

struct VaapiH264Decoder::Impl {
    const AVCodec* codec{nullptr};
    AVCodecContext* codecCtx{nullptr};
    AVBufferRef* hwDeviceCtx{nullptr};
    AVPacket* packet{nullptr};
    AVFrame* hwFrame{nullptr};
    AVFrame* swFrame{nullptr};
    SwsContext* swsCtx{nullptr};
    int swsWidth{0};
    int swsHeight{0};
    AVPixelFormat swsSrcFmt{AV_PIX_FMT_NONE};
    bool allowSwFallback{false};
};

VaapiH264Decoder::~VaapiH264Decoder() noexcept {
    Shutdown();
}

bool VaapiH264Decoder::Initialize(
    bool allowSwFallback,
    const std::string& vaapiDevicePath,
    std::string& outError)
{
    Shutdown();
    auto* impl = new Impl();
    impl->allowSwFallback = allowSwFallback;
    impl->codec = avcodec_find_decoder(AV_CODEC_ID_H264);
    if (impl->codec == nullptr) {
        delete impl;
        outError = "FFmpeg libavcodec missing H.264 decoder";
        return false;
    }

    const char* devPath = vaapiDevicePath.empty() ? nullptr : vaapiDevicePath.c_str();
    bool vaapiReady = false;
    const int hwErr = av_hwdevice_ctx_create(
        &impl->hwDeviceCtx,
        AV_HWDEVICE_TYPE_VAAPI,
        devPath,
        nullptr,
        0);
    if (hwErr == 0 && impl->hwDeviceCtx != nullptr) {
        impl->codecCtx = avcodec_alloc_context3(impl->codec);
        if (impl->codecCtx != nullptr) {
            impl->codecCtx->flags |= AV_CODEC_FLAG_LOW_DELAY;
            impl->codecCtx->flags2 |= AV_CODEC_FLAG2_FAST;
            impl->codecCtx->hw_device_ctx = av_buffer_ref(impl->hwDeviceCtx);
            impl->codecCtx->opaque = &impl->allowSwFallback;
            impl->codecCtx->get_format = &GetVaapiHwFormat;
            if (avcodec_open2(impl->codecCtx, impl->codec, nullptr) >= 0) {
                vaapiReady = true;
            } else {
                avcodec_free_context(&impl->codecCtx);
            }
        }
    }

    if (!vaapiReady) {
        if (impl->hwDeviceCtx != nullptr) {
            av_buffer_unref(&impl->hwDeviceCtx);
        }
        if (!allowSwFallback) {
            delete impl;
            outError = "VA-API hardware decode initialization failed (" +
                       FfmpegErrStr(hwErr) +
                       "); install Intel/AMD VA-API drivers (vainfo) or pass --allow-sw-fallback for diagnostics";
            return false;
        }
        impl->codecCtx = avcodec_alloc_context3(impl->codec);
        if (impl->codecCtx == nullptr) {
            delete impl;
            outError = "failed allocating H.264 AVCodecContext";
            return false;
        }
        impl->codecCtx->flags |= AV_CODEC_FLAG_LOW_DELAY;
        impl->codecCtx->thread_count = 2;
        const int openErr = avcodec_open2(impl->codecCtx, impl->codec, nullptr);
        if (openErr < 0) {
            avcodec_free_context(&impl->codecCtx);
            delete impl;
            outError = "avcodec_open2 SW diagnostic failed: " + FfmpegErrStr(openErr);
            return false;
        }
    }

    impl->packet = av_packet_alloc();
    impl->hwFrame = av_frame_alloc();
    impl->swFrame = av_frame_alloc();
    if (impl->packet == nullptr || impl->hwFrame == nullptr || impl->swFrame == nullptr) {
        m_impl = impl;
        Shutdown();
        outError = "failed allocating FFmpeg packet/frame objects";
        return false;
    }

    m_impl = impl;
    m_stats = DecoderStats{};
    m_stats.vaapiActive = vaapiReady;
    m_stats.backendName = vaapiReady ? "vaapi" : "software_diagnostic";
    return true;
}

bool VaapiH264Decoder::DecodePacket(
    const uint8_t* annexBData,
    size_t sizeBytes,
    std::vector<DecodedRgbaFrame>& outFrames,
    std::string& outError)
{
    outFrames.clear();
    if (m_impl == nullptr || m_impl->codecCtx == nullptr || annexBData == nullptr ||
        sizeBytes == 0U || sizeBytes > static_cast<size_t>(INT_MAX)) {
        outError = "decoder uninitialized or invalid Annex-B payload size";
        return false;
    }

    av_packet_unref(m_impl->packet);
    if (av_new_packet(m_impl->packet, static_cast<int>(sizeBytes)) < 0) {
        ++m_stats.decodeErrors;
        outError = "av_new_packet failed";
        return false;
    }
    std::memcpy(m_impl->packet->data, annexBData, sizeBytes);

    const int sendRet = avcodec_send_packet(m_impl->codecCtx, m_impl->packet);
    av_packet_unref(m_impl->packet);
    if (sendRet < 0 && sendRet != AVERROR(EAGAIN)) {
        ++m_stats.decodeErrors;
        outError = "avcodec_send_packet failed: " + FfmpegErrStr(sendRet);
        return false;
    }

    while (true) {
        av_frame_unref(m_impl->hwFrame);
        av_frame_unref(m_impl->swFrame);
        const int recvRet = avcodec_receive_frame(m_impl->codecCtx, m_impl->hwFrame);
        if (recvRet == AVERROR(EAGAIN) || recvRet == AVERROR_EOF) {
            break;
        }
        if (recvRet < 0) {
            ++m_stats.decodeErrors;
            outError = "avcodec_receive_frame failed: " + FfmpegErrStr(recvRet);
            return false;
        }

        AVFrame* srcFrame = m_impl->hwFrame;
        if (m_impl->hwFrame->format == AV_PIX_FMT_VAAPI) {
            if (av_hwframe_transfer_data(m_impl->swFrame, m_impl->hwFrame, 0) < 0) {
                ++m_stats.decodeErrors;
                outError = "av_hwframe_transfer_data failed";
                return false;
            }
            srcFrame = m_impl->swFrame;
        }

        const int w = srcFrame->width;
        const int h = srcFrame->height;
        const auto srcFmt = static_cast<AVPixelFormat>(srcFrame->format);
        if (w <= 0 || h <= 0) {
            continue;
        }

        if (m_impl->swsCtx == nullptr ||
            m_impl->swsWidth != w ||
            m_impl->swsHeight != h ||
            m_impl->swsSrcFmt != srcFmt) {
            if (m_impl->swsCtx != nullptr) {
                sws_freeContext(m_impl->swsCtx);
            }
            m_impl->swsCtx = sws_getContext(
                w,
                h,
                srcFmt,
                w,
                h,
                AV_PIX_FMT_BGRA,
                SWS_FAST_BILINEAR,
                nullptr,
                nullptr,
                nullptr);
            m_impl->swsWidth = w;
            m_impl->swsHeight = h;
            m_impl->swsSrcFmt = srcFmt;
            if (m_impl->swsCtx == nullptr) {
                ++m_stats.decodeErrors;
                outError = "sws_getContext BGRA conversion failed";
                return false;
            }
        }

        DecodedRgbaFrame out{};
        out.width = static_cast<uint32_t>(w);
        out.height = static_cast<uint32_t>(h);
        out.pitchBytes = static_cast<uint32_t>(w) * 4U;
        out.bgraPixels.resize(static_cast<size_t>(out.pitchBytes) * static_cast<size_t>(h));

        uint8_t* dstSlice[4] = {out.bgraPixels.data(), nullptr, nullptr, nullptr};
        int dstStride[4] = {static_cast<int>(out.pitchBytes), 0, 0, 0};
        if (sws_scale(m_impl->swsCtx, srcFrame->data, srcFrame->linesize, 0, h, dstSlice, dstStride) <= 0) {
            ++m_stats.decodeErrors;
            outError = "sws_scale BGRA conversion produced 0 rows";
            return false;
        }

        outFrames.push_back(std::move(out));
        ++m_stats.framesDecoded;
    }
    return true;
}

void VaapiH264Decoder::Shutdown() noexcept {
    if (m_impl == nullptr) {
        return;
    }
    if (m_impl->swsCtx != nullptr) {
        sws_freeContext(m_impl->swsCtx);
    }
    if (m_impl->packet != nullptr) {
        av_packet_free(&m_impl->packet);
    }
    if (m_impl->hwFrame != nullptr) {
        av_frame_free(&m_impl->hwFrame);
    }
    if (m_impl->swFrame != nullptr) {
        av_frame_free(&m_impl->swFrame);
    }
    if (m_impl->codecCtx != nullptr) {
        avcodec_free_context(&m_impl->codecCtx);
    }
    if (m_impl->hwDeviceCtx != nullptr) {
        av_buffer_unref(&m_impl->hwDeviceCtx);
    }
    delete m_impl;
    m_impl = nullptr;
}

} // namespace lumabridge::linux_rx
