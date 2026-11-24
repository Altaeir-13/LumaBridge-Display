// SPDX-License-Identifier: Apache-2.0
#include "FfiPocAdapter.h"

#ifdef LUMABRIDGE_ENABLE_FFI_POC

#include "lumabridge_ffi.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <mutex>
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
    hdr.reserved = 0;
    return hdr;
}

struct HostSelfTestCtx {
    std::mutex mu;
    std::condition_variable cv;
    std::atomic<uint64_t> rx_packets{0};
    std::atomic<uint64_t> rx_bytes{0};
    std::atomic<uint64_t> rust_buf_released{0};
    std::atomic<uint64_t> native_buf_released{0};
    std::atomic<bool> integrity_ok{true};
};

struct NativeHostBuffer {
    uint8_t* ptr;
    size_t len;
    HostSelfTestCtx* ctx;
};

void HostNativeRelease(void* user_ctx, const uint8_t* data, size_t len, size_t capacity) noexcept {
    if (user_ctx == nullptr) {
        return;
    }
    auto* nb = static_cast<NativeHostBuffer*>(user_ctx);
    if (nb->ptr != data || nb->len != len || nb->len != capacity) {
        nb->ctx->integrity_ok.store(false, std::memory_order_seq_cst);
    }
    delete[] nb->ptr;
    nb->ctx->native_buf_released.fetch_add(1, std::memory_order_seq_cst);
    delete nb;
}

void HostOutputCallback(void* user_ctx, const LbEncodedFrameMeta* meta, LbOwnedBuffer owned) noexcept {
    auto* ctx = static_cast<HostSelfTestCtx*>(user_ctx);
    if (ctx == nullptr || meta == nullptr || owned.data == nullptr || owned.len == 0) {
        if (ctx != nullptr) {
            ctx->integrity_ok.store(false, std::memory_order_seq_cst);
        }
        if (owned.release != nullptr) {
            (void)lb_core_release_buffer(&owned);
        }
        return;
    }
    ctx->rx_bytes.fetch_add(static_cast<uint64_t>(owned.len), std::memory_order_seq_cst);
    if (lb_core_release_buffer(&owned) == LB_STATUS_OK) {
        ctx->rust_buf_released.fetch_add(1, std::memory_order_seq_cst);
    } else {
        ctx->integrity_ok.store(false, std::memory_order_seq_cst);
    }
    ctx->rx_packets.fetch_add(1, std::memory_order_seq_cst);
    ctx->cv.notify_all();
}

} // namespace

int RunLumaBridgeFfiPocSelfTest() noexcept {
    uint32_t major = 0;
    uint32_t minor = 0;
    if (lb_core_abi_version(&major, &minor) != LB_STATUS_OK ||
        major != LB_FFI_ABI_MAJOR || minor != LB_FFI_ABI_MINOR) {
        std::fprintf(stderr, "[FFI-POC] ABI version check failed.\n");
        return EXIT_FAILURE;
    }

    LbAbiLayoutSignature sig{};
    sig.abi = MakeAbiHeader<LbAbiLayoutSignature>();
    if (lb_core_layout_signature(&sig) != LB_STATUS_OK ||
        sig.size_core_config != sizeof(LbCoreConfig) ||
        sig.size_encoded_frame_meta != sizeof(LbEncodedFrameMeta) ||
        sig.size_owned_buffer != sizeof(LbOwnedBuffer)) {
        std::fprintf(stderr, "[FFI-POC] Struct layout verification failed.\n");
        return EXIT_FAILURE;
    }

    LbGlobalResourceCounters before{};
    before.abi = MakeAbiHeader<LbGlobalResourceCounters>();
    if (lb_core_get_global_resource_counters(&before) != LB_STATUS_OK) {
        std::fprintf(stderr, "[FFI-POC] Failed to read baseline global counters.\n");
        return EXIT_FAILURE;
    }

    HostSelfTestCtx ctx{};
    LbCoreConfig cfg{};
    cfg.abi = MakeAbiHeader<LbCoreConfig>();
    cfg.queue_capacity = 16;
    cfg.expected_frame_bytes_hint = 4096;
    cfg.on_output_packet = &HostOutputCallback;
    cfg.on_state_change = nullptr;
    cfg.callback_user_ctx = &ctx;

    LbCoreHandle* handle = nullptr;
    if (lb_core_create(&cfg, &handle) != LB_STATUS_OK || handle == nullptr) {
        std::fprintf(stderr, "[FFI-POC] lb_core_create failed.\n");
        return EXIT_FAILURE;
    }

    if (lb_core_start(handle) != LB_STATUS_OK) {
        std::fprintf(stderr, "[FFI-POC] lb_core_start failed.\n");
        (void)lb_core_destroy(handle);
        return EXIT_FAILURE;
    }

    LbEncodedFrameMeta meta{};
    meta.abi = MakeAbiHeader<LbEncodedFrameMeta>();
    meta.session_id = 1001ULL;
    meta.capture_ts_us = 10000ULL;
    meta.encode_done_ts_us = 10200ULL;
    meta.submit_qpc_ticks = 123456ULL;
    meta.codec = static_cast<uint32_t>(LB_ENCODED_CODEC_H264_ANNEX_B);
    meta.flags = 1U;
    meta.frame_id = 1U;
    meta.display_id = 0U;
    meta.gop_id = 1U;

    const std::vector<uint8_t> borrowed(2048, 0x65U);
    if (lb_core_submit_encoded_frame(handle, &meta, borrowed.data(), borrowed.size()) != LB_STATUS_OK) {
        std::fprintf(stderr, "[FFI-POC] lb_core_submit_encoded_frame failed.\n");
        (void)lb_core_stop(handle);
        (void)lb_core_destroy(handle);
        return EXIT_FAILURE;
    }

    meta.frame_id = 2U;
    constexpr size_t kNativeLen = 4096U;
    auto* raw_native = new uint8_t[kNativeLen];
    std::memset(raw_native, 0x42, kNativeLen);
    auto* holder = new NativeHostBuffer{raw_native, kNativeLen, &ctx};

    LbOwnedBuffer owned{};
    owned.data = raw_native;
    owned.len = kNativeLen;
    owned.capacity = kNativeLen;
    owned.release = &HostNativeRelease;
    owned.user_ctx = holder;

    if (lb_core_submit_owned_encoded_frame(handle, &meta, &owned) != LB_STATUS_OK) {
        (void)lb_core_release_buffer(&owned);
        std::fprintf(stderr, "[FFI-POC] lb_core_submit_owned_encoded_frame failed.\n");
        (void)lb_core_stop(handle);
        (void)lb_core_destroy(handle);
        return EXIT_FAILURE;
    }
    if (owned.release != nullptr || owned.data != nullptr) {
        std::fprintf(stderr, "[FFI-POC] Expected accepted LbOwnedBuffer descriptor to be zeroed.\n");
        (void)lb_core_stop(handle);
        (void)lb_core_destroy(handle);
        return EXIT_FAILURE;
    }

    {
        std::unique_lock<std::mutex> lock(ctx.mu);
        const bool drained = ctx.cv.wait_for(lock, std::chrono::seconds(5), [&]() {
            return ctx.rx_packets.load(std::memory_order_seq_cst) >= 2ULL;
        });
        if (!drained) {
            std::fprintf(stderr, "[FFI-POC] Timed out waiting for packet callbacks.\n");
            (void)lb_core_stop(handle);
            (void)lb_core_destroy(handle);
            return EXIT_FAILURE;
        }
    }

    (void)lb_core_stop(handle);
    if (lb_core_destroy(handle) != LB_STATUS_OK) {
        std::fprintf(stderr, "[FFI-POC] lb_core_destroy failed.\n");
        return EXIT_FAILURE;
    }

    LbGlobalResourceCounters after{};
    after.abi = MakeAbiHeader<LbGlobalResourceCounters>();
    if (lb_core_get_global_resource_counters(&after) != LB_STATUS_OK) {
        std::fprintf(stderr, "[FFI-POC] Failed to read final global counters.\n");
        return EXIT_FAILURE;
    }

    if (!ctx.integrity_ok.load(std::memory_order_seq_cst) ||
        ctx.rx_packets.load(std::memory_order_seq_cst) != 2ULL ||
        ctx.rust_buf_released.load(std::memory_order_seq_cst) != 2ULL ||
        ctx.native_buf_released.load(std::memory_order_seq_cst) != 1ULL ||
        after.active_instances != before.active_instances ||
        after.active_worker_threads != before.active_worker_threads ||
        after.in_flight_buffers != before.in_flight_buffers) {
        std::fprintf(stderr, "[FFI-POC] Resource balance or integrity check failed.\n");
        return EXIT_FAILURE;
    }

    std::printf(
        "[FFI-POC] PASS lumabridge-host linkage self-test (abi=%u.%u, packets=%llu, bytes=%llu, "
        "active_instances=%llu, in_flight=%llu)\n",
        major, minor,
        static_cast<unsigned long long>(ctx.rx_packets.load(std::memory_order_seq_cst)),
        static_cast<unsigned long long>(ctx.rx_bytes.load(std::memory_order_seq_cst)),
        static_cast<unsigned long long>(after.active_instances),
        static_cast<unsigned long long>(after.in_flight_buffers));
    return EXIT_SUCCESS;
}

} // namespace lumabridge::host

#else

#include <cstdlib>

namespace lumabridge::host {
int RunLumaBridgeFfiPocSelfTest() noexcept {
    return EXIT_FAILURE;
}
} // namespace lumabridge::host

#endif
