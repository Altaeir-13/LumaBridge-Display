// SPDX-License-Identifier: Apache-2.0
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <psapi.h>

#include "lumabridge_ffi.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

extern "C" {
void LbC11GetLayoutSignature(LbAbiLayoutSignature* out_sig);
LbStatus LbC11ProbeAbiVersion(uint32_t* out_major, uint32_t* out_minor);
}

namespace {

#define REQUIRE_TRUE(cond, msg)                                                                  \
    do {                                                                                         \
        if (!(cond)) {                                                                           \
            std::fprintf(stderr, "[FAIL] %s (line %d): %s\n", __FILE__, __LINE__, (msg));      \
            std::fflush(stderr);                                                                 \
            return false;                                                                        \
        }                                                                                        \
    } while (false)

#define REQUIRE_STATUS(expr, expected, msg)                                                      \
    do {                                                                                         \
        const LbStatus actual_status__ = (expr);                                                 \
        if (actual_status__ != (expected)) {                                                     \
            std::fprintf(stderr,                                                                 \
                         "[FAIL] %s (line %d): %s (expected status=%u, actual=%u)\n",            \
                         __FILE__, __LINE__, (msg), static_cast<unsigned>(expected),             \
                         static_cast<unsigned>(actual_status__));                                \
            std::fflush(stderr);                                                                 \
            return false;                                                                        \
        }                                                                                        \
    } while (false)

template <typename T>
LbAbiHeader MakeHeader() noexcept {
    LbAbiHeader hdr{};
    hdr.abi_major = LB_FFI_ABI_MAJOR;
    hdr.abi_minor = LB_FFI_ABI_MINOR;
    hdr.struct_size = static_cast<uint32_t>(sizeof(T));
    hdr.reserved = 0;
    return hdr;
}

LbEncodedFrameMeta MakeValidMeta(uint32_t frame_id, LbEncodedCodec codec = LB_ENCODED_CODEC_H264_ANNEX_B) noexcept {
    LbEncodedFrameMeta meta{};
    meta.abi = MakeHeader<LbEncodedFrameMeta>();
    meta.session_id = 0x1122334455667788ULL;
    meta.capture_ts_us = static_cast<uint64_t>(frame_id) * 16667ULL;
    meta.encode_done_ts_us = meta.capture_ts_us + 250ULL;
    meta.submit_qpc_ticks = static_cast<uint64_t>(frame_id) * 1000ULL;
    meta.codec = static_cast<uint32_t>(codec);
    meta.flags = (frame_id == 1U) ? 1U : 0U;
    meta.frame_id = frame_id;
    meta.display_id = 0U;
    meta.gop_id = 1U;
    return meta;
}

struct NativeHeapTracker {
    std::atomic<uint64_t> allocated{0};
    std::atomic<uint64_t> released{0};
    std::atomic<uint64_t> invalid_releases{0};
};

struct NativeBufferAllocation {
    NativeHeapTracker* tracker;
    uint8_t* ptr;
    size_t len;
    uint8_t expected_seed;
};

void NativeReleaseCallback(void* user_ctx, const uint8_t* data, size_t len, size_t capacity) noexcept {
    if (user_ctx == nullptr) {
        return;
    }
    auto* alloc = static_cast<NativeBufferAllocation*>(user_ctx);
    if (alloc->ptr != data || alloc->len != len || alloc->len != capacity) {
        alloc->tracker->invalid_releases.fetch_add(1, std::memory_order_seq_cst);
    } else if (len > 0 && data[0] != alloc->expected_seed) {
        alloc->tracker->invalid_releases.fetch_add(1, std::memory_order_seq_cst);
    }
    delete[] alloc->ptr;
    alloc->tracker->released.fetch_add(1, std::memory_order_seq_cst);
    delete alloc;
}

LbOwnedBuffer MakeTrackedNativeBuffer(NativeHeapTracker& tracker, size_t len, uint8_t seed) {
    auto* bytes = new uint8_t[len];
    for (size_t i = 0; i < len; ++i) {
        bytes[i] = static_cast<uint8_t>((seed + i) & 0xFFU);
    }
    auto* alloc = new NativeBufferAllocation{&tracker, bytes, len, seed};
    tracker.allocated.fetch_add(1, std::memory_order_seq_cst);

    LbOwnedBuffer buf{};
    buf.data = bytes;
    buf.len = len;
    buf.capacity = len;
    buf.release = &NativeReleaseCallback;
    buf.user_ctx = alloc;
    return buf;
}

void ReleaseTrackedManualFailure(LbOwnedBuffer& buf) noexcept {
    if (buf.release != nullptr && buf.user_ctx != nullptr) {
        buf.release(buf.user_ctx, buf.data, buf.len, buf.capacity);
        buf.data = nullptr;
        buf.len = 0;
        buf.capacity = 0;
        buf.release = nullptr;
        buf.user_ctx = nullptr;
    }
}

bool CheckGlobalCountersBalanced(const LbGlobalResourceCounters& before, const char* context) {
    LbGlobalResourceCounters after{};
    after.abi = MakeHeader<LbGlobalResourceCounters>();
    REQUIRE_STATUS(lb_core_get_global_resource_counters(&after), LB_STATUS_OK, context);

    REQUIRE_TRUE(after.active_instances == before.active_instances, "active_instances returned to baseline");
    REQUIRE_TRUE(after.active_worker_threads == before.active_worker_threads, "active_worker_threads returned to baseline");
    REQUIRE_TRUE(after.in_flight_buffers == before.in_flight_buffers, "in_flight_buffers returned to baseline");
    REQUIRE_TRUE(after.callbacks_in_progress == 0ULL, "callbacks_in_progress is 0");
    const uint64_t rust_alloc_delta = after.rust_buffers_allocated - before.rust_buffers_allocated;
    const uint64_t rust_rel_delta = after.rust_buffers_released - before.rust_buffers_released;
    const uint64_t native_rx_delta = after.native_buffers_received - before.native_buffers_received;
    const uint64_t native_rel_delta = after.native_buffers_released - before.native_buffers_released;
    REQUIRE_TRUE(rust_alloc_delta == rust_rel_delta, "rust buffer alloc == release");
    REQUIRE_TRUE(native_rx_delta == native_rel_delta, "native buffer rx == release");
    return true;
}

bool TestAbiLayoutAndVersion() {
    uint32_t major = 0;
    uint32_t minor = 0;
    REQUIRE_STATUS(lb_core_abi_version(&major, &minor), LB_STATUS_OK, "lb_core_abi_version");
    REQUIRE_TRUE(major == LB_FFI_ABI_MAJOR && minor == LB_FFI_ABI_MINOR, "ABI version 1.0");

    uint32_t c_major = 0;
    uint32_t c_minor = 0;
    REQUIRE_STATUS(LbC11ProbeAbiVersion(&c_major, &c_minor), LB_STATUS_OK, "C11 probe");
    REQUIRE_TRUE(c_major == major && c_minor == minor, "C11 == C++20 ABI version");

    LbAbiLayoutSignature rust_sig{};
    rust_sig.abi = MakeHeader<LbAbiLayoutSignature>();
    REQUIRE_STATUS(lb_core_layout_signature(&rust_sig), LB_STATUS_OK, "lb_core_layout_signature");

    LbAbiLayoutSignature c11_sig{};
    LbC11GetLayoutSignature(&c11_sig);

    REQUIRE_TRUE(rust_sig.size_abi_header == sizeof(LbAbiHeader), "sizeof LbAbiHeader");
    REQUIRE_TRUE(rust_sig.size_owned_buffer == sizeof(LbOwnedBuffer), "sizeof LbOwnedBuffer");
    REQUIRE_TRUE(rust_sig.size_encoded_frame_meta == sizeof(LbEncodedFrameMeta), "sizeof LbEncodedFrameMeta");
    REQUIRE_TRUE(rust_sig.size_core_config == sizeof(LbCoreConfig), "sizeof LbCoreConfig");
    REQUIRE_TRUE(rust_sig.size_core_metrics == sizeof(LbCoreMetrics), "sizeof LbCoreMetrics");
    REQUIRE_TRUE(rust_sig.size_global_counters == sizeof(LbGlobalResourceCounters), "sizeof LbGlobalResourceCounters");
    REQUIRE_TRUE(rust_sig.offset_meta_codec == offsetof(LbEncodedFrameMeta, codec), "offsetof codec");
    REQUIRE_TRUE(rust_sig.offset_meta_gop_id == offsetof(LbEncodedFrameMeta, gop_id), "offsetof gop_id");
    REQUIRE_TRUE(rust_sig.offset_owned_release == offsetof(LbOwnedBuffer, release), "offsetof release");
    REQUIRE_TRUE(rust_sig.offset_config_on_output == offsetof(LbCoreConfig, on_output_packet), "offsetof on_output_packet");

    REQUIRE_TRUE(std::memcmp(&rust_sig, &c11_sig, sizeof(rust_sig)) == 0, "Rust == C++20 == C11 layout signature");
    std::printf("[PASS] TestAbiLayoutAndVersion (C11 == C++20 == Rust verified)\n");
    return true;
}

bool TestInputValidationAndErrorContract() {
    LbGlobalResourceCounters before{};
    before.abi = MakeHeader<LbGlobalResourceCounters>();
    REQUIRE_STATUS(lb_core_get_global_resource_counters(&before), LB_STATUS_OK, "baseline counters");

    LbCoreHandle* handle = nullptr;
    LbCoreConfig cfg{};
    cfg.abi = MakeHeader<LbCoreConfig>();
    cfg.queue_capacity = 8;
    cfg.expected_frame_bytes_hint = 4096;

    REQUIRE_STATUS(lb_core_abi_version(nullptr, nullptr), LB_STATUS_INVALID_ARGUMENT, "null abi_version outputs");
    REQUIRE_STATUS(lb_core_create(nullptr, &handle), LB_STATUS_INVALID_ARGUMENT, "null config");
    REQUIRE_STATUS(lb_core_create(&cfg, nullptr), LB_STATUS_INVALID_ARGUMENT, "null out_handle");
    REQUIRE_STATUS(lb_core_destroy(nullptr), LB_STATUS_INVALID_ARGUMENT, "destroy null handle");
    REQUIRE_STATUS(lb_core_release_buffer(nullptr), LB_STATUS_INVALID_ARGUMENT, "release null buffer");

    LbOwnedBuffer empty_buf{};
    REQUIRE_STATUS(lb_core_release_buffer(&empty_buf), LB_STATUS_INVALID_ARGUMENT, "release buffer with null release fn");

    // ABI header failure cases
    LbCoreConfig bad_cfg = cfg;
    bad_cfg.abi.abi_major = 2;
    REQUIRE_STATUS(lb_core_create(&bad_cfg, &handle), LB_STATUS_ABI_VERSION_MISMATCH, "bad abi_major");
    bad_cfg = cfg;
    bad_cfg.abi.abi_minor = 99;
    REQUIRE_STATUS(lb_core_create(&bad_cfg, &handle), LB_STATUS_ABI_VERSION_MISMATCH, "newer abi_minor");
    bad_cfg = cfg;
    bad_cfg.abi.struct_size = 4;
    REQUIRE_STATUS(lb_core_create(&bad_cfg, &handle), LB_STATUS_INVALID_STRUCT_SIZE, "small struct_size");
    bad_cfg = cfg;
    bad_cfg.abi.reserved = 1;
    REQUIRE_STATUS(lb_core_create(&bad_cfg, &handle), LB_STATUS_INVALID_ARGUMENT, "non-zero reserved");
    bad_cfg = cfg;
    bad_cfg.queue_capacity = 0;
    REQUIRE_STATUS(lb_core_create(&bad_cfg, &handle), LB_STATUS_INVALID_ARGUMENT, "queue_capacity 0");
    bad_cfg.queue_capacity = LB_FFI_MAX_QUEUE_CAPACITY + 1U;
    REQUIRE_STATUS(lb_core_create(&bad_cfg, &handle), LB_STATUS_INVALID_ARGUMENT, "queue_capacity > max");
    bad_cfg = cfg;
    bad_cfg.expected_frame_bytes_hint = static_cast<uint32_t>(LB_FFI_MAX_FRAME_BYTES) + 1U;
    REQUIRE_STATUS(lb_core_create(&bad_cfg, &handle), LB_STATUS_INVALID_ARGUMENT, "hint > 8 MiB");

    REQUIRE_STATUS(lb_core_create(&cfg, &handle), LB_STATUS_OK, "valid create");
    REQUIRE_TRUE(handle != nullptr, "handle allocated");

    const uint8_t sample[8] = {0, 0, 0, 1, 0x65, 1, 2, 3};
    LbEncodedFrameMeta meta = MakeValidMeta(1);
    REQUIRE_STATUS(lb_core_submit_encoded_frame(handle, &meta, sample, sizeof(sample)),
                   LB_STATUS_INVALID_STATE, "submit before start");

    REQUIRE_STATUS(lb_core_start(handle), LB_STATUS_OK, "start");
    REQUIRE_STATUS(lb_core_start(handle), LB_STATUS_INVALID_STATE, "double start rejected");

    REQUIRE_STATUS(lb_core_submit_encoded_frame(handle, &meta, nullptr, sizeof(sample)), LB_STATUS_INVALID_ARGUMENT, "null data");
    REQUIRE_STATUS(lb_core_submit_encoded_frame(handle, &meta, sample, 0), LB_STATUS_INVALID_ARGUMENT, "0 len");
    REQUIRE_STATUS(lb_core_submit_encoded_frame(handle, &meta, sample, LB_FFI_MAX_FRAME_BYTES + 1U),
                   LB_STATUS_INVALID_ARGUMENT, "oversized len");

    LbEncodedFrameMeta bad_meta = meta;
    bad_meta.codec = 999U;
    REQUIRE_STATUS(lb_core_submit_encoded_frame(handle, &bad_meta, sample, sizeof(sample)),
                   LB_STATUS_NOT_SUPPORTED, "unsupported codec");

    bad_meta = meta;
    bad_meta.session_id = 0ULL;
    REQUIRE_STATUS(lb_core_submit_encoded_frame(handle, &bad_meta, sample, sizeof(sample)),
                   LB_STATUS_INVALID_ARGUMENT, "session_id 0");

    // Verify rejected owned buffer keeps ownership with caller without triggering release.
    NativeHeapTracker tracker{};
    LbOwnedBuffer native_buf = MakeTrackedNativeBuffer(tracker, 64, 0x33U);
    REQUIRE_STATUS(lb_core_submit_owned_encoded_frame(handle, &bad_meta, &native_buf),
                   LB_STATUS_INVALID_ARGUMENT, "owned submit with bad_meta");
    REQUIRE_TRUE(tracker.released.load(std::memory_order_seq_cst) == 0ULL,
                 "rejected owned buffer release MUST NOT be invoked by Rust");
    ReleaseTrackedManualFailure(native_buf);
    REQUIRE_TRUE(tracker.released.load(std::memory_order_seq_cst) == 1ULL, "caller released unaccepted owned buffer");

    bad_meta = meta;
    bad_meta.display_id = 0xFFFFU;
    REQUIRE_STATUS(lb_core_submit_encoded_frame(handle, &bad_meta, sample, sizeof(sample)),
                   LB_STATUS_INVALID_ARGUMENT, "display_id 0xFFFF rejected");

    bad_meta = meta;
    bad_meta.encode_done_ts_us = bad_meta.capture_ts_us - 1ULL;
    REQUIRE_STATUS(lb_core_submit_encoded_frame(handle, &bad_meta, sample, sizeof(sample)),
                   LB_STATUS_INVALID_ARGUMENT, "encode_done_ts_us < capture_ts_us rejected");

    LbOwnedBuffer missing_release{};
    missing_release.data = sample;
    missing_release.len = sizeof(sample);
    missing_release.capacity = sizeof(sample);
    missing_release.release = nullptr;
    REQUIRE_STATUS(lb_core_submit_owned_encoded_frame(handle, &meta, &missing_release),
                   LB_STATUS_INVALID_ARGUMENT, "null release callback rejected");

    REQUIRE_STATUS(lb_core_stop(handle), LB_STATUS_OK, "stop 1");
    REQUIRE_STATUS(lb_core_stop(handle), LB_STATUS_OK, "stop 2 idempotent");
    REQUIRE_STATUS(lb_core_submit_encoded_frame(handle, &meta, sample, sizeof(sample)),
                   LB_STATUS_INVALID_STATE, "submit after stop rejected");

    // Verify get_last_error works with small and sufficient buffer
    uint8_t err_buf[256]{};
    size_t err_len = 0;
    REQUIRE_STATUS(lb_core_get_last_error(handle, err_buf, sizeof(err_buf), &err_len), LB_STATUS_OK, "get_last_error");

    REQUIRE_STATUS(lb_core_destroy(handle), LB_STATUS_OK, "destroy");
    REQUIRE_TRUE(tracker.invalid_releases.load(std::memory_order_seq_cst) == 0ULL, "no invalid native release args");
    REQUIRE_TRUE(CheckGlobalCountersBalanced(before, "after TestInputValidationAndErrorContract"), "counters balanced");

    std::printf("[PASS] TestInputValidationAndErrorContract\n");
    return true;
}

struct OwnershipTestCtx {
    std::mutex mu;
    std::condition_variable cv;
    std::vector<LbOwnedBuffer> deferred_rust_buffers;
    std::atomic<uint64_t> sync_released{0};
    std::atomic<uint64_t> total_received{0};
    std::atomic<uint64_t> bad_payloads{0};
    std::atomic<uint64_t> state_callbacks{0};
};

void OwnershipOutputCallback(void* user_ctx, const LbEncodedFrameMeta* meta, LbOwnedBuffer owned) noexcept {
    auto* ctx = static_cast<OwnershipTestCtx*>(user_ctx);
    if (ctx == nullptr || meta == nullptr || owned.data == nullptr || owned.len == 0) {
        if (ctx != nullptr) {
            ctx->bad_payloads.fetch_add(1, std::memory_order_seq_cst);
        }
        if (owned.release != nullptr) {
            (void)lb_core_release_buffer(&owned);
        }
        return;
    }

    // Odd frame_ids: validate and release synchronously inside callback.
    // Even frame_ids: retain ownership across callback return and release from consumer thread.
    if ((meta->frame_id % 2U) == 1U) {
        if (owned.data[0] != 0xA1U) {
            ctx->bad_payloads.fetch_add(1, std::memory_order_seq_cst);
        }
        if (lb_core_release_buffer(&owned) == LB_STATUS_OK) {
            ctx->sync_released.fetch_add(1, std::memory_order_seq_cst);
        }
    } else {
        std::lock_guard<std::mutex> lock(ctx->mu);
        ctx->deferred_rust_buffers.push_back(owned);
    }

    ctx->total_received.fetch_add(1, std::memory_order_seq_cst);
    ctx->cv.notify_all();
}

void GenericStateCallback(void* user_ctx, uint32_t /*new_state*/, uint32_t /*status_code*/) noexcept {
    if (user_ctx != nullptr) {
        auto* ctx = static_cast<OwnershipTestCtx*>(user_ctx);
        ctx->state_callbacks.fetch_add(1, std::memory_order_seq_cst);
    }
}

bool TestBidirectionalOwnershipAcrossCrt() {
    LbGlobalResourceCounters before{};
    before.abi = MakeHeader<LbGlobalResourceCounters>();
    REQUIRE_STATUS(lb_core_get_global_resource_counters(&before), LB_STATUS_OK, "baseline counters");

    OwnershipTestCtx ctx{};
    NativeHeapTracker native_tracker{};

    LbCoreConfig cfg{};
    cfg.abi = MakeHeader<LbCoreConfig>();
    cfg.queue_capacity = 16;
    cfg.expected_frame_bytes_hint = 64 * 1024;
    cfg.on_output_packet = &OwnershipOutputCallback;
    cfg.on_state_change = &GenericStateCallback;
    cfg.callback_user_ctx = &ctx;

    LbCoreHandle* handle = nullptr;
    REQUIRE_STATUS(lb_core_create(&cfg, &handle), LB_STATUS_OK, "create");
    REQUIRE_STATUS(lb_core_start(handle), LB_STATUS_OK, "start");

    // 1) Borrowed frame (frame_id = 1 -> sync release)
    std::vector<uint8_t> borrowed_payload(4096, 0xA1U);
    const LbEncodedFrameMeta m1 = MakeValidMeta(1, LB_ENCODED_CODEC_H264_ANNEX_B);
    REQUIRE_STATUS(lb_core_submit_encoded_frame(handle, &m1, borrowed_payload.data(), borrowed_payload.size()),
                   LB_STATUS_OK, "submit borrowed frame 1");

    // 2) Native-owned C++ heap buffer (frame_id = 2 -> deferred release)
    LbOwnedBuffer native_buf = MakeTrackedNativeBuffer(native_tracker, 32768, 0x5AU);
    const LbEncodedFrameMeta m2 = MakeValidMeta(2, LB_ENCODED_CODEC_HEVC_ANNEX_B);
    REQUIRE_STATUS(lb_core_submit_owned_encoded_frame(handle, &m2, &native_buf),
                   LB_STATUS_OK, "submit owned frame 2");

    // 3) Native-owned C++ heap buffer (frame_id = 4 -> deferred release)
    LbOwnedBuffer native_buf2 = MakeTrackedNativeBuffer(native_tracker, 65536, 0x7CU);
    const LbEncodedFrameMeta m3 = MakeValidMeta(4, LB_ENCODED_CODEC_AV1_OBU);
    REQUIRE_STATUS(lb_core_submit_owned_encoded_frame(handle, &m3, &native_buf2),
                   LB_STATUS_OK, "submit owned frame 4");

    {
        std::unique_lock<std::mutex> lock(ctx.mu);
        const bool ok = ctx.cv.wait_for(lock, std::chrono::seconds(5), [&]() {
            return ctx.total_received.load(std::memory_order_seq_cst) >= 3ULL;
        });
        REQUIRE_TRUE(ok, "timed out waiting for worker packet delivery");
    }

    // Release deferred Rust buffers on the C++ consumer thread AFTER callback returned.
    std::vector<LbOwnedBuffer> to_release;
    {
        std::lock_guard<std::mutex> lock(ctx.mu);
        to_release.swap(ctx.deferred_rust_buffers);
    }
    REQUIRE_TRUE(to_release.size() == 2U, "two Rust-owned buffers deferred cleanly");
    for (LbOwnedBuffer& buf : to_release) {
        REQUIRE_STATUS(lb_core_release_buffer(&buf), LB_STATUS_OK, "deferred lb_core_release_buffer");
        REQUIRE_TRUE(buf.data == nullptr && buf.release == nullptr, "released descriptor zeroed");
    }

    REQUIRE_STATUS(lb_core_stop(handle), LB_STATUS_OK, "stop");
    REQUIRE_STATUS(lb_core_destroy(handle), LB_STATUS_OK, "destroy");

    REQUIRE_TRUE(ctx.bad_payloads.load(std::memory_order_seq_cst) == 0ULL, "all payloads intact");
    REQUIRE_TRUE(ctx.sync_released.load(std::memory_order_seq_cst) == 1ULL, "sync release ran once");
    REQUIRE_TRUE(native_tracker.allocated.load(std::memory_order_seq_cst) == 2ULL &&
                     native_tracker.released.load(std::memory_order_seq_cst) == 2ULL,
                 "both native owned buffers freed cleanly");
    REQUIRE_TRUE(native_tracker.invalid_releases.load(std::memory_order_seq_cst) == 0ULL, "no invalid native release args");
    REQUIRE_TRUE(CheckGlobalCountersBalanced(before, "after TestBidirectionalOwnershipAcrossCrt"), "counters balanced");

    std::printf("[PASS] TestBidirectionalOwnershipAcrossCrt (borrowed + sync/deferred native<->Rust ownership)\n");
    return true;
}

struct BackpressureCtx {
    std::mutex mu;
    std::condition_variable cv_entered;
    std::condition_variable cv_release;
    bool first_entered{false};
    bool allow_return{false};
    std::atomic<uint64_t> output_count{0};
};

void BlockingOutputCallback(void* user_ctx, const LbEncodedFrameMeta* /*meta*/, LbOwnedBuffer owned) noexcept {
    auto* ctx = static_cast<BackpressureCtx*>(user_ctx);
    if (ctx != nullptr) {
        const uint64_t idx = ctx->output_count.fetch_add(1, std::memory_order_seq_cst);
        if (idx == 0ULL) {
            std::unique_lock<std::mutex> lock(ctx->mu);
            ctx->first_entered = true;
            ctx->cv_entered.notify_all();
            ctx->cv_release.wait(lock, [&]() { return ctx->allow_return; });
        }
    }
    if (owned.release != nullptr) {
        (void)lb_core_release_buffer(&owned);
    }
}

bool TestBackpressureAndQueueCapacity() {
    LbGlobalResourceCounters before{};
    before.abi = MakeHeader<LbGlobalResourceCounters>();
    REQUIRE_STATUS(lb_core_get_global_resource_counters(&before), LB_STATUS_OK, "baseline counters");

    BackpressureCtx bp_ctx{};
    NativeHeapTracker tracker{};

    LbCoreConfig cfg{};
    cfg.abi = MakeHeader<LbCoreConfig>();
    cfg.queue_capacity = 2;
    cfg.expected_frame_bytes_hint = 1024;
    cfg.on_output_packet = &BlockingOutputCallback;
    cfg.callback_user_ctx = &bp_ctx;

    LbCoreHandle* handle = nullptr;
    REQUIRE_STATUS(lb_core_create(&cfg, &handle), LB_STATUS_OK, "create");
    REQUIRE_STATUS(lb_core_start(handle), LB_STATUS_OK, "start");

    const std::vector<uint8_t> small_frame(512, 0x22U);
    const LbEncodedFrameMeta m1 = MakeValidMeta(1);
    REQUIRE_STATUS(lb_core_submit_encoded_frame(handle, &m1, small_frame.data(), small_frame.size()),
                   LB_STATUS_OK, "submit frame 1 to stall worker inside callback");

    {
        std::unique_lock<std::mutex> lock(bp_ctx.mu);
        const bool entered = bp_ctx.cv_entered.wait_for(lock, std::chrono::seconds(5), [&]() { return bp_ctx.first_entered; });
        REQUIRE_TRUE(entered, "worker did not enter blocking callback");
    }

    // Worker is parked inside callback for frame 1, so queue (cap=2) absorbs frames 2 and 3.
    const LbEncodedFrameMeta m2 = MakeValidMeta(2);
    const LbEncodedFrameMeta m3 = MakeValidMeta(3);
    REQUIRE_STATUS(lb_core_submit_encoded_frame(handle, &m2, small_frame.data(), small_frame.size()),
                   LB_STATUS_OK, "queue slot 1/2");
    REQUIRE_STATUS(lb_core_submit_encoded_frame(handle, &m3, small_frame.data(), small_frame.size()),
                   LB_STATUS_OK, "queue slot 2/2");

    // Next borrowed submit MUST hit LB_STATUS_BACKPRESSURE.
    const LbEncodedFrameMeta m4 = MakeValidMeta(4);
    REQUIRE_STATUS(lb_core_submit_encoded_frame(handle, &m4, small_frame.data(), small_frame.size()),
                   LB_STATUS_BACKPRESSURE, "borrowed backpressure");

    // Next owned submit MUST hit LB_STATUS_BACKPRESSURE without invoking release!
    LbOwnedBuffer rejected_owned = MakeTrackedNativeBuffer(tracker, 256, 0x44U);
    REQUIRE_STATUS(lb_core_submit_owned_encoded_frame(handle, &m4, &rejected_owned),
                   LB_STATUS_BACKPRESSURE, "owned backpressure");
    REQUIRE_TRUE(tracker.released.load(std::memory_order_seq_cst) == 0ULL,
                 "backpressured owned buffer MUST keep caller ownership");
    ReleaseTrackedManualFailure(rejected_owned);

    {
        std::lock_guard<std::mutex> lock(bp_ctx.mu);
        bp_ctx.allow_return = true;
    }
    bp_ctx.cv_release.notify_all();

    // Wait for queued frames 2 & 3 to drain cleanly before stopping.
    for (int i = 0; i < 200; ++i) {
        if (bp_ctx.output_count.load(std::memory_order_seq_cst) >= 3ULL) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    LbCoreMetrics metrics{};
    metrics.abi = MakeHeader<LbCoreMetrics>();
    REQUIRE_STATUS(lb_core_get_metrics(handle, &metrics), LB_STATUS_OK, "get_metrics");
    REQUIRE_TRUE(metrics.backpressure_events >= 2ULL, "backpressure_events counted");

    REQUIRE_STATUS(lb_core_stop(handle), LB_STATUS_OK, "stop");
    REQUIRE_STATUS(lb_core_destroy(handle), LB_STATUS_OK, "destroy");
    REQUIRE_TRUE(CheckGlobalCountersBalanced(before, "after TestBackpressureAndQueueCapacity"), "counters balanced");

    std::printf("[PASS] TestBackpressureAndQueueCapacity\n");
    return true;
}

struct ReentrantStopCtx {
    LbCoreHandle* handle{nullptr};
    std::atomic<uint64_t> callbacks_seen{0};
    std::atomic<uint32_t> reentrant_stop_status{999U};
};

void ReentrantStopOutputCallback(void* user_ctx, const LbEncodedFrameMeta* /*meta*/, LbOwnedBuffer owned) noexcept {
    auto* ctx = static_cast<ReentrantStopCtx*>(user_ctx);
    if (owned.release != nullptr) {
        (void)lb_core_release_buffer(&owned);
    }
    if (ctx != nullptr) {
        const uint64_t seen = ctx->callbacks_seen.fetch_add(1, std::memory_order_seq_cst) + 1ULL;
        if (seen == 8ULL && ctx->handle != nullptr) {
            // Reentrant lb_core_stop from inside worker thread callback MUST NOT self-join/deadlock!
            const LbStatus st = lb_core_stop(ctx->handle);
            ctx->reentrant_stop_status.store(static_cast<uint32_t>(st), std::memory_order_seq_cst);
        }
    }
}

bool TestConcurrentSubmissionAndReentrantStop() {
    LbGlobalResourceCounters before{};
    before.abi = MakeHeader<LbGlobalResourceCounters>();
    REQUIRE_STATUS(lb_core_get_global_resource_counters(&before), LB_STATUS_OK, "baseline counters");

    ReentrantStopCtx ctx{};
    NativeHeapTracker tracker{};

    LbCoreConfig cfg{};
    cfg.abi = MakeHeader<LbCoreConfig>();
    cfg.queue_capacity = 32;
    cfg.expected_frame_bytes_hint = 8192;
    cfg.on_output_packet = &ReentrantStopOutputCallback;
    cfg.callback_user_ctx = &ctx;

    LbCoreHandle* handle = nullptr;
    REQUIRE_STATUS(lb_core_create(&cfg, &handle), LB_STATUS_OK, "create");
    ctx.handle = handle;
    REQUIRE_STATUS(lb_core_start(handle), LB_STATUS_OK, "start");

    std::vector<std::thread> producers;
    for (int t = 0; t < 4; ++t) {
        producers.emplace_back([&, t]() {
            std::vector<uint8_t> payload(2048, static_cast<uint8_t>(0x10 + t));
            for (uint32_t i = 1; i <= 50; ++i) {
                LbEncodedFrameMeta meta = MakeValidMeta(static_cast<uint32_t>(t * 100U + i));
                if ((i % 2U) == 0U) {
                    LbOwnedBuffer ob = MakeTrackedNativeBuffer(tracker, 1024, static_cast<uint8_t>(0x30 + t));
                    const LbStatus st = lb_core_submit_owned_encoded_frame(handle, &meta, &ob);
                    if (st != LB_STATUS_OK) {
                        ReleaseTrackedManualFailure(ob);
                    }
                } else {
                    (void)lb_core_submit_encoded_frame(handle, &meta, payload.data(), payload.size());
                }
                if (ctx.reentrant_stop_status.load(std::memory_order_seq_cst) == static_cast<uint32_t>(LB_STATUS_OK)) {
                    // Keep pushing a couple more iterations to exercise concurrent Stopping/Stopped checks.
                    if (i > 12U) {
                        break;
                    }
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        });
    }

    for (auto& th : producers) {
        th.join();
    }

    REQUIRE_TRUE(ctx.reentrant_stop_status.load(std::memory_order_seq_cst) == static_cast<uint32_t>(LB_STATUS_OK),
                 "reentrant lb_core_stop returned LB_STATUS_OK without self-join deadlock");
    REQUIRE_STATUS(lb_core_stop(handle), LB_STATUS_OK, "external stop after reentrant stop");
    REQUIRE_STATUS(lb_core_destroy(handle), LB_STATUS_OK, "destroy");

    REQUIRE_TRUE(tracker.allocated.load(std::memory_order_seq_cst) == tracker.released.load(std::memory_order_seq_cst),
                 "all native owned buffers freed cleanly under concurrent stop");
    REQUIRE_TRUE(CheckGlobalCountersBalanced(before, "after TestConcurrentSubmissionAndReentrantStop"), "counters balanced");

    std::printf("[PASS] TestConcurrentSubmissionAndReentrantStop\n");
    return true;
}

bool TestAbruptDisconnectDrainsOwnedBuffers() {
    LbGlobalResourceCounters before{};
    before.abi = MakeHeader<LbGlobalResourceCounters>();
    REQUIRE_STATUS(lb_core_get_global_resource_counters(&before), LB_STATUS_OK, "baseline counters");

    BackpressureCtx park_ctx{};
    NativeHeapTracker tracker{};

    LbCoreConfig cfg{};
    cfg.abi = MakeHeader<LbCoreConfig>();
    cfg.queue_capacity = 8;
    cfg.expected_frame_bytes_hint = 4096;
    cfg.on_output_packet = &BlockingOutputCallback;
    cfg.callback_user_ctx = &park_ctx;

    LbCoreHandle* handle = nullptr;
    REQUIRE_STATUS(lb_core_create(&cfg, &handle), LB_STATUS_OK, "create");
    REQUIRE_STATUS(lb_core_start(handle), LB_STATUS_OK, "start");

    const std::vector<uint8_t> first(256, 0x11U);
    const LbEncodedFrameMeta m1 = MakeValidMeta(1);
    REQUIRE_STATUS(lb_core_submit_encoded_frame(handle, &m1, first.data(), first.size()), LB_STATUS_OK, "submit first");

    {
        std::unique_lock<std::mutex> lock(park_ctx.mu);
        const bool ok = park_ctx.cv_entered.wait_for(lock, std::chrono::seconds(5), [&]() { return park_ctx.first_entered; });
        REQUIRE_TRUE(ok, "worker entered callback");
    }

    // Queue 4 native-owned buffers while worker is parked.
    for (uint32_t i = 2; i <= 5; ++i) {
        LbOwnedBuffer ob = MakeTrackedNativeBuffer(tracker, 4096, static_cast<uint8_t>(0x50 + i));
        const LbEncodedFrameMeta mi = MakeValidMeta(i);
        REQUIRE_STATUS(lb_core_submit_owned_encoded_frame(handle, &mi, &ob), LB_STATUS_OK, "queue owned before disconnect");
    }
    REQUIRE_TRUE(tracker.released.load(std::memory_order_seq_cst) == 0ULL, "all 4 still queued in Rust");

    // Release worker gate concurrently while triggering abrupt disconnect.
    std::thread unpark([&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        std::lock_guard<std::mutex> lock(park_ctx.mu);
        park_ctx.allow_return = true;
        park_ctx.cv_release.notify_all();
    });

    REQUIRE_STATUS(lb_core_simulate_disconnect(handle), LB_STATUS_OK, "simulate_disconnect");
    unpark.join();

    REQUIRE_STATUS(lb_core_destroy(handle), LB_STATUS_OK, "destroy after disconnect");
    REQUIRE_TRUE(tracker.allocated.load(std::memory_order_seq_cst) == 4ULL &&
                     tracker.released.load(std::memory_order_seq_cst) == 4ULL,
                 "abrupt disconnect drained and released all queued native buffers");
    REQUIRE_TRUE(CheckGlobalCountersBalanced(before, "after TestAbruptDisconnectDrainsOwnedBuffers"), "counters balanced");

    std::printf("[PASS] TestAbruptDisconnectDrainsOwnedBuffers\n");
    return true;
}

bool TestLifecycle100CyclesAndProcessTelemetry() {
    LbGlobalResourceCounters before{};
    before.abi = MakeHeader<LbGlobalResourceCounters>();
    REQUIRE_STATUS(lb_core_get_global_resource_counters(&before), LB_STATUS_OK, "baseline counters");

    PROCESS_MEMORY_COUNTERS_EX pmc_before{};
    pmc_before.cb = sizeof(pmc_before);
    DWORD handles_before = 0;
    const HANDLE self = GetCurrentProcess();
    REQUIRE_TRUE(GetProcessMemoryInfo(self, reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc_before), sizeof(pmc_before)) != FALSE,
                 "GetProcessMemoryInfo before");
    REQUIRE_TRUE(GetProcessHandleCount(self, &handles_before) != FALSE, "GetProcessHandleCount before");

    NativeHeapTracker tracker{};
    OwnershipTestCtx ctx{};

    const auto sink_cb = [](void* user_ctx, const LbEncodedFrameMeta* /*meta*/, LbOwnedBuffer owned) noexcept {
        auto* c = static_cast<OwnershipTestCtx*>(user_ctx);
        if (owned.release != nullptr) {
            (void)lb_core_release_buffer(&owned);
        }
        if (c != nullptr) {
            c->total_received.fetch_add(1, std::memory_order_seq_cst);
        }
    };

    constexpr int kCycles = 120;
    const std::vector<uint8_t> borrowed(16384, 0xA5U);

    for (int cycle = 0; cycle < kCycles; ++cycle) {
        LbCoreConfig cfg{};
        cfg.abi = MakeHeader<LbCoreConfig>();
        cfg.queue_capacity = 8;
        cfg.expected_frame_bytes_hint = 16384;
        cfg.on_output_packet = sink_cb;
        cfg.callback_user_ctx = &ctx;

        LbCoreHandle* handle = nullptr;
        REQUIRE_STATUS(lb_core_create(&cfg, &handle), LB_STATUS_OK, "cycle create");
        REQUIRE_STATUS(lb_core_start(handle), LB_STATUS_OK, "cycle start");

        const LbEncodedFrameMeta m1 = MakeValidMeta(static_cast<uint32_t>(cycle * 2 + 1));
        REQUIRE_STATUS(lb_core_submit_encoded_frame(handle, &m1, borrowed.data(), borrowed.size()),
                       LB_STATUS_OK, "cycle submit borrowed");

        LbOwnedBuffer ob = MakeTrackedNativeBuffer(tracker, 8192, 0x6CU);
        const LbEncodedFrameMeta m2 = MakeValidMeta(static_cast<uint32_t>(cycle * 2 + 2));
        REQUIRE_STATUS(lb_core_submit_owned_encoded_frame(handle, &m2, &ob),
                       LB_STATUS_OK, "cycle submit owned");

        if ((cycle % 10) == 9) {
            REQUIRE_STATUS(lb_core_simulate_disconnect(handle), LB_STATUS_OK, "cycle simulate_disconnect");
        } else {
            REQUIRE_STATUS(lb_core_stop(handle), LB_STATUS_OK, "cycle stop");
        }
        REQUIRE_STATUS(lb_core_destroy(handle), LB_STATUS_OK, "cycle destroy");
    }

    PROCESS_MEMORY_COUNTERS_EX pmc_after{};
    pmc_after.cb = sizeof(pmc_after);
    DWORD handles_after = 0;
    REQUIRE_TRUE(GetProcessMemoryInfo(self, reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc_after), sizeof(pmc_after)) != FALSE,
                 "GetProcessMemoryInfo after");
    REQUIRE_TRUE(GetProcessHandleCount(self, &handles_after) != FALSE, "GetProcessHandleCount after");

    REQUIRE_TRUE(tracker.allocated.load(std::memory_order_seq_cst) == static_cast<uint64_t>(kCycles) &&
                     tracker.released.load(std::memory_order_seq_cst) == static_cast<uint64_t>(kCycles),
                 "all 120 cycles released native owned buffers");
    REQUIRE_TRUE(CheckGlobalCountersBalanced(before, "after 120 lifecycle cycles"), "global counters balanced after 120 cycles");

    const int64_t handle_delta = static_cast<int64_t>(handles_after) - static_cast<int64_t>(handles_before);
    const int64_t private_delta_kb =
        (static_cast<int64_t>(pmc_after.PrivateUsage) - static_cast<int64_t>(pmc_before.PrivateUsage)) / 1024;
    const int64_t ws_delta_kb =
        (static_cast<int64_t>(pmc_after.WorkingSetSize) - static_cast<int64_t>(pmc_before.WorkingSetSize)) / 1024;

    // Tolerate minor allocator cache growth/noise while failing hard on thread handle or per-cycle buffer leaks.
    REQUIRE_TRUE(handle_delta <= 8, "no handle leak across 120 create/start/stop/destroy cycles");
    REQUIRE_TRUE(private_delta_kb <= 4096, "no unbounded private memory leak across 120 cycles");

    std::printf(
        "[PASS] TestLifecycle100CyclesAndProcessTelemetry (cycles=%d, handles_before=%lu, handles_after=%lu, "
        "private_before_kb=%llu, private_after_kb=%llu, ws_delta_kb=%lld)\n",
        kCycles, handles_before, handles_after,
        static_cast<unsigned long long>(pmc_before.PrivateUsage / 1024ULL),
        static_cast<unsigned long long>(pmc_after.PrivateUsage / 1024ULL),
        static_cast<long long>(ws_delta_kb));
    return true;
}

bool TestConcurrentExternalStopsWaitForWorkerAndSingleStopped() {
    LbGlobalResourceCounters before{};
    before.abi = MakeHeader<LbGlobalResourceCounters>();
    REQUIRE_STATUS(lb_core_get_global_resource_counters(&before), LB_STATUS_OK, "baseline counters");

    struct ConcurrentStopCtx {
        std::mutex mu;
        std::condition_variable cv_entered;
        std::condition_variable cv_release;
        bool cb_entered{false};
        bool cb_release{false};
        std::atomic<uint64_t> stopped_count{0};
        std::vector<uint32_t> states;
        std::mutex state_mu;
    } ctx{};

    const auto on_out = [](void* u, const LbEncodedFrameMeta* /*m*/, LbOwnedBuffer buf) noexcept {
        auto* c = static_cast<ConcurrentStopCtx*>(u);
        {
            std::unique_lock<std::mutex> lock(c->mu);
            c->cb_entered = true;
            c->cv_entered.notify_all();
            c->cv_release.wait(lock, [&]() { return c->cb_release; });
        }
        if (buf.release != nullptr) {
            (void)lb_core_release_buffer(&buf);
        }
    };
    const auto on_state = [](void* u, uint32_t state, uint32_t /*status*/) noexcept {
        auto* c = static_cast<ConcurrentStopCtx*>(u);
        {
            std::lock_guard<std::mutex> lock(c->state_mu);
            c->states.push_back(state);
        }
        if (state == LB_CORE_STATE_STOPPED) {
            c->stopped_count.fetch_add(1, std::memory_order_seq_cst);
        }
    };

    LbCoreConfig cfg{};
    cfg.abi = MakeHeader<LbCoreConfig>();
    cfg.queue_capacity = 4;
    cfg.expected_frame_bytes_hint = 512;
    cfg.on_output_packet = on_out;
    cfg.on_state_change = on_state;
    cfg.callback_user_ctx = &ctx;

    LbCoreHandle* handle = nullptr;
    REQUIRE_STATUS(lb_core_create(&cfg, &handle), LB_STATUS_OK, "create");
    REQUIRE_STATUS(lb_core_start(handle), LB_STATUS_OK, "start");

    const uint8_t payload[64]{1, 2, 3, 4};
    const LbEncodedFrameMeta meta = MakeValidMeta(1);
    REQUIRE_STATUS(lb_core_submit_encoded_frame(handle, &meta, payload, sizeof(payload)), LB_STATUS_OK, "submit");

    {
        std::unique_lock<std::mutex> lock(ctx.mu);
        REQUIRE_TRUE(ctx.cv_entered.wait_for(lock, std::chrono::seconds(5), [&]() { return ctx.cb_entered; }),
                     "worker entered output callback");
    }

    std::atomic<int> ready{0};
    std::atomic<int> finished{0};
    std::atomic<uint32_t> rc1{999U};
    std::atomic<uint32_t> rc2{999U};
    std::thread t1([&]() {
        ready.fetch_add(1, std::memory_order_seq_cst);
        while (ready.load(std::memory_order_seq_cst) < 2) {
            std::this_thread::yield();
        }
        rc1.store(static_cast<uint32_t>(lb_core_stop(handle)), std::memory_order_seq_cst);
        finished.fetch_add(1, std::memory_order_seq_cst);
    });
    std::thread t2([&]() {
        ready.fetch_add(1, std::memory_order_seq_cst);
        while (ready.load(std::memory_order_seq_cst) < 2) {
            std::this_thread::yield();
        }
        rc2.store(static_cast<uint32_t>(lb_core_stop(handle)), std::memory_order_seq_cst);
        finished.fetch_add(1, std::memory_order_seq_cst);
    });

    while (ready.load(std::memory_order_seq_cst) < 2) {
        std::this_thread::yield();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(25));
    REQUIRE_TRUE(finished.load(std::memory_order_seq_cst) == 0,
                 "neither concurrent lb_core_stop may return before worker callback finishes");

    {
        std::lock_guard<std::mutex> lock(ctx.mu);
        ctx.cb_release = true;
    }
    ctx.cv_release.notify_all();
    t1.join();
    t2.join();

    REQUIRE_TRUE(finished.load(std::memory_order_seq_cst) == 2, "both stops finished");
    REQUIRE_TRUE(rc1.load(std::memory_order_seq_cst) == static_cast<uint32_t>(LB_STATUS_OK), "stop 1 ok");
    REQUIRE_TRUE(rc2.load(std::memory_order_seq_cst) == static_cast<uint32_t>(LB_STATUS_OK), "stop 2 ok");
    REQUIRE_TRUE(ctx.stopped_count.load(std::memory_order_seq_cst) == 1ULL, "single Stopped callback");
    {
        std::lock_guard<std::mutex> lock(ctx.state_mu);
        REQUIRE_TRUE(ctx.states.size() == 2U && ctx.states[0] == LB_CORE_STATE_RUNNING &&
                         ctx.states[1] == LB_CORE_STATE_STOPPED,
                     "monotonic [Running, Stopped] transition");
    }

    REQUIRE_STATUS(lb_core_destroy(handle), LB_STATUS_OK, "destroy");
    REQUIRE_TRUE(CheckGlobalCountersBalanced(before, "after TestConcurrentExternalStopsWaitForWorkerAndSingleStopped"),
                 "counters balanced");
    std::printf("[PASS] TestConcurrentExternalStopsWaitForWorkerAndSingleStopped\n");
    return true;
}

bool TestAbruptDisconnectRacingConcurrentSubmitters() {
    LbGlobalResourceCounters before{};
    before.abi = MakeHeader<LbGlobalResourceCounters>();
    REQUIRE_STATUS(lb_core_get_global_resource_counters(&before), LB_STATUS_OK, "baseline counters");

    NativeHeapTracker tracker{};
    LbCoreConfig cfg{};
    cfg.abi = MakeHeader<LbCoreConfig>();
    cfg.queue_capacity = 8;
    cfg.expected_frame_bytes_hint = 1024;
    cfg.on_output_packet = [](void* /*u*/, const LbEncodedFrameMeta* /*m*/, LbOwnedBuffer buf) noexcept {
        if (buf.release != nullptr) {
            (void)lb_core_release_buffer(&buf);
        }
    };

    LbCoreHandle* handle = nullptr;
    REQUIRE_STATUS(lb_core_create(&cfg, &handle), LB_STATUS_OK, "create");
    REQUIRE_STATUS(lb_core_start(handle), LB_STATUS_OK, "start");

    std::atomic<bool> stop_flag{false};
    std::atomic<uint64_t> accepted{0};
    std::atomic<uint64_t> unexpected_failures{0};

    auto producer = [&](uint32_t base_id) {
        for (uint32_t i = 0; i < 120 && !stop_flag.load(std::memory_order_relaxed); ++i) {
            LbOwnedBuffer owned = MakeTrackedNativeBuffer(tracker, 512, static_cast<uint8_t>(i & 0xFFU));
            const LbEncodedFrameMeta meta = MakeValidMeta(base_id + i + 1U);
            const LbStatus st = lb_core_submit_owned_encoded_frame(handle, &meta, &owned);
            if (st == LB_STATUS_OK) {
                if (owned.data != nullptr || owned.release != nullptr) {
                    unexpected_failures.fetch_add(1, std::memory_order_seq_cst);
                }
                accepted.fetch_add(1, std::memory_order_seq_cst);
            } else if (st == LB_STATUS_BACKPRESSURE || st == LB_STATUS_INVALID_STATE) {
                ReleaseTrackedManualFailure(owned);
            } else {
                unexpected_failures.fetch_add(1, std::memory_order_seq_cst);
                ReleaseTrackedManualFailure(owned);
            }
        }
    };

    std::thread p1(producer, 1000U);
    std::thread p2(producer, 2000U);
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    REQUIRE_STATUS(lb_core_simulate_disconnect(handle), LB_STATUS_OK, "simulate disconnect mid-stream");
    stop_flag.store(true, std::memory_order_relaxed);
    p1.join();
    p2.join();

    REQUIRE_STATUS(lb_core_stop(handle), LB_STATUS_OK, "stop after disconnect");
    REQUIRE_STATUS(lb_core_destroy(handle), LB_STATUS_OK, "destroy after disconnect");

    REQUIRE_TRUE(unexpected_failures.load(std::memory_order_seq_cst) == 0ULL, "no unexpected submit status/contract violations");
    REQUIRE_TRUE(tracker.allocated.load(std::memory_order_seq_cst) == tracker.released.load(std::memory_order_seq_cst),
                 "every tracked native buffer freed once across concurrent disconnect");
    REQUIRE_TRUE(tracker.invalid_releases.load(std::memory_order_seq_cst) == 0ULL, "no invalid native releases");
    REQUIRE_TRUE(CheckGlobalCountersBalanced(before, "after TestAbruptDisconnectRacingConcurrentSubmitters"),
                 "counters balanced");
    std::printf("[PASS] TestAbruptDisconnectRacingConcurrentSubmitters (accepted=%llu, released=%llu)\n",
                static_cast<unsigned long long>(accepted.load(std::memory_order_seq_cst)),
                static_cast<unsigned long long>(tracker.released.load(std::memory_order_seq_cst)));
    return true;
}

bool TestDeferredRustBufferReleaseAfterDestroy() {
    LbGlobalResourceCounters before{};
    before.abi = MakeHeader<LbGlobalResourceCounters>();
    REQUIRE_STATUS(lb_core_get_global_resource_counters(&before), LB_STATUS_OK, "baseline counters");

    struct DeferredCtx {
        std::mutex mu;
        std::condition_variable cv;
        bool has_buf{false};
        LbOwnedBuffer retained{};
    } ctx{};

    const auto on_out = [](void* u, const LbEncodedFrameMeta* /*m*/, LbOwnedBuffer buf) noexcept {
        auto* c = static_cast<DeferredCtx*>(u);
        std::lock_guard<std::mutex> lock(c->mu);
        c->retained = buf;
        c->has_buf = true;
        c->cv.notify_all();
    };

    LbCoreConfig cfg{};
    cfg.abi = MakeHeader<LbCoreConfig>();
    cfg.queue_capacity = 4;
    cfg.expected_frame_bytes_hint = 1024;
    cfg.on_output_packet = on_out;
    cfg.callback_user_ctx = &ctx;

    LbCoreHandle* handle = nullptr;
    REQUIRE_STATUS(lb_core_create(&cfg, &handle), LB_STATUS_OK, "create");
    REQUIRE_STATUS(lb_core_start(handle), LB_STATUS_OK, "start");

    std::vector<uint8_t> payload(256, 0x5CU);
    payload[0] = 0xDE;
    payload[255] = 0xAD;
    const LbEncodedFrameMeta meta = MakeValidMeta(1);
    REQUIRE_STATUS(lb_core_submit_encoded_frame(handle, &meta, payload.data(), payload.size()),
                   LB_STATUS_OK, "submit for deferred post-destroy release");

    {
        std::unique_lock<std::mutex> lock(ctx.mu);
        REQUIRE_TRUE(ctx.cv.wait_for(lock, std::chrono::seconds(5), [&]() { return ctx.has_buf; }),
                     "received output buffer");
    }

    REQUIRE_STATUS(lb_core_stop(handle), LB_STATUS_OK, "stop before destroy");
    REQUIRE_STATUS(lb_core_destroy(handle), LB_STATUS_OK, "destroy while Rust output buffer still retained by caller");
    handle = nullptr;

    // Verify instance teardown already ran, Rust buffer payload is STILL intact, and DLL release succeeds on another thread!
    LbGlobalResourceCounters mid{};
    mid.abi = MakeHeader<LbGlobalResourceCounters>();
    REQUIRE_STATUS(lb_core_get_global_resource_counters(&mid), LB_STATUS_OK, "mid global counters");
    REQUIRE_TRUE(mid.active_instances == before.active_instances, "instance destroyed while buffer still held");
    REQUIRE_TRUE((mid.rust_buffers_allocated - before.rust_buffers_allocated) == 1ULL, "1 Rust buffer allocated");
    REQUIRE_TRUE((mid.rust_buffers_released - before.rust_buffers_released) == 0ULL, "0 Rust buffers released yet");
    REQUIRE_TRUE(ctx.retained.data != nullptr && ctx.retained.len == 256 &&
                     ctx.retained.data[0] == 0xDE && ctx.retained.data[255] == 0xAD,
                 "deferred Rust buffer remains valid & readable after lb_core_destroy while DLL is loaded");

    LbStatus release_rc = LB_STATUS_INTERNAL_PANIC;
    std::thread releaser([&]() { release_rc = lb_core_release_buffer(&ctx.retained); });
    releaser.join();
    REQUIRE_STATUS(release_rc, LB_STATUS_OK, "cross-thread post-destroy lb_core_release_buffer succeeded");
    REQUIRE_TRUE(ctx.retained.data == nullptr && ctx.retained.release == nullptr, "released descriptor zeroed");
    REQUIRE_TRUE(CheckGlobalCountersBalanced(before, "after TestDeferredRustBufferReleaseAfterDestroy"),
                 "counters balanced after post-destroy release");

    std::printf("[PASS] TestDeferredRustBufferReleaseAfterDestroy\n");
    return true;
}

bool TestPanicContainmentAndDefaultDllIsolation(const std::wstring& faultDllPath) {
    // 1. Default production DLL MUST NOT export lb_core_poc_trigger_panic.
    const HMODULE prodMod = GetModuleHandleW(L"lumabridge_ffi.dll");
    REQUIRE_TRUE(prodMod != nullptr, "default lumabridge_ffi.dll loaded");
    REQUIRE_TRUE(GetProcAddress(prodMod, "lb_core_poc_trigger_panic") == nullptr,
                 "default production DLL MUST NOT export lb_core_poc_trigger_panic");

    // 2. Dynamically load isolated poc-fault-injection DLL via safe LoadLibraryExW flags.
    const HMODULE faultMod =
        LoadLibraryExW(faultDllPath.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    REQUIRE_TRUE(faultMod != nullptr, "failed to load fault-injection DLL");

    struct DllGuard {
        HMODULE mod;
        ~DllGuard() {
            if (mod != nullptr) {
                FreeLibrary(mod);
            }
        }
    } guard{faultMod};

    using FnAbiVer = LbStatus (*)(uint32_t*, uint32_t*);
    using FnCreate = LbStatus (*)(const LbCoreConfig*, LbCoreHandle**);
    using FnStart = LbStatus (*)(LbCoreHandle*);
    using FnSubmitOwned = LbStatus (*)(LbCoreHandle*, const LbEncodedFrameMeta*, LbOwnedBuffer*);
    using FnReleaseBuf = LbStatus (*)(LbOwnedBuffer*);
    using FnTriggerPanic = LbStatus (*)(LbCoreHandle*, uint32_t);
    using FnMetrics = LbStatus (*)(const LbCoreHandle*, LbCoreMetrics*);
    using FnLastError = LbStatus (*)(const LbCoreHandle*, uint8_t*, size_t, size_t*);
    using FnDestroy = LbStatus (*)(LbCoreHandle*);
    using FnGlobalCounters = LbStatus (*)(LbGlobalResourceCounters*);

    auto fn_abi = reinterpret_cast<FnAbiVer>(GetProcAddress(faultMod, "lb_core_abi_version"));
    auto fn_create = reinterpret_cast<FnCreate>(GetProcAddress(faultMod, "lb_core_create"));
    auto fn_start = reinterpret_cast<FnStart>(GetProcAddress(faultMod, "lb_core_start"));
    auto fn_submit_owned = reinterpret_cast<FnSubmitOwned>(GetProcAddress(faultMod, "lb_core_submit_owned_encoded_frame"));
    auto fn_release = reinterpret_cast<FnReleaseBuf>(GetProcAddress(faultMod, "lb_core_release_buffer"));
    auto fn_trigger = reinterpret_cast<FnTriggerPanic>(GetProcAddress(faultMod, "lb_core_poc_trigger_panic"));
    auto fn_metrics = reinterpret_cast<FnMetrics>(GetProcAddress(faultMod, "lb_core_get_metrics"));
    auto fn_last_error = reinterpret_cast<FnLastError>(GetProcAddress(faultMod, "lb_core_get_last_error"));
    auto fn_destroy = reinterpret_cast<FnDestroy>(GetProcAddress(faultMod, "lb_core_destroy"));
    auto fn_global = reinterpret_cast<FnGlobalCounters>(GetProcAddress(faultMod, "lb_core_get_global_resource_counters"));

    REQUIRE_TRUE(fn_abi && fn_create && fn_start && fn_submit_owned && fn_release && fn_trigger && fn_metrics &&
                     fn_last_error && fn_destroy && fn_global,
                 "resolved all fault-injection exports");

    uint32_t fmaj = 0;
    uint32_t fmin = 0;
    REQUIRE_STATUS(fn_abi(&fmaj, &fmin), LB_STATUS_OK, "fault dll abi_version");

    // Mode 1: Direct FFI boundary panic containment
    {
        struct StateTrack {
            std::atomic<uint32_t> last_state{999U};
            std::atomic<uint32_t> last_status{999U};
        } st_track{};

        const auto st_cb = [](void* u, uint32_t s, uint32_t c) noexcept {
            auto* tr = static_cast<StateTrack*>(u);
            tr->last_state.store(s, std::memory_order_seq_cst);
            tr->last_status.store(c, std::memory_order_seq_cst);
        };

        LbCoreConfig cfg{};
        cfg.abi = MakeHeader<LbCoreConfig>();
        cfg.queue_capacity = 4;
        cfg.expected_frame_bytes_hint = 1024;
        cfg.on_state_change = st_cb;
        cfg.callback_user_ctx = &st_track;

        LbCoreHandle* h1 = nullptr;
        REQUIRE_STATUS(fn_create(&cfg, &h1), LB_STATUS_OK, "mode 1 create");
        REQUIRE_STATUS(fn_start(h1), LB_STATUS_OK, "mode 1 start");

        REQUIRE_STATUS(fn_trigger(h1, 1U), LB_STATUS_INTERNAL_PANIC, "mode 1 panic trapped to LB_STATUS_INTERNAL_PANIC");

        LbCoreMetrics metrics{};
        metrics.abi = MakeHeader<LbCoreMetrics>();
        REQUIRE_STATUS(fn_metrics(h1, &metrics), LB_STATUS_OK, "mode 1 get_metrics");
        REQUIRE_TRUE(metrics.state == LB_CORE_STATE_FAULTED, "mode 1 transitioned to Faulted");
        REQUIRE_TRUE(metrics.panic_faults >= 1ULL, "mode 1 panic_faults incremented");
        REQUIRE_TRUE(st_track.last_state.load(std::memory_order_seq_cst) == LB_CORE_STATE_FAULTED &&
                         st_track.last_status.load(std::memory_order_seq_cst) == LB_STATUS_INTERNAL_PANIC,
                     "mode 1 state callback reported Faulted + InternalPanic");

        uint8_t msg[256]{};
        size_t msg_len = 0;
        REQUIRE_STATUS(fn_last_error(h1, msg, sizeof(msg), &msg_len), LB_STATUS_OK, "mode 1 get_last_error");
        REQUIRE_TRUE(msg_len > 0U, "mode 1 sanitized error non-empty");

        NativeHeapTracker tracker{};
        LbOwnedBuffer post_fault_buf = MakeTrackedNativeBuffer(tracker, 128, 0x99U);
        const LbEncodedFrameMeta m = MakeValidMeta(1);
        REQUIRE_STATUS(fn_submit_owned(h1, &m, &post_fault_buf), LB_STATUS_FAULTED, "post-fault submit returns LB_STATUS_FAULTED");
        ReleaseTrackedManualFailure(post_fault_buf);

        REQUIRE_STATUS(fn_destroy(h1), LB_STATUS_OK, "mode 1 destroy cleanly");
    }

    // Mode 2: Worker thread panic containment + queued native buffer drain
    {
        NativeHeapTracker tracker{};
        std::atomic<uint32_t> fault_state{999U};
        std::atomic<uint32_t> fault_code{999U};
        struct WorkerCtx {
            std::atomic<uint32_t>* st;
            std::atomic<uint32_t>* code;
        } wctx{&fault_state, &fault_code};

        const auto st_cb = [](void* u, uint32_t s, uint32_t c) noexcept {
            auto* wc = static_cast<WorkerCtx*>(u);
            if (s == LB_CORE_STATE_FAULTED) {
                wc->st->store(s, std::memory_order_seq_cst);
                wc->code->store(c, std::memory_order_seq_cst);
            }
        };

        LbCoreConfig cfg{};
        cfg.abi = MakeHeader<LbCoreConfig>();
        cfg.queue_capacity = 8;
        cfg.expected_frame_bytes_hint = 1024;
        cfg.on_state_change = st_cb;
        cfg.callback_user_ctx = &wctx;

        LbCoreHandle* h2 = nullptr;
        REQUIRE_STATUS(fn_create(&cfg, &h2), LB_STATUS_OK, "mode 2 create");
        REQUIRE_STATUS(fn_start(h2), LB_STATUS_OK, "mode 2 start");

        // Arm worker panic, wake worker with a native owned buffer queued.
        REQUIRE_STATUS(fn_trigger(h2, 2U), LB_STATUS_OK, "mode 2 arm worker panic");
        LbOwnedBuffer qbuf = MakeTrackedNativeBuffer(tracker, 2048, 0xEEU);
        const LbEncodedFrameMeta m = MakeValidMeta(1);
        const LbStatus sub_rc = fn_submit_owned(h2, &m, &qbuf);
        if (sub_rc != LB_STATUS_OK) {
            // Worker panicked before submit lock acquired; submit must reject without calling release.
            REQUIRE_TRUE(sub_rc == LB_STATUS_FAULTED, "unexpected submit status in mode 2");
            ReleaseTrackedManualFailure(qbuf);
        }

        for (int i = 0; i < 200; ++i) {
            if (fault_state.load(std::memory_order_seq_cst) == LB_CORE_STATE_FAULTED) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }

        LbCoreMetrics metrics{};
        metrics.abi = MakeHeader<LbCoreMetrics>();
        REQUIRE_STATUS(fn_metrics(h2, &metrics), LB_STATUS_OK, "mode 2 get_metrics");
        REQUIRE_TRUE(metrics.state == LB_CORE_STATE_FAULTED, "mode 2 worker panic transitioned to Faulted");
        REQUIRE_TRUE(metrics.panic_faults >= 1ULL, "mode 2 panic_faults incremented");
        REQUIRE_TRUE(fault_code.load(std::memory_order_seq_cst) == LB_STATUS_INTERNAL_PANIC,
                     "mode 2 callback received InternalPanic");

        REQUIRE_STATUS(fn_destroy(h2), LB_STATUS_OK, "mode 2 destroy cleanly");
        REQUIRE_TRUE(tracker.allocated.load(std::memory_order_seq_cst) == tracker.released.load(std::memory_order_seq_cst),
                     "mode 2 queued native buffers cleanly released");
    }

    // Mode 3: Transactional pre-commit panic inside submit_owned_boxed (descriptor intact, NOT released by Rust)
    {
        NativeHeapTracker tracker{};
        LbCoreConfig cfg{};
        cfg.abi = MakeHeader<LbCoreConfig>();
        cfg.queue_capacity = 4;
        cfg.expected_frame_bytes_hint = 512;

        LbCoreHandle* h3 = nullptr;
        REQUIRE_STATUS(fn_create(&cfg, &h3), LB_STATUS_OK, "mode 3 create");
        REQUIRE_STATUS(fn_start(h3), LB_STATUS_OK, "mode 3 start");
        REQUIRE_STATUS(fn_trigger(h3, 3U), LB_STATUS_OK, "mode 3 arm pre-commit panic");

        LbOwnedBuffer pre_buf = MakeTrackedNativeBuffer(tracker, 512, 0x33U);
        const LbEncodedFrameMeta m = MakeValidMeta(1);
        REQUIRE_STATUS(fn_submit_owned(h3, &m, &pre_buf), LB_STATUS_INTERNAL_PANIC, "mode 3 pre-commit panic trapped");
        REQUIRE_TRUE(pre_buf.data != nullptr && pre_buf.release != nullptr,
                     "mode 3 caller retains untouched descriptor on pre-commit panic");
        REQUIRE_TRUE(tracker.released.load(std::memory_order_seq_cst) == 0ULL,
                     "mode 3 Rust MUST NOT call release on pre-commit unwind");
        REQUIRE_STATUS(fn_release(&pre_buf), LB_STATUS_OK, "mode 3 caller frees retained buffer once");
        REQUIRE_TRUE(tracker.released.load(std::memory_order_seq_cst) == 1ULL, "mode 3 single release verified");
        REQUIRE_STATUS(fn_destroy(h3), LB_STATUS_OK, "mode 3 destroy cleanly");
    }

    // Mode 4: Transactional post-commit panic inside submit_owned_boxed (descriptor zeroed, Rust drains once)
    {
        NativeHeapTracker tracker{};
        LbCoreConfig cfg{};
        cfg.abi = MakeHeader<LbCoreConfig>();
        cfg.queue_capacity = 4;
        cfg.expected_frame_bytes_hint = 512;

        LbCoreHandle* h4 = nullptr;
        REQUIRE_STATUS(fn_create(&cfg, &h4), LB_STATUS_OK, "mode 4 create");
        REQUIRE_STATUS(fn_start(h4), LB_STATUS_OK, "mode 4 start");
        REQUIRE_STATUS(fn_trigger(h4, 4U), LB_STATUS_OK, "mode 4 arm post-commit panic");

        LbOwnedBuffer post_buf = MakeTrackedNativeBuffer(tracker, 512, 0x44U);
        const LbEncodedFrameMeta m = MakeValidMeta(1);
        REQUIRE_STATUS(fn_submit_owned(h4, &m, &post_buf), LB_STATUS_INTERNAL_PANIC, "mode 4 post-commit panic trapped");
        REQUIRE_TRUE(post_buf.data == nullptr && post_buf.release == nullptr,
                     "mode 4 committed descriptor zeroed even on post-commit panic");
        REQUIRE_TRUE(tracker.released.load(std::memory_order_seq_cst) == 1ULL,
                     "mode 4 Rust drained & released committed buffer exactly once");
        REQUIRE_STATUS(fn_release(&post_buf), LB_STATUS_INVALID_ARGUMENT,
                       "mode 4 defensive caller lb_core_release_buffer is safe no-op without double-free");
        REQUIRE_TRUE(tracker.released.load(std::memory_order_seq_cst) == 1ULL, "mode 4 still released once");
        REQUIRE_STATUS(fn_destroy(h4), LB_STATUS_OK, "mode 4 destroy cleanly");
    }

    LbGlobalResourceCounters after{};
    after.abi = MakeHeader<LbGlobalResourceCounters>();
    REQUIRE_STATUS(fn_global(&after), LB_STATUS_OK, "fault dll global counters");
    REQUIRE_TRUE(after.active_instances == 0ULL && after.active_worker_threads == 0ULL &&
                     after.in_flight_buffers == 0ULL &&
                     after.rust_buffers_allocated == after.rust_buffers_released &&
                     after.native_buffers_received == after.native_buffers_released,
                 "fault dll zero leaked resources after Mode 1..4 panic checks");

    std::printf("[PASS] TestPanicContainmentAndDefaultDllIsolation (Mode 1..4 + prod isolation)\n");
    return true;
}

} // namespace

int wmain(int argc, wchar_t* argv[]) {
    std::wstring faultDllPath;
    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = argv[i];
        if (arg == L"--fault-dll" && (i + 1) < argc) {
            faultDllPath = argv[++i];
        } else {
            std::fwprintf(stderr, L"Usage: LumaBridgeFfiHarness.exe [--fault-dll <path>]\n");
            return 2;
        }
    }

    std::printf("=== LumaBridge M1.1 Native C11/C++20 Qualification Harness ===\n");
    if (!TestAbiLayoutAndVersion()) return 1;
    if (!TestInputValidationAndErrorContract()) return 1;
    if (!TestBidirectionalOwnershipAcrossCrt()) return 1;
    if (!TestBackpressureAndQueueCapacity()) return 1;
    if (!TestConcurrentSubmissionAndReentrantStop()) return 1;
    if (!TestAbruptDisconnectDrainsOwnedBuffers()) return 1;
    if (!TestConcurrentExternalStopsWaitForWorkerAndSingleStopped()) return 1;
    if (!TestAbruptDisconnectRacingConcurrentSubmitters()) return 1;
    if (!TestDeferredRustBufferReleaseAfterDestroy()) return 1;
    if (!TestLifecycle100CyclesAndProcessTelemetry()) return 1;

    if (!faultDllPath.empty()) {
        if (!TestPanicContainmentAndDefaultDllIsolation(faultDllPath)) return 1;
    } else {
        std::printf("[INFO] --fault-dll not supplied; skipping fault-injection DLL dynamic load test.\n");
    }

    std::printf("=== ALL NATIVE QUALIFICATION TESTS PASSED ===\n");
    return 0;
}
