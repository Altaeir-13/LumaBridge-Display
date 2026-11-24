// SPDX-License-Identifier: Apache-2.0
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include "lumabridge_ffi.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fstream>
#include <mutex>
#include <numeric>
#include <string>
#include <thread>
#include <vector>

namespace {

template <typename T>
LbAbiHeader MakeHeader() noexcept {
    LbAbiHeader hdr{};
    hdr.abi_major = LB_FFI_ABI_MAJOR;
    hdr.abi_minor = LB_FFI_ABI_MINOR;
    hdr.struct_size = static_cast<uint32_t>(sizeof(T));
    hdr.reserved = 0;
    return hdr;
}

inline int64_t QueryQpcNow() noexcept {
    LARGE_INTEGER li{};
    QueryPerformanceCounter(&li);
    return li.QuadPart;
}

inline double TicksToUs(int64_t delta_ticks, double qpc_freq_hz) noexcept {
    return (static_cast<double>(delta_ticks) * 1000000.0) / qpc_freq_hz;
}

struct StatsSummary {
    size_t count{0};
    double min_us{0.0};
    double avg_us{0.0};
    double p50_us{0.0};
    double p95_us{0.0};
    double p99_us{0.0};
    double max_us{0.0};
};

StatsSummary ComputeExactPopulationStats(std::vector<double> samples) {
    StatsSummary s{};
    if (samples.empty()) {
        return s;
    }
    std::sort(samples.begin(), samples.end());
    const size_t n = samples.size();
    s.count = n;
    s.min_us = samples.front();
    s.max_us = samples.back();
    const double sum = std::accumulate(samples.begin(), samples.end(), 0.0);
    s.avg_us = sum / static_cast<double>(n);

    auto pick_quantile = [&](double q) -> double {
        const size_t rank = static_cast<size_t>(std::ceil(q * static_cast<double>(n)));
        const size_t idx = (rank == 0U) ? 0U : std::min(rank - 1U, n - 1U);
        return samples[idx];
    };
    s.p50_us = pick_quantile(0.50);
    s.p95_us = pick_quantile(0.95);
    s.p99_us = pick_quantile(0.99);
    return s;
}

// Comparable native C++20 bounded queue + recycle pool implementation used as paired baseline.
class CppBoundedQueueReference {
public:
    explicit CppBoundedQueueReference(size_t capacity)
        : capacity_(capacity) {
        pool_.reserve(capacity);
        for (size_t i = 0; i < capacity; ++i) {
            pool_.emplace_back();
        }
    }

    ~CppBoundedQueueReference() {
        Stop();
    }

    void Start() {
        std::lock_guard<std::mutex> lock(mu_);
        running_ = true;
        stop_requested_ = false;
        worker_ = std::thread([this]() { WorkerLoop(); });
    }

    void Stop() {
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (!running_ && !worker_.joinable()) {
                return;
            }
            stop_requested_ = true;
            running_ = false;
        }
        cv_.notify_all();
        if (worker_.joinable()) {
            worker_.join();
        }
    }

    bool SubmitBorrowed(const LbEncodedFrameMeta& meta, const uint8_t* data, size_t len) noexcept {
        if (meta.session_id == 0ULL || meta.display_id > 0xFFFEU ||
            meta.encode_done_ts_us < meta.capture_ts_us || data == nullptr ||
            len == 0U || len > LB_FFI_MAX_FRAME_BYTES) {
            return false;
        }
        std::lock_guard<std::mutex> lock(mu_);
        if (!running_ || queue_.size() >= capacity_) {
            return false;
        }
        std::vector<uint8_t> buf;
        if (!pool_.empty()) {
            buf = std::move(pool_.back());
            pool_.pop_back();
        }
        buf.resize(len);
        std::memcpy(buf.data(), data, len);

        QueuedPacket pkt{};
        pkt.meta = meta;
        pkt.copied = std::move(buf);
        pkt.is_external = false;
        queue_.push_back(std::move(pkt));
        cv_.notify_one();
        return true;
    }

    bool SubmitOwned(const LbEncodedFrameMeta& meta, LbOwnedBuffer buffer) noexcept {
        if (meta.session_id == 0ULL || meta.display_id > 0xFFFEU ||
            meta.encode_done_ts_us < meta.capture_ts_us || buffer.data == nullptr ||
            buffer.len == 0U || buffer.len > buffer.capacity ||
            buffer.len > LB_FFI_MAX_FRAME_BYTES || buffer.release == nullptr) {
            return false;
        }
        std::lock_guard<std::mutex> lock(mu_);
        if (!running_ || queue_.size() >= capacity_) {
            return false;
        }
        QueuedPacket pkt{};
        pkt.meta = meta;
        pkt.external = buffer;
        pkt.is_external = true;
        queue_.push_back(std::move(pkt));
        cv_.notify_one();
        return true;
    }

    uint64_t ProcessedCount() const noexcept {
        return processed_.load(std::memory_order_seq_cst);
    }

private:
    struct QueuedPacket {
        LbEncodedFrameMeta meta{};
        std::vector<uint8_t> copied;
        LbOwnedBuffer external{};
        bool is_external{false};
    };

    void WorkerLoop() {
        while (true) {
            QueuedPacket item{};
            {
                std::unique_lock<std::mutex> lock(mu_);
                cv_.wait(lock, [this]() { return stop_requested_ || !queue_.empty(); });
                if (stop_requested_ && queue_.empty()) {
                    return;
                }
                item = std::move(queue_.front());
                queue_.pop_front();
            }

            if (item.is_external) {
                std::vector<uint8_t> out(item.external.data, item.external.data + item.external.len);
                item.external.release(item.external.user_ctx, item.external.data, item.external.len, item.external.capacity);
                volatile size_t sink = out.size();
                (void)sink;
            } else {
                std::vector<uint8_t> out(item.copied);
                {
                    std::lock_guard<std::mutex> lock(mu_);
                    if (pool_.size() < capacity_) {
                        item.copied.clear();
                        pool_.push_back(std::move(item.copied));
                    }
                }
                volatile size_t sink = out.size();
                (void)sink;
            }
            processed_.fetch_add(1, std::memory_order_seq_cst);
        }
    }

    size_t capacity_;
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::deque<QueuedPacket> queue_;
    std::vector<std::vector<uint8_t>> pool_;
    std::thread worker_;
    bool running_{false};
    bool stop_requested_{false};
    std::atomic<uint64_t> processed_{0};
};

struct BenchmarkSinkCtx {
    double qpc_freq_hz{1.0};
    std::atomic<bool> collect_latency{false};
    std::mutex mu;
    std::condition_variable cv;
    std::vector<double> worker_latencies_us;
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> active_phase_packets{0};
    std::atomic<uint64_t> errors{0};
};

void BenchmarkOutputCallback(void* user_ctx, const LbEncodedFrameMeta* meta, LbOwnedBuffer owned) noexcept {
    const int64_t rx_qpc = QueryQpcNow();
    auto* ctx = static_cast<BenchmarkSinkCtx*>(user_ctx);
    if (ctx == nullptr || meta == nullptr || owned.data == nullptr || owned.len == 0U) {
        if (ctx != nullptr) {
            ctx->errors.fetch_add(1, std::memory_order_seq_cst);
        }
        if (owned.release != nullptr) {
            (void)lb_core_release_buffer(&owned);
        }
        return;
    }

    if (lb_core_release_buffer(&owned) != LB_STATUS_OK) {
        ctx->errors.fetch_add(1, std::memory_order_seq_cst);
    }

    if (ctx->collect_latency.load(std::memory_order_acquire) && meta->submit_qpc_ticks > 0ULL) {
        const double lat_us = TicksToUs(rx_qpc - static_cast<int64_t>(meta->submit_qpc_ticks), ctx->qpc_freq_hz);
        std::lock_guard<std::mutex> lock(ctx->mu);
        ctx->worker_latencies_us.push_back(lat_us);
    }

    ctx->total_packets.fetch_add(1, std::memory_order_seq_cst);
    ctx->active_phase_packets.fetch_add(1, std::memory_order_seq_cst);
    ctx->cv.notify_all();
}

struct OwnedPoolSlot {
    std::vector<uint8_t> storage;
    std::atomic<bool> in_use{false};
};

void PoolSlotReleaseFn(void* user_ctx, const uint8_t* /*data*/, size_t /*len*/, size_t /*cap*/) noexcept {
    auto* slot = static_cast<OwnedPoolSlot*>(user_ctx);
    if (slot != nullptr) {
        slot->in_use.store(false, std::memory_order_release);
    }
}

void PrintStats(const char* name, const StatsSummary& s) {
    std::printf(
        "%-30s count=%zu min=%.3f avg=%.3f p50=%.3f p95=%.3f p99=%.3f max=%.3f us\n",
        name, s.count, s.min_us, s.avg_us, s.p50_us, s.p95_us, s.p99_us, s.max_us);
}

struct BenchmarkArgs {
    size_t packets{1800};
    size_t warmup{60};
    double pps{60.0};
    bool ci_informative{false};
    std::string json_path;
};

bool ParseArgs(int argc, char* argv[], BenchmarkArgs& out) {
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--packets" && (i + 1) < argc) {
            out.packets = static_cast<size_t>(std::strtoull(argv[++i], nullptr, 10));
        } else if (arg == "--warmup" && (i + 1) < argc) {
            out.warmup = static_cast<size_t>(std::strtoull(argv[++i], nullptr, 10));
        } else if (arg == "--pps" && (i + 1) < argc) {
            out.pps = std::strtod(argv[++i], nullptr);
        } else if (arg == "--json" && (i + 1) < argc) {
            out.json_path = argv[++i];
        } else if (arg == "--ci-informative") {
            out.ci_informative = true;
            out.packets = 300;
            out.warmup = 30;
            out.pps = 0.0;
        } else {
            std::fprintf(stderr, "Unknown argument: %s\n", arg.c_str());
            return false;
        }
    }
    return out.packets > 0;
}

} // namespace

int main(int argc, char* argv[]) {
    BenchmarkArgs args{};
    if (!ParseArgs(argc, argv, args)) {
        return 2;
    }

    LARGE_INTEGER freq{};
    QueryPerformanceFrequency(&freq);
    const double qpc_freq_hz = static_cast<double>(freq.QuadPart);

    LbGlobalResourceCounters before_global{};
    before_global.abi = MakeHeader<LbGlobalResourceCounters>();
    if (lb_core_get_global_resource_counters(&before_global) != LB_STATUS_OK) {
        std::fprintf(stderr, "[FAIL] Failed to query baseline global resource counters.\n");
        return 1;
    }

    constexpr size_t kQueueCapacity = 128;
    constexpr size_t kPoolTemplates = 64;

    // Pre-generate deterministic synthetic H.264 Annex-B packet templates strictly within 30..150 KiB.
    std::vector<std::vector<uint8_t>> templates(kPoolTemplates);
    size_t payload_min = SIZE_MAX;
    size_t payload_max = 0;
    uint64_t payload_sum = 0;

    for (size_t i = 0; i < kPoolTemplates; ++i) {
        const size_t sz = ((i % 60U) == 0U)
                              ? (136U * 1024U + ((i * 257U) % (14U * 1024U)))
                              : (30U * 1024U + ((i * 997U) % (66U * 1024U)));
        templates[i].resize(sz);
        templates[i][0] = 0x00U;
        templates[i][1] = 0x00U;
        templates[i][2] = 0x00U;
        templates[i][3] = 0x01U;
        templates[i][4] = ((i % 60U) == 0U) ? 0x65U : 0x41U;
        for (size_t b = 5; b < sz; ++b) {
            templates[i][b] = static_cast<uint8_t>((b + i) & 0xFFU);
        }
    }

    std::deque<OwnedPoolSlot> rust_owned_slots(kQueueCapacity * 2U);
    std::deque<OwnedPoolSlot> cpp_owned_slots(kQueueCapacity * 2U);
    for (size_t i = 0; i < rust_owned_slots.size(); ++i) {
        rust_owned_slots[i].storage = templates[i % kPoolTemplates];
        cpp_owned_slots[i].storage = templates[i % kPoolTemplates];
    }

    BenchmarkSinkCtx ffi_sink{};
    ffi_sink.qpc_freq_hz = qpc_freq_hz;
    ffi_sink.worker_latencies_us.reserve(args.packets * 2U);

    LbCoreConfig cfg{};
    cfg.abi = MakeHeader<LbCoreConfig>();
    cfg.queue_capacity = static_cast<uint32_t>(kQueueCapacity);
    cfg.expected_frame_bytes_hint = 150U * 1024U;
    cfg.on_output_packet = &BenchmarkOutputCallback;
    cfg.callback_user_ctx = &ffi_sink;

    LbCoreHandle* handle = nullptr;
    if (lb_core_create(&cfg, &handle) != LB_STATUS_OK || handle == nullptr) {
        std::fprintf(stderr, "[FAIL] lb_core_create failed.\n");
        return 1;
    }
    if (lb_core_start(handle) != LB_STATUS_OK) {
        std::fprintf(stderr, "[FAIL] lb_core_start failed.\n");
        (void)lb_core_destroy(handle);
        return 1;
    }

    CppBoundedQueueReference cpp_ref(kQueueCapacity);
    cpp_ref.Start();

    auto run_drain_wait = [&](uint64_t expected_rust, uint64_t expected_cpp) -> bool {
        for (int wait_i = 0; wait_i < 1000; ++wait_i) {
            if (ffi_sink.active_phase_packets.load(std::memory_order_seq_cst) >= expected_rust &&
                cpp_ref.ProcessedCount() >= expected_cpp) {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        return false;
    };

    auto make_meta = [](uint32_t frame_id, size_t idx) noexcept -> LbEncodedFrameMeta {
        LbEncodedFrameMeta m{};
        m.abi = MakeHeader<LbEncodedFrameMeta>();
        m.session_id = 0xCAFEBABE0001ULL;
        m.capture_ts_us = static_cast<uint64_t>(frame_id) * 16667ULL;
        m.encode_done_ts_us = m.capture_ts_us + 200ULL;
        m.submit_qpc_ticks = 0ULL;
        m.codec = static_cast<uint32_t>(LB_ENCODED_CODEC_H264_ANNEX_B);
        m.flags = ((idx % 60U) == 0U) ? 1U : 0U;
        m.frame_id = frame_id;
        m.display_id = 0U;
        m.gop_id = static_cast<uint16_t>((idx / 60U) + 1U);
        return m;
    };

    auto acquire_slot = [](std::deque<OwnedPoolSlot>& pool, size_t start_idx, size_t want_len,
                           const std::vector<uint8_t>& src) -> OwnedPoolSlot* {
        for (size_t attempt = 0; attempt < 2000; ++attempt) {
            for (size_t k = 0; k < pool.size(); ++k) {
                OwnedPoolSlot& s = pool[(start_idx + k) % pool.size()];
                bool expected = false;
                if (s.in_use.compare_exchange_strong(expected, true, std::memory_order_acquire)) {
                    if (s.storage.size() != want_len) {
                        s.storage = src;
                    }
                    return &s;
                }
            }
            std::this_thread::yield();
        }
        return nullptr;
    };

    // 1. Warm-up phase (explicitly drained & discarded before measurement)
    const uint64_t cpp_base_warmup = cpp_ref.ProcessedCount();
    ffi_sink.active_phase_packets.store(0ULL, std::memory_order_seq_cst);
    ffi_sink.collect_latency.store(false, std::memory_order_release);

    for (size_t i = 0; i < args.warmup; ++i) {
        const auto& tpl = templates[i % kPoolTemplates];
        const LbEncodedFrameMeta meta = make_meta(static_cast<uint32_t>(i + 1U), i);
        if (lb_core_submit_encoded_frame(handle, &meta, tpl.data(), tpl.size()) != LB_STATUS_OK) {
            std::fprintf(stderr, "[FAIL] Warmup Rust borrowed submit failed.\n");
            return 1;
        }
        if (!cpp_ref.SubmitBorrowed(meta, tpl.data(), tpl.size())) {
            std::fprintf(stderr, "[FAIL] Warmup C++ borrowed submit failed.\n");
            return 1;
        }

        OwnedPoolSlot* rslot = acquire_slot(rust_owned_slots, i, tpl.size(), tpl);
        OwnedPoolSlot* cslot = acquire_slot(cpp_owned_slots, i, tpl.size(), tpl);
        if (!rslot || !cslot) {
            std::fprintf(stderr, "[FAIL] Warmup pool slot exhausted.\n");
            return 1;
        }
        LbOwnedBuffer rob{rslot->storage.data(), rslot->storage.size(), rslot->storage.capacity(), &PoolSlotReleaseFn, rslot};
        LbOwnedBuffer cob{cslot->storage.data(), cslot->storage.size(), cslot->storage.capacity(), &PoolSlotReleaseFn, cslot};
        if (lb_core_submit_owned_encoded_frame(handle, &meta, &rob) != LB_STATUS_OK ||
            !cpp_ref.SubmitOwned(meta, cob)) {
            std::fprintf(stderr, "[FAIL] Warmup owned submit failed.\n");
            return 1;
        }
        if ((i % 16U) == 15U) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    }
    if (!run_drain_wait(static_cast<uint64_t>(args.warmup) * 2ULL,
                        cpp_base_warmup + static_cast<uint64_t>(args.warmup) * 2ULL)) {
        std::fprintf(stderr, "[FAIL] Warmup drain timeout.\n");
        return 1;
    }

    // 2. Measured steady-state phase (1,800 packets @ 60 pps by default)
    std::vector<double> c_abi_noop_us;
    std::vector<double> cpp_borrowed_us;
    std::vector<double> ffi_borrowed_us;
    std::vector<double> paired_borrowed_overhead_us;
    std::vector<double> cpp_owned_us;
    std::vector<double> ffi_owned_us;
    std::vector<double> paired_owned_overhead_us;

    c_abi_noop_us.reserve(args.packets);
    cpp_borrowed_us.reserve(args.packets);
    ffi_borrowed_us.reserve(args.packets);
    paired_borrowed_overhead_us.reserve(args.packets);
    cpp_owned_us.reserve(args.packets);
    ffi_owned_us.reserve(args.packets);
    paired_owned_overhead_us.reserve(args.packets);

    {
        std::lock_guard<std::mutex> lock(ffi_sink.mu);
        ffi_sink.worker_latencies_us.clear();
    }
    const uint64_t cpp_base_measure = cpp_ref.ProcessedCount();
    ffi_sink.active_phase_packets.store(0ULL, std::memory_order_seq_cst);
    ffi_sink.collect_latency.store(true, std::memory_order_release);

    const int64_t measure_start_qpc = QueryQpcNow();
    const double ticks_per_packet = (args.pps > 0.0) ? (qpc_freq_hz / args.pps) : 0.0;

    for (size_t i = 0; i < args.packets; ++i) {
        if (args.pps > 0.0 && i > 0U) {
            const int64_t target_qpc = measure_start_qpc + static_cast<int64_t>(std::llround(static_cast<double>(i) * ticks_per_packet));
            for (;;) {
                const int64_t now = QueryQpcNow();
                if (now >= target_qpc) {
                    break;
                }
                const double rem_ms = (static_cast<double>(target_qpc - now) * 1000.0) / qpc_freq_hz;
                if (rem_ms > 2.0) {
                    Sleep(static_cast<DWORD>(rem_ms - 1.0));
                } else {
                    std::this_thread::yield();
                }
            }
        }

        const size_t tpl_idx = (i + args.warmup) % kPoolTemplates;
        const auto& tpl = templates[tpl_idx];
        payload_min = std::min(payload_min, tpl.size());
        payload_max = std::max(payload_max, tpl.size());
        payload_sum += static_cast<uint64_t>(tpl.size());

        LbEncodedFrameMeta meta = make_meta(static_cast<uint32_t>(args.warmup + i + 1U), i);

        // (a) Pure C ABI empty crossing overhead
        uint32_t maj = 0;
        uint32_t minv = 0;
        const int64_t noop_t0 = QueryQpcNow();
        const LbStatus noop_st = lb_core_abi_version(&maj, &minv);
        const int64_t noop_t1 = QueryQpcNow();
        if (noop_st != LB_STATUS_OK) {
            std::fprintf(stderr, "[FAIL] lb_core_abi_version failed during measurement.\n");
            return 1;
        }
        c_abi_noop_us.push_back(TicksToUs(noop_t1 - noop_t0, qpc_freq_hz));

        // (b) Paired borrowed submission: alternate execution order on even/odd samples
        double t_cpp_bor = 0.0;
        double t_ffi_bor = 0.0;
        if ((i % 2U) == 0U) {
            const int64_t c0 = QueryQpcNow();
            const bool cok = cpp_ref.SubmitBorrowed(meta, tpl.data(), tpl.size());
            const int64_t c1 = QueryQpcNow();
            if (!cok) {
                std::fprintf(stderr, "[FAIL] C++ SubmitBorrowed rejected at i=%zu.\n", i);
                return 1;
            }
            t_cpp_bor = TicksToUs(c1 - c0, qpc_freq_hz);

            const int64_t r0 = QueryQpcNow();
            meta.submit_qpc_ticks = static_cast<uint64_t>(r0);
            const LbStatus rst = lb_core_submit_encoded_frame(handle, &meta, tpl.data(), tpl.size());
            const int64_t r1 = QueryQpcNow();
            if (rst != LB_STATUS_OK) {
                std::fprintf(stderr, "[FAIL] Rust lb_core_submit_encoded_frame failed (%u) at i=%zu.\n", rst, i);
                return 1;
            }
            t_ffi_bor = TicksToUs(r1 - r0, qpc_freq_hz);
        } else {
            const int64_t r0 = QueryQpcNow();
            meta.submit_qpc_ticks = static_cast<uint64_t>(r0);
            const LbStatus rst = lb_core_submit_encoded_frame(handle, &meta, tpl.data(), tpl.size());
            const int64_t r1 = QueryQpcNow();
            if (rst != LB_STATUS_OK) {
                std::fprintf(stderr, "[FAIL] Rust lb_core_submit_encoded_frame failed (%u) at i=%zu.\n", rst, i);
                return 1;
            }
            t_ffi_bor = TicksToUs(r1 - r0, qpc_freq_hz);

            const int64_t c0 = QueryQpcNow();
            const bool cok = cpp_ref.SubmitBorrowed(meta, tpl.data(), tpl.size());
            const int64_t c1 = QueryQpcNow();
            if (!cok) {
                std::fprintf(stderr, "[FAIL] C++ SubmitBorrowed rejected at i=%zu.\n", i);
                return 1;
            }
            t_cpp_bor = TicksToUs(c1 - c0, qpc_freq_hz);
        }
        cpp_borrowed_us.push_back(t_cpp_bor);
        ffi_borrowed_us.push_back(t_ffi_bor);
        paired_borrowed_overhead_us.push_back(t_ffi_bor - t_cpp_bor);

        // (c) Paired owned transfer submission (native LbOwnedBuffer -> queue without submit-time payload copy)
        OwnedPoolSlot* rslot = acquire_slot(rust_owned_slots, i, tpl.size(), tpl);
        OwnedPoolSlot* cslot = acquire_slot(cpp_owned_slots, i, tpl.size(), tpl);
        if (!rslot || !cslot) {
            std::fprintf(stderr, "[FAIL] Pool slot exhausted during measurement at i=%zu.\n", i);
            return 1;
        }
        LbOwnedBuffer rob{rslot->storage.data(), rslot->storage.size(), rslot->storage.capacity(), &PoolSlotReleaseFn, rslot};
        LbOwnedBuffer cob{cslot->storage.data(), cslot->storage.size(), cslot->storage.capacity(), &PoolSlotReleaseFn, cslot};

        double t_cpp_own = 0.0;
        double t_ffi_own = 0.0;
        if ((i % 2U) == 0U) {
            const int64_t c0 = QueryQpcNow();
            const bool cok = cpp_ref.SubmitOwned(meta, cob);
            const int64_t c1 = QueryQpcNow();
            if (!cok) {
                cslot->in_use.store(false, std::memory_order_release);
                std::fprintf(stderr, "[FAIL] C++ SubmitOwned rejected at i=%zu.\n", i);
                return 1;
            }
            t_cpp_own = TicksToUs(c1 - c0, qpc_freq_hz);

            const int64_t r0 = QueryQpcNow();
            meta.submit_qpc_ticks = static_cast<uint64_t>(r0);
            const LbStatus rst = lb_core_submit_owned_encoded_frame(handle, &meta, &rob);
            const int64_t r1 = QueryQpcNow();
            if (rst != LB_STATUS_OK) {
                rslot->in_use.store(false, std::memory_order_release);
                std::fprintf(stderr, "[FAIL] Rust lb_core_submit_owned_encoded_frame failed (%u) at i=%zu.\n", rst, i);
                return 1;
            }
            t_ffi_own = TicksToUs(r1 - r0, qpc_freq_hz);
        } else {
            const int64_t r0 = QueryQpcNow();
            meta.submit_qpc_ticks = static_cast<uint64_t>(r0);
            const LbStatus rst = lb_core_submit_owned_encoded_frame(handle, &meta, &rob);
            const int64_t r1 = QueryQpcNow();
            if (rst != LB_STATUS_OK) {
                rslot->in_use.store(false, std::memory_order_release);
                std::fprintf(stderr, "[FAIL] Rust lb_core_submit_owned_encoded_frame failed (%u) at i=%zu.\n", rst, i);
                return 1;
            }
            t_ffi_own = TicksToUs(r1 - r0, qpc_freq_hz);

            const int64_t c0 = QueryQpcNow();
            const bool cok = cpp_ref.SubmitOwned(meta, cob);
            const int64_t c1 = QueryQpcNow();
            if (!cok) {
                cslot->in_use.store(false, std::memory_order_release);
                std::fprintf(stderr, "[FAIL] C++ SubmitOwned rejected at i=%zu.\n", i);
                return 1;
            }
            t_cpp_own = TicksToUs(c1 - c0, qpc_freq_hz);
        }
        cpp_owned_us.push_back(t_cpp_own);
        ffi_owned_us.push_back(t_ffi_own);
        paired_owned_overhead_us.push_back(t_ffi_own - t_cpp_own);
    }

    const int64_t measure_end_qpc = QueryQpcNow();
    const double elapsed_sec = TicksToUs(measure_end_qpc - measure_start_qpc, qpc_freq_hz) / 1000000.0;

    if (!run_drain_wait(static_cast<uint64_t>(args.packets) * 2ULL,
                        cpp_base_measure + static_cast<uint64_t>(args.packets) * 2ULL)) {
        std::fprintf(stderr, "[FAIL] Timed out waiting for final drain.\n");
        (void)lb_core_stop(handle);
        (void)lb_core_destroy(handle);
        return 1;
    }

    LbCoreMetrics core_metrics{};
    core_metrics.abi = MakeHeader<LbCoreMetrics>();
    (void)lb_core_get_metrics(handle, &core_metrics);

    (void)lb_core_stop(handle);
    cpp_ref.Stop();
    (void)lb_core_destroy(handle);

    LbGlobalResourceCounters after_global{};
    after_global.abi = MakeHeader<LbGlobalResourceCounters>();
    (void)lb_core_get_global_resource_counters(&after_global);

    std::vector<double> worker_lats;
    {
        std::lock_guard<std::mutex> lock(ffi_sink.mu);
        worker_lats = ffi_sink.worker_latencies_us;
    }

    const StatsSummary s_noop = ComputeExactPopulationStats(c_abi_noop_us);
    const StatsSummary s_cpp_bor = ComputeExactPopulationStats(cpp_borrowed_us);
    const StatsSummary s_ffi_bor = ComputeExactPopulationStats(ffi_borrowed_us);
    const StatsSummary s_pair_bor = ComputeExactPopulationStats(paired_borrowed_overhead_us);
    const StatsSummary s_cpp_own = ComputeExactPopulationStats(cpp_owned_us);
    const StatsSummary s_ffi_own = ComputeExactPopulationStats(ffi_owned_us);
    const StatsSummary s_pair_own = ComputeExactPopulationStats(paired_owned_overhead_us);
    const StatsSummary s_worker = ComputeExactPopulationStats(worker_lats);

    const double payload_avg = static_cast<double>(payload_sum) / static_cast<double>(args.packets);
    const uint64_t expected_total = static_cast<uint64_t>(args.warmup + args.packets) * 2ULL;

    const bool counters_ok =
        (ffi_sink.errors.load(std::memory_order_seq_cst) == 0ULL) &&
        (core_metrics.backpressure_events == 0ULL) &&
        (core_metrics.packets_processed == expected_total) &&
        (after_global.active_instances == before_global.active_instances) &&
        (after_global.active_worker_threads == before_global.active_worker_threads) &&
        (after_global.in_flight_buffers == before_global.in_flight_buffers) &&
        ((after_global.rust_buffers_allocated - before_global.rust_buffers_allocated) ==
         (after_global.rust_buffers_released - before_global.rust_buffers_released)) &&
        ((after_global.native_buffers_received - before_global.native_buffers_received) ==
         (after_global.native_buffers_released - before_global.native_buffers_released));

    const bool gate_ok =
        (s_ffi_bor.p99_us < 100.0) &&
        (s_ffi_own.p99_us < 100.0) &&
        (s_pair_bor.p99_us < 100.0) &&
        (s_pair_own.p99_us < 100.0);

    std::printf("=== LumaBridge M1.1 FFI Overhead Benchmark ===\n");
    std::printf("Mode: %s | Packets: %zu (+%zu warmup) | Pacing: %.1f pps | Elapsed: %.3f s | QPC_Hz: %.0f\n",
                args.ci_informative ? "CI_INFORMATIVE" : "LOCAL_RELEASE_GATED",
                args.packets, args.warmup, args.pps, elapsed_sec, qpc_freq_hz);
    std::printf("Payload bytes (30-150 KiB): min=%zu avg=%.1f max=%zu\n", payload_min, payload_avg, payload_max);
    PrintStats("c_abi_noop", s_noop);
    PrintStats("cpp_ref_borrowed_submit", s_cpp_bor);
    PrintStats("ffi_borrowed_submit", s_ffi_bor);
    PrintStats("paired_borrowed_overhead", s_pair_bor);
    PrintStats("cpp_ref_owned_submit", s_cpp_own);
    PrintStats("ffi_owned_submit", s_ffi_own);
    PrintStats("paired_owned_overhead", s_pair_own);
    PrintStats("async_worker_e2e_lat", s_worker);
    std::printf("Packets processed=%llu backpressure=%llu rust_buf_bal=%lld native_buf_bal=%lld\n",
                static_cast<unsigned long long>(core_metrics.packets_processed),
                static_cast<unsigned long long>(core_metrics.backpressure_events),
                static_cast<long long>((after_global.rust_buffers_allocated - before_global.rust_buffers_allocated) -
                                       (after_global.rust_buffers_released - before_global.rust_buffers_released)),
                static_cast<long long>((after_global.native_buffers_received - before_global.native_buffers_received) -
                                       (after_global.native_buffers_released - before_global.native_buffers_released)));
    std::printf("CountersBalanced=%s | P99Gate(<100us)=%s\n",
                counters_ok ? "TRUE" : "FALSE", gate_ok ? "PASS" : "FAIL");

    if (!args.json_path.empty()) {
        std::ofstream jf(args.json_path);
        if (jf.is_open()) {
            auto write_s = [&](const char* key, const StatsSummary& st, bool trailing) {
                jf << "    \"" << key << "\": {\"count\": " << st.count
                   << ", \"min_us\": " << st.min_us << ", \"avg_us\": " << st.avg_us
                   << ", \"p50_us\": " << st.p50_us << ", \"p95_us\": " << st.p95_us
                   << ", \"p99_us\": " << st.p99_us << ", \"max_us\": " << st.max_us << "}"
                   << (trailing ? ",\n" : "\n");
            };
            jf << "{\n"
               << "  \"mode\": \"" << (args.ci_informative ? "ci_informative" : "local_release_gated") << "\",\n"
               << "  \"packets\": " << args.packets << ",\n"
               << "  \"warmup\": " << args.warmup << ",\n"
               << "  \"pps\": " << args.pps << ",\n"
               << "  \"elapsed_sec\": " << elapsed_sec << ",\n"
               << "  \"qpc_freq_hz\": " << qpc_freq_hz << ",\n"
               << "  \"payload_min_bytes\": " << payload_min << ",\n"
               << "  \"payload_avg_bytes\": " << payload_avg << ",\n"
               << "  \"payload_max_bytes\": " << payload_max << ",\n"
               << "  \"counters_balanced\": " << (counters_ok ? "true" : "false") << ",\n"
               << "  \"p99_gate_passed\": " << (gate_ok ? "true" : "false") << ",\n"
               << "  \"percentile_method\": \"ExactPopulation\",\n"
               << "  \"stats\": {\n";
            write_s("c_abi_noop", s_noop, true);
            write_s("cpp_ref_borrowed_submit", s_cpp_bor, true);
            write_s("ffi_borrowed_submit", s_ffi_bor, true);
            write_s("paired_borrowed_overhead", s_pair_bor, true);
            write_s("cpp_ref_owned_submit", s_cpp_own, true);
            write_s("ffi_owned_submit", s_ffi_own, true);
            write_s("paired_owned_overhead", s_pair_own, true);
            write_s("async_worker_e2e_lat", s_worker, false);
            jf << "  }\n}\n";
        }
    }

    if (!counters_ok) {
        return 1;
    }
    if (!args.ci_informative && !gate_ok) {
        return 1;
    }
    return 0;
}
