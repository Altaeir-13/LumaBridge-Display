#pragma once

#include <Windows.h>
#include <objbase.h>

#include "H264BitstreamValidator.h"
#include "NvencH264Encoder.h"

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <new>
#include <string>
#include <thread>
#include <utility>

namespace lumabridge::host {

enum class H264WorkerCompletionState : uint32_t
{
    NotStarted = 0U,
    Running = 1U,
    NormalShutdown = 2U,
    StartFailed = 3U,
    EnqueueTimeout = 4U,
    EnqueueRejected = 5U,
    DecodeError = 6U,
    DrainFailed = 7U,
    WatchdogForcedTermination = 8U,
};

inline const char*
H264WorkerCompletionStateToString(
    H264WorkerCompletionState state
    ) noexcept
{
    switch (state)
    {
    case H264WorkerCompletionState::NotStarted:
        return "NotStarted";
    case H264WorkerCompletionState::Running:
        return "Running";
    case H264WorkerCompletionState::NormalShutdown:
        return "NormalShutdown";
    case H264WorkerCompletionState::StartFailed:
        return "StartFailed";
    case H264WorkerCompletionState::EnqueueTimeout:
        return "EnqueueTimeout";
    case H264WorkerCompletionState::EnqueueRejected:
        return "EnqueueRejected";
    case H264WorkerCompletionState::DecodeError:
        return "DecodeError";
    case H264WorkerCompletionState::DrainFailed:
        return "DrainFailed";
    case H264WorkerCompletionState::WatchdogForcedTermination:
        return "WatchdogForcedTermination";
    default:
        return "Unknown";
    }
}

enum class H264WorkerEnqueueStatus : uint32_t
{
    Enqueued = 0U,
    ProcessedSynchronously = 1U,
    RejectedNotStarted = 2U,
    RejectedStopping = 3U,
    RejectedWorkerFailed = 4U,
    TimedOutQueueFull = 5U,
    AllocationFailed = 6U,
};

inline const char*
H264WorkerEnqueueStatusToString(
    H264WorkerEnqueueStatus status
    ) noexcept
{
    switch (status)
    {
    case H264WorkerEnqueueStatus::Enqueued:
        return "Enqueued";
    case H264WorkerEnqueueStatus::ProcessedSynchronously:
        return "ProcessedSynchronously";
    case H264WorkerEnqueueStatus::RejectedNotStarted:
        return "RejectedNotStarted";
    case H264WorkerEnqueueStatus::RejectedStopping:
        return "RejectedStopping";
    case H264WorkerEnqueueStatus::RejectedWorkerFailed:
        return "RejectedWorkerFailed";
    case H264WorkerEnqueueStatus::TimedOutQueueFull:
        return "TimedOutQueueFull";
    case H264WorkerEnqueueStatus::AllocationFailed:
        return "AllocationFailed";
    default:
        return "Unknown";
    }
}

struct H264WorkerConfig
{
    size_t MaxQueueCapacity{256U};
    uint32_t StartupTimeoutMs{10000U};
    uint32_t EnqueueTimeoutMs{5000U};
    uint32_t DrainWaitTimeoutMs{15000U};
    /// Explicitly opts into distinct synchronous fallback lifecycle on the caller thread if async startup fails.
    /// Production validation keeps this false so async worker startup failures are never masked.
    bool AllowSynchronousFallback{false};
};

/// Testability seam for deterministically exercising allocation/push failures in Enqueue().
class IH264WorkerHooks
{
public:
    virtual ~IH264WorkerHooks() = default;

    virtual void OnBeforeQueuePush()
    {
    }
};

struct H264WorkerMetricsSnapshot
{
    bool Enabled{false};
    bool Started{false};
    bool Healthy{false};
    bool SynchronousFallbackActive{false};
    size_t QueueCapacity{256U};
    uint64_t PacketsEnqueued{0ULL};
    uint64_t PacketsDequeued{0ULL};
    uint64_t PacketsProcessed{0ULL};
    uint64_t PacketsRejected{0ULL};
    uint64_t QueuePeakDepth{0ULL};
    uint64_t QueuePendingAtShutdown{0ULL};
    uint64_t QueueRemainingAtExit{0ULL};
    uint64_t QueueFullWaitCount{0ULL};
    uint64_t QueueWaitTimeoutCount{0ULL};
    uint64_t WorkerFailureCount{0ULL};
    bool DrainDeadlineExceeded{false};
    bool ComBalanced{false};
    uint32_t WorkerComInitCount{0U};
    uint32_t WorkerComUninitCount{0U};
    DWORD WorkerThreadId{0U};
    DWORD WorkerComInitThreadId{0U};
    DWORD WorkerComUninitThreadId{0U};
    DecoderLifecycleDiagnostics DecoderLifecycle{};
    H264WorkerCompletionState CompletionState{H264WorkerCompletionState::NotStarted};
    HRESULT LastHResult{S_OK};
    std::string LastErrorMessage{};
};

/// Bounded-queue asynchronous H.264 validation worker running COM MTA + Media Foundation on its own thread.
///
/// NOTE ON THREAD JOIN SAFETY: If a synchronous third-party/OS MFT call hangs indefinitely inside
/// WorkerProc, std::thread cannot be safely aborted in-process without TerminateThread or detach(),
/// both of which risk resource corruption. After DrainWaitTimeoutMs expires, StopAndDrain records
/// DrainDeadlineExceeded/DrainFailed and still joins safely; the caller process HardTimeoutMs
/// remains the final external containment boundary.
class AsyncH264ValidationWorker final
{
public:
    static constexpr size_t kMaxQueueCapacity = 256U;

    explicit AsyncH264ValidationWorker(
        H264StreamValidationSession& session,
        H264WorkerConfig config = {},
        IH264WorkerHooks* hooks = nullptr
        ) noexcept
        : m_session(session),
          m_config(config),
          m_hooks(hooks)
    {
        if (m_config.MaxQueueCapacity == 0U)
        {
            m_config.MaxQueueCapacity = kMaxQueueCapacity;
        }
        m_metrics.QueueCapacity = m_config.MaxQueueCapacity;
    }

    ~AsyncH264ValidationWorker()
    {
        StopAndDrain(false);
    }

    AsyncH264ValidationWorker(const AsyncH264ValidationWorker&) = delete;
    AsyncH264ValidationWorker& operator=(const AsyncH264ValidationWorker&) = delete;

    void SetHooks(IH264WorkerHooks* hooks) noexcept
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_hooks = hooks;
    }

    bool Start(
        uint32_t prewarmWidth,
        uint32_t prewarmHeight,
        uint32_t prewarmFps
        ) noexcept
    {
        StopAndDrain(false);

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_queue.clear();
            m_stopRequested = false;
            m_ready = false;
            m_startSucceeded = false;
            m_startFailed = false;
            m_workerExited = false;
            m_started = true;
            m_drainFailed = false;
            m_syncFallbackComInit = false;
            m_syncFallbackThreadId = 0U;
            m_finalSummary = {};
            m_metrics = {};
            m_metrics.Enabled = true;
            m_metrics.Started = true;
            m_metrics.QueueCapacity = m_config.MaxQueueCapacity;
            m_metrics.CompletionState = H264WorkerCompletionState::Running;
        }

        try
        {
            m_worker = std::thread(
                &AsyncH264ValidationWorker::WorkerProc,
                this,
                prewarmWidth,
                prewarmHeight,
                prewarmFps);
        }
        catch (const std::exception& ex)
        {
            return HandleAsyncStartFailure(E_OUTOFMEMORY, ex.what());
        }
        catch (...)
        {
            return HandleAsyncStartFailure(E_FAIL, "Failed spawning AsyncH264ValidationWorker thread.");
        }

        bool readyWithinBudget = false;
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            const auto deadline =
                std::chrono::steady_clock::now() + std::chrono::milliseconds(m_config.StartupTimeoutMs);
            readyWithinBudget = m_readyCv.wait_until(lock, deadline, [this]() { return m_ready; });
            if (!readyWithinBudget)
            {
                m_startFailed = true;
                m_stopRequested = true;
                m_started = false;
                m_metrics.Started = false;
                ++m_metrics.WorkerFailureCount;
                m_metrics.CompletionState = H264WorkerCompletionState::StartFailed;
                m_metrics.LastHResult = HRESULT_FROM_WIN32(ERROR_TIMEOUT);
                m_metrics.LastErrorMessage = "AsyncH264ValidationWorker startup timed out waiting for worker readiness.";
            }
        }

        if (!readyWithinBudget)
        {
            m_notEmptyCv.notify_all();
            m_notFullCv.notify_all();
            if (m_worker.joinable())
            {
                m_worker.join();
            }
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                UpdateComBalancedLocked();
            }
            return TryActivateSynchronousFallback(prewarmWidth, prewarmHeight, prewarmFps);
        }

        bool startOk = false;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            startOk = m_startSucceeded && !m_startFailed;
        }

        if (!startOk)
        {
            if (m_worker.joinable())
            {
                m_worker.join();
            }
            std::lock_guard<std::mutex> lock(m_mutex);
            m_started = false;
            m_metrics.Started = false;
            m_metrics.CompletionState = H264WorkerCompletionState::StartFailed;
            UpdateComBalancedLocked();
            return TryActivateSynchronousFallbackLocked(prewarmWidth, prewarmHeight, prewarmFps);
        }

        return true;
    }

    H264WorkerEnqueueStatus Enqueue(EncodedFramePacket&& packet) noexcept
    {
        std::unique_lock<std::mutex> lock(m_mutex);

        if (m_metrics.SynchronousFallbackActive)
        {
            if (m_stopRequested)
            {
                ++m_metrics.PacketsRejected;
                ++m_metrics.WorkerFailureCount;
                RecordEnqueueRejectionStateLocked(
                    H264WorkerCompletionState::EnqueueRejected,
                    HRESULT_FROM_WIN32(ERROR_CANCELLED),
                    "Enqueue rejected after StopAndDrain requested (synchronous fallback).");
                return H264WorkerEnqueueStatus::RejectedStopping;
            }
            ++m_metrics.PacketsEnqueued;
            lock.unlock();
            m_session.SubmitPacket(packet);
            lock.lock();
            ++m_metrics.PacketsProcessed;
            return H264WorkerEnqueueStatus::ProcessedSynchronously;
        }

        if (!m_started)
        {
            ++m_metrics.PacketsRejected;
            ++m_metrics.WorkerFailureCount;
            if (m_metrics.CompletionState != H264WorkerCompletionState::StartFailed)
            {
                RecordEnqueueRejectionStateLocked(
                    H264WorkerCompletionState::EnqueueRejected,
                    E_NOT_VALID_STATE,
                    "Enqueue rejected because AsyncH264ValidationWorker is not started.");
            }
            return (m_metrics.CompletionState == H264WorkerCompletionState::StartFailed)
                ? H264WorkerEnqueueStatus::RejectedWorkerFailed
                : H264WorkerEnqueueStatus::RejectedNotStarted;
        }

        if (m_stopRequested)
        {
            ++m_metrics.PacketsRejected;
            ++m_metrics.WorkerFailureCount;
            RecordEnqueueRejectionStateLocked(
                H264WorkerCompletionState::EnqueueRejected,
                HRESULT_FROM_WIN32(ERROR_CANCELLED),
                "Enqueue rejected after StopAndDrain was requested.");
            return H264WorkerEnqueueStatus::RejectedStopping;
        }

        if (m_startFailed || m_workerExited)
        {
            ++m_metrics.PacketsRejected;
            ++m_metrics.WorkerFailureCount;
            RecordEnqueueRejectionStateLocked(
                H264WorkerCompletionState::EnqueueRejected,
                FAILED(m_metrics.LastHResult) ? m_metrics.LastHResult : E_FAIL,
                "Enqueue rejected because worker already terminated or failed.");
            return H264WorkerEnqueueStatus::RejectedWorkerFailed;
        }

        if (m_queue.size() >= m_config.MaxQueueCapacity)
        {
            ++m_metrics.QueueFullWaitCount;
            const auto deadline =
                std::chrono::steady_clock::now() + std::chrono::milliseconds(m_config.EnqueueTimeoutMs);
            const bool spaceAvailable = m_notFullCv.wait_until(lock, deadline, [this]() {
                return m_stopRequested || m_startFailed || m_workerExited ||
                       (m_queue.size() < m_config.MaxQueueCapacity);
            });

            if (!spaceAvailable)
            {
                ++m_metrics.QueueWaitTimeoutCount;
                ++m_metrics.PacketsRejected;
                ++m_metrics.WorkerFailureCount;
                RecordEnqueueRejectionStateLocked(
                    H264WorkerCompletionState::EnqueueTimeout,
                    HRESULT_FROM_WIN32(ERROR_TIMEOUT),
                    "Timed out waiting for bounded MFT validation queue capacity.");
                return H264WorkerEnqueueStatus::TimedOutQueueFull;
            }

            if (m_stopRequested)
            {
                ++m_metrics.PacketsRejected;
                ++m_metrics.WorkerFailureCount;
                RecordEnqueueRejectionStateLocked(
                    H264WorkerCompletionState::EnqueueRejected,
                    HRESULT_FROM_WIN32(ERROR_CANCELLED),
                    "Enqueue aborted because StopAndDrain was signaled while queue was full.");
                return H264WorkerEnqueueStatus::RejectedStopping;
            }

            if (m_startFailed || m_workerExited)
            {
                ++m_metrics.PacketsRejected;
                ++m_metrics.WorkerFailureCount;
                RecordEnqueueRejectionStateLocked(
                    H264WorkerCompletionState::EnqueueRejected,
                    FAILED(m_metrics.LastHResult) ? m_metrics.LastHResult : E_FAIL,
                    "Enqueue rejected because worker stopped unexpectedly while waiting for space.");
                return H264WorkerEnqueueStatus::RejectedWorkerFailed;
            }
        }

        try
        {
            if (m_hooks != nullptr)
            {
                m_hooks->OnBeforeQueuePush();
            }
            m_queue.push_back(std::move(packet));
        }
        catch (const std::bad_alloc&)
        {
            ++m_metrics.PacketsRejected;
            ++m_metrics.WorkerFailureCount;
            RecordEnqueueRejectionStateLocked(
                H264WorkerCompletionState::EnqueueRejected,
                E_OUTOFMEMORY,
                "Out of memory while enqueueing encoded packet to MFT validation worker.");
            return H264WorkerEnqueueStatus::AllocationFailed;
        }
        catch (const std::exception& ex)
        {
            ++m_metrics.PacketsRejected;
            ++m_metrics.WorkerFailureCount;
            RecordEnqueueRejectionStateLocked(
                H264WorkerCompletionState::EnqueueRejected,
                E_FAIL,
                ex.what());
            return H264WorkerEnqueueStatus::AllocationFailed;
        }
        catch (...)
        {
            ++m_metrics.PacketsRejected;
            ++m_metrics.WorkerFailureCount;
            RecordEnqueueRejectionStateLocked(
                H264WorkerCompletionState::EnqueueRejected,
                E_FAIL,
                "Unexpected exception while enqueueing encoded packet to MFT validation worker.");
            return H264WorkerEnqueueStatus::AllocationFailed;
        }

        ++m_metrics.PacketsEnqueued;
        if (static_cast<uint64_t>(m_queue.size()) > m_metrics.QueuePeakDepth)
        {
            m_metrics.QueuePeakDepth = static_cast<uint64_t>(m_queue.size());
        }
        lock.unlock();
        m_notEmptyCv.notify_one();
        return H264WorkerEnqueueStatus::Enqueued;
    }

    void StopAndDrain(bool watchdogForced = false) noexcept
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_metrics.SynchronousFallbackActive)
            {
                m_stopRequested = true;
                m_metrics.QueuePendingAtShutdown = 0ULL;
                m_metrics.QueueRemainingAtExit = 0ULL;
                m_session.Finish();
                m_finalSummary = m_session.GetSummary();
                m_drainFailed = m_session.HasDrainFailure();
                m_session.Shutdown();
                if (m_syncFallbackComInit && GetCurrentThreadId() == m_syncFallbackThreadId)
                {
                    CoUninitialize();
                    m_syncFallbackComInit = false;
                    ++m_metrics.WorkerComUninitCount;
                    m_metrics.WorkerComUninitThreadId = GetCurrentThreadId();
                }
                m_metrics.DecoderLifecycle = m_session.GetDecoderLifecycleDiagnostics();
                m_metrics.SynchronousFallbackActive = false;
                m_started = false;
                m_metrics.Started = false;
                FinalizeCompletionLocked(watchdogForced);
                return;
            }

            if (!m_started && !m_worker.joinable())
            {
                if (watchdogForced && m_metrics.Enabled &&
                    m_metrics.CompletionState != H264WorkerCompletionState::StartFailed)
                {
                    m_metrics.CompletionState = H264WorkerCompletionState::WatchdogForcedTermination;
                    ++m_metrics.WorkerFailureCount;
                    m_metrics.Healthy = false;
                }
                return;
            }

            if (!m_stopRequested)
            {
                m_metrics.QueuePendingAtShutdown = static_cast<uint64_t>(m_queue.size());
                m_stopRequested = true;
            }
        }

        m_notEmptyCv.notify_all();
        m_notFullCv.notify_all();

        {
            std::unique_lock<std::mutex> lock(m_mutex);
            const auto drainDeadline =
                std::chrono::steady_clock::now() + std::chrono::milliseconds(m_config.DrainWaitTimeoutMs);
            const bool exitedBeforeDeadline =
                m_drainDoneCv.wait_until(lock, drainDeadline, [this]() { return m_workerExited; });
            if (!exitedBeforeDeadline)
            {
                m_metrics.DrainDeadlineExceeded = true;
                ++m_metrics.WorkerFailureCount;
                m_metrics.LastHResult = HRESULT_FROM_WIN32(ERROR_TIMEOUT);
                m_metrics.LastErrorMessage =
                    "AsyncH264ValidationWorker exceeded DrainWaitTimeoutMs before exiting; awaiting thread join.";
            }
        }

        if (m_worker.joinable())
        {
            m_worker.join();
        }

        std::lock_guard<std::mutex> lock(m_mutex);
        m_started = false;
        m_metrics.Started = false;
        FinalizeCompletionLocked(watchdogForced);
    }

    H264WorkerMetricsSnapshot GetMetricsSnapshot() const noexcept
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_metrics;
    }

    H264ValidationSummary GetFinalSessionSummary() const noexcept
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_metrics.Enabled ? m_finalSummary : m_session.GetSummary();
    }

private:
    bool HandleAsyncStartFailure(HRESULT hr, const char* msg) noexcept
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_started = false;
            m_startFailed = true;
            m_metrics.Started = false;
            ++m_metrics.WorkerFailureCount;
            m_metrics.CompletionState = H264WorkerCompletionState::StartFailed;
            m_metrics.LastHResult = hr;
            m_metrics.LastErrorMessage = (msg != nullptr) ? msg : "AsyncH264ValidationWorker start error.";
        }
        return TryActivateSynchronousFallback(0U, 0U, 0U);
    }

    bool TryActivateSynchronousFallback(
        uint32_t prewarmWidth,
        uint32_t prewarmHeight,
        uint32_t prewarmFps
        ) noexcept
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return TryActivateSynchronousFallbackLocked(prewarmWidth, prewarmHeight, prewarmFps);
    }

    bool TryActivateSynchronousFallbackLocked(
        uint32_t prewarmWidth,
        uint32_t prewarmHeight,
        uint32_t prewarmFps
        ) noexcept
    {
        if (!m_config.AllowSynchronousFallback)
        {
            return false;
        }

        const DWORD callerTid = GetCurrentThreadId();
        const HRESULT comHr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (SUCCEEDED(comHr))
        {
            m_syncFallbackComInit = true;
            m_syncFallbackThreadId = callerTid;
            m_metrics.WorkerComInitCount = 1U;
            m_metrics.WorkerComUninitCount = 0U;
            m_metrics.WorkerComInitThreadId = callerTid;
            m_metrics.WorkerComUninitThreadId = 0U;
        }
        else if (comHr != RPC_E_CHANGED_MODE)
        {
            ++m_metrics.WorkerFailureCount;
            m_metrics.LastHResult = comHr;
            m_metrics.LastErrorMessage = "Synchronous fallback CoInitializeEx failed.";
            return false;
        }

        if (prewarmWidth > 0U && prewarmHeight > 0U)
        {
            const HRESULT preHr = m_session.PrewarmDecoder(prewarmWidth, prewarmHeight, prewarmFps);
            if (FAILED(preHr))
            {
                ++m_metrics.WorkerFailureCount;
                m_metrics.LastHResult = preHr;
                m_metrics.LastErrorMessage = "Synchronous fallback PrewarmDecoder failed.";
                m_session.Shutdown();
                if (m_syncFallbackComInit)
                {
                    CoUninitialize();
                    m_syncFallbackComInit = false;
                    ++m_metrics.WorkerComUninitCount;
                    m_metrics.WorkerComUninitThreadId = callerTid;
                }
                m_metrics.DecoderLifecycle = m_session.GetDecoderLifecycleDiagnostics();
                return false;
            }
        }

        m_metrics.SynchronousFallbackActive = true;
        m_metrics.CompletionState = H264WorkerCompletionState::Running;
        m_stopRequested = false;
        m_started = true;
        m_metrics.Started = true;
        return true;
    }

    void RecordEnqueueRejectionStateLocked(
        H264WorkerCompletionState state,
        HRESULT hr,
        const char* message
        ) noexcept
    {
        if (m_metrics.CompletionState == H264WorkerCompletionState::Running ||
            m_metrics.CompletionState == H264WorkerCompletionState::NotStarted ||
            state == H264WorkerCompletionState::EnqueueTimeout)
        {
            m_metrics.CompletionState = state;
        }
        if (SUCCEEDED(m_metrics.LastHResult) && FAILED(hr))
        {
            m_metrics.LastHResult = hr;
        }
        if (m_metrics.LastErrorMessage.empty() && message != nullptr)
        {
            m_metrics.LastErrorMessage = message;
        }
    }

    void UpdateComBalancedLocked() noexcept
    {
        const bool workerComBalanced =
            (m_metrics.WorkerComInitCount == m_metrics.WorkerComUninitCount) &&
            (m_metrics.WorkerComInitCount == 0U ||
             m_metrics.WorkerComInitThreadId == m_metrics.WorkerComUninitThreadId);
        const bool decoderLifecycleBalanced =
            m_metrics.DecoderLifecycle.ComBalanced() &&
            m_metrics.DecoderLifecycle.MfBalanced() &&
            m_metrics.DecoderLifecycle.ShutdownOnOwnerThread();
        m_metrics.ComBalanced = workerComBalanced && decoderLifecycleBalanced;
    }

    void FinalizeCompletionLocked(bool watchdogForced) noexcept
    {
        UpdateComBalancedLocked();

        const bool hasDecodeFailure =
            (m_finalSummary.DecodeFailures > 0ULL) ||
            (m_finalSummary.NalParseFailures > 0ULL) ||
            (m_finalSummary.Enabled && !m_finalSummary.Passed && m_metrics.PacketsProcessed > 0ULL);

        if (m_startFailed || m_metrics.CompletionState == H264WorkerCompletionState::StartFailed)
        {
            m_metrics.CompletionState = H264WorkerCompletionState::StartFailed;
        }
        else if (watchdogForced)
        {
            m_metrics.CompletionState = H264WorkerCompletionState::WatchdogForcedTermination;
        }
        else if (m_metrics.DrainDeadlineExceeded || m_drainFailed || m_metrics.QueueRemainingAtExit > 0ULL)
        {
            m_metrics.CompletionState = H264WorkerCompletionState::DrainFailed;
        }
        else if (m_metrics.QueueWaitTimeoutCount > 0ULL)
        {
            m_metrics.CompletionState = H264WorkerCompletionState::EnqueueTimeout;
        }
        else if (m_metrics.PacketsRejected > 0ULL)
        {
            m_metrics.CompletionState = H264WorkerCompletionState::EnqueueRejected;
        }
        else if (hasDecodeFailure)
        {
            m_metrics.CompletionState = H264WorkerCompletionState::DecodeError;
            if (SUCCEEDED(m_metrics.LastHResult) && FAILED(m_finalSummary.LastHResult))
            {
                m_metrics.LastHResult = m_finalSummary.LastHResult;
            }
        }
        else
        {
            m_metrics.CompletionState = H264WorkerCompletionState::NormalShutdown;
        }

        const bool countsConsistent =
            m_metrics.SynchronousFallbackActive
                ? (m_metrics.PacketsEnqueued == m_metrics.PacketsProcessed)
                : ((m_metrics.PacketsEnqueued == m_metrics.PacketsDequeued) &&
                   (m_metrics.PacketsDequeued == m_metrics.PacketsProcessed));

        m_metrics.Healthy =
            (m_metrics.CompletionState == H264WorkerCompletionState::NormalShutdown) &&
            (m_metrics.WorkerFailureCount == 0ULL) &&
            (m_metrics.PacketsRejected == 0ULL) &&
            (m_metrics.QueueWaitTimeoutCount == 0ULL) &&
            (m_metrics.QueueRemainingAtExit == 0ULL) &&
            !m_metrics.DrainDeadlineExceeded &&
            countsConsistent &&
            m_metrics.ComBalanced;
    }

    void WorkerProc(
        uint32_t prewarmWidth,
        uint32_t prewarmHeight,
        uint32_t prewarmFps
        ) noexcept
    {
        const DWORD workerTid = GetCurrentThreadId();
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_metrics.WorkerThreadId = workerTid;
        }

        const HRESULT comHr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        const bool comInitialized = SUCCEEDED(comHr);
        if (comInitialized)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            ++m_metrics.WorkerComInitCount;
            m_metrics.WorkerComInitThreadId = workerTid;
        }
        else if (comHr != RPC_E_CHANGED_MODE)
        {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_startFailed = true;
                m_ready = true;
                ++m_metrics.WorkerFailureCount;
                m_metrics.CompletionState = H264WorkerCompletionState::StartFailed;
                m_metrics.LastHResult = comHr;
                m_metrics.LastErrorMessage = "CoInitializeEx(COINIT_MULTITHREADED) failed in MFT worker thread.";
                m_metrics.QueueRemainingAtExit = static_cast<uint64_t>(m_queue.size());
                m_workerExited = true;
            }
            m_readyCv.notify_one();
            m_drainDoneCv.notify_all();
            return;
        }

        if (prewarmWidth > 0U && prewarmHeight > 0U)
        {
            const HRESULT preHr = m_session.PrewarmDecoder(prewarmWidth, prewarmHeight, prewarmFps);
            if (FAILED(preHr))
            {
                m_session.Shutdown();
                const DecoderLifecycleDiagnostics lifeDiag = m_session.GetDecoderLifecycleDiagnostics();
                if (comInitialized)
                {
                    CoUninitialize();
                }
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    if (comInitialized)
                    {
                        ++m_metrics.WorkerComUninitCount;
                        m_metrics.WorkerComUninitThreadId = workerTid;
                    }
                    m_metrics.DecoderLifecycle = lifeDiag;
                    m_finalSummary = m_session.GetSummary();
                    m_startFailed = true;
                    m_ready = true;
                    ++m_metrics.WorkerFailureCount;
                    m_metrics.CompletionState = H264WorkerCompletionState::StartFailed;
                    m_metrics.LastHResult = preHr;
                    m_metrics.LastErrorMessage = "Decoder prewarm initialization failed in MFT worker thread.";
                    m_metrics.QueueRemainingAtExit = static_cast<uint64_t>(m_queue.size());
                    m_workerExited = true;
                }
                m_readyCv.notify_one();
                m_drainDoneCv.notify_all();
                return;
            }
        }

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_startSucceeded = true;
            m_ready = true;
        }
        m_readyCv.notify_one();

        for (;;)
        {
            EncodedFramePacket pkt{};
            bool hasPacket = false;
            bool done = false;
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                m_notEmptyCv.wait(lock, [this]() {
                    return m_stopRequested || !m_queue.empty();
                });
                if (!m_queue.empty())
                {
                    pkt = std::move(m_queue.front());
                    m_queue.pop_front();
                    ++m_metrics.PacketsDequeued;
                    hasPacket = true;
                }
                else if (m_stopRequested)
                {
                    done = true;
                }
            }

            if (hasPacket)
            {
                m_notFullCv.notify_one();
                m_session.SubmitPacket(pkt);
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    ++m_metrics.PacketsProcessed;
                }
                continue;
            }
            if (done)
            {
                break;
            }
        }

        m_session.Finish();
        const H264ValidationSummary finalSnap = m_session.GetSummary();
        const bool drainFailed = m_session.HasDrainFailure();
        m_session.Shutdown();
        const DecoderLifecycleDiagnostics lifeDiag = m_session.GetDecoderLifecycleDiagnostics();
        if (comInitialized)
        {
            CoUninitialize();
        }

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (comInitialized)
            {
                ++m_metrics.WorkerComUninitCount;
                m_metrics.WorkerComUninitThreadId = workerTid;
            }
            m_metrics.DecoderLifecycle = lifeDiag;
            m_finalSummary = finalSnap;
            m_drainFailed = drainFailed;
            if (drainFailed)
            {
                ++m_metrics.WorkerFailureCount;
                if (SUCCEEDED(m_metrics.LastHResult) && FAILED(finalSnap.LastHResult))
                {
                    m_metrics.LastHResult = finalSnap.LastHResult;
                }
                if (m_metrics.LastErrorMessage.empty())
                {
                    m_metrics.LastErrorMessage = "H264 decoder Drain() returned failure during worker shutdown.";
                }
            }
            if (finalSnap.DecodeFailures > 0ULL)
            {
                m_metrics.WorkerFailureCount += finalSnap.DecodeFailures;
                if (SUCCEEDED(m_metrics.LastHResult) && FAILED(finalSnap.LastHResult))
                {
                    m_metrics.LastHResult = finalSnap.LastHResult;
                }
                if (m_metrics.LastErrorMessage.empty())
                {
                    m_metrics.LastErrorMessage = "H264 decoder reported decode failures during worker execution.";
                }
            }
            m_metrics.QueueRemainingAtExit = static_cast<uint64_t>(m_queue.size());
            m_workerExited = true;
        }
        m_drainDoneCv.notify_all();
    }

    H264StreamValidationSession& m_session;
    H264WorkerConfig m_config{};
    IH264WorkerHooks* m_hooks{nullptr};
    mutable std::mutex m_mutex{};
    std::condition_variable m_notEmptyCv{};
    std::condition_variable m_notFullCv{};
    std::condition_variable m_readyCv{};
    std::condition_variable m_drainDoneCv{};
    std::deque<EncodedFramePacket> m_queue{};
    std::thread m_worker{};
    bool m_started{false};
    bool m_stopRequested{false};
    bool m_ready{false};
    bool m_startSucceeded{false};
    bool m_startFailed{false};
    bool m_workerExited{false};
    bool m_drainFailed{false};
    bool m_syncFallbackComInit{false};
    DWORD m_syncFallbackThreadId{0U};
    H264ValidationSummary m_finalSummary{};
    H264WorkerMetricsSnapshot m_metrics{};
};

} // namespace lumabridge::host
