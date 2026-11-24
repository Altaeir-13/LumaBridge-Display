#pragma once

#include <Windows.h>
#include <d3d11_1.h>
#include <dxgi1_3.h>
#include <wrl/client.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cwctype>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

namespace lumabridge::host {

enum class StimulusBackend : uint32_t
{
    Auto = 0U,
    D3d11DxgiVSync = 1U,
    GdiLegacy = 2U
};

inline const char*
StimulusBackendToString(StimulusBackend backend) noexcept
{
    switch (backend)
    {
    case StimulusBackend::D3d11DxgiVSync:
        return "D3d11DxgiVSync";
    case StimulusBackend::GdiLegacy:
        return "GdiLegacy";
    case StimulusBackend::Auto:
    default:
        return "Auto";
    }
}

inline bool
ParseStimulusBackend(
    const std::wstring& value,
    StimulusBackend& outBackend
    ) noexcept
{
    if (_wcsicmp(value.c_str(), L"auto") == 0)
    {
        outBackend = StimulusBackend::Auto;
        return true;
    }
    if (_wcsicmp(value.c_str(), L"dxgi") == 0 ||
        _wcsicmp(value.c_str(), L"d3d11") == 0 ||
        _wcsicmp(value.c_str(), L"vsync") == 0 ||
        _wcsicmp(value.c_str(), L"d3d11dxgivsync") == 0)
    {
        outBackend = StimulusBackend::D3d11DxgiVSync;
        return true;
    }
    if (_wcsicmp(value.c_str(), L"gdi") == 0 ||
        _wcsicmp(value.c_str(), L"gdilegacy") == 0)
    {
        outBackend = StimulusBackend::GdiLegacy;
        return true;
    }
    return false;
}

/// Computes exact rational QPC tick offset for tickIndex at targetFps without cumulative truncation drift.
inline uint64_t
ComputeExactRationalOffsetQpc(
    uint64_t tickIndex,
    uint64_t qpcFreq,
    uint32_t targetFps
    ) noexcept
{
    if (targetFps == 0U || qpcFreq == 0ULL)
    {
        return 0ULL;
    }
    const uint64_t fps = static_cast<uint64_t>(targetFps);
    const uint64_t wholeSeconds = tickIndex / fps;
    const uint64_t remTicks = tickIndex % fps;
    return (wholeSeconds * qpcFreq) + ((remTicks * qpcFreq) / fps);
}

inline uint64_t
ComputeExactRationalDeadlineQpc(
    uint64_t anchorQpc,
    uint64_t tickIndex,
    uint64_t qpcFreq,
    uint32_t targetFps
    ) noexcept
{
    return anchorQpc + ComputeExactRationalOffsetQpc(tickIndex, qpcFreq, targetFps);
}

/// Presenter abstraction allowing production D3D11/DXGI flip-model swaps or deterministic mock presenters.
class IStimulusPresenterBackend
{
public:
    virtual ~IStimulusPresenterBackend() = default;

    virtual HRESULT Initialize(
        HWND hwnd,
        uint32_t width,
        uint32_t height,
        HANDLE& outWaitableObject,
        std::string& outError
        ) noexcept = 0;

    virtual HRESULT PresentFrame(
        uint64_t tickSeq,
        uint32_t width,
        uint32_t height,
        bool occludedTestOnly,
        bool& outRenderedFrame
        ) noexcept = 0;

    virtual void Reset() noexcept = 0;
};

struct VirtualDisplayStimulusConfig
{
    uint32_t TargetFps{60U};
    StimulusBackend Backend{StimulusBackend::Auto};
    std::wstring ExplicitDisplayName{};
    LUID ExpectedAdapterLuid{0, 0};
    bool UseExplicitRectForTestOnly{false};
    RECT ExplicitTestRect{0L, 0L, 0L, 0L};
    std::wstring TestDisplayName{L"LUMABRIDGE_TEST_SURFACE"};
    IStimulusPresenterBackend* CustomDxgiPresenter{nullptr};
    uint32_t PersistentOcclusionThresholdTicks{2U};
    uint32_t MaxConsecutiveDeviceLosses{4U};
    uint32_t MaxConsecutivePresentFailures{4U};
};

struct DisplayCandidateInfo
{
    std::wstring DeviceName{};
    std::wstring AdapterString{};
    std::wstring MonitorString{};
    std::wstring MonitorDeviceId{};
    std::wstring FriendlyName{};
    std::wstring AdapterDevicePath{};
    int32_t BoundsLeft{0};
    int32_t BoundsTop{0};
    uint32_t BoundsWidth{0U};
    uint32_t BoundsHeight{0U};
    uint32_t RefreshRateHz{60U};
    LUID AdapterLuid{0, 0};
    bool Active{false};
    bool Primary{false};
    bool IsIndirectWired{false};
};

struct VirtualDisplaySelectionResult
{
    bool Identified{false};
    DisplayCandidateInfo Selected{};
    std::string IdentificationSource{"None"};
    std::string FailureReason{};
};

struct StimulusMetricsSnapshot
{
    bool Requested{false};
    bool VirtualDisplayIdentified{false};
    bool Started{false};
    bool Active{false};
    bool CompletedCleanly{false};
    bool TerminalFailure{false};
    bool StopRequested{false};
    bool HighResolutionTimerUsed{false};
    uint32_t TargetFps{60U};
    std::string BackendRequested{"Auto"};
    std::string BackendActive{"None"};
    bool FallbackFromDxgiOccurred{false};
    std::string FallbackReason{};
    uint64_t PlannedTicks{0ULL};
    uint64_t ExecutedTicks{0ULL};
    uint64_t TicksPresented{0ULL};
    uint64_t PaintCount{0ULL};
    uint64_t PresentRequests{0ULL};
    uint64_t PresentSucceeded{0ULL};
    uint64_t PresentOccluded{0ULL};
    uint64_t PresentFailures{0ULL};
    uint64_t SwapChainRecreations{0ULL};
    uint64_t PresentFastReturnGuardCount{0ULL};
    uint64_t DeadlineMissCount{0ULL};
    uint64_t DurationUs{0ULL};
    uint64_t TickIntervalAvgUs{0ULL};
    uint64_t TickIntervalP95Us{0ULL};
    uint64_t TickIntervalMaxUs{0ULL};
    uint64_t WaitLatencyAvgUs{0ULL};
    uint64_t WaitLatencyP95Us{0ULL};
    uint64_t WaitLatencyMaxUs{0ULL};
    uint64_t PresentLatencyAvgUs{0ULL};
    uint64_t PresentLatencyP95Us{0ULL};
    uint64_t PresentLatencyMaxUs{0ULL};
    int64_t CumulativeDriftUs{0LL};
    uint64_t MaxInterPresentGapUs{0ULL};
    uint64_t InterPresentGapsOver25ms{0ULL};
    double AchievedFps{0.0};
    std::wstring DisplayDeviceName{};
    int32_t BoundsLeft{0};
    int32_t BoundsTop{0};
    uint32_t BoundsWidth{0U};
    uint32_t BoundsHeight{0U};
    std::string IdentificationSource{"None"};
    HRESULT LastHResult{S_OK};
    std::string ErrorMessage{};
};

namespace detail {

inline bool
ContainsCaseInsensitive(
    const std::wstring& haystack,
    const wchar_t* needle
    ) noexcept
{
    if (needle == nullptr || needle[0] == L'\0' || haystack.empty())
    {
        return false;
    }

    const size_t needleLen = wcslen(needle);
    if (haystack.size() < needleLen)
    {
        return false;
    }

    for (size_t i = 0U; i <= (haystack.size() - needleLen); ++i)
    {
        bool match = true;
        for (size_t j = 0U; j < needleLen; ++j)
        {
            if (std::towlower(haystack[i + j]) != std::towlower(needle[j]))
            {
                match = false;
                break;
            }
        }
        if (match)
        {
            return true;
        }
    }
    return false;
}

inline bool
IsLumaBridgeCandidate(
    const DisplayCandidateInfo& c
    ) noexcept
{
    return ContainsCaseInsensitive(c.AdapterString, L"lumabridge") ||
           ContainsCaseInsensitive(c.MonitorString, L"lumabridge") ||
           ContainsCaseInsensitive(c.MonitorDeviceId, L"lumabridge") ||
           ContainsCaseInsensitive(c.FriendlyName, L"lumabridge") ||
           ContainsCaseInsensitive(c.AdapterDevicePath, L"lumabridge");
}

inline bool
HasValidBounds(
    const DisplayCandidateInfo& c
    ) noexcept
{
    return c.Active && c.BoundsWidth >= 64U && c.BoundsHeight >= 64U;
}

inline bool
SameLuid(
    LUID a,
    LUID b
    ) noexcept
{
    return (a.LowPart == b.LowPart) && (a.HighPart == b.HighPart);
}

inline bool
NonZeroLuid(
    LUID luid
    ) noexcept
{
    return (luid.LowPart != 0UL) || (luid.HighPart != 0L);
}

} // namespace detail

inline VirtualDisplaySelectionResult
DiscoverVirtualDisplayFromCandidates(
    const std::vector<DisplayCandidateInfo>& candidates,
    const std::wstring& explicitDisplayName = {},
    LUID expectedAdapterLuid = LUID{0, 0}
    )
{
    VirtualDisplaySelectionResult result{};

    if (!explicitDisplayName.empty())
    {
        for (const auto& c : candidates)
        {
            if (detail::HasValidBounds(c) &&
                _wcsicmp(c.DeviceName.c_str(), explicitDisplayName.c_str()) == 0)
            {
                result.Identified = true;
                result.Selected = c;
                result.IdentificationSource = "ExplicitDisplayName";
                return result;
            }
        }
        result.Identified = false;
        result.FailureReason = "Explicitly specified virtual display device was not found among active desktops.";
        return result;
    }

    for (const auto& c : candidates)
    {
        if (detail::HasValidBounds(c) && detail::IsLumaBridgeCandidate(c))
        {
            result.Identified = true;
            result.Selected = c;
            result.IdentificationSource = "LumaBridgeAdapterOrMonitorIdentity";
            return result;
        }
    }

    if (detail::NonZeroLuid(expectedAdapterLuid))
    {
        for (const auto& c : candidates)
        {
            if (detail::HasValidBounds(c) &&
                c.IsIndirectWired &&
                detail::SameLuid(c.AdapterLuid, expectedAdapterLuid))
            {
                result.Identified = true;
                result.Selected = c;
                result.IdentificationSource = "AdapterLuidAndIndirectWired";
                return result;
            }
        }
    }

    for (const auto& c : candidates)
    {
        if (detail::HasValidBounds(c) && c.IsIndirectWired && !c.Primary)
        {
            result.Identified = true;
            result.Selected = c;
            result.IdentificationSource = "NonPrimaryIndirectWiredDisplay";
            return result;
        }
    }

    result.Identified = false;
    result.FailureReason =
        "No active LumaBridge virtual display found; refusing to interfere with physical monitor.";
    return result;
}

inline std::vector<DisplayCandidateInfo>
EnumerateActiveDisplayCandidates()
{
    std::vector<DisplayCandidateInfo> candidates;

    struct ActivePathMetadata
    {
        std::wstring GdiDeviceName{};
        std::wstring FriendlyName{};
        std::wstring AdapterDevicePath{};
        LUID AdapterLuid{0, 0};
        bool IsIndirectWired{false};
    };
    std::vector<ActivePathMetadata> pathMetadata;

    UINT32 pathCount = 0U;
    UINT32 modeCount = 0U;
    if (GetDisplayConfigBufferSizes(QDC_ONLY_ACTIVE_PATHS, &pathCount, &modeCount) == ERROR_SUCCESS &&
        pathCount > 0U &&
        modeCount > 0U)
    {
        std::vector<DISPLAYCONFIG_PATH_INFO> paths(pathCount);
        std::vector<DISPLAYCONFIG_MODE_INFO> modes(modeCount);
        if (QueryDisplayConfig(
                QDC_ONLY_ACTIVE_PATHS,
                &pathCount,
                paths.data(),
                &modeCount,
                modes.data(),
                nullptr) == ERROR_SUCCESS)
        {
            for (UINT32 i = 0U; i < pathCount; ++i)
            {
                const DISPLAYCONFIG_PATH_INFO& path = paths[i];
                DISPLAYCONFIG_SOURCE_DEVICE_NAME srcName{};
                srcName.header.type = DISPLAYCONFIG_DEVICE_INFO_GET_SOURCE_NAME;
                srcName.header.size = sizeof(srcName);
                srcName.header.adapterId = path.sourceInfo.adapterId;
                srcName.header.id = path.sourceInfo.id;
                if (DisplayConfigGetDeviceInfo(&srcName.header) != ERROR_SUCCESS)
                {
                    continue;
                }

                ActivePathMetadata meta{};
                meta.GdiDeviceName = srcName.viewGdiDeviceName;
                meta.AdapterLuid = path.targetInfo.adapterId;
                meta.IsIndirectWired =
                    (path.targetInfo.outputTechnology == DISPLAYCONFIG_OUTPUT_TECHNOLOGY_INDIRECT_WIRED);

                DISPLAYCONFIG_TARGET_DEVICE_NAME tgtName{};
                tgtName.header.type = DISPLAYCONFIG_DEVICE_INFO_GET_TARGET_NAME;
                tgtName.header.size = sizeof(tgtName);
                tgtName.header.adapterId = path.targetInfo.adapterId;
                tgtName.header.id = path.targetInfo.id;
                if (DisplayConfigGetDeviceInfo(&tgtName.header) == ERROR_SUCCESS)
                {
                    meta.FriendlyName = tgtName.monitorFriendlyDeviceName;
                }

                DISPLAYCONFIG_ADAPTER_NAME adapterName{};
                adapterName.header.type = DISPLAYCONFIG_DEVICE_INFO_GET_ADAPTER_NAME;
                adapterName.header.size = sizeof(adapterName);
                adapterName.header.adapterId = path.targetInfo.adapterId;
                if (DisplayConfigGetDeviceInfo(&adapterName.header) == ERROR_SUCCESS)
                {
                    meta.AdapterDevicePath = adapterName.adapterDevicePath;
                }
                pathMetadata.push_back(std::move(meta));
            }
        }
    }

    for (DWORD devIdx = 0U;; ++devIdx)
    {
        DISPLAY_DEVICEW dd{};
        dd.cb = sizeof(dd);
        if (EnumDisplayDevicesW(nullptr, devIdx, &dd, 0U) == FALSE)
        {
            break;
        }
        if ((dd.StateFlags & DISPLAY_DEVICE_ACTIVE) == 0U ||
            (dd.StateFlags & DISPLAY_DEVICE_MIRRORING_DRIVER) != 0U)
        {
            continue;
        }

        DEVMODEW dm{};
        dm.dmSize = sizeof(dm);
        if (EnumDisplaySettingsW(dd.DeviceName, ENUM_CURRENT_SETTINGS, &dm) == FALSE ||
            dm.dmPelsWidth == 0U ||
            dm.dmPelsHeight == 0U)
        {
            continue;
        }

        DisplayCandidateInfo info{};
        info.DeviceName = dd.DeviceName;
        info.AdapterString = dd.DeviceString;
        info.BoundsLeft = static_cast<int32_t>(dm.dmPosition.x);
        info.BoundsTop = static_cast<int32_t>(dm.dmPosition.y);
        info.BoundsWidth = static_cast<uint32_t>(dm.dmPelsWidth);
        info.BoundsHeight = static_cast<uint32_t>(dm.dmPelsHeight);
        info.RefreshRateHz = (dm.dmDisplayFrequency > 0U && dm.dmDisplayFrequency <= 240U)
            ? static_cast<uint32_t>(dm.dmDisplayFrequency)
            : 60U;
        info.Active = true;
        info.Primary = ((dd.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE) != 0U);

        DISPLAY_DEVICEW mon{};
        mon.cb = sizeof(mon);
        if (EnumDisplayDevicesW(dd.DeviceName, 0U, &mon, EDD_GET_DEVICE_INTERFACE_NAME) != FALSE)
        {
            info.MonitorString = mon.DeviceString;
            info.MonitorDeviceId = mon.DeviceID;
        }

        for (const auto& meta : pathMetadata)
        {
            if (_wcsicmp(meta.GdiDeviceName.c_str(), info.DeviceName.c_str()) == 0)
            {
                info.AdapterLuid = meta.AdapterLuid;
                info.IsIndirectWired = meta.IsIndirectWired;
                if (!meta.FriendlyName.empty())
                {
                    info.FriendlyName = meta.FriendlyName;
                }
                if (!meta.AdapterDevicePath.empty())
                {
                    info.AdapterDevicePath = meta.AdapterDevicePath;
                }
                break;
            }
        }

        candidates.push_back(std::move(info));
    }

    return candidates;
}

/// Renders non-intrusive synthetic motion directly inside the identified virtual monitor bounds
/// without capturing or inspecting any desktop pixels.
class VirtualDisplayStimulus final
{
public:
    VirtualDisplayStimulus() noexcept = default;
    ~VirtualDisplayStimulus()
    {
        Stop();
    }

    VirtualDisplayStimulus(const VirtualDisplayStimulus&) = delete;
    VirtualDisplayStimulus& operator=(const VirtualDisplayStimulus&) = delete;

    bool Start(const VirtualDisplayStimulusConfig& config) noexcept
    {
        Stop();

        const uint32_t clampedFps = (config.TargetFps == 0U)
            ? 60U
            : ((config.TargetFps > 120U) ? 120U : config.TargetFps);

        {
            std::lock_guard<std::mutex> lock(m_stateMutex);
            m_config = config;
            m_config.TargetFps = clampedFps;
            if (m_config.PersistentOcclusionThresholdTicks == 0U)
            {
                m_config.PersistentOcclusionThresholdTicks = 2U;
            }
            if (m_config.MaxConsecutivePresentFailures == 0U)
            {
                m_config.MaxConsecutivePresentFailures = 4U;
            }
            m_snapshot = {};
            m_snapshot.Requested = true;
            m_snapshot.TargetFps = clampedFps;
            m_snapshot.BackendRequested = StimulusBackendToString(config.Backend);
            m_requestedBackend = config.Backend;
        }

        if (config.UseExplicitRectForTestOnly)
        {
            const LONG width = config.ExplicitTestRect.right - config.ExplicitTestRect.left;
            const LONG height = config.ExplicitTestRect.bottom - config.ExplicitTestRect.top;
            if (width < 64L || height < 64L)
            {
                std::lock_guard<std::mutex> lock(m_stateMutex);
                m_snapshot.VirtualDisplayIdentified = false;
                m_snapshot.Started = false;
                m_snapshot.TerminalFailure = true;
                m_snapshot.LastHResult = E_INVALIDARG;
                m_snapshot.ErrorMessage = "Explicit test rect must have width >= 64 and height >= 64.";
                m_terminalFailure = true;
                m_lastHResult = E_INVALIDARG;
                m_threadError = m_snapshot.ErrorMessage;
                return false;
            }

            DisplayCandidateInfo testTarget{};
            testTarget.DeviceName = config.TestDisplayName.empty()
                ? std::wstring(L"LUMABRIDGE_TEST_SURFACE")
                : config.TestDisplayName;
            testTarget.BoundsLeft = static_cast<int32_t>(config.ExplicitTestRect.left);
            testTarget.BoundsTop = static_cast<int32_t>(config.ExplicitTestRect.top);
            testTarget.BoundsWidth = static_cast<uint32_t>(width);
            testTarget.BoundsHeight = static_cast<uint32_t>(height);
            testTarget.RefreshRateHz = clampedFps;
            testTarget.Active = true;
            std::lock_guard<std::mutex> lock(m_stateMutex);
            m_targetDisplay = std::move(testTarget);
            m_snapshot.VirtualDisplayIdentified = true;
            m_snapshot.IdentificationSource = "ExplicitTestRect";
        }
        else
        {
            const auto candidates = EnumerateActiveDisplayCandidates();
            const VirtualDisplaySelectionResult selection = DiscoverVirtualDisplayFromCandidates(
                candidates,
                config.ExplicitDisplayName,
                config.ExpectedAdapterLuid);

            if (!selection.Identified)
            {
                std::lock_guard<std::mutex> lock(m_stateMutex);
                m_snapshot.VirtualDisplayIdentified = false;
                m_snapshot.Started = false;
                m_snapshot.TerminalFailure = true;
                m_snapshot.LastHResult = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
                m_snapshot.ErrorMessage = selection.FailureReason;
                m_terminalFailure = true;
                m_lastHResult = m_snapshot.LastHResult;
                m_threadError = m_snapshot.ErrorMessage;
                return false;
            }

            std::lock_guard<std::mutex> lock(m_stateMutex);
            m_targetDisplay = selection.Selected;
            m_snapshot.VirtualDisplayIdentified = true;
            m_snapshot.IdentificationSource = selection.IdentificationSource;
        }

        {
            std::lock_guard<std::mutex> lock(m_stateMutex);
            m_snapshot.DisplayDeviceName = m_targetDisplay.DeviceName;
            m_snapshot.BoundsLeft = m_targetDisplay.BoundsLeft;
            m_snapshot.BoundsTop = m_targetDisplay.BoundsTop;
            m_snapshot.BoundsWidth = m_targetDisplay.BoundsWidth;
            m_snapshot.BoundsHeight = m_targetDisplay.BoundsHeight;
        }

        m_readyEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        m_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (m_readyEvent == nullptr || m_stopEvent == nullptr)
        {
            const DWORD err = GetLastError();
            std::lock_guard<std::mutex> lock(m_stateMutex);
            m_snapshot.TerminalFailure = true;
            m_snapshot.LastHResult = (err != 0U) ? HRESULT_FROM_WIN32(err) : E_FAIL;
            m_snapshot.ErrorMessage = "Failed creating stimulus synchronization events.";
            m_terminalFailure = true;
            m_lastHResult = m_snapshot.LastHResult;
            m_threadError = m_snapshot.ErrorMessage;
            CleanupEvents();
            return false;
        }

        ResetRuntimeCounters();

        try
        {
            m_worker = std::thread(&VirtualDisplayStimulus::ThreadProc, this, clampedFps);
        }
        catch (...)
        {
            std::lock_guard<std::mutex> lock(m_stateMutex);
            m_snapshot.TerminalFailure = true;
            m_snapshot.LastHResult = E_OUTOFMEMORY;
            m_snapshot.ErrorMessage = "Failed spawning virtual display stimulus thread.";
            m_terminalFailure = true;
            m_lastHResult = E_OUTOFMEMORY;
            m_threadError = m_snapshot.ErrorMessage;
            CleanupEvents();
            return false;
        }

        const DWORD readyWait = WaitForSingleObject(m_readyEvent, 5000U);
        bool startOk = false;
        {
            std::lock_guard<std::mutex> lock(m_stateMutex);
            if (readyWait != WAIT_OBJECT_0 && !m_threadStartOk && m_threadError.empty())
            {
                m_terminalFailure = true;
                m_lastHResult = HRESULT_FROM_WIN32(ERROR_TIMEOUT);
                m_threadError = "Timed out waiting for virtual display stimulus startup.";
            }
            startOk = m_threadStartOk;
            if (!startOk)
            {
                m_snapshot.Started = false;
                m_snapshot.Active = false;
                m_snapshot.CompletedCleanly = false;
                m_snapshot.TerminalFailure = true;
                m_snapshot.LastHResult = FAILED(m_lastHResult) ? m_lastHResult : E_FAIL;
                m_snapshot.ErrorMessage = m_threadError.empty()
                    ? "Stimulus window failed initialization."
                    : m_threadError;
                m_terminalFailure = true;
                m_lastHResult = m_snapshot.LastHResult;
                m_threadError = m_snapshot.ErrorMessage;
            }
        }

        if (!startOk)
        {
            Stop();
            return false;
        }

        {
            std::lock_guard<std::mutex> lock(m_stateMutex);
            m_snapshot.Started = true;
            m_snapshot.Active = true;
            m_snapshot.BackendActive = StimulusBackendToString(m_activeBackend);
            m_snapshot.FallbackFromDxgiOccurred = m_fallbackFromDxgiOccurred;
            m_snapshot.FallbackReason = m_fallbackReason;
            m_snapshot.LastHResult = m_lastHResult;
            m_snapshot.TerminalFailure = m_terminalFailure;
        }
        return true;
    }

    bool Start(
        uint32_t targetFps,
        const std::wstring& explicitDisplayName = {},
        LUID expectedAdapterLuid = LUID{0, 0}
        ) noexcept
    {
        VirtualDisplayStimulusConfig cfg{};
        cfg.TargetFps = targetFps;
        cfg.ExplicitDisplayName = explicitDisplayName;
        cfg.ExpectedAdapterLuid = expectedAdapterLuid;
        return Start(cfg);
    }

    void Stop() noexcept
    {
        {
            std::lock_guard<std::mutex> lock(m_stateMutex);
            if (m_snapshot.Started || m_worker.joinable())
            {
                m_stopRequestedFlag = true;
                m_snapshot.StopRequested = true;
            }
        }

        if (m_stopEvent != nullptr)
        {
            (void)SetEvent(m_stopEvent);
        }
        if (m_worker.joinable())
        {
            m_worker.join();
        }
        CleanupEvents();

        std::lock_guard<std::mutex> lock(m_stateMutex);
        m_snapshot.Active = false;
        m_threadActive = false;
        m_snapshot.HighResolutionTimerUsed = m_highResTimerUsed;
        m_snapshot.BackendActive = StimulusBackendToString(m_activeBackend);
        m_snapshot.FallbackFromDxgiOccurred = m_fallbackFromDxgiOccurred;
        m_snapshot.FallbackReason = m_fallbackReason;
        m_snapshot.StopRequested = m_stopRequestedFlag;
        m_snapshot.TerminalFailure = m_terminalFailure;
        m_snapshot.LastHResult = m_lastHResult;
        if (!m_threadError.empty())
        {
            m_snapshot.ErrorMessage = m_threadError;
        }
        m_snapshot.PlannedTicks = m_plannedTicks.load(std::memory_order_relaxed);
        m_snapshot.ExecutedTicks = m_executedTicks.load(std::memory_order_relaxed);
        m_snapshot.TicksPresented = m_ticksPresented.load(std::memory_order_relaxed);
        m_snapshot.PaintCount = m_paintCount.load(std::memory_order_relaxed);
        m_snapshot.PresentRequests = m_presentRequests.load(std::memory_order_relaxed);
        m_snapshot.PresentSucceeded = m_presentSucceeded.load(std::memory_order_relaxed);
        m_snapshot.PresentOccluded = m_presentOccluded.load(std::memory_order_relaxed);
        m_snapshot.PresentFailures = m_presentFailures.load(std::memory_order_relaxed);
        m_snapshot.SwapChainRecreations = m_swapChainRecreations.load(std::memory_order_relaxed);
        m_snapshot.PresentFastReturnGuardCount = m_presentFastReturnGuardCount.load(std::memory_order_relaxed);
        m_snapshot.DeadlineMissCount = m_deadlineMissCount.load(std::memory_order_relaxed);
        m_snapshot.CumulativeDriftUs = m_cumulativeDriftUs;
        m_snapshot.MaxInterPresentGapUs = m_maxInterPresentGapUs;
        m_snapshot.InterPresentGapsOver25ms = m_interPresentGapsOver25ms;

        ComputeSeriesStats(
            m_tickIntervalsUs,
            m_snapshot.TickIntervalAvgUs,
            m_snapshot.TickIntervalP95Us,
            m_snapshot.TickIntervalMaxUs);
        ComputeSeriesStats(
            m_waitLatenciesUs,
            m_snapshot.WaitLatencyAvgUs,
            m_snapshot.WaitLatencyP95Us,
            m_snapshot.WaitLatencyMaxUs);
        ComputeSeriesStats(
            m_presentLatenciesUs,
            m_snapshot.PresentLatencyAvgUs,
            m_snapshot.PresentLatencyP95Us,
            m_snapshot.PresentLatencyMaxUs);

        if (m_startQpc > 0ULL && m_endQpc > m_startQpc && m_qpcFreq > 0ULL)
        {
            m_snapshot.DurationUs = ((m_endQpc - m_startQpc) * 1000000ULL) / m_qpcFreq;
            if (m_snapshot.DurationUs > 0ULL && m_snapshot.TicksPresented > 0ULL)
            {
                m_snapshot.AchievedFps =
                    static_cast<double>(m_snapshot.TicksPresented) /
                    (static_cast<double>(m_snapshot.DurationUs) / 1000000.0);
            }
        }
        m_snapshot.CompletedCleanly =
            m_snapshot.Started &&
            !m_snapshot.TerminalFailure &&
            m_snapshot.ErrorMessage.empty() &&
            SUCCEEDED(m_snapshot.LastHResult);
    }

    StimulusMetricsSnapshot GetMetricsSnapshot() const noexcept
    {
        std::lock_guard<std::mutex> lock(m_stateMutex);
        StimulusMetricsSnapshot snap = m_snapshot;
        if (m_snapshot.Requested && (m_threadStartOk || m_terminalFailure))
        {
            snap.Active = m_threadActive && snap.Active;
            snap.BackendActive = StimulusBackendToString(m_activeBackend);
            snap.FallbackFromDxgiOccurred = m_fallbackFromDxgiOccurred;
            snap.FallbackReason = m_fallbackReason;
            snap.HighResolutionTimerUsed = m_highResTimerUsed;
            snap.StopRequested = m_stopRequestedFlag;
            snap.TerminalFailure = m_terminalFailure;
            snap.LastHResult = m_lastHResult;
            if (!m_threadError.empty())
            {
                snap.ErrorMessage = m_threadError;
            }
            if (snap.TerminalFailure)
            {
                snap.CompletedCleanly = false;
            }
        }
        snap.PlannedTicks = m_plannedTicks.load(std::memory_order_relaxed);
        snap.ExecutedTicks = m_executedTicks.load(std::memory_order_relaxed);
        snap.TicksPresented = m_ticksPresented.load(std::memory_order_relaxed);
        snap.PaintCount = m_paintCount.load(std::memory_order_relaxed);
        snap.PresentRequests = m_presentRequests.load(std::memory_order_relaxed);
        snap.PresentSucceeded = m_presentSucceeded.load(std::memory_order_relaxed);
        snap.PresentOccluded = m_presentOccluded.load(std::memory_order_relaxed);
        snap.PresentFailures = m_presentFailures.load(std::memory_order_relaxed);
        snap.SwapChainRecreations = m_swapChainRecreations.load(std::memory_order_relaxed);
        snap.PresentFastReturnGuardCount = m_presentFastReturnGuardCount.load(std::memory_order_relaxed);
        snap.DeadlineMissCount = m_deadlineMissCount.load(std::memory_order_relaxed);
        LARGE_INTEGER nowQpc{};
        if (snap.Active && m_startQpc > 0ULL && m_qpcFreq > 0ULL && QueryPerformanceCounter(&nowQpc) != FALSE)
        {
            const uint64_t curQpc = static_cast<uint64_t>(nowQpc.QuadPart);
            if (curQpc > m_startQpc)
            {
                snap.DurationUs = ((curQpc - m_startQpc) * 1000000ULL) / m_qpcFreq;
                if (snap.DurationUs > 0ULL && snap.TicksPresented > 0ULL)
                {
                    snap.AchievedFps =
                        static_cast<double>(snap.TicksPresented) /
                        (static_cast<double>(snap.DurationUs) / 1000000.0);
                }
            }
        }
        return snap;
    }

private:
    static LRESULT CALLBACK StimulusWndProc(
        HWND hwnd,
        UINT msg,
        WPARAM wParam,
        LPARAM lParam
        ) noexcept
    {
        if (msg == WM_NCCREATE)
        {
            const auto* cs = reinterpret_cast<const CREATESTRUCTW*>(lParam);
            if (cs != nullptr)
            {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
            }
            return TRUE;
        }

        auto* self = reinterpret_cast<VirtualDisplayStimulus*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (msg == WM_ERASEBKGND)
        {
            return 1;
        }
        if (msg == WM_PAINT && self != nullptr)
        {
            if (self->m_dxgiOwnsPaint.load(std::memory_order_relaxed))
            {
                (void)ValidateRect(hwnd, nullptr);
                return 0;
            }
            self->HandlePaint(hwnd);
            return 0;
        }
        if (msg == WM_NCHITTEST)
        {
            return HTTRANSPARENT;
        }
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    struct DxgiStimulusResources
    {
        Microsoft::WRL::ComPtr<IDXGIFactory2> Factory{};
        Microsoft::WRL::ComPtr<ID3D11Device> Device{};
        Microsoft::WRL::ComPtr<ID3D11DeviceContext> Context{};
        Microsoft::WRL::ComPtr<ID3D11DeviceContext1> Context1{};
        Microsoft::WRL::ComPtr<IDXGISwapChain1> SwapChain1{};
        Microsoft::WRL::ComPtr<IDXGISwapChain2> SwapChain2{};
        Microsoft::WRL::ComPtr<ID3D11RenderTargetView> Rtv{};
        HANDLE WaitableObject{nullptr};
        bool ClearViewSupported{false};

        void Reset() noexcept
        {
            if (Context != nullptr)
            {
                Context->ClearState();
                Context->Flush();
            }
            if (WaitableObject != nullptr)
            {
                CloseHandle(WaitableObject);
                WaitableObject = nullptr;
            }
            Rtv.Reset();
            SwapChain2.Reset();
            SwapChain1.Reset();
            Context1.Reset();
            Context.Reset();
            Device.Reset();
            Factory.Reset();
            ClearViewSupported = false;
        }

        ~DxgiStimulusResources()
        {
            Reset();
        }
    };

    static void ComputeSeriesStats(
        const std::vector<uint64_t>& samples,
        uint64_t& outAvg,
        uint64_t& outP95,
        uint64_t& outMax
        ) noexcept
    {
        outAvg = 0ULL;
        outP95 = 0ULL;
        outMax = 0ULL;
        if (samples.empty())
        {
            return;
        }

        std::vector<uint64_t> sorted = samples;
        std::sort(sorted.begin(), sorted.end());
        uint64_t sum = 0ULL;
        for (uint64_t v : sorted)
        {
            sum += v;
        }
        outAvg = sum / sorted.size();
        outMax = sorted.back();
        const size_t rank = (95U * sorted.size() + 99U) / 100U;
        const size_t idx = (rank > 0U && (rank - 1U) < sorted.size()) ? (rank - 1U) : (sorted.size() - 1U);
        outP95 = sorted[idx];
    }

    void ResetRuntimeCounters() noexcept
    {
        std::lock_guard<std::mutex> lock(m_stateMutex);
        m_plannedTicks.store(0ULL, std::memory_order_relaxed);
        m_executedTicks.store(0ULL, std::memory_order_relaxed);
        m_ticksPresented.store(0ULL, std::memory_order_relaxed);
        m_paintCount.store(0ULL, std::memory_order_relaxed);
        m_presentRequests.store(0ULL, std::memory_order_relaxed);
        m_presentSucceeded.store(0ULL, std::memory_order_relaxed);
        m_presentOccluded.store(0ULL, std::memory_order_relaxed);
        m_presentFailures.store(0ULL, std::memory_order_relaxed);
        m_swapChainRecreations.store(0ULL, std::memory_order_relaxed);
        m_presentFastReturnGuardCount.store(0ULL, std::memory_order_relaxed);
        m_deadlineMissCount.store(0ULL, std::memory_order_relaxed);
        m_dxgiOwnsPaint.store(false, std::memory_order_relaxed);
        m_activeBackend = StimulusBackend::Auto;
        m_fallbackFromDxgiOccurred = false;
        m_fallbackReason.clear();
        m_stopRequestedFlag = false;
        m_terminalFailure = false;
        m_lastHResult = S_OK;
        m_threadActive = false;
        m_startQpc = 0ULL;
        m_endQpc = 0ULL;
        m_tickIntervalsUs.clear();
        m_waitLatenciesUs.clear();
        m_presentLatenciesUs.clear();
        m_highResTimerUsed = false;
        m_cumulativeDriftUs = 0LL;
        m_maxInterPresentGapUs = 0ULL;
        m_interPresentGapsOver25ms = 0ULL;
        m_threadStartOk = false;
        m_threadError.clear();
    }

    static HRESULT InitializeDxgiResources(
        HWND hwnd,
        uint32_t width,
        uint32_t height,
        DxgiStimulusResources& outRes,
        std::string& outError
        ) noexcept
    {
        outRes.Reset();
        outError.clear();

        HRESULT hr = CreateDXGIFactory1(
            __uuidof(IDXGIFactory2),
            reinterpret_cast<void**>(outRes.Factory.GetAddressOf()));
        if (FAILED(hr) || outRes.Factory == nullptr)
        {
            outError = "CreateDXGIFactory1(IDXGIFactory2) failed.";
            return FAILED(hr) ? hr : E_FAIL;
        }

        static constexpr D3D_FEATURE_LEVEL kLevels[] = {
            D3D_FEATURE_LEVEL_11_1,
            D3D_FEATURE_LEVEL_11_0,
            D3D_FEATURE_LEVEL_10_1
        };

        hr = D3D11CreateDevice(
            nullptr,
            D3D_DRIVER_TYPE_HARDWARE,
            nullptr,
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            kLevels,
            ARRAYSIZE(kLevels),
            D3D11_SDK_VERSION,
            outRes.Device.GetAddressOf(),
            nullptr,
            outRes.Context.GetAddressOf());
        if (FAILED(hr) || outRes.Device == nullptr || outRes.Context == nullptr)
        {
            hr = D3D11CreateDevice(
                nullptr,
                D3D_DRIVER_TYPE_WARP,
                nullptr,
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                kLevels,
                ARRAYSIZE(kLevels),
                D3D11_SDK_VERSION,
                outRes.Device.GetAddressOf(),
                nullptr,
                outRes.Context.GetAddressOf());
        }
        if (FAILED(hr) || outRes.Device == nullptr || outRes.Context == nullptr)
        {
            outError = "D3D11CreateDevice failed for both hardware and WARP adapters.";
            outRes.Reset();
            return FAILED(hr) ? hr : E_FAIL;
        }

        (void)outRes.Context.As(&outRes.Context1);
        D3D11_FEATURE_DATA_D3D11_OPTIONS opts{};
        if (outRes.Context1 != nullptr &&
            SUCCEEDED(outRes.Device->CheckFeatureSupport(D3D11_FEATURE_D3D11_OPTIONS, &opts, sizeof(opts))) &&
            opts.ClearView != FALSE)
        {
            outRes.ClearViewSupported = true;
        }

        DXGI_SWAP_CHAIN_DESC1 scDesc{};
        scDesc.Width = (std::max)(64U, width);
        scDesc.Height = (std::max)(64U, height);
        scDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
        scDesc.SampleDesc.Count = 1U;
        scDesc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        scDesc.BufferCount = 3U;
        scDesc.Scaling = DXGI_SCALING_STRETCH;
        scDesc.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
        scDesc.AlphaMode = DXGI_ALPHA_MODE_IGNORE;
        scDesc.Flags = DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT;

        hr = outRes.Factory->CreateSwapChainForHwnd(
            outRes.Device.Get(),
            hwnd,
            &scDesc,
            nullptr,
            nullptr,
            outRes.SwapChain1.GetAddressOf());
        if (FAILED(hr) || outRes.SwapChain1 == nullptr)
        {
            scDesc.Flags = 0U;
            hr = outRes.Factory->CreateSwapChainForHwnd(
                outRes.Device.Get(),
                hwnd,
                &scDesc,
                nullptr,
                nullptr,
                outRes.SwapChain1.GetAddressOf());
        }
        if (FAILED(hr) || outRes.SwapChain1 == nullptr)
        {
            outError = "CreateSwapChainForHwnd(FLIP_DISCARD) failed.";
            outRes.Reset();
            return FAILED(hr) ? hr : E_FAIL;
        }

        (void)outRes.Factory->MakeWindowAssociation(hwnd, DXGI_MWA_NO_ALT_ENTER | DXGI_MWA_NO_WINDOW_CHANGES);

        if (scDesc.Flags != 0U && SUCCEEDED(outRes.SwapChain1.As(&outRes.SwapChain2)) && outRes.SwapChain2 != nullptr)
        {
            (void)outRes.SwapChain2->SetMaximumFrameLatency(1U);
            outRes.WaitableObject = outRes.SwapChain2->GetFrameLatencyWaitableObject();
        }

        Microsoft::WRL::ComPtr<ID3D11Texture2D> backBuffer;
        hr = outRes.SwapChain1->GetBuffer(
            0U,
            __uuidof(ID3D11Texture2D),
            reinterpret_cast<void**>(backBuffer.GetAddressOf()));
        if (FAILED(hr) || backBuffer == nullptr)
        {
            outError = "IDXGISwapChain1::GetBuffer(0) failed.";
            outRes.Reset();
            return FAILED(hr) ? hr : E_FAIL;
        }

        hr = outRes.Device->CreateRenderTargetView(backBuffer.Get(), nullptr, outRes.Rtv.GetAddressOf());
        if (FAILED(hr) || outRes.Rtv == nullptr)
        {
            outError = "CreateRenderTargetView failed on swapchain backbuffer.";
            outRes.Reset();
            return FAILED(hr) ? hr : E_FAIL;
        }

        return S_OK;
    }

    class D3d11DxgiStimulusPresenter final : public IStimulusPresenterBackend
    {
    public:
        HRESULT Initialize(
            HWND hwnd,
            uint32_t width,
            uint32_t height,
            HANDLE& outWaitableObject,
            std::string& outError
            ) noexcept override
        {
            outWaitableObject = nullptr;
            const HRESULT hr = InitializeDxgiResources(hwnd, width, height, m_res, outError);
            if (SUCCEEDED(hr))
            {
                outWaitableObject = m_res.WaitableObject;
            }
            return hr;
        }

        HRESULT PresentFrame(
            uint64_t tickSeq,
            uint32_t width,
            uint32_t height,
            bool occludedTestOnly,
            bool& outRenderedFrame
            ) noexcept override
        {
            outRenderedFrame = false;
            if (m_res.SwapChain1 == nullptr)
            {
                return E_NOT_VALID_STATE;
            }
            if (occludedTestOnly)
            {
                const HRESULT testHr = m_res.SwapChain1->Present(1U, DXGI_PRESENT_TEST);
                if (testHr != S_OK)
                {
                    return testHr;
                }
            }
            RenderDxgiFrame(m_res, tickSeq, width, height);
            outRenderedFrame = true;
            return m_res.SwapChain1->Present(1U, 0U);
        }

        void Reset() noexcept override
        {
            m_res.Reset();
        }

    private:
        DxgiStimulusResources m_res{};
    };

    static void RenderDxgiFrame(
        DxgiStimulusResources& dxgi,
        uint64_t tick,
        uint32_t width,
        uint32_t height
        ) noexcept
    {
        if (dxgi.Context == nullptr || dxgi.Rtv == nullptr)
        {
            return;
        }

        const FLOAT bgColor[4] = {
            static_cast<FLOAT>((tick * 5ULL) & 0x3FU) / 255.0f,
            static_cast<FLOAT>(16ULL + ((tick * 3ULL) & 0x3FU)) / 255.0f,
            static_cast<FLOAT>(28ULL + ((tick * 7ULL) & 0x3FU)) / 255.0f,
            1.0f
        };
        dxgi.Context->ClearRenderTargetView(dxgi.Rtv.Get(), bgColor);

        if (dxgi.ClearViewSupported && dxgi.Context1 != nullptr && width > 0U && height > 0U)
        {
            const LONG w = static_cast<LONG>(width);
            const LONG h = static_cast<LONG>(height);
            const LONG barW = (std::max)(32L, w / 8L);
            const LONG xPos = static_cast<LONG>((tick * 29ULL) % static_cast<uint64_t>(w));
            const RECT barRc{xPos, 0L, (std::min)(w, xPos + barW), h};
            const FLOAT barColor[4] = {
                static_cast<FLOAT>((tick * 13ULL + 80ULL) & 0xFFU) / 255.0f,
                static_cast<FLOAT>((tick * 17ULL + 120ULL) & 0xFFU) / 255.0f,
                static_cast<FLOAT>((tick * 23ULL + 40ULL) & 0xFFU) / 255.0f,
                1.0f
            };
            dxgi.Context1->ClearView(dxgi.Rtv.Get(), barColor, &barRc, 1U);

            const LONG stripeH = (std::max)(16L, h / 10L);
            const LONG yPos = static_cast<LONG>((tick * 19ULL) % static_cast<uint64_t>(h));
            const RECT stripeRc{0L, yPos, w, (std::min)(h, yPos + stripeH)};
            const FLOAT stripeColor[4] = {
                static_cast<FLOAT>((tick * 29ULL + 40ULL) & 0xFFU) / 255.0f,
                static_cast<FLOAT>((tick * 7ULL + 190ULL) & 0xFFU) / 255.0f,
                static_cast<FLOAT>((tick * 11ULL + 90ULL) & 0xFFU) / 255.0f,
                1.0f
            };
            dxgi.Context1->ClearView(dxgi.Rtv.Get(), stripeColor, &stripeRc, 1U);
        }
    }

    static bool PumpWindowMessages(bool& outQuit) noexcept
    {
        outQuit = false;
        MSG msg{};
        while (PeekMessageW(&msg, nullptr, 0U, 0U, PM_REMOVE) != FALSE)
        {
            if (msg.message == WM_QUIT)
            {
                outQuit = true;
                return false;
            }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        return true;
    }

    bool WaitUntilQpcDeadline(
        HANDLE pacingTimer,
        uint64_t deadlineQpc,
        uint64_t spinThresholdQpc
        ) noexcept
    {
        for (;;)
        {
            if (WaitForSingleObject(m_stopEvent, 0U) == WAIT_OBJECT_0)
            {
                return false;
            }

            bool quit = false;
            if (!PumpWindowMessages(quit) || quit)
            {
                return false;
            }

            LARGE_INTEGER nowLi{};
            (void)QueryPerformanceCounter(&nowLi);
            const uint64_t nowQpc = (nowLi.QuadPart > 0) ? static_cast<uint64_t>(nowLi.QuadPart) : deadlineQpc;
            if (nowQpc >= deadlineQpc)
            {
                return true;
            }

            const uint64_t remQpc = deadlineQpc - nowQpc;
            if (pacingTimer != nullptr && remQpc > spinThresholdQpc)
            {
                const uint64_t waitQpc = remQpc - spinThresholdQpc;
                const uint64_t wait100Ns = (std::max)(1ULL, (waitQpc * 10000000ULL) / m_qpcFreq);
                LARGE_INTEGER dueTime{};
                dueTime.QuadPart = -static_cast<LONGLONG>(wait100Ns);
                (void)SetWaitableTimer(pacingTimer, &dueTime, 0L, nullptr, nullptr, FALSE);
                const HANDLE waitHandles[2] = {m_stopEvent, pacingTimer};
                const DWORD waitRes = MsgWaitForMultipleObjects(2U, waitHandles, FALSE, INFINITE, QS_ALLINPUT);
                if (waitRes == WAIT_OBJECT_0)
                {
                    return false;
                }
                continue;
            }
            else if (pacingTimer == nullptr)
            {
                const DWORD sleepMs = static_cast<DWORD>((remQpc * 1000ULL) / m_qpcFreq);
                if (sleepMs > 0U)
                {
                    const DWORD waitRes = MsgWaitForMultipleObjects(1U, &m_stopEvent, FALSE, sleepMs, QS_ALLINPUT);
                    if (waitRes == WAIT_OBJECT_0)
                    {
                        return false;
                    }
                    continue;
                }
            }

            while (WaitForSingleObject(m_stopEvent, 0U) != WAIT_OBJECT_0)
            {
                LARGE_INTEGER spinLi{};
                (void)QueryPerformanceCounter(&spinLi);
                if (static_cast<uint64_t>(spinLi.QuadPart) >= deadlineQpc)
                {
                    return true;
                }
                SwitchToThread();
            }
            return false;
        }
    }

    void HandlePaint(HWND hwnd) noexcept
    {
        PAINTSTRUCT ps{};
        HDC hdc = BeginPaint(hwnd, &ps);
        if (hdc == nullptr)
        {
            return;
        }

        RECT rc{};
        (void)GetClientRect(hwnd, &rc);
        const LONG w = (rc.right > rc.left) ? (rc.right - rc.left) : 1L;
        const LONG h = (rc.bottom > rc.top) ? (rc.bottom - rc.top) : 1L;

        const uint64_t tick = m_ticksPresented.load(std::memory_order_relaxed);
        const uint8_t bgR = static_cast<uint8_t>((tick * 5ULL) & 0x3FU);
        const uint8_t bgG = static_cast<uint8_t>(16ULL + ((tick * 3ULL) & 0x3FU));
        const uint8_t bgB = static_cast<uint8_t>(28ULL + ((tick * 7ULL) & 0x3FU));

        HBRUSH bgBrush = CreateSolidBrush(RGB(bgR, bgG, bgB));
        if (bgBrush != nullptr)
        {
            (void)FillRect(hdc, &rc, bgBrush);
            DeleteObject(bgBrush);
        }

        // Animated sweeping horizontal/vertical color bars ensure DWM sees new non-trivial
        // surface dirties every tick without reading any user window or desktop pixels.
        const LONG barWidth = (std::max)(32L, w / 8L);
        const LONG xPos = static_cast<LONG>((tick * 29ULL) % static_cast<uint64_t>((std::max)(1L, w)));
        RECT barRc{xPos, 0L, (std::min)(w, xPos + barWidth), h};
        HBRUSH accentBrush = CreateSolidBrush(RGB(
            static_cast<uint8_t>((tick * 13ULL + 80ULL) & 0xFFU),
            static_cast<uint8_t>((tick * 17ULL + 120ULL) & 0xFFU),
            static_cast<uint8_t>((tick * 23ULL + 40ULL) & 0xFFU)));
        if (accentBrush != nullptr)
        {
            (void)FillRect(hdc, &barRc, accentBrush);
            DeleteObject(accentBrush);
        }

        const LONG stripeHeight = (std::max)(16L, h / 10L);
        const LONG yPos = static_cast<LONG>((tick * 19ULL) % static_cast<uint64_t>((std::max)(1L, h)));
        RECT stripeRc{0L, yPos, w, (std::min)(h, yPos + stripeHeight)};
        HBRUSH stripeBrush = CreateSolidBrush(RGB(
            static_cast<uint8_t>((tick * 29ULL + 40ULL) & 0xFFU),
            static_cast<uint8_t>((tick * 7ULL + 190ULL) & 0xFFU),
            static_cast<uint8_t>((tick * 11ULL + 90ULL) & 0xFFU)));
        if (stripeBrush != nullptr)
        {
            (void)FillRect(hdc, &stripeRc, stripeBrush);
            DeleteObject(stripeBrush);
        }

        m_paintCount.fetch_add(1ULL, std::memory_order_relaxed);
        (void)EndPaint(hwnd, &ps);
    }

    void ThreadProc(uint32_t targetFps) noexcept
    {
        wchar_t className[96]{};
        _snwprintf_s(
            className,
            ARRAYSIZE(className),
            _TRUNCATE,
            L"LumaBridgeStimulus_%lu_%llu",
            GetCurrentProcessId(),
            static_cast<unsigned long long>(GetTickCount64()));

        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc);
        wc.style = 0U;
        wc.lpfnWndProc = &VirtualDisplayStimulus::StimulusWndProc;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.lpszClassName = className;

        const ATOM classAtom = RegisterClassExW(&wc);
        if (classAtom == 0)
        {
            const DWORD err = GetLastError();
            {
                std::lock_guard<std::mutex> lock(m_stateMutex);
                m_terminalFailure = true;
                m_lastHResult = (err != 0U) ? HRESULT_FROM_WIN32(err) : E_FAIL;
                m_threadError = "RegisterClassExW failed for virtual display stimulus.";
                m_threadStartOk = false;
            }
            (void)SetEvent(m_readyEvent);
            return;
        }

        const uint32_t stimW = (std::min)(m_targetDisplay.BoundsWidth, 640U);
        const uint32_t stimH = (std::min)(m_targetDisplay.BoundsHeight, 360U);
        const int stimX = static_cast<int>(m_targetDisplay.BoundsLeft) +
                          static_cast<int>(m_targetDisplay.BoundsWidth - stimW) / 2;
        const int stimY = static_cast<int>(m_targetDisplay.BoundsTop) +
                          static_cast<int>(m_targetDisplay.BoundsHeight - stimH) / 2;

        HWND hwnd = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_TRANSPARENT,
            className,
            L"LumaBridge M4.1.1 Virtual Display Stimulus",
            WS_POPUP | WS_VISIBLE,
            stimX,
            stimY,
            static_cast<int>(stimW),
            static_cast<int>(stimH),
            nullptr,
            nullptr,
            wc.hInstance,
            this);
        if (hwnd == nullptr)
        {
            const DWORD err = GetLastError();
            {
                std::lock_guard<std::mutex> lock(m_stateMutex);
                m_terminalFailure = true;
                m_lastHResult = (err != 0U) ? HRESULT_FROM_WIN32(err) : E_FAIL;
                m_threadError = "CreateWindowExW failed inside virtual monitor rectangle.";
                m_threadStartOk = false;
            }
            (void)UnregisterClassW(className, wc.hInstance);
            (void)SetEvent(m_readyEvent);
            return;
        }

        ShowWindow(hwnd, SW_SHOWNOACTIVATE);

        D3d11DxgiStimulusPresenter defaultDxgiPresenter;
        IStimulusPresenterBackend* presenter = (m_config.CustomDxgiPresenter != nullptr)
            ? m_config.CustomDxgiPresenter
            : &defaultDxgiPresenter;
        HANDLE dxgiWaitable = nullptr;
        bool useDxgi = (m_requestedBackend != StimulusBackend::GdiLegacy);
        if (useDxgi)
        {
            std::string dxgiErr;
            const HRESULT initHr = presenter->Initialize(hwnd, stimW, stimH, dxgiWaitable, dxgiErr);
            if (SUCCEEDED(initHr))
            {
                std::lock_guard<std::mutex> lock(m_stateMutex);
                m_activeBackend = StimulusBackend::D3d11DxgiVSync;
                m_dxgiOwnsPaint.store(true, std::memory_order_relaxed);
            }
            else
            {
                if (m_requestedBackend == StimulusBackend::D3d11DxgiVSync)
                {
                    {
                        std::lock_guard<std::mutex> lock(m_stateMutex);
                        m_terminalFailure = true;
                        m_lastHResult = initHr;
                        m_threadError = dxgiErr.empty()
                            ? "Requested D3d11DxgiVSync stimulus backend failed initialization."
                            : dxgiErr;
                        m_threadStartOk = false;
                    }
                    presenter->Reset();
                    DestroyWindow(hwnd);
                    (void)UnregisterClassW(className, wc.hInstance);
                    (void)SetEvent(m_readyEvent);
                    return;
                }
                {
                    std::lock_guard<std::mutex> lock(m_stateMutex);
                    m_fallbackFromDxgiOccurred = true;
                    m_fallbackReason = dxgiErr.empty()
                        ? "DXGI initialization failed in Auto mode; switched to GdiLegacy."
                        : dxgiErr;
                    m_activeBackend = StimulusBackend::GdiLegacy;
                }
                useDxgi = false;
                UpdateWindow(hwnd);
            }
        }
        else
        {
            {
                std::lock_guard<std::mutex> lock(m_stateMutex);
                m_activeBackend = StimulusBackend::GdiLegacy;
            }
            UpdateWindow(hwnd);
        }

#ifndef CREATE_WAITABLE_TIMER_HIGH_RESOLUTION
        constexpr DWORD kCreateWaitableTimerHighResolution = 0x00000002U;
#else
        constexpr DWORD kCreateWaitableTimerHighResolution = CREATE_WAITABLE_TIMER_HIGH_RESOLUTION;
#endif
        HANDLE pacingTimer = CreateWaitableTimerExW(
            nullptr,
            nullptr,
            kCreateWaitableTimerHighResolution,
            TIMER_ALL_ACCESS);
        bool hiResUsed = false;
        if (pacingTimer != nullptr)
        {
            hiResUsed = true;
        }
        else
        {
            pacingTimer = CreateWaitableTimerW(nullptr, FALSE, nullptr);
        }

        LARGE_INTEGER freqLi{};
        (void)QueryPerformanceFrequency(&freqLi);
        const uint64_t localQpcFreq = (freqLi.QuadPart > 0) ? static_cast<uint64_t>(freqLi.QuadPart) : 10000000ULL;
        LARGE_INTEGER startLi{};
        (void)QueryPerformanceCounter(&startLi);
        const uint64_t localStartQpc = (startLi.QuadPart > 0) ? static_cast<uint64_t>(startLi.QuadPart) : 0ULL;

        {
            std::lock_guard<std::mutex> lock(m_stateMutex);
            m_qpcFreq = localQpcFreq;
            m_startQpc = localStartQpc;
            m_highResTimerUsed = hiResUsed;
            m_threadStartOk = true;
            m_threadActive = true;
        }
        (void)SetEvent(m_readyEvent);

        const uint64_t approxFrameQpc = (std::max)(1ULL, localQpcFreq / static_cast<uint64_t>(targetFps));
        const uint64_t spinThresholdQpc = (std::max)(1ULL, (localQpcFreq * 250ULL) / 1000000ULL);
        uint64_t anchorQpc = localStartQpc;
        uint64_t anchorTick = 0ULL;
        uint64_t firstTickQpc = 0ULL;
        uint64_t lastTickQpc = 0ULL;
        uint64_t prevTickQpc = 0ULL;
        uint64_t executedTicks = 0ULL;
        uint32_t consecutiveDeviceLosses = 0U;
        uint32_t consecutiveOccluded = 0U;
        uint32_t consecutivePresentFailures = 0U;
        bool occludedState = false;
        HRESULT lastTransientFailureHr = S_OK;
        std::string lastTransientFailureMsg{};

        for (;;)
        {
            if (WaitForSingleObject(m_stopEvent, 0U) == WAIT_OBJECT_0)
            {
                break;
            }

            const uint64_t deadlineQpc = ComputeExactRationalDeadlineQpc(anchorQpc, anchorTick, localQpcFreq, targetFps);
            m_plannedTicks.fetch_add(1ULL, std::memory_order_relaxed);

            LARGE_INTEGER waitStartLi{};
            (void)QueryPerformanceCounter(&waitStartLi);
            const uint64_t waitStartQpc = static_cast<uint64_t>((std::max)(0LL, waitStartLi.QuadPart));

            if (useDxgi && dxgiWaitable != nullptr && !occludedState)
            {
                const HANDLE handles[2] = {m_stopEvent, dxgiWaitable};
                const DWORD waitRes = WaitForMultipleObjects(2U, handles, FALSE, 100U);
                if (waitRes == WAIT_OBJECT_0)
                {
                    break;
                }
            }

            if (!WaitUntilQpcDeadline(pacingTimer, deadlineQpc, spinThresholdQpc))
            {
                break;
            }

            LARGE_INTEGER presentStartLi{};
            (void)QueryPerformanceCounter(&presentStartLi);
            const uint64_t presentStartQpc = static_cast<uint64_t>((std::max)(0LL, presentStartLi.QuadPart));
            if (presentStartQpc >= waitStartQpc && m_waitLatenciesUs.size() < 65536U)
            {
                m_waitLatenciesUs.push_back(((presentStartQpc - waitStartQpc) * 1000000ULL) / localQpcFreq);
            }

            bool tickCountedAsPresented = false;
            bool terminalBreakRequested = false;
            if (useDxgi)
            {
                const uint64_t tickSeq = m_ticksPresented.load(std::memory_order_relaxed);
                m_presentRequests.fetch_add(1ULL, std::memory_order_relaxed);
                bool renderedFrame = false;
                const HRESULT hr = presenter->PresentFrame(
                    tickSeq,
                    stimW,
                    stimH,
                    occludedState,
                    renderedFrame);
                if (renderedFrame)
                {
                    m_paintCount.fetch_add(1ULL, std::memory_order_relaxed);
                }

                if (hr == DXGI_STATUS_OCCLUDED)
                {
                    occludedState = true;
                    ++consecutiveOccluded;
                    m_presentOccluded.fetch_add(1ULL, std::memory_order_relaxed);
                    if (m_requestedBackend == StimulusBackend::Auto && consecutiveOccluded >= 2U)
                    {
                        presenter->Reset();
                        dxgiWaitable = nullptr;
                        useDxgi = false;
                        occludedState = false;
                        m_dxgiOwnsPaint.store(false, std::memory_order_relaxed);
                        {
                            std::lock_guard<std::mutex> lock(m_stateMutex);
                            m_activeBackend = StimulusBackend::GdiLegacy;
                            m_fallbackFromDxgiOccurred = true;
                            m_fallbackReason =
                                "DXGI_STATUS_OCCLUDED persisted on target desktop; switched to GdiLegacy.";
                        }
                        (void)InvalidateRect(hwnd, nullptr, FALSE);
                        (void)UpdateWindow(hwnd);
                        m_presentSucceeded.fetch_add(1ULL, std::memory_order_relaxed);
                        tickCountedAsPresented = true;
                    }
                    else if (m_requestedBackend == StimulusBackend::D3d11DxgiVSync)
                    {
                        std::lock_guard<std::mutex> lock(m_stateMutex);
                        m_lastHResult = DXGI_STATUS_OCCLUDED;
                    }
                }
                else if (hr == DXGI_ERROR_DEVICE_REMOVED || hr == DXGI_ERROR_DEVICE_RESET)
                {
                    consecutiveOccluded = 0U;
                    m_presentFailures.fetch_add(1ULL, std::memory_order_relaxed);
                    ++consecutiveDeviceLosses;
                    std::string recreateErr;
                    HANDLE newWaitable = nullptr;
                    HRESULT recreateHr = hr;
                    bool recreated = false;
                    if (consecutiveDeviceLosses <= m_config.MaxConsecutiveDeviceLosses)
                    {
                        recreateHr = presenter->Initialize(hwnd, stimW, stimH, newWaitable, recreateErr);
                        recreated = SUCCEEDED(recreateHr);
                    }
                    if (recreated)
                    {
                        dxgiWaitable = newWaitable;
                        occludedState = false;
                        m_swapChainRecreations.fetch_add(1ULL, std::memory_order_relaxed);
                        lastTransientFailureHr = hr;
                        lastTransientFailureMsg.clear();
                    }
                    else if (m_requestedBackend == StimulusBackend::Auto)
                    {
                        presenter->Reset();
                        dxgiWaitable = nullptr;
                        useDxgi = false;
                        m_dxgiOwnsPaint.store(false, std::memory_order_relaxed);
                        std::lock_guard<std::mutex> lock(m_stateMutex);
                        m_activeBackend = StimulusBackend::GdiLegacy;
                        m_fallbackFromDxgiOccurred = true;
                        m_fallbackReason = recreateErr.empty()
                            ? "DXGI device lost during presentation; switched to GdiLegacy."
                            : recreateErr;
                    }
                    else
                    {
                        const HRESULT finalHr = FAILED(recreateHr) ? recreateHr : hr;
                        char msgBuf[256]{};
                        _snprintf_s(
                            msgBuf,
                            sizeof(msgBuf),
                            _TRUNCATE,
                            "%s (presentHr=0x%08lX, recreateHr=0x%08lX)",
                            recreateErr.empty() ? "DXGI device lost during D3d11DxgiVSync presentation" : recreateErr.c_str(),
                            static_cast<unsigned long>(hr),
                            static_cast<unsigned long>(recreateHr));
                        std::lock_guard<std::mutex> lock(m_stateMutex);
                        m_terminalFailure = true;
                        m_lastHResult = finalHr;
                        m_threadError = msgBuf;
                        terminalBreakRequested = true;
                    }
                }
                else if (FAILED(hr))
                {
                    consecutiveOccluded = 0U;
                    ++consecutivePresentFailures;
                    m_presentFailures.fetch_add(1ULL, std::memory_order_relaxed);
                    lastTransientFailureHr = hr;
                    char errBuf[192]{};
                    _snprintf_s(
                        errBuf,
                        sizeof(errBuf),
                        _TRUNCATE,
                        "DXGI Present() failed with HRESULT 0x%08lX.",
                        static_cast<unsigned long>(hr));
                    lastTransientFailureMsg = errBuf;
                    if (m_requestedBackend == StimulusBackend::D3d11DxgiVSync &&
                        consecutivePresentFailures >= m_config.MaxConsecutivePresentFailures)
                    {
                        std::lock_guard<std::mutex> lock(m_stateMutex);
                        m_terminalFailure = true;
                        m_lastHResult = hr;
                        m_threadError = lastTransientFailureMsg;
                        terminalBreakRequested = true;
                    }
                    else
                    {
                        std::lock_guard<std::mutex> lock(m_stateMutex);
                        m_lastHResult = hr;
                    }
                }
                else
                {
                    consecutiveOccluded = 0U;
                    consecutiveDeviceLosses = 0U;
                    consecutivePresentFailures = 0U;
                    if (occludedState || lastTransientFailureHr != S_OK)
                    {
                        std::lock_guard<std::mutex> lock(m_stateMutex);
                        if (!m_terminalFailure)
                        {
                            m_lastHResult = S_OK;
                        }
                    }
                    occludedState = false;
                    lastTransientFailureHr = S_OK;
                    lastTransientFailureMsg.clear();
                    m_presentSucceeded.fetch_add(1ULL, std::memory_order_relaxed);
                    tickCountedAsPresented = true;
                }
            }
            else
            {
                m_presentRequests.fetch_add(1ULL, std::memory_order_relaxed);
                (void)InvalidateRect(hwnd, nullptr, FALSE);
                (void)UpdateWindow(hwnd);
                m_presentSucceeded.fetch_add(1ULL, std::memory_order_relaxed);
                tickCountedAsPresented = true;
            }

            LARGE_INTEGER presentEndLi{};
            (void)QueryPerformanceCounter(&presentEndLi);
            const uint64_t presentEndQpc =
                (presentEndLi.QuadPart > 0) ? static_cast<uint64_t>(presentEndLi.QuadPart) : deadlineQpc;
            const uint64_t presentElapsedUs = (presentEndQpc >= presentStartQpc)
                ? (((presentEndQpc - presentStartQpc) * 1000000ULL) / localQpcFreq)
                : 0ULL;
            if (m_presentLatenciesUs.size() < 65536U)
            {
                m_presentLatenciesUs.push_back(presentElapsedUs);
            }

            if (useDxgi && tickCountedAsPresented && presentElapsedUs < 1000ULL)
            {
                m_presentFastReturnGuardCount.fetch_add(1ULL, std::memory_order_relaxed);
            }

            ++executedTicks;
            m_executedTicks.fetch_add(1ULL, std::memory_order_relaxed);
            if (tickCountedAsPresented)
            {
                m_ticksPresented.fetch_add(1ULL, std::memory_order_relaxed);
            }

            if (firstTickQpc == 0ULL)
            {
                firstTickQpc = presentEndQpc;
            }
            lastTickQpc = presentEndQpc;

            if (prevTickQpc > 0ULL && presentEndQpc >= prevTickQpc)
            {
                const uint64_t gapUs = ((presentEndQpc - prevTickQpc) * 1000000ULL) / localQpcFreq;
                if (m_tickIntervalsUs.size() < 65536U)
                {
                    m_tickIntervalsUs.push_back(gapUs);
                }
                if (gapUs > m_maxInterPresentGapUs)
                {
                    m_maxInterPresentGapUs = gapUs;
                }
                if (gapUs > 25000ULL)
                {
                    ++m_interPresentGapsOver25ms;
                }
            }
            prevTickQpc = presentEndQpc;

            if (terminalBreakRequested)
            {
                break;
            }

            ++anchorTick;
            const uint64_t nextIdealQpc = ComputeExactRationalDeadlineQpc(anchorQpc, anchorTick, localQpcFreq, targetFps);
            if (presentEndQpc > nextIdealQpc + approxFrameQpc)
            {
                m_deadlineMissCount.fetch_add(1ULL, std::memory_order_relaxed);
                if (presentEndQpc > nextIdealQpc + (approxFrameQpc * 2ULL))
                {
                    // Re-anchor cleanly after a prolonged stall without burst catch-up frames.
                    anchorQpc = presentEndQpc;
                    anchorTick = 1ULL;
                }
            }
        }

        if (useDxgi && m_requestedBackend == StimulusBackend::D3d11DxgiVSync)
        {
            const uint64_t succeededNow = m_presentSucceeded.load(std::memory_order_relaxed);
            const uint64_t occludedNow = m_presentOccluded.load(std::memory_order_relaxed);
            const uint64_t failuresNow = m_presentFailures.load(std::memory_order_relaxed);
            std::lock_guard<std::mutex> lock(m_stateMutex);
            if (!m_terminalFailure)
            {
                if (occludedState &&
                    (consecutiveOccluded >= m_config.PersistentOcclusionThresholdTicks ||
                     (succeededNow == 0ULL && occludedNow > 0ULL)))
                {
                    m_terminalFailure = true;
                    m_lastHResult = DXGI_STATUS_OCCLUDED;
                    m_threadError =
                        "DXGI_STATUS_OCCLUDED persisted without recovery in explicit D3d11DxgiVSync mode.";
                }
                else if (succeededNow == 0ULL && failuresNow > 0ULL && FAILED(lastTransientFailureHr))
                {
                    m_terminalFailure = true;
                    m_lastHResult = lastTransientFailureHr;
                    m_threadError = lastTransientFailureMsg.empty()
                        ? "DXGI presentation failed with zero succeeded frames."
                        : lastTransientFailureMsg;
                }
            }
        }

        if (executedTicks >= 2ULL && firstTickQpc > 0ULL && lastTickQpc >= firstTickQpc)
        {
            const uint64_t actualSpanUs = ((lastTickQpc - firstTickQpc) * 1000000ULL) / localQpcFreq;
            const uint64_t idealSpanUs =
                (ComputeExactRationalOffsetQpc(executedTicks - 1ULL, localQpcFreq, targetFps) * 1000000ULL) / localQpcFreq;
            m_cumulativeDriftUs = static_cast<int64_t>(actualSpanUs) - static_cast<int64_t>(idealSpanUs);
        }

        if (pacingTimer != nullptr)
        {
            CloseHandle(pacingTimer);
        }

        LARGE_INTEGER endLi{};
        (void)QueryPerformanceCounter(&endLi);
        m_endQpc = (endLi.QuadPart > 0) ? static_cast<uint64_t>(endLi.QuadPart) : localStartQpc;

        {
            std::lock_guard<std::mutex> lock(m_stateMutex);
            m_threadActive = false;
        }
        m_dxgiOwnsPaint.store(false, std::memory_order_relaxed);
        presenter->Reset();
        DestroyWindow(hwnd);
        (void)UnregisterClassW(className, wc.hInstance);
    }

    void CleanupEvents() noexcept
    {
        if (m_readyEvent != nullptr)
        {
            CloseHandle(m_readyEvent);
            m_readyEvent = nullptr;
        }
        if (m_stopEvent != nullptr)
        {
            CloseHandle(m_stopEvent);
            m_stopEvent = nullptr;
        }
    }

    mutable std::mutex m_stateMutex{};
    VirtualDisplayStimulusConfig m_config{};
    DisplayCandidateInfo m_targetDisplay{};
    StimulusMetricsSnapshot m_snapshot{};
    StimulusBackend m_requestedBackend{StimulusBackend::Auto};
    StimulusBackend m_activeBackend{StimulusBackend::Auto};
    bool m_fallbackFromDxgiOccurred{false};
    std::string m_fallbackReason{};
    bool m_stopRequestedFlag{false};
    bool m_terminalFailure{false};
    bool m_threadActive{false};
    HRESULT m_lastHResult{S_OK};
    std::thread m_worker{};
    HANDLE m_readyEvent{nullptr};
    HANDLE m_stopEvent{nullptr};
    std::atomic<bool> m_dxgiOwnsPaint{false};
    std::atomic<uint64_t> m_plannedTicks{0ULL};
    std::atomic<uint64_t> m_executedTicks{0ULL};
    std::atomic<uint64_t> m_ticksPresented{0ULL};
    std::atomic<uint64_t> m_paintCount{0ULL};
    std::atomic<uint64_t> m_presentRequests{0ULL};
    std::atomic<uint64_t> m_presentSucceeded{0ULL};
    std::atomic<uint64_t> m_presentOccluded{0ULL};
    std::atomic<uint64_t> m_presentFailures{0ULL};
    std::atomic<uint64_t> m_swapChainRecreations{0ULL};
    std::atomic<uint64_t> m_presentFastReturnGuardCount{0ULL};
    std::atomic<uint64_t> m_deadlineMissCount{0ULL};
    uint64_t m_qpcFreq{10000000ULL};
    uint64_t m_startQpc{0ULL};
    uint64_t m_endQpc{0ULL};
    bool m_highResTimerUsed{false};
    int64_t m_cumulativeDriftUs{0LL};
    uint64_t m_maxInterPresentGapUs{0ULL};
    uint64_t m_interPresentGapsOver25ms{0ULL};
    std::vector<uint64_t> m_tickIntervalsUs{};
    std::vector<uint64_t> m_waitLatenciesUs{};
    std::vector<uint64_t> m_presentLatenciesUs{};
    bool m_threadStartOk{false};
    std::string m_threadError{};
};

} // namespace lumabridge::host
