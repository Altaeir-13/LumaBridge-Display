#pragma once

#include <Windows.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cwctype>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

namespace lumabridge::host {

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
    bool HighResolutionTimerUsed{false};
    uint32_t TargetFps{60U};
    uint64_t TicksPresented{0ULL};
    uint64_t PaintCount{0ULL};
    uint64_t DurationUs{0ULL};
    uint64_t TickIntervalAvgUs{0ULL};
    uint64_t TickIntervalP95Us{0ULL};
    uint64_t TickIntervalMaxUs{0ULL};
    double AchievedFps{0.0};
    std::wstring DisplayDeviceName{};
    int32_t BoundsLeft{0};
    int32_t BoundsTop{0};
    uint32_t BoundsWidth{0U};
    uint32_t BoundsHeight{0U};
    std::string IdentificationSource{"None"};
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

    bool Start(
        uint32_t targetFps,
        const std::wstring& explicitDisplayName = {},
        LUID expectedAdapterLuid = LUID{0, 0}
        ) noexcept
    {
        Stop();

        const uint32_t clampedFps = (targetFps == 0U)
            ? 60U
            : ((targetFps > 120U) ? 120U : targetFps);

        m_snapshot = {};
        m_snapshot.Requested = true;
        m_snapshot.TargetFps = clampedFps;

        const auto candidates = EnumerateActiveDisplayCandidates();
        const VirtualDisplaySelectionResult selection = DiscoverVirtualDisplayFromCandidates(
            candidates,
            explicitDisplayName,
            expectedAdapterLuid);

        if (!selection.Identified)
        {
            m_snapshot.VirtualDisplayIdentified = false;
            m_snapshot.Started = false;
            m_snapshot.ErrorMessage = selection.FailureReason;
            return false;
        }

        m_targetDisplay = selection.Selected;
        m_snapshot.VirtualDisplayIdentified = true;
        m_snapshot.DisplayDeviceName = m_targetDisplay.DeviceName;
        m_snapshot.BoundsLeft = m_targetDisplay.BoundsLeft;
        m_snapshot.BoundsTop = m_targetDisplay.BoundsTop;
        m_snapshot.BoundsWidth = m_targetDisplay.BoundsWidth;
        m_snapshot.BoundsHeight = m_targetDisplay.BoundsHeight;
        m_snapshot.IdentificationSource = selection.IdentificationSource;

        m_readyEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        m_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (m_readyEvent == nullptr || m_stopEvent == nullptr)
        {
            m_snapshot.ErrorMessage = "Failed creating stimulus synchronization events.";
            CleanupEvents();
            return false;
        }

        m_ticksPresented.store(0ULL, std::memory_order_relaxed);
        m_paintCount.store(0ULL, std::memory_order_relaxed);
        m_tickIntervalsUs.clear();
        m_highResTimerUsed = false;
        m_threadStartOk = false;
        m_threadError.clear();

        try
        {
            m_worker = std::thread(&VirtualDisplayStimulus::ThreadProc, this, clampedFps);
        }
        catch (...)
        {
            m_snapshot.ErrorMessage = "Failed spawning virtual display stimulus thread.";
            CleanupEvents();
            return false;
        }

        (void)WaitForSingleObject(m_readyEvent, 5000U);
        if (!m_threadStartOk)
        {
            m_snapshot.Started = false;
            m_snapshot.Active = false;
            m_snapshot.ErrorMessage = m_threadError.empty()
                ? "Stimulus window failed initialization."
                : m_threadError;
            Stop();
            return false;
        }

        m_snapshot.Started = true;
        m_snapshot.Active = true;
        return true;
    }

    void Stop() noexcept
    {
        if (m_stopEvent != nullptr)
        {
            (void)SetEvent(m_stopEvent);
        }
        if (m_worker.joinable())
        {
            m_worker.join();
        }
        CleanupEvents();

        m_snapshot.Active = false;
        m_snapshot.HighResolutionTimerUsed = m_highResTimerUsed;
        m_snapshot.TicksPresented = m_ticksPresented.load(std::memory_order_relaxed);
        m_snapshot.PaintCount = m_paintCount.load(std::memory_order_relaxed);
        if (!m_tickIntervalsUs.empty())
        {
            std::vector<uint64_t> sorted = m_tickIntervalsUs;
            std::sort(sorted.begin(), sorted.end());
            uint64_t sumUs = 0ULL;
            for (uint64_t v : sorted)
            {
                sumUs += v;
            }
            m_snapshot.TickIntervalAvgUs = sumUs / sorted.size();
            m_snapshot.TickIntervalMaxUs = sorted.back();
            const size_t rank = (95U * sorted.size() + 99U) / 100U;
            const size_t idx = (rank > 0U && (rank - 1U) < sorted.size()) ? (rank - 1U) : (sorted.size() - 1U);
            m_snapshot.TickIntervalP95Us = sorted[idx];
        }
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
        if (m_snapshot.Started)
        {
            m_snapshot.CompletedCleanly = true;
        }
    }

    StimulusMetricsSnapshot GetMetricsSnapshot() const noexcept
    {
        StimulusMetricsSnapshot snap = m_snapshot;
        snap.TicksPresented = m_ticksPresented.load(std::memory_order_relaxed);
        snap.PaintCount = m_paintCount.load(std::memory_order_relaxed);
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
            self->HandlePaint(hwnd);
            return 0;
        }
        if (msg == WM_NCHITTEST)
        {
            return HTTRANSPARENT;
        }
        return DefWindowProcW(hwnd, msg, wParam, lParam);
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
        const LONG barWidth = std::max<LONG>(32L, w / 8L);
        const LONG xPos = static_cast<LONG>((tick * 29ULL) % static_cast<uint64_t>(std::max<LONG>(1L, w)));
        RECT barRc{xPos, 0L, std::min<LONG>(w, xPos + barWidth), h};
        HBRUSH accentBrush = CreateSolidBrush(RGB(
            static_cast<uint8_t>((tick * 13ULL + 80ULL) & 0xFFU),
            static_cast<uint8_t>((tick * 17ULL + 120ULL) & 0xFFU),
            static_cast<uint8_t>((tick * 23ULL + 40ULL) & 0xFFU)));
        if (accentBrush != nullptr)
        {
            (void)FillRect(hdc, &barRc, accentBrush);
            DeleteObject(accentBrush);
        }

        const LONG stripeHeight = std::max<LONG>(16L, h / 10L);
        const LONG yPos = static_cast<LONG>((tick * 19ULL) % static_cast<uint64_t>(std::max<LONG>(1L, h)));
        RECT stripeRc{0L, yPos, w, std::min<LONG>(h, yPos + stripeHeight)};
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
        wc.style = CS_OWNDC;
        wc.lpfnWndProc = &VirtualDisplayStimulus::StimulusWndProc;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.lpszClassName = className;

        const ATOM classAtom = RegisterClassExW(&wc);
        if (classAtom == 0)
        {
            m_threadError = "RegisterClassExW failed for virtual display stimulus.";
            (void)SetEvent(m_readyEvent);
            return;
        }

        const int stimW = static_cast<int>(std::min<uint32_t>(m_targetDisplay.BoundsWidth, 640U));
        const int stimH = static_cast<int>(std::min<uint32_t>(m_targetDisplay.BoundsHeight, 360U));
        const int stimX = static_cast<int>(m_targetDisplay.BoundsLeft) +
                          static_cast<int>(m_targetDisplay.BoundsWidth - static_cast<uint32_t>(stimW)) / 2;
        const int stimY = static_cast<int>(m_targetDisplay.BoundsTop) +
                          static_cast<int>(m_targetDisplay.BoundsHeight - static_cast<uint32_t>(stimH)) / 2;

        HWND hwnd = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_TRANSPARENT,
            className,
            L"LumaBridge M4.1.1 Virtual Display Stimulus",
            WS_POPUP | WS_VISIBLE,
            stimX,
            stimY,
            stimW,
            stimH,
            nullptr,
            nullptr,
            wc.hInstance,
            this);
        if (hwnd == nullptr)
        {
            m_threadError = "CreateWindowExW failed inside virtual monitor rectangle.";
            (void)UnregisterClassW(className, wc.hInstance);
            (void)SetEvent(m_readyEvent);
            return;
        }

        ShowWindow(hwnd, SW_SHOWNOACTIVATE);
        UpdateWindow(hwnd);

        LARGE_INTEGER freqLi{};
        (void)QueryPerformanceFrequency(&freqLi);
        m_qpcFreq = (freqLi.QuadPart > 0) ? static_cast<uint64_t>(freqLi.QuadPart) : 10000000ULL;
        LARGE_INTEGER startLi{};
        (void)QueryPerformanceCounter(&startLi);
        m_startQpc = (startLi.QuadPart > 0) ? static_cast<uint64_t>(startLi.QuadPart) : 0ULL;

        m_threadStartOk = true;
        (void)SetEvent(m_readyEvent);

        // Use a high-resolution waitable timer + absolute QPC deadline pacing to avoid the
        // 15.625ms Windows scheduler tick quantization that throttled 16ms relative waits to ~37.3 FPS.
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
        if (pacingTimer != nullptr)
        {
            m_highResTimerUsed = true;
        }
        else
        {
            pacingTimer = CreateWaitableTimerW(nullptr, FALSE, nullptr);
        }

        const uint64_t intervalQpc = std::max<uint64_t>(1ULL, m_qpcFreq / static_cast<uint64_t>(targetFps));
        uint64_t nextDeadlineQpc = m_startQpc;
        uint64_t prevTickQpc = 0ULL;
        const uint64_t spinThresholdQpc = std::max<uint64_t>(1ULL, (m_qpcFreq * 250ULL) / 1000000ULL);

        for (;;)
        {
            if (WaitForSingleObject(m_stopEvent, 0U) == WAIT_OBJECT_0)
            {
                break;
            }

            MSG msg{};
            while (PeekMessageW(&msg, nullptr, 0U, 0U, PM_REMOVE) != FALSE)
            {
                if (msg.message == WM_QUIT)
                {
                    break;
                }
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }

            if (WaitForSingleObject(m_stopEvent, 0U) == WAIT_OBJECT_0)
            {
                break;
            }

            LARGE_INTEGER nowLi{};
            (void)QueryPerformanceCounter(&nowLi);
            const uint64_t nowQpc = (nowLi.QuadPart > 0) ? static_cast<uint64_t>(nowLi.QuadPart) : m_startQpc;

            if (nowQpc < nextDeadlineQpc)
            {
                const uint64_t remQpc = nextDeadlineQpc - nowQpc;
                if (pacingTimer != nullptr && remQpc > spinThresholdQpc)
                {
                    const uint64_t waitQpc = remQpc - spinThresholdQpc;
                    const uint64_t wait100Ns = std::max<uint64_t>(1ULL, (waitQpc * 10000000ULL) / m_qpcFreq);
                    LARGE_INTEGER dueTime{};
                    dueTime.QuadPart = -static_cast<LONGLONG>(wait100Ns);
                    (void)SetWaitableTimer(pacingTimer, &dueTime, 0L, nullptr, nullptr, FALSE);
                    const HANDLE waitHandles[2] = {m_stopEvent, pacingTimer};
                    const DWORD waitRes = MsgWaitForMultipleObjects(2U, waitHandles, FALSE, INFINITE, QS_ALLINPUT);
                    if (waitRes == WAIT_OBJECT_0)
                    {
                        break;
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
                            break;
                        }
                        continue;
                    }
                }

                while (WaitForSingleObject(m_stopEvent, 0U) != WAIT_OBJECT_0)
                {
                    LARGE_INTEGER spinLi{};
                    (void)QueryPerformanceCounter(&spinLi);
                    if (static_cast<uint64_t>(spinLi.QuadPart) >= nextDeadlineQpc)
                    {
                        break;
                    }
                    SwitchToThread();
                }
                if (WaitForSingleObject(m_stopEvent, 0U) == WAIT_OBJECT_0)
                {
                    break;
                }
            }

            LARGE_INTEGER presentLi{};
            (void)QueryPerformanceCounter(&presentLi);
            const uint64_t presentQpc = (presentLi.QuadPart > 0) ? static_cast<uint64_t>(presentLi.QuadPart) : nextDeadlineQpc;
            if (prevTickQpc > 0ULL && presentQpc >= prevTickQpc && m_tickIntervalsUs.size() < 65536U)
            {
                m_tickIntervalsUs.push_back(((presentQpc - prevTickQpc) * 1000000ULL) / m_qpcFreq);
            }
            prevTickQpc = presentQpc;

            nextDeadlineQpc += intervalQpc;
            if (presentQpc > nextDeadlineQpc + (intervalQpc * 2ULL))
            {
                // Resynchronize after an OS stall without burst catch-up.
                nextDeadlineQpc = presentQpc + intervalQpc;
            }

            m_ticksPresented.fetch_add(1ULL, std::memory_order_relaxed);
            (void)InvalidateRect(hwnd, nullptr, FALSE);
            (void)UpdateWindow(hwnd);
        }

        if (pacingTimer != nullptr)
        {
            CloseHandle(pacingTimer);
        }

        LARGE_INTEGER endLi{};
        (void)QueryPerformanceCounter(&endLi);
        m_endQpc = (endLi.QuadPart > 0) ? static_cast<uint64_t>(endLi.QuadPart) : m_startQpc;

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

    DisplayCandidateInfo m_targetDisplay{};
    StimulusMetricsSnapshot m_snapshot{};
    std::thread m_worker{};
    HANDLE m_readyEvent{nullptr};
    HANDLE m_stopEvent{nullptr};
    std::atomic<uint64_t> m_ticksPresented{0ULL};
    std::atomic<uint64_t> m_paintCount{0ULL};
    uint64_t m_qpcFreq{10000000ULL};
    uint64_t m_startQpc{0ULL};
    uint64_t m_endQpc{0ULL};
    bool m_highResTimerUsed{false};
    std::vector<uint64_t> m_tickIntervalsUs{};
    bool m_threadStartOk{false};
    std::string m_threadError{};
};

} // namespace lumabridge::host
