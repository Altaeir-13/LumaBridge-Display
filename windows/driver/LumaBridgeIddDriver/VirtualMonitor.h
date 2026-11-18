#pragma once

#ifndef WIN32_NO_STATUS
#define WIN32_NO_STATUS
#define LUMABRIDGE_VMON_DEFINED_WIN32_NO_STATUS
#endif
#include <Windows.h>
#ifdef LUMABRIDGE_VMON_DEFINED_WIN32_NO_STATUS
#undef WIN32_NO_STATUS
#undef LUMABRIDGE_VMON_DEFINED_WIN32_NO_STATUS
#endif

#include <ntstatus.h>

#include <cstdint>

typedef LONG NTSTATUS;

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace lumabridge::driver {

inline constexpr uint32_t kMvpVirtualMonitorConnectorIndex = 0U;
inline constexpr bool kDefaultVirtualMonitorActivationEnabled = false;
inline constexpr GUID kMvpVirtualMonitorContainerId = {
    0x8e7b5f32,
    0x4c19,
    0x4e8a,
    {0x9b, 0x7d, 0x2f, 0x6c, 0x3d, 0x9a, 0x10, 0x01}};

/// Explicit lifecycle states for the single MVP virtual monitor.
enum class VirtualMonitorState : uint32_t
{
    NotCreated = 0,
    Creating,
    Created,
    Arriving,
    Arrived,
    Departing,
    Departed,
    Faulted,
};

/// Synchronized state and diagnostic snapshot of VirtualMonitorManager.
struct VirtualMonitorSnapshot
{
    VirtualMonitorState State{VirtualMonitorState::NotCreated};
    bool ActivationEnabled{kDefaultVirtualMonitorActivationEnabled};
    bool HasMonitorHandle{false};
    uint32_t ConnectorIndex{kMvpVirtualMonitorConnectorIndex};
    GUID ContainerId{kMvpVirtualMonitorContainerId};
    LUID OsAdapterLuid{0, 0};
    uint32_t OsTargetId{0};
    uint64_t CreateCount{0};
    uint64_t ArrivalCount{0};
    uint64_t DepartureCount{0};
    uint64_t SkippedDisabledCount{0};
    uint64_t DuplicateArrivalPreventedCount{0};
    uint64_t PartialInitFailures{0};
    uint64_t UnarrivedDeletions{0};
    NTSTATUS LastErrorStatus{STATUS_SUCCESS};
};

/// Abstraction over IddCx monitor creation/arrival/departure DDIs for deterministic unit tests.
class IVirtualMonitorBackend
{
public:
    virtual ~IVirtualMonitorBackend() = default;

    /// Creates an IDDCX_MONITOR object configured without EDID (IDDCX_MONITOR_DESCRIPTION_TYPE_UNCONFIGURED).
    virtual NTSTATUS CreateMonitor(
        void* adapterHandle,
        uint32_t connectorIndex,
        const GUID& containerId,
        void*& outMonitorHandle
        ) noexcept = 0;

    /// Announces monitor arrival to Windows via IddCxMonitorArrival.
    virtual NTSTATUS ArriveMonitor(
        void* monitorHandle,
        LUID& outOsAdapterLuid,
        uint32_t& outOsTargetId
        ) noexcept = 0;

    /// Reports monitor departure to Windows via IddCxMonitorDeparture.
    virtual NTSTATUS DepartMonitor(
        void* monitorHandle
        ) noexcept = 0;

    /// Deletes an unarrived IDDCX_MONITOR object (e.g., partial initialization failure) via WdfObjectDelete.
    virtual void DeleteUnarrivedMonitorObject(
        void* monitorHandle
        ) noexcept = 0;

    /// Stops any active swapchain processing associated with the monitor prior to departure.
    virtual void StopMonitorSwapChain(
        void* monitorHandle
        ) noexcept = 0;
};

/// Thread-safe manager for the single MVP virtual monitor lifecycle.
/// Lock hierarchy: m_operationLock -> m_stateLock (m_stateLock is never held across backend DDIs).
class VirtualMonitorManager final
{
public:
    explicit VirtualMonitorManager(IVirtualMonitorBackend* backend) noexcept;
    ~VirtualMonitorManager() = default;

    VirtualMonitorManager(const VirtualMonitorManager&) = delete;
    VirtualMonitorManager& operator=(const VirtualMonitorManager&) = delete;

    /// Controls whether monitor creation/arrival is permitted (disabled by default in MVP).
    void SetActivationEnabled(bool enabled) noexcept;

    /// Returns whether controlled monitor activation is enabled.
    bool IsActivationEnabled() const noexcept;

    /// Creates and announces the single MVP virtual monitor if enabled and not already arrived.
    /// Cleans up partial creations if arrival fails so no orphan IDDCX_MONITOR remains.
    NTSTATUS EnsureMonitorArrived(void* adapterHandle) noexcept;

    /// Safely stops swapchain processing and departs (or deletes if unarrived) the virtual monitor.
    /// Idempotent when no monitor is active; allows clean recreation on subsequent EnsureMonitorArrived.
    NTSTATUS DepartMonitor() noexcept;

    /// Notifies manager that WDF cleaned up the monitor object (e.g., during EvtCleanupCallback).
    void NotifyMonitorObjectCleanedUp(void* monitorHandle) noexcept;

    /// Returns a thread-safe snapshot of monitor state, identity, and counters.
    VirtualMonitorSnapshot GetSnapshot() const noexcept;

private:
    IVirtualMonitorBackend* m_backend{nullptr};
    SRWLOCK m_operationLock{SRWLOCK_INIT};
    mutable SRWLOCK m_stateLock{SRWLOCK_INIT};
    void* m_monitorHandle{nullptr};
    VirtualMonitorSnapshot m_snapshot{};
};

} // namespace lumabridge::driver
