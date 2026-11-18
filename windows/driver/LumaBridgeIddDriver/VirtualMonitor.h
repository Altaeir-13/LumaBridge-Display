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
    Suspended,
    Stopping,
    Stopped,
    Faulted,
};

/// Returns a concise ASCII name for a VirtualMonitorState value.
inline const char*
VirtualMonitorStateToString(
    VirtualMonitorState state
    ) noexcept
{
    switch (state)
    {
    case VirtualMonitorState::NotCreated:
        return "NotCreated";
    case VirtualMonitorState::Creating:
        return "Creating";
    case VirtualMonitorState::Created:
        return "Created";
    case VirtualMonitorState::Arriving:
        return "Arriving";
    case VirtualMonitorState::Arrived:
        return "Arrived";
    case VirtualMonitorState::Departing:
        return "Departing";
    case VirtualMonitorState::Departed:
        return "Departed";
    case VirtualMonitorState::Suspended:
        return "Suspended";
    case VirtualMonitorState::Stopping:
        return "Stopping";
    case VirtualMonitorState::Stopped:
        return "Stopped";
    case VirtualMonitorState::Faulted:
        return "Faulted";
    default:
        return "Unknown";
    }
}

/// Derives a persistent, deterministic RFC 4122 GUID per device instance and connector.
/// Preserves kMvpVirtualMonitorContainerId for primary instance (0, 0).
GUID
DeriveMonitorContainerId(
    uint32_t deviceInstanceIndex,
    uint32_t connectorIndex
    ) noexcept;

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
    uint64_t DepartureFailures{0};
    uint64_t UnconfirmedRemovalBlockedCount{0};
    uint64_t LateCreateRejectedCount{0};
    uint64_t SkippedDisabledCount{0};
    uint64_t DuplicateArrivalPreventedCount{0};
    uint64_t PartialInitFailures{0};
    uint64_t UnarrivedDeletions{0};
    NTSTATUS LastErrorStatus{STATUS_SUCCESS};
    NTSTATUS LastDepartureStatus{STATUS_SUCCESS};
};

/// Abstraction over IddCx monitor creation/arrival/departure DDIs for deterministic unit tests.
class IVirtualMonitorBackend
{
public:
    virtual ~IVirtualMonitorBackend() = default;

    /// Creates an IDDCX_MONITOR object configured without EDID
    /// (IDDCX_MONITOR_DESCRIPTION_TYPE_EDID with DataSize = 0, pData = nullptr).
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

    /// Stops swapchain processing scoped specifically to monitorHandle prior to departure.
    virtual void StopMonitorSwapChain(
        void* monitorHandle
        ) noexcept = 0;

    /// Acquires an additional handle reference across IddCx calls when supported by backend (WdfObjectReference).
    virtual void AcquireMonitorReference(
        void* monitorHandle
        ) noexcept
    {
        (void)monitorHandle;
    }

    /// Releases a previously held handle reference once removal is confirmed (WdfObjectDereference).
    virtual void ReleaseMonitorReference(
        void* monitorHandle
        ) noexcept
    {
        (void)monitorHandle;
    }
};

/// Thread-safe manager for the single MVP virtual monitor lifecycle.
/// Lock hierarchy: m_operationLock -> m_stateLock (m_stateLock is never held across backend DDIs).
class VirtualMonitorManager final
{
public:
    explicit VirtualMonitorManager(
        IVirtualMonitorBackend* backend,
        uint32_t deviceInstanceIndex = 0U
        ) noexcept;
    ~VirtualMonitorManager();

    VirtualMonitorManager(const VirtualMonitorManager&) = delete;
    VirtualMonitorManager& operator=(const VirtualMonitorManager&) = delete;

    /// Controls whether monitor creation/arrival is permitted (disabled by default in MVP).
    void SetActivationEnabled(bool enabled) noexcept;

    /// Returns whether controlled monitor activation is enabled.
    bool IsActivationEnabled() const noexcept;

    /// Creates and announces the single MVP virtual monitor if enabled and not already arrived.
    /// Rejects late creation during suspend/shutdown and blocks recreation while removal is unconfirmed.
    NTSTATUS EnsureMonitorArrived(void* adapterHandle) noexcept;

    /// Safely stops swapchain processing and departs (or deletes if unarrived) the virtual monitor.
    /// Preserves the monitor handle if IddCxMonitorDeparture fails until retry or WDF cleanup confirms removal.
    NTSTATUS DepartMonitor() noexcept;

    /// Transitions manager into Suspended (D0Exit), departs active monitor, and blocks creation until OnResume().
    NTSTATUS OnSuspend() noexcept;

    /// Exits Suspended state on D0Entry unless permanent Shutdown() has occurred.
    NTSTATUS OnResume() noexcept;

    /// Enters irreversible teardown (Stopping -> Stopped), departs any active monitor, and blocks future creation.
    NTSTATUS Shutdown() noexcept;

    /// Returns the currently tracked monitor handle, or nullptr if none / unconfirmed removal is absent.
    void* GetActiveMonitorHandle() const noexcept;

    /// Notifies manager that WDF cleaned up the monitor object (e.g., during EvtCleanupCallback).
    void NotifyMonitorObjectCleanedUp(void* monitorHandle) noexcept;

    /// Returns a thread-safe snapshot of monitor state, identity, and counters.
    VirtualMonitorSnapshot GetSnapshot() const noexcept;

private:
    bool IsReentrantOperationCall() const noexcept;
    NTSTATUS DepartMonitorLocked(bool keepSuspendedState) noexcept;

    IVirtualMonitorBackend* m_backend{nullptr};
    uint32_t m_deviceInstanceIndex{0U};
    SRWLOCK m_operationLock{SRWLOCK_INIT};
    mutable SRWLOCK m_stateLock{SRWLOCK_INIT};
    volatile LONG m_operationLockOwnerThreadId{0};
    volatile LONG m_shutdownRequested{0};
    bool m_suspended{false};
    void* m_monitorHandle{nullptr};
    VirtualMonitorSnapshot m_snapshot{};
};

} // namespace lumabridge::driver
