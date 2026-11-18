#include "VirtualMonitor.h"

namespace lumabridge::driver {

namespace {

class ExclusiveSrwLock final
{
public:
    explicit ExclusiveSrwLock(SRWLOCK* lock) noexcept
        : m_lock(lock)
    {
        if (m_lock != nullptr)
        {
            AcquireSRWLockExclusive(m_lock);
        }
    }

    ~ExclusiveSrwLock()
    {
        if (m_lock != nullptr)
        {
            ReleaseSRWLockExclusive(m_lock);
        }
    }

    ExclusiveSrwLock(const ExclusiveSrwLock&) = delete;
    ExclusiveSrwLock& operator=(const ExclusiveSrwLock&) = delete;

private:
    SRWLOCK* m_lock;
};

class SharedSrwLock final
{
public:
    explicit SharedSrwLock(SRWLOCK* lock) noexcept
        : m_lock(lock)
    {
        if (m_lock != nullptr)
        {
            AcquireSRWLockShared(m_lock);
        }
    }

    ~SharedSrwLock()
    {
        if (m_lock != nullptr)
        {
            ReleaseSRWLockShared(m_lock);
        }
    }

    SharedSrwLock(const SharedSrwLock&) = delete;
    SharedSrwLock& operator=(const SharedSrwLock&) = delete;

private:
    SRWLOCK* m_lock;
};

NTSTATUS
NormalizeNonSuccess(
    NTSTATUS status
    ) noexcept
{
    return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
}

} // namespace

VirtualMonitorManager::VirtualMonitorManager(
    IVirtualMonitorBackend* backend
    ) noexcept
    : m_backend(backend)
{
}

void
VirtualMonitorManager::SetActivationEnabled(
    bool enabled
    ) noexcept
{
    ExclusiveSrwLock stateGuard(&m_stateLock);
    m_snapshot.ActivationEnabled = enabled;
}

bool
VirtualMonitorManager::IsActivationEnabled() const noexcept
{
    SharedSrwLock stateGuard(&m_stateLock);
    return m_snapshot.ActivationEnabled;
}

NTSTATUS
VirtualMonitorManager::EnsureMonitorArrived(
    void* adapterHandle
    ) noexcept
{
    ExclusiveSrwLock opGuard(&m_operationLock);

    {
        ExclusiveSrwLock stateGuard(&m_stateLock);
        if (!m_snapshot.ActivationEnabled)
        {
            ++m_snapshot.SkippedDisabledCount;
            return STATUS_SUCCESS;
        }

        if (m_snapshot.State == VirtualMonitorState::Arrived && m_monitorHandle != nullptr)
        {
            ++m_snapshot.DuplicateArrivalPreventedCount;
            return STATUS_SUCCESS;
        }

        if (m_backend == nullptr || adapterHandle == nullptr)
        {
            m_snapshot.LastErrorStatus = STATUS_INVALID_PARAMETER;
            return STATUS_INVALID_PARAMETER;
        }

        m_snapshot.State = VirtualMonitorState::Creating;
    }

    void* createdHandle = nullptr;
    const NTSTATUS createStatus = m_backend->CreateMonitor(
        adapterHandle,
        kMvpVirtualMonitorConnectorIndex,
        kMvpVirtualMonitorContainerId,
        createdHandle);

    if (!NT_SUCCESS(createStatus) || createdHandle == nullptr)
    {
        const NTSTATUS failure = NormalizeNonSuccess(createStatus);
        ExclusiveSrwLock stateGuard(&m_stateLock);
        m_snapshot.State = VirtualMonitorState::Faulted;
        m_snapshot.LastErrorStatus = failure;
        return failure;
    }

    {
        ExclusiveSrwLock stateGuard(&m_stateLock);
        m_monitorHandle = createdHandle;
        m_snapshot.HasMonitorHandle = true;
        m_snapshot.State = VirtualMonitorState::Arriving;
        ++m_snapshot.CreateCount;
    }

    LUID osLuid{0, 0};
    uint32_t osTargetId = 0;
    const NTSTATUS arriveStatus = m_backend->ArriveMonitor(createdHandle, osLuid, osTargetId);

    if (!NT_SUCCESS(arriveStatus))
    {
        const NTSTATUS failure = NormalizeNonSuccess(arriveStatus);
        m_backend->DeleteUnarrivedMonitorObject(createdHandle);

        ExclusiveSrwLock stateGuard(&m_stateLock);
        if (m_monitorHandle == createdHandle)
        {
            m_monitorHandle = nullptr;
            m_snapshot.HasMonitorHandle = false;
        }
        m_snapshot.OsAdapterLuid = LUID{0, 0};
        m_snapshot.OsTargetId = 0;
        m_snapshot.State = VirtualMonitorState::Faulted;
        ++m_snapshot.PartialInitFailures;
        ++m_snapshot.UnarrivedDeletions;
        m_snapshot.LastErrorStatus = failure;
        return failure;
    }

    {
        ExclusiveSrwLock stateGuard(&m_stateLock);
        if (m_monitorHandle == createdHandle)
        {
            m_snapshot.State = VirtualMonitorState::Arrived;
            m_snapshot.OsAdapterLuid = osLuid;
            m_snapshot.OsTargetId = osTargetId;
            ++m_snapshot.ArrivalCount;
            m_snapshot.LastErrorStatus = STATUS_SUCCESS;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
VirtualMonitorManager::DepartMonitor() noexcept
{
    ExclusiveSrwLock opGuard(&m_operationLock);

    void* handleToDepart = nullptr;
    bool wasUnarrivedOnly = false;
    {
        ExclusiveSrwLock stateGuard(&m_stateLock);
        if (m_monitorHandle == nullptr || m_backend == nullptr)
        {
            m_monitorHandle = nullptr;
            m_snapshot.HasMonitorHandle = false;
            m_snapshot.OsAdapterLuid = LUID{0, 0};
            m_snapshot.OsTargetId = 0;
            return STATUS_SUCCESS;
        }

        handleToDepart = m_monitorHandle;
        wasUnarrivedOnly = (m_snapshot.State == VirtualMonitorState::Created);
        m_snapshot.State = VirtualMonitorState::Departing;
    }

    m_backend->StopMonitorSwapChain(handleToDepart);

    NTSTATUS departStatus = STATUS_SUCCESS;
    if (wasUnarrivedOnly)
    {
        m_backend->DeleteUnarrivedMonitorObject(handleToDepart);
    }
    else
    {
        departStatus = m_backend->DepartMonitor(handleToDepart);
    }

    {
        ExclusiveSrwLock stateGuard(&m_stateLock);
        if (m_monitorHandle == handleToDepart)
        {
            m_monitorHandle = nullptr;
            m_snapshot.HasMonitorHandle = false;
        }
        m_snapshot.OsAdapterLuid = LUID{0, 0};
        m_snapshot.OsTargetId = 0;
        if (wasUnarrivedOnly)
        {
            ++m_snapshot.UnarrivedDeletions;
        }
        else
        {
            ++m_snapshot.DepartureCount;
        }
        m_snapshot.State = NT_SUCCESS(departStatus)
            ? VirtualMonitorState::Departed
            : VirtualMonitorState::Faulted;
        m_snapshot.LastErrorStatus = departStatus;
    }

    return departStatus;
}

void
VirtualMonitorManager::NotifyMonitorObjectCleanedUp(
    void* monitorHandle
    ) noexcept
{
    if (monitorHandle == nullptr)
    {
        return;
    }

    ExclusiveSrwLock stateGuard(&m_stateLock);
    if (m_monitorHandle == monitorHandle)
    {
        m_monitorHandle = nullptr;
        m_snapshot.HasMonitorHandle = false;
        m_snapshot.OsAdapterLuid = LUID{0, 0};
        m_snapshot.OsTargetId = 0;
        if (m_snapshot.State != VirtualMonitorState::Faulted &&
            m_snapshot.State != VirtualMonitorState::Departed)
        {
            m_snapshot.State = VirtualMonitorState::Departed;
        }
    }
}

VirtualMonitorSnapshot
VirtualMonitorManager::GetSnapshot() const noexcept
{
    SharedSrwLock stateGuard(&m_stateLock);
    return m_snapshot;
}

} // namespace lumabridge::driver
