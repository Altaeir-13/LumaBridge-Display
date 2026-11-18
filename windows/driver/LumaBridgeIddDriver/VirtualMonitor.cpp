#include "VirtualMonitor.h"

#include <cstring>

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

class OwnedOperationLockGuard final
{
public:
    OwnedOperationLockGuard(
        SRWLOCK* lock,
        volatile LONG* ownerThreadId
        ) noexcept
        : m_lock(lock),
          m_ownerThreadId(ownerThreadId)
    {
        if (m_lock != nullptr)
        {
            AcquireSRWLockExclusive(m_lock);
            if (m_ownerThreadId != nullptr)
            {
                InterlockedExchange(m_ownerThreadId, static_cast<LONG>(GetCurrentThreadId()));
            }
        }
    }

    ~OwnedOperationLockGuard()
    {
        if (m_lock != nullptr)
        {
            if (m_ownerThreadId != nullptr)
            {
                InterlockedExchange(m_ownerThreadId, 0);
            }
            ReleaseSRWLockExclusive(m_lock);
        }
    }

    OwnedOperationLockGuard(const OwnedOperationLockGuard&) = delete;
    OwnedOperationLockGuard& operator=(const OwnedOperationLockGuard&) = delete;

private:
    SRWLOCK* m_lock;
    volatile LONG* m_ownerThreadId;
};

NTSTATUS
NormalizeNonSuccess(
    NTSTATUS status
    ) noexcept
{
    return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
}

uint64_t
Fnv1a64Mix(
    uint64_t hash,
    const void* data,
    size_t size
    ) noexcept
{
    constexpr uint64_t kFnvPrime = 1099511628211ULL;
    const auto* bytes = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < size; ++i)
    {
        hash ^= static_cast<uint64_t>(bytes[i]);
        hash *= kFnvPrime;
    }
    return hash;
}

} // namespace

GUID
DeriveMonitorContainerId(
    uint32_t deviceInstanceIndex,
    uint32_t connectorIndex
    ) noexcept
{
    if (deviceInstanceIndex == 0U && connectorIndex == kMvpVirtualMonitorConnectorIndex)
    {
        return kMvpVirtualMonitorContainerId;
    }

    constexpr uint64_t kFnvOffsetBasis = 14695981039346656037ULL;
    const uint8_t tagHigh = 0x01U;
    const uint8_t tagLow = 0x02U;

    uint64_t lowHash = kFnvOffsetBasis;
    lowHash = Fnv1a64Mix(lowHash, &tagLow, sizeof(tagLow));
    lowHash = Fnv1a64Mix(lowHash, &kMvpVirtualMonitorContainerId, sizeof(kMvpVirtualMonitorContainerId));
    lowHash = Fnv1a64Mix(lowHash, &deviceInstanceIndex, sizeof(deviceInstanceIndex));
    lowHash = Fnv1a64Mix(lowHash, &connectorIndex, sizeof(connectorIndex));

    uint64_t highHash = kFnvOffsetBasis;
    highHash = Fnv1a64Mix(highHash, &tagHigh, sizeof(tagHigh));
    highHash = Fnv1a64Mix(highHash, &connectorIndex, sizeof(connectorIndex));
    highHash = Fnv1a64Mix(highHash, &deviceInstanceIndex, sizeof(deviceInstanceIndex));
    highHash = Fnv1a64Mix(highHash, &kMvpVirtualMonitorContainerId, sizeof(kMvpVirtualMonitorContainerId));

    GUID derived{};
    static_assert(sizeof(derived) == sizeof(lowHash) + sizeof(highHash), "GUID size must be 16 bytes");
    auto* rawBytes = reinterpret_cast<uint8_t*>(&derived);
    std::memcpy(rawBytes, &lowHash, sizeof(lowHash));
    std::memcpy(rawBytes + sizeof(lowHash), &highHash, sizeof(highHash));

    // Set RFC 4122 version 5 (name-based) and variant 1 (10xxxxxx).
    derived.Data3 = static_cast<unsigned short>((derived.Data3 & 0x0FFFU) | 0x5000U);
    derived.Data4[0] = static_cast<unsigned char>((derived.Data4[0] & 0x3FU) | 0x80U);

    if (std::memcmp(&derived, &kMvpVirtualMonitorContainerId, sizeof(GUID)) == 0)
    {
        derived.Data1 ^= 0x00000001UL;
    }

    return derived;
}

VirtualMonitorManager::VirtualMonitorManager(
    IVirtualMonitorBackend* backend,
    uint32_t deviceInstanceIndex
    ) noexcept
    : m_backend(backend),
      m_deviceInstanceIndex(deviceInstanceIndex)
{
    m_snapshot.ConnectorIndex = kMvpVirtualMonitorConnectorIndex;
    m_snapshot.ContainerId = DeriveMonitorContainerId(m_deviceInstanceIndex, kMvpVirtualMonitorConnectorIndex);
}

VirtualMonitorManager::~VirtualMonitorManager()
{
    void* leftoverHandle = nullptr;
    {
        ExclusiveSrwLock stateGuard(&m_stateLock);
        leftoverHandle = m_monitorHandle;
        m_monitorHandle = nullptr;
        m_snapshot.HasMonitorHandle = false;
    }
    if (leftoverHandle != nullptr && m_backend != nullptr)
    {
        m_backend->ReleaseMonitorReference(leftoverHandle);
    }
}

bool
VirtualMonitorManager::IsReentrantOperationCall() const noexcept
{
    const LONG currentTid = static_cast<LONG>(GetCurrentThreadId());
    return InterlockedCompareExchange(const_cast<volatile LONG*>(&m_operationLockOwnerThreadId), 0, 0) == currentTid;
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
    if (InterlockedCompareExchange(&m_shutdownRequested, 0, 0) != 0)
    {
        ExclusiveSrwLock stateGuard(&m_stateLock);
        ++m_snapshot.LateCreateRejectedCount;
        m_snapshot.State = VirtualMonitorState::Stopped;
        m_snapshot.LastErrorStatus = STATUS_INVALID_DEVICE_STATE;
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (IsReentrantOperationCall())
    {
        return STATUS_DEVICE_BUSY;
    }

    OwnedOperationLockGuard opGuard(&m_operationLock, &m_operationLockOwnerThreadId);

    GUID containerId{};
    {
        ExclusiveSrwLock stateGuard(&m_stateLock);
        if (InterlockedCompareExchange(&m_shutdownRequested, 0, 0) != 0 ||
            m_snapshot.State == VirtualMonitorState::Stopping ||
            m_snapshot.State == VirtualMonitorState::Stopped)
        {
            ++m_snapshot.LateCreateRejectedCount;
            m_snapshot.State = VirtualMonitorState::Stopped;
            m_snapshot.LastErrorStatus = STATUS_INVALID_DEVICE_STATE;
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (m_suspended || m_snapshot.State == VirtualMonitorState::Suspended)
        {
            ++m_snapshot.LateCreateRejectedCount;
            m_snapshot.State = VirtualMonitorState::Suspended;
            m_snapshot.LastErrorStatus = STATUS_INVALID_DEVICE_STATE;
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (m_monitorHandle != nullptr)
        {
            if (m_snapshot.State == VirtualMonitorState::Arrived)
            {
                ++m_snapshot.DuplicateArrivalPreventedCount;
                return STATUS_SUCCESS;
            }

            // Do not create a second monitor while an existing object's removal is unconfirmed.
            ++m_snapshot.UnconfirmedRemovalBlockedCount;
            m_snapshot.LastErrorStatus = STATUS_DEVICE_BUSY;
            return STATUS_DEVICE_BUSY;
        }

        if (!m_snapshot.ActivationEnabled)
        {
            ++m_snapshot.SkippedDisabledCount;
            return STATUS_SUCCESS;
        }

        if (m_backend == nullptr || adapterHandle == nullptr)
        {
            m_snapshot.LastErrorStatus = STATUS_INVALID_PARAMETER;
            return STATUS_INVALID_PARAMETER;
        }

        m_snapshot.State = VirtualMonitorState::Creating;
        containerId = m_snapshot.ContainerId;
    }

    void* createdHandle = nullptr;
    const NTSTATUS createStatus = m_backend->CreateMonitor(
        adapterHandle,
        kMvpVirtualMonitorConnectorIndex,
        containerId,
        createdHandle);

    if (!NT_SUCCESS(createStatus) || createdHandle == nullptr)
    {
        const NTSTATUS failure = NormalizeNonSuccess(createStatus);
        ExclusiveSrwLock stateGuard(&m_stateLock);
        if (InterlockedCompareExchange(&m_shutdownRequested, 0, 0) != 0)
        {
            m_snapshot.State = VirtualMonitorState::Stopped;
        }
        else if (m_suspended)
        {
            m_snapshot.State = VirtualMonitorState::Suspended;
        }
        else
        {
            m_snapshot.State = VirtualMonitorState::Faulted;
        }
        m_snapshot.LastErrorStatus = failure;
        return failure;
    }

    // Check if Shutdown() or OnSuspend() raced (or fired reentrantly) while CreateMonitor ran.
    bool cancelCreatedBeforeArrival = false;
    bool cancelledDueToShutdown = false;
    {
        ExclusiveSrwLock stateGuard(&m_stateLock);
        cancelledDueToShutdown = (InterlockedCompareExchange(&m_shutdownRequested, 0, 0) != 0);
        if (cancelledDueToShutdown || m_suspended)
        {
            cancelCreatedBeforeArrival = true;
            ++m_snapshot.LateCreateRejectedCount;
            ++m_snapshot.UnarrivedDeletions;
            m_snapshot.State = cancelledDueToShutdown
                ? VirtualMonitorState::Stopped
                : VirtualMonitorState::Suspended;
            m_snapshot.LastErrorStatus = STATUS_INVALID_DEVICE_STATE;
        }
        else
        {
            m_monitorHandle = createdHandle;
            m_snapshot.HasMonitorHandle = true;
            m_snapshot.State = VirtualMonitorState::Arriving;
            ++m_snapshot.CreateCount;
            m_backend->AcquireMonitorReference(createdHandle);
        }
    }

    if (cancelCreatedBeforeArrival)
    {
        m_backend->DeleteUnarrivedMonitorObject(createdHandle);
        m_backend->ReleaseMonitorReference(createdHandle);
        return STATUS_INVALID_DEVICE_STATE;
    }

    LUID osLuid{0, 0};
    uint32_t osTargetId = 0;
    const NTSTATUS arriveStatus = m_backend->ArriveMonitor(createdHandle, osLuid, osTargetId);

    if (!NT_SUCCESS(arriveStatus))
    {
        const NTSTATUS failure = NormalizeNonSuccess(arriveStatus);
        m_backend->ReleaseMonitorReference(createdHandle);
        m_backend->DeleteUnarrivedMonitorObject(createdHandle);

        void* storedHandleToRelease = nullptr;
        {
            ExclusiveSrwLock stateGuard(&m_stateLock);
            if (m_monitorHandle == createdHandle)
            {
                storedHandleToRelease = m_monitorHandle;
                m_monitorHandle = nullptr;
                m_snapshot.HasMonitorHandle = false;
            }
            m_snapshot.OsAdapterLuid = LUID{0, 0};
            m_snapshot.OsTargetId = 0;
            if (InterlockedCompareExchange(&m_shutdownRequested, 0, 0) != 0)
            {
                m_snapshot.State = VirtualMonitorState::Stopped;
            }
            else if (m_suspended)
            {
                m_snapshot.State = VirtualMonitorState::Suspended;
            }
            else
            {
                m_snapshot.State = VirtualMonitorState::Faulted;
            }
            ++m_snapshot.PartialInitFailures;
            ++m_snapshot.UnarrivedDeletions;
            m_snapshot.LastErrorStatus = failure;
        }

        if (storedHandleToRelease != nullptr)
        {
            m_backend->ReleaseMonitorReference(storedHandleToRelease);
        }
        return failure;
    }

    bool needImmediateTeardown = false;
    {
        ExclusiveSrwLock stateGuard(&m_stateLock);
        const bool shutdownActive = (InterlockedCompareExchange(&m_shutdownRequested, 0, 0) != 0);
        if (m_monitorHandle == createdHandle)
        {
            m_snapshot.OsAdapterLuid = osLuid;
            m_snapshot.OsTargetId = osTargetId;
            ++m_snapshot.ArrivalCount;
            if (shutdownActive || m_suspended)
            {
                m_snapshot.State = VirtualMonitorState::Arrived;
                needImmediateTeardown = true;
            }
            else
            {
                m_snapshot.State = VirtualMonitorState::Arrived;
                m_snapshot.LastErrorStatus = STATUS_SUCCESS;
            }
        }
        else if (shutdownActive || m_suspended)
        {
            needImmediateTeardown = true;
        }
    }

    // Release the transient ArriveMonitor reference before evaluating immediate teardown.
    m_backend->ReleaseMonitorReference(createdHandle);

    if (needImmediateTeardown)
    {
        const bool shutdownActive = (InterlockedCompareExchange(&m_shutdownRequested, 0, 0) != 0);
        (void)DepartMonitorLocked(!shutdownActive && m_suspended);
        ExclusiveSrwLock stateGuard(&m_stateLock);
        ++m_snapshot.LateCreateRejectedCount;
        m_snapshot.LastErrorStatus = STATUS_INVALID_DEVICE_STATE;
        if (shutdownActive)
        {
            m_snapshot.State = VirtualMonitorState::Stopped;
        }
        return STATUS_INVALID_DEVICE_STATE;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
VirtualMonitorManager::DepartMonitor() noexcept
{
    if (IsReentrantOperationCall())
    {
        return STATUS_DEVICE_BUSY;
    }

    OwnedOperationLockGuard opGuard(&m_operationLock, &m_operationLockOwnerThreadId);
    return DepartMonitorLocked(false);
}

NTSTATUS
VirtualMonitorManager::DepartMonitorLocked(
    bool keepSuspendedState
    ) noexcept
{
    void* handleToDepart = nullptr;
    bool wasUnarrivedOnly = false;
    {
        ExclusiveSrwLock stateGuard(&m_stateLock);
        const bool shutdownActive = (InterlockedCompareExchange(&m_shutdownRequested, 0, 0) != 0);
        if (m_monitorHandle == nullptr)
        {
            m_snapshot.HasMonitorHandle = false;
            m_snapshot.OsAdapterLuid = LUID{0, 0};
            m_snapshot.OsTargetId = 0;
            m_snapshot.LastDepartureStatus = STATUS_SUCCESS;
            if (shutdownActive)
            {
                m_snapshot.State = VirtualMonitorState::Stopped;
            }
            else if (keepSuspendedState || m_suspended)
            {
                m_snapshot.State = VirtualMonitorState::Suspended;
            }
            else if (m_snapshot.State != VirtualMonitorState::NotCreated &&
                     m_snapshot.State != VirtualMonitorState::Departed)
            {
                m_snapshot.State = VirtualMonitorState::Departed;
            }
            return STATUS_SUCCESS;
        }

        if (m_backend == nullptr)
        {
            m_snapshot.LastDepartureStatus = STATUS_INVALID_DEVICE_STATE;
            m_snapshot.LastErrorStatus = STATUS_INVALID_DEVICE_STATE;
            return STATUS_INVALID_DEVICE_STATE;
        }

        handleToDepart = m_monitorHandle;
        wasUnarrivedOnly = (m_snapshot.State == VirtualMonitorState::Created);
        m_snapshot.State = VirtualMonitorState::Departing;
        m_backend->AcquireMonitorReference(handleToDepart);
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

    void* storedHandleToRelease = nullptr;
    NTSTATUS resultStatus = STATUS_SUCCESS;
    {
        ExclusiveSrwLock stateGuard(&m_stateLock);
        const bool shutdownActive = (InterlockedCompareExchange(&m_shutdownRequested, 0, 0) != 0);
        if (wasUnarrivedOnly || NT_SUCCESS(departStatus))
        {
            if (m_monitorHandle == handleToDepart)
            {
                storedHandleToRelease = m_monitorHandle;
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
            m_snapshot.LastDepartureStatus = STATUS_SUCCESS;
            m_snapshot.LastErrorStatus = STATUS_SUCCESS;
            if (shutdownActive)
            {
                m_snapshot.State = VirtualMonitorState::Stopped;
            }
            else if (keepSuspendedState || m_suspended)
            {
                m_snapshot.State = VirtualMonitorState::Suspended;
            }
            else
            {
                m_snapshot.State = VirtualMonitorState::Departed;
            }
            resultStatus = STATUS_SUCCESS;
        }
        else
        {
            const NTSTATUS failure = NormalizeNonSuccess(departStatus);
            // Preserve m_monitorHandle when departure fails so subsequent EnsureMonitorArrived
            // cannot spawn a duplicate monitor until retry or WDF cleanup confirms removal.
            m_snapshot.HasMonitorHandle = (m_monitorHandle != nullptr);
            ++m_snapshot.DepartureFailures;
            m_snapshot.LastDepartureStatus = failure;
            m_snapshot.LastErrorStatus = failure;
            if (m_monitorHandle == nullptr)
            {
                m_snapshot.OsAdapterLuid = LUID{0, 0};
                m_snapshot.OsTargetId = 0;
                if (shutdownActive)
                {
                    m_snapshot.State = VirtualMonitorState::Stopped;
                }
                else if (keepSuspendedState || m_suspended)
                {
                    m_snapshot.State = VirtualMonitorState::Suspended;
                }
                else
                {
                    m_snapshot.State = VirtualMonitorState::Departed;
                }
            }
            else
            {
                m_snapshot.State = VirtualMonitorState::Faulted;
            }
            resultStatus = failure;
        }
    }

    m_backend->ReleaseMonitorReference(handleToDepart);
    if (storedHandleToRelease != nullptr)
    {
        m_backend->ReleaseMonitorReference(storedHandleToRelease);
    }

    return resultStatus;
}

NTSTATUS
VirtualMonitorManager::OnSuspend() noexcept
{
    if (IsReentrantOperationCall())
    {
        ExclusiveSrwLock stateGuard(&m_stateLock);
        m_suspended = true;
        if (InterlockedCompareExchange(&m_shutdownRequested, 0, 0) == 0 &&
            m_monitorHandle == nullptr)
        {
            m_snapshot.State = VirtualMonitorState::Suspended;
        }
        return STATUS_SUCCESS;
    }

    OwnedOperationLockGuard opGuard(&m_operationLock, &m_operationLockOwnerThreadId);

    {
        ExclusiveSrwLock stateGuard(&m_stateLock);
        m_suspended = true;
        if (InterlockedCompareExchange(&m_shutdownRequested, 0, 0) != 0)
        {
            m_snapshot.State = VirtualMonitorState::Stopped;
            return STATUS_SUCCESS;
        }
    }

    return DepartMonitorLocked(true);
}

NTSTATUS
VirtualMonitorManager::OnResume() noexcept
{
    if (InterlockedCompareExchange(&m_shutdownRequested, 0, 0) != 0)
    {
        ExclusiveSrwLock stateGuard(&m_stateLock);
        m_snapshot.State = VirtualMonitorState::Stopped;
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (IsReentrantOperationCall())
    {
        ExclusiveSrwLock stateGuard(&m_stateLock);
        if (InterlockedCompareExchange(&m_shutdownRequested, 0, 0) != 0 ||
            m_snapshot.State == VirtualMonitorState::Stopping ||
            m_snapshot.State == VirtualMonitorState::Stopped)
        {
            m_snapshot.State = VirtualMonitorState::Stopped;
            return STATUS_INVALID_DEVICE_STATE;
        }

        m_suspended = false;
        if (m_monitorHandle == nullptr &&
            (m_snapshot.State == VirtualMonitorState::Suspended ||
             m_snapshot.State == VirtualMonitorState::Faulted))
        {
            m_snapshot.State = (m_snapshot.CreateCount == 0U)
                ? VirtualMonitorState::NotCreated
                : VirtualMonitorState::Departed;
        }
        return STATUS_SUCCESS;
    }

    OwnedOperationLockGuard opGuard(&m_operationLock, &m_operationLockOwnerThreadId);
    ExclusiveSrwLock stateGuard(&m_stateLock);

    if (InterlockedCompareExchange(&m_shutdownRequested, 0, 0) != 0 ||
        m_snapshot.State == VirtualMonitorState::Stopping ||
        m_snapshot.State == VirtualMonitorState::Stopped)
    {
        m_snapshot.State = VirtualMonitorState::Stopped;
        return STATUS_INVALID_DEVICE_STATE;
    }

    m_suspended = false;
    if (m_monitorHandle == nullptr &&
        (m_snapshot.State == VirtualMonitorState::Suspended ||
         m_snapshot.State == VirtualMonitorState::Faulted))
    {
        m_snapshot.State = (m_snapshot.CreateCount == 0U)
            ? VirtualMonitorState::NotCreated
            : VirtualMonitorState::Departed;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
VirtualMonitorManager::Shutdown() noexcept
{
    InterlockedExchange(&m_shutdownRequested, 1);

    if (IsReentrantOperationCall())
    {
        ExclusiveSrwLock stateGuard(&m_stateLock);
        if (m_snapshot.State != VirtualMonitorState::Stopped)
        {
            m_snapshot.State = VirtualMonitorState::Stopping;
        }
        return STATUS_SUCCESS;
    }

    OwnedOperationLockGuard opGuard(&m_operationLock, &m_operationLockOwnerThreadId);

    {
        ExclusiveSrwLock stateGuard(&m_stateLock);
        if (m_snapshot.State != VirtualMonitorState::Stopped)
        {
            m_snapshot.State = VirtualMonitorState::Stopping;
        }
    }

    const NTSTATUS departStatus = DepartMonitorLocked(false);

    {
        ExclusiveSrwLock stateGuard(&m_stateLock);
        m_snapshot.State = VirtualMonitorState::Stopped;
    }

    return departStatus;
}

void*
VirtualMonitorManager::GetActiveMonitorHandle() const noexcept
{
    SharedSrwLock stateGuard(&m_stateLock);
    return m_monitorHandle;
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

    void* storedHandleToRelease = nullptr;
    {
        ExclusiveSrwLock stateGuard(&m_stateLock);
        if (m_monitorHandle == monitorHandle)
        {
            storedHandleToRelease = m_monitorHandle;
            m_monitorHandle = nullptr;
            m_snapshot.HasMonitorHandle = false;
            m_snapshot.OsAdapterLuid = LUID{0, 0};
            m_snapshot.OsTargetId = 0;

            if (InterlockedCompareExchange(&m_shutdownRequested, 0, 0) != 0 ||
                m_snapshot.State == VirtualMonitorState::Stopping ||
                m_snapshot.State == VirtualMonitorState::Stopped)
            {
                m_snapshot.State = VirtualMonitorState::Stopped;
            }
            else if (m_suspended || m_snapshot.State == VirtualMonitorState::Suspended)
            {
                m_snapshot.State = VirtualMonitorState::Suspended;
            }
            else
            {
                m_snapshot.State = VirtualMonitorState::Departed;
            }
        }
    }

    if (storedHandleToRelease != nullptr && m_backend != nullptr)
    {
        m_backend->ReleaseMonitorReference(storedHandleToRelease);
    }
}

VirtualMonitorSnapshot
VirtualMonitorManager::GetSnapshot() const noexcept
{
    SharedSrwLock stateGuard(&m_stateLock);
    return m_snapshot;
}

} // namespace lumabridge::driver
