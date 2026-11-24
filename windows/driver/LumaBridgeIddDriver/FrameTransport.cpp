#include "FrameTransport.h"
#include "Trace.h"

#include <sddl.h>
#include <stdio.h>

#include <cstring>
#include <new>

namespace lumabridge::driver {

namespace {

class ExclusiveLock final
{
public:
    explicit ExclusiveLock(SRWLOCK* lock) noexcept
        : m_lock(lock)
    {
        if (m_lock != nullptr)
        {
            AcquireSRWLockExclusive(m_lock);
        }
    }

    ~ExclusiveLock()
    {
        if (m_lock != nullptr)
        {
            ReleaseSRWLockExclusive(m_lock);
        }
    }

    ExclusiveLock(const ExclusiveLock&) = delete;
    ExclusiveLock& operator=(const ExclusiveLock&) = delete;

private:
    SRWLOCK* m_lock;
};

class SharedLock final
{
public:
    explicit SharedLock(SRWLOCK* lock) noexcept
        : m_lock(lock)
    {
        if (m_lock != nullptr)
        {
            AcquireSRWLockShared(m_lock);
        }
    }

    ~SharedLock()
    {
        if (m_lock != nullptr)
        {
            ReleaseSRWLockShared(m_lock);
        }
    }

    SharedLock(const SharedLock&) = delete;
    SharedLock& operator=(const SharedLock&) = delete;

private:
    SRWLOCK* m_lock;
};

struct LocalFreeGuard final
{
    HLOCAL Ptr{nullptr};

    ~LocalFreeGuard()
    {
        if (Ptr != nullptr)
        {
            LocalFree(Ptr);
            Ptr = nullptr;
        }
    }
};

class ScopedRevertToSelf final
{
public:
    explicit ScopedRevertToSelf(bool active) noexcept
        : m_active(active)
    {
    }

    ~ScopedRevertToSelf()
    {
        RevertNow();
    }

    void RevertNow() noexcept
    {
        if (m_active)
        {
            (void)RevertToSelf();
            m_active = false;
        }
    }

    ScopedRevertToSelf(const ScopedRevertToSelf&) = delete;
    ScopedRevertToSelf& operator=(const ScopedRevertToSelf&) = delete;

private:
    bool m_active{false};
};

bool
QueryTokenUserSidBytes(
    HANDLE token,
    uint8_t* outBuf,
    size_t outBufSize,
    PSID& outSid
    ) noexcept
{
    outSid = nullptr;
    if (token == nullptr || outBuf == nullptr || outBufSize < sizeof(TOKEN_USER))
    {
        return false;
    }

    DWORD requiredSize = static_cast<DWORD>(outBufSize);
    if (GetTokenInformation(
            token,
            TokenUser,
            outBuf,
            requiredSize,
            &requiredSize) == FALSE)
    {
        return false;
    }

    const TOKEN_USER* tokenUser = reinterpret_cast<const TOKEN_USER*>(outBuf);
    if (tokenUser->User.Sid == nullptr || IsValidSid(tokenUser->User.Sid) == FALSE)
    {
        return false;
    }

    outSid = tokenUser->User.Sid;
    return true;
}

bool
IsSidEqualToWellKnown(
    PSID sid,
    WELL_KNOWN_SID_TYPE sidType
    ) noexcept
{
    if (sid == nullptr || IsValidSid(sid) == FALSE)
    {
        return false;
    }

    uint8_t wellKnownBuf[SECURITY_MAX_SID_SIZE]{};
    DWORD sidSize = sizeof(wellKnownBuf);
    if (CreateWellKnownSid(sidType, nullptr, wellKnownBuf, &sidSize) == FALSE)
    {
        return false;
    }

    return EqualSid(sid, wellKnownBuf) != FALSE;
}

bool
IsGuestUserSid(
    PSID sid
    ) noexcept
{
    if (sid == nullptr || IsValidSid(sid) == FALSE)
    {
        return false;
    }

    const PUCHAR subAuthCountPtr = GetSidSubAuthorityCount(sid);
    if (subAuthCountPtr == nullptr || *subAuthCountPtr < 2U)
    {
        return false;
    }

    const DWORD rid = *GetSidSubAuthority(sid, static_cast<DWORD>(*subAuthCountPtr - 1U));
    return rid == DOMAIN_USER_RID_GUEST;
}

bool
IsImpersonationTokenMemberOfWellKnown(
    HANDLE impersonationToken,
    WELL_KNOWN_SID_TYPE sidType,
    bool& outIsMember
    ) noexcept
{
    outIsMember = false;
    if (impersonationToken == nullptr)
    {
        return false;
    }

    uint8_t wellKnownBuf[SECURITY_MAX_SID_SIZE]{};
    DWORD sidSize = sizeof(wellKnownBuf);
    if (CreateWellKnownSid(sidType, nullptr, wellKnownBuf, &sidSize) == FALSE)
    {
        return false;
    }

    BOOL isMember = FALSE;
    if (CheckTokenMembership(impersonationToken, wellKnownBuf, &isMember) == FALSE)
    {
        return false;
    }

    outIsMember = (isMember != FALSE);
    return true;
}

bool
CanonicalizeSidString(
    const wchar_t* inputSidString,
    wchar_t* outCanonicalSidBuf,
    size_t outCanonicalSidBufChars
    ) noexcept
{
    if (outCanonicalSidBuf == nullptr || outCanonicalSidBufChars == 0U)
    {
        return false;
    }
    outCanonicalSidBuf[0] = L'\0';
    if (inputSidString == nullptr || inputSidString[0] == L'\0')
    {
        return false;
    }

    PSID rawSid = nullptr;
    if (ConvertStringSidToSidW(inputSidString, &rawSid) == FALSE || rawSid == nullptr)
    {
        return false;
    }
    LocalFreeGuard sidMemGuard{rawSid};

    if (IsValidSid(rawSid) == FALSE)
    {
        return false;
    }

    LPWSTR canonicalStr = nullptr;
    if (ConvertSidToStringSidW(rawSid, &canonicalStr) == FALSE || canonicalStr == nullptr)
    {
        return false;
    }
    LocalFreeGuard strGuard{canonicalStr};

    const errno_t copyErr = wcsncpy_s(
        outCanonicalSidBuf,
        outCanonicalSidBufChars,
        canonicalStr,
        _TRUNCATE);
    return (copyErr == 0) && (outCanonicalSidBuf[0] != L'\0');
}

bool
QueryCurrentProcessUserSidInfo(
    wchar_t* outSidBuf,
    size_t outSidBufChars,
    bool& outIsServiceAccount
    ) noexcept
{
    outIsServiceAccount = false;
    if (outSidBuf == nullptr || outSidBufChars == 0U)
    {
        return false;
    }
    outSidBuf[0] = L'\0';

    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) == FALSE || token == nullptr)
    {
        return false;
    }
    ScopedWin32Handle tokenGuard(token);

    uint8_t stackTokenBuf[256]{};
    PSID userSid = nullptr;
    if (!QueryTokenUserSidBytes(tokenGuard.Get(), stackTokenBuf, sizeof(stackTokenBuf), userSid))
    {
        return false;
    }

    outIsServiceAccount =
        IsSidEqualToWellKnown(userSid, WinLocalServiceSid) ||
        IsSidEqualToWellKnown(userSid, WinLocalSystemSid);

    LPWSTR sidStr = nullptr;
    if (ConvertSidToStringSidW(userSid, &sidStr) == FALSE || sidStr == nullptr)
    {
        return false;
    }
    LocalFreeGuard sidGuard{sidStr};

    const errno_t copyErr = wcsncpy_s(outSidBuf, outSidBufChars, sidStr, _TRUNCATE);
    return (copyErr == 0) && (outSidBuf[0] != L'\0');
}

uint64_t
QueryCurrentQpc() noexcept
{
    LARGE_INTEGER li{};
    (void)QueryPerformanceCounter(&li);
    return (li.QuadPart > 0) ? static_cast<uint64_t>(li.QuadPart) : 0ULL;
}

uint64_t
QueryQpcFrequencySafe() noexcept
{
    LARGE_INTEGER li{};
    (void)QueryPerformanceFrequency(&li);
    return (li.QuadPart > 0) ? static_cast<uint64_t>(li.QuadPart) : 10000000ULL;
}

HRESULT
LastWin32HResult() noexcept
{
    const DWORD err = GetLastError();
    return (err != ERROR_SUCCESS) ? HRESULT_FROM_WIN32(err) : E_FAIL;
}

bool
IsPeerDisconnectWin32Error(
    DWORD err
    ) noexcept
{
    return err == ERROR_BROKEN_PIPE ||
           err == ERROR_NO_DATA ||
           err == ERROR_PIPE_NOT_CONNECTED;
}

DWORD
WaitOverlappedWithStop(
    HANDLE pipeHandle,
    OVERLAPPED& ov,
    HANDLE stopEvent,
    DWORD initialErr,
    DWORD timeoutMs,
    DWORD& outBytesTransferred
    ) noexcept
{
    outBytesTransferred = 0U;
    if (initialErr == ERROR_PIPE_CONNECTED)
    {
        return ERROR_SUCCESS;
    }
    if (initialErr != ERROR_IO_PENDING)
    {
        return initialErr;
    }

    const HANDLE handles[2] = {ov.hEvent, stopEvent};
    const DWORD waitResult = WaitForMultipleObjects(2U, handles, FALSE, timeoutMs);
    if (waitResult == WAIT_OBJECT_0)
    {
        if (GetOverlappedResult(pipeHandle, &ov, &outBytesTransferred, FALSE) != FALSE)
        {
            return ERROR_SUCCESS;
        }
        return GetLastError();
    }

    // Drain any in-flight overlapped IRP before OVERLAPPED goes out of scope.
    (void)CancelIoEx(pipeHandle, &ov);
    DWORD cancelledBytes = 0U;
    const BOOL gotCancelledResult = GetOverlappedResult(pipeHandle, &ov, &cancelledBytes, TRUE);

    if (waitResult == WAIT_OBJECT_0 + 1)
    {
        return ERROR_OPERATION_ABORTED;
    }
    if (waitResult == WAIT_TIMEOUT)
    {
        if (gotCancelledResult != FALSE && cancelledBytes > 0U)
        {
            outBytesTransferred = cancelledBytes;
            return ERROR_SUCCESS;
        }
        return ERROR_TIMEOUT;
    }
    return ERROR_GEN_FAILURE;
}

DWORD
ConnectPipeOverlapped(
    HANDLE pipeHandle,
    HANDLE ioEvent,
    HANDLE stopEvent
    ) noexcept
{
    (void)ResetEvent(ioEvent);
    OVERLAPPED ov{};
    ov.hEvent = ioEvent;

    if (ConnectNamedPipe(pipeHandle, &ov) != FALSE)
    {
        return ERROR_SUCCESS;
    }

    const DWORD err = GetLastError();
    if (err == ERROR_PIPE_CONNECTED)
    {
        return ERROR_SUCCESS;
    }

    DWORD unusedBytes = 0U;
    return WaitOverlappedWithStop(pipeHandle, ov, stopEvent, err, INFINITE, unusedBytes);
}

DWORD
ReadExactOverlapped(
    HANDLE pipeHandle,
    HANDLE ioEvent,
    HANDLE stopEvent,
    void* buffer,
    size_t totalBytes,
    DWORD timeoutMs
    ) noexcept
{
    if (buffer == nullptr && totalBytes > 0U)
    {
        return ERROR_INVALID_PARAMETER;
    }

    uint8_t* dst = static_cast<uint8_t*>(buffer);
    size_t offset = 0U;
    while (offset < totalBytes)
    {
        if (WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0)
        {
            return ERROR_OPERATION_ABORTED;
        }

        (void)ResetEvent(ioEvent);
        OVERLAPPED ov{};
        ov.hEvent = ioEvent;

        const size_t remaining = totalBytes - offset;
        const DWORD chunkSize = static_cast<DWORD>((remaining > 0x00100000U) ? 0x00100000U : remaining);
        DWORD bytesRead = 0U;
        if (ReadFile(pipeHandle, dst + offset, chunkSize, &bytesRead, &ov) != FALSE)
        {
            if (bytesRead == 0U)
            {
                return ERROR_BROKEN_PIPE;
            }
            offset += static_cast<size_t>(bytesRead);
            continue;
        }

        const DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING)
        {
            return err;
        }

        DWORD overlappedBytes = 0U;
        const DWORD waitErr = WaitOverlappedWithStop(
            pipeHandle,
            ov,
            stopEvent,
            err,
            timeoutMs,
            overlappedBytes);
        if (waitErr != ERROR_SUCCESS)
        {
            return waitErr;
        }
        if (overlappedBytes == 0U)
        {
            return ERROR_BROKEN_PIPE;
        }
        offset += static_cast<size_t>(overlappedBytes);
    }

    return ERROR_SUCCESS;
}

DWORD
WriteExactOverlapped(
    HANDLE pipeHandle,
    HANDLE ioEvent,
    HANDLE stopEvent,
    const void* buffer,
    size_t totalBytes,
    DWORD timeoutMs
    ) noexcept
{
    if (buffer == nullptr && totalBytes > 0U)
    {
        return ERROR_INVALID_PARAMETER;
    }

    const uint8_t* src = static_cast<const uint8_t*>(buffer);
    size_t offset = 0U;
    while (offset < totalBytes)
    {
        if (WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0)
        {
            return ERROR_OPERATION_ABORTED;
        }

        (void)ResetEvent(ioEvent);
        OVERLAPPED ov{};
        ov.hEvent = ioEvent;

        const size_t remaining = totalBytes - offset;
        const DWORD chunkSize = static_cast<DWORD>((remaining > 0x00100000U) ? 0x00100000U : remaining);
        DWORD bytesWritten = 0U;
        if (WriteFile(pipeHandle, src + offset, chunkSize, &bytesWritten, &ov) != FALSE)
        {
            if (bytesWritten == 0U)
            {
                return ERROR_BROKEN_PIPE;
            }
            offset += static_cast<size_t>(bytesWritten);
            continue;
        }

        const DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING)
        {
            return err;
        }

        DWORD overlappedBytes = 0U;
        const DWORD waitErr = WaitOverlappedWithStop(
            pipeHandle,
            ov,
            stopEvent,
            err,
            timeoutMs,
            overlappedBytes);
        if (waitErr != ERROR_SUCCESS)
        {
            return waitErr;
        }
        if (overlappedBytes == 0U)
        {
            return ERROR_BROKEN_PIPE;
        }
        offset += static_cast<size_t>(overlappedBytes);
    }

    return ERROR_SUCCESS;
}

} // namespace

FrameIpcServer::~FrameIpcServer()
{
    Stop();
}

HRESULT
FrameIpcServer::CreateSecuredPipeHandle(
    const FrameTransportConfig& config,
    ScopedWin32Handle& outPipeHandle
    ) noexcept
{
    outPipeHandle.Reset();

    if (config.PipeName[0] == L'\0')
    {
        return E_INVALIDARG;
    }

    wchar_t canonicalAuthorizedSid[128]{};
    bool hasAuthorizedUserSid = false;
    if (config.AuthorizedUserSid[0] != L'\0')
    {
        if (!CanonicalizeSidString(
                config.AuthorizedUserSid,
                canonicalAuthorizedSid,
                ARRAYSIZE(canonicalAuthorizedSid)))
        {
            return E_INVALIDARG;
        }
        hasAuthorizedUserSid = true;
    }

    wchar_t serverSidBuf[128]{};
    bool isServerServiceAccount = false;
    const bool hasServerUserSid = QueryCurrentProcessUserSidInfo(
        serverSidBuf,
        ARRAYSIZE(serverSidBuf),
        isServerServiceAccount);
    if (!hasServerUserSid)
    {
        return LastWin32HResult();
    }

    // Explicitly deny Network (NU) and Anonymous (AN) logons and grant full control
    // to SYSTEM (SY), Built-in Administrators (BA), and LOCAL SERVICE (LS / WUDFHost.exe).
    // Broad Interactive Users (IU) is omitted whenever a specific AuthorizedUserSid is
    // provided, when RestrictDaclToAuthorizedSid is enabled, or when running under a
    // user account (which grants only its own user SID).
    static constexpr wchar_t kBaseDacl[] =
        L"D:P(D;;GA;;;NU)(D;;GA;;;AN)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;LS)";
    static constexpr wchar_t kMediumLabelSacl[] = L"S:(ML;;NW;;;ME)";

    wchar_t sddlBuf[768]{};
    if (wcsncpy_s(sddlBuf, ARRAYSIZE(sddlBuf), kBaseDacl, _TRUNCATE) != 0)
    {
        return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
    }

    auto appendAce = [&sddlBuf](const wchar_t* fragment) noexcept -> bool {
        return (wcscat_s(sddlBuf, ARRAYSIZE(sddlBuf), fragment) == 0);
    };

    if (hasAuthorizedUserSid)
    {
        wchar_t authAce[192]{};
        if (_snwprintf_s(authAce, ARRAYSIZE(authAce), _TRUNCATE, L"(A;;GRGW;;;%ls)", canonicalAuthorizedSid) <= 0 ||
            !appendAce(authAce))
        {
            return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        }
    }

    const bool restrictServerSidByAuthPolicy = config.RestrictDaclToAuthorizedSid && hasAuthorizedUserSid;
    const bool serverMatchesAuthorized =
        hasAuthorizedUserSid && (_wcsicmp(serverSidBuf, canonicalAuthorizedSid) == 0);
    if (config.AllowSameUserAccess &&
        !isServerServiceAccount &&
        !restrictServerSidByAuthPolicy &&
        !serverMatchesAuthorized)
    {
        wchar_t serverAce[192]{};
        if (_snwprintf_s(serverAce, ARRAYSIZE(serverAce), _TRUNCATE, L"(A;;GA;;;%ls)", serverSidBuf) <= 0 ||
            !appendAce(serverAce))
        {
            return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        }
    }

    // Only allow Interactive Users (IU) in the DACL when WUDFHost.exe runs as a service
    // account (LOCAL SERVICE / SYSTEM) without a brokered AuthorizedUserSid, while the
    // server still strictly enforces TokenSessionId, integrity, and membership checks
    // during VerifyConnectedClientIdentity() before transmitting any frame.
    if (isServerServiceAccount &&
        !hasAuthorizedUserSid &&
        !config.RestrictDaclToAuthorizedSid &&
        config.AllowActiveConsoleInteractiveUser)
    {
        if (!appendAce(L"(A;;GRGW;;;IU)"))
        {
            return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        }
    }

    if (!appendAce(kMediumLabelSacl))
    {
        return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
    }

    PSECURITY_DESCRIPTOR rawSd = nullptr;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddlBuf,
            SDDL_REVISION_1,
            &rawSd,
            nullptr) == FALSE ||
        rawSd == nullptr)
    {
        return LastWin32HResult();
    }
    LocalFreeGuard sdGuard{rawSd};

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = rawSd;
    sa.bInheritHandle = FALSE;

    constexpr DWORD kPipeBufferBytes = 1024U * 1024U;
    const HANDLE pipe = CreateNamedPipeW(
        config.PipeName,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1U,
        kPipeBufferBytes,
        65536U,
        0U,
        &sa);

    if (pipe == INVALID_HANDLE_VALUE)
    {
        return LastWin32HResult();
    }

    outPipeHandle.Reset(pipe);
    return S_OK;
}

ipc::FrameIpcStatus
FrameIpcServer::VerifyConnectedClientIdentity(
    HANDLE pipeHandle,
    const ipc::FrameIpcClientHello& clientHello,
    ScopedWin32Handle* outClientProcess
    ) const noexcept
{
    if (outClientProcess != nullptr)
    {
        outClientProcess->Reset();
    }
    if (pipeHandle == nullptr || pipeHandle == INVALID_HANDLE_VALUE)
    {
        return ipc::FrameIpcStatus::UnauthorizedClient;
    }

    // 1. Verify kernel-reported client PID matches ClientHello without relying on secrets.
    ULONG osClientPid = 0U;
    if (GetNamedPipeClientProcessId(pipeHandle, &osClientPid) == FALSE ||
        osClientPid == 0U ||
        clientHello.ClientProcessId != static_cast<uint32_t>(osClientPid))
    {
        return ipc::FrameIpcStatus::UnauthorizedClient;
    }

    // 2. Obtain the effective security token used by the client when opening the Named Pipe.
    ScopedWin32Handle clientToken;
    ScopedWin32Handle clientProcHandle;
    if (ImpersonateNamedPipeClient(pipeHandle) == FALSE)
    {
        return ipc::FrameIpcStatus::UnauthorizedClient;
    }
    {
        ScopedRevertToSelf revertGuard(true);
        HANDLE threadToken = nullptr;
        if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_DUPLICATE, TRUE, &threadToken) != FALSE &&
            threadToken != nullptr)
        {
            clientToken.Reset(threadToken);
        }
        if (outClientProcess != nullptr && clientToken.IsValid())
        {
            HANDLE openedProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, osClientPid);
            if (openedProc != nullptr)
            {
                clientProcHandle.Reset(openedProc);
            }
        }
        revertGuard.RevertNow();
    }

    if (!clientToken.IsValid())
    {
        return ipc::FrameIpcStatus::UnauthorizedClient;
    }

    TOKEN_TYPE tokenType = TokenPrimary;
    DWORD typeSize = 0U;
    if (GetTokenInformation(clientToken.Get(), TokenType, &tokenType, sizeof(tokenType), &typeSize) == FALSE ||
        typeSize != sizeof(tokenType) ||
        tokenType != TokenImpersonation)
    {
        return ipc::FrameIpcStatus::UnauthorizedClient;
    }

    SECURITY_IMPERSONATION_LEVEL impLevel = SecurityAnonymous;
    DWORD impSize = 0U;
    if (GetTokenInformation(clientToken.Get(), TokenImpersonationLevel, &impLevel, sizeof(impLevel), &impSize) == FALSE ||
        impSize != sizeof(impLevel) ||
        impLevel < SecurityIdentification)
    {
        return ipc::FrameIpcStatus::UnauthorizedClient;
    }

    // 3. Reject AppContainer / sandboxed tokens as well as Network, Anonymous, and Guest logons.
    DWORD isAppContainer = 1U;
    DWORD appContSize = 0U;
    if (GetTokenInformation(
            clientToken.Get(),
            TokenIsAppContainer,
            &isAppContainer,
            sizeof(isAppContainer),
            &appContSize) == FALSE ||
        appContSize != sizeof(isAppContainer) ||
        isAppContainer != 0U)
    {
        return ipc::FrameIpcStatus::UnauthorizedClient;
    }

    bool isNetwork = true;
    bool isAnonymous = true;
    bool isBuiltinGuest = true;
    if (!IsImpersonationTokenMemberOfWellKnown(clientToken.Get(), WinNetworkSid, isNetwork) ||
        !IsImpersonationTokenMemberOfWellKnown(clientToken.Get(), WinAnonymousSid, isAnonymous) ||
        !IsImpersonationTokenMemberOfWellKnown(clientToken.Get(), WinBuiltinGuestsSid, isBuiltinGuest) ||
        isNetwork || isAnonymous || isBuiltinGuest)
    {
        return ipc::FrameIpcStatus::UnauthorizedClient;
    }

    // 4. Enforce Mandatory Integrity Level (>= MinimumIntegrityRid, default Medium 0x2000).
    uint8_t ilBuf[SECURITY_MAX_SID_SIZE + sizeof(TOKEN_MANDATORY_LABEL)]{};
    DWORD ilSize = 0U;
    if (GetTokenInformation(clientToken.Get(), TokenIntegrityLevel, ilBuf, sizeof(ilBuf), &ilSize) == FALSE ||
        ilSize < sizeof(TOKEN_MANDATORY_LABEL))
    {
        return ipc::FrameIpcStatus::UnauthorizedClient;
    }

    const TOKEN_MANDATORY_LABEL* tml = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(ilBuf);
    if (tml->Label.Sid == nullptr || IsValidSid(tml->Label.Sid) == FALSE)
    {
        return ipc::FrameIpcStatus::UnauthorizedClient;
    }
    const PUCHAR subAuthCountPtr = GetSidSubAuthorityCount(tml->Label.Sid);
    if (subAuthCountPtr == nullptr || *subAuthCountPtr == 0U)
    {
        return ipc::FrameIpcStatus::UnauthorizedClient;
    }
    const DWORD integrityRid = *GetSidSubAuthority(tml->Label.Sid, static_cast<DWORD>(*subAuthCountPtr - 1U));
    if (integrityRid < m_config.MinimumIntegrityRid)
    {
        return ipc::FrameIpcStatus::UnauthorizedClient;
    }

    // 5. Verify kernel logon/Terminal Services Session ID matches ClientHello and policy.
    DWORD clientTokenSessionId = 0U;
    DWORD sessionSize = 0U;
    if (GetTokenInformation(
            clientToken.Get(),
            TokenSessionId,
            &clientTokenSessionId,
            sizeof(clientTokenSessionId),
            &sessionSize) == FALSE ||
        sessionSize != sizeof(clientTokenSessionId) ||
        clientHello.ClientSessionId != static_cast<uint32_t>(clientTokenSessionId))
    {
        return ipc::FrameIpcStatus::UnauthorizedClient;
    }

    const DWORD activeConsoleSessionId = WTSGetActiveConsoleSessionId();
    if (m_config.RequireMatchingClientSession)
    {
        if (m_config.HasExplicitAllowedSessionId)
        {
            if (clientTokenSessionId != m_config.AllowedClientSessionId)
            {
                return ipc::FrameIpcStatus::UnauthorizedClient;
            }
        }
        else
        {
            DWORD serverSessionId = 0U;
            if (ProcessIdToSessionId(GetCurrentProcessId(), &serverSessionId) == FALSE)
            {
                return ipc::FrameIpcStatus::UnauthorizedClient;
            }

            const bool matchesServerSession = (clientTokenSessionId == serverSessionId);
            const bool matchesActiveConsole =
                (activeConsoleSessionId != 0xFFFFFFFFU && clientTokenSessionId == activeConsoleSessionId);
            if (!matchesServerSession && !matchesActiveConsole)
            {
                return ipc::FrameIpcStatus::UnauthorizedClient;
            }
        }
    }

    // 6. Verify client user SID / privileged role / active console interactive logon.
    uint8_t clientUserBuf[256]{};
    PSID clientUserSid = nullptr;
    if (!QueryTokenUserSidBytes(clientToken.Get(), clientUserBuf, sizeof(clientUserBuf), clientUserSid) ||
        IsGuestUserSid(clientUserSid))
    {
        return ipc::FrameIpcStatus::UnauthorizedClient;
    }

    HANDLE serverProcTokenRaw = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &serverProcTokenRaw) == FALSE ||
        serverProcTokenRaw == nullptr)
    {
        return ipc::FrameIpcStatus::UnauthorizedClient;
    }
    ScopedWin32Handle serverProcToken(serverProcTokenRaw);

    uint8_t serverUserBuf[256]{};
    PSID serverUserSid = nullptr;
    if (!QueryTokenUserSidBytes(serverProcToken.Get(), serverUserBuf, sizeof(serverUserBuf), serverUserSid))
    {
        return ipc::FrameIpcStatus::UnauthorizedClient;
    }

    const bool isServerServiceAccount =
        IsSidEqualToWellKnown(serverUserSid, WinLocalServiceSid) ||
        IsSidEqualToWellKnown(serverUserSid, WinLocalSystemSid);

    bool isBuiltinAdmin = false;
    (void)IsImpersonationTokenMemberOfWellKnown(clientToken.Get(), WinBuiltinAdministratorsSid, isBuiltinAdmin);
    const bool isLocalSystem = IsSidEqualToWellKnown(clientUserSid, WinLocalSystemSid);
    const bool isPrivilegedAdminOrSystem = isBuiltinAdmin || isLocalSystem;

    bool isAuthorized = false;
    if (m_config.AuthorizedUserSid[0] != L'\0')
    {
        PSID expectedSid = nullptr;
        if (ConvertStringSidToSidW(m_config.AuthorizedUserSid, &expectedSid) == FALSE || expectedSid == nullptr)
        {
            return ipc::FrameIpcStatus::UnauthorizedClient;
        }
        LocalFreeGuard expectedSidGuard{expectedSid};

        if (IsValidSid(expectedSid) != FALSE && EqualSid(clientUserSid, expectedSid) != FALSE)
        {
            isAuthorized = true;
        }
        else if (m_config.AllowBuiltinAdmins && isPrivilegedAdminOrSystem)
        {
            isAuthorized = true;
        }
    }
    else
    {
        if (m_config.AllowSameUserAccess && EqualSid(clientUserSid, serverUserSid) != FALSE)
        {
            isAuthorized = true;
        }
        else if (m_config.AllowBuiltinAdmins && isPrivilegedAdminOrSystem)
        {
            isAuthorized = true;
        }
        else if (isServerServiceAccount && m_config.AllowActiveConsoleInteractiveUser)
        {
            bool isInteractive = false;
            if (IsImpersonationTokenMemberOfWellKnown(clientToken.Get(), WinInteractiveSid, isInteractive) &&
                isInteractive &&
                clientTokenSessionId != 0U &&
                activeConsoleSessionId != 0xFFFFFFFFU &&
                clientTokenSessionId == activeConsoleSessionId)
            {
                isAuthorized = true;
            }
        }
    }

    if (isAuthorized && outClientProcess != nullptr)
    {
        if (!clientProcHandle.IsValid())
        {
            HANDLE fallbackProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, osClientPid);
            if (fallbackProc != nullptr)
            {
                clientProcHandle.Reset(fallbackProc);
            }
        }
        if (clientProcHandle.IsValid())
        {
            *outClientProcess = std::move(clientProcHandle);
        }
    }

    return isAuthorized ? ipc::FrameIpcStatus::Ok : ipc::FrameIpcStatus::UnauthorizedClient;
}

HRESULT
FrameIpcServer::Start(
    const FrameTransportConfig& config
    ) noexcept
{
    ExclusiveLock lifecycleGuard(&m_lifecycleLock);

    if (InterlockedCompareExchange(&m_running, 0, 0) != 0)
    {
        return S_OK;
    }

    if (config.PipeName[0] == L'\0')
    {
        return E_INVALIDARG;
    }

    size_t clampedQueueDepth = (config.MaxQueueDepth == 0U)
        ? 1U
        : ((config.MaxQueueDepth > kMaxSupportedQueueDepth) ? kMaxSupportedQueueDepth : config.MaxQueueDepth);
    size_t clampedPoolSize = config.BufferPoolSize;
    if (clampedPoolSize == 0U)
    {
        clampedPoolSize = clampedQueueDepth + 2U;
    }
    if (clampedPoolSize > kMaxSupportedPoolSize)
    {
        clampedPoolSize = kMaxSupportedPoolSize;
    }
    if (clampedQueueDepth > clampedPoolSize)
    {
        clampedQueueDepth = clampedPoolSize;
    }

    ScopedWin32Handle pipeHandle;
    const HRESULT pipeHr = CreateSecuredPipeHandle(config, pipeHandle);
    if (FAILED(pipeHr))
    {
        ExclusiveLock metricsGuard(&m_metricsLock);
        m_transportMetrics.LastTransportError = pipeHr;
        return pipeHr;
    }

    ScopedWin32Handle stopEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!stopEvent.IsValid())
    {
        return LastWin32HResult();
    }

    ScopedWin32Handle frameEvent(CreateEventW(nullptr, FALSE, FALSE, nullptr));
    if (!frameEvent.IsValid())
    {
        return LastWin32HResult();
    }

    {
        ExclusiveLock queueGuard(&m_queueLock);
        ++m_poolEpoch;
        ClearAllBuffersLocked();

        m_effectiveMaxQueueDepth = clampedQueueDepth;
        m_effectiveMaxPoolSize = clampedPoolSize;
        m_nextPublishSequence = 1ULL;
        m_sessionGeneration = 0ULL;
        m_activeSessionId = 0ULL;
        m_activeSessionAuthorized = false;
        m_activeSessionMode = ipc::FrameIpcTransportMode::CpuStagingPipe;
        m_activeSessionAllowCpuFallback = false;
        m_currentSessionSummary = {};
        m_lastCompletedSessionSummary = {};
        m_sessionStartGpuSharedBaseline = 0ULL;
        m_sessionStartGpuDroppedBaseline = 0ULL;
        m_sessionStartGpuSyncTimeoutsBaseline = 0ULL;
        InterlockedExchange64(&m_pendingAckCount, 0);
        m_queueMetrics = {};
        m_queueMetrics.Running = true;

        if (config.PreallocatePoolOnStart)
        {
            for (size_t i = 0U; i < clampedPoolSize; ++i)
            {
                std::unique_ptr<ExtractedFrameBuffer> slot(
                    (InterlockedCompareExchange(&m_simulateSlotAllocationFailure, 0, 0) != 0)
                        ? nullptr
                        : new (std::nothrow) ExtractedFrameBuffer());
                if (slot == nullptr)
                {
                    ClearAllBuffersLocked();
                    m_queueMetrics.Running = false;
                    ++m_queueMetrics.PoolAllocationFailures;
                    return E_OUTOFMEMORY;
                }
                slot->PooledSlot = true;
                slot->InFlightFromPool = false;
                slot->PoolEpoch = m_poolEpoch;
                if (!m_freePool.PushBack(std::move(slot)))
                {
                    ClearAllBuffersLocked();
                    m_queueMetrics.Running = false;
                    return E_OUTOFMEMORY;
                }
            }
            m_totalPoolSlots = clampedPoolSize;
        }
        UpdatePoolMetricsLocked();
    }

    {
        ExclusiveLock metricsGuard(&m_metricsLock);
        m_transportMetrics = {};
        m_transportMetrics.Running = true;
    }

    m_config = config;
    if (m_config.SharedTexturePoolSize < ipc::kMinSharedTexturePoolSize)
    {
        m_config.SharedTexturePoolSize = ipc::kMinSharedTexturePoolSize;
    }
    else if (m_config.SharedTexturePoolSize > ipc::kMaxSharedTexturePoolSize)
    {
        m_config.SharedTexturePoolSize = ipc::kMaxSharedTexturePoolSize;
    }
    if (m_config.GpuKeyedMutexTimeoutMs == 0U)
    {
        m_config.GpuKeyedMutexTimeoutMs = ipc::kDefaultGpuKeyedMutexTimeoutMs;
    }
    if (m_config.IoTimeoutMs == 0U)
    {
        m_config.IoTimeoutMs = ipc::kDefaultIpcIoTimeoutMs;
    }
    else if (m_config.IoTimeoutMs < kMinIpcIoTimeoutMs)
    {
        m_config.IoTimeoutMs = kMinIpcIoTimeoutMs;
    }
    else if (m_config.IoTimeoutMs > kMaxIpcIoTimeoutMs)
    {
        m_config.IoTimeoutMs = kMaxIpcIoTimeoutMs;
    }

    if (m_config.SharedTexturePool != nullptr && m_config.EnableGpuSharedTransport)
    {
        if (m_config.SharedTexturePool->GetPoolSize() != m_config.SharedTexturePoolSize)
        {
            (void)m_config.SharedTexturePool->Configure(
                m_config.SharedTexturePoolSize,
                (m_config.AuthorizedUserSid[0] != L'\0') ? m_config.AuthorizedUserSid : nullptr,
                m_config.RestrictDaclToAuthorizedSid,
                m_config.AllowSameUserAccess,
                m_config.AllowBuiltinAdmins,
                m_config.AllowActiveConsoleInteractiveUser,
                10U);
        }
    }

    m_pipeHandle = std::move(pipeHandle);
    m_stopEvent = std::move(stopEvent);
    m_frameAvailableEvent = std::move(frameEvent);
    InterlockedExchange(&m_activeSessionNegotiatedGpu, 0);
    InterlockedExchange(&m_stopRequested, 0);
    InterlockedExchange(&m_running, 1);

    DWORD workerTid = 0U;
    ScopedWin32Handle workerThread(CreateThread(
        nullptr,
        0,
        &FrameIpcServer::WorkerThreadProc,
        this,
        0,
        &workerTid));
    if (!workerThread.IsValid())
    {
        const HRESULT threadHr = LastWin32HResult();
        InterlockedExchange(&m_running, 0);
        InterlockedExchange(&m_stopRequested, 1);
        m_pipeHandle.Reset();
        m_stopEvent.Reset();
        m_frameAvailableEvent.Reset();
        {
            ExclusiveLock queueGuard(&m_queueLock);
            ClearAllBuffersLocked();
            m_queueMetrics.Running = false;
        }
        {
            ExclusiveLock metricsGuard(&m_metricsLock);
            m_transportMetrics.Running = false;
            m_transportMetrics.LastTransportError = threadHr;
        }
        return threadHr;
    }

    m_workerThread = std::move(workerThread);
    return S_OK;
}

void
FrameIpcServer::Stop() noexcept
{
    ExclusiveLock lifecycleGuard(&m_lifecycleLock);

    InterlockedExchange(&m_stopRequested, 1);
    if (m_stopEvent.IsValid())
    {
        (void)SetEvent(m_stopEvent.Get());
    }
    if (m_frameAvailableEvent.IsValid())
    {
        (void)SetEvent(m_frameAvailableEvent.Get());
    }

    if (m_workerThread.IsValid())
    {
        (void)WaitForSingleObject(m_workerThread.Get(), INFINITE);
        m_workerThread.Reset();
    }

    InterlockedExchange(&m_running, 0);
    m_pipeHandle.Reset();
    m_stopEvent.Reset();
    m_frameAvailableEvent.Reset();

    {
        ExclusiveLock queueGuard(&m_queueLock);
        ++m_poolEpoch;
        ClearAllBuffersLocked();
        m_queueMetrics.Running = false;
        UpdatePoolMetricsLocked();
    }

    {
        ExclusiveLock metricsGuard(&m_metricsLock);
        m_transportMetrics.Running = false;
        m_transportMetrics.ActiveHostConnections = 0U;
        m_transportMetrics.ActiveSessionId = 0ULL;
    }
}

bool
FrameIpcServer::IsRunning() const noexcept
{
    return InterlockedCompareExchange(const_cast<volatile LONG*>(&m_running), 0, 0) != 0 &&
           InterlockedCompareExchange(const_cast<volatile LONG*>(&m_stopRequested), 0, 0) == 0;
}

void
FrameIpcServer::SetSimulateSlotAllocationFailureForTesting(
    bool simulateFailure
    ) noexcept
{
    InterlockedExchange(&m_simulateSlotAllocationFailure, simulateFailure ? 1 : 0);
}

void
FrameIpcServer::SetNextPublishSequenceForTesting(
    uint64_t nextSequence
    ) noexcept
{
    ExclusiveLock queueGuard(&m_queueLock);
    m_nextPublishSequence = (nextSequence == 0ULL) ? 1ULL : nextSequence;
}

TransportSessionSnapshot
FrameIpcServer::GetActiveSessionSnapshot() const noexcept
{
    SharedLock queueGuard(&m_queueLock);
    TransportSessionSnapshot snap{};
    snap.SessionId = m_activeSessionId;
    snap.SessionGeneration = m_sessionGeneration;
    snap.ClientAuthorized = m_activeSessionAuthorized;
    snap.HasActiveConsumer = IsRunning() && m_activeSessionAuthorized && (m_activeSessionId != 0ULL);
    snap.NegotiatedMode = m_activeSessionMode;
    snap.AllowCpuFallback = m_activeSessionAllowCpuFallback;
    snap.RequireGpuOnly =
        snap.HasActiveConsumer &&
        (m_activeSessionMode == ipc::FrameIpcTransportMode::GpuSharedNtHandle) &&
        !m_activeSessionAllowCpuFallback;
    return snap;
}

bool
FrameIpcServer::GetLastCompletedSessionSummary(
    DriverSessionSummarySnapshot& outSummary
    ) const noexcept
{
    SharedLock queueGuard(&m_queueLock);
    outSummary = m_lastCompletedSessionSummary;
    return outSummary.Valid;
}

bool
FrameIpcServer::ShouldProduceGpuSharedFrame() const noexcept
{
    return IsRunning() &&
           (m_config.SharedTexturePool != nullptr) &&
           m_config.EnableGpuSharedTransport &&
           (InterlockedCompareExchange(const_cast<volatile LONG*>(&m_activeSessionNegotiatedGpu), 0, 0) != 0);
}

void
FrameIpcServer::ReturnBufferToFreePoolLocked(
    std::unique_ptr<ExtractedFrameBuffer> buffer,
    bool freePixelStorage
    ) noexcept
{
    if (buffer == nullptr)
    {
        return;
    }

    if (freePixelStorage)
    {
        buffer->ResetMetadataAndFreePixels();
    }
    else
    {
        buffer->ResetMetadataKeepCapacity();
    }

    if (buffer->PooledSlot && buffer->PoolEpoch == m_poolEpoch)
    {
        buffer->InFlightFromPool = false;
        if (m_freePool.Size() >= m_effectiveMaxPoolSize ||
            !m_freePool.PushBack(std::move(buffer)))
        {
            if (m_totalPoolSlots > 0U)
            {
                --m_totalPoolSlots;
            }
        }
    }
}

void
FrameIpcServer::ReleaseFrameResources(
    const ExtractedFrameBuffer* frame,
    bool countGpuAsDrop
    ) noexcept
{
    if (frame != nullptr && frame->IsGpuSharedFrame && m_config.SharedTexturePool != nullptr)
    {
        m_config.SharedTexturePool->ReleaseQueuedSlot(
            frame->GpuSlotIndex,
            frame->GpuSlotGeneration,
            countGpuAsDrop);
    }
}

void
FrameIpcServer::ReleasePendingGpuSlots(
    const PendingGpuSlotRelease* pending,
    size_t count
    ) noexcept
{
    if (pending == nullptr || m_config.SharedTexturePool == nullptr)
    {
        return;
    }
    for (size_t i = 0U; i < count; ++i)
    {
        if (pending[i].Valid)
        {
            m_config.SharedTexturePool->ReleaseQueuedSlot(
                pending[i].SlotIndex,
                pending[i].SlotGeneration,
                pending[i].CountAsDrop);
        }
    }
}

std::unique_ptr<ExtractedFrameBuffer>
FrameIpcServer::AcquireBufferSlot() noexcept
{
    bool needDynamicAlloc = false;
    uint64_t acquiredEpoch = 0ULL;
    PendingGpuSlotRelease pendingReleases[kMaxSupportedQueueDepth]{};
    size_t pendingReleaseCount = 0U;
    std::unique_ptr<ExtractedFrameBuffer> acquiredEvictedSlot{};

    {
        ExclusiveLock queueGuard(&m_queueLock);
        if (!IsRunning())
        {
            return nullptr;
        }

        if (!m_freePool.Empty())
        {
            auto slot = m_freePool.PopFront();
            if (slot != nullptr)
            {
                slot->PooledSlot = true;
                slot->InFlightFromPool = true;
                slot->PoolEpoch = m_poolEpoch;
                ++m_inFlightSlots;
                UpdatePoolMetricsLocked();
                slot->ResetMetadataKeepCapacity();
                return slot;
            }
        }

        if (m_totalPoolSlots < m_effectiveMaxPoolSize)
        {
            ++m_totalPoolSlots;
            ++m_inFlightSlots;
            acquiredEpoch = m_poolEpoch;
            UpdatePoolMetricsLocked();
            needDynamicAlloc = true;
        }
        else if (!m_queue.Empty())
        {
            while (!m_queue.Empty())
            {
                auto evicted = m_queue.PopFront();
                ++m_queueMetrics.FramesDroppedByBackpressure;
                ++m_queueMetrics.QueueEvictionsByBackpressure;
                if (m_activeSessionAuthorized)
                {
                    ++m_currentSessionSummary.FramesDroppedByBackpressure;
                }
                if (evicted == nullptr)
                {
                    continue;
                }
                if (evicted->IsGpuSharedFrame && pendingReleaseCount < ARRAYSIZE(pendingReleases))
                {
                    pendingReleases[pendingReleaseCount++] = PendingGpuSlotRelease{
                        true,
                        evicted->GpuSlotIndex,
                        evicted->GpuSlotGeneration,
                        true};
                }
                if (evicted->PooledSlot)
                {
                    evicted->InFlightFromPool = true;
                    evicted->PoolEpoch = m_poolEpoch;
                    ++m_inFlightSlots;
                    UpdatePoolMetricsLocked();
                    evicted->ResetMetadataKeepCapacity();
                    acquiredEvictedSlot = std::move(evicted);
                    break;
                }
                if (m_totalPoolSlots < m_effectiveMaxPoolSize &&
                    m_inFlightSlots < m_effectiveMaxPoolSize)
                {
                    evicted->PooledSlot = true;
                    evicted->InFlightFromPool = true;
                    evicted->PoolEpoch = m_poolEpoch;
                    ++m_totalPoolSlots;
                    ++m_inFlightSlots;
                    UpdatePoolMetricsLocked();
                    evicted->ResetMetadataKeepCapacity();
                    acquiredEvictedSlot = std::move(evicted);
                    break;
                }
            }

            if (acquiredEvictedSlot == nullptr)
            {
                ++m_queueMetrics.PoolExhaustionDrops;
                UpdatePoolMetricsLocked();
            }
        }
        else
        {
            ++m_queueMetrics.FramesDroppedByBackpressure;
            ++m_queueMetrics.PoolExhaustionDrops;
            UpdatePoolMetricsLocked();
            return nullptr;
        }
    }

    if (pendingReleaseCount > 0U)
    {
        ReleasePendingGpuSlots(pendingReleases, pendingReleaseCount);
    }
    if (acquiredEvictedSlot != nullptr)
    {
        return acquiredEvictedSlot;
    }

    if (needDynamicAlloc)
    {
        std::unique_ptr<ExtractedFrameBuffer> allocated(
            (InterlockedCompareExchange(&m_simulateSlotAllocationFailure, 0, 0) != 0)
                ? nullptr
                : new (std::nothrow) ExtractedFrameBuffer());
        if (allocated == nullptr)
        {
            ExclusiveLock queueGuard(&m_queueLock);
            if (m_poolEpoch == acquiredEpoch)
            {
                if (m_inFlightSlots > 0U)
                {
                    --m_inFlightSlots;
                }
                if (m_totalPoolSlots > 0U)
                {
                    --m_totalPoolSlots;
                }
                ++m_queueMetrics.PoolAllocationFailures;
                ++m_queueMetrics.FramesDroppedByBackpressure;
                UpdatePoolMetricsLocked();
            }
            return nullptr;
        }

        ExclusiveLock queueGuard(&m_queueLock);
        if (!IsRunning() || m_poolEpoch != acquiredEpoch)
        {
            if (m_poolEpoch == acquiredEpoch)
            {
                if (m_inFlightSlots > 0U)
                {
                    --m_inFlightSlots;
                }
                if (m_totalPoolSlots > 0U)
                {
                    --m_totalPoolSlots;
                }
                UpdatePoolMetricsLocked();
            }
            return nullptr;
        }

        allocated->PooledSlot = true;
        allocated->InFlightFromPool = true;
        allocated->PoolEpoch = acquiredEpoch;
        return allocated;
    }

    return nullptr;
}

void
FrameIpcServer::RecycleBufferSlot(
    std::unique_ptr<ExtractedFrameBuffer> slot
    ) noexcept
{
    if (slot == nullptr)
    {
        return;
    }

    slot->ResetMetadataKeepCapacity();

    ExclusiveLock queueGuard(&m_queueLock);
    const bool matchesActiveEpoch = (slot->PoolEpoch == m_poolEpoch);
    const bool wasPooled = slot->PooledSlot;
    const bool wasInFlightFromPool = (wasPooled && slot->InFlightFromPool);

    if (matchesActiveEpoch && wasInFlightFromPool && m_inFlightSlots > 0U)
    {
        --m_inFlightSlots;
    }
    slot->InFlightFromPool = false;

    if (!IsRunning() || (wasPooled && !matchesActiveEpoch))
    {
        if (matchesActiveEpoch && wasPooled && m_totalPoolSlots > 0U)
        {
            --m_totalPoolSlots;
        }
        UpdatePoolMetricsLocked();
        return;
    }

    if (wasPooled)
    {
        if (m_freePool.Size() < m_effectiveMaxPoolSize &&
            m_freePool.PushBack(std::move(slot)))
        {
            UpdatePoolMetricsLocked();
            return;
        }
        if (m_totalPoolSlots > 0U)
        {
            --m_totalPoolSlots;
        }
        UpdatePoolMetricsLocked();
        return;
    }

    // Adopt non-pooled external buffer only if pool capacity still has headroom.
    if (m_totalPoolSlots < m_effectiveMaxPoolSize &&
        m_freePool.Size() < m_effectiveMaxPoolSize)
    {
        slot->PooledSlot = true;
        slot->PoolEpoch = m_poolEpoch;
        if (m_freePool.PushBack(std::move(slot)))
        {
            ++m_totalPoolSlots;
        }
    }
    UpdatePoolMetricsLocked();
}

HRESULT
FrameIpcServer::EnqueueFrame(
    std::unique_ptr<ExtractedFrameBuffer> frame,
    bool& outEvictedOldest,
    uint64_t* outAssignedSequence
    ) noexcept
{
    outEvictedOldest = false;
    if (outAssignedSequence != nullptr)
    {
        *outAssignedSequence = 0ULL;
    }
    if (frame == nullptr)
    {
        return E_INVALIDARG;
    }

    frame->EnqueueQpcTime = QueryCurrentQpc();

    if (!IsRunning())
    {
        ReleaseFrameResources(frame.get(), false);
        RecycleBufferSlot(std::move(frame));
        return E_ABORT;
    }

    HANDLE eventToSignal = nullptr;
    HRESULT resultHr = S_OK;
    PendingGpuSlotRelease pendingReleases[kMaxSupportedQueueDepth + 1U]{};
    size_t pendingReleaseCount = 0U;

    {
        ExclusiveLock queueGuard(&m_queueLock);
        if (!IsRunning() || (frame->PooledSlot && frame->PoolEpoch != m_poolEpoch))
        {
            if (frame->PooledSlot && frame->PoolEpoch == m_poolEpoch)
            {
                if (frame->InFlightFromPool && m_inFlightSlots > 0U)
                {
                    --m_inFlightSlots;
                }
                if (m_totalPoolSlots > 0U)
                {
                    --m_totalPoolSlots;
                }
                UpdatePoolMetricsLocked();
            }
            if (frame->IsGpuSharedFrame)
            {
                pendingReleases[pendingReleaseCount++] = PendingGpuSlotRelease{
                    true,
                    frame->GpuSlotIndex,
                    frame->GpuSlotGeneration,
                    false};
            }
            resultHr = E_ABORT;
        }
        else
        {
            const bool wasInFlightFromPool = (frame->PooledSlot && frame->InFlightFromPool);
            if (wasInFlightFromPool && m_inFlightSlots > 0U)
            {
                --m_inFlightSlots;
            }
            frame->InFlightFromPool = false;

            const auto recordRejectionLocked = [&](bool isGpu, uint32_t slotIdx, uint32_t slotGen, HRESULT hr) noexcept {
                if (isGpu && pendingReleaseCount < ARRAYSIZE(pendingReleases))
                {
                    pendingReleases[pendingReleaseCount++] = PendingGpuSlotRelease{
                        true,
                        slotIdx,
                        slotGen,
                        false};
                }
                ReturnBufferToFreePoolLocked(std::move(frame), false);
                UpdatePoolMetricsLocked();
                resultHr = hr;
            };

            // 1. Validate session affinity and active consumer policy under m_queueLock.
            if (frame->HasSessionBinding)
            {
                if (!m_activeSessionAuthorized ||
                    m_activeSessionId == 0ULL ||
                    frame->TargetSessionId != m_activeSessionId ||
                    frame->TargetSessionGeneration != m_sessionGeneration)
                {
                    ++m_queueMetrics.FramesDiscardedStaleSession;
                    if (m_activeSessionAuthorized)
                    {
                        ++m_currentSessionSummary.FramesDiscardedStaleSession;
                    }
                    recordRejectionLocked(
                        frame->IsGpuSharedFrame,
                        frame->GpuSlotIndex,
                        frame->GpuSlotGeneration,
                        HRESULT_FROM_WIN32(ERROR_CONTEXT_EXPIRED));
                }
            }
            else if (m_config.RequireActiveSessionForEnqueue &&
                     (!m_activeSessionAuthorized || m_activeSessionId == 0ULL))
            {
                ++m_queueMetrics.FramesDiscardedNoConsumer;
                recordRejectionLocked(
                    frame->IsGpuSharedFrame,
                    frame->GpuSlotIndex,
                    frame->GpuSlotGeneration,
                    HRESULT_FROM_WIN32(ERROR_NO_DATA));
            }

            // 2. Validate transport contract compatibility with active session before publishing.
            if (SUCCEEDED(resultHr) && m_activeSessionAuthorized)
            {
                if (m_activeSessionMode == ipc::FrameIpcTransportMode::GpuSharedNtHandle &&
                    !frame->IsGpuSharedFrame &&
                    !m_activeSessionAllowCpuFallback)
                {
                    ++m_queueMetrics.FramesDiscardedTransportMismatch;
                    ++m_currentSessionSummary.FramesDiscardedTransportMismatch;
                    recordRejectionLocked(
                        false,
                        0U,
                        0U,
                        DXGI_ERROR_INVALID_CALL);
                }
                else if (m_activeSessionMode == ipc::FrameIpcTransportMode::CpuStagingPipe &&
                         frame->IsGpuSharedFrame)
                {
                    ++m_queueMetrics.FramesDiscardedTransportMismatch;
                    ++m_currentSessionSummary.FramesDiscardedTransportMismatch;
                    recordRejectionLocked(
                        true,
                        frame->GpuSlotIndex,
                        frame->GpuSlotGeneration,
                        DXGI_ERROR_INVALID_CALL);
                }
            }

            // 3. Validate structural dimensions/payload before consuming a wire FrameSequence.
            if (SUCCEEDED(resultHr))
            {
                const bool dimsInvalid = (frame->Width == 0U || frame->Height == 0U);
                const bool cpuPayloadInvalid =
                    (!frame->IsGpuSharedFrame &&
                     (frame->Pixels.empty() || frame->Pixels.size() > ipc::kMaxFramePayloadBytes));
                const bool seqMissingWhenExternal =
                    (!m_config.AssignSequenceOnEnqueue && frame->FrameSequence == 0ULL);
                if (dimsInvalid || cpuPayloadInvalid || seqMissingWhenExternal)
                {
                    recordRejectionLocked(
                        frame->IsGpuSharedFrame,
                        frame->GpuSlotIndex,
                        frame->GpuSlotGeneration,
                        E_INVALIDARG);
                }
            }

            // 4. Enforce bounded drop-oldest queue capacity and assign authoritative sequence atomically.
            if (SUCCEEDED(resultHr))
            {
                while (m_queue.Size() >= m_effectiveMaxQueueDepth)
                {
                    auto evicted = m_queue.PopFront();
                    ++m_queueMetrics.FramesDroppedByBackpressure;
                    ++m_queueMetrics.QueueEvictionsByBackpressure;
                    if (m_activeSessionAuthorized)
                    {
                        ++m_currentSessionSummary.FramesDroppedByBackpressure;
                    }
                    outEvictedOldest = true;

                    if (evicted != nullptr)
                    {
                        if (evicted->IsGpuSharedFrame && pendingReleaseCount < ARRAYSIZE(pendingReleases))
                        {
                            pendingReleases[pendingReleaseCount++] = PendingGpuSlotRelease{
                                true,
                                evicted->GpuSlotIndex,
                                evicted->GpuSlotGeneration,
                                true};
                        }
                        ReturnBufferToFreePoolLocked(std::move(evicted), false);
                    }
                }

                if (m_config.AssignSequenceOnEnqueue)
                {
                    if (m_nextPublishSequence == 0ULL)
                    {
                        m_nextPublishSequence = 1ULL;
                    }
                    const uint64_t assigned = m_nextPublishSequence;
                    frame->FrameSequence = assigned;
                    if (assigned == UINT64_MAX)
                    {
                        m_nextPublishSequence = 1ULL;
                        ++m_queueMetrics.SequenceWrapAroundCount;
                    }
                    else
                    {
                        m_nextPublishSequence = assigned + 1ULL;
                    }
                }
                else if (frame->FrameSequence >= m_nextPublishSequence)
                {
                    m_nextPublishSequence =
                        (frame->FrameSequence == UINT64_MAX) ? 1ULL : (frame->FrameSequence + 1ULL);
                }

                const uint64_t publishedSeq = frame->FrameSequence;
                if (!m_queue.PushBack(std::move(frame)))
                {
                    if (frame != nullptr && frame->IsGpuSharedFrame && pendingReleaseCount < ARRAYSIZE(pendingReleases))
                    {
                        pendingReleases[pendingReleaseCount++] = PendingGpuSlotRelease{
                            true,
                            frame->GpuSlotIndex,
                            frame->GpuSlotGeneration,
                            true};
                    }
                    ReturnBufferToFreePoolLocked(std::move(frame), false);
                    UpdatePoolMetricsLocked();
                    resultHr = E_OUTOFMEMORY;
                }
                else
                {
                    if (outAssignedSequence != nullptr)
                    {
                        *outAssignedSequence = publishedSeq;
                    }
                    UpdatePoolMetricsLocked();
                    if (m_queueMetrics.QueueDepth > m_queueMetrics.PeakQueueDepth)
                    {
                        m_queueMetrics.PeakQueueDepth = m_queueMetrics.QueueDepth;
                    }
                    ++m_queueMetrics.FramesEnqueued;
                    ++m_queueMetrics.FramesPublished;
                    m_queueMetrics.LastFrameSequence = publishedSeq;
                    if (m_activeSessionAuthorized)
                    {
                        ++m_currentSessionSummary.FramesPublished;
                        m_currentSessionSummary.LastFrameSequence = publishedSeq;
                    }
                    eventToSignal = m_frameAvailableEvent.Get();
                }
            }
        }
    }

    if (pendingReleaseCount > 0U)
    {
        ReleasePendingGpuSlots(pendingReleases, pendingReleaseCount);
    }

    if (SUCCEEDED(resultHr) && eventToSignal != nullptr)
    {
        (void)SetEvent(eventToSignal);
    }

    return resultHr;
}

void
FrameIpcServer::FlushQueue() noexcept
{
    PendingGpuSlotRelease pendingReleases[kMaxSupportedQueueDepth]{};
    size_t pendingReleaseCount = 0U;

    {
        ExclusiveLock queueGuard(&m_queueLock);
        while (!m_queue.Empty())
        {
            auto item = m_queue.PopFront();
            if (item != nullptr)
            {
                if (item->IsGpuSharedFrame && pendingReleaseCount < ARRAYSIZE(pendingReleases))
                {
                    pendingReleases[pendingReleaseCount++] = PendingGpuSlotRelease{
                        true,
                        item->GpuSlotIndex,
                        item->GpuSlotGeneration,
                        false};
                }
                ReturnBufferToFreePoolLocked(std::move(item), true);
            }
        }
        m_freePool.FreeAllPixelStorage();
        UpdatePoolMetricsLocked();
    }

    if (pendingReleaseCount > 0U)
    {
        ReleasePendingGpuSlots(pendingReleases, pendingReleaseCount);
    }
}

FrameTransportMetricsSnapshot
FrameIpcServer::GetMetricsSnapshot() const noexcept
{
    FrameTransportMetricsSnapshot queueSnap{};
    {
        SharedLock queueGuard(&m_queueLock);
        queueSnap = m_queueMetrics;
    }

    FrameTransportMetricsSnapshot combined{};
    {
        SharedLock metricsGuard(&m_metricsLock);
        combined = m_transportMetrics;
    }

    combined.Running = queueSnap.Running;
    combined.QueueDepth = queueSnap.QueueDepth;
    combined.PeakQueueDepth = queueSnap.PeakQueueDepth;
    combined.TotalPoolSlots = queueSnap.TotalPoolSlots;
    combined.FreePoolSlots = queueSnap.FreePoolSlots;
    combined.InFlightSlots = queueSnap.InFlightSlots;
    combined.PeakInFlightSlots = queueSnap.PeakInFlightSlots;
    combined.SessionGeneration = queueSnap.SessionGeneration;
    if (queueSnap.ActiveSessionId != 0ULL)
    {
        combined.ActiveSessionId = queueSnap.ActiveSessionId;
    }
    combined.LastFrameSequence = queueSnap.LastFrameSequence;
    combined.FramesEnqueued = queueSnap.FramesEnqueued;
    combined.FramesPublished = queueSnap.FramesPublished;
    combined.FramesDroppedByBackpressure = queueSnap.FramesDroppedByBackpressure;
    combined.QueueEvictionsByBackpressure = queueSnap.QueueEvictionsByBackpressure;
    combined.PoolExhaustionDrops = queueSnap.PoolExhaustionDrops;
    combined.PoolAllocationFailures = queueSnap.PoolAllocationFailures;
    combined.FramesDiscardedNoConsumer = queueSnap.FramesDiscardedNoConsumer;
    combined.FramesDiscardedStaleSession = queueSnap.FramesDiscardedStaleSession;
    combined.FramesDiscardedTransportMismatch = queueSnap.FramesDiscardedTransportMismatch;
    combined.FramesFlushedOnSessionTransition = queueSnap.FramesFlushedOnSessionTransition;
    combined.SequenceWrapAroundCount = queueSnap.SequenceWrapAroundCount;
    combined.PendingAckCount =
        static_cast<uint64_t>(InterlockedCompareExchange64(const_cast<volatile LONG64*>(&m_pendingAckCount), 0, 0));
    combined.GpuSharedTransportConfigured =
        (m_config.SharedTexturePool != nullptr && m_config.EnableGpuSharedTransport);
    if (m_config.SharedTexturePool != nullptr)
    {
        const SharedTexturePoolMetricsSnapshot gpuSnap = m_config.SharedTexturePool->GetMetricsSnapshot();
        combined.SharedTexturePoolSize = gpuSnap.PoolSize;
        combined.SharedTexturePoolPeakUsage = gpuSnap.PeakUsage;
        combined.GpuFramesShared = gpuSnap.GpuFramesShared;
        combined.GpuFramesDropped = gpuSnap.GpuFramesDropped;
        combined.GpuSyncTimeouts = gpuSnap.GpuSyncTimeouts;
        combined.LastGpuSyncWaitUs = gpuSnap.LastGpuSyncWaitUs;
        combined.AvgGpuSyncWaitUs = gpuSnap.AvgGpuSyncWaitUs;
        combined.MaxGpuSyncWaitUs = gpuSnap.MaxGpuSyncWaitUs;
    }
    return combined;
}

bool
FrameIpcServer::PopNextQueuedFrame(
    std::unique_ptr<ExtractedFrameBuffer>& outFrame
    ) noexcept
{
    outFrame.reset();
    ExclusiveLock queueGuard(&m_queueLock);
    if (m_queue.Empty())
    {
        UpdatePoolMetricsLocked();
        return false;
    }

    outFrame = m_queue.PopFront();
    if (outFrame != nullptr && outFrame->PooledSlot && outFrame->PoolEpoch == m_poolEpoch)
    {
        outFrame->InFlightFromPool = true;
        ++m_inFlightSlots;
    }
    UpdatePoolMetricsLocked();
    return outFrame != nullptr;
}

void
FrameIpcServer::UpdatePoolMetricsLocked() noexcept
{
    m_queueMetrics.QueueDepth = static_cast<uint32_t>(m_queue.Size());
    m_queueMetrics.TotalPoolSlots = static_cast<uint32_t>(m_totalPoolSlots);
    m_queueMetrics.FreePoolSlots = static_cast<uint32_t>(m_freePool.Size());
    m_queueMetrics.InFlightSlots = static_cast<uint32_t>(m_inFlightSlots);
    if (m_queueMetrics.InFlightSlots > m_queueMetrics.PeakInFlightSlots)
    {
        m_queueMetrics.PeakInFlightSlots = m_queueMetrics.InFlightSlots;
    }
}

void
FrameIpcServer::ClearAllBuffersLocked() noexcept
{
    while (!m_queue.Empty())
    {
        auto item = m_queue.PopFront();
        if (item != nullptr)
        {
            ReleaseFrameResources(item.get(), false);
        }
    }
    m_queue.Clear();
    m_freePool.Clear();
    m_totalPoolSlots = 0U;
    m_inFlightSlots = 0U;
    UpdatePoolMetricsLocked();
}

DWORD WINAPI
FrameIpcServer::WorkerThreadProc(
    LPVOID context
    ) noexcept
{
    auto* self = static_cast<FrameIpcServer*>(context);
    if (self == nullptr)
    {
        return ERROR_INVALID_PARAMETER;
    }
    self->WorkerLoop();
    return 0U;
}

void
FrameIpcServer::WorkerLoop() noexcept
{
    const HANDLE pipeHandle = m_pipeHandle.Get();
    const HANDLE stopEvent = m_stopEvent.Get();
    const HANDLE frameEvent = m_frameAvailableEvent.Get();
    if (pipeHandle == nullptr || stopEvent == nullptr || frameEvent == nullptr)
    {
        return;
    }

    ScopedWin32Handle ioEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!ioEvent.IsValid())
    {
        ExclusiveLock metricsGuard(&m_metricsLock);
        m_transportMetrics.LastTransportError = LastWin32HResult();
        return;
    }

    const uint64_t qpcFreq = QueryQpcFrequencySafe();

    while (InterlockedCompareExchange(&m_stopRequested, 0, 0) == 0)
    {
        const DWORD connectErr = ConnectPipeOverlapped(pipeHandle, ioEvent.Get(), stopEvent);
        if (connectErr == ERROR_OPERATION_ABORTED ||
            InterlockedCompareExchange(&m_stopRequested, 0, 0) != 0)
        {
            break;
        }
        if (connectErr != ERROR_SUCCESS)
        {
            {
                ExclusiveLock metricsGuard(&m_metricsLock);
                ++m_transportMetrics.FrameTransportFailures;
                m_transportMetrics.LastTransportError = HRESULT_FROM_WIN32(connectErr);
            }
            InterlockedExchange(&m_activeSessionNegotiatedGpu, 0);
            (void)DisconnectNamedPipe(pipeHandle);
            continue;
        }

        ipc::FrameIpcClientHello clientHello{};
        const DWORD helloReadErr = ReadExactOverlapped(
            pipeHandle,
            ioEvent.Get(),
            stopEvent,
            &clientHello,
            sizeof(clientHello),
            m_config.IoTimeoutMs);
        if (helloReadErr != ERROR_SUCCESS)
        {
            if (helloReadErr != ERROR_OPERATION_ABORTED)
            {
                ExclusiveLock metricsGuard(&m_metricsLock);
                ++m_transportMetrics.ClientConnectionsRejected;
                ++m_transportMetrics.FrameTransportFailures;
                m_transportMetrics.LastTransportError = HRESULT_FROM_WIN32(helloReadErr);
            }
            InterlockedExchange(&m_activeSessionNegotiatedGpu, 0);
            (void)DisconnectNamedPipe(pipeHandle);
            continue;
        }

        ipc::FrameIpcStatus validationStatus = ipc::ValidateClientHello(
            &clientHello,
            sizeof(clientHello));

        ScopedWin32Handle authenticatedClientProcess;
        if (validationStatus == ipc::FrameIpcStatus::Ok)
        {
            validationStatus = VerifyConnectedClientIdentity(
                pipeHandle,
                clientHello,
                &authenticatedClientProcess);
        }

        const bool gpuPoolReady =
            (m_config.SharedTexturePool != nullptr) &&
            m_config.EnableGpuSharedTransport;
        const bool clientWantsGpu =
            (clientHello.ClientCapabilities & static_cast<uint32_t>(ipc::FrameIpcCapabilities::GpuSharedNtHandle)) != 0U;
        const bool gpuSessionNegotiated =
            (validationStatus == ipc::FrameIpcStatus::Ok) &&
            gpuPoolReady &&
            clientWantsGpu &&
            authenticatedClientProcess.IsValid();

        uint32_t negotiatedCaps = static_cast<uint32_t>(ipc::FrameIpcCapabilities::CpuStagingRawPixels);
        if (gpuSessionNegotiated)
        {
            negotiatedCaps |= static_cast<uint32_t>(ipc::FrameIpcCapabilities::GpuSharedNtHandle);
            if (m_config.AllowCpuFallbackWhenGpuNegotiated)
            {
                negotiatedCaps |= static_cast<uint32_t>(ipc::FrameIpcCapabilities::GpuFallbackToCpuStaging);
            }
        }
        else if (gpuPoolReady && m_config.AllowCpuFallbackWhenGpuNegotiated)
        {
            negotiatedCaps |= static_cast<uint32_t>(ipc::FrameIpcCapabilities::GpuFallbackToCpuStaging);
        }

        const uint16_t helloMinorVersion =
            (clientHello.Envelope.VersionMinor >= ipc::kFrameIpcProtocolVersionMinorV1_1)
                ? ipc::kFrameIpcProtocolVersionMinorV1_1
                : ipc::kFrameIpcProtocolVersionMinor;

        ipc::FrameIpcServerHello serverHello{};
        serverHello.Envelope = ipc::InitEnvelope(
            ipc::FrameIpcMessageType::ServerHello,
            static_cast<uint32_t>(sizeof(ipc::FrameIpcServerHello)),
            helloMinorVersion);
        serverHello.Status = static_cast<uint32_t>(validationStatus);
        serverHello.ServerProcessId = GetCurrentProcessId();
        serverHello.AdapterLuidLow = static_cast<int32_t>(m_config.AdapterLuid.LowPart);
        serverHello.AdapterLuidHigh = static_cast<int32_t>(m_config.AdapterLuid.HighPart);
        serverHello.MaxQueueDepth = static_cast<uint32_t>(m_effectiveMaxQueueDepth);
        serverHello.Reserved1 = ipc::PackServerHelloCapabilities(
            negotiatedCaps,
            gpuPoolReady ? static_cast<uint32_t>(m_config.SharedTexturePool->GetPoolSize()) : 0U);

        if (validationStatus != ipc::FrameIpcStatus::Ok)
        {
            serverHello.SessionId = 0ULL;
            const DWORD rejectWriteTimeoutMs = (m_config.IoTimeoutMs < 100U) ? m_config.IoTimeoutMs : 100U;
            (void)WriteExactOverlapped(
                pipeHandle,
                ioEvent.Get(),
                stopEvent,
                &serverHello,
                sizeof(serverHello),
                rejectWriteTimeoutMs);
            {
                ExclusiveLock metricsGuard(&m_metricsLock);
                ++m_transportMetrics.ClientConnectionsRejected;
                ++m_transportMetrics.FrameTransportFailures;
                m_transportMetrics.LastTransportError =
                    (validationStatus == ipc::FrameIpcStatus::UnauthorizedClient)
                    ? E_ACCESSDENIED
                    : E_INVALIDARG;
            }
            InterlockedExchange(&m_activeSessionNegotiatedGpu, 0);
            authenticatedClientProcess.Reset();
            (void)DisconnectNamedPipe(pipeHandle);
            continue;
        }

        const uint64_t sessionId = static_cast<uint64_t>(InterlockedIncrement64(&m_nextSessionId));
        const ipc::FrameIpcTransportMode negotiatedMode = gpuSessionNegotiated
            ? ipc::FrameIpcTransportMode::GpuSharedNtHandle
            : ipc::FrameIpcTransportMode::CpuStagingPipe;
        const bool effectiveAllowCpuFallback =
            gpuSessionNegotiated ? m_config.AllowCpuFallbackWhenGpuNegotiated : true;
        uint64_t activeSessionGen = 0ULL;

        {
            SharedTexturePoolMetricsSnapshot gpuBaseline{};
            if (m_config.SharedTexturePool != nullptr)
            {
                gpuBaseline = m_config.SharedTexturePool->GetMetricsSnapshot();
            }

            PendingGpuSlotRelease transitionReleases[kMaxSupportedQueueDepth]{};
            size_t transitionReleaseCount = 0U;
            {
                ExclusiveLock queueGuard(&m_queueLock);
                ++m_sessionGeneration;
                if (m_sessionGeneration == 0ULL)
                {
                    m_sessionGeneration = 1ULL;
                }
                activeSessionGen = m_sessionGeneration;
                m_activeSessionId = sessionId;
                m_activeSessionMode = negotiatedMode;
                m_activeSessionAllowCpuFallback = effectiveAllowCpuFallback;
                m_activeSessionAuthorized = true;

                m_sessionStartGpuSharedBaseline = gpuBaseline.GpuFramesShared;
                m_sessionStartGpuDroppedBaseline = gpuBaseline.GpuFramesDropped;
                m_sessionStartGpuSyncTimeoutsBaseline = gpuBaseline.GpuSyncTimeouts;

                m_currentSessionSummary = {};
                m_currentSessionSummary.Valid = true;
                m_currentSessionSummary.SessionId = sessionId;
                m_currentSessionSummary.SessionGeneration = activeSessionGen;
                m_currentSessionSummary.NegotiatedMode = negotiatedMode;
                m_currentSessionSummary.AllowCpuFallback = effectiveAllowCpuFallback;

                std::unique_ptr<ExtractedFrameBuffer> kept[kMaxSupportedQueueDepth]{};
                size_t keptCount = 0U;
                while (!m_queue.Empty())
                {
                    auto item = m_queue.PopFront();
                    if (item == nullptr)
                    {
                        continue;
                    }
                    const bool transportMismatch =
                        (!gpuSessionNegotiated && item->IsGpuSharedFrame) ||
                        (gpuSessionNegotiated && !effectiveAllowCpuFallback && !item->IsGpuSharedFrame);
                    const bool mustFlush =
                        m_config.FlushQueueOnSessionStart ||
                        gpuSessionNegotiated ||
                        item->HasSessionBinding ||
                        transportMismatch;
                    if (!mustFlush && keptCount < ARRAYSIZE(kept))
                    {
                        kept[keptCount++] = std::move(item);
                    }
                    else
                    {
                        if (item->IsGpuSharedFrame && transitionReleaseCount < ARRAYSIZE(transitionReleases))
                        {
                            transitionReleases[transitionReleaseCount++] = PendingGpuSlotRelease{
                                true,
                                item->GpuSlotIndex,
                                item->GpuSlotGeneration,
                                false};
                        }
                        if (item->HasSessionBinding)
                        {
                            ++m_queueMetrics.FramesDiscardedStaleSession;
                            ++m_currentSessionSummary.FramesDiscardedStaleSession;
                        }
                        if (transportMismatch)
                        {
                            ++m_queueMetrics.FramesDiscardedTransportMismatch;
                            ++m_currentSessionSummary.FramesDiscardedTransportMismatch;
                        }
                        ++m_queueMetrics.FramesFlushedOnSessionTransition;
                        ++m_currentSessionSummary.FramesFlushedOnSessionTransition;
                        ReturnBufferToFreePoolLocked(std::move(item), true);
                    }
                }
                for (size_t k = 0U; k < keptCount; ++k)
                {
                    (void)m_queue.PushBack(std::move(kept[k]));
                }
                if (m_config.ResetSequenceOnSessionStart && m_queue.Empty())
                {
                    m_nextPublishSequence = 1ULL;
                }
                m_queueMetrics.SessionGeneration = activeSessionGen;
                m_queueMetrics.ActiveSessionId = sessionId;
                UpdatePoolMetricsLocked();
            }

            if (transitionReleaseCount > 0U)
            {
                ReleasePendingGpuSlots(transitionReleases, transitionReleaseCount);
            }
        }

        InterlockedExchange(&m_activeSessionNegotiatedGpu, gpuSessionNegotiated ? 1 : 0);
        serverHello.SessionId = sessionId;

        const DWORD helloWriteErr = WriteExactOverlapped(
            pipeHandle,
            ioEvent.Get(),
            stopEvent,
            &serverHello,
            sizeof(serverHello),
            m_config.IoTimeoutMs);
        if (helloWriteErr != ERROR_SUCCESS)
        {
            const HRESULT writeHr = HRESULT_FROM_WIN32(helloWriteErr);
            if (helloWriteErr != ERROR_OPERATION_ABORTED)
            {
                ExclusiveLock metricsGuard(&m_metricsLock);
                ++m_transportMetrics.FrameTransportFailures;
                m_transportMetrics.LastTransportError = writeHr;
            }
            InterlockedExchange(&m_activeSessionNegotiatedGpu, 0);
            {
                ExclusiveLock queueGuard(&m_queueLock);
                m_activeSessionAuthorized = false;
                m_activeSessionId = 0ULL;
                m_activeSessionMode = ipc::FrameIpcTransportMode::CpuStagingPipe;
                m_activeSessionAllowCpuFallback = false;
                m_queueMetrics.ActiveSessionId = 0ULL;
                m_currentSessionSummary.DisconnectReason = writeHr;
                m_lastCompletedSessionSummary = m_currentSessionSummary;
            }
            authenticatedClientProcess.Reset();
            (void)DisconnectNamedPipe(pipeHandle);
            continue;
        }

        const uint64_t sessionConnectQpc = QueryCurrentQpc();

        uint32_t sessionDuplicatedGen[ipc::kMaxSharedTexturePoolSize]{};
        uint64_t sessionDuplicatedHandles[ipc::kMaxSharedTexturePoolSize]{};

        {
            ExclusiveLock metricsGuard(&m_metricsLock);
            ++m_transportMetrics.ClientConnectionsAccepted;
            m_transportMetrics.ActiveHostConnections = 1U;
            m_transportMetrics.ActiveSessionId = sessionId;
        }

        bool disconnectedByPeer = false;
        HRESULT sessionDisconnectReason = S_OK;
        uint64_t sessionFramesDelivered = 0ULL;
        while (InterlockedCompareExchange(&m_stopRequested, 0, 0) == 0)
        {
            std::unique_ptr<ExtractedFrameBuffer> frame;
            if (!PopNextQueuedFrame(frame))
            {
                const HANDLE waitHandles[2] = {frameEvent, stopEvent};
                const DWORD waitRes = WaitForMultipleObjects(2U, waitHandles, FALSE, 250U);
                if (waitRes == WAIT_OBJECT_0 + 1)
                {
                    sessionDisconnectReason = HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED);
                    break;
                }
                if (waitRes == WAIT_TIMEOUT || waitRes == WAIT_OBJECT_0)
                {
                    DWORD availBytes = 0U;
                    if (PeekNamedPipe(pipeHandle, nullptr, 0U, nullptr, &availBytes, nullptr) == FALSE)
                    {
                        disconnectedByPeer = true;
                        break;
                    }
                    if (availBytes >= sizeof(ipc::FrameIpcEnvelope))
                    {
                        ipc::FrameIpcDisconnectNotice notice{};
                        const DWORD noticeErr = ReadExactOverlapped(
                            pipeHandle,
                            ioEvent.Get(),
                            stopEvent,
                            &notice,
                            sizeof(notice),
                            50U);
                        if (noticeErr == ERROR_SUCCESS || IsPeerDisconnectWin32Error(noticeErr))
                        {
                            disconnectedByPeer = true;
                            break;
                        }
                    }
                }
                continue;
            }

            // Defense-in-depth guard: never emit a stale-session or transport-mismatched frame on the wire.
            if (frame->HasSessionBinding &&
                (frame->TargetSessionId != sessionId || frame->TargetSessionGeneration != activeSessionGen))
            {
                ReleaseFrameResources(frame.get(), false);
                RecycleBufferSlot(std::move(frame));
                ExclusiveLock queueGuard(&m_queueLock);
                ++m_queueMetrics.FramesDiscardedStaleSession;
                ++m_currentSessionSummary.FramesDiscardedStaleSession;
                continue;
            }
            if ((frame->IsGpuSharedFrame && !gpuSessionNegotiated) ||
                (!frame->IsGpuSharedFrame && gpuSessionNegotiated && !effectiveAllowCpuFallback))
            {
                ReleaseFrameResources(frame.get(), false);
                RecycleBufferSlot(std::move(frame));
                ExclusiveLock queueGuard(&m_queueLock);
                ++m_queueMetrics.FramesDiscardedTransportMismatch;
                ++m_currentSessionSummary.FramesDiscardedTransportMismatch;
                continue;
            }

            if (frame->IsGpuSharedFrame)
            {
                const uint32_t slotIdx = frame->GpuSlotIndex;
                const uint32_t slotGen = frame->GpuSlotGeneration;
                if (!gpuSessionNegotiated ||
                    m_config.SharedTexturePool == nullptr ||
                    !authenticatedClientProcess.IsValid() ||
                    slotIdx >= ipc::kMaxSharedTexturePoolSize ||
                    slotGen == 0U)
                {
                    if (m_config.SharedTexturePool != nullptr)
                    {
                        m_config.SharedTexturePool->ReleaseQueuedSlot(slotIdx, slotGen, true);
                    }
                    RecycleBufferSlot(std::move(frame));
                    continue;
                }

                HANDLE slotNtHandle = nullptr;
                LUID slotAdapterLuid{0, 0};
                if (!m_config.SharedTexturePool->BeginHostUseForSlot(slotIdx, slotGen, slotNtHandle, slotAdapterLuid) ||
                    slotNtHandle == nullptr ||
                    slotNtHandle == INVALID_HANDLE_VALUE)
                {
                    m_config.SharedTexturePool->CompleteHostUseForSlot(slotIdx, slotGen, false, 0U);
                    RecycleBufferSlot(std::move(frame));
                    continue;
                }

                bool newHandleDuplicated = false;
                uint64_t dupHandleForClient = sessionDuplicatedHandles[slotIdx];
                if (sessionDuplicatedGen[slotIdx] != slotGen || dupHandleForClient == 0ULL)
                {
                    HANDLE targetHandle = nullptr;
                    if (DuplicateHandle(
                            GetCurrentProcess(),
                            slotNtHandle,
                            authenticatedClientProcess.Get(),
                            &targetHandle,
                            0U,
                            FALSE,
                            DUPLICATE_SAME_ACCESS) == FALSE ||
                        targetHandle == nullptr ||
                        targetHandle == INVALID_HANDLE_VALUE)
                    {
                        const HRESULT dupHr = LastWin32HResult();
                        m_config.SharedTexturePool->CompleteHostUseForSlot(slotIdx, slotGen, false, 0U);
                        RecycleBufferSlot(std::move(frame));
                        ExclusiveLock metricsGuard(&m_metricsLock);
                        ++m_transportMetrics.HandleDuplicationFailures;
                        ++m_transportMetrics.FrameTransportFailures;
                        m_transportMetrics.LastTransportError = dupHr;
                        continue;
                    }
                    dupHandleForClient = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(targetHandle));
                    sessionDuplicatedGen[slotIdx] = slotGen;
                    sessionDuplicatedHandles[slotIdx] = dupHandleForClient;
                    newHandleDuplicated = true;
                }

                const uint64_t sendStartQpc = QueryCurrentQpc();
                const uint64_t frameQpcFreq = (frame->QpcFrequency > 0ULL) ? frame->QpcFrequency : qpcFreq;
                const uint64_t queueOriginQpc =
                    (frame->EnqueueQpcTime > 0ULL) ? frame->EnqueueQpcTime : frame->ExtractCompleteQpcTime;
                const uint64_t queueWaitUs = ipc::ComputeQpcElapsedUs(queueOriginQpc, sendStartQpc, frameQpcFreq);
                const bool isPreConnectFrame =
                    (frame->ExtractCompleteQpcTime > 0ULL && frame->ExtractCompleteQpcTime < sessionConnectQpc);
                uint32_t frameFlags = frame->Flags;
                if (isPreConnectFrame)
                {
                    frameFlags |= static_cast<uint32_t>(ipc::FrameIpcFlags::PreConnectQueuedFrame);
                }

                ipc::FrameIpcGpuFrameHeader gpuHeader{};
                gpuHeader.Envelope = ipc::InitEnvelope(
                    ipc::FrameIpcMessageType::GpuFrameHeader,
                    static_cast<uint32_t>(sizeof(ipc::FrameIpcGpuFrameHeader)),
                    ipc::kFrameIpcProtocolVersionMinorV1_1);
                gpuHeader.SessionId = sessionId;
                gpuHeader.FrameSequence = frame->FrameSequence;
                gpuHeader.PresentationFrameNumber = frame->PresentationFrameNumber;
                gpuHeader.TransportMode = static_cast<uint32_t>(ipc::FrameIpcTransportMode::GpuSharedNtHandle);
                gpuHeader.SlotIndex = slotIdx;
                gpuHeader.SlotGeneration = slotGen;
                gpuHeader.DuplicatedNtHandleValue = dupHandleForClient;
                gpuHeader.Width = frame->Width;
                gpuHeader.Height = frame->Height;
                gpuHeader.PixelFormat = frame->Format;
                gpuHeader.Flags = ipc::PackFrameFlags(frameFlags, frame->CopyLatencyUs);
                gpuHeader.AdapterLuidLow = static_cast<int32_t>(slotAdapterLuid.LowPart);
                gpuHeader.AdapterLuidHigh = static_cast<int32_t>(slotAdapterLuid.HighPart);
                gpuHeader.KeyedMutexAcquireKey = ipc::kSharedTextureConsumerMutexKey;
                gpuHeader.KeyedMutexReleaseKey = ipc::kSharedTextureProducerMutexKey;
                gpuHeader.KeyedMutexTimeoutMs = m_config.GpuKeyedMutexTimeoutMs;
                gpuHeader.SyncAndFallbackFlags =
                    (newHandleDuplicated ? static_cast<uint32_t>(ipc::FrameIpcGpuFrameFlags::NewHandleDuplicated) : 0U) |
                    (m_config.AllowCpuFallbackWhenGpuNegotiated
                        ? static_cast<uint32_t>(ipc::FrameIpcGpuFrameFlags::CpuFallbackAvailable)
                        : 0U);
                gpuHeader.PresentDisplayQpcTime = frame->PresentDisplayQpcTime;
                gpuHeader.ExtractCompleteQpcTime = frame->ExtractCompleteQpcTime;
                gpuHeader.ServerSendQpcTime = sendStartQpc;
                gpuHeader.QpcFrequency = frameQpcFreq;

                const uint64_t sentSeq = frame->FrameSequence;
                const uint64_t extractQpc = frame->ExtractCompleteQpcTime;

                const DWORD ioErr = WriteExactOverlapped(
                    pipeHandle,
                    ioEvent.Get(),
                    stopEvent,
                    &gpuHeader,
                    sizeof(gpuHeader),
                    m_config.IoTimeoutMs);

                RecycleBufferSlot(std::move(frame));

                if (ioErr != ERROR_SUCCESS)
                {
                    m_config.SharedTexturePool->CompleteHostUseForSlot(slotIdx, slotGen, false, 0U);
                    sessionDuplicatedGen[slotIdx] = 0U;
                    sessionDuplicatedHandles[slotIdx] = 0ULL;
                    if (ioErr == ERROR_OPERATION_ABORTED)
                    {
                        break;
                    }
                    {
                        ExclusiveLock metricsGuard(&m_metricsLock);
                        ++m_transportMetrics.FrameTransportFailures;
                        m_transportMetrics.LastTransportError = HRESULT_FROM_WIN32(ioErr);
                    }
                    disconnectedByPeer = true;
                    break;
                }

                // GPU shared frames ALWAYS require ACK (or fail/disconnect) before releasing slot back to producer.
                ipc::FrameIpcFrameAck ack{};
                InterlockedIncrement64(&m_pendingAckCount);
                const DWORD ackErr = ReadExactOverlapped(
                    pipeHandle,
                    ioEvent.Get(),
                    stopEvent,
                    &ack,
                    sizeof(ack),
                    m_config.IoTimeoutMs);
                InterlockedDecrement64(&m_pendingAckCount);
                if (ackErr != ERROR_SUCCESS)
                {
                    m_config.SharedTexturePool->CompleteHostUseForSlot(slotIdx, slotGen, false, 0U);
                    sessionDuplicatedGen[slotIdx] = 0U;
                    sessionDuplicatedHandles[slotIdx] = 0ULL;
                    if (ackErr == ERROR_OPERATION_ABORTED)
                    {
                        sessionDisconnectReason = HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED);
                        break;
                    }
                    {
                        ExclusiveLock metricsGuard(&m_metricsLock);
                        ++m_transportMetrics.FrameTransportFailures;
                        m_transportMetrics.LastTransportError = HRESULT_FROM_WIN32(ackErr);
                    }
                    sessionDisconnectReason = HRESULT_FROM_WIN32(ackErr);
                    disconnectedByPeer = true;
                    break;
                }

                const ipc::FrameIpcStatus ackStatus = ipc::ValidateFrameAck(&ack, sizeof(ack), sessionId);
                if (ackStatus != ipc::FrameIpcStatus::Ok || ack.FrameSequence != sentSeq)
                {
                    m_config.SharedTexturePool->CompleteHostUseForSlot(slotIdx, slotGen, false, 0U);
                    sessionDuplicatedGen[slotIdx] = 0U;
                    sessionDuplicatedHandles[slotIdx] = 0ULL;
                    {
                        ExclusiveLock metricsGuard(&m_metricsLock);
                        ++m_transportMetrics.FrameTransportFailures;
                        m_transportMetrics.LastTransportError = E_FAIL;
                    }
                    sessionDisconnectReason = E_FAIL;
                    disconnectedByPeer = true;
                    break;
                }

                const uint32_t consumerGpuSyncWaitUs = ipc::UnpackGpuAckSyncWaitUs(ack.Reserved1);
                m_config.SharedTexturePool->CompleteHostUseForSlot(slotIdx, slotGen, true, consumerGpuSyncWaitUs);

                const uint64_t deliveredQpc = QueryCurrentQpc();
                const uint64_t deliveryLatencyUs = ipc::ComputeQpcElapsedUs(extractQpc, deliveredQpc, frameQpcFreq);
                ++sessionFramesDelivered;

                {
                    ExclusiveLock metricsGuard(&m_metricsLock);
                    ++m_transportMetrics.FramesDelivered;
                    if (isPreConnectFrame)
                    {
                        ++m_transportMetrics.PreConnectFramesDelivered;
                    }
                    m_transportMetrics.LastDeliveredFrameSequence = sentSeq;
                    m_transportMetrics.LastQueueWaitLatencyUs = queueWaitUs;
                    m_transportMetrics.TotalQueueWaitLatencyUs += queueWaitUs;
                    m_transportMetrics.AvgQueueWaitLatencyUs =
                        m_transportMetrics.TotalQueueWaitLatencyUs / m_transportMetrics.FramesDelivered;
                    if (queueWaitUs > m_transportMetrics.MaxQueueWaitLatencyUs)
                    {
                        m_transportMetrics.MaxQueueWaitLatencyUs = queueWaitUs;
                    }
                    m_transportMetrics.LastDeliveryLatencyUs = deliveryLatencyUs;
                    m_transportMetrics.TotalDeliveryLatencyUs += deliveryLatencyUs;
                    m_transportMetrics.AvgDeliveryLatencyUs =
                        m_transportMetrics.TotalDeliveryLatencyUs / m_transportMetrics.FramesDelivered;
                    if (deliveryLatencyUs > m_transportMetrics.MaxDeliveryLatencyUs)
                    {
                        m_transportMetrics.MaxDeliveryLatencyUs = deliveryLatencyUs;
                    }
                }
                continue;
            }

            const size_t payloadBytes = frame->Pixels.size();
            if (payloadBytes == 0U || payloadBytes > ipc::kMaxFramePayloadBytes)
            {
                RecycleBufferSlot(std::move(frame));
                continue;
            }

            const uint64_t sendStartQpc = QueryCurrentQpc();
            const uint64_t frameQpcFreq = (frame->QpcFrequency > 0ULL) ? frame->QpcFrequency : qpcFreq;
            const uint64_t queueOriginQpc =
                (frame->EnqueueQpcTime > 0ULL) ? frame->EnqueueQpcTime : frame->ExtractCompleteQpcTime;
            const uint64_t queueWaitUs = ipc::ComputeQpcElapsedUs(queueOriginQpc, sendStartQpc, frameQpcFreq);
            const bool isPreConnectFrame =
                (frame->ExtractCompleteQpcTime > 0ULL && frame->ExtractCompleteQpcTime < sessionConnectQpc);
            uint32_t frameFlags = frame->Flags;
            if (isPreConnectFrame)
            {
                frameFlags |= static_cast<uint32_t>(ipc::FrameIpcFlags::PreConnectQueuedFrame);
            }

            ipc::FrameIpcFrameHeader header{};
            header.Envelope = ipc::InitEnvelope(
                ipc::FrameIpcMessageType::FrameHeader,
                static_cast<uint32_t>(sizeof(ipc::FrameIpcFrameHeader)));
            header.SessionId = sessionId;
            header.FrameSequence = frame->FrameSequence;
            header.PresentationFrameNumber = frame->PresentationFrameNumber;
            header.Width = frame->Width;
            header.Height = frame->Height;
            header.RowPitchBytes = frame->RowPitchBytes;
            header.PixelFormat = frame->Format;
            header.Flags = ipc::PackFrameFlags(frameFlags, frame->CopyLatencyUs);
            header.DirtyRectCount = frame->DirtyRectCount;
            header.MoveRegionCount = frame->MoveRegionCount;
            header.PresentDisplayQpcTime = frame->PresentDisplayQpcTime;
            header.ExtractCompleteQpcTime = frame->ExtractCompleteQpcTime;
            header.ServerSendQpcTime = sendStartQpc;
            header.QpcFrequency = frameQpcFreq;
            header.PayloadSizeBytes = static_cast<uint32_t>(payloadBytes);
            header.PayloadCrc32 = frame->PayloadCrc32;

            const uint64_t sentSeq = frame->FrameSequence;
            const uint64_t extractQpc = frame->ExtractCompleteQpcTime;

            DWORD ioErr = WriteExactOverlapped(
                pipeHandle,
                ioEvent.Get(),
                stopEvent,
                &header,
                sizeof(header),
                m_config.IoTimeoutMs);
            if (ioErr == ERROR_SUCCESS)
            {
                ioErr = WriteExactOverlapped(
                    pipeHandle,
                    ioEvent.Get(),
                    stopEvent,
                    frame->Pixels.data(),
                    payloadBytes,
                    m_config.IoTimeoutMs);
            }

            RecycleBufferSlot(std::move(frame));

            if (ioErr != ERROR_SUCCESS)
            {
                if (ioErr == ERROR_OPERATION_ABORTED)
                {
                    break;
                }
                {
                    ExclusiveLock metricsGuard(&m_metricsLock);
                    ++m_transportMetrics.FrameTransportFailures;
                    m_transportMetrics.LastTransportError = HRESULT_FROM_WIN32(ioErr);
                }
                disconnectedByPeer = true;
                break;
            }

            if (m_config.RequireClientAck)
            {
                ipc::FrameIpcFrameAck ack{};
                InterlockedIncrement64(&m_pendingAckCount);
                const DWORD ackErr = ReadExactOverlapped(
                    pipeHandle,
                    ioEvent.Get(),
                    stopEvent,
                    &ack,
                    sizeof(ack),
                    m_config.IoTimeoutMs);
                InterlockedDecrement64(&m_pendingAckCount);
                if (ackErr != ERROR_SUCCESS)
                {
                    if (ackErr == ERROR_OPERATION_ABORTED)
                    {
                        sessionDisconnectReason = HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED);
                        break;
                    }
                    {
                        ExclusiveLock metricsGuard(&m_metricsLock);
                        ++m_transportMetrics.FrameTransportFailures;
                        m_transportMetrics.LastTransportError = HRESULT_FROM_WIN32(ackErr);
                    }
                    sessionDisconnectReason = HRESULT_FROM_WIN32(ackErr);
                    disconnectedByPeer = true;
                    break;
                }

                const ipc::FrameIpcStatus ackStatus = ipc::ValidateFrameAck(&ack, sizeof(ack), sessionId);
                if (ackStatus != ipc::FrameIpcStatus::Ok || ack.FrameSequence != sentSeq)
                {
                    {
                        ExclusiveLock metricsGuard(&m_metricsLock);
                        ++m_transportMetrics.FrameTransportFailures;
                        m_transportMetrics.LastTransportError = E_FAIL;
                    }
                    sessionDisconnectReason = E_FAIL;
                    disconnectedByPeer = true;
                    break;
                }
            }

            const uint64_t deliveredQpc = QueryCurrentQpc();
            const uint64_t deliveryLatencyUs = ipc::ComputeQpcElapsedUs(extractQpc, deliveredQpc, frameQpcFreq);
            ++sessionFramesDelivered;

            {
                ExclusiveLock metricsGuard(&m_metricsLock);
                ++m_transportMetrics.FramesDelivered;
                if (isPreConnectFrame)
                {
                    ++m_transportMetrics.PreConnectFramesDelivered;
                }
                m_transportMetrics.LastDeliveredFrameSequence = sentSeq;
                m_transportMetrics.LastQueueWaitLatencyUs = queueWaitUs;
                m_transportMetrics.TotalQueueWaitLatencyUs += queueWaitUs;
                m_transportMetrics.AvgQueueWaitLatencyUs =
                    m_transportMetrics.TotalQueueWaitLatencyUs / m_transportMetrics.FramesDelivered;
                if (queueWaitUs > m_transportMetrics.MaxQueueWaitLatencyUs)
                {
                    m_transportMetrics.MaxQueueWaitLatencyUs = queueWaitUs;
                }
                m_transportMetrics.LastDeliveryLatencyUs = deliveryLatencyUs;
                m_transportMetrics.TotalDeliveryLatencyUs += deliveryLatencyUs;
                m_transportMetrics.AvgDeliveryLatencyUs =
                    m_transportMetrics.TotalDeliveryLatencyUs / m_transportMetrics.FramesDelivered;
                if (deliveryLatencyUs > m_transportMetrics.MaxDeliveryLatencyUs)
                {
                    m_transportMetrics.MaxDeliveryLatencyUs = deliveryLatencyUs;
                }
            }
        }

        if (!disconnectedByPeer && InterlockedCompareExchange(&m_stopRequested, 0, 0) != 0)
        {
            ipc::FrameIpcDisconnectNotice notice{};
            notice.Envelope = ipc::InitEnvelope(
                ipc::FrameIpcMessageType::DisconnectNotice,
                static_cast<uint32_t>(sizeof(ipc::FrameIpcDisconnectNotice)));
            notice.SessionId = sessionId;
            notice.ReasonCode = static_cast<uint32_t>(ipc::FrameIpcStatus::ServerStopping);

            OVERLAPPED ov{};
            ov.hEvent = ioEvent.Get();
            (void)ResetEvent(ioEvent.Get());
            DWORD unusedWritten = 0U;
            if (WriteFile(pipeHandle, &notice, sizeof(notice), &unusedWritten, &ov) == FALSE &&
                GetLastError() == ERROR_IO_PENDING)
            {
                (void)WaitForSingleObject(ioEvent.Get(), 50U);
                (void)CancelIoEx(pipeHandle, &ov);
                (void)GetOverlappedResult(pipeHandle, &ov, &unusedWritten, TRUE);
            }
        }

        InterlockedExchange(&m_activeSessionNegotiatedGpu, 0);
        PendingGpuSlotRelease teardownReleases[kMaxSupportedQueueDepth]{};
        size_t teardownReleaseCount = 0U;
        {
            ExclusiveLock queueGuard(&m_queueLock);
            m_activeSessionAuthorized = false;
            m_activeSessionId = 0ULL;
            m_activeSessionMode = ipc::FrameIpcTransportMode::CpuStagingPipe;
            m_activeSessionAllowCpuFallback = false;
            m_queueMetrics.ActiveSessionId = 0ULL;

            std::unique_ptr<ExtractedFrameBuffer> kept[kMaxSupportedQueueDepth]{};
            size_t keptCount = 0U;
            while (!m_queue.Empty())
            {
                auto item = m_queue.PopFront();
                if (item == nullptr)
                {
                    continue;
                }
                const bool shouldFlushOnDisconnect =
                    gpuSessionNegotiated ||
                    m_config.FlushQueueOnSessionStart ||
                    item->HasSessionBinding ||
                    item->IsGpuSharedFrame;
                if (!shouldFlushOnDisconnect && keptCount < ARRAYSIZE(kept))
                {
                    kept[keptCount++] = std::move(item);
                }
                else
                {
                    if (item->IsGpuSharedFrame && teardownReleaseCount < ARRAYSIZE(teardownReleases))
                    {
                        teardownReleases[teardownReleaseCount++] = PendingGpuSlotRelease{
                            true,
                            item->GpuSlotIndex,
                            item->GpuSlotGeneration,
                            false};
                    }
                    ++m_queueMetrics.FramesFlushedOnSessionTransition;
                    ++m_currentSessionSummary.FramesFlushedOnSessionTransition;
                    ReturnBufferToFreePoolLocked(std::move(item), true);
                }
            }
            for (size_t k = 0U; k < keptCount; ++k)
            {
                (void)m_queue.PushBack(std::move(kept[k]));
            }
            if (m_queue.Empty())
            {
                m_freePool.FreeAllPixelStorage();
            }
            UpdatePoolMetricsLocked();
        }
        if (teardownReleaseCount > 0U)
        {
            ReleasePendingGpuSlots(teardownReleases, teardownReleaseCount);
        }

        SharedTexturePoolMetricsSnapshot gpuEndSnap{};
        if (m_config.SharedTexturePool != nullptr)
        {
            gpuEndSnap = m_config.SharedTexturePool->GetMetricsSnapshot();
        }
        DriverSessionSummarySnapshot completedSummary{};
        {
            ExclusiveLock queueGuard(&m_queueLock);
            m_currentSessionSummary.FramesDelivered = sessionFramesDelivered;
            m_currentSessionSummary.DisconnectReason = sessionDisconnectReason;
            if (gpuEndSnap.GpuFramesShared >= m_sessionStartGpuSharedBaseline)
            {
                m_currentSessionSummary.GpuFramesShared = gpuEndSnap.GpuFramesShared - m_sessionStartGpuSharedBaseline;
            }
            if (gpuEndSnap.GpuFramesDropped >= m_sessionStartGpuDroppedBaseline)
            {
                m_currentSessionSummary.GpuFramesDropped = gpuEndSnap.GpuFramesDropped - m_sessionStartGpuDroppedBaseline;
            }
            if (gpuEndSnap.GpuSyncTimeouts >= m_sessionStartGpuSyncTimeoutsBaseline)
            {
                m_currentSessionSummary.GpuSyncTimeouts = gpuEndSnap.GpuSyncTimeouts - m_sessionStartGpuSyncTimeoutsBaseline;
            }
            m_lastCompletedSessionSummary = m_currentSessionSummary;
            completedSummary = m_lastCompletedSessionSummary;
        }

        const char* modeLabel =
            (completedSummary.NegotiatedMode == ipc::FrameIpcTransportMode::GpuSharedNtHandle)
                ? "GpuSharedNtHandle"
                : "CpuStagingPipe";
        LumaBridgeTraceSessionSummary(
            completedSummary.SessionId,
            completedSummary.SessionGeneration,
            modeLabel,
            completedSummary.AllowCpuFallback,
            completedSummary.FramesPublished,
            completedSummary.FramesDelivered,
            completedSummary.FramesDroppedByBackpressure,
            completedSummary.GpuFramesShared,
            completedSummary.GpuFramesDropped,
            completedSummary.GpuSyncTimeouts,
            completedSummary.FramesDiscardedStaleSession,
            completedSummary.FramesDiscardedTransportMismatch,
            completedSummary.FramesFlushedOnSessionTransition,
            completedSummary.LastFrameSequence,
            completedSummary.DisconnectReason);

        authenticatedClientProcess.Reset();
        (void)DisconnectNamedPipe(pipeHandle);

        {
            ExclusiveLock metricsGuard(&m_metricsLock);
            ++m_transportMetrics.ClientDisconnects;
            m_transportMetrics.ActiveHostConnections = 0U;
            m_transportMetrics.ActiveSessionId = 0ULL;
        }
    }
}

} // namespace lumabridge::driver
