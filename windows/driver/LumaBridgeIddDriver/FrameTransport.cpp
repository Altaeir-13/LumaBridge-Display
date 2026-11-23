#include "FrameTransport.h"

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
    (void)GetOverlappedResult(pipeHandle, &ov, &cancelledBytes, TRUE);

    if (waitResult == WAIT_OBJECT_0 + 1)
    {
        return ERROR_OPERATION_ABORTED;
    }
    if (waitResult == WAIT_TIMEOUT)
    {
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
    const ipc::FrameIpcClientHello& clientHello
    ) const noexcept
{
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

    const size_t clampedQueueDepth = (config.MaxQueueDepth == 0U)
        ? 1U
        : ((config.MaxQueueDepth > kMaxSupportedQueueDepth) ? kMaxSupportedQueueDepth : config.MaxQueueDepth);
    size_t clampedPoolSize = (config.BufferPoolSize < clampedQueueDepth + 2U)
        ? (clampedQueueDepth + 2U)
        : config.BufferPoolSize;
    if (clampedPoolSize > kMaxSupportedPoolSize)
    {
        clampedPoolSize = kMaxSupportedPoolSize;
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
        ClearAllBuffersLocked();

        for (size_t i = 0U; i < clampedPoolSize; ++i)
        {
            std::unique_ptr<ExtractedFrameBuffer> slot(new (std::nothrow) ExtractedFrameBuffer());
            if (slot == nullptr || !m_freePool.PushBack(std::move(slot)))
            {
                ClearAllBuffersLocked();
                return E_OUTOFMEMORY;
            }
        }

        m_effectiveMaxQueueDepth = clampedQueueDepth;
        m_effectiveMaxPoolSize = clampedPoolSize;
        m_totalPoolSlots = clampedPoolSize;
        m_queueMetrics = {};
        m_queueMetrics.Running = true;
    }

    {
        ExclusiveLock metricsGuard(&m_metricsLock);
        m_transportMetrics = {};
        m_transportMetrics.Running = true;
    }

    m_config = config;
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

    m_pipeHandle = std::move(pipeHandle);
    m_stopEvent = std::move(stopEvent);
    m_frameAvailableEvent = std::move(frameEvent);
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
        ClearAllBuffersLocked();
        m_queueMetrics.Running = false;
        m_queueMetrics.QueueDepth = 0U;
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

std::unique_ptr<ExtractedFrameBuffer>
FrameIpcServer::AcquireBufferSlot() noexcept
{
    {
        ExclusiveLock queueGuard(&m_queueLock);
        if (!m_freePool.Empty())
        {
            auto slot = m_freePool.PopFront();
            if (slot != nullptr)
            {
                slot->ResetMetadataKeepCapacity();
                return slot;
            }
        }

        if (m_totalPoolSlots < m_effectiveMaxPoolSize)
        {
            ++m_totalPoolSlots;
        }
        else if (!m_queue.Empty())
        {
            auto evicted = m_queue.PopFront();
            ++m_queueMetrics.FramesDroppedByBackpressure;
            m_queueMetrics.QueueDepth = static_cast<uint32_t>(m_queue.Size());
            if (evicted != nullptr)
            {
                evicted->ResetMetadataKeepCapacity();
                return evicted;
            }
        }
    }

    return std::unique_ptr<ExtractedFrameBuffer>(new (std::nothrow) ExtractedFrameBuffer());
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
    if (InterlockedCompareExchange(&m_running, 0, 0) == 0)
    {
        return;
    }

    if (m_freePool.Size() < m_effectiveMaxPoolSize)
    {
        (void)m_freePool.PushBack(std::move(slot));
    }
}

HRESULT
FrameIpcServer::EnqueueFrame(
    std::unique_ptr<ExtractedFrameBuffer> frame,
    bool& outEvictedOldest
    ) noexcept
{
    outEvictedOldest = false;
    if (frame == nullptr)
    {
        return E_INVALIDARG;
    }

    if (!IsRunning())
    {
        RecycleBufferSlot(std::move(frame));
        return E_ABORT;
    }

    HANDLE eventToSignal = nullptr;
    {
        ExclusiveLock queueGuard(&m_queueLock);
        if (!IsRunning())
        {
            return E_ABORT;
        }

        while (m_queue.Size() >= m_effectiveMaxQueueDepth)
        {
            auto evicted = m_queue.PopFront();
            ++m_queueMetrics.FramesDroppedByBackpressure;
            outEvictedOldest = true;

            if (evicted != nullptr && m_freePool.Size() < m_effectiveMaxPoolSize)
            {
                evicted->ResetMetadataKeepCapacity();
                (void)m_freePool.PushBack(std::move(evicted));
            }
        }

        if (!m_queue.PushBack(std::move(frame)))
        {
            return E_OUTOFMEMORY;
        }

        const uint32_t depth = static_cast<uint32_t>(m_queue.Size());
        m_queueMetrics.QueueDepth = depth;
        if (depth > m_queueMetrics.PeakQueueDepth)
        {
            m_queueMetrics.PeakQueueDepth = depth;
        }
        ++m_queueMetrics.FramesEnqueued;
        eventToSignal = m_frameAvailableEvent.Get();
    }

    if (eventToSignal != nullptr)
    {
        (void)SetEvent(eventToSignal);
    }

    return S_OK;
}

void
FrameIpcServer::FlushQueue() noexcept
{
    ExclusiveLock queueGuard(&m_queueLock);
    while (!m_queue.Empty())
    {
        auto item = m_queue.PopFront();
        if (item != nullptr && m_freePool.Size() < m_effectiveMaxPoolSize)
        {
            item->ResetMetadataAndFreePixels();
            (void)m_freePool.PushBack(std::move(item));
        }
    }
    m_freePool.FreeAllPixelStorage();
    m_queueMetrics.QueueDepth = 0U;
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
    combined.FramesEnqueued = queueSnap.FramesEnqueued;
    combined.FramesDroppedByBackpressure = queueSnap.FramesDroppedByBackpressure;
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
        m_queueMetrics.QueueDepth = 0U;
        return false;
    }

    outFrame = m_queue.PopFront();
    m_queueMetrics.QueueDepth = static_cast<uint32_t>(m_queue.Size());
    return outFrame != nullptr;
}

void
FrameIpcServer::ClearAllBuffersLocked() noexcept
{
    m_queue.Clear();
    m_freePool.Clear();
    m_totalPoolSlots = 0U;
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
            (void)DisconnectNamedPipe(pipeHandle);
            continue;
        }

        ipc::FrameIpcStatus validationStatus = ipc::ValidateClientHello(
            &clientHello,
            sizeof(clientHello));

        if (validationStatus == ipc::FrameIpcStatus::Ok)
        {
            validationStatus = VerifyConnectedClientIdentity(pipeHandle, clientHello);
        }

        ipc::FrameIpcServerHello serverHello{};
        serverHello.Envelope = ipc::InitEnvelope(
            ipc::FrameIpcMessageType::ServerHello,
            static_cast<uint32_t>(sizeof(ipc::FrameIpcServerHello)));
        serverHello.Status = static_cast<uint32_t>(validationStatus);
        serverHello.ServerProcessId = GetCurrentProcessId();
        serverHello.AdapterLuidLow = static_cast<int32_t>(m_config.AdapterLuid.LowPart);
        serverHello.AdapterLuidHigh = static_cast<int32_t>(m_config.AdapterLuid.HighPart);
        serverHello.MaxQueueDepth = static_cast<uint32_t>(m_effectiveMaxQueueDepth);

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
            (void)DisconnectNamedPipe(pipeHandle);
            continue;
        }

        const uint64_t sessionId = static_cast<uint64_t>(InterlockedIncrement64(&m_nextSessionId));
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
            if (helloWriteErr != ERROR_OPERATION_ABORTED)
            {
                ExclusiveLock metricsGuard(&m_metricsLock);
                ++m_transportMetrics.FrameTransportFailures;
                m_transportMetrics.LastTransportError = HRESULT_FROM_WIN32(helloWriteErr);
            }
            (void)DisconnectNamedPipe(pipeHandle);
            continue;
        }

        {
            ExclusiveLock metricsGuard(&m_metricsLock);
            ++m_transportMetrics.ClientConnectionsAccepted;
            m_transportMetrics.ActiveHostConnections = 1U;
            m_transportMetrics.ActiveSessionId = sessionId;
        }

        bool disconnectedByPeer = false;
        while (InterlockedCompareExchange(&m_stopRequested, 0, 0) == 0)
        {
            std::unique_ptr<ExtractedFrameBuffer> frame;
            if (!PopNextQueuedFrame(frame))
            {
                const HANDLE waitHandles[2] = {frameEvent, stopEvent};
                const DWORD waitRes = WaitForMultipleObjects(2U, waitHandles, FALSE, 250U);
                if (waitRes == WAIT_OBJECT_0 + 1)
                {
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

            const size_t payloadBytes = frame->Pixels.size();
            if (payloadBytes == 0U || payloadBytes > ipc::kMaxFramePayloadBytes)
            {
                RecycleBufferSlot(std::move(frame));
                continue;
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
            header.Flags = frame->Flags;
            header.DirtyRectCount = frame->DirtyRectCount;
            header.MoveRegionCount = frame->MoveRegionCount;
            header.PresentDisplayQpcTime = frame->PresentDisplayQpcTime;
            header.ExtractCompleteQpcTime = frame->ExtractCompleteQpcTime;
            header.ServerSendQpcTime = QueryCurrentQpc();
            header.QpcFrequency = (frame->QpcFrequency > 0ULL) ? frame->QpcFrequency : qpcFreq;
            header.PayloadSizeBytes = static_cast<uint32_t>(payloadBytes);
            header.PayloadCrc32 = frame->PayloadCrc32;

            const uint64_t sentSeq = frame->FrameSequence;
            const uint64_t extractQpc = frame->ExtractCompleteQpcTime;
            const uint64_t frameQpcFreq = header.QpcFrequency;

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
                const DWORD ackErr = ReadExactOverlapped(
                    pipeHandle,
                    ioEvent.Get(),
                    stopEvent,
                    &ack,
                    sizeof(ack),
                    m_config.IoTimeoutMs);
                if (ackErr != ERROR_SUCCESS)
                {
                    if (ackErr == ERROR_OPERATION_ABORTED)
                    {
                        break;
                    }
                    {
                        ExclusiveLock metricsGuard(&m_metricsLock);
                        ++m_transportMetrics.FrameTransportFailures;
                        m_transportMetrics.LastTransportError = HRESULT_FROM_WIN32(ackErr);
                    }
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
                    disconnectedByPeer = true;
                    break;
                }
            }

            const uint64_t deliveredQpc = QueryCurrentQpc();
            const uint64_t deliveryTicks = (deliveredQpc >= extractQpc) ? (deliveredQpc - extractQpc) : 0ULL;
            const uint64_t deliveryLatencyUs =
                (deliveryTicks * 1000000ULL) / ((frameQpcFreq > 0ULL) ? frameQpcFreq : qpcFreq);

            {
                ExclusiveLock metricsGuard(&m_metricsLock);
                ++m_transportMetrics.FramesDelivered;
                m_transportMetrics.LastDeliveredFrameSequence = sentSeq;
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
