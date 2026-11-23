#include "SharedTexturePool.h"

#include <sddl.h>
#include <stdio.h>

#include <cstring>

using Microsoft::WRL::ComPtr;

namespace lumabridge::driver {

namespace {

class ExclusivePoolLock final
{
public:
    explicit ExclusivePoolLock(SRWLOCK* lock) noexcept
        : m_lock(lock)
    {
        if (m_lock != nullptr)
        {
            AcquireSRWLockExclusive(m_lock);
        }
    }

    ~ExclusivePoolLock()
    {
        if (m_lock != nullptr)
        {
            ReleaseSRWLockExclusive(m_lock);
        }
    }

    ExclusivePoolLock(const ExclusivePoolLock&) = delete;
    ExclusivePoolLock& operator=(const ExclusivePoolLock&) = delete;

private:
    SRWLOCK* m_lock;
};

class SharedPoolLock final
{
public:
    explicit SharedPoolLock(SRWLOCK* lock) noexcept
        : m_lock(lock)
    {
        if (m_lock != nullptr)
        {
            AcquireSRWLockShared(m_lock);
        }
    }

    ~SharedPoolLock()
    {
        if (m_lock != nullptr)
        {
            ReleaseSRWLockShared(m_lock);
        }
    }

    SharedPoolLock(const SharedPoolLock&) = delete;
    SharedPoolLock& operator=(const SharedPoolLock&) = delete;

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

bool
CanonicalizeSidWide(
    const wchar_t* inputSidString,
    wchar_t* outBuf,
    size_t outBufChars
    ) noexcept
{
    if (outBuf == nullptr || outBufChars == 0U)
    {
        return false;
    }
    outBuf[0] = L'\0';
    if (inputSidString == nullptr || inputSidString[0] == L'\0')
    {
        return false;
    }

    PSID rawSid = nullptr;
    if (ConvertStringSidToSidW(inputSidString, &rawSid) == FALSE || rawSid == nullptr)
    {
        return false;
    }
    LocalFreeGuard sidGuard{rawSid};

    if (IsValidSid(rawSid) == FALSE)
    {
        return false;
    }

    LPWSTR canonical = nullptr;
    if (ConvertSidToStringSidW(rawSid, &canonical) == FALSE || canonical == nullptr)
    {
        return false;
    }
    LocalFreeGuard strGuard{canonical};

    return (wcsncpy_s(outBuf, outBufChars, canonical, _TRUNCATE) == 0) && (outBuf[0] != L'\0');
}

bool
QueryProcessUserSidWide(
    wchar_t* outBuf,
    size_t outBufChars,
    bool& outIsServiceAccount
    ) noexcept
{
    outIsServiceAccount = false;
    if (outBuf == nullptr || outBufChars == 0U)
    {
        return false;
    }
    outBuf[0] = L'\0';

    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) == FALSE || token == nullptr)
    {
        return false;
    }
    ScopedWin32Handle tokenGuard(token);

    uint8_t buf[256]{};
    DWORD reqSize = sizeof(buf);
    if (GetTokenInformation(tokenGuard.Get(), TokenUser, buf, reqSize, &reqSize) == FALSE)
    {
        return false;
    }

    const TOKEN_USER* tu = reinterpret_cast<const TOKEN_USER*>(buf);
    if (tu->User.Sid == nullptr || IsValidSid(tu->User.Sid) == FALSE)
    {
        return false;
    }

    uint8_t lsSid[SECURITY_MAX_SID_SIZE]{};
    DWORD lsSize = sizeof(lsSid);
    uint8_t sysSid[SECURITY_MAX_SID_SIZE]{};
    DWORD sysSize = sizeof(sysSid);
    if (CreateWellKnownSid(WinLocalServiceSid, nullptr, lsSid, &lsSize) != FALSE &&
        EqualSid(tu->User.Sid, lsSid) != FALSE)
    {
        outIsServiceAccount = true;
    }
    else if (CreateWellKnownSid(WinLocalSystemSid, nullptr, sysSid, &sysSize) != FALSE &&
             EqualSid(tu->User.Sid, sysSid) != FALSE)
    {
        outIsServiceAccount = true;
    }

    LPWSTR str = nullptr;
    if (ConvertSidToStringSidW(tu->User.Sid, &str) == FALSE || str == nullptr)
    {
        return false;
    }
    LocalFreeGuard strGuard{str};

    return (wcsncpy_s(outBuf, outBufChars, str, _TRUNCATE) == 0) && (outBuf[0] != L'\0');
}

} // namespace

HRESULT
ID3d11SharedTextureHooks::CreateSharedTexture(
    ID3D11Device* device,
    const D3D11_TEXTURE2D_DESC& desc,
    ID3D11Texture2D** outTexture
    ) noexcept
{
    if (device == nullptr || outTexture == nullptr)
    {
        return E_INVALIDARG;
    }
    *outTexture = nullptr;
    return device->CreateTexture2D(&desc, nullptr, outTexture);
}

HRESULT
ID3d11SharedTextureHooks::CreateSharedNtHandle(
    ID3D11Texture2D* texture,
    const SECURITY_ATTRIBUTES* securityAttributes,
    DWORD accessMask,
    HANDLE* outHandle
    ) noexcept
{
    if (texture == nullptr || outHandle == nullptr)
    {
        return E_INVALIDARG;
    }
    *outHandle = nullptr;

    ComPtr<IDXGIResource1> dxgiResource1;
    const HRESULT qiHr = texture->QueryInterface(IID_PPV_ARGS(&dxgiResource1));
    if (FAILED(qiHr) || dxgiResource1 == nullptr)
    {
        return FAILED(qiHr) ? qiHr : E_NOINTERFACE;
    }

    return dxgiResource1->CreateSharedHandle(
        securityAttributes,
        accessMask,
        nullptr,
        outHandle);
}

HRESULT
ID3d11SharedTextureHooks::AcquireKeyedMutex(
    IDXGIKeyedMutex* keyedMutex,
    UINT64 key,
    DWORD timeoutMs
    ) noexcept
{
    if (keyedMutex == nullptr)
    {
        return E_INVALIDARG;
    }
    return keyedMutex->AcquireSync(key, timeoutMs);
}

HRESULT
ID3d11SharedTextureHooks::ReleaseKeyedMutex(
    IDXGIKeyedMutex* keyedMutex,
    UINT64 key
    ) noexcept
{
    if (keyedMutex == nullptr)
    {
        return E_INVALIDARG;
    }
    return keyedMutex->ReleaseSync(key);
}

HRESULT
ID3d11SharedTextureHooks::CopyTextureResource(
    ID3D11DeviceContext* context,
    ID3D11Texture2D* dstSharedTexture,
    ID3D11Texture2D* srcTexture
    ) noexcept
{
    if (context == nullptr || dstSharedTexture == nullptr || srcTexture == nullptr)
    {
        return E_INVALIDARG;
    }
    context->CopyResource(dstSharedTexture, srcTexture);
    return S_OK;
}

D3d11SharedTexturePool::~D3d11SharedTexturePool()
{
    Shutdown();
}

bool
D3d11SharedTexturePool::IsDeviceRemovedOrResetHResult(
    HRESULT hr
    ) noexcept
{
    return hr == DXGI_ERROR_DEVICE_REMOVED ||
           hr == DXGI_ERROR_DEVICE_RESET ||
           hr == DXGI_ERROR_DEVICE_HUNG ||
           hr == DXGI_ERROR_DRIVER_INTERNAL_ERROR;
}

HRESULT
D3d11SharedTexturePool::Configure(
    size_t poolSize,
    const wchar_t* authorizedUserSid,
    bool restrictDaclToAuthorizedSid,
    bool allowSameUserAccess,
    bool allowBuiltinAdmins,
    bool allowActiveConsoleInteractiveUser,
    DWORD producerMutexTimeoutMs
    ) noexcept
{
    wchar_t canonicalSid[128]{};
    if (authorizedUserSid != nullptr && authorizedUserSid[0] != L'\0')
    {
        if (!CanonicalizeSidWide(authorizedUserSid, canonicalSid, ARRAYSIZE(canonicalSid)))
        {
            return E_INVALIDARG;
        }
    }

    size_t clampedSize = poolSize;
    if (clampedSize < ipc::kMinSharedTexturePoolSize)
    {
        clampedSize = ipc::kMinSharedTexturePoolSize;
    }
    else if (clampedSize > ipc::kMaxSharedTexturePoolSize)
    {
        clampedSize = ipc::kMaxSharedTexturePoolSize;
    }

    ExclusivePoolLock lock(&m_poolLock);
    for (size_t i = 0U; i < ipc::kMaxSharedTexturePoolSize; ++i)
    {
        m_slots[i].ReleaseGpuObjects();
        m_slots[i].SlotIndex = static_cast<uint32_t>(i);
        m_slots[i].State = SharedTextureSlotState::Free;
    }

    m_poolSize = clampedSize;
    (void)wcsncpy_s(m_authorizedUserSid, ARRAYSIZE(m_authorizedUserSid), canonicalSid, _TRUNCATE);
    m_restrictDaclToAuthorizedSid = restrictDaclToAuthorizedSid;
    m_allowSameUserAccess = allowSameUserAccess;
    m_allowBuiltinAdmins = allowBuiltinAdmins;
    m_allowActiveConsoleInteractiveUser = allowActiveConsoleInteractiveUser;
    m_producerMutexTimeoutMs = (producerMutexTimeoutMs == 0U) ? 10U : producerMutexTimeoutMs;
    m_metrics = {};
    m_metrics.PoolSize = static_cast<uint32_t>(clampedSize);
    m_metrics.FreeSlots = static_cast<uint32_t>(clampedSize);
    return S_OK;
}

void
D3d11SharedTexturePool::SetDevice(
    ID3D11Device* device,
    ID3D11DeviceContext* context,
    LUID adapterLuid
    ) noexcept
{
    ExclusivePoolLock lock(&m_poolLock);
    const bool changed =
        (m_d3dDevice.Get() != device) ||
        (m_d3dContext.Get() != context) ||
        (m_adapterLuid.LowPart != adapterLuid.LowPart) ||
        (m_adapterLuid.HighPart != adapterLuid.HighPart);

    if (changed)
    {
        for (size_t i = 0U; i < ipc::kMaxSharedTexturePoolSize; ++i)
        {
            m_slots[i].ReleaseGpuObjects();
            m_slots[i].State = SharedTextureSlotState::Free;
        }
        UpdateUsageMetricsLocked();
    }

    m_d3dDevice = device;
    m_d3dContext = context;
    m_adapterLuid = adapterLuid;
}

void
D3d11SharedTexturePool::SetHooks(
    ID3d11SharedTextureHooks* hooks
    ) noexcept
{
    ExclusivePoolLock lock(&m_poolLock);
    m_hooks = (hooks != nullptr) ? hooks : &m_defaultHooks;
}

void
D3d11SharedTexturePool::ResetResources() noexcept
{
    ExclusivePoolLock lock(&m_poolLock);
    for (size_t i = 0U; i < ipc::kMaxSharedTexturePoolSize; ++i)
    {
        m_slots[i].ReleaseGpuObjects();
        m_slots[i].State = SharedTextureSlotState::Free;
    }
    UpdateUsageMetricsLocked();
}

void
D3d11SharedTexturePool::Shutdown() noexcept
{
    ExclusivePoolLock lock(&m_poolLock);
    for (size_t i = 0U; i < ipc::kMaxSharedTexturePoolSize; ++i)
    {
        m_slots[i].ReleaseGpuObjects();
        m_slots[i].State = SharedTextureSlotState::Free;
    }
    m_d3dContext.Reset();
    m_d3dDevice.Reset();
    m_adapterLuid = LUID{0, 0};
    UpdateUsageMetricsLocked();
}

HRESULT
D3d11SharedTexturePool::BuildSharedHandleSecurityDescriptor(
    PSECURITY_DESCRIPTOR& outSd
    ) const noexcept
{
    outSd = nullptr;

    wchar_t serverSidBuf[128]{};
    bool isServiceAccount = false;
    if (!QueryProcessUserSidWide(serverSidBuf, ARRAYSIZE(serverSidBuf), isServiceAccount))
    {
        const DWORD err = GetLastError();
        return (err != ERROR_SUCCESS) ? HRESULT_FROM_WIN32(err) : E_FAIL;
    }

    static constexpr wchar_t kBaseDacl[] =
        L"D:P(D;;GA;;;NU)(D;;GA;;;AN)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;LS)";
    static constexpr wchar_t kMediumLabelSacl[] = L"S:(ML;;NW;;;ME)";

    wchar_t sddlBuf[768]{};
    if (wcsncpy_s(sddlBuf, ARRAYSIZE(sddlBuf), kBaseDacl, _TRUNCATE) != 0)
    {
        return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
    }

    auto appendAce = [&sddlBuf](const wchar_t* fragment) noexcept -> bool {
        return wcscat_s(sddlBuf, ARRAYSIZE(sddlBuf), fragment) == 0;
    };

    const bool hasAuthSid = (m_authorizedUserSid[0] != L'\0');
    if (hasAuthSid)
    {
        wchar_t authAce[192]{};
        if (_snwprintf_s(authAce, ARRAYSIZE(authAce), _TRUNCATE, L"(A;;GA;;;%ls)", m_authorizedUserSid) <= 0 ||
            !appendAce(authAce))
        {
            return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        }
    }

    const bool restrictServerByAuth = m_restrictDaclToAuthorizedSid && hasAuthSid;
    const bool serverMatchesAuth = hasAuthSid && (_wcsicmp(serverSidBuf, m_authorizedUserSid) == 0);
    if (m_allowSameUserAccess &&
        !isServiceAccount &&
        !restrictServerByAuth &&
        !serverMatchesAuth)
    {
        wchar_t serverAce[192]{};
        if (_snwprintf_s(serverAce, ARRAYSIZE(serverAce), _TRUNCATE, L"(A;;GA;;;%ls)", serverSidBuf) <= 0 ||
            !appendAce(serverAce))
        {
            return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        }
    }

    if (isServiceAccount &&
        !hasAuthSid &&
        !m_restrictDaclToAuthorizedSid &&
        m_allowActiveConsoleInteractiveUser)
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

    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddlBuf,
            SDDL_REVISION_1,
            &outSd,
            nullptr) == FALSE ||
        outSd == nullptr)
    {
        const DWORD err = GetLastError();
        return (err != ERROR_SUCCESS) ? HRESULT_FROM_WIN32(err) : E_FAIL;
    }

    return S_OK;
}

void
D3d11SharedTexturePool::UpdateUsageMetricsLocked() noexcept
{
    uint32_t freeCount = 0U;
    uint32_t queuedCount = 0U;
    uint32_t inUseCount = 0U;

    for (size_t i = 0U; i < m_poolSize; ++i)
    {
        switch (m_slots[i].State)
        {
        case SharedTextureSlotState::Free:
            ++freeCount;
            break;
        case SharedTextureSlotState::QueuedForIpc:
            ++queuedCount;
            break;
        case SharedTextureSlotState::InProducerCopy:
        case SharedTextureSlotState::InUseByHost:
            ++inUseCount;
            break;
        default:
            break;
        }
    }

    m_metrics.PoolSize = static_cast<uint32_t>(m_poolSize);
    m_metrics.FreeSlots = freeCount;
    m_metrics.QueuedSlots = queuedCount;
    m_metrics.InUseByHostSlots = inUseCount;
    const uint32_t used = (m_poolSize >= freeCount) ? (static_cast<uint32_t>(m_poolSize) - freeCount) : 0U;
    if (used > m_metrics.PeakUsage)
    {
        m_metrics.PeakUsage = used;
    }
}

HRESULT
D3d11SharedTexturePool::EnsureSlotTextureLocked(
    SharedTextureSlot& slot,
    uint32_t width,
    uint32_t height,
    DXGI_FORMAT format,
    bool& outRecreated
    ) noexcept
{
    outRecreated = false;
    if (m_d3dDevice == nullptr || m_hooks == nullptr)
    {
        return E_NOT_VALID_STATE;
    }

    const bool matchesExisting =
        !slot.NeedsRecreate &&
        (slot.Texture != nullptr) &&
        (slot.KeyedMutex != nullptr) &&
        slot.SharedNtHandle.IsValid() &&
        (slot.Width == width) &&
        (slot.Height == height) &&
        (slot.Format == format);

    if (matchesExisting)
    {
        return S_OK;
    }

    slot.ReleaseGpuObjects();

    D3D11_TEXTURE2D_DESC desc{};
    desc.Width = width;
    desc.Height = height;
    desc.MipLevels = 1U;
    desc.ArraySize = 1U;
    desc.Format = format;
    desc.SampleDesc.Count = 1U;
    desc.SampleDesc.Quality = 0U;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE | D3D11_BIND_RENDER_TARGET;
    desc.CPUAccessFlags = 0U;
    desc.MiscFlags = D3D11_RESOURCE_MISC_SHARED_NTHANDLE | D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX;

    ComPtr<ID3D11Texture2D> texture;
    HRESULT hr = m_hooks->CreateSharedTexture(m_d3dDevice.Get(), desc, &texture);
    if (FAILED(hr) || texture == nullptr)
    {
        // Retry with SRV-only bind flags in case a format/adapter disallows RT binding on shared resources.
        desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        hr = m_hooks->CreateSharedTexture(m_d3dDevice.Get(), desc, &texture);
        if (FAILED(hr) || texture == nullptr)
        {
            return FAILED(hr) ? hr : E_OUTOFMEMORY;
        }
    }

    ComPtr<IDXGIKeyedMutex> keyedMutex;
    hr = texture.As(&keyedMutex);
    if (FAILED(hr) || keyedMutex == nullptr)
    {
        return FAILED(hr) ? hr : E_NOINTERFACE;
    }

    PSECURITY_DESCRIPTOR sd = nullptr;
    hr = BuildSharedHandleSecurityDescriptor(sd);
    if (FAILED(hr))
    {
        return hr;
    }
    LocalFreeGuard sdGuard{sd};

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;

    HANDLE ntHandle = nullptr;
    hr = m_hooks->CreateSharedNtHandle(
        texture.Get(),
        &sa,
        DXGI_SHARED_RESOURCE_READ | DXGI_SHARED_RESOURCE_WRITE,
        &ntHandle);
    if (FAILED(hr) || ntHandle == nullptr || ntHandle == INVALID_HANDLE_VALUE)
    {
        ++m_metrics.HandleCreateFailures;
        return FAILED(hr) ? hr : E_FAIL;
    }

    slot.Texture = texture;
    slot.KeyedMutex = keyedMutex;
    slot.SharedNtHandle.Reset(ntHandle);
    slot.Width = width;
    slot.Height = height;
    slot.Format = format;
    slot.CurrentMutexKey = ipc::kSharedTextureProducerMutexKey;
    slot.NeedsRecreate = false;
    ++slot.Generation;
    if (slot.Generation == 0U)
    {
        slot.Generation = 1U;
    }
    ++m_metrics.GpuResourceRecreations;
    outRecreated = true;
    return S_OK;
}

SharedTextureExtractResult
D3d11SharedTexturePool::ExtractToSharedTexture(
    const FrameExtractionInput& input,
    ExtractedFrameBuffer& outFrameMetadata,
    bool allowPoolSlotAcquire
    ) noexcept
{
    SharedTextureExtractResult result{};
    outFrameMetadata.ResetMetadataKeepCapacity();

    const uint64_t qpcFreq = QueryQpcFrequencySafe();
    const uint64_t startQpc = QueryCurrentQpc();

    ComPtr<ID3D11Texture2D> sourceTexture;
    if (input.AdoptSourceTexture != nullptr)
    {
        sourceTexture.Attach(input.AdoptSourceTexture);
    }
    auto releaseSourceRefs = [&]() noexcept {
        sourceTexture.Reset();
    };

    if (sourceTexture != nullptr)
    {
    }
    else if (input.SourceTexture != nullptr)
    {
        sourceTexture = input.SourceTexture;
    }
    else if (input.SurfaceResource != nullptr)
    {
        const HRESULT qiHr = input.SurfaceResource->QueryInterface(IID_PPV_ARGS(&sourceTexture));
        if (FAILED(qiHr) || sourceTexture == nullptr)
        {
            releaseSourceRefs();
            result.HResult = FAILED(qiHr) ? qiHr : E_NOINTERFACE;
            return result;
        }
    }
    else
    {
        releaseSourceRefs();
        result.HResult = E_INVALIDARG;
        return result;
    }

    D3D11_TEXTURE2D_DESC srcDesc{};
    sourceTexture->GetDesc(&srcDesc);
    if (srcDesc.Width == 0U || srcDesc.Height == 0U)
    {
        releaseSourceRefs();
        result.HResult = E_INVALIDARG;
        return result;
    }

    result.SurfaceValid = true;
    result.Width = srcDesc.Width;
    result.Height = srcDesc.Height;
    result.Format = static_cast<uint32_t>(srcDesc.Format);

    if (input.HwProtectedSurface || (srcDesc.MiscFlags & D3D11_RESOURCE_MISC_HW_PROTECTED) != 0U)
    {
        releaseSourceRefs();
        result.ProtectedContentRejected = true;
        result.HResult = DXGI_ERROR_ACCESS_DENIED;
        return result;
    }

    if (srcDesc.Width > ipc::kMaxFrameWidth ||
        srcDesc.Height > ipc::kMaxFrameHeight ||
        srcDesc.MipLevels != 1U ||
        srcDesc.ArraySize != 1U ||
        srcDesc.SampleDesc.Count != 1U)
    {
        releaseSourceRefs();
        result.HResult = E_INVALIDARG;
        return result;
    }

    if (!ipc::IsSupportedExtractionDxgiFormat(static_cast<uint32_t>(srcDesc.Format)))
    {
        releaseSourceRefs();
        result.HResult = DXGI_ERROR_UNSUPPORTED;
        return result;
    }

    uint32_t tightPitch = 0U;
    if (!ipc::ComputeTightRowPitchBytes(srcDesc.Width, tightPitch))
    {
        releaseSourceRefs();
        result.HResult = HRESULT_FROM_WIN32(ERROR_ARITHMETIC_OVERFLOW);
        return result;
    }

    result.AcceptedForExtraction = true;

    if (!allowPoolSlotAcquire)
    {
        releaseSourceRefs();
        ExclusivePoolLock lock(&m_poolLock);
        ++m_metrics.GpuFramesDropped;
        result.PoolExhausted = true;
        result.HResult = HRESULT_FROM_WIN32(ERROR_BUSY);
        return result;
    }

    ComPtr<ID3D11Device> d3dDevice;
    ComPtr<ID3D11DeviceContext> d3dContext;
    ID3d11SharedTextureHooks* hooks = nullptr;
    LUID adapterLuid{0, 0};
    DWORD acquireTimeoutMs = 10U;

    uint32_t chosenSlotIdx = 0U;
    uint32_t chosenSlotGen = 0U;
    uint64_t expectedMutexKey = ipc::kSharedTextureProducerMutexKey;
    ComPtr<ID3D11Texture2D> sharedTexture;
    ComPtr<IDXGIKeyedMutex> keyedMutex;
    bool slotRecreated = false;

    {
        ExclusivePoolLock lock(&m_poolLock);
        if (m_d3dDevice == nullptr || m_d3dContext == nullptr || m_hooks == nullptr || m_poolSize == 0U)
        {
            releaseSourceRefs();
            result.HResult = E_NOT_VALID_STATE;
            return result;
        }

        d3dDevice = m_d3dDevice;
        d3dContext = m_d3dContext;
        hooks = m_hooks;
        adapterLuid = m_adapterLuid;
        acquireTimeoutMs = m_producerMutexTimeoutMs;

        size_t freeIdx = m_poolSize;
        for (size_t i = 0U; i < m_poolSize; ++i)
        {
            if (m_slots[i].State == SharedTextureSlotState::Free)
            {
                freeIdx = i;
                break;
            }
        }

        if (freeIdx >= m_poolSize)
        {
            ++m_metrics.GpuFramesDropped;
            result.PoolExhausted = true;
            result.HResult = HRESULT_FROM_WIN32(ERROR_BUSY);
            releaseSourceRefs();
            return result;
        }

        SharedTextureSlot& slot = m_slots[freeIdx];
        slot.State = SharedTextureSlotState::InProducerCopy;
        UpdateUsageMetricsLocked();

        const HRESULT ensureHr = EnsureSlotTextureLocked(
            slot,
            srcDesc.Width,
            srcDesc.Height,
            srcDesc.Format,
            slotRecreated);
        if (FAILED(ensureHr))
        {
            const HRESULT removedReason = d3dDevice->GetDeviceRemovedReason();
            HRESULT effectiveHr = ensureHr;
            if (IsDeviceRemovedOrResetHResult(ensureHr) || IsDeviceRemovedOrResetHResult(removedReason))
            {
                result.DeviceRemovedOrReset = true;
                if (IsDeviceRemovedOrResetHResult(removedReason) && !IsDeviceRemovedOrResetHResult(ensureHr))
                {
                    effectiveHr = removedReason;
                }
            }
            slot.ReleaseGpuObjects();
            slot.State = SharedTextureSlotState::Free;
            ++m_metrics.GpuCopyFailures;
            m_metrics.LastGpuError = effectiveHr;
            UpdateUsageMetricsLocked();
            releaseSourceRefs();
            result.HResult = effectiveHr;
            return result;
        }

        chosenSlotIdx = slot.SlotIndex;
        chosenSlotGen = slot.Generation;
        expectedMutexKey = slot.CurrentMutexKey;
        sharedTexture = slot.Texture;
        keyedMutex = slot.KeyedMutex;
    }

    auto rollbackSlotOnError = [&](bool markNeedsRecreate, HRESULT errHr) noexcept {
        releaseSourceRefs();
        ExclusivePoolLock lock(&m_poolLock);
        SharedTextureSlot& slot = m_slots[chosenSlotIdx];
        if (slot.Generation == chosenSlotGen)
        {
            if (markNeedsRecreate)
            {
                slot.ReleaseGpuObjects();
                slot.NeedsRecreate = true;
            }
            slot.State = SharedTextureSlotState::Free;
        }
        ++m_metrics.GpuCopyFailures;
        m_metrics.LastGpuError = errHr;
        UpdateUsageMetricsLocked();
    };

    HRESULT acqHr = hooks->AcquireKeyedMutex(keyedMutex.Get(), expectedMutexKey, acquireTimeoutMs);
    if (acqHr != S_OK)
    {
        const bool isTimeoutOrAbandoned = (acqHr == static_cast<HRESULT>(WAIT_TIMEOUT) || acqHr == static_cast<HRESULT>(WAIT_ABANDONED));
        if (acqHr == static_cast<HRESULT>(WAIT_TIMEOUT))
        {
            ExclusivePoolLock lock(&m_poolLock);
            ++m_metrics.GpuSyncTimeouts;
        }

        // Attempt one clean slot recreation if the mutex timed out or was abandoned.
        bool recovered = false;
        if (isTimeoutOrAbandoned)
        {
            ExclusivePoolLock lock(&m_poolLock);
            SharedTextureSlot& slot = m_slots[chosenSlotIdx];
            if (slot.Generation == chosenSlotGen)
            {
                slot.NeedsRecreate = true;
                bool recreatedNow = false;
                if (SUCCEEDED(EnsureSlotTextureLocked(slot, srcDesc.Width, srcDesc.Height, srcDesc.Format, recreatedNow)))
                {
                    slotRecreated = true;
                    chosenSlotGen = slot.Generation;
                    expectedMutexKey = slot.CurrentMutexKey;
                    sharedTexture = slot.Texture;
                    keyedMutex = slot.KeyedMutex;
                    recovered = true;
                }
            }
        }

        if (recovered)
        {
            acqHr = hooks->AcquireKeyedMutex(keyedMutex.Get(), expectedMutexKey, acquireTimeoutMs);
        }

        if (acqHr != S_OK)
        {
            const HRESULT removedReason = d3dDevice->GetDeviceRemovedReason();
            HRESULT effectiveHr = (acqHr == static_cast<HRESULT>(WAIT_TIMEOUT))
                ? HRESULT_FROM_WIN32(ERROR_TIMEOUT)
                : (FAILED(acqHr) ? acqHr : HRESULT_FROM_WIN32(ERROR_ABANDONED_WAIT_0));
            if (IsDeviceRemovedOrResetHResult(removedReason))
            {
                result.DeviceRemovedOrReset = true;
                effectiveHr = removedReason;
            }
            rollbackSlotOnError(true, effectiveHr);
            result.HResult = effectiveHr;
            return result;
        }
    }

    const uint64_t gpuCopyStartQpc = QueryCurrentQpc();
    HRESULT copyHr = hooks->CopyTextureResource(
        d3dContext.Get(),
        sharedTexture.Get(),
        sourceTexture.Get());

    // Release ALL references to the acquired IddCx surface immediately after CopyResource submission.
    releaseSourceRefs();
    const uint64_t gpuCopyEndQpc = QueryCurrentQpc();

    const HRESULT releaseHr = hooks->ReleaseKeyedMutex(
        keyedMutex.Get(),
        ipc::kSharedTextureConsumerMutexKey);

    const HRESULT postCopyRemoved = d3dDevice->GetDeviceRemovedReason();
    if (FAILED(copyHr) || FAILED(releaseHr) || IsDeviceRemovedOrResetHResult(postCopyRemoved))
    {
        HRESULT effectiveHr = FAILED(copyHr) ? copyHr : releaseHr;
        if (IsDeviceRemovedOrResetHResult(effectiveHr) || IsDeviceRemovedOrResetHResult(postCopyRemoved))
        {
            result.DeviceRemovedOrReset = true;
            if (IsDeviceRemovedOrResetHResult(postCopyRemoved) && !IsDeviceRemovedOrResetHResult(effectiveHr))
            {
                effectiveHr = postCopyRemoved;
            }
        }
        rollbackSlotOnError(true, effectiveHr);
        result.HResult = effectiveHr;
        return result;
    }

    {
        ExclusivePoolLock lock(&m_poolLock);
        SharedTextureSlot& slot = m_slots[chosenSlotIdx];
        if (slot.Generation != chosenSlotGen)
        {
            result.HResult = E_ABORT;
            return result;
        }
        slot.CurrentMutexKey = ipc::kSharedTextureConsumerMutexKey;
        slot.State = SharedTextureSlotState::QueuedForIpc;
        const uint64_t slotWaitUs = ipc::ComputeQpcElapsedUs(startQpc, gpuCopyStartQpc, qpcFreq);
        m_metrics.LastProducerSlotWaitUs = slotWaitUs;
        m_metrics.TotalProducerSlotWaitUs += slotWaitUs;
        const uint64_t sampleDiv = m_metrics.GpuFramesShared + m_metrics.QueuedSlots + 1ULL;
        m_metrics.AvgProducerSlotWaitUs = m_metrics.TotalProducerSlotWaitUs / sampleDiv;
        if (slotWaitUs > m_metrics.MaxProducerSlotWaitUs)
        {
            m_metrics.MaxProducerSlotWaitUs = slotWaitUs;
        }
        UpdateUsageMetricsLocked();
    }

    const uint64_t endQpc = QueryCurrentQpc();
    const uint64_t producerSlotWaitUs = ipc::ComputeQpcElapsedUs(startQpc, gpuCopyStartQpc, qpcFreq);
    const uint64_t gpuCopyLatencyUs = ipc::ComputeQpcElapsedUs(gpuCopyStartQpc, gpuCopyEndQpc, qpcFreq);
    const uint64_t seq = static_cast<uint64_t>(InterlockedIncrement64(&m_sequenceCounter));

    outFrameMetadata.FrameSequence = seq;
    outFrameMetadata.PresentationFrameNumber = input.PresentationFrameNumber;
    outFrameMetadata.Width = srcDesc.Width;
    outFrameMetadata.Height = srcDesc.Height;
    outFrameMetadata.RowPitchBytes = tightPitch;
    outFrameMetadata.Format = static_cast<uint32_t>(srcDesc.Format);
    outFrameMetadata.DirtyRectCount = input.DirtyRectCount;
    outFrameMetadata.MoveRegionCount = input.MoveRegionCount;
    outFrameMetadata.Flags = input.Flags;
    outFrameMetadata.PresentDisplayQpcTime = input.PresentDisplayQpcTime;
    outFrameMetadata.ExtractStartQpcTime = startQpc;
    outFrameMetadata.GpuCopyCompleteQpcTime = gpuCopyEndQpc;
    outFrameMetadata.ExtractCompleteQpcTime = endQpc;
    outFrameMetadata.EnqueueQpcTime = 0ULL;
    outFrameMetadata.QpcFrequency = qpcFreq;
    outFrameMetadata.CopyLatencyUs = gpuCopyLatencyUs;
    outFrameMetadata.GpuCopyLatencyUs = gpuCopyLatencyUs;
    outFrameMetadata.MapAndCpuCopyLatencyUs = 0ULL;
    outFrameMetadata.CrcComputeLatencyUs = 0ULL;
    outFrameMetadata.PayloadCrc32 = 0U;
    outFrameMetadata.IsGpuSharedFrame = true;
    outFrameMetadata.GpuSlotIndex = chosenSlotIdx;
    outFrameMetadata.GpuSlotGeneration = chosenSlotGen;
    outFrameMetadata.GpuAdapterLuid = adapterLuid;

    result.HResult = S_OK;
    result.GpuCopied = true;
    result.SlotRecreated = slotRecreated;
    result.SlotIndex = chosenSlotIdx;
    result.SlotGeneration = chosenSlotGen;
    result.FrameSequence = seq;
    result.ProducerSlotAndMutexWaitUs = producerSlotWaitUs;
    result.GpuCopyLatencyUs = gpuCopyLatencyUs;
    return result;
}

bool
D3d11SharedTexturePool::BeginHostUseForSlot(
    uint32_t slotIndex,
    uint32_t slotGeneration,
    HANDLE& outSharedNtHandle,
    LUID& outAdapterLuid
    ) noexcept
{
    outSharedNtHandle = nullptr;
    outAdapterLuid = LUID{0, 0};

    ExclusivePoolLock lock(&m_poolLock);
    if (slotIndex >= m_poolSize)
    {
        return false;
    }

    SharedTextureSlot& slot = m_slots[slotIndex];
    if (slot.Generation != slotGeneration ||
        !slot.SharedNtHandle.IsValid() ||
        slot.NeedsRecreate)
    {
        return false;
    }

    slot.State = SharedTextureSlotState::InUseByHost;
    outSharedNtHandle = slot.SharedNtHandle.Get();
    outAdapterLuid = m_adapterLuid;
    UpdateUsageMetricsLocked();
    return true;
}

void
D3d11SharedTexturePool::ReleaseQueuedSlot(
    uint32_t slotIndex,
    uint32_t slotGeneration,
    bool countAsDrop
    ) noexcept
{
    ExclusivePoolLock lock(&m_poolLock);
    if (slotIndex >= m_poolSize)
    {
        return;
    }

    SharedTextureSlot& slot = m_slots[slotIndex];
    if (slot.Generation != slotGeneration)
    {
        return;
    }

    if (slot.State == SharedTextureSlotState::QueuedForIpc)
    {
        // Producer already released mutex to consumer key=1 before enqueueing; since the host never
        // consumed this evicted frame, acquire key=1 -> release key=0 cleanly to avoid destroying
        // and reallocating the DXGI shared texture + NT handle on every backpressure eviction!
        bool reusedKeyedMutex = false;
        if (slot.KeyedMutex != nullptr &&
            slot.CurrentMutexKey == ipc::kSharedTextureConsumerMutexKey &&
            m_hooks != nullptr)
        {
            if (m_hooks->AcquireKeyedMutex(
                    slot.KeyedMutex.Get(),
                    ipc::kSharedTextureConsumerMutexKey,
                    0U) == S_OK &&
                m_hooks->ReleaseKeyedMutex(
                    slot.KeyedMutex.Get(),
                    ipc::kSharedTextureProducerMutexKey) == S_OK)
            {
                slot.CurrentMutexKey = ipc::kSharedTextureProducerMutexKey;
                reusedKeyedMutex = true;
            }
        }
        if (!reusedKeyedMutex && slot.CurrentMutexKey != ipc::kSharedTextureProducerMutexKey)
        {
            slot.ReleaseGpuObjects();
            slot.NeedsRecreate = true;
        }
        slot.State = SharedTextureSlotState::Free;
        if (countAsDrop)
        {
            ++m_metrics.GpuFramesDropped;
        }
        UpdateUsageMetricsLocked();
    }
}

void
D3d11SharedTexturePool::CancelProducerCopySlot(
    uint32_t slotIndex,
    uint32_t slotGeneration,
    bool needsRecreate
    ) noexcept
{
    ExclusivePoolLock lock(&m_poolLock);
    if (slotIndex >= m_poolSize)
    {
        return;
    }

    SharedTextureSlot& slot = m_slots[slotIndex];
    if (slot.Generation != slotGeneration)
    {
        return;
    }

    if (needsRecreate || slot.CurrentMutexKey != ipc::kSharedTextureProducerMutexKey)
    {
        slot.ReleaseGpuObjects();
        slot.NeedsRecreate = true;
    }
    slot.State = SharedTextureSlotState::Free;
    UpdateUsageMetricsLocked();
}

void
D3d11SharedTexturePool::CompleteHostUseForSlot(
    uint32_t slotIndex,
    uint32_t slotGeneration,
    bool cleanReleaseToProducer,
    uint32_t consumerGpuSyncWaitUs
    ) noexcept
{
    ExclusivePoolLock lock(&m_poolLock);
    if (slotIndex >= m_poolSize)
    {
        return;
    }

    SharedTextureSlot& slot = m_slots[slotIndex];
    if (slot.Generation != slotGeneration)
    {
        return;
    }

    if (cleanReleaseToProducer)
    {
        slot.CurrentMutexKey = ipc::kSharedTextureProducerMutexKey;
        slot.State = SharedTextureSlotState::Free;
        ++m_metrics.GpuFramesShared;
        m_metrics.LastGpuSyncWaitUs = consumerGpuSyncWaitUs;
        m_metrics.TotalGpuSyncWaitUs += consumerGpuSyncWaitUs;
        m_metrics.AvgGpuSyncWaitUs =
            (m_metrics.GpuFramesShared > 0ULL) ? (m_metrics.TotalGpuSyncWaitUs / m_metrics.GpuFramesShared) : 0ULL;
        if (consumerGpuSyncWaitUs > m_metrics.MaxGpuSyncWaitUs)
        {
            m_metrics.MaxGpuSyncWaitUs = consumerGpuSyncWaitUs;
        }
    }
    else
    {
        slot.ReleaseGpuObjects();
        slot.NeedsRecreate = true;
        slot.State = SharedTextureSlotState::Free;
        ++m_metrics.GpuFramesDropped;
    }
    UpdateUsageMetricsLocked();
}

size_t
D3d11SharedTexturePool::GetPoolSize() const noexcept
{
    SharedPoolLock lock(&m_poolLock);
    return m_poolSize;
}

LUID
D3d11SharedTexturePool::GetAdapterLuid() const noexcept
{
    SharedPoolLock lock(&m_poolLock);
    return m_adapterLuid;
}

SharedTexturePoolMetricsSnapshot
D3d11SharedTexturePool::GetMetricsSnapshot() const noexcept
{
    SharedPoolLock lock(&m_poolLock);
    return m_metrics;
}

} // namespace lumabridge::driver
