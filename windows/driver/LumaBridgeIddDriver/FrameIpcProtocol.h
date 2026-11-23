#pragma once

#include <dxgiformat.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace lumabridge::ipc {

inline constexpr uint32_t kFrameIpcMagic = 0x4649424CU; // 'LBIF'
inline constexpr uint16_t kFrameIpcProtocolVersionMajor = 1U;
inline constexpr uint16_t kFrameIpcProtocolVersionMinor = 0U;

inline constexpr uint32_t kMinFrameDimension = 1U;
inline constexpr uint32_t kMaxFrameWidth = 4096U;
inline constexpr uint32_t kMaxFrameHeight = 4096U;
inline constexpr uint32_t kBytesPerPixelBgra8 = 4U;
inline constexpr uint64_t kMaxFramePayloadBytes = 4096ULL * 4096ULL * 4ULL; // 64 MiB
inline constexpr size_t kMaxRetainedPoolBufferBytes = 2560ULL * 1440ULL * 4ULL; // ~14.06 MiB (1440p BGRA8)

inline constexpr size_t kDefaultMaxFrameQueueDepth = 3U;
inline constexpr size_t kDefaultFrameBufferPoolSize = 5U;
inline constexpr uint32_t kDefaultIpcIoTimeoutMs = 500U;
inline constexpr wchar_t kDefaultFrameIpcPipeName[] = L"\\\\.\\pipe\\LumaBridgeFrameIpc_v1";

enum class FrameIpcMessageType : uint16_t
{
    Invalid = 0,
    ClientHello = 1,
    ServerHello = 2,
    FrameHeader = 3,
    FrameAck = 4,
    DisconnectNotice = 5,
};

enum class FrameIpcStatus : uint32_t
{
    Ok = 0,
    InvalidMagic = 1,
    VersionMismatch = 2,
    InvalidLength = 3,
    UnauthorizedClient = 4,
    SessionMismatch = 5,
    PayloadOutOfBounds = 6,
    UnsupportedPixelFormat = 7,
    ChecksumMismatch = 8,
    ServerStopping = 9,
};

enum class FrameIpcFlags : uint32_t
{
    None = 0U,
    SyntheticTestFrame = 1U << 0,
    PreConnectQueuedFrame = 1U << 1,
};

inline constexpr uint32_t kFrameIpcFlagBitMask = 0x000000FFU;
inline constexpr uint32_t kFrameIpcCopyLatencyUsShift = 8U;
inline constexpr uint32_t kFrameIpcMaxEncodedCopyLatencyUs = 0x00FFFFFFU;

inline constexpr uint32_t
PackFrameFlags(
    uint32_t baseFlags,
    uint64_t copyLatencyUs
    ) noexcept
{
    const uint32_t lowFlags = (baseFlags & kFrameIpcFlagBitMask);
    const uint32_t encodedCopyUs = (copyLatencyUs >= static_cast<uint64_t>(kFrameIpcMaxEncodedCopyLatencyUs))
        ? kFrameIpcMaxEncodedCopyLatencyUs
        : static_cast<uint32_t>(copyLatencyUs);
    return lowFlags | (encodedCopyUs << kFrameIpcCopyLatencyUsShift);
}

inline constexpr uint64_t
UnpackCopyLatencyUsFromFlags(
    uint32_t flags
    ) noexcept
{
    return static_cast<uint64_t>((flags >> kFrameIpcCopyLatencyUsShift) & kFrameIpcMaxEncodedCopyLatencyUs);
}

inline constexpr uint64_t
ComputeQpcElapsedUs(
    uint64_t startQpc,
    uint64_t endQpc,
    uint64_t qpcFreq,
    bool* outOrderValid = nullptr
    ) noexcept
{
    if (startQpc == 0ULL || endQpc == 0ULL || qpcFreq == 0ULL || endQpc < startQpc)
    {
        if (outOrderValid != nullptr)
        {
            *outOrderValid = false;
        }
        return 0ULL;
    }
    if (outOrderValid != nullptr)
    {
        *outOrderValid = true;
    }
    return ((endQpc - startQpc) * 1000000ULL) / qpcFreq;
}

inline const char*
FrameIpcStatusToString(
    FrameIpcStatus status
    ) noexcept
{
    switch (status)
    {
    case FrameIpcStatus::Ok:
        return "Ok";
    case FrameIpcStatus::InvalidMagic:
        return "InvalidMagic";
    case FrameIpcStatus::VersionMismatch:
        return "VersionMismatch";
    case FrameIpcStatus::InvalidLength:
        return "InvalidLength";
    case FrameIpcStatus::UnauthorizedClient:
        return "UnauthorizedClient";
    case FrameIpcStatus::SessionMismatch:
        return "SessionMismatch";
    case FrameIpcStatus::PayloadOutOfBounds:
        return "PayloadOutOfBounds";
    case FrameIpcStatus::UnsupportedPixelFormat:
        return "UnsupportedPixelFormat";
    case FrameIpcStatus::ChecksumMismatch:
        return "ChecksumMismatch";
    case FrameIpcStatus::ServerStopping:
        return "ServerStopping";
    default:
        return "Unknown";
    }
}

#pragma pack(push, 1)

struct FrameIpcEnvelope
{
    uint32_t Magic{kFrameIpcMagic};
    uint16_t VersionMajor{kFrameIpcProtocolVersionMajor};
    uint16_t VersionMinor{kFrameIpcProtocolVersionMinor};
    uint16_t MessageType{static_cast<uint16_t>(FrameIpcMessageType::Invalid)};
    uint16_t Reserved0{0};
    uint32_t HeaderSizeBytes{0};
};

struct FrameIpcClientHello
{
    FrameIpcEnvelope Envelope{};
    uint32_t ClientProcessId{0};
    uint32_t ClientSessionId{0};
    uint32_t ClientCapabilities{0};
    uint32_t Reserved1{0};
};

struct FrameIpcServerHello
{
    FrameIpcEnvelope Envelope{};
    uint32_t Status{static_cast<uint32_t>(FrameIpcStatus::Ok)};
    uint32_t ServerProcessId{0};
    uint64_t SessionId{0};
    int32_t AdapterLuidLow{0};
    int32_t AdapterLuidHigh{0};
    uint32_t MaxQueueDepth{0};
    uint32_t Reserved1{0};
};

struct FrameIpcFrameHeader
{
    FrameIpcEnvelope Envelope{};
    uint64_t SessionId{0};
    uint64_t FrameSequence{0};
    uint32_t PresentationFrameNumber{0};
    uint32_t Width{0};
    uint32_t Height{0};
    uint32_t RowPitchBytes{0};
    uint32_t PixelFormat{0};
    uint32_t Flags{0};
    uint32_t DirtyRectCount{0};
    uint32_t MoveRegionCount{0};
    uint64_t PresentDisplayQpcTime{0};
    uint64_t ExtractCompleteQpcTime{0};
    uint64_t ServerSendQpcTime{0};
    uint64_t QpcFrequency{0};
    uint32_t PayloadSizeBytes{0};
    uint32_t PayloadCrc32{0};
};

struct FrameIpcFrameAck
{
    FrameIpcEnvelope Envelope{};
    uint64_t SessionId{0};
    uint64_t FrameSequence{0};
    uint32_t PresentationFrameNumber{0};
    uint32_t Status{static_cast<uint32_t>(FrameIpcStatus::Ok)};
    uint64_t HostReceiveQpcTime{0};
    uint64_t Reserved1{0};
};

struct FrameIpcDisconnectNotice
{
    FrameIpcEnvelope Envelope{};
    uint64_t SessionId{0};
    uint32_t ReasonCode{0};
    uint32_t Reserved1{0};
};

#pragma pack(pop)

static_assert(sizeof(FrameIpcEnvelope) == 16U, "FrameIpcEnvelope wire size must be 16 bytes.");
static_assert(sizeof(FrameIpcClientHello) == 32U, "FrameIpcClientHello wire size must be 32 bytes.");
static_assert(sizeof(FrameIpcServerHello) == 48U, "FrameIpcServerHello wire size must be 48 bytes.");
static_assert(sizeof(FrameIpcFrameHeader) == 104U, "FrameIpcFrameHeader wire size must be 104 bytes.");
static_assert(sizeof(FrameIpcFrameAck) == 56U, "FrameIpcFrameAck wire size must be 56 bytes.");
static_assert(sizeof(FrameIpcDisconnectNotice) == 32U, "FrameIpcDisconnectNotice wire size must be 32 bytes.");

inline constexpr bool
IsSupportedExtractionDxgiFormat(
    uint32_t dxgiFormat
    ) noexcept
{
    switch (static_cast<DXGI_FORMAT>(dxgiFormat))
    {
    case DXGI_FORMAT_B8G8R8A8_UNORM:
    case DXGI_FORMAT_B8G8R8A8_UNORM_SRGB:
    case DXGI_FORMAT_R8G8B8A8_UNORM:
    case DXGI_FORMAT_R8G8B8A8_UNORM_SRGB:
        return true;
    default:
        return false;
    }
}

inline bool
ComputeTightRowPitchBytes(
    uint32_t width,
    uint32_t& outRowPitchBytes
    ) noexcept
{
    outRowPitchBytes = 0U;
    if (width < kMinFrameDimension || width > kMaxFrameWidth)
    {
        return false;
    }

    const uint64_t pitch = static_cast<uint64_t>(width) * static_cast<uint64_t>(kBytesPerPixelBgra8);
    if (pitch == 0ULL || pitch > 0xFFFFFFFFULL)
    {
        return false;
    }

    outRowPitchBytes = static_cast<uint32_t>(pitch);
    return true;
}

inline bool
ComputeValidatedFramePayloadBytes(
    uint32_t width,
    uint32_t height,
    uint32_t rowPitchBytes,
    uint32_t& outPayloadBytes
    ) noexcept
{
    outPayloadBytes = 0U;
    if (width < kMinFrameDimension ||
        width > kMaxFrameWidth ||
        height < kMinFrameDimension ||
        height > kMaxFrameHeight)
    {
        return false;
    }

    uint32_t expectedPitch = 0U;
    if (!ComputeTightRowPitchBytes(width, expectedPitch) || rowPitchBytes != expectedPitch)
    {
        return false;
    }

    const uint64_t totalBytes = static_cast<uint64_t>(rowPitchBytes) * static_cast<uint64_t>(height);
    if (totalBytes == 0ULL || totalBytes > kMaxFramePayloadBytes || totalBytes > 0xFFFFFFFFULL)
    {
        return false;
    }

    outPayloadBytes = static_cast<uint32_t>(totalBytes);
    return true;
}

inline FrameIpcEnvelope
InitEnvelope(
    FrameIpcMessageType type,
    uint32_t headerSize
    ) noexcept
{
    FrameIpcEnvelope env{};
    env.Magic = kFrameIpcMagic;
    env.VersionMajor = kFrameIpcProtocolVersionMajor;
    env.VersionMinor = kFrameIpcProtocolVersionMinor;
    env.MessageType = static_cast<uint16_t>(type);
    env.Reserved0 = 0U;
    env.HeaderSizeBytes = headerSize;
    return env;
}

inline FrameIpcStatus
ValidateEnvelope(
    const void* data,
    size_t byteCount,
    FrameIpcMessageType expectedType,
    uint32_t expectedHeaderSize
    ) noexcept
{
    if (data == nullptr || byteCount < sizeof(FrameIpcEnvelope))
    {
        return FrameIpcStatus::InvalidLength;
    }

    FrameIpcEnvelope env{};
    std::memcpy(&env, data, sizeof(env));

    if (env.Magic != kFrameIpcMagic)
    {
        return FrameIpcStatus::InvalidMagic;
    }

    if (env.VersionMajor != kFrameIpcProtocolVersionMajor ||
        env.VersionMinor != kFrameIpcProtocolVersionMinor)
    {
        return FrameIpcStatus::VersionMismatch;
    }

    if (env.MessageType != static_cast<uint16_t>(expectedType) ||
        env.HeaderSizeBytes != expectedHeaderSize ||
        byteCount != static_cast<size_t>(expectedHeaderSize))
    {
        return FrameIpcStatus::InvalidLength;
    }

    return FrameIpcStatus::Ok;
}

inline FrameIpcStatus
ValidateClientHello(
    const void* data,
    size_t byteCount
    ) noexcept
{
    const FrameIpcStatus envStatus = ValidateEnvelope(
        data,
        byteCount,
        FrameIpcMessageType::ClientHello,
        static_cast<uint32_t>(sizeof(FrameIpcClientHello)));
    if (envStatus != FrameIpcStatus::Ok)
    {
        return envStatus;
    }

    FrameIpcClientHello hello{};
    std::memcpy(&hello, data, sizeof(hello));
    if (hello.ClientProcessId == 0U)
    {
        return FrameIpcStatus::UnauthorizedClient;
    }

    return FrameIpcStatus::Ok;
}

inline FrameIpcStatus
ValidateServerHello(
    const void* data,
    size_t byteCount
    ) noexcept
{
    const FrameIpcStatus envStatus = ValidateEnvelope(
        data,
        byteCount,
        FrameIpcMessageType::ServerHello,
        static_cast<uint32_t>(sizeof(FrameIpcServerHello)));
    if (envStatus != FrameIpcStatus::Ok)
    {
        return envStatus;
    }

    FrameIpcServerHello hello{};
    std::memcpy(&hello, data, sizeof(hello));
    if (hello.Status != static_cast<uint32_t>(FrameIpcStatus::Ok))
    {
        if (hello.Status <= static_cast<uint32_t>(FrameIpcStatus::ServerStopping))
        {
            return static_cast<FrameIpcStatus>(hello.Status);
        }
        return FrameIpcStatus::InvalidLength;
    }

    if (hello.SessionId == 0ULL || hello.ServerProcessId == 0U || hello.MaxQueueDepth == 0U)
    {
        return FrameIpcStatus::SessionMismatch;
    }

    return FrameIpcStatus::Ok;
}

inline FrameIpcStatus
ValidateFrameHeader(
    const void* data,
    size_t byteCount,
    uint64_t expectedSessionId
    ) noexcept
{
    const FrameIpcStatus envStatus = ValidateEnvelope(
        data,
        byteCount,
        FrameIpcMessageType::FrameHeader,
        static_cast<uint32_t>(sizeof(FrameIpcFrameHeader)));
    if (envStatus != FrameIpcStatus::Ok)
    {
        return envStatus;
    }

    FrameIpcFrameHeader header{};
    std::memcpy(&header, data, sizeof(header));

    if (header.SessionId == 0ULL ||
        (expectedSessionId != 0ULL && header.SessionId != expectedSessionId))
    {
        return FrameIpcStatus::SessionMismatch;
    }

    if (header.FrameSequence == 0ULL)
    {
        return FrameIpcStatus::InvalidLength;
    }

    if (!IsSupportedExtractionDxgiFormat(header.PixelFormat))
    {
        return FrameIpcStatus::UnsupportedPixelFormat;
    }

    uint32_t expectedPayloadBytes = 0U;
    if (!ComputeValidatedFramePayloadBytes(
            header.Width,
            header.Height,
            header.RowPitchBytes,
            expectedPayloadBytes) ||
        header.PayloadSizeBytes != expectedPayloadBytes)
    {
        return FrameIpcStatus::PayloadOutOfBounds;
    }

    return FrameIpcStatus::Ok;
}

inline FrameIpcStatus
ValidateFrameAck(
    const void* data,
    size_t byteCount,
    uint64_t expectedSessionId
    ) noexcept
{
    const FrameIpcStatus envStatus = ValidateEnvelope(
        data,
        byteCount,
        FrameIpcMessageType::FrameAck,
        static_cast<uint32_t>(sizeof(FrameIpcFrameAck)));
    if (envStatus != FrameIpcStatus::Ok)
    {
        return envStatus;
    }

    FrameIpcFrameAck ack{};
    std::memcpy(&ack, data, sizeof(ack));

    if (ack.SessionId == 0ULL ||
        (expectedSessionId != 0ULL && ack.SessionId != expectedSessionId))
    {
        return FrameIpcStatus::SessionMismatch;
    }

    if (ack.FrameSequence == 0ULL)
    {
        return FrameIpcStatus::InvalidLength;
    }

    if (ack.Status != static_cast<uint32_t>(FrameIpcStatus::Ok))
    {
        if (ack.Status <= static_cast<uint32_t>(FrameIpcStatus::ServerStopping))
        {
            return static_cast<FrameIpcStatus>(ack.Status);
        }
        return FrameIpcStatus::InvalidLength;
    }

    return FrameIpcStatus::Ok;
}

namespace detail {

inline constexpr std::array<uint32_t, 256>
MakeCrc32Table() noexcept
{
    std::array<uint32_t, 256> table{};
    for (uint32_t i = 0U; i < 256U; ++i)
    {
        uint32_t c = i;
        for (int k = 0; k < 8; ++k)
        {
            c = ((c & 1U) != 0U) ? (0xEDB88320U ^ (c >> 1U)) : (c >> 1U);
        }
        table[i] = c;
    }
    return table;
}

inline constexpr std::array<uint32_t, 256> kCrc32Table = MakeCrc32Table();

} // namespace detail

inline uint32_t
ComputeFrameCrc32(
    const uint8_t* data,
    size_t size
    ) noexcept
{
    if (data == nullptr && size > 0U)
    {
        return 0U;
    }

    uint32_t crc = 0xFFFFFFFFU;
    for (size_t i = 0U; i < size; ++i)
    {
        const uint8_t idx = static_cast<uint8_t>((crc ^ data[i]) & 0xFFU);
        crc = detail::kCrc32Table[idx] ^ (crc >> 8U);
    }
    return crc ^ 0xFFFFFFFFU;
}

inline bool
GenerateSyntheticTestPatternBgra8(
    uint32_t frameNumber,
    uint32_t width,
    uint32_t height,
    uint8_t* outBuffer,
    size_t bufferSize
    ) noexcept
{
    uint32_t rowPitch = 0U;
    uint32_t requiredBytes = 0U;
    if (outBuffer == nullptr ||
        !ComputeTightRowPitchBytes(width, rowPitch) ||
        !ComputeValidatedFramePayloadBytes(width, height, rowPitch, requiredBytes) ||
        bufferSize < static_cast<size_t>(requiredBytes))
    {
        return false;
    }

    for (uint32_t y = 0U; y < height; ++y)
    {
        uint8_t* rowPtr = outBuffer + static_cast<size_t>(y) * rowPitch;
        for (uint32_t x = 0U; x < width; ++x)
        {
            uint8_t* px = rowPtr + static_cast<size_t>(x) * kBytesPerPixelBgra8;
            px[0] = static_cast<uint8_t>((x + frameNumber * 3U) & 0xFFU);        // B
            px[1] = static_cast<uint8_t>((y + frameNumber * 5U) & 0xFFU);        // G
            px[2] = static_cast<uint8_t>(((x ^ y) + frameNumber * 7U) & 0xFFU);  // R
            px[3] = 0xFFU;                                                       // A
        }
    }

    return true;
}

inline bool
VerifySyntheticTestPatternBgra8(
    uint32_t frameNumber,
    uint32_t width,
    uint32_t height,
    const uint8_t* buffer,
    size_t bufferSize
    ) noexcept
{
    uint32_t rowPitch = 0U;
    uint32_t requiredBytes = 0U;
    if (buffer == nullptr ||
        !ComputeTightRowPitchBytes(width, rowPitch) ||
        !ComputeValidatedFramePayloadBytes(width, height, rowPitch, requiredBytes) ||
        bufferSize != static_cast<size_t>(requiredBytes))
    {
        return false;
    }

    for (uint32_t y = 0U; y < height; ++y)
    {
        const uint8_t* rowPtr = buffer + static_cast<size_t>(y) * rowPitch;
        for (uint32_t x = 0U; x < width; ++x)
        {
            const uint8_t* px = rowPtr + static_cast<size_t>(x) * kBytesPerPixelBgra8;
            const uint8_t expectedB = static_cast<uint8_t>((x + frameNumber * 3U) & 0xFFU);
            const uint8_t expectedG = static_cast<uint8_t>((y + frameNumber * 5U) & 0xFFU);
            const uint8_t expectedR = static_cast<uint8_t>(((x ^ y) + frameNumber * 7U) & 0xFFU);
            if (px[0] != expectedB || px[1] != expectedG || px[2] != expectedR || px[3] != 0xFFU)
            {
                return false;
            }
        }
    }

    return true;
}

} // namespace lumabridge::ipc
