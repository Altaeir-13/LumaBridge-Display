#include "../LumaBridgeIddDriver/SwapChainProcessor.h"
#include "../LumaBridgeIddDriver/FrameIpcProtocol.h"
#include "../LumaBridgeIddDriver/FrameTransport.h"
#include "../../host/FrameConsumer.h"

#include <aclapi.h>
#include <sddl.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace lumabridge::driver;
using namespace lumabridge::ipc;
using namespace lumabridge::host;

namespace {

int g_TestsRun = 0;
int g_TestsFailed = 0;

void
CheckCondition(
    bool condition,
    const char* expression,
    int line
    ) noexcept
{
    if (!condition)
    {
        ++g_TestsFailed;
        std::printf("[FAIL] line %d: %s\n", line, expression);
    }
}

#define EXPECT_TRUE(expr) CheckCondition((expr), #expr, __LINE__)
#define EXPECT_EQ(actual, expected) CheckCondition(((actual) == (expected)), #actual " == " #expected, __LINE__)

std::wstring
MakeUniquePipeName(
    uint32_t caseId
    )
{
    wchar_t buf[128]{};
    _snwprintf_s(
        buf,
        ARRAYSIZE(buf),
        _TRUNCATE,
        L"\\\\.\\pipe\\LumaBridgeIpcTest_%lu_%u",
        GetCurrentProcessId(),
        caseId);
    return buf;
}

std::unique_ptr<ExtractedFrameBuffer>
MakeSyntheticExtractedFrame(
    uint64_t sequence,
    uint32_t presNumber,
    uint32_t width,
    uint32_t height
    )
{
    uint32_t rowPitch = 0U;
    uint32_t payloadBytes = 0U;
    if (!ComputeTightRowPitchBytes(width, rowPitch) ||
        !ComputeValidatedFramePayloadBytes(width, height, rowPitch, payloadBytes))
    {
        return nullptr;
    }

    auto frame = std::make_unique<ExtractedFrameBuffer>();
    if (!frame->Pixels.Resize(payloadBytes))
    {
        return nullptr;
    }

    if (!GenerateSyntheticTestPatternBgra8(
            presNumber,
            width,
            height,
            frame->Pixels.data(),
            frame->Pixels.size()))
    {
        return nullptr;
    }

    LARGE_INTEGER qpc{};
    LARGE_INTEGER freq{};
    (void)QueryPerformanceCounter(&qpc);
    (void)QueryPerformanceFrequency(&freq);

    frame->FrameSequence = sequence;
    frame->PresentationFrameNumber = presNumber;
    frame->Width = width;
    frame->Height = height;
    frame->RowPitchBytes = rowPitch;
    frame->Format = static_cast<uint32_t>(DXGI_FORMAT_B8G8R8A8_UNORM);
    frame->DirtyRectCount = 1U;
    frame->MoveRegionCount = 0U;
    frame->Flags = static_cast<uint32_t>(FrameIpcFlags::SyntheticTestFrame);
    frame->PresentDisplayQpcTime = static_cast<uint64_t>(qpc.QuadPart);
    frame->ExtractCompleteQpcTime = static_cast<uint64_t>(qpc.QuadPart);
    frame->QpcFrequency = static_cast<uint64_t>(freq.QuadPart);
    frame->CopyLatencyUs = 100ULL;
    frame->PayloadCrc32 = ComputeFrameCrc32(frame->Pixels.data(), frame->Pixels.size());
    return frame;
}

bool
WriteAllSync(
    HANDLE h,
    const void* data,
    size_t len
    ) noexcept
{
    const uint8_t* ptr = static_cast<const uint8_t*>(data);
    size_t offset = 0U;
    while (offset < len)
    {
        DWORD written = 0U;
        if (WriteFile(h, ptr + offset, static_cast<DWORD>(len - offset), &written, nullptr) == FALSE ||
            written == 0U)
        {
            return false;
        }
        offset += written;
    }
    return true;
}

bool
ReadAllSync(
    HANDLE h,
    void* data,
    size_t len
    ) noexcept
{
    uint8_t* ptr = static_cast<uint8_t*>(data);
    size_t offset = 0U;
    while (offset < len)
    {
        DWORD bytesRead = 0U;
        if (ReadFile(h, ptr + offset, static_cast<DWORD>(len - offset), &bytesRead, nullptr) == FALSE ||
            bytesRead == 0U)
        {
            return false;
        }
        offset += bytesRead;
    }
    return true;
}

void
TestValidHandshakeFrameTransferAndAck()
{
    const std::wstring pipeName = MakeUniquePipeName(1U);
    FrameTransportConfig serverCfg;
    serverCfg.SetPipeName(pipeName.c_str());
    serverCfg.AdapterLuid = LUID{0x1122, 0x3344};
    serverCfg.MaxQueueDepth = 3U;
    serverCfg.BufferPoolSize = 5U;

    FrameIpcServer server;
    EXPECT_EQ(server.Start(serverCfg), S_OK);
    EXPECT_TRUE(server.IsRunning());

    HostConsumerConfig clientCfg;
    clientCfg.PipeName = pipeName;
    clientCfg.VerifySyntheticPattern = true;
    FrameConsumer consumer(clientCfg);
    EXPECT_EQ(consumer.Connect(2000U), S_OK);

    const auto midMetrics = consumer.GetMetricsSnapshot();
    EXPECT_TRUE(midMetrics.Connected);
    EXPECT_TRUE(midMetrics.SessionId != 0ULL);
    EXPECT_EQ(midMetrics.ServerProcessId, GetCurrentProcessId());
    EXPECT_EQ(midMetrics.AdapterLuidLow, 0x1122);
    EXPECT_EQ(midMetrics.AdapterLuidHigh, 0x3344);

    for (uint32_t i = 1U; i <= 5U; ++i)
    {
        const uint32_t w = (i == 5U) ? 1280U : 64U;
        const uint32_t h = (i == 5U) ? 720U : 64U;
        auto frame = MakeSyntheticExtractedFrame(i, 100U + i, w, h);
        EXPECT_TRUE(frame != nullptr);
        bool evicted = false;
        EXPECT_EQ(server.EnqueueFrame(std::move(frame), evicted), S_OK);

        FrameIpcFrameHeader hdr{};
        std::vector<uint8_t> pixels;
        EXPECT_EQ(consumer.ReceiveNextFrame(hdr, pixels, 2000U), S_OK);
        EXPECT_EQ(hdr.FrameSequence, static_cast<uint64_t>(i));
        EXPECT_EQ(hdr.PresentationFrameNumber, 100U + i);
        EXPECT_EQ(hdr.Width, w);
        EXPECT_EQ(hdr.Height, h);
        EXPECT_TRUE(VerifySyntheticTestPatternBgra8(100U + i, w, h, pixels.data(), pixels.size()));
    }

    const auto cSnap = consumer.GetMetricsSnapshot();
    EXPECT_EQ(cSnap.FramesReceived, 5ULL);
    EXPECT_EQ(cSnap.ChecksumMismatches, 0ULL);
    EXPECT_EQ(cSnap.SyntheticPatternMismatches, 0ULL);
    EXPECT_EQ(cSnap.SequenceGapsDetected, 0ULL);

    const auto sSnap = server.GetMetricsSnapshot();
    EXPECT_EQ(sSnap.FramesDelivered, 5ULL);
    EXPECT_EQ(sSnap.ActiveHostConnections, 1U);
    EXPECT_EQ(sSnap.ClientConnectionsAccepted, 1ULL);

    consumer.Disconnect();
    server.Stop();
    EXPECT_TRUE(!server.IsRunning());
}

DWORD
QueryCurrentSessionId() noexcept
{
    DWORD sid = 0U;
    (void)ProcessIdToSessionId(GetCurrentProcessId(), &sid);
    return sid;
}

bool
QueryCurrentUserSidWide(
    wchar_t* outSidBuf,
    size_t outSidBufChars
    ) noexcept
{
    if (outSidBuf == nullptr || outSidBufChars == 0U)
    {
        return false;
    }
    outSidBuf[0] = L'\0';

    HANDLE procToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &procToken) == FALSE || procToken == nullptr)
    {
        return false;
    }
    ScopedWin32Handle tokenGuard(procToken);

    uint8_t buf[256]{};
    DWORD len = sizeof(buf);
    if (GetTokenInformation(tokenGuard.Get(), TokenUser, buf, len, &len) == FALSE)
    {
        return false;
    }

    const TOKEN_USER* tu = reinterpret_cast<const TOKEN_USER*>(buf);
    LPWSTR sidStr = nullptr;
    if (ConvertSidToStringSidW(tu->User.Sid, &sidStr) == FALSE || sidStr == nullptr)
    {
        return false;
    }
    const errno_t err = wcsncpy_s(outSidBuf, outSidBufChars, sidStr, _TRUNCATE);
    LocalFree(sidStr);
    return (err == 0) && (outSidBuf[0] != L'\0');
}

void
TestIncompatibleProtocolVersionRejected()
{
    const std::wstring pipeName = MakeUniquePipeName(2U);
    FrameTransportConfig serverCfg;
    serverCfg.SetPipeName(pipeName.c_str());

    FrameIpcServer server;
    EXPECT_EQ(server.Start(serverCfg), S_OK);

    ScopedWin32Handle rawClient(CreateFileW(
        pipeName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0U,
        nullptr,
        OPEN_EXISTING,
        0U,
        nullptr));
    EXPECT_TRUE(rawClient.IsValid());

    FrameIpcClientHello badHello{};
    badHello.Envelope = InitEnvelope(
        FrameIpcMessageType::ClientHello,
        static_cast<uint32_t>(sizeof(FrameIpcClientHello)));
    badHello.Envelope.VersionMajor = 99U;
    badHello.ClientProcessId = GetCurrentProcessId();
    badHello.ClientSessionId = static_cast<uint32_t>(QueryCurrentSessionId());
    EXPECT_TRUE(WriteAllSync(rawClient.Get(), &badHello, sizeof(badHello)));

    FrameIpcServerHello serverHello{};
    EXPECT_TRUE(ReadAllSync(rawClient.Get(), &serverHello, sizeof(serverHello)));
    EXPECT_EQ(serverHello.Status, static_cast<uint32_t>(FrameIpcStatus::VersionMismatch));
    EXPECT_EQ(serverHello.SessionId, 0ULL);
    rawClient.Reset();

    // Subsequent valid client still connects cleanly.
    HostConsumerConfig validCfg;
    validCfg.PipeName = pipeName;
    FrameConsumer consumer(validCfg);
    EXPECT_EQ(consumer.Connect(2000U), S_OK);
    EXPECT_EQ(server.GetMetricsSnapshot().ClientConnectionsRejected, 1ULL);
    EXPECT_EQ(server.GetMetricsSnapshot().ClientConnectionsAccepted, 1ULL);

    consumer.Disconnect();
    server.Stop();
}

void
TestInvalidMessageLengthAndBadMagicRejected()
{
    uint8_t tiny[4]{1, 2, 3, 4};
    EXPECT_EQ(
        ValidateEnvelope(tiny, sizeof(tiny), FrameIpcMessageType::ClientHello, sizeof(FrameIpcClientHello)),
        FrameIpcStatus::InvalidLength);

    FrameIpcClientHello badMagic{};
    badMagic.Envelope = InitEnvelope(FrameIpcMessageType::ClientHello, sizeof(FrameIpcClientHello));
    badMagic.Envelope.Magic = 0xDEADBEEFU;
    EXPECT_EQ(
        ValidateClientHello(&badMagic, sizeof(badMagic)),
        FrameIpcStatus::InvalidMagic);

    FrameIpcClientHello badHdrSize{};
    badHdrSize.Envelope = InitEnvelope(FrameIpcMessageType::ClientHello, sizeof(FrameIpcClientHello) + 8U);
    EXPECT_EQ(
        ValidateClientHello(&badHdrSize, sizeof(badHdrSize)),
        FrameIpcStatus::InvalidLength);

    FrameIpcClientHello wrongType{};
    wrongType.Envelope = InitEnvelope(FrameIpcMessageType::FrameAck, sizeof(FrameIpcClientHello));
    EXPECT_EQ(
        ValidateClientHello(&wrongType, sizeof(wrongType)),
        FrameIpcStatus::InvalidLength);

    // Live malformed (bad magic) and truncated ClientHello over Named Pipe.
    const std::wstring pipeName = MakeUniquePipeName(3U);
    FrameTransportConfig serverCfg;
    serverCfg.SetPipeName(pipeName.c_str());
    serverCfg.IoTimeoutMs = 100U;
    FrameIpcServer server;
    EXPECT_EQ(server.Start(serverCfg), S_OK);

    // Case A: Full-size ClientHello with invalid magic gets ServerHello::InvalidMagic.
    {
        ScopedWin32Handle rawClient(CreateFileW(
            pipeName.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0U,
            nullptr,
            OPEN_EXISTING,
            0U,
            nullptr));
        EXPECT_TRUE(rawClient.IsValid());
        EXPECT_TRUE(WriteAllSync(rawClient.Get(), &badMagic, sizeof(badMagic)));
        FrameIpcServerHello srvHello{};
        EXPECT_TRUE(ReadAllSync(rawClient.Get(), &srvHello, sizeof(srvHello)));
        EXPECT_EQ(srvHello.Status, static_cast<uint32_t>(FrameIpcStatus::InvalidMagic));
    }

    // Case B: Truncated 4-byte ClientHello kept open times out server-side and disconnects.
    {
        ScopedWin32Handle rawClient(CreateFileW(
            pipeName.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0U,
            nullptr,
            OPEN_EXISTING,
            0U,
            nullptr));
        EXPECT_TRUE(rawClient.IsValid());
        EXPECT_TRUE(WriteAllSync(rawClient.Get(), tiny, sizeof(tiny)));
        uint8_t eofProbe = 0U;
        DWORD bytesRead = 0U;
        const BOOL ok = ReadFile(rawClient.Get(), &eofProbe, 1U, &bytesRead, nullptr);
        EXPECT_TRUE(ok == FALSE);
    }

    HostConsumerConfig validCfg;
    validCfg.PipeName = pipeName;
    FrameConsumer consumer(validCfg);
    EXPECT_EQ(consumer.Connect(2000U), S_OK);
    EXPECT_EQ(server.GetMetricsSnapshot().ClientConnectionsRejected, 2ULL);
    consumer.Disconnect();
    server.Stop();
}

void
TestIncorrectSessionIdRejected()
{
    FrameIpcFrameHeader hdr{};
    hdr.Envelope = InitEnvelope(FrameIpcMessageType::FrameHeader, sizeof(FrameIpcFrameHeader));
    hdr.SessionId = 42ULL;
    hdr.FrameSequence = 1ULL;
    hdr.Width = 64U;
    hdr.Height = 64U;
    hdr.RowPitchBytes = 256U;
    hdr.PixelFormat = static_cast<uint32_t>(DXGI_FORMAT_B8G8R8A8_UNORM);
    hdr.PayloadSizeBytes = 64U * 64U * 4U;

    EXPECT_EQ(ValidateFrameHeader(&hdr, sizeof(hdr), 42ULL), FrameIpcStatus::Ok);
    EXPECT_EQ(ValidateFrameHeader(&hdr, sizeof(hdr), 99ULL), FrameIpcStatus::SessionMismatch);
    hdr.SessionId = 0ULL;
    EXPECT_EQ(ValidateFrameHeader(&hdr, sizeof(hdr), 42ULL), FrameIpcStatus::SessionMismatch);

    FrameIpcFrameAck ack{};
    ack.Envelope = InitEnvelope(FrameIpcMessageType::FrameAck, sizeof(FrameIpcFrameAck));
    ack.SessionId = 42ULL;
    ack.FrameSequence = 1ULL;
    EXPECT_EQ(ValidateFrameAck(&ack, sizeof(ack), 42ULL), FrameIpcStatus::Ok);
    EXPECT_EQ(ValidateFrameAck(&ack, sizeof(ack), 77ULL), FrameIpcStatus::SessionMismatch);

    // Live server rejects FrameAck with wrong SessionId and disconnects peer.
    const std::wstring pipeName = MakeUniquePipeName(4U);
    FrameTransportConfig serverCfg;
    serverCfg.SetPipeName(pipeName.c_str());
    serverCfg.IoTimeoutMs = 200U;
    FrameIpcServer server;
    EXPECT_EQ(server.Start(serverCfg), S_OK);

    ScopedWin32Handle rawClient(CreateFileW(
        pipeName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0U,
        nullptr,
        OPEN_EXISTING,
        0U,
        nullptr));
    EXPECT_TRUE(rawClient.IsValid());

    FrameIpcClientHello hello{};
    hello.Envelope = InitEnvelope(FrameIpcMessageType::ClientHello, sizeof(FrameIpcClientHello));
    hello.ClientProcessId = GetCurrentProcessId();
    hello.ClientSessionId = static_cast<uint32_t>(QueryCurrentSessionId());
    EXPECT_TRUE(WriteAllSync(rawClient.Get(), &hello, sizeof(hello)));

    FrameIpcServerHello serverHello{};
    EXPECT_TRUE(ReadAllSync(rawClient.Get(), &serverHello, sizeof(serverHello)));
    EXPECT_EQ(serverHello.Status, static_cast<uint32_t>(FrameIpcStatus::Ok));

    auto frame = MakeSyntheticExtractedFrame(1ULL, 1U, 32U, 32U);
    bool evicted = false;
    EXPECT_EQ(server.EnqueueFrame(std::move(frame), evicted), S_OK);

    FrameIpcFrameHeader recvHdr{};
    EXPECT_TRUE(ReadAllSync(rawClient.Get(), &recvHdr, sizeof(recvHdr)));
    std::vector<uint8_t> buf(recvHdr.PayloadSizeBytes, 0U);
    EXPECT_TRUE(ReadAllSync(rawClient.Get(), buf.data(), buf.size()));

    FrameIpcFrameAck badAck{};
    badAck.Envelope = InitEnvelope(FrameIpcMessageType::FrameAck, sizeof(FrameIpcFrameAck));
    badAck.SessionId = serverHello.SessionId + 999ULL;
    badAck.FrameSequence = recvHdr.FrameSequence;
    EXPECT_TRUE(WriteAllSync(rawClient.Get(), &badAck, sizeof(badAck)));

    // Server must drop connection and record failure without counting delivery.
    uint8_t probe = 0U;
    DWORD readOut = 0U;
    const BOOL more = ReadFile(rawClient.Get(), &probe, 1U, &readOut, nullptr);
    EXPECT_TRUE(more == FALSE);
    rawClient.Reset();

    const auto sSnap = server.GetMetricsSnapshot();
    EXPECT_EQ(sSnap.FramesDelivered, 0ULL);
    EXPECT_TRUE(sSnap.FrameTransportFailures >= 1ULL);
    server.Stop();
}

void
TestFrameSequenceMonotonicityAndGapDetection()
{
    const std::wstring pipeName = MakeUniquePipeName(5U);
    FrameTransportConfig serverCfg;
    serverCfg.SetPipeName(pipeName.c_str());
    serverCfg.MaxQueueDepth = 2U;
    serverCfg.BufferPoolSize = 4U;

    FrameIpcServer server;
    EXPECT_EQ(server.Start(serverCfg), S_OK);

    // Enqueue 4 frames before host connects -> frames 1 and 2 are dropped by queue depth=2.
    for (uint32_t seq = 1U; seq <= 4U; ++seq)
    {
        bool evicted = false;
        auto frame = MakeSyntheticExtractedFrame(seq, seq, 32U, 32U);
        EXPECT_EQ(server.EnqueueFrame(std::move(frame), evicted), S_OK);
    }
    EXPECT_EQ(server.GetMetricsSnapshot().FramesDroppedByBackpressure, 2ULL);

    HostConsumerConfig cCfg;
    cCfg.PipeName = pipeName;
    FrameConsumer consumer(cCfg);
    EXPECT_EQ(consumer.Connect(2000U), S_OK);

    FrameIpcFrameHeader h1{};
    FrameIpcFrameHeader h2{};
    std::vector<uint8_t> pixels;
    EXPECT_EQ(consumer.ReceiveNextFrame(h1, pixels, 2000U), S_OK);
    EXPECT_EQ(consumer.ReceiveNextFrame(h2, pixels, 2000U), S_OK);
    EXPECT_EQ(h1.FrameSequence, 3ULL);
    EXPECT_EQ(h2.FrameSequence, 4ULL);

    // Enqueue sequence 10 directly to verify gap detection between 4 and 10.
    bool evicted = false;
    EXPECT_EQ(server.EnqueueFrame(MakeSyntheticExtractedFrame(10ULL, 10U, 32U, 32U), evicted), S_OK);
    FrameIpcFrameHeader h3{};
    EXPECT_EQ(consumer.ReceiveNextFrame(h3, pixels, 2000U), S_OK);
    EXPECT_EQ(h3.FrameSequence, 10ULL);

    EXPECT_EQ(consumer.GetMetricsSnapshot().SequenceGapsDetected, 5ULL);
    consumer.Disconnect();
    server.Stop();
}

void
TestPayloadLimitsAndOverflowValidation()
{
    uint32_t pitch = 0U;
    uint32_t bytes = 0U;
    EXPECT_TRUE(!ComputeTightRowPitchBytes(0U, pitch));
    EXPECT_TRUE(!ComputeTightRowPitchBytes(kMaxFrameWidth + 1U, pitch));
    EXPECT_TRUE(!ComputeTightRowPitchBytes(0x40000001U, pitch));
    EXPECT_TRUE(ComputeTightRowPitchBytes(4096U, pitch));
    EXPECT_EQ(pitch, 4096U * 4U);

    EXPECT_TRUE(ComputeValidatedFramePayloadBytes(4096U, 4096U, 4096U * 4U, bytes));
    EXPECT_EQ(bytes, 4096U * 4096U * 4U);
    EXPECT_TRUE(!ComputeValidatedFramePayloadBytes(4096U, 4097U, 4096U * 4U, bytes));
    EXPECT_TRUE(!ComputeValidatedFramePayloadBytes(1280U, 720U, 1280U * 4U + 4U, bytes));

    FrameIpcFrameHeader hdr{};
    hdr.Envelope = InitEnvelope(FrameIpcMessageType::FrameHeader, sizeof(FrameIpcFrameHeader));
    hdr.SessionId = 1ULL;
    hdr.FrameSequence = 1ULL;
    hdr.Width = 1280U;
    hdr.Height = 720U;
    hdr.RowPitchBytes = 1280U * 4U;
    hdr.PixelFormat = static_cast<uint32_t>(DXGI_FORMAT_NV12);
    hdr.PayloadSizeBytes = 1280U * 720U * 4U;
    EXPECT_EQ(ValidateFrameHeader(&hdr, sizeof(hdr), 1ULL), FrameIpcStatus::UnsupportedPixelFormat);

    hdr.PixelFormat = static_cast<uint32_t>(DXGI_FORMAT_B8G8R8A8_UNORM);
    hdr.PayloadSizeBytes = 1280U * 720U * 4U + 4U;
    EXPECT_EQ(ValidateFrameHeader(&hdr, sizeof(hdr), 1ULL), FrameIpcStatus::PayloadOutOfBounds);

    hdr.Width = kMaxFrameWidth + 1U;
    hdr.RowPitchBytes = hdr.Width * 4U;
    EXPECT_EQ(ValidateFrameHeader(&hdr, sizeof(hdr), 1ULL), FrameIpcStatus::PayloadOutOfBounds);
}

void
TestUnauthorizedClientRejected()
{
    const std::wstring pipeName = MakeUniquePipeName(7U);
    FrameTransportConfig serverCfg;
    serverCfg.SetPipeName(pipeName.c_str());

    FrameIpcServer server;
    EXPECT_EQ(server.Start(serverCfg), S_OK);

    // Enqueue a frame before unauthorized attempts to prove zero pixels are transmitted to them.
    bool evicted = false;
    EXPECT_EQ(server.EnqueueFrame(MakeSyntheticExtractedFrame(1ULL, 11U, 64U, 64U), evicted), S_OK);

    // 1. ClientHello with zero PID rejected cleanly.
    {
        ScopedWin32Handle zeroPidClient(CreateFileW(
            pipeName.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0U,
            nullptr,
            OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            nullptr));
        EXPECT_TRUE(zeroPidClient.IsValid());

        FrameIpcClientHello zeroHello{};
        zeroHello.Envelope = InitEnvelope(FrameIpcMessageType::ClientHello, sizeof(FrameIpcClientHello));
        zeroHello.ClientProcessId = 0U;
        zeroHello.ClientSessionId = static_cast<uint32_t>(QueryCurrentSessionId());
        EXPECT_TRUE(WriteAllSync(zeroPidClient.Get(), &zeroHello, sizeof(zeroHello)));

        FrameIpcServerHello srvHello{};
        EXPECT_TRUE(ReadAllSync(zeroPidClient.Get(), &srvHello, sizeof(srvHello)));
        EXPECT_EQ(srvHello.Status, static_cast<uint32_t>(FrameIpcStatus::UnauthorizedClient));
        EXPECT_EQ(srvHello.SessionId, 0ULL);
    }

    // 2. Spoofed ClientProcessId rejected by kernel GetNamedPipeClientProcessId verification.
    {
        ScopedWin32Handle rawClient(CreateFileW(
            pipeName.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0U,
            nullptr,
            OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            nullptr));
        EXPECT_TRUE(rawClient.IsValid());

        FrameIpcClientHello spoofHello{};
        spoofHello.Envelope = InitEnvelope(FrameIpcMessageType::ClientHello, sizeof(FrameIpcClientHello));
        spoofHello.ClientProcessId = GetCurrentProcessId() + 99999U;
        spoofHello.ClientSessionId = static_cast<uint32_t>(QueryCurrentSessionId());
        EXPECT_TRUE(WriteAllSync(rawClient.Get(), &spoofHello, sizeof(spoofHello)));

        FrameIpcServerHello srvHello{};
        EXPECT_TRUE(ReadAllSync(rawClient.Get(), &srvHello, sizeof(srvHello)));
        EXPECT_EQ(srvHello.Status, static_cast<uint32_t>(FrameIpcStatus::UnauthorizedClient));
        EXPECT_EQ(srvHello.SessionId, 0ULL);
    }

    const auto midSnap = server.GetMetricsSnapshot();
    EXPECT_EQ(midSnap.ClientConnectionsRejected, 2ULL);
    EXPECT_EQ(midSnap.FramesDelivered, 0ULL);
    EXPECT_EQ(midSnap.QueueDepth, 1U);

    // 3. Verify Named Pipe DACL & SACL explicitly deny Network (NU) & Anonymous (AN),
    //    omit broad Interactive Users (IU), allow SYSTEM/BA/LS + owner user SID,
    //    and enforce Medium Mandatory Label.
    {
        ScopedWin32Handle aclProbeClient(CreateFileW(
            pipeName.c_str(),
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
            0U,
            nullptr,
            OPEN_EXISTING,
            0U,
            nullptr));
        EXPECT_TRUE(aclProbeClient.IsValid());

        PACL dacl = nullptr;
        PACL sacl = nullptr;
        PSECURITY_DESCRIPTOR pipeSd = nullptr;
        const DWORD secErr = GetSecurityInfo(
            aclProbeClient.Get(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            &dacl,
            &sacl,
            &pipeSd);
        EXPECT_EQ(secErr, static_cast<DWORD>(ERROR_SUCCESS));
        EXPECT_TRUE(dacl != nullptr);
        EXPECT_TRUE(sacl != nullptr);

        auto hasAceForSid = [](PACL acl, PSID targetSid, BYTE expectedAceType) noexcept {
            if (acl == nullptr || targetSid == nullptr)
            {
                return false;
            }
            ACL_SIZE_INFORMATION aclInfo{};
            if (GetAclInformation(acl, &aclInfo, sizeof(aclInfo), AclSizeInformation) == FALSE)
            {
                return false;
            }
            for (DWORD idx = 0U; idx < aclInfo.AceCount; ++idx)
            {
                LPVOID acePtr = nullptr;
                if (GetAce(acl, idx, &acePtr) == FALSE || acePtr == nullptr)
                {
                    continue;
                }
                const PACE_HEADER hdr = static_cast<PACE_HEADER>(acePtr);
                if (hdr->AceType != expectedAceType)
                {
                    continue;
                }
                PSID aceSid = nullptr;
                if (hdr->AceType == ACCESS_DENIED_ACE_TYPE)
                {
                    aceSid = &(static_cast<PACCESS_DENIED_ACE>(acePtr)->SidStart);
                }
                else if (hdr->AceType == ACCESS_ALLOWED_ACE_TYPE)
                {
                    aceSid = &(static_cast<PACCESS_ALLOWED_ACE>(acePtr)->SidStart);
                }
                else if (hdr->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE)
                {
                    aceSid = &(static_cast<PSYSTEM_MANDATORY_LABEL_ACE>(acePtr)->SidStart);
                }
                if (aceSid != nullptr && EqualSid(aceSid, targetSid) != FALSE)
                {
                    return true;
                }
            }
            return false;
        };

        auto hasAceForWellKnownSid = [&hasAceForSid](PACL acl, WELL_KNOWN_SID_TYPE sidType, BYTE expectedAceType) noexcept {
            uint8_t sidBuf[SECURITY_MAX_SID_SIZE]{};
            DWORD sidSize = sizeof(sidBuf);
            if (CreateWellKnownSid(sidType, nullptr, sidBuf, &sidSize) == FALSE)
            {
                return false;
            }
            return hasAceForSid(acl, sidBuf, expectedAceType);
        };

        if (dacl != nullptr)
        {
            EXPECT_TRUE(hasAceForWellKnownSid(dacl, WinNetworkSid, ACCESS_DENIED_ACE_TYPE));
            EXPECT_TRUE(hasAceForWellKnownSid(dacl, WinAnonymousSid, ACCESS_DENIED_ACE_TYPE));
            EXPECT_TRUE(hasAceForWellKnownSid(dacl, WinLocalSystemSid, ACCESS_ALLOWED_ACE_TYPE));
            EXPECT_TRUE(hasAceForWellKnownSid(dacl, WinBuiltinAdministratorsSid, ACCESS_ALLOWED_ACE_TYPE));
            EXPECT_TRUE(hasAceForWellKnownSid(dacl, WinLocalServiceSid, ACCESS_ALLOWED_ACE_TYPE));
            EXPECT_TRUE(!hasAceForWellKnownSid(dacl, WinInteractiveSid, ACCESS_ALLOWED_ACE_TYPE));

            wchar_t curUserSidStr[128]{};
            EXPECT_TRUE(QueryCurrentUserSidWide(curUserSidStr, ARRAYSIZE(curUserSidStr)));
            PSID curUserSid = nullptr;
            EXPECT_TRUE(ConvertStringSidToSidW(curUserSidStr, &curUserSid) != FALSE);
            EXPECT_TRUE(hasAceForSid(dacl, curUserSid, ACCESS_ALLOWED_ACE_TYPE));
            if (curUserSid != nullptr)
            {
                LocalFree(curUserSid);
            }
        }

        if (sacl != nullptr)
        {
            EXPECT_TRUE(hasAceForWellKnownSid(sacl, WinMediumLabelSid, SYSTEM_MANDATORY_LABEL_ACE_TYPE));
        }

        if (pipeSd != nullptr)
        {
            LocalFree(pipeSd);
        }
    }
    Sleep(30U);

    // Valid client connects and receives the still-queued frame intact.
    HostConsumerConfig okCfg;
    okCfg.PipeName = pipeName;
    okCfg.VerifySyntheticPattern = true;
    FrameConsumer okConsumer(okCfg);
    EXPECT_EQ(okConsumer.Connect(2000U), S_OK);
    FrameIpcFrameHeader hdr{};
    std::vector<uint8_t> pixels;
    EXPECT_EQ(okConsumer.ReceiveNextFrame(hdr, pixels, 2000U), S_OK);
    EXPECT_EQ(hdr.FrameSequence, 1ULL);
    EXPECT_EQ(hdr.PresentationFrameNumber, 11U);
    okConsumer.Disconnect();
    server.Stop();
}

void
TestHostDisconnectReconnectAndMidFrameDisconnect()
{
    const std::wstring pipeName = MakeUniquePipeName(8U);
    FrameTransportConfig serverCfg;
    serverCfg.SetPipeName(pipeName.c_str());
    serverCfg.IoTimeoutMs = 200U;

    FrameIpcServer server;
    EXPECT_EQ(server.Start(serverCfg), S_OK);

    // Connect raw client, read header only, and abruptly close handle mid-frame.
    {
        ScopedWin32Handle rawClient(CreateFileW(
            pipeName.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0U,
            nullptr,
            OPEN_EXISTING,
            0U,
            nullptr));
        EXPECT_TRUE(rawClient.IsValid());

        FrameIpcClientHello hello{};
        hello.Envelope = InitEnvelope(FrameIpcMessageType::ClientHello, sizeof(FrameIpcClientHello));
        hello.ClientProcessId = GetCurrentProcessId();
        hello.ClientSessionId = static_cast<uint32_t>(QueryCurrentSessionId());
        EXPECT_TRUE(WriteAllSync(rawClient.Get(), &hello, sizeof(hello)));

        FrameIpcServerHello srvHello{};
        EXPECT_TRUE(ReadAllSync(rawClient.Get(), &srvHello, sizeof(srvHello)));
        EXPECT_EQ(srvHello.Status, static_cast<uint32_t>(FrameIpcStatus::Ok));

        bool evicted = false;
        EXPECT_EQ(server.EnqueueFrame(MakeSyntheticExtractedFrame(1ULL, 1U, 1280U, 720U), evicted), S_OK);

        FrameIpcFrameHeader hdr{};
        EXPECT_TRUE(ReadAllSync(rawClient.Get(), &hdr, sizeof(hdr)));
        // Abruptly close without reading pixel payload or sending ACK.
        rawClient.Reset();
    }

    // Reconnect with clean FrameConsumer and verify new session delivers frames properly.
    HostConsumerConfig okCfg;
    okCfg.PipeName = pipeName;
    okCfg.VerifySyntheticPattern = true;
    FrameConsumer consumer(okCfg);
    EXPECT_EQ(consumer.Connect(2000U), S_OK);

    bool evicted = false;
    EXPECT_EQ(server.EnqueueFrame(MakeSyntheticExtractedFrame(2ULL, 2U, 1280U, 720U), evicted), S_OK);
    FrameIpcFrameHeader hdr2{};
    std::vector<uint8_t> pixels;
    EXPECT_EQ(consumer.ReceiveNextFrame(hdr2, pixels, 2000U), S_OK);
    EXPECT_EQ(hdr2.FrameSequence, 2ULL);
    EXPECT_TRUE(VerifySyntheticTestPatternBgra8(2U, 1280U, 720U, pixels.data(), pixels.size()));

    // Disconnect cleanly and reconnect again with the same consumer.
    consumer.Disconnect();
    Sleep(50U);
    EXPECT_EQ(consumer.Connect(2000U), S_OK);
    EXPECT_EQ(consumer.GetMetricsSnapshot().ReconnectCount, 1ULL);

    EXPECT_EQ(server.EnqueueFrame(MakeSyntheticExtractedFrame(3ULL, 3U, 64U, 64U), evicted), S_OK);
    EXPECT_EQ(consumer.ReceiveNextFrame(hdr2, pixels, 2000U), S_OK);
    EXPECT_EQ(hdr2.FrameSequence, 3ULL);
    EXPECT_TRUE(VerifySyntheticTestPatternBgra8(3U, 64U, 64U, pixels.data(), pixels.size()));

    consumer.Disconnect();
    server.Stop();
}

void
TestBoundedQueueBackpressureSlowConsumerAndNoBusyWait()
{
    const std::wstring pipeName = MakeUniquePipeName(9U);
    FrameTransportConfig serverCfg;
    serverCfg.SetPipeName(pipeName.c_str());
    serverCfg.MaxQueueDepth = 3U;
    serverCfg.BufferPoolSize = 5U;

    FrameIpcServer server;
    EXPECT_EQ(server.Start(serverCfg), S_OK);

    // 1. Producer pushes 50 frames with NO host connected -> bounded to MaxQueueDepth=3, zero blocking.
    const ULONGLONG t0 = GetTickCount64();
    for (uint32_t i = 1U; i <= 50U; ++i)
    {
        auto slot = server.AcquireBufferSlot();
        EXPECT_TRUE(slot != nullptr);
        uint32_t pitch = 0U;
        uint32_t bytes = 0U;
        EXPECT_TRUE(ComputeTightRowPitchBytes(64U, pitch));
        EXPECT_TRUE(ComputeValidatedFramePayloadBytes(64U, 64U, pitch, bytes));
        EXPECT_TRUE(slot->Pixels.Resize(bytes));
        EXPECT_TRUE(GenerateSyntheticTestPatternBgra8(i, 64U, 64U, slot->Pixels.data(), slot->Pixels.size()));
        slot->FrameSequence = i;
        slot->PresentationFrameNumber = i;
        slot->Width = 64U;
        slot->Height = 64U;
        slot->RowPitchBytes = pitch;
        slot->Format = static_cast<uint32_t>(DXGI_FORMAT_B8G8R8A8_UNORM);
        slot->PayloadCrc32 = ComputeFrameCrc32(slot->Pixels.data(), slot->Pixels.size());

        bool evicted = false;
        EXPECT_EQ(server.EnqueueFrame(std::move(slot), evicted), S_OK);
        if (i > 3U)
        {
            EXPECT_TRUE(evicted);
        }
    }
    const ULONGLONG enqueueElapsedMs = GetTickCount64() - t0;
    EXPECT_TRUE(enqueueElapsedMs < 1000ULL);

    const auto idleSnap = server.GetMetricsSnapshot();
    EXPECT_EQ(idleSnap.FramesEnqueued, 50ULL);
    EXPECT_EQ(idleSnap.QueueDepth, 3U);
    EXPECT_EQ(idleSnap.PeakQueueDepth, 3U);
    EXPECT_EQ(idleSnap.FramesDroppedByBackpressure, 47ULL);

    // 2. Idle period without frames must remain completely quiescent (no busy-wait).
    Sleep(200U);
    const auto idleAfterSnap = server.GetMetricsSnapshot();
    EXPECT_EQ(idleAfterSnap.FramesEnqueued, 50ULL);
    EXPECT_EQ(idleAfterSnap.FramesDelivered, 0ULL);

    // 3. Connect slow consumer: verify latest 3 queued frames (48, 49, 50) arrive cleanly.
    HostConsumerConfig cCfg;
    cCfg.PipeName = pipeName;
    cCfg.VerifySyntheticPattern = true;
    FrameConsumer consumer(cCfg);
    EXPECT_EQ(consumer.Connect(2000U), S_OK);

    FrameIpcFrameHeader hdr{};
    std::vector<uint8_t> pixels;
    for (uint64_t expectedSeq = 48ULL; expectedSeq <= 50ULL; ++expectedSeq)
    {
        EXPECT_EQ(consumer.ReceiveNextFrame(hdr, pixels, 2000U), S_OK);
        EXPECT_EQ(hdr.FrameSequence, expectedSeq);
        EXPECT_TRUE(VerifySyntheticTestPatternBgra8(
            static_cast<uint32_t>(expectedSeq), 64U, 64U, pixels.data(), pixels.size()));
    }

    consumer.Disconnect();
    server.Stop();
}

void
TestConcurrentShutdownSuspendAndResourceCleanup()
{
    const std::wstring pipeName = MakeUniquePipeName(10U);
    FrameTransportConfig serverCfg;
    serverCfg.SetPipeName(pipeName.c_str());
    serverCfg.MaxQueueDepth = 3U;
    serverCfg.BufferPoolSize = 5U;
    serverCfg.IoTimeoutMs = 150U;

    FrameIpcServer server;
    EXPECT_EQ(server.Start(serverCfg), S_OK);

    std::atomic<bool> stopThreads{false};
    std::thread producer([&]() {
        uint32_t seq = 1U;
        while (!stopThreads.load(std::memory_order_acquire))
        {
            auto slot = server.AcquireBufferSlot();
            if (slot != nullptr && slot->Pixels.Resize(64U * 64U * 4U))
            {
                (void)GenerateSyntheticTestPatternBgra8(seq, 64U, 64U, slot->Pixels.data(), slot->Pixels.size());
                slot->FrameSequence = seq;
                slot->PresentationFrameNumber = seq;
                slot->Width = 64U;
                slot->Height = 64U;
                slot->RowPitchBytes = 64U * 4U;
                slot->Format = static_cast<uint32_t>(DXGI_FORMAT_B8G8R8A8_UNORM);
                slot->PayloadCrc32 = ComputeFrameCrc32(slot->Pixels.data(), slot->Pixels.size());
                bool evicted = false;
                (void)server.EnqueueFrame(std::move(slot), evicted);
                ++seq;
            }
            Sleep(2U);
        }
    });

    std::thread consumerThread([&]() {
        HostConsumerConfig cCfg;
        cCfg.PipeName = pipeName;
        cCfg.ConnectTimeoutMs = 500U;
        cCfg.IoTimeoutMs = 150U;
        FrameConsumer consumer(cCfg);
        while (!stopThreads.load(std::memory_order_acquire))
        {
            if (SUCCEEDED(consumer.Connect(300U)))
            {
                FrameIpcFrameHeader hdr{};
                std::vector<uint8_t> pixels;
                for (int i = 0; i < 4 && !stopThreads.load(std::memory_order_acquire); ++i)
                {
                    if (FAILED(consumer.ReceiveNextFrame(hdr, pixels, 200U)))
                    {
                        break;
                    }
                }
                consumer.Disconnect();
            }
            Sleep(5U);
        }
    });

    Sleep(150U);
    const ULONGLONG stopStart = GetTickCount64();
    stopThreads.store(true, std::memory_order_release);
    server.Stop();
    const ULONGLONG stopElapsed = GetTickCount64() - stopStart;

    producer.join();
    consumerThread.join();

    EXPECT_TRUE(stopElapsed < 3000ULL);
    EXPECT_TRUE(!server.IsRunning());
    const auto finalSnap = server.GetMetricsSnapshot();
    EXPECT_EQ(finalSnap.ActiveHostConnections, 0U);
    EXPECT_EQ(finalSnap.QueueDepth, 0U);
}

void
TestCrossUserSidAuthorizationAndRestrictedDaclRejection()
{
    static constexpr wchar_t kOtherUserSid[] = L"S-1-5-21-999999999-888888888-777777777-1001";

    // Subcase A: Token SID enforcement rejects mismatched user before sending any queued frame.
    {
        const std::wstring pipeName = MakeUniquePipeName(11U);
        FrameTransportConfig serverCfg;
        serverCfg.SetPipeName(pipeName.c_str());
        serverCfg.SetAuthorizedUserSid(kOtherUserSid);
        serverCfg.RestrictDaclToAuthorizedSid = false;
        serverCfg.AllowSameUserAccess = true;
        serverCfg.AllowBuiltinAdmins = false;

        FrameIpcServer server;
        EXPECT_EQ(server.Start(serverCfg), S_OK);

        bool evicted = false;
        EXPECT_EQ(server.EnqueueFrame(MakeSyntheticExtractedFrame(1ULL, 1U, 64U, 64U), evicted), S_OK);

        HostConsumerConfig clientCfg;
        clientCfg.PipeName = pipeName;
        FrameConsumer consumer(clientCfg);
        EXPECT_EQ(consumer.Connect(2000U), E_ACCESSDENIED);
        EXPECT_EQ(consumer.GetMetricsSnapshot().LastProtocolStatus, FrameIpcStatus::UnauthorizedClient);

        const auto snap = server.GetMetricsSnapshot();
        EXPECT_EQ(snap.ClientConnectionsRejected, 1ULL);
        EXPECT_EQ(snap.ClientConnectionsAccepted, 0ULL);
        EXPECT_EQ(snap.FramesDelivered, 0ULL);
        EXPECT_EQ(snap.QueueDepth, 1U);
        server.Stop();
    }

    // Subcase B: Kernel DACL restriction blocks unauthorized user when RestrictDaclToAuthorizedSid is enabled.
    {
        const std::wstring pipeName = MakeUniquePipeName(12U);
        FrameTransportConfig serverCfg;
        serverCfg.SetPipeName(pipeName.c_str());
        serverCfg.SetAuthorizedUserSid(kOtherUserSid);
        serverCfg.RestrictDaclToAuthorizedSid = true;
        serverCfg.AllowSameUserAccess = false;
        serverCfg.AllowBuiltinAdmins = false;

        FrameIpcServer server;
        EXPECT_EQ(server.Start(serverCfg), S_OK);

        bool evicted = false;
        EXPECT_EQ(server.EnqueueFrame(MakeSyntheticExtractedFrame(1ULL, 1U, 64U, 64U), evicted), S_OK);

        HostConsumerConfig clientCfg;
        clientCfg.PipeName = pipeName;
        FrameConsumer consumer(clientCfg);
        EXPECT_EQ(consumer.Connect(2000U), E_ACCESSDENIED);

        const auto snap = server.GetMetricsSnapshot();
        EXPECT_EQ(snap.ClientConnectionsAccepted, 0ULL);
        EXPECT_EQ(snap.FramesDelivered, 0ULL);
        EXPECT_EQ(snap.QueueDepth, 1U);
        server.Stop();
    }

    // Subcase C: Exact current user SID with RestrictDaclToAuthorizedSid succeeds cleanly.
    {
        wchar_t currentUserSid[128]{};
        EXPECT_TRUE(QueryCurrentUserSidWide(currentUserSid, ARRAYSIZE(currentUserSid)));

        const std::wstring pipeName = MakeUniquePipeName(13U);
        FrameTransportConfig serverCfg;
        serverCfg.SetPipeName(pipeName.c_str());
        serverCfg.SetAuthorizedUserSid(currentUserSid);
        serverCfg.RestrictDaclToAuthorizedSid = true;
        serverCfg.AllowSameUserAccess = false;

        FrameIpcServer server;
        EXPECT_EQ(server.Start(serverCfg), S_OK);

        bool evicted = false;
        EXPECT_EQ(server.EnqueueFrame(MakeSyntheticExtractedFrame(1ULL, 77U, 64U, 64U), evicted), S_OK);

        HostConsumerConfig clientCfg;
        clientCfg.PipeName = pipeName;
        clientCfg.VerifySyntheticPattern = true;
        FrameConsumer consumer(clientCfg);
        EXPECT_EQ(consumer.Connect(2000U), S_OK);

        FrameIpcFrameHeader hdr{};
        std::vector<uint8_t> pixels;
        EXPECT_EQ(consumer.ReceiveNextFrame(hdr, pixels, 2000U), S_OK);
        EXPECT_EQ(hdr.PresentationFrameNumber, 77U);
        consumer.Disconnect();
        server.Stop();
    }
}

void
TestCrossSessionAndSpoofedSessionRejection()
{
    const DWORD currentSessionId = QueryCurrentSessionId();

    // 1. Server expects a different Terminal Services session ID -> rejects token session mismatch.
    {
        const std::wstring pipeName = MakeUniquePipeName(14U);
        FrameTransportConfig serverCfg;
        serverCfg.SetPipeName(pipeName.c_str());
        serverCfg.SetAllowedClientSessionId(currentSessionId + 17U);

        FrameIpcServer server;
        EXPECT_EQ(server.Start(serverCfg), S_OK);

        bool evicted = false;
        EXPECT_EQ(server.EnqueueFrame(MakeSyntheticExtractedFrame(1ULL, 1U, 64U, 64U), evicted), S_OK);

        HostConsumerConfig clientCfg;
        clientCfg.PipeName = pipeName;
        FrameConsumer consumer(clientCfg);
        EXPECT_EQ(consumer.Connect(2000U), E_ACCESSDENIED);
        EXPECT_EQ(consumer.GetMetricsSnapshot().LastProtocolStatus, FrameIpcStatus::UnauthorizedClient);

        const auto snap = server.GetMetricsSnapshot();
        EXPECT_EQ(snap.ClientConnectionsRejected, 1ULL);
        EXPECT_EQ(snap.FramesDelivered, 0ULL);
        server.Stop();
    }

    // 2. ClientHello claims wrong ClientSessionId compared to kernel TokenSessionId -> rejected.
    {
        const std::wstring pipeName = MakeUniquePipeName(15U);
        FrameTransportConfig serverCfg;
        serverCfg.SetPipeName(pipeName.c_str());

        FrameIpcServer server;
        EXPECT_EQ(server.Start(serverCfg), S_OK);

        bool evicted = false;
        EXPECT_EQ(server.EnqueueFrame(MakeSyntheticExtractedFrame(1ULL, 1U, 64U, 64U), evicted), S_OK);

        ScopedWin32Handle rawClient(CreateFileW(
            pipeName.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0U,
            nullptr,
            OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            nullptr));
        EXPECT_TRUE(rawClient.IsValid());

        FrameIpcClientHello spoofSessionHello{};
        spoofSessionHello.Envelope = InitEnvelope(FrameIpcMessageType::ClientHello, sizeof(FrameIpcClientHello));
        spoofSessionHello.ClientProcessId = GetCurrentProcessId();
        spoofSessionHello.ClientSessionId = static_cast<uint32_t>(currentSessionId + 1U);
        EXPECT_TRUE(WriteAllSync(rawClient.Get(), &spoofSessionHello, sizeof(spoofSessionHello)));

        FrameIpcServerHello srvHello{};
        EXPECT_TRUE(ReadAllSync(rawClient.Get(), &srvHello, sizeof(srvHello)));
        EXPECT_EQ(srvHello.Status, static_cast<uint32_t>(FrameIpcStatus::UnauthorizedClient));
        EXPECT_EQ(srvHello.SessionId, 0ULL);
        rawClient.Reset();

        const auto snap = server.GetMetricsSnapshot();
        EXPECT_EQ(snap.ClientConnectionsRejected, 1ULL);
        EXPECT_EQ(snap.FramesDelivered, 0ULL);
        server.Stop();
    }
}

void
TestProcessIntegrityAndAnonymousSqosRejectionBeforePixels()
{
    // 1. Server requiring higher integrity level rejects standard process token before any frame transfer.
    {
        const std::wstring pipeName = MakeUniquePipeName(16U);
        FrameTransportConfig serverCfg;
        serverCfg.SetPipeName(pipeName.c_str());
        serverCfg.MinimumIntegrityRid = SECURITY_MANDATORY_SYSTEM_RID;

        FrameIpcServer server;
        EXPECT_EQ(server.Start(serverCfg), S_OK);

        bool evicted = false;
        EXPECT_EQ(server.EnqueueFrame(MakeSyntheticExtractedFrame(1ULL, 1U, 64U, 64U), evicted), S_OK);

        HostConsumerConfig clientCfg;
        clientCfg.PipeName = pipeName;
        FrameConsumer consumer(clientCfg);
        EXPECT_EQ(consumer.Connect(2000U), E_ACCESSDENIED);
        EXPECT_EQ(consumer.GetMetricsSnapshot().LastProtocolStatus, FrameIpcStatus::UnauthorizedClient);
        EXPECT_EQ(server.GetMetricsSnapshot().FramesDelivered, 0ULL);
        server.Stop();
    }

    // 2. Anonymous SQOS client and real Low-Integrity token client are both blocked prior to frame delivery.
    {
        const std::wstring pipeName = MakeUniquePipeName(17U);
        FrameTransportConfig serverCfg;
        serverCfg.SetPipeName(pipeName.c_str());

        FrameIpcServer server;
        EXPECT_EQ(server.Start(serverCfg), S_OK);

        bool evicted = false;
        EXPECT_EQ(server.EnqueueFrame(MakeSyntheticExtractedFrame(1ULL, 55U, 64U, 64U), evicted), S_OK);

        // 2a. SECURITY_ANONYMOUS client cannot pass VerifyConnectedClientIdentity.
        {
            ScopedWin32Handle anonClient(CreateFileW(
                pipeName.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                0U,
                nullptr,
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS,
                nullptr));
            if (anonClient.IsValid())
            {
                FrameIpcClientHello anonHello{};
                anonHello.Envelope = InitEnvelope(FrameIpcMessageType::ClientHello, sizeof(FrameIpcClientHello));
                anonHello.ClientProcessId = GetCurrentProcessId();
                anonHello.ClientSessionId = static_cast<uint32_t>(QueryCurrentSessionId());
                if (WriteAllSync(anonClient.Get(), &anonHello, sizeof(anonHello)))
                {
                    FrameIpcServerHello srvHello{};
                    if (ReadAllSync(anonClient.Get(), &srvHello, sizeof(srvHello)))
                    {
                        EXPECT_EQ(srvHello.Status, static_cast<uint32_t>(FrameIpcStatus::UnauthorizedClient));
                        EXPECT_EQ(srvHello.SessionId, 0ULL);
                    }
                }
            }
        }

        // 2b. Duplicated Low Mandatory Integrity token (S-1-16-4096) blocked by kernel Medium Mandatory Label.
        std::atomic<DWORD> lowOpenError{ERROR_SUCCESS};
        std::atomic<bool> lowTokenTested{false};
        std::thread lowThread([&]() {
            HANDLE procToken = nullptr;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &procToken) == FALSE)
            {
                return;
            }
            ScopedWin32Handle procTokenGuard(procToken);

            HANDLE dupLowToken = nullptr;
            if (DuplicateTokenEx(
                    procTokenGuard.Get(),
                    TOKEN_ALL_ACCESS,
                    nullptr,
                    SecurityImpersonation,
                    TokenImpersonation,
                    &dupLowToken) == FALSE)
            {
                return;
            }
            ScopedWin32Handle lowTokenGuard(dupLowToken);

            SID_IDENTIFIER_AUTHORITY mlAuth = SECURITY_MANDATORY_LABEL_AUTHORITY;
            PSID lowSid = nullptr;
            if (AllocateAndInitializeSid(&mlAuth, 1U, SECURITY_MANDATORY_LOW_RID, 0, 0, 0, 0, 0, 0, 0, &lowSid) == FALSE)
            {
                return;
            }

            TOKEN_MANDATORY_LABEL tml{};
            tml.Label.Attributes = SE_GROUP_INTEGRITY;
            tml.Label.Sid = lowSid;
            const BOOL setIlOk = SetTokenInformation(
                lowTokenGuard.Get(),
                TokenIntegrityLevel,
                &tml,
                sizeof(tml) + GetLengthSid(lowSid));
            FreeSid(lowSid);
            if (setIlOk == FALSE)
            {
                return;
            }

            if (ImpersonateLoggedOnUser(lowTokenGuard.Get()) != FALSE)
            {
                lowTokenTested.store(true, std::memory_order_release);
                const HANDLE h = CreateFileW(
                    pipeName.c_str(),
                    GENERIC_READ | GENERIC_WRITE,
                    0U,
                    nullptr,
                    OPEN_EXISTING,
                    SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    nullptr);
                if (h == INVALID_HANDLE_VALUE)
                {
                    lowOpenError.store(GetLastError(), std::memory_order_release);
                }
                else
                {
                    CloseHandle(h);
                }
                (void)RevertToSelf();
            }
        });
        lowThread.join();

        EXPECT_TRUE(lowTokenTested.load(std::memory_order_acquire));
        EXPECT_EQ(lowOpenError.load(std::memory_order_acquire), static_cast<DWORD>(ERROR_ACCESS_DENIED));
        EXPECT_EQ(server.GetMetricsSnapshot().FramesDelivered, 0ULL);

        // Authorized client still receives the untouched queued frame.
        HostConsumerConfig okCfg;
        okCfg.PipeName = pipeName;
        okCfg.VerifySyntheticPattern = true;
        FrameConsumer okConsumer(okCfg);
        EXPECT_EQ(okConsumer.Connect(2000U), S_OK);
        FrameIpcFrameHeader hdr{};
        std::vector<uint8_t> pixels;
        EXPECT_EQ(okConsumer.ReceiveNextFrame(hdr, pixels, 2000U), S_OK);
        EXPECT_EQ(hdr.PresentationFrameNumber, 55U);
        okConsumer.Disconnect();
        server.Stop();
    }
}

template <typename Fn>
void
RunTest(
    const char* name,
    Fn fn
    )
{
    ++g_TestsRun;
    const int failuresBefore = g_TestsFailed;
    fn();
    if (g_TestsFailed == failuresBefore)
    {
        std::printf("[PASS] %s\n", name);
    }
    else
    {
        std::printf("[FAIL] %s\n", name);
    }
}

} // namespace

int
main()
{
    RunTest("ValidHandshakeFrameTransferAndAck", TestValidHandshakeFrameTransferAndAck);
    RunTest("IncompatibleProtocolVersionRejected", TestIncompatibleProtocolVersionRejected);
    RunTest("InvalidMessageLengthAndBadMagicRejected", TestInvalidMessageLengthAndBadMagicRejected);
    RunTest("IncorrectSessionIdRejected", TestIncorrectSessionIdRejected);
    RunTest("FrameSequenceMonotonicityAndGapDetection", TestFrameSequenceMonotonicityAndGapDetection);
    RunTest("PayloadLimitsAndOverflowValidation", TestPayloadLimitsAndOverflowValidation);
    RunTest("UnauthorizedClientRejected", TestUnauthorizedClientRejected);
    RunTest("HostDisconnectReconnectAndMidFrameDisconnect", TestHostDisconnectReconnectAndMidFrameDisconnect);
    RunTest("BoundedQueueBackpressureSlowConsumerAndNoBusyWait", TestBoundedQueueBackpressureSlowConsumerAndNoBusyWait);
    RunTest("ConcurrentShutdownSuspendAndResourceCleanup", TestConcurrentShutdownSuspendAndResourceCleanup);
    RunTest("CrossUserSidAuthorizationAndRestrictedDaclRejection", TestCrossUserSidAuthorizationAndRestrictedDaclRejection);
    RunTest("CrossSessionAndSpoofedSessionRejection", TestCrossSessionAndSpoofedSessionRejection);
    RunTest("ProcessIntegrityAndAnonymousSqosRejectionBeforePixels", TestProcessIntegrityAndAnonymousSqosRejectionBeforePixels);

    std::printf("Summary: %d tests run, %d assertion failures.\n", g_TestsRun, g_TestsFailed);
    return (g_TestsFailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
