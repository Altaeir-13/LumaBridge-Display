#include "../LumaBridgeIddDriver/SwapChainProcessor.h"
#include "../LumaBridgeIddDriver/FrameIpcProtocol.h"
#include "../LumaBridgeIddDriver/FrameTransport.h"
#include "../LumaBridgeIddDriver/SharedTexturePool.h"
#include "../../host/FrameConsumer.h"
#include "../../host/VirtualDisplayStimulus.h"

#include <aclapi.h>
#include <sddl.h>
#include <d3d11_1.h>
#include <dxgi1_4.h>
#include <wrl/client.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
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
    // Preserve caller-injected synthetic gap (4 -> 10) to test consumer gap accounting directly.
    serverCfg.AssignSequenceOnEnqueue = false;

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

void
TestPoolCapacityLimitsExhaustionAndAllocationFailureRollback()
{
    // 1. Exact exhaustion: BufferPoolSize = 3, MaxQueueDepth = 1.
    //    State under test: 1 slot queued + 1 slot held in IPC worker/peer + 1 slot in extraction.
    //    Acquiring again evicts the 1 queued frame (no over-allocation); acquiring ONE more time
    //    when queue is empty and all 3 slots are in-flight MUST return nullptr without allocating #4.
    {
        const std::wstring pipeName = MakeUniquePipeName(18U);
        FrameTransportConfig serverCfg;
        serverCfg.SetPipeName(pipeName.c_str());
        serverCfg.MaxQueueDepth = 1U;
        serverCfg.BufferPoolSize = 3U;

        FrameIpcServer server;
        EXPECT_EQ(server.Start(serverCfg), S_OK);

        auto initialSnap = server.GetMetricsSnapshot();
        EXPECT_EQ(initialSnap.TotalPoolSlots, 3U);
        EXPECT_EQ(initialSnap.FreePoolSlots, 3U);
        EXPECT_EQ(initialSnap.InFlightSlots, 0U);

        // Slot #1 -> enqueue so it sits in m_queue (depth=1), Slot #2 & #3 held in-flight (extraction/transit).
        auto s1 = server.AcquireBufferSlot();
        EXPECT_TRUE(s1 != nullptr);
        EXPECT_TRUE(s1->Pixels.Resize(64U * 64U * 4U));
        s1->FrameSequence = 1ULL;
        s1->Width = 64U;
        s1->Height = 64U;
        s1->RowPitchBytes = 64U * 4U;
        s1->Format = static_cast<uint32_t>(DXGI_FORMAT_B8G8R8A8_UNORM);
        s1->PayloadCrc32 = ComputeFrameCrc32(s1->Pixels.data(), s1->Pixels.size());
        bool evicted = false;
        EXPECT_EQ(server.EnqueueFrame(std::move(s1), evicted), S_OK);

        auto s2 = server.AcquireBufferSlot();
        auto s3 = server.AcquireBufferSlot();
        EXPECT_TRUE(s2 != nullptr);
        EXPECT_TRUE(s3 != nullptr);

        auto midSnap = server.GetMetricsSnapshot();
        EXPECT_EQ(midSnap.TotalPoolSlots, 3U);
        EXPECT_EQ(midSnap.FreePoolSlots, 0U);
        EXPECT_EQ(midSnap.QueueDepth, 1U);
        EXPECT_EQ(midSnap.InFlightSlots, 2U);

        // Acquiring #4 when Free==0 and Queue==1 evicts the queued frame (#1) cleanly without exceeding 3 slots.
        auto s4FromEviction = server.AcquireBufferSlot();
        EXPECT_TRUE(s4FromEviction != nullptr);
        auto fullInFlightSnap = server.GetMetricsSnapshot();
        EXPECT_EQ(fullInFlightSnap.TotalPoolSlots, 3U);
        EXPECT_EQ(fullInFlightSnap.FreePoolSlots, 0U);
        EXPECT_EQ(fullInFlightSnap.QueueDepth, 0U);
        EXPECT_EQ(fullInFlightSnap.InFlightSlots, 3U);
        EXPECT_EQ(fullInFlightSnap.QueueEvictionsByBackpressure, 1ULL);

        // Acquiring #5 when Free==0, Queue==0, and all 3 slots are checked out in-flight MUST return nullptr!
        auto s5Exhausted = server.AcquireBufferSlot();
        EXPECT_TRUE(s5Exhausted == nullptr);
        auto exhaustedSnap = server.GetMetricsSnapshot();
        EXPECT_EQ(exhaustedSnap.TotalPoolSlots, 3U);
        EXPECT_EQ(exhaustedSnap.InFlightSlots, 3U);
        EXPECT_EQ(exhaustedSnap.PoolExhaustionDrops, 1ULL);
        EXPECT_EQ(exhaustedSnap.FramesDroppedByBackpressure, 2ULL);

        // Recycling one slot restores capacity cleanly.
        server.RecycleBufferSlot(std::move(s2));
        auto s6 = server.AcquireBufferSlot();
        EXPECT_TRUE(s6 != nullptr);

        server.RecycleBufferSlot(std::move(s3));
        server.RecycleBufferSlot(std::move(s4FromEviction));
        server.RecycleBufferSlot(std::move(s6));

        auto cleanSnap = server.GetMetricsSnapshot();
        EXPECT_EQ(cleanSnap.TotalPoolSlots, 3U);
        EXPECT_EQ(cleanSnap.FreePoolSlots, 3U);
        EXPECT_EQ(cleanSnap.InFlightSlots, 0U);
        EXPECT_EQ(cleanSnap.QueueDepth, 0U);

        server.Stop();
        auto stoppedSnap = server.GetMetricsSnapshot();
        EXPECT_EQ(stoppedSnap.TotalPoolSlots, 0U);
        EXPECT_EQ(stoppedSnap.FreePoolSlots, 0U);
        EXPECT_EQ(stoppedSnap.InFlightSlots, 0U);
    }

    // 2. Allocation failure handling and counter rollback (PreallocatePoolOnStart = false + Start fail).
    {
        const std::wstring pipeName = MakeUniquePipeName(19U);
        FrameTransportConfig failStartCfg;
        failStartCfg.SetPipeName(pipeName.c_str());
        failStartCfg.BufferPoolSize = 3U;

        FrameIpcServer server;
        server.SetSimulateSlotAllocationFailureForTesting(true);
        EXPECT_EQ(server.Start(failStartCfg), E_OUTOFMEMORY);
        EXPECT_TRUE(!server.IsRunning());
        EXPECT_EQ(server.GetMetricsSnapshot().TotalPoolSlots, 0U);
        EXPECT_EQ(server.GetMetricsSnapshot().PoolAllocationFailures, 1ULL);

        server.SetSimulateSlotAllocationFailureForTesting(false);

        FrameTransportConfig lazyCfg;
        lazyCfg.SetPipeName(pipeName.c_str());
        lazyCfg.MaxQueueDepth = 1U;
        lazyCfg.BufferPoolSize = 3U;
        lazyCfg.PreallocatePoolOnStart = false;
        EXPECT_EQ(server.Start(lazyCfg), S_OK);
        EXPECT_EQ(server.GetMetricsSnapshot().TotalPoolSlots, 0U);

        // First slot succeeds -> Total=1, InFlight=1.
        auto first = server.AcquireBufferSlot();
        EXPECT_TRUE(first != nullptr);
        EXPECT_EQ(server.GetMetricsSnapshot().TotalPoolSlots, 1U);
        EXPECT_EQ(server.GetMetricsSnapshot().InFlightSlots, 1U);

        // Next slot hits simulated new(std::nothrow)==nullptr -> counters roll back cleanly to Total=1, InFlight=1!
        server.SetSimulateSlotAllocationFailureForTesting(true);
        auto failed = server.AcquireBufferSlot();
        EXPECT_TRUE(failed == nullptr);
        const auto rollbackSnap = server.GetMetricsSnapshot();
        EXPECT_EQ(rollbackSnap.TotalPoolSlots, 1U);
        EXPECT_EQ(rollbackSnap.InFlightSlots, 1U);
        EXPECT_EQ(rollbackSnap.PoolAllocationFailures, 1ULL);
        EXPECT_EQ(rollbackSnap.FramesDroppedByBackpressure, 1ULL);

        // Clearing fault allows subsequent allocation up to BufferPoolSize=3.
        server.SetSimulateSlotAllocationFailureForTesting(false);
        auto second = server.AcquireBufferSlot();
        EXPECT_TRUE(second != nullptr);
        EXPECT_EQ(server.GetMetricsSnapshot().TotalPoolSlots, 2U);
        server.RecycleBufferSlot(std::move(first));
        server.RecycleBufferSlot(std::move(second));
        server.Stop();
    }
}

void
TestSmokeExitReasonsIdleDesktopAndRecoverableVsPartialTimeouts()
{
    // Case A: Idle desktop with zero frames -> normal DurationElapsed, TransportHealthy=true, LastError=S_OK.
    {
        const std::wstring pipeName = MakeUniquePipeName(20U);
        FrameTransportConfig serverCfg;
        serverCfg.SetPipeName(pipeName.c_str());
        FrameIpcServer server;
        EXPECT_EQ(server.Start(serverCfg), S_OK);

        HostConsumerConfig hostCfg;
        hostCfg.PipeName = pipeName;
        hostCfg.IoTimeoutMs = 80U;
        hostCfg.MaxDurationMs = 260U;
        hostCfg.MaxFrames = 60ULL;
        hostCfg.MinFrames = 0ULL;
        hostCfg.RequireFrameTarget = false;

        FrameConsumer consumer(hostCfg);
        EXPECT_EQ(consumer.RunLoop(), S_OK);

        const auto snap = consumer.GetMetricsSnapshot();
        EXPECT_EQ(snap.ExitReason, HostExitReason::DurationElapsed);
        EXPECT_TRUE(snap.HostProcessExitedNormally);
        EXPECT_TRUE(snap.TransportHealthy);
        EXPECT_EQ(snap.FramesReceived, 0ULL);
        EXPECT_EQ(snap.RecoverableIoTimeouts >= 1ULL, true);
        EXPECT_EQ(snap.FatalIoTimeouts, 0ULL);
        EXPECT_EQ(snap.PartialMessageTimeouts, 0ULL);
        EXPECT_EQ(snap.LastErrorHResult, S_OK);
        EXPECT_TRUE(snap.TotalIdleWaitDurationUs > 0ULL);
        server.Stop();
    }

    // Case B: Single valid frame delivered cleanly.
    {
        const std::wstring pipeName = MakeUniquePipeName(21U);
        FrameTransportConfig serverCfg;
        serverCfg.SetPipeName(pipeName.c_str());
        FrameIpcServer server;
        EXPECT_EQ(server.Start(serverCfg), S_OK);

        bool evicted = false;
        EXPECT_EQ(server.EnqueueFrame(MakeSyntheticExtractedFrame(1ULL, 10U, 64U, 64U), evicted), S_OK);

        HostConsumerConfig hostCfg;
        hostCfg.PipeName = pipeName;
        hostCfg.IoTimeoutMs = 80U;
        hostCfg.MaxDurationMs = 220U;
        hostCfg.MaxFrames = 60ULL;
        hostCfg.MinFrames = 1ULL;
        hostCfg.RequireFrameTarget = false;
        hostCfg.VerifySyntheticPattern = true;

        FrameConsumer consumer(hostCfg);
        EXPECT_EQ(consumer.RunLoop(), S_OK);

        const auto snap = consumer.GetMetricsSnapshot();
        EXPECT_EQ(snap.ExitReason, HostExitReason::DurationElapsed);
        EXPECT_TRUE(snap.HostProcessExitedNormally);
        EXPECT_TRUE(snap.TransportHealthy);
        EXPECT_EQ(snap.FramesValid, 1ULL);
        EXPECT_TRUE(snap.MinFramesReached);
        EXPECT_TRUE(!snap.FrameTargetReached);
        EXPECT_EQ(snap.PreConnectFramesReceived, 1ULL);
        EXPECT_EQ(snap.LiveFramesReceived, 0ULL);
        EXPECT_TRUE(!snap.FpsSampleSufficient);
        EXPECT_EQ(snap.ObservedActiveFps, 0.0);
        server.Stop();
    }

    // Case C: Three valid frames with target 60 -> smoke passes cleanly while distinguishing target not reached,
    //         and recoverable boundary timeout recovers cleanly for the next frame.
    {
        const std::wstring pipeName = MakeUniquePipeName(22U);
        FrameTransportConfig serverCfg;
        serverCfg.SetPipeName(pipeName.c_str());
        FrameIpcServer server;
        EXPECT_EQ(server.Start(serverCfg), S_OK);

        HostConsumerConfig hostCfg;
        hostCfg.PipeName = pipeName;
        hostCfg.IoTimeoutMs = 80U;
        hostCfg.VerifySyntheticPattern = true;
        FrameConsumer consumer(hostCfg);
        EXPECT_EQ(consumer.Connect(2000U), S_OK);

        // Boundary timeout with 0 frames sent must NOT drop connection.
        FrameIpcFrameHeader tmpHdr{};
        std::vector<uint8_t> tmpPixels;
        EXPECT_EQ(consumer.ReceiveNextFrame(tmpHdr, tmpPixels, 70U), HRESULT_FROM_WIN32(ERROR_TIMEOUT));
        EXPECT_EQ(consumer.GetMetricsSnapshot().RecoverableIoTimeouts, 1ULL);
        EXPECT_EQ(consumer.GetMetricsSnapshot().FatalIoTimeouts, 0ULL);
        EXPECT_TRUE(consumer.GetMetricsSnapshot().Connected);
        EXPECT_TRUE(consumer.GetMetricsSnapshot().TransportHealthy);

        // Next 3 live frames still transfer cleanly on the SAME synchronized pipe!
        for (uint32_t i = 1U; i <= 3U; ++i)
        {
            bool evicted = false;
            EXPECT_EQ(server.EnqueueFrame(MakeSyntheticExtractedFrame(i, i, 64U, 64U), evicted), S_OK);
            EXPECT_EQ(consumer.ReceiveNextFrame(tmpHdr, tmpPixels, 1000U), S_OK);
        }

        const auto snap = consumer.GetMetricsSnapshot();
        EXPECT_EQ(snap.FramesValid, 3ULL);
        EXPECT_EQ(snap.LiveFramesReceived, 3ULL);
        EXPECT_EQ(snap.ChecksumMismatches, 0ULL);
        EXPECT_TRUE(snap.TransportHealthy);
        EXPECT_EQ(snap.RecoverableIoTimeouts, 1ULL);
        consumer.Disconnect();
        server.Stop();
    }

    // Case D: Partial envelope and mid-payload timeouts close pipe immediately and mark fatal timeout.
    {
        const std::wstring pipeName = MakeUniquePipeName(23U);
        HANDLE serverPipe = CreateNamedPipeW(
            pipeName.c_str(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1U,
            65536U,
            65536U,
            0U,
            nullptr);
        EXPECT_TRUE(serverPipe != INVALID_HANDLE_VALUE);

        std::thread rawServer([&]() {
            ConnectNamedPipe(serverPipe, nullptr);
            FrameIpcClientHello cHello{};
            ReadAllSync(serverPipe, &cHello, sizeof(cHello));

            FrameIpcServerHello sHello{};
            sHello.Envelope = InitEnvelope(FrameIpcMessageType::ServerHello, sizeof(sHello));
            sHello.Status = static_cast<uint32_t>(FrameIpcStatus::Ok);
            sHello.ServerProcessId = GetCurrentProcessId();
            sHello.SessionId = 88ULL;
            sHello.MaxQueueDepth = 3U;
            WriteAllSync(serverPipe, &sHello, sizeof(sHello));

            // Write ONLY 6 bytes of 16-byte FrameIpcEnvelope, then stall past IoTimeoutMs!
            uint8_t partialEnv[6]{0x4C, 0x42, 0x49, 0x46, 0x01, 0x00};
            WriteAllSync(serverPipe, partialEnv, sizeof(partialEnv));
            Sleep(250U);
            CloseHandle(serverPipe);
        });

        HostConsumerConfig cfg;
        cfg.PipeName = pipeName;
        cfg.IoTimeoutMs = 90U;
        cfg.MaxDurationMs = 1000U;
        FrameConsumer consumer(cfg);
        const HRESULT runHr = consumer.RunLoop();
        rawServer.join();

        EXPECT_EQ(runHr, HRESULT_FROM_WIN32(ERROR_TIMEOUT));
        const auto snap = consumer.GetMetricsSnapshot();
        EXPECT_EQ(snap.ExitReason, HostExitReason::FatalIoTimeout);
        EXPECT_TRUE(!snap.HostProcessExitedNormally);
        EXPECT_TRUE(!snap.TransportHealthy);
        EXPECT_EQ(snap.FatalIoTimeouts, 1ULL);
        EXPECT_EQ(snap.PartialMessageTimeouts, 1ULL);
        EXPECT_EQ(snap.RecoverableIoTimeouts, 0ULL);
    }

    // Case E: Mid-payload timeout (full header sent, partial payload stalls).
    {
        const std::wstring pipeName = MakeUniquePipeName(24U);
        HANDLE serverPipe = CreateNamedPipeW(
            pipeName.c_str(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1U,
            65536U,
            65536U,
            0U,
            nullptr);
        EXPECT_TRUE(serverPipe != INVALID_HANDLE_VALUE);

        std::thread rawServer([&]() {
            ConnectNamedPipe(serverPipe, nullptr);
            FrameIpcClientHello cHello{};
            ReadAllSync(serverPipe, &cHello, sizeof(cHello));

            LARGE_INTEGER freq{};
            QueryPerformanceFrequency(&freq);
            FrameIpcServerHello sHello{};
            sHello.Envelope = InitEnvelope(FrameIpcMessageType::ServerHello, sizeof(sHello));
            sHello.Status = static_cast<uint32_t>(FrameIpcStatus::Ok);
            sHello.ServerProcessId = GetCurrentProcessId();
            sHello.SessionId = 99ULL;
            sHello.MaxQueueDepth = 3U;
            WriteAllSync(serverPipe, &sHello, sizeof(sHello));

            FrameIpcFrameHeader hdr{};
            hdr.Envelope = InitEnvelope(FrameIpcMessageType::FrameHeader, sizeof(hdr));
            hdr.SessionId = 99ULL;
            hdr.FrameSequence = 1ULL;
            hdr.Width = 64U;
            hdr.Height = 64U;
            hdr.RowPitchBytes = 256U;
            hdr.PixelFormat = static_cast<uint32_t>(DXGI_FORMAT_B8G8R8A8_UNORM);
            hdr.PayloadSizeBytes = 64U * 64U * 4U;
            hdr.QpcFrequency = static_cast<uint64_t>(freq.QuadPart);
            hdr.ExtractCompleteQpcTime = 1000ULL;
            hdr.ServerSendQpcTime = 1010ULL;
            WriteAllSync(serverPipe, &hdr, sizeof(hdr));

            std::vector<uint8_t> partialPayload(512U, 0xAAU);
            WriteAllSync(serverPipe, partialPayload.data(), partialPayload.size());
            Sleep(250U);
            CloseHandle(serverPipe);
        });

        HostConsumerConfig cfg;
        cfg.PipeName = pipeName;
        cfg.IoTimeoutMs = 90U;
        cfg.MaxDurationMs = 1000U;
        FrameConsumer consumer(cfg);
        const HRESULT runHr = consumer.RunLoop();
        rawServer.join();

        EXPECT_EQ(runHr, HRESULT_FROM_WIN32(ERROR_TIMEOUT));
        const auto snap = consumer.GetMetricsSnapshot();
        EXPECT_EQ(snap.ExitReason, HostExitReason::FatalIoTimeout);
        EXPECT_TRUE(!snap.TransportHealthy);
        EXPECT_EQ(snap.FatalIoTimeouts, 1ULL);
        EXPECT_EQ(snap.PartialMessageTimeouts, 1ULL);
    }
}

void
TestDeterministicFpsGuardrailsTimestampValidationAndVirtualDisplaySelection()
{
    // 1. Small-sample FPS guardrails (3 frames in 37 ms burst over 15s execution -> insufficient active sample).
    constexpr uint64_t kFreq = 10000000ULL;
    const HostFpsBreakdown smallBurst = ComputeHostFpsBreakdown(
        3ULL,
        0ULL,
        15000000ULL,
        14990000ULL,
        kFreq * 10ULL,
        kFreq * 10ULL + 370000ULL,
        0ULL,
        0ULL,
        kFreq);
    EXPECT_TRUE(!smallBurst.FpsSampleSufficient);
    EXPECT_EQ(smallBurst.ObservedActiveFps, 0.0);
    EXPECT_TRUE(smallBurst.AverageExecutionFps > 0.19 && smallBurst.AverageExecutionFps < 0.21);

    // Sufficient sample (60 frames over 1s -> ObservedActiveFps ~ 59-60 FPS).
    const HostFpsBreakdown steadyRun = ComputeHostFpsBreakdown(
        60ULL,
        59ULL,
        1200000ULL,
        1100000ULL,
        kFreq * 1ULL,
        kFreq * 2ULL,
        kFreq * 1ULL + 200000ULL,
        kFreq * 2ULL,
        kFreq);
    EXPECT_TRUE(steadyRun.FpsSampleSufficient);
    EXPECT_TRUE(steadyRun.ObservedActiveFps > 58.9 && steadyRun.ObservedActiveFps < 59.1);
    EXPECT_TRUE(steadyRun.SustainedLiveFps > 50.0);

    // 2. QPC frequency mismatch & out-of-order timestamp rejection (must report error, not wrapped latency).
    FrameIpcFrameHeader hdr{};
    hdr.Envelope = InitEnvelope(FrameIpcMessageType::FrameHeader, sizeof(hdr));
    hdr.QpcFrequency = kFreq + 1ULL;
    hdr.PresentDisplayQpcTime = 1000ULL;
    hdr.ExtractCompleteQpcTime = 2000ULL;
    hdr.ServerSendQpcTime = 3000ULL;
    const ValidatedFrameIntervals freqMismatch = ComputeValidatedFrameIntervals(hdr, 4000ULL, 5000ULL, kFreq, true);
    EXPECT_TRUE(!freqMismatch.Valid);
    EXPECT_TRUE(freqMismatch.QpcFrequencyMismatch);

    hdr.QpcFrequency = kFreq;
    hdr.ServerSendQpcTime = 1500ULL; // < ExtractCompleteQpcTime (2000) -> invalid out-of-order!
    const ValidatedFrameIntervals outOfOrder = ComputeValidatedFrameIntervals(hdr, 4000ULL, 5000ULL, kFreq, true);
    EXPECT_TRUE(!outOfOrder.Valid);
    EXPECT_TRUE(outOfOrder.OutOfOrderTimestamps);

    hdr.ServerSendQpcTime = 3000ULL;
    hdr.Flags = PackFrameFlags(static_cast<uint32_t>(FrameIpcFlags::PreConnectQueuedFrame), 850ULL);
    const ValidatedFrameIntervals validIntervals = ComputeValidatedFrameIntervals(hdr, 4000ULL, 5000ULL, kFreq, true);
    EXPECT_TRUE(validIntervals.Valid);
    EXPECT_TRUE(validIntervals.PreConnectQueued);
    EXPECT_EQ(validIntervals.CopyUs, 850ULL);
    EXPECT_EQ(validIntervals.QueueWaitUs, 100ULL);
    EXPECT_EQ(validIntervals.IpcTransitUs, 100ULL);
    EXPECT_EQ(validIntervals.HostVerifyAckUs, 100ULL);
    EXPECT_EQ(validIntervals.EndToEndUs, 200ULL);

    // 3. Percentile summary validation.
    std::vector<uint64_t> latSamples{500ULL, 100ULL, 300ULL, 900ULL, 200ULL, 400ULL, 700ULL, 800ULL, 600ULL, 1000ULL};
    const LatencySummaryStats stats = ComputeLatencySummary(latSamples, 1000ULL);
    EXPECT_EQ(stats.SampleCount, 10ULL);
    EXPECT_EQ(stats.MinUs, 100ULL);
    EXPECT_EQ(stats.MaxUs, 1000ULL);
    EXPECT_EQ(stats.P50Us, 500ULL);
    EXPECT_EQ(stats.P95Us, 1000ULL);
    EXPECT_EQ(stats.P99Us, 1000ULL);

    // 4. Virtual display stimulus selection guardrails: refuse physical monitor when no virtual display exists.
    DisplayCandidateInfo physical{};
    physical.DeviceName = L"\\\\.\\DISPLAY1";
    physical.AdapterString = L"NVIDIA GeForce RTX 3060 Ti";
    physical.MonitorString = L"Generic PnP Monitor";
    physical.BoundsWidth = 2560U;
    physical.BoundsHeight = 1440U;
    physical.Active = true;
    physical.Primary = true;
    physical.IsIndirectWired = false;

    const auto onlyPhysical = DiscoverVirtualDisplayFromCandidates({physical});
    EXPECT_TRUE(!onlyPhysical.Identified);

    DisplayCandidateInfo virtualDisp{};
    virtualDisp.DeviceName = L"\\\\.\\DISPLAY2";
    virtualDisp.AdapterString = L"NVIDIA GeForce RTX 3060 Ti";
    virtualDisp.MonitorString = L"Generic PnP Monitor";
    virtualDisp.MonitorDeviceId = L"MONITOR\\DEFAULT_MONITOR\\{1234}";
    virtualDisp.BoundsLeft = 2560;
    virtualDisp.BoundsTop = 0;
    virtualDisp.BoundsWidth = 1920U;
    virtualDisp.BoundsHeight = 1080U;
    virtualDisp.Active = true;
    virtualDisp.Primary = false;
    virtualDisp.IsIndirectWired = true;

    const auto multiMon = DiscoverVirtualDisplayFromCandidates({physical, virtualDisp});
    EXPECT_TRUE(multiMon.Identified);
    EXPECT_TRUE(multiMon.Selected.DeviceName == L"\\\\.\\DISPLAY2");
}

void
TestRepeatedSessionsMemoryBoundedness()
{
    const std::wstring pipeName = MakeUniquePipeName(25U);
    FrameTransportConfig serverCfg;
    serverCfg.SetPipeName(pipeName.c_str());
    serverCfg.MaxQueueDepth = 3U;
    serverCfg.BufferPoolSize = 5U;

    FrameIpcServer server;
    EXPECT_EQ(server.Start(serverCfg), S_OK);

    HostConsumerConfig cCfg;
    cCfg.PipeName = pipeName;
    cCfg.VerifySyntheticPattern = true;
    FrameConsumer consumer(cCfg);

    for (uint32_t sess = 0U; sess < 8U; ++sess)
    {
        EXPECT_EQ(consumer.Connect(2000U), S_OK);
        for (uint32_t f = 1U; f <= 3U; ++f)
        {
            const uint64_t seq = static_cast<uint64_t>(sess) * 3ULL + f;
            auto slot = server.AcquireBufferSlot();
            EXPECT_TRUE(slot != nullptr);
            constexpr uint32_t kW = 1920U;
            constexpr uint32_t kH = 1080U;
            uint32_t pitch = 0U;
            uint32_t bytes = 0U;
            EXPECT_TRUE(ComputeTightRowPitchBytes(kW, pitch));
            EXPECT_TRUE(ComputeValidatedFramePayloadBytes(kW, kH, pitch, bytes));
            EXPECT_TRUE(slot->Pixels.Resize(bytes));
            EXPECT_TRUE(GenerateSyntheticTestPatternBgra8(static_cast<uint32_t>(seq), kW, kH, slot->Pixels.data(), slot->Pixels.size()));
            slot->FrameSequence = seq;
            slot->PresentationFrameNumber = static_cast<uint32_t>(seq);
            slot->Width = kW;
            slot->Height = kH;
            slot->RowPitchBytes = pitch;
            slot->Format = static_cast<uint32_t>(DXGI_FORMAT_B8G8R8A8_UNORM);
            slot->PayloadCrc32 = ComputeFrameCrc32(slot->Pixels.data(), slot->Pixels.size());

            bool evicted = false;
            EXPECT_EQ(server.EnqueueFrame(std::move(slot), evicted), S_OK);

            FrameIpcFrameHeader hdr{};
            std::vector<uint8_t> pixels;
            EXPECT_EQ(consumer.ReceiveNextFrame(hdr, pixels, 2000U), S_OK);
            EXPECT_EQ(hdr.FrameSequence, seq);
        }
        consumer.Disconnect();

        const auto sSnap = server.GetMetricsSnapshot();
        EXPECT_EQ(sSnap.TotalPoolSlots, 5U);
        EXPECT_EQ(sSnap.InFlightSlots, 0U);
        EXPECT_EQ(sSnap.QueueDepth, 0U);
    }

    const auto cSnap = consumer.GetMetricsSnapshot();
    EXPECT_EQ(cSnap.SessionsCompleted, 8ULL);
    EXPECT_EQ(cSnap.ConnectCount, 8ULL);
    EXPECT_EQ(cSnap.FramesValid, 24ULL);
    EXPECT_EQ(cSnap.ChecksumMismatches, 0ULL);
    EXPECT_TRUE(cSnap.TransportHealthy);
    server.Stop();
}

bool
CreateIpcTestD3d11Device(
    Microsoft::WRL::ComPtr<ID3D11Device>& outDev,
    Microsoft::WRL::ComPtr<ID3D11DeviceContext>& outCtx,
    LUID& outLuid
    ) noexcept
{
    outLuid = LUID{0, 0};
    static constexpr D3D_FEATURE_LEVEL kLevels[] = {
        D3D_FEATURE_LEVEL_11_1,
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_1,
        D3D_FEATURE_LEVEL_10_0};
    D3D_FEATURE_LEVEL level = D3D_FEATURE_LEVEL_11_0;
    HRESULT hr = D3D11CreateDevice(
        nullptr,
        D3D_DRIVER_TYPE_HARDWARE,
        nullptr,
        D3D11_CREATE_DEVICE_BGRA_SUPPORT,
        kLevels,
        ARRAYSIZE(kLevels),
        D3D11_SDK_VERSION,
        &outDev,
        &level,
        &outCtx);
    if (FAILED(hr) || outDev == nullptr)
    {
        hr = D3D11CreateDevice(
            nullptr,
            D3D_DRIVER_TYPE_WARP,
            nullptr,
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            kLevels,
            ARRAYSIZE(kLevels),
            D3D11_SDK_VERSION,
            &outDev,
            &level,
            &outCtx);
    }
    if (FAILED(hr) || outDev == nullptr || outCtx == nullptr)
    {
        return false;
    }

    Microsoft::WRL::ComPtr<IDXGIDevice> dxgiDev;
    Microsoft::WRL::ComPtr<IDXGIAdapter> adapter;
    if (SUCCEEDED(outDev.As(&dxgiDev)) && dxgiDev != nullptr && SUCCEEDED(dxgiDev->GetAdapter(&adapter)) && adapter != nullptr)
    {
        DXGI_ADAPTER_DESC desc{};
        if (SUCCEEDED(adapter->GetDesc(&desc)))
        {
            outLuid = desc.AdapterLuid;
        }
    }
    return true;
}

bool
CreateSyntheticIpcGpuTexture(
    ID3D11Device* device,
    uint32_t width,
    uint32_t height,
    uint32_t frameNumber,
    Microsoft::WRL::ComPtr<ID3D11Texture2D>& outTex
    )
{
    uint32_t rowPitch = 0U;
    uint32_t payloadBytes = 0U;
    if (!ComputeTightRowPitchBytes(width, rowPitch) ||
        !ComputeValidatedFramePayloadBytes(width, height, rowPitch, payloadBytes))
    {
        return false;
    }
    std::vector<uint8_t> pixels(payloadBytes, 0U);
    if (!GenerateSyntheticTestPatternBgra8(frameNumber, width, height, pixels.data(), pixels.size()))
    {
        return false;
    }
    D3D11_TEXTURE2D_DESC desc{};
    desc.Width = width;
    desc.Height = height;
    desc.MipLevels = 1U;
    desc.ArraySize = 1U;
    desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    desc.SampleDesc.Count = 1U;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
    D3D11_SUBRESOURCE_DATA init{};
    init.pSysMem = pixels.data();
    init.SysMemPitch = rowPitch;
    return SUCCEEDED(device->CreateTexture2D(&desc, &init, &outTex)) && outTex != nullptr;
}

void
TestV1_1GpuTransportCapabilityNegotiationAndFallback()
{
    // 1. Client requests Auto GPU, server has no GPU pool -> negotiates fallback to CpuStagingPipe cleanly.
    {
        const std::wstring pipeName = MakeUniquePipeName(26U);
        FrameTransportConfig serverCfg;
        serverCfg.SetPipeName(pipeName.c_str());
        serverCfg.EnableGpuSharedTransport = false;
        serverCfg.SharedTexturePool = nullptr;

        FrameIpcServer server;
        EXPECT_EQ(server.Start(serverCfg), S_OK);

        HostConsumerConfig autoCfg;
        autoCfg.PipeName = pipeName;
        autoCfg.TransportPreference = HostTransportPreference::Auto;
        autoCfg.AllowCpuFallback = true;
        autoCfg.VerifySyntheticPattern = true;
        FrameConsumer consumer(autoCfg);
        EXPECT_EQ(consumer.Connect(2000U), S_OK);
        EXPECT_EQ(consumer.GetMetricsSnapshot().NegotiatedTransportMode, FrameIpcTransportMode::CpuStagingPipe);
        EXPECT_TRUE(consumer.GetMetricsSnapshot().FallbackToCpuActivated);

        bool evicted = false;
        EXPECT_EQ(server.EnqueueFrame(MakeSyntheticExtractedFrame(1ULL, 10U, 64U, 64U), evicted), S_OK);
        FrameIpcFrameHeader hdr{};
        std::vector<uint8_t> pixels;
        EXPECT_EQ(consumer.ReceiveNextFrame(hdr, pixels, 2000U), S_OK);
        EXPECT_EQ(hdr.PresentationFrameNumber, 10U);
        consumer.Disconnect();

        // 2. Client requires GpuSharedOnly against CPU-only server -> rejected cleanly.
        HostConsumerConfig strictGpuCfg;
        strictGpuCfg.PipeName = pipeName;
        strictGpuCfg.TransportPreference = HostTransportPreference::GpuSharedOnly;
        strictGpuCfg.AllowCpuFallback = false;
        FrameConsumer strictConsumer(strictGpuCfg);
        EXPECT_EQ(strictConsumer.Connect(2000U), DXGI_ERROR_UNSUPPORTED);
        server.Stop();
    }
}

void
TestGpuSharedTextureIpcUnauthorizedClientCannotObtainHandle()
{
    static constexpr wchar_t kOtherUserSid[] = L"S-1-5-21-999999999-888888888-777777777-1002";

    Microsoft::WRL::ComPtr<ID3D11Device> dev;
    Microsoft::WRL::ComPtr<ID3D11DeviceContext> ctx;
    LUID adapterLuid{0, 0};
    EXPECT_TRUE(CreateIpcTestD3d11Device(dev, ctx, adapterLuid));

    D3d11SharedTexturePool pool;
    EXPECT_EQ(pool.Configure(3U, kOtherUserSid, true, false, false, false), S_OK);
    pool.SetDevice(dev.Get(), ctx.Get(), adapterLuid);

    const std::wstring pipeName = MakeUniquePipeName(27U);
    FrameTransportConfig serverCfg;
    serverCfg.SetPipeName(pipeName.c_str());
    serverCfg.SetAuthorizedUserSid(kOtherUserSid);
    serverCfg.RestrictDaclToAuthorizedSid = true;
    serverCfg.AllowSameUserAccess = false;
    serverCfg.AllowBuiltinAdmins = false;
    serverCfg.AdapterLuid = adapterLuid;
    serverCfg.EnableGpuSharedTransport = true;
    serverCfg.SharedTexturePoolSize = 3U;
    serverCfg.SharedTexturePool = &pool;

    FrameIpcServer server;
    EXPECT_EQ(server.Start(serverCfg), S_OK);

    HostConsumerConfig unauthCfg;
    unauthCfg.PipeName = pipeName;
    unauthCfg.TransportPreference = HostTransportPreference::GpuSharedOnly;
    unauthCfg.AllowCpuFallback = false;
    FrameConsumer unauthConsumer(unauthCfg);
    EXPECT_EQ(unauthConsumer.Connect(2000U), E_ACCESSDENIED);
    EXPECT_EQ(server.GetMetricsSnapshot().GpuFramesShared, 0ULL);
    EXPECT_EQ(server.GetMetricsSnapshot().ClientConnectionsAccepted, 0ULL);

    server.Stop();
    pool.Shutdown();
}

void
TestGpuSharedTextureDelayedAckAndMidUseClientDisconnectRecovery()
{
    Microsoft::WRL::ComPtr<ID3D11Device> dev;
    Microsoft::WRL::ComPtr<ID3D11DeviceContext> ctx;
    LUID adapterLuid{0, 0};
    EXPECT_TRUE(CreateIpcTestD3d11Device(dev, ctx, adapterLuid));

    D3d11SharedTexturePool pool;
    EXPECT_EQ(pool.Configure(3U), S_OK);
    pool.SetDevice(dev.Get(), ctx.Get(), adapterLuid);

    const std::wstring pipeName = MakeUniquePipeName(28U);
    FrameTransportConfig serverCfg;
    serverCfg.SetPipeName(pipeName.c_str());
    serverCfg.AdapterLuid = adapterLuid;
    serverCfg.EnableGpuSharedTransport = true;
    serverCfg.SharedTexturePoolSize = 3U;
    serverCfg.SharedTexturePool = &pool;
    serverCfg.IoTimeoutMs = 150U;

    FrameIpcServer server;
    EXPECT_EQ(server.Start(serverCfg), S_OK);

    // 1. Client disconnects while holding KeyedMutex -> server retires slot and recreates cleanly for next client.
    {
        HostConsumerConfig abortCfg;
        abortCfg.PipeName = pipeName;
        abortCfg.TransportPreference = HostTransportPreference::GpuSharedOnly;
        abortCfg.AllowCpuFallback = false;
        abortCfg.SimulateDisconnectWhileHoldingMutexForTesting = true;
        FrameConsumer abortConsumer(abortCfg);
        EXPECT_EQ(abortConsumer.Connect(2000U), S_OK);

        Microsoft::WRL::ComPtr<ID3D11Texture2D> src;
        EXPECT_TRUE(CreateSyntheticIpcGpuTexture(dev.Get(), 64U, 64U, 1U, src));
        auto slot = server.AcquireBufferSlot();
        EXPECT_TRUE(slot != nullptr);
        FrameExtractionInput in{};
        in.AdoptSourceTexture = src.Detach();
        in.PresentationFrameNumber = 1U;
        const auto ext = pool.ExtractToSharedTexture(in, *slot, true);
        EXPECT_EQ(ext.HResult, S_OK);
        bool evicted = false;
        EXPECT_EQ(server.EnqueueFrame(std::move(slot), evicted), S_OK);

        bool isGpu = false;
        FrameIpcGpuFrameHeader gpuHdr{};
        FrameIpcFrameHeader cpuHdr{};
        std::vector<uint8_t> pixels;
        EXPECT_EQ(abortConsumer.ReceiveNextGpuOrCpuFrame(isGpu, gpuHdr, cpuHdr, pixels, 2000U), HRESULT_FROM_WIN32(ERROR_CONNECTION_ABORTED));
    }

    Sleep(60U);

    // 2. Subsequent healthy client connects, delays ACK briefly (below timeout), verifies visual pattern, and succeeds.
    {
        HostConsumerConfig okCfg;
        okCfg.PipeName = pipeName;
        okCfg.TransportPreference = HostTransportPreference::GpuSharedOnly;
        okCfg.AllowCpuFallback = false;
        okCfg.VerifySyntheticPattern = true;
        okCfg.SimulatedAckDelayMsForTesting = 40U;
        FrameConsumer okConsumer(okCfg);
        EXPECT_EQ(okConsumer.Connect(2000U), S_OK);

        Microsoft::WRL::ComPtr<ID3D11Texture2D> src2;
        EXPECT_TRUE(CreateSyntheticIpcGpuTexture(dev.Get(), 128U, 128U, 22U, src2));
        auto slot2 = server.AcquireBufferSlot();
        EXPECT_TRUE(slot2 != nullptr);
        FrameExtractionInput in2{};
        in2.AdoptSourceTexture = src2.Detach();
        in2.PresentationFrameNumber = 22U;
        const auto ext2 = pool.ExtractToSharedTexture(in2, *slot2, true);
        EXPECT_EQ(ext2.HResult, S_OK);
        bool evicted = false;
        EXPECT_EQ(server.EnqueueFrame(std::move(slot2), evicted), S_OK);

        bool isGpu = false;
        FrameIpcGpuFrameHeader gpuHdr{};
        FrameIpcFrameHeader cpuHdr{};
        std::vector<uint8_t> pixels;
        EXPECT_EQ(okConsumer.ReceiveNextGpuOrCpuFrame(isGpu, gpuHdr, cpuHdr, pixels, 2000U), S_OK);
        EXPECT_TRUE(isGpu);
        EXPECT_EQ(okConsumer.GetMetricsSnapshot().FramesValid, 1ULL);
        EXPECT_EQ(okConsumer.GetMetricsSnapshot().SyntheticPatternMismatches, 0ULL);
        okConsumer.Disconnect();
    }

    server.Stop();
    pool.Shutdown();
}

void
TestGpuSharedTextureIncompatibleAdapterAndInvalidHandleAckHandling()
{
    Microsoft::WRL::ComPtr<ID3D11Device> dev;
    Microsoft::WRL::ComPtr<ID3D11DeviceContext> ctx;
    LUID adapterLuid{0, 0};
    EXPECT_TRUE(CreateIpcTestD3d11Device(dev, ctx, adapterLuid));

    D3d11SharedTexturePool pool;
    EXPECT_EQ(pool.Configure(3U), S_OK);
    pool.SetDevice(dev.Get(), ctx.Get(), adapterLuid);

    const std::wstring pipeName = MakeUniquePipeName(29U);
    FrameTransportConfig serverCfg;
    serverCfg.SetPipeName(pipeName.c_str());
    serverCfg.AdapterLuid = adapterLuid;
    serverCfg.EnableGpuSharedTransport = true;
    serverCfg.SharedTexturePoolSize = 3U;
    serverCfg.SharedTexturePool = &pool;

    FrameIpcServer server;
    EXPECT_EQ(server.Start(serverCfg), S_OK);

    // Client simulates invalid handle rejection on frame 1 -> sends ResourceOpenFailed ACK, disconnects cleanly.
    HostConsumerConfig badHandleCfg;
    badHandleCfg.PipeName = pipeName;
    badHandleCfg.TransportPreference = HostTransportPreference::GpuSharedOnly;
    badHandleCfg.AllowCpuFallback = false;
    badHandleCfg.SimulateInvalidSharedHandleForTesting = true;
    FrameConsumer badHandleConsumer(badHandleCfg);
    EXPECT_EQ(badHandleConsumer.Connect(2000U), S_OK);

    Microsoft::WRL::ComPtr<ID3D11Texture2D> src;
    EXPECT_TRUE(CreateSyntheticIpcGpuTexture(dev.Get(), 64U, 64U, 5U, src));
    auto slot = server.AcquireBufferSlot();
    EXPECT_TRUE(slot != nullptr);
    FrameExtractionInput in{};
    in.AdoptSourceTexture = src.Detach();
    in.PresentationFrameNumber = 5U;
    EXPECT_EQ(pool.ExtractToSharedTexture(in, *slot, true).HResult, S_OK);
    bool evicted = false;
    EXPECT_EQ(server.EnqueueFrame(std::move(slot), evicted), S_OK);

    bool isGpu = false;
    FrameIpcGpuFrameHeader gpuHdr{};
    FrameIpcFrameHeader cpuHdr{};
    std::vector<uint8_t> pixels;
    EXPECT_EQ(badHandleConsumer.ReceiveNextGpuOrCpuFrame(isGpu, gpuHdr, cpuHdr, pixels, 2000U), E_HANDLE);
    EXPECT_EQ(badHandleConsumer.GetMetricsSnapshot().GpuSharedOpenFailures, 1ULL);
    EXPECT_EQ(badHandleConsumer.GetMetricsSnapshot().LastProtocolStatus, FrameIpcStatus::ResourceOpenFailed);

    Sleep(40U);
    const auto poolSnap = pool.GetMetricsSnapshot();
    EXPECT_EQ(poolSnap.FreeSlots, 3U);
    EXPECT_EQ(poolSnap.GpuFramesDropped, 1ULL);

    server.Stop();
    pool.Shutdown();
}

void
TestM421TimestampValidationAndRegressionScenarios()
{
    constexpr uint64_t kFreq = 10000000ULL;

    // 1. Unit tests for unavailable metrics, optional PresentDisplayQpcTime, core missing, future, and unit mismatch.
    {
        const LatencySummaryStats emptyStats = ComputeLatencySummary({}, 0ULL);
        EXPECT_TRUE(!emptyStats.Available);
        EXPECT_EQ(emptyStats.SampleCount, 0ULL);
        EXPECT_EQ(emptyStats.AvgUs, 0ULL);

        FrameIpcFrameHeader hdr{};
        hdr.Envelope = InitEnvelope(FrameIpcMessageType::FrameHeader, sizeof(hdr));
        hdr.QpcFrequency = kFreq;
        hdr.PresentDisplayQpcTime = 0ULL; // optional
        hdr.ExtractCompleteQpcTime = 2000ULL;
        hdr.ServerSendQpcTime = 3000ULL;
        hdr.Flags = PackFrameFlags(0U, 500ULL);
        const ValidatedFrameIntervals missingPresent = ComputeValidatedFrameIntervals(hdr, 4000ULL, 5000ULL, kFreq, true);
        EXPECT_TRUE(missingPresent.Valid);
        EXPECT_TRUE(missingPresent.CoreTimestampsValid);
        EXPECT_TRUE(!missingPresent.MissingCoreTimestamp);
        EXPECT_TRUE(missingPresent.PresentTimestampMissing);
        EXPECT_TRUE(!missingPresent.PresentTimestampAvailable);
        EXPECT_TRUE(!missingPresent.HasPresentToExtract);
        EXPECT_TRUE(!missingPresent.FutureTimestampDetected);
        EXPECT_TRUE(!missingPresent.IncompatibleTimestampUnits);
        EXPECT_EQ(missingPresent.QueueWaitUs, 100ULL);
        EXPECT_EQ(missingPresent.IpcTransitUs, 100ULL);
        EXPECT_EQ(missingPresent.HostVerifyAckUs, 100ULL);
        EXPECT_EQ(missingPresent.EndToEndUs, 200ULL);

        // Missing core timestamp (ExtractCompleteQpcTime == 0).
        hdr.ExtractCompleteQpcTime = 0ULL;
        const ValidatedFrameIntervals missingCore = ComputeValidatedFrameIntervals(hdr, 4000ULL, 5000ULL, kFreq, true);
        EXPECT_TRUE(!missingCore.Valid);
        EXPECT_TRUE(!missingCore.CoreTimestampsValid);
        EXPECT_TRUE(missingCore.MissingCoreTimestamp);

        // Future PresentDisplayQpcTime > ExtractCompleteQpcTime (simulating raw future IddCx VSync target).
        hdr.PresentDisplayQpcTime = 3500ULL;
        hdr.ExtractCompleteQpcTime = 2000ULL;
        hdr.ServerSendQpcTime = 3000ULL;
        const ValidatedFrameIntervals futurePresent = ComputeValidatedFrameIntervals(hdr, 4000ULL, 5000ULL, kFreq, true);
        EXPECT_TRUE(!futurePresent.Valid);
        EXPECT_TRUE(futurePresent.FutureTimestampDetected);
        EXPECT_TRUE(futurePresent.OutOfOrderTimestamps);

        // Future ServerSendQpcTime > recvPayloadQpc.
        hdr.PresentDisplayQpcTime = 1500ULL;
        hdr.ExtractCompleteQpcTime = 2000ULL;
        hdr.ServerSendQpcTime = 4500ULL;
        const ValidatedFrameIntervals futureCore = ComputeValidatedFrameIntervals(hdr, 4000ULL, 5000ULL, kFreq, true);
        EXPECT_TRUE(!futureCore.Valid);
        EXPECT_TRUE(futureCore.FutureTimestampDetected);
        EXPECT_TRUE(futureCore.OutOfOrderTimestamps);

        // Incompatible timestamp units (> 30s delta between extract and server send).
        hdr.PresentDisplayQpcTime = 1500ULL;
        hdr.ExtractCompleteQpcTime = 2000ULL;
        hdr.ServerSendQpcTime = 2000ULL + kFreq * 35ULL;
        const ValidatedFrameIntervals hugeDelta = ComputeValidatedFrameIntervals(hdr, hdr.ServerSendQpcTime + 1000ULL, hdr.ServerSendQpcTime + 2000ULL, kFreq, true);
        EXPECT_TRUE(!hugeDelta.Valid);
        EXPECT_TRUE(hugeDelta.IncompatibleTimestampUnits);

        // Incompatible QpcFrequency.
        hdr.ServerSendQpcTime = 3000ULL;
        hdr.QpcFrequency = kFreq + 12345ULL;
        const ValidatedFrameIntervals freqMismatch = ComputeValidatedFrameIntervals(hdr, 4000ULL, 5000ULL, kFreq, true);
        EXPECT_TRUE(!freqMismatch.Valid);
        EXPECT_TRUE(freqMismatch.QpcFrequencyMismatch);
        EXPECT_TRUE(freqMismatch.IncompatibleTimestampUnits);
    }

    // 2. Live over-pipe regression: Send 7 valid-CRC frames covering missing optional Present, valid causal,
    //    backwards non-monotonic, future Present, missing core Extract, >30s unit mismatch, and QPC freq mismatch.
    {
        const std::wstring pipeName = MakeUniquePipeName(90U);
        HANDLE serverPipe = CreateNamedPipeW(
            pipeName.c_str(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1U,
            65536U,
            65536U,
            0U,
            nullptr);
        EXPECT_TRUE(serverPipe != INVALID_HANDLE_VALUE);

        std::thread rawServer([&]() {
            ConnectNamedPipe(serverPipe, nullptr);
            FrameIpcClientHello cHello{};
            ReadAllSync(serverPipe, &cHello, sizeof(cHello));

            LARGE_INTEGER freqLi{};
            LARGE_INTEGER nowLi{};
            QueryPerformanceFrequency(&freqLi);
            QueryPerformanceCounter(&nowLi);
            const uint64_t freq = (freqLi.QuadPart > 0) ? static_cast<uint64_t>(freqLi.QuadPart) : kFreq;
            const uint64_t nowQpc = static_cast<uint64_t>(nowLi.QuadPart);
            // Anchor 50 ms in the past so live consumer recvQpc >= ServerSendQpcTime and < 30s.
            const uint64_t anchorQpc = (nowQpc > (freq / 20ULL)) ? (nowQpc - (freq / 20ULL)) : nowQpc;

            FrameIpcServerHello sHello{};
            sHello.Envelope = InitEnvelope(FrameIpcMessageType::ServerHello, sizeof(sHello));
            sHello.Status = static_cast<uint32_t>(FrameIpcStatus::Ok);
            sHello.ServerProcessId = GetCurrentProcessId();
            sHello.SessionId = 777ULL;
            sHello.MaxQueueDepth = 3U;
            WriteAllSync(serverPipe, &sHello, sizeof(sHello));

            std::vector<uint8_t> pixels(64U * 64U * 4U, 0x42U);
            const uint32_t crc = ComputeFrameCrc32(pixels.data(), pixels.size());

            struct FrameTsCase
            {
                uint64_t Present;
                uint64_t Extract;
                uint64_t Send;
                uint64_t Freq;
            };
            const FrameTsCase cases[7] = {
                // 1: Missing optional PresentDisplayQpcTime, valid core timestamps
                {0ULL, anchorQpc + 2000ULL, anchorQpc + 3000ULL, freq},
                // 2: Valid monotonic causal Present <= Extract <= Send
                {anchorQpc + 3200ULL, anchorQpc + 4000ULL, anchorQpc + 5000ULL, freq},
                // 3: Non-monotonic backwards Extract/Send (< Frame 2)
                {anchorQpc + 1000ULL, anchorQpc + 1500ULL, anchorQpc + 2500ULL, freq},
                // 4: Future Present > Extract
                {anchorQpc + 9000ULL, anchorQpc + 6000ULL, anchorQpc + 7000ULL, freq},
                // 5: Missing core Extract == 0
                {0ULL, 0ULL, anchorQpc + 8000ULL, freq},
                // 6: Incompatible units (> 30s old Extract)
                {0ULL, (anchorQpc > freq * 45ULL) ? (anchorQpc - freq * 45ULL) : 1ULL, anchorQpc + 8500ULL, freq},
                // 7: QPC frequency mismatch
                {anchorQpc + 8800ULL, anchorQpc + 9000ULL, anchorQpc + 9500ULL, freq + 12345ULL},
            };

            for (uint32_t i = 0U; i < 7U; ++i)
            {
                FrameIpcFrameHeader hdr{};
                hdr.Envelope = InitEnvelope(FrameIpcMessageType::FrameHeader, sizeof(hdr));
                hdr.SessionId = 777ULL;
                hdr.FrameSequence = static_cast<uint64_t>(i) + 1ULL;
                hdr.PresentationFrameNumber = i + 1U;
                hdr.Width = 64U;
                hdr.Height = 64U;
                hdr.RowPitchBytes = 256U;
                hdr.PixelFormat = static_cast<uint32_t>(DXGI_FORMAT_B8G8R8A8_UNORM);
                hdr.PayloadSizeBytes = static_cast<uint32_t>(pixels.size());
                hdr.PayloadCrc32 = crc;
                hdr.QpcFrequency = cases[i].Freq;
                hdr.PresentDisplayQpcTime = cases[i].Present;
                hdr.ExtractCompleteQpcTime = cases[i].Extract;
                hdr.ServerSendQpcTime = cases[i].Send;
                hdr.Flags = PackFrameFlags(0U, 200ULL);
                WriteAllSync(serverPipe, &hdr, sizeof(hdr));
                WriteAllSync(serverPipe, pixels.data(), pixels.size());

                FrameIpcFrameAck ack{};
                ReadAllSync(serverPipe, &ack, sizeof(ack));
            }
            Sleep(30U);
            CloseHandle(serverPipe);
        });

        HostConsumerConfig cfg;
        cfg.PipeName = pipeName;
        cfg.MaxFrames = 7ULL;
        cfg.IoTimeoutMs = 500U;
        cfg.ConnectTimeoutMs = 2000U;
        FrameConsumer consumer(cfg);
        const HRESULT runHr = consumer.RunLoop();
        rawServer.join();

        EXPECT_EQ(runHr, S_OK);
        const auto snap = consumer.GetMetricsSnapshot();
        EXPECT_EQ(snap.FramesReceived, 7ULL);
        EXPECT_EQ(snap.FramesValid, 7ULL);
        EXPECT_EQ(snap.ProtocolErrors, 0ULL);
        EXPECT_EQ(snap.ChecksumMismatches, 0ULL);
        EXPECT_EQ(snap.MissingPresentTimestampCount, 1ULL); // frame 1 (valid core, missing optional present)
        EXPECT_EQ(snap.MissingCoreTimestampCount, 1ULL);    // frame 5
        EXPECT_EQ(snap.FutureTimestampErrorCount, 1ULL);    // frame 4
        EXPECT_EQ(snap.NonMonotonicTimestampCount, 1ULL);   // frame 3
        EXPECT_EQ(snap.IncompatibleTimestampUnitsCount, 2ULL); // frames 6 & 7
        EXPECT_EQ(snap.QpcFrequencyMismatchCount, 1ULL);    // frame 7
        EXPECT_EQ(snap.TimestampMeasurementErrors, 5ULL);   // frames 3..7
        EXPECT_EQ(snap.ValidPresentTimestampSamples, 1ULL); // frame 2 only
        EXPECT_EQ(snap.ValidCoreTimestampSamples, 2ULL);    // frames 1 & 2
        EXPECT_TRUE(snap.CoreTimestampCoveragePercent > 20.0 && snap.CoreTimestampCoveragePercent < 50.0);
        EXPECT_TRUE(snap.PresentTimestampCoveragePercent > 10.0 && snap.PresentTimestampCoveragePercent < 20.0);
        EXPECT_TRUE(snap.PresentToExtractLatency.Available);
        EXPECT_TRUE(snap.EndToEndLatency.Available);
        EXPECT_TRUE(snap.LiveEndToEndLatency.Available);
    }
}

void
TestReservoirLatencySamplingForLongRuns()
{
    lumabridge::host::ReservoirLatencyAccumulator exactAcc;
    for (uint64_t i = 1ULL; i <= 100U; ++i)
    {
        exactAcc.Record(i * 10ULL);
    }
    const auto exactSnap = exactAcc.Summarize();
    EXPECT_TRUE(exactSnap.Available);
    EXPECT_EQ(exactSnap.SampleCount, 100ULL);
    EXPECT_EQ(exactSnap.StoredSampleCount, 100ULL);
    EXPECT_TRUE(!exactSnap.SamplesTruncated);
    EXPECT_TRUE(!exactSnap.ReservoirSampled);
    EXPECT_EQ(exactSnap.MinUs, 10ULL);
    EXPECT_EQ(exactSnap.MaxUs, 1000ULL);
    EXPECT_EQ(exactSnap.AvgUs, 505ULL);
    EXPECT_EQ(exactSnap.P50Us, 500ULL);
    EXPECT_EQ(exactSnap.P95Us, 950ULL);
    EXPECT_EQ(exactSnap.P99Us, 990ULL);

    // Simulate a 3600s 60FPS run (216,000 samples > 65,536 storage cap):
    // Algorithm R keeps full-run distribution representative instead of silently frozen at minute 18.
    lumabridge::host::ReservoirLatencyAccumulator longAcc;
    for (uint64_t i = 0ULL; i < 216000ULL; ++i)
    {
        const uint64_t val = (i < 65536ULL) ? 100ULL : 10000ULL;
        longAcc.Record(val);
    }
    const auto longSnap = longAcc.Summarize();
    EXPECT_TRUE(longSnap.Available);
    EXPECT_EQ(longSnap.SampleCount, 216000ULL);
    EXPECT_EQ(longSnap.StoredSampleCount, lumabridge::host::ReservoirLatencyAccumulator::kDefaultMaxStoredSamples);
    EXPECT_TRUE(longSnap.SamplesTruncated);
    EXPECT_TRUE(longSnap.ReservoirSampled);
    EXPECT_EQ(longSnap.MinUs, 100ULL);
    EXPECT_EQ(longSnap.MaxUs, 10000ULL);
    // True proportion of 10000us values is ~69.7%, so P50 and P95 must reflect 10000us (old truncated vector had P95=100!).
    EXPECT_EQ(longSnap.P50Us, 10000ULL);
    EXPECT_EQ(longSnap.P95Us, 10000ULL);
    EXPECT_EQ(longSnap.P99Us, 10000ULL);
}

void
TestPercentileMethodologyBoundariesAndReservoirEstimate()
{
    // 0 samples: PercentilesAvailable=false, PercentileMethod=NotAvailable.
    {
        lumabridge::host::ReservoirLatencyAccumulator acc0;
        const auto s0 = acc0.Summarize();
        EXPECT_TRUE(!s0.Available);
        EXPECT_TRUE(!s0.PercentilesAvailable);
        EXPECT_TRUE(!s0.PercentilesAreEstimated);
        EXPECT_EQ(s0.PercentileMethod, lumabridge::host::LatencyPercentileMethod::NotAvailable);
        EXPECT_EQ(s0.SampleCount, 0ULL);
        EXPECT_EQ(s0.StoredSampleCount, 0ULL);
        EXPECT_TRUE(!s0.SamplesTruncated);
        EXPECT_TRUE(!s0.ReservoirSampled);
        EXPECT_EQ(s0.P50Us, 0ULL);
        EXPECT_EQ(s0.P95Us, 0ULL);
        EXPECT_EQ(s0.P99Us, 0ULL);

        const auto emptyVec = lumabridge::host::ComputeLatencySummary({}, 77ULL);
        EXPECT_TRUE(!emptyVec.Available);
        EXPECT_TRUE(!emptyVec.PercentilesAvailable);
        EXPECT_EQ(emptyVec.PercentileMethod, lumabridge::host::LatencyPercentileMethod::NotAvailable);
        EXPECT_EQ(emptyVec.LastUs, 77ULL);
    }

    // 1 sample -> ExactPopulation.
    {
        lumabridge::host::ReservoirLatencyAccumulator acc1;
        acc1.Record(1234ULL);
        const auto s1 = acc1.Summarize();
        EXPECT_TRUE(s1.Available);
        EXPECT_TRUE(s1.PercentilesAvailable);
        EXPECT_TRUE(!s1.PercentilesAreEstimated);
        EXPECT_EQ(s1.PercentileMethod, lumabridge::host::LatencyPercentileMethod::ExactPopulation);
        EXPECT_EQ(s1.SampleCount, 1ULL);
        EXPECT_EQ(s1.StoredSampleCount, 1ULL);
        EXPECT_TRUE(!s1.SamplesTruncated);
        EXPECT_TRUE(!s1.ReservoirSampled);
        EXPECT_EQ(s1.MinUs, 1234ULL);
        EXPECT_EQ(s1.AvgUs, 1234ULL);
        EXPECT_EQ(s1.MaxUs, 1234ULL);
        EXPECT_EQ(s1.P50Us, 1234ULL);
        EXPECT_EQ(s1.P95Us, 1234ULL);
        EXPECT_EQ(s1.P99Us, 1234ULL);
        EXPECT_EQ(s1.LastUs, 1234ULL);
    }

    // Exact boundary sizes: 1800 (30s@60fps), 10800 (180s@60fps), and 65536 (reservoir cap).
    for (uint64_t count : {1800ULL, 10800ULL, 65536ULL})
    {
        lumabridge::host::ReservoirLatencyAccumulator acc;
        for (uint64_t i = 1ULL; i <= count; ++i)
        {
            acc.Record(i);
        }
        const auto s = acc.Summarize();
        EXPECT_TRUE(s.Available);
        EXPECT_TRUE(s.PercentilesAvailable);
        EXPECT_TRUE(!s.PercentilesAreEstimated);
        EXPECT_EQ(s.PercentileMethod, lumabridge::host::LatencyPercentileMethod::ExactPopulation);
        EXPECT_EQ(s.SampleCount, count);
        EXPECT_EQ(s.StoredSampleCount, count);
        EXPECT_TRUE(!s.SamplesTruncated);
        EXPECT_TRUE(!s.ReservoirSampled);
        EXPECT_EQ(s.MinUs, 1ULL);
        EXPECT_EQ(s.MaxUs, count);
    }

    // Boundary + 1 (65537) and 216000 (1h@60fps): Algorithm R estimated percentiles while preserving exact Min/Avg/Max.
    for (uint64_t count : {65537ULL, 216000ULL})
    {
        lumabridge::host::ReservoirLatencyAccumulator acc;
        uint64_t exactSum = 0ULL;
        for (uint64_t i = 0ULL; i < count; ++i)
        {
            const uint64_t v = (i == 0ULL) ? 5ULL : ((i == count - 1ULL) ? 900ULL : 100ULL);
            exactSum += v;
            acc.Record(v);
        }
        const auto s = acc.Summarize();
        EXPECT_TRUE(s.Available);
        EXPECT_TRUE(s.PercentilesAvailable);
        EXPECT_TRUE(s.PercentilesAreEstimated);
        EXPECT_EQ(
            s.PercentileMethod,
            lumabridge::host::LatencyPercentileMethod::ReservoirSampledEstimate_AlgorithmR);
        EXPECT_EQ(s.SampleCount, count);
        EXPECT_EQ(s.StoredSampleCount, lumabridge::host::ReservoirLatencyAccumulator::kDefaultMaxStoredSamples);
        EXPECT_TRUE(s.SamplesTruncated);
        EXPECT_TRUE(s.ReservoirSampled);
        EXPECT_EQ(s.MinUs, 5ULL);
        EXPECT_EQ(s.MaxUs, 900ULL);
        EXPECT_EQ(s.AvgUs, exactSum / count);
        EXPECT_EQ(s.LastUs, 900ULL);
    }
}

void
TestConnectedDurationClockSafetyAndBoundaries()
{
    // 1. Overflow-safe QPC ticks -> us conversion + floor rounding + 128-bit remainder path.
    EXPECT_EQ(lumabridge::host::ComputeQpcTicksToUsSafe(0ULL, 10000000ULL), 0ULL);
    EXPECT_EQ(lumabridge::host::ComputeQpcTicksToUsSafe(1000ULL, 0ULL), 0ULL);
    EXPECT_EQ(lumabridge::host::ComputeQpcTicksToUsSafe(3ULL, 2000000ULL), 1ULL);
    EXPECT_EQ(lumabridge::host::ComputeQpcTicksToUsSafe(1999999ULL, 2000000ULL), 999999ULL);
    // Would overflow uint64_t if computed as (ticks * 1,000,000ULL) / qpcFreq:
    EXPECT_EQ(
        lumabridge::host::ComputeQpcTicksToUsSafe(30000000000000ULL, 1000000000ULL),
        30000000000ULL);
    // 128-bit fractional path when qpcFreq > UINT64_MAX / 1,000,000:
    EXPECT_EQ(
        lumabridge::host::ComputeQpcTicksToUsSafe(50000000000000ULL, 100000000000000ULL),
        500000ULL);
    EXPECT_EQ(
        lumabridge::host::ComputeQpcTicksToUsSafe((std::numeric_limits<uint64_t>::max)(), 1ULL),
        (std::numeric_limits<uint64_t>::max)());

    // 2. Invalid QPC frequency (=0) fails closed without synthesizing 10MHz.
    {
        HostConsumerConfig cfg;
        cfg.PipeName = MakeUniquePipeName(901U);
        cfg.HasForcedQpcFrequencyForTesting = true;
        cfg.ForcedQpcFrequencyForTesting = 0ULL;
        cfg.DurationCountsConnected = true;
        cfg.MaxDurationMs = 100U;
        FrameConsumer consumer(cfg);
        EXPECT_TRUE(FAILED(consumer.RunLoop()));
        const auto snap = consumer.GetMetricsSnapshot();
        EXPECT_TRUE(!snap.QpcClockValid);
        EXPECT_EQ(snap.QpcFrequency, 0ULL);
        EXPECT_EQ(snap.ExitReason, HostExitReason::InvalidQpcClock);
        EXPECT_TRUE(!snap.HostProcessExitedNormally);
        EXPECT_TRUE(!snap.TransportHealthy);
    }

    // 3. Delayed server start: pre-connect delay (~220ms) is excluded from connected duration (250ms target).
    {
        const std::wstring pipeName = MakeUniquePipeName(902U);
        std::atomic<bool> stopProducer{false};
        std::thread delayedServer([&pipeName, &stopProducer]() {
            Sleep(220U);
            FrameTransportConfig serverCfg;
            serverCfg.SetPipeName(pipeName.c_str());
            FrameIpcServer server;
            if (SUCCEEDED(server.Start(serverCfg)))
            {
                for (uint64_t seq = 1ULL; !stopProducer.load() && seq <= 60ULL; ++seq)
                {
                    bool evicted = false;
                    (void)server.EnqueueFrame(
                        MakeSyntheticExtractedFrame(seq, static_cast<uint32_t>(seq), 64U, 64U),
                        evicted);
                    Sleep(15U);
                }
                server.Stop();
            }
        });

        HostConsumerConfig cfg;
        cfg.PipeName = pipeName;
        cfg.IoTimeoutMs = 40U;
        cfg.ConnectTimeoutMs = 2000U;
        cfg.MaxDurationMs = 250U;
        cfg.DurationCountsConnected = true;
        cfg.MaxExecutionDurationMs = 4000U;
        cfg.VerifySyntheticPattern = true;
        FrameConsumer consumer(cfg);
        const HRESULT hr = consumer.RunLoop();
        stopProducer.store(true);
        delayedServer.join();

        EXPECT_EQ(hr, S_OK);
        const auto snap = consumer.GetMetricsSnapshot();
        EXPECT_TRUE(snap.QpcClockValid);
        EXPECT_TRUE(snap.DurationCountsConnected);
        EXPECT_EQ(snap.RequestedDurationUs, 250000ULL);
        EXPECT_TRUE(snap.TotalConnectedDurationUs >= 250000ULL);
        EXPECT_TRUE(snap.TotalExecutionDurationUs >= snap.TotalConnectedDurationUs + 150000ULL);
        EXPECT_TRUE(snap.DurationTargetReached);
        EXPECT_TRUE(!snap.SafetyExecutionTimeoutHit);
        EXPECT_EQ(snap.ExitReason, HostExitReason::DurationElapsed);
        EXPECT_TRUE(snap.FramesValid >= 5ULL);
        EXPECT_TRUE(snap.ActiveStreamingDurationUs > 0ULL);
    }

    // 4. Reconnect pause: disconnect gap (~220ms) does not advance connected duration (320ms target).
    {
        const std::wstring pipeName = MakeUniquePipeName(903U);
        std::atomic<bool> stopProducer{false};
        std::atomic<uint64_t> framesReceivedTotal{0ULL};
        std::thread reconnectServer([&pipeName, &stopProducer, &framesReceivedTotal]() {
            FrameTransportConfig serverCfg;
            serverCfg.SetPipeName(pipeName.c_str());
            {
                FrameIpcServer server1;
                if (SUCCEEDED(server1.Start(serverCfg)))
                {
                    for (uint64_t seq = 1ULL; seq <= 100ULL; ++seq)
                    {
                        bool evicted = false;
                        (void)server1.EnqueueFrame(
                            MakeSyntheticExtractedFrame(seq, static_cast<uint32_t>(seq), 64U, 64U),
                            evicted);
                        Sleep(15U);
                        if (framesReceivedTotal.load() >= 3ULL)
                        {
                            break;
                        }
                    }
                    server1.Stop();
                }
            }
            Sleep(220U);
            {
                FrameIpcServer server2;
                if (SUCCEEDED(server2.Start(serverCfg)))
                {
                    for (uint64_t seq = 1ULL; !stopProducer.load() && seq <= 120ULL; ++seq)
                    {
                        bool evicted = false;
                        (void)server2.EnqueueFrame(
                            MakeSyntheticExtractedFrame(seq, static_cast<uint32_t>(seq), 64U, 64U),
                            evicted);
                        Sleep(15U);
                    }
                    server2.Stop();
                }
            }
        });

        HostConsumerConfig cfg;
        cfg.PipeName = pipeName;
        cfg.AutoReconnect = true;
        cfg.TransportPreference = HostTransportPreference::CpuStagingOnly;
        cfg.IoTimeoutMs = 40U;
        cfg.ConnectTimeoutMs = 1500U;
        cfg.MaxDurationMs = 320U;
        cfg.DurationCountsConnected = true;
        cfg.MaxExecutionDurationMs = 5000U;
        FrameConsumer consumer(cfg);
        const HRESULT hr = consumer.RunLoop(
            nullptr,
            [&framesReceivedTotal](const FrameIpcFrameHeader&, const std::vector<uint8_t>&) {
                framesReceivedTotal.fetch_add(1ULL);
            });
        stopProducer.store(true);
        reconnectServer.join();

        EXPECT_EQ(hr, S_OK);
        const auto snap = consumer.GetMetricsSnapshot();
        EXPECT_TRUE(snap.ReconnectCount >= 1ULL);
        EXPECT_TRUE(snap.DurationTargetReached);
        EXPECT_TRUE(snap.TotalConnectedDurationUs >= 320000ULL);
        EXPECT_TRUE(snap.TotalExecutionDurationUs >= snap.TotalConnectedDurationUs + 150000ULL);
        EXPECT_EQ(snap.ExitReason, HostExitReason::DurationElapsed);
    }

    // 5. Idle connected pipe tracks ActiveStreamingDurationUs == 0 and FramesValid == 0.
    {
        const std::wstring pipeName = MakeUniquePipeName(904U);
        FrameTransportConfig serverCfg;
        serverCfg.SetPipeName(pipeName.c_str());
        FrameIpcServer server;
        EXPECT_EQ(server.Start(serverCfg), S_OK);

        HostConsumerConfig cfg;
        cfg.PipeName = pipeName;
        cfg.TransportPreference = HostTransportPreference::CpuStagingOnly;
        cfg.IoTimeoutMs = 40U;
        cfg.MaxDurationMs = 150U;
        cfg.DurationCountsConnected = true;
        FrameConsumer consumer(cfg);
        EXPECT_EQ(consumer.RunLoop(), S_OK);
        const auto snap = consumer.GetMetricsSnapshot();
        EXPECT_EQ(snap.ExitReason, HostExitReason::DurationElapsed);
        EXPECT_TRUE(snap.TotalConnectedDurationUs >= 150000ULL);
        EXPECT_EQ(snap.FramesValid, 0ULL);
        EXPECT_EQ(snap.ActiveStreamingDurationUs, 0ULL);
        server.Stop();
    }

    // 6. Early peer disconnect with !AutoReconnect leaves DurationTargetReached == false.
    {
        const std::wstring pipeName = MakeUniquePipeName(905U);
        FrameTransportConfig serverCfg;
        serverCfg.SetPipeName(pipeName.c_str());
        FrameIpcServer server;
        EXPECT_EQ(server.Start(serverCfg), S_OK);
        std::atomic<uint64_t> framesSeen{0ULL};
        std::thread stopper([&server, &framesSeen]() {
            for (uint64_t seq = 1ULL; seq <= 80ULL; ++seq)
            {
                bool evicted = false;
                (void)server.EnqueueFrame(
                    MakeSyntheticExtractedFrame(seq, static_cast<uint32_t>(seq), 64U, 64U),
                    evicted);
                Sleep(15U);
                if (framesSeen.load() >= 2ULL)
                {
                    break;
                }
            }
            Sleep(25U);
            server.Stop();
        });

        HostConsumerConfig cfg;
        cfg.PipeName = pipeName;
        cfg.AutoReconnect = false;
        cfg.TransportPreference = HostTransportPreference::CpuStagingOnly;
        cfg.IoTimeoutMs = 40U;
        cfg.MaxDurationMs = 2000U;
        cfg.DurationCountsConnected = true;
        FrameConsumer consumer(cfg);
        (void)consumer.RunLoop(
            nullptr,
            [&framesSeen](const FrameIpcFrameHeader&, const std::vector<uint8_t>&) {
                framesSeen.fetch_add(1ULL);
            });
        stopper.join();
        const auto snap = consumer.GetMetricsSnapshot();
        EXPECT_EQ(snap.ExitReason, HostExitReason::PeerDisconnected);
        EXPECT_TRUE(!snap.DurationTargetReached);
        EXPECT_TRUE(snap.TotalConnectedDurationUs < 2000000ULL);
    }

    // 7. Connect timeout without server: ConnectFailed, TotalConnectedDurationUs=0, DurationTargetReached=false.
    {
        HostConsumerConfig cfg;
        cfg.PipeName = MakeUniquePipeName(906U);
        cfg.AutoReconnect = false;
        cfg.ConnectTimeoutMs = 120U;
        cfg.MaxDurationMs = 1000U;
        cfg.DurationCountsConnected = true;
        FrameConsumer consumer(cfg);
        EXPECT_TRUE(FAILED(consumer.RunLoop()));
        const auto snap = consumer.GetMetricsSnapshot();
        EXPECT_EQ(snap.ExitReason, HostExitReason::ConnectFailed);
        EXPECT_EQ(snap.TotalConnectedDurationUs, 0ULL);
        EXPECT_TRUE(!snap.DurationTargetReached);
    }

    // 8. Safety execution ceiling aborts stalled AutoReconnect cleanly with SafetyExecutionTimeout.
    {
        HostConsumerConfig cfg;
        cfg.PipeName = MakeUniquePipeName(907U);
        cfg.AutoReconnect = true;
        cfg.ConnectTimeoutMs = 120U;
        cfg.IoTimeoutMs = 40U;
        cfg.MaxDurationMs = 3000U;
        cfg.DurationCountsConnected = true;
        cfg.MaxExecutionDurationMs = 280U;
        FrameConsumer consumer(cfg);
        const HRESULT hr = consumer.RunLoop();
        EXPECT_EQ(hr, HRESULT_FROM_WIN32(ERROR_TIMEOUT));
        const auto snap = consumer.GetMetricsSnapshot();
        EXPECT_EQ(snap.ExitReason, HostExitReason::SafetyExecutionTimeout);
        EXPECT_TRUE(snap.SafetyExecutionTimeoutHit);
        EXPECT_TRUE(!snap.HostProcessExitedNormally);
        EXPECT_TRUE(!snap.DurationTargetReached);
        EXPECT_TRUE(snap.TotalExecutionDurationUs >= 280000ULL);
    }
}

void
TestSessionTransitionsAndStaleFrameGating()
{
    Microsoft::WRL::ComPtr<ID3D11Device> dev;
    Microsoft::WRL::ComPtr<ID3D11DeviceContext> ctx;
    LUID adapterLuid{0, 0};
    EXPECT_TRUE(CreateIpcTestD3d11Device(dev, ctx, adapterLuid));

    D3d11SharedTexturePool pool;
    EXPECT_EQ(pool.Configure(4U), S_OK);
    pool.SetDevice(dev.Get(), ctx.Get(), adapterLuid);

    const std::wstring pipeName = MakeUniquePipeName(950U);
    FrameTransportConfig serverCfg;
    serverCfg.SetPipeName(pipeName.c_str());
    serverCfg.MaxQueueDepth = 4U;
    serverCfg.BufferPoolSize = 6U;
    serverCfg.AdapterLuid = adapterLuid;
    serverCfg.EnableGpuSharedTransport = true;
    serverCfg.AllowCpuFallbackWhenGpuNegotiated = false;
    serverCfg.SharedTexturePoolSize = 4U;
    serverCfg.SharedTexturePool = &pool;
    serverCfg.RequireActiveSessionForEnqueue = false;
    serverCfg.FlushQueueOnSessionStart = true;

    FrameIpcServer server;
    EXPECT_EQ(server.Start(serverCfg), S_OK);

    // 1. Pre-existing CPU frames in queue before GPU consumer connects must be flushed cleanly.
    for (uint32_t i = 1U; i <= 2U; ++i)
    {
        bool evicted = false;
        EXPECT_EQ(server.EnqueueFrame(MakeSyntheticExtractedFrame(i, i, 64U, 64U), evicted), S_OK);
    }

    // 2. Connect GPU-only consumer -> flushes pre-existing CPU queue and enforces GPU contract.
    HostConsumerConfig gpuCfg;
    gpuCfg.PipeName = pipeName;
    gpuCfg.TransportPreference = HostTransportPreference::GpuSharedOnly;
    gpuCfg.AllowCpuFallback = false;
    gpuCfg.VerifySyntheticPattern = false;
    FrameConsumer gpuConsumer(gpuCfg);
    EXPECT_EQ(gpuConsumer.Connect(2000U), S_OK);

    const TransportSessionSnapshot sessGpu = server.GetActiveSessionSnapshot();
    EXPECT_TRUE(sessGpu.HasActiveConsumer && sessGpu.ClientAuthorized);
    EXPECT_EQ(sessGpu.NegotiatedMode, FrameIpcTransportMode::GpuSharedNtHandle);
    EXPECT_TRUE(sessGpu.RequireGpuOnly);
    EXPECT_TRUE(server.GetMetricsSnapshot().FramesFlushedOnSessionTransition >= 2ULL);

    // Late in-flight CPU frame arriving during active GPU session must be rejected cleanly.
    auto lateCpu = MakeSyntheticExtractedFrame(10U, 10U, 64U, 64U);
    bool evicted = false;
    EXPECT_EQ(server.EnqueueFrame(std::move(lateCpu), evicted), DXGI_ERROR_INVALID_CALL);
    EXPECT_TRUE(server.GetMetricsSnapshot().FramesDiscardedTransportMismatch >= 1ULL);

    // Frame tagged with stale session generation must be rejected without entering queue.
    auto staleGenFrame = MakeSyntheticExtractedFrame(11U, 11U, 64U, 64U);
    staleGenFrame->HasSessionBinding = true;
    staleGenFrame->TargetSessionId = sessGpu.SessionId;
    staleGenFrame->TargetSessionGeneration = (sessGpu.SessionGeneration > 1ULL) ? (sessGpu.SessionGeneration - 1ULL) : 9999ULL;
    staleGenFrame->IsGpuSharedFrame = true;
    EXPECT_EQ(server.EnqueueFrame(std::move(staleGenFrame), evicted), HRESULT_FROM_WIN32(ERROR_CONTEXT_EXPIRED));
    EXPECT_TRUE(server.GetMetricsSnapshot().FramesDiscardedStaleSession >= 1ULL);

    // Valid GPU frame delivers strictly on GPU path with 0 CPU reads and continuous sequence.
    {
        Microsoft::WRL::ComPtr<ID3D11Texture2D> srcGpu;
        EXPECT_TRUE(CreateSyntheticIpcGpuTexture(dev.Get(), 64U, 64U, 30U, srcGpu));
        auto slotGpu = server.AcquireBufferSlot();
        EXPECT_TRUE(slotGpu != nullptr);
        FrameExtractionInput in{};
        in.AdoptSourceTexture = srcGpu.Detach();
        in.PresentationFrameNumber = 30U;
        in.Flags = static_cast<uint32_t>(FrameIpcFlags::SyntheticTestFrame);
        EXPECT_EQ(pool.ExtractToSharedTexture(in, *slotGpu, true).HResult, S_OK);
        uint64_t assignedSeq = 0ULL;
        EXPECT_EQ(server.EnqueueFrame(std::move(slotGpu), evicted, &assignedSeq), S_OK);
        EXPECT_TRUE(assignedSeq >= 3ULL);

        bool isGpu = false;
        FrameIpcGpuFrameHeader gpuHdr{};
        FrameIpcFrameHeader cpuHdr{};
        std::vector<uint8_t> cpuPix;
        EXPECT_EQ(gpuConsumer.ReceiveNextGpuOrCpuFrame(isGpu, gpuHdr, cpuHdr, cpuPix, 2000U), S_OK);
        EXPECT_TRUE(isGpu);
        EXPECT_EQ(gpuHdr.FrameSequence, assignedSeq);
        const auto mGpu = gpuConsumer.GetMetricsSnapshot();
        EXPECT_EQ(mGpu.GpuFramesReceived, 1ULL);
        EXPECT_EQ(mGpu.CpuFramesReceived, 0ULL);
        EXPECT_EQ(mGpu.UnexpectedCpuFramesInGpuSession, 0ULL);
        EXPECT_EQ(mGpu.CpuStagingReadsPerformed, 0ULL);
    }

    gpuConsumer.Disconnect();
    DriverSessionSummarySnapshot summaryGpu{};
    const ULONGLONG waitDiscStart = GetTickCount64();
    while (!server.GetLastCompletedSessionSummary(summaryGpu) && (GetTickCount64() - waitDiscStart) < 1500ULL)
    {
        Sleep(15U);
    }
    EXPECT_TRUE(summaryGpu.Valid);
    EXPECT_EQ(summaryGpu.SessionId, sessGpu.SessionId);
    EXPECT_EQ(summaryGpu.NegotiatedMode, FrameIpcTransportMode::GpuSharedNtHandle);
    EXPECT_EQ(summaryGpu.FramesDelivered, 1ULL);

    // 3. Authorized GPU -> CPU session transition keeps monotonic server sequence without stale leaks.
    HostConsumerConfig cpuCfg;
    cpuCfg.PipeName = pipeName;
    cpuCfg.TransportPreference = HostTransportPreference::CpuStagingOnly;
    cpuCfg.VerifySyntheticPattern = true;
    FrameConsumer cpuConsumer(cpuCfg);
    EXPECT_EQ(cpuConsumer.Connect(2000U), S_OK);

    const TransportSessionSnapshot sessCpu = server.GetActiveSessionSnapshot();
    EXPECT_EQ(sessCpu.NegotiatedMode, FrameIpcTransportMode::CpuStagingPipe);
    EXPECT_TRUE(sessCpu.SessionGeneration > sessGpu.SessionGeneration);

    auto validCpu = MakeSyntheticExtractedFrame(1ULL, 31U, 64U, 64U);
    uint64_t cpuAssignedSeq = 0ULL;
    EXPECT_EQ(server.EnqueueFrame(std::move(validCpu), evicted, &cpuAssignedSeq), S_OK);
    EXPECT_TRUE(cpuAssignedSeq > summaryGpu.LastFrameSequence);

    bool isGpu2 = true;
    FrameIpcGpuFrameHeader gpuHdr2{};
    FrameIpcFrameHeader cpuHdr2{};
    std::vector<uint8_t> cpuPix2;
    EXPECT_EQ(cpuConsumer.ReceiveNextGpuOrCpuFrame(isGpu2, gpuHdr2, cpuHdr2, cpuPix2, 2000U), S_OK);
    EXPECT_TRUE(!isGpu2);
    EXPECT_EQ(cpuHdr2.FrameSequence, cpuAssignedSeq);
    EXPECT_EQ(cpuConsumer.GetMetricsSnapshot().CpuFramesReceived, 1ULL);
    EXPECT_EQ(cpuConsumer.GetMetricsSnapshot().GpuFramesReceived, 0ULL);

    cpuConsumer.Disconnect();
    server.Stop();
    EXPECT_EQ(pool.GetMetricsSnapshot().QueuedSlots, 0U);
    EXPECT_EQ(pool.GetMetricsSnapshot().InUseByHostSlots, 0U);
    pool.Shutdown();
}

void
TestConcurrentPublishSequenceAndDisconnectRecovery()
{
    const std::wstring pipeName = MakeUniquePipeName(951U);
    FrameTransportConfig serverCfg;
    serverCfg.SetPipeName(pipeName.c_str());
    serverCfg.MaxQueueDepth = 4U;
    serverCfg.BufferPoolSize = 8U;
    serverCfg.RequireActiveSessionForEnqueue = false;

    FrameIpcServer server;
    EXPECT_EQ(server.Start(serverCfg), S_OK);

    std::atomic<bool> stopThreads{false};
    std::atomic<uint64_t> rxCount{0ULL};

    HostConsumerConfig cfg;
    cfg.PipeName = pipeName;
    cfg.AutoReconnect = true;
    cfg.TransportPreference = HostTransportPreference::CpuStagingOnly;
    cfg.IoTimeoutMs = 50U;
    cfg.ConnectTimeoutMs = 2000U;
    cfg.MaxFrames = 80ULL;
    cfg.RequireFrameTarget = true;
    FrameConsumer consumer(cfg);

    HANDLE stopEvt = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    EXPECT_TRUE(stopEvt != nullptr);
    HRESULT consumerHr = E_FAIL;
    std::thread consumerThread([&]() {
        consumerHr = consumer.RunLoop(
            stopEvt,
            [&rxCount](const FrameIpcFrameHeader&, const std::vector<uint8_t>&) {
                rxCount.fetch_add(1ULL, std::memory_order_relaxed);
            });
    });

    auto spawnWorker = [&](uint32_t threadOffset) {
        return std::thread([&, threadOffset]() {
            for (uint32_t k = 0U; !stopThreads.load(std::memory_order_relaxed) && k < 120U; ++k)
            {
                if (rxCount.load(std::memory_order_relaxed) >= 80ULL)
                {
                    break;
                }
                auto slot = server.AcquireBufferSlot();
                if (slot != nullptr)
                {
                    auto synth = MakeSyntheticExtractedFrame(1ULL, threadOffset + k, 64U, 64U);
                    slot->Width = synth->Width;
                    slot->Height = synth->Height;
                    slot->RowPitchBytes = synth->RowPitchBytes;
                    slot->Format = synth->Format;
                    slot->PresentationFrameNumber = synth->PresentationFrameNumber;
                    slot->Flags = 0U;
                    slot->QpcFrequency = synth->QpcFrequency;
                    slot->ExtractCompleteQpcTime = synth->ExtractCompleteQpcTime;
                    slot->Pixels = std::move(synth->Pixels);
                    slot->PayloadCrc32 = synth->PayloadCrc32;
                    bool evicted = false;
                    (void)server.EnqueueFrame(std::move(slot), evicted);
                }
                Sleep(4U);
            }
        });
    };

    std::thread p1 = spawnWorker(0U);
    std::thread p2 = spawnWorker(1000U);
    consumerThread.join();
    stopThreads.store(true);
    p1.join();
    p2.join();
    CloseHandle(stopEvt);

    EXPECT_EQ(consumerHr, S_OK);
    const auto m = consumer.GetMetricsSnapshot();
    EXPECT_TRUE(m.FramesValid >= 80ULL);
    EXPECT_EQ(m.OutOfOrderSequenceCount, 0ULL);

    server.Stop();
}

void
TestSequenceWraparoundAndNoConsumerNonBlocking()
{
    const std::wstring pipeName = MakeUniquePipeName(952U);
    FrameTransportConfig serverCfg;
    serverCfg.SetPipeName(pipeName.c_str());
    serverCfg.RequireActiveSessionForEnqueue = true;
    serverCfg.FlushQueueOnSessionStart = true;

    FrameIpcServer server;
    EXPECT_EQ(server.Start(serverCfg), S_OK);

    // 1. RequireActiveSessionForEnqueue rejects without blocking when no consumer is connected.
    LARGE_INTEGER freqLi{}, startLi{}, endLi{};
    QueryPerformanceFrequency(&freqLi);
    QueryPerformanceCounter(&startLi);
    for (uint32_t i = 0U; i < 100U; ++i)
    {
        bool evicted = false;
        EXPECT_EQ(
            server.EnqueueFrame(MakeSyntheticExtractedFrame(1ULL, i + 1U, 64U, 64U), evicted),
            HRESULT_FROM_WIN32(ERROR_NO_DATA));
    }
    QueryPerformanceCounter(&endLi);
    const uint64_t elapsedUs =
        (static_cast<uint64_t>(endLi.QuadPart - startLi.QuadPart) * 1000000ULL) /
        static_cast<uint64_t>((freqLi.QuadPart > 0) ? freqLi.QuadPart : 10000000LL);
    EXPECT_TRUE(elapsedUs < 250000ULL);
    EXPECT_EQ(server.GetMetricsSnapshot().FramesDiscardedNoConsumer, 100ULL);
    EXPECT_EQ(server.GetMetricsSnapshot().QueueDepth, 0U);

    // 2. UINT64_MAX -> 1 authoritative publish sequence wraparound.
    server.Stop();
    serverCfg.RequireActiveSessionForEnqueue = false;
    EXPECT_EQ(server.Start(serverCfg), S_OK);
    server.SetNextPublishSequenceForTesting(UINT64_MAX - 1ULL);

    uint64_t seq1 = 0ULL, seq2 = 0ULL, seq3 = 0ULL;
    bool evicted = false;
    EXPECT_EQ(server.EnqueueFrame(MakeSyntheticExtractedFrame(1ULL, 1U, 64U, 64U), evicted, &seq1), S_OK);
    EXPECT_EQ(server.EnqueueFrame(MakeSyntheticExtractedFrame(1ULL, 2U, 64U, 64U), evicted, &seq2), S_OK);
    EXPECT_EQ(server.EnqueueFrame(MakeSyntheticExtractedFrame(1ULL, 3U, 64U, 64U), evicted, &seq3), S_OK);
    EXPECT_EQ(seq1, UINT64_MAX - 1ULL);
    EXPECT_EQ(seq2, UINT64_MAX);
    EXPECT_EQ(seq3, 1ULL);
    EXPECT_EQ(server.GetMetricsSnapshot().SequenceWrapAroundCount, 1ULL);

    // 3. FlushQueue releases queued resources back into free pool cleanly.
    server.FlushQueue();
    const auto flushSnap = server.GetMetricsSnapshot();
    EXPECT_EQ(flushSnap.QueueDepth, 0U);
    EXPECT_EQ(flushSnap.FreePoolSlots, flushSnap.TotalPoolSlots);

    server.Stop();
}

void
TestHostRejectsUnexpectedCpuFrameInGpuOnlySessionAndCountsSeparation()
{
    Microsoft::WRL::ComPtr<ID3D11Device> dev;
    Microsoft::WRL::ComPtr<ID3D11DeviceContext> ctx;
    LUID adapterLuid{0, 0};
    EXPECT_TRUE(CreateIpcTestD3d11Device(dev, ctx, adapterLuid));

    auto runMockMismatchCase = [adapterLuid](bool serverNegotiatesGpu, bool sendGpuPayloadOnWire) -> HostConsumerMetricsSnapshot {
        wchar_t pipeBuf[128]{};
        _snwprintf_s(
            pipeBuf,
            ARRAYSIZE(pipeBuf),
            _TRUNCATE,
            L"\\\\.\\pipe\\LumaBridgeMismatchRaw_%lu_%u_%u",
            GetCurrentProcessId(),
            serverNegotiatesGpu ? 1U : 0U,
            sendGpuPayloadOnWire ? 1U : 0U);
        const std::wstring pipeName(pipeBuf);

        HANDLE hPipe = CreateNamedPipeW(
            pipeName.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1U,
            65536U,
            65536U,
            2000U,
            nullptr);
        EXPECT_TRUE(hPipe != INVALID_HANDLE_VALUE);

        std::thread mockServer([hPipe, adapterLuid, serverNegotiatesGpu, sendGpuPayloadOnWire]() {
            if (!ConnectNamedPipe(hPipe, nullptr) && GetLastError() != ERROR_PIPE_CONNECTED)
            {
                CloseHandle(hPipe);
                return;
            }
            FrameIpcClientHello hello{};
            DWORD bytesRead = 0U;
            if (!ReadFile(hPipe, &hello, sizeof(hello), &bytesRead, nullptr) || bytesRead != sizeof(hello))
            {
                CloseHandle(hPipe);
                return;
            }

            FrameIpcServerHello sh{};
            sh.Envelope = InitEnvelope(FrameIpcMessageType::ServerHello, sizeof(sh));
            sh.Status = static_cast<uint32_t>(FrameIpcStatus::Ok);
            sh.SessionId = 42ULL;
            sh.ServerProcessId = GetCurrentProcessId();
            sh.AdapterLuidLow = static_cast<int32_t>(adapterLuid.LowPart);
            sh.AdapterLuidHigh = adapterLuid.HighPart;
            sh.MaxQueueDepth = 3U;
            const uint32_t caps = serverNegotiatesGpu
                ? static_cast<uint32_t>(FrameIpcCapabilities::GpuSharedNtHandle)
                : static_cast<uint32_t>(FrameIpcCapabilities::CpuStagingRawPixels);
            sh.Reserved1 = PackServerHelloCapabilities(caps, serverNegotiatesGpu ? 3U : 0U);

            DWORD bytesWritten = 0U;
            (void)WriteFile(hPipe, &sh, sizeof(sh), &bytesWritten, nullptr);

            LARGE_INTEGER freq{}, now{};
            QueryPerformanceFrequency(&freq);
            QueryPerformanceCounter(&now);
            if (!sendGpuPayloadOnWire)
            {
                FrameIpcFrameHeader fh{};
                fh.Envelope = InitEnvelope(FrameIpcMessageType::FrameHeader, sizeof(fh));
                fh.SessionId = 42ULL;
                fh.FrameSequence = 1ULL;
                fh.PresentationFrameNumber = 1U;
                fh.Width = 4U;
                fh.Height = 4U;
                fh.RowPitchBytes = 16U;
                fh.PixelFormat = static_cast<uint32_t>(DXGI_FORMAT_B8G8R8A8_UNORM);
                fh.ExtractCompleteQpcTime = static_cast<uint64_t>(now.QuadPart);
                fh.ServerSendQpcTime = static_cast<uint64_t>(now.QuadPart);
                fh.QpcFrequency = static_cast<uint64_t>(freq.QuadPart);
                fh.PayloadSizeBytes = 64U;
                std::vector<uint8_t> zeros(64U, 0U);
                fh.PayloadCrc32 = ComputeFrameCrc32(zeros.data(), zeros.size());
                (void)WriteFile(hPipe, &fh, sizeof(fh), &bytesWritten, nullptr);
                (void)WriteFile(hPipe, zeros.data(), static_cast<DWORD>(zeros.size()), &bytesWritten, nullptr);
            }
            else
            {
                FrameIpcGpuFrameHeader gh{};
                gh.Envelope = InitEnvelope(FrameIpcMessageType::GpuFrameHeader, sizeof(gh));
                gh.Envelope.VersionMinor = kFrameIpcProtocolVersionMinorV1_1;
                gh.SessionId = 42ULL;
                gh.FrameSequence = 1ULL;
                gh.PresentationFrameNumber = 1U;
                gh.Width = 4U;
                gh.Height = 4U;
                gh.PixelFormat = static_cast<uint32_t>(DXGI_FORMAT_B8G8R8A8_UNORM);
                gh.SlotIndex = 0U;
                gh.SlotGeneration = 1U;
                gh.DuplicatedNtHandleValue = 0x1234ULL;
                gh.AdapterLuidLow = static_cast<int32_t>(adapterLuid.LowPart);
                gh.AdapterLuidHigh = adapterLuid.HighPart;
                gh.ExtractCompleteQpcTime = static_cast<uint64_t>(now.QuadPart);
                gh.ServerSendQpcTime = static_cast<uint64_t>(now.QuadPart);
                gh.QpcFrequency = static_cast<uint64_t>(freq.QuadPart);
                (void)WriteFile(hPipe, &gh, sizeof(gh), &bytesWritten, nullptr);
            }
            FlushFileBuffers(hPipe);
            Sleep(50U);
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
        });

        HostConsumerConfig cfg;
        cfg.PipeName = pipeName;
        cfg.TransportPreference =
            serverNegotiatesGpu ? HostTransportPreference::GpuSharedOnly : HostTransportPreference::CpuStagingOnly;
        cfg.AllowCpuFallback = false;
        cfg.ConnectTimeoutMs = 2000U;
        cfg.IoTimeoutMs = 1000U;
        FrameConsumer consumer(cfg);
        const HRESULT hr = consumer.RunLoop();
        mockServer.join();
        EXPECT_EQ(hr, DXGI_ERROR_INVALID_CALL);
        return consumer.GetMetricsSnapshot();
    };

    const auto gpuExpectingReject = runMockMismatchCase(true, false);
    EXPECT_EQ(gpuExpectingReject.ExitReason, HostExitReason::FatalProtocolError);
    EXPECT_TRUE(!gpuExpectingReject.TransportHealthy);
    EXPECT_EQ(gpuExpectingReject.UnexpectedCpuFramesInGpuSession, 1ULL);
    EXPECT_EQ(gpuExpectingReject.TransportContractViolations, 1ULL);
    EXPECT_EQ(gpuExpectingReject.CpuFramesReceived, 1ULL);
    EXPECT_EQ(gpuExpectingReject.GpuFramesReceived, 0ULL);

    const auto cpuExpectingReject = runMockMismatchCase(false, true);
    EXPECT_EQ(cpuExpectingReject.ExitReason, HostExitReason::FatalProtocolError);
    EXPECT_TRUE(!cpuExpectingReject.TransportHealthy);
    EXPECT_EQ(cpuExpectingReject.UnexpectedGpuFramesInCpuSession, 1ULL);
    EXPECT_EQ(cpuExpectingReject.TransportContractViolations, 1ULL);
    EXPECT_EQ(cpuExpectingReject.GpuFramesReceived, 0ULL);
}

void
TestVirtualDisplayDiscoveryRationalPacingAndCorrelation()
{
    // 1. Zero-drift exact rational QPC math across 108,000 ticks (30 min @ 60fps & 59Hz/120Hz).
    constexpr uint64_t kFreq = 10000000ULL;
    const uint64_t exact108k = ComputeExactRationalOffsetQpc(108000ULL, kFreq, 60U);
    EXPECT_EQ(exact108k, 1800ULL * kFreq);
    const uint64_t exact59Hz = ComputeExactRationalOffsetQpc(59ULL * 1000ULL, kFreq, 59U);
    EXPECT_EQ(exact59Hz, 1000ULL * kFreq);
    const uint64_t exact120Hz = ComputeExactRationalOffsetQpc(120ULL * 600ULL, kFreq, 120U);
    EXPECT_EQ(exact120Hz, 600ULL * kFreq);

    // 2. Virtual display selection strictly refuses falling back to physical primary display.
    DisplayCandidateInfo physicalPrimary{};
    physicalPrimary.DeviceName = L"\\\\.\\DISPLAY1";
    physicalPrimary.AdapterString = L"NVIDIA GeForce RTX";
    physicalPrimary.BoundsWidth = 1920U;
    physicalPrimary.BoundsHeight = 1080U;
    physicalPrimary.Active = true;
    physicalPrimary.Primary = true;
    physicalPrimary.IsIndirectWired = false;

    const auto noVirtual = DiscoverVirtualDisplayFromCandidates({physicalPrimary});
    EXPECT_TRUE(!noVirtual.Identified);

    DisplayCandidateInfo lumaVirtual{};
    lumaVirtual.DeviceName = L"\\\\.\\DISPLAY10";
    lumaVirtual.AdapterString = L"LumaBridgeIddDriver";
    lumaVirtual.BoundsLeft = 1920;
    lumaVirtual.BoundsWidth = 1920U;
    lumaVirtual.BoundsHeight = 1080U;
    lumaVirtual.Active = true;
    lumaVirtual.Primary = false;
    lumaVirtual.IsIndirectWired = true;

    const auto foundVirtual = DiscoverVirtualDisplayFromCandidates({physicalPrimary, lumaVirtual});
    EXPECT_TRUE(foundVirtual.Identified);
    EXPECT_TRUE(_wcsicmp(foundVirtual.Selected.DeviceName.c_str(), L"\\\\.\\DISPLAY10") == 0);

    // 3. PacingCorrelation accurately detects PresDelta=0/2, SeqGap, and >25ms gaps without per-frame console spam.
    const std::wstring pipeName = MakeUniquePipeName(953U);
    FrameTransportConfig srvCfg;
    srvCfg.SetPipeName(pipeName.c_str());
    srvCfg.AssignSequenceOnEnqueue = false;
    srvCfg.RequireActiveSessionForEnqueue = false;
    FrameIpcServer server;
    EXPECT_EQ(server.Start(srvCfg), S_OK);

    HostConsumerConfig consCfg;
    consCfg.PipeName = pipeName;
    consCfg.TransportPreference = HostTransportPreference::CpuStagingOnly;
    consCfg.MaxFrames = 5ULL;
    consCfg.RequireFrameTarget = true;
    FrameConsumer consumer(consCfg);

    std::thread producer([&server]() {
        bool ev = false;
        (void)server.EnqueueFrame(MakeSyntheticExtractedFrame(1ULL, 1U, 64U, 64U), ev);
        Sleep(10U);
        (void)server.EnqueueFrame(MakeSyntheticExtractedFrame(2ULL, 1U, 64U, 64U), ev); // PresDelta == 0
        Sleep(10U);
        (void)server.EnqueueFrame(MakeSyntheticExtractedFrame(3ULL, 3U, 64U, 64U), ev); // PresDelta == 2
        Sleep(32U);
        (void)server.EnqueueFrame(MakeSyntheticExtractedFrame(5ULL, 4U, 64U, 64U), ev); // SeqGap + >25ms gap
        Sleep(10U);
        (void)server.EnqueueFrame(MakeSyntheticExtractedFrame(6ULL, 5U, 64U, 64U), ev); // Normal
    });

    EXPECT_EQ(consumer.RunLoop(), S_OK);
    producer.join();
    server.Stop();

    const auto corrSnap = consumer.GetMetricsSnapshot().PacingCorrelation;
    EXPECT_EQ(corrSnap.PresentationDelta0Count, 1ULL);
    EXPECT_EQ(corrSnap.PresentationDelta1Count, 2ULL);
    EXPECT_EQ(corrSnap.PresentationDelta2Count, 1ULL);
    EXPECT_EQ(corrSnap.SequenceDeltaGapCount, 1ULL);
    EXPECT_TRUE(corrSnap.InterArrivalGapsOver25ms >= 1ULL);
    EXPECT_EQ(corrSnap.TotalAnomaliesRecorded, 3ULL);
    EXPECT_EQ(corrSnap.RecentAnomalies.size(), static_cast<size_t>(3U));
}

void
TestDxgiStimulusExplicitTestSurfaceLifecycle()
{
    VirtualDisplayStimulus stim;
    VirtualDisplayStimulusConfig cfg{};
    cfg.TargetFps = 60U;
    cfg.Backend = StimulusBackend::Auto;
    cfg.UseExplicitRectForTestOnly = true;
    cfg.ExplicitTestRect = RECT{0L, 0L, 320L, 240L};
    cfg.TestDisplayName = L"LUMABRIDGE_M024_TEST_SURFACE";

    EXPECT_TRUE(stim.Start(cfg));
    Sleep(350U);
    stim.Stop();

    const auto snap = stim.GetMetricsSnapshot();
    std::printf(
        "[INFO] DxgiStimulusExplicitTestSurface: BackendRequested=%s BackendActive=%s "
        "PresentSucceeded=%llu PresentOccluded=%llu PresentFailures=%llu "
        "FallbackFromDxgiOccurred=%s CompletedCleanly=%s DurationUs=%llu LastHResult=0x%08lX ErrorMessage=\"%s\"\n",
        snap.BackendRequested.c_str(),
        snap.BackendActive.c_str(),
        static_cast<unsigned long long>(snap.PresentSucceeded),
        static_cast<unsigned long long>(snap.PresentOccluded),
        static_cast<unsigned long long>(snap.PresentFailures),
        snap.FallbackFromDxgiOccurred ? "true" : "false",
        snap.CompletedCleanly ? "true" : "false",
        static_cast<unsigned long long>(snap.DurationUs),
        static_cast<unsigned long>(snap.LastHResult),
        snap.ErrorMessage.c_str());
    if (snap.FallbackFromDxgiOccurred && snap.PresentOccluded > 0ULL)
    {
        std::printf(
            "[BLOCKED_BY_ENVIRONMENT] Explicit test surface hit DXGI_STATUS_OCCLUDED (%llu) on isolated desktop; "
            "Auto mode fell back to GdiLegacy (DXGI pacing NOT validated by GDI fallback).\n",
            static_cast<unsigned long long>(snap.PresentOccluded));
    }

    EXPECT_TRUE(snap.VirtualDisplayIdentified);
    EXPECT_TRUE(snap.IdentificationSource == "ExplicitTestRect");
    EXPECT_TRUE(snap.Started);
    EXPECT_TRUE(snap.CompletedCleanly);
    EXPECT_TRUE(snap.HighResolutionTimerUsed);
    EXPECT_TRUE(snap.ExecutedTicks >= 15ULL);
    EXPECT_TRUE(snap.TicksPresented >= 15ULL);
    EXPECT_EQ(snap.PresentFailures, 0ULL);
    EXPECT_EQ(snap.BoundsWidth, 320U);
    EXPECT_EQ(snap.BoundsHeight, 240U);
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
    RunTest("PoolCapacityLimitsExhaustionAndAllocationFailureRollback", TestPoolCapacityLimitsExhaustionAndAllocationFailureRollback);
    RunTest("SmokeExitReasonsIdleDesktopAndRecoverableVsPartialTimeouts", TestSmokeExitReasonsIdleDesktopAndRecoverableVsPartialTimeouts);
    RunTest("DeterministicFpsGuardrailsTimestampValidationAndVirtualDisplaySelection", TestDeterministicFpsGuardrailsTimestampValidationAndVirtualDisplaySelection);
    RunTest("RepeatedSessionsMemoryBoundedness", TestRepeatedSessionsMemoryBoundedness);
    RunTest("V1_1GpuTransportCapabilityNegotiationAndFallback", TestV1_1GpuTransportCapabilityNegotiationAndFallback);
    RunTest("GpuSharedTextureIpcUnauthorizedClientCannotObtainHandle", TestGpuSharedTextureIpcUnauthorizedClientCannotObtainHandle);
    RunTest("GpuSharedTextureDelayedAckAndMidUseClientDisconnectRecovery", TestGpuSharedTextureDelayedAckAndMidUseClientDisconnectRecovery);
    RunTest("GpuSharedTextureIncompatibleAdapterAndInvalidHandleAckHandling", TestGpuSharedTextureIncompatibleAdapterAndInvalidHandleAckHandling);
    RunTest("M421TimestampValidationAndRegressionScenarios", TestM421TimestampValidationAndRegressionScenarios);
    RunTest("ReservoirLatencySamplingForLongRuns", TestReservoirLatencySamplingForLongRuns);
    RunTest("PercentileMethodologyBoundariesAndReservoirEstimate", TestPercentileMethodologyBoundariesAndReservoirEstimate);
    RunTest("ConnectedDurationClockSafetyAndBoundaries", TestConnectedDurationClockSafetyAndBoundaries);
    RunTest("SessionTransitionsAndStaleFrameGating", TestSessionTransitionsAndStaleFrameGating);
    RunTest("ConcurrentPublishSequenceAndDisconnectRecovery", TestConcurrentPublishSequenceAndDisconnectRecovery);
    RunTest("SequenceWraparoundAndNoConsumerNonBlocking", TestSequenceWraparoundAndNoConsumerNonBlocking);
    RunTest("HostRejectsUnexpectedCpuFrameInGpuOnlySessionAndCountsSeparation", TestHostRejectsUnexpectedCpuFrameInGpuOnlySessionAndCountsSeparation);
    RunTest("VirtualDisplayDiscoveryRationalPacingAndCorrelation", TestVirtualDisplayDiscoveryRationalPacingAndCorrelation);
    RunTest("DxgiStimulusExplicitTestSurfaceLifecycle", TestDxgiStimulusExplicitTestSurfaceLifecycle);

    std::printf("Summary: %d tests run, %d assertion failures.\n", g_TestsRun, g_TestsFailed);
    return (g_TestsFailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
