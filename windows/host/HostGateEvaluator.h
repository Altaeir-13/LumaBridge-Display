#pragma once

#include <Windows.h>

#include "AsyncH264ValidationWorker.h"
#include "FrameConsumer.h"
#include "H264BitstreamValidator.h"
#include "NvencH264Encoder.h"
#include "VirtualDisplayStimulus.h"

#include <algorithm>
#include <cstdint>
#include <string>

namespace lumabridge::host {

struct HostGateConfig
{
    std::wstring RunId{};
    bool RequireGpuShared{false};
    bool EnableNvenc{false};
    bool RequireNvenc{false};
    bool VerifyH264Decode{false};
    bool VerifyH264Psnr{false};
    bool RequireVirtualStimulus{false};
    StimulusBackend RequestedStimulusBackend{StimulusBackend::Auto};
    bool RequireValidTimestamps{false};
    uint32_t RequireWidth{0U};
    uint32_t RequireHeight{0U};
    double MinNvencEncodeRatio{0.0};
    double MaxNvencDropRatio{1.0};
    uint64_t MinNvencEncodedFrames{0ULL};
};

struct HostGateEvaluation
{
    bool IntegrityOk{false};
    bool MinFramesOk{false};
    bool MaxTargetOk{false};
    bool DurationOk{false};
    bool StimulusOk{false};
    bool TransportContractOk{false};
    bool GpuTransportOk{false};
    bool NvencOk{false};
    bool H264DecodeOk{false};
    bool H264PsnrOk{false};
    bool TimestampsOk{false};
    bool ResolutionOk{false};
    bool OverallExitOk{false};
};

inline HostGateEvaluation
EvaluateHostGates(
    const HostConsumerConfig& config,
    const HostConsumerMetricsSnapshot& metrics,
    const StimulusMetricsSnapshot& stimSnap,
    const NvencMetricsSnapshot& nvencSnap,
    const H264ValidationSummary& h264Snap,
    const H264WorkerMetricsSnapshot& h264WorkerSnap,
    const HostGateConfig& gateCfg,
    bool nvencInitFatal,
    HRESULT nvencLastHr,
    HRESULT runHr
    ) noexcept
{
    HostGateEvaluation eval{};
    eval.IntegrityOk =
        (metrics.ChecksumMismatches == 0ULL) &&
        (metrics.SyntheticPatternMismatches == 0ULL) &&
        (metrics.ProtocolErrors == 0ULL);
    eval.MinFramesOk = (metrics.FramesValid >= config.MinFrames);
    eval.MaxTargetOk = (!config.RequireFrameTarget) || metrics.FrameTargetReached;

    const bool enforceStimulus =
        gateCfg.RequireVirtualStimulus ||
        (stimSnap.Requested && gateCfg.RequestedStimulusBackend != StimulusBackend::Auto);
    bool stimulusOk = !enforceStimulus;
    if (enforceStimulus)
    {
        const bool baseStimOk =
            stimSnap.VirtualDisplayIdentified &&
            stimSnap.Started &&
            stimSnap.CompletedCleanly &&
            !stimSnap.TerminalFailure &&
            SUCCEEDED(stimSnap.LastHResult) &&
            stimSnap.ErrorMessage.empty() &&
            !stimSnap.DisplayDeviceName.empty() &&
            !stimSnap.IdentificationSource.empty() &&
            (stimSnap.IdentificationSource != "None");

        if (gateCfg.RequestedStimulusBackend == StimulusBackend::D3d11DxgiVSync)
        {
            stimulusOk =
                baseStimOk &&
                (stimSnap.BackendRequested == "D3d11DxgiVSync") &&
                (stimSnap.BackendActive == "D3d11DxgiVSync") &&
                !stimSnap.FallbackFromDxgiOccurred &&
                (stimSnap.PresentSucceeded > 0ULL) &&
                (stimSnap.LastHResult == S_OK);
        }
        else if (gateCfg.RequestedStimulusBackend == StimulusBackend::GdiLegacy)
        {
            stimulusOk =
                baseStimOk &&
                (stimSnap.BackendRequested == "GdiLegacy") &&
                (stimSnap.BackendActive == "GdiLegacy") &&
                !stimSnap.FallbackFromDxgiOccurred &&
                (stimSnap.PresentSucceeded > 0ULL) &&
                (stimSnap.LastHResult == S_OK);
        }
        else
        {
            stimulusOk = baseStimOk;
        }
    }
    eval.StimulusOk = stimulusOk;
    eval.TransportContractOk =
        (metrics.TransportContractViolations == 0ULL) &&
        (metrics.UnexpectedCpuFramesInGpuSession == 0ULL) &&
        (metrics.UnexpectedGpuFramesInCpuSession == 0ULL) &&
        (!gateCfg.RequireGpuShared || metrics.CpuFramesReceived == 0ULL);
    eval.GpuTransportOk =
        (!gateCfg.RequireGpuShared) ||
        (metrics.NegotiatedTransportMode == ipc::FrameIpcTransportMode::GpuSharedNtHandle &&
         !metrics.FallbackToCpuActivated &&
         eval.TransportContractOk &&
         metrics.GpuFramesReceived > 0ULL &&
         metrics.CpuFramesReceived == 0ULL &&
         metrics.UnexpectedCpuFramesInGpuSession == 0ULL &&
         metrics.TransportContractViolations == 0ULL &&
         metrics.GpuFramesOpened > 0ULL &&
         metrics.GpuSharedOpenFailures == 0ULL &&
         metrics.GpuSyncTimeouts == 0ULL &&
         metrics.AdapterMismatchErrors == 0ULL &&
         (config.VerifySyntheticPattern || metrics.CpuStagingReadsPerformed == 0ULL));

    bool nvencOk = !gateCfg.RequireNvenc;
    if (gateCfg.RequireNvenc)
    {
        const uint64_t minEncoded = (std::max)(1ULL, gateCfg.MinNvencEncodedFrames);
        const bool baseNvencOk =
            !nvencInitFatal &&
            SUCCEEDED(nvencLastHr) &&
            nvencSnap.NvencFramesEncoded >= minEncoded &&
            nvencSnap.TotalBitstreamBytes > 0ULL;
        const bool ratioOk =
            (gateCfg.MinNvencEncodeRatio <= 0.0) ||
            (metrics.FramesValid > 0ULL &&
             (static_cast<double>(nvencSnap.NvencFramesEncoded) / static_cast<double>(metrics.FramesValid)) >=
                 gateCfg.MinNvencEncodeRatio);
        const uint64_t totalDrops = nvencSnap.NvencDroppedFrames + nvencSnap.EncodedQueueDrops;
        const bool dropsOk =
            (gateCfg.MaxNvencDropRatio >= 1.0) ||
            (nvencSnap.NvencFramesSubmitted > 0ULL &&
             (static_cast<double>(totalDrops) / static_cast<double>(nvencSnap.NvencFramesSubmitted)) <=
                 gateCfg.MaxNvencDropRatio);
        nvencOk = baseNvencOk && ratioOk && dropsOk;
    }
    eval.NvencOk = nvencOk;

    const bool workerHealthyForDecode =
        (!h264WorkerSnap.Enabled) ||
        (h264WorkerSnap.Healthy &&
         h264WorkerSnap.PacketsRejected == 0ULL &&
         h264WorkerSnap.QueueWaitTimeoutCount == 0ULL &&
         h264WorkerSnap.WorkerFailureCount == 0ULL &&
         h264WorkerSnap.QueueRemainingAtExit == 0ULL &&
         !h264WorkerSnap.DrainDeadlineExceeded &&
         h264WorkerSnap.ComBalanced &&
         (h264WorkerSnap.PacketsEnqueued == h264WorkerSnap.PacketsProcessed));

    eval.H264DecodeOk = (!gateCfg.VerifyH264Decode) || (h264Snap.Passed && workerHealthyForDecode);
    eval.H264PsnrOk = (!gateCfg.VerifyH264Psnr) || (h264Snap.FidelityPsnrValidated && workerHealthyForDecode);

    bool timestampsOk = true;
    if (gateCfg.RequireValidTimestamps)
    {
        const bool liveSamplesOk =
            (metrics.LiveFramesReceived == 0ULL) ||
            (metrics.LiveTimestampCoveragePercent >= 95.0 &&
             metrics.LiveEndToEndLatency.Available &&
             metrics.LiveEndToEndLatency.SampleCount > 0ULL);
        const bool nvencTsOk =
            (nvencSnap.NvencFramesEncoded == 0ULL) ||
            (nvencSnap.InvalidTimestampCount == 0ULL &&
             nvencSnap.ExtractToBitstreamCoveragePercent >= 95.0);
        timestampsOk =
            (metrics.TimestampMeasurementErrors == 0ULL) &&
            (metrics.OutOfOrderSequenceCount == 0ULL) &&
            (metrics.NonMonotonicTimestampCount == 0ULL) &&
            (metrics.MissingCoreTimestampCount == 0ULL) &&
            (metrics.FutureTimestampErrorCount == 0ULL) &&
            (metrics.IncompatibleTimestampUnitsCount == 0ULL) &&
            (metrics.QpcFrequencyMismatchCount == 0ULL) &&
            (metrics.CoreTimestampCoveragePercent >= 95.0) &&
            liveSamplesOk &&
            nvencTsOk;
    }
    eval.TimestampsOk = timestampsOk;

    bool resolutionOk = true;
    if (gateCfg.RequireWidth > 0U || gateCfg.RequireHeight > 0U)
    {
        const bool frameDimOk =
            (metrics.FramesValid > 0ULL) &&
            (gateCfg.RequireWidth == 0U || metrics.LastFrameWidth == gateCfg.RequireWidth) &&
            (gateCfg.RequireHeight == 0U || metrics.LastFrameHeight == gateCfg.RequireHeight);
        const bool nvencDimOk =
            (!gateCfg.EnableNvenc || !nvencSnap.Initialized) ||
            ((gateCfg.RequireWidth == 0U || nvencSnap.Width == gateCfg.RequireWidth) &&
             (gateCfg.RequireHeight == 0U || nvencSnap.Height == gateCfg.RequireHeight));
        resolutionOk = frameDimOk && nvencDimOk;
    }
    eval.ResolutionOk = resolutionOk;

    bool durationOk = metrics.QpcClockValid && (metrics.QpcFrequency > 0ULL) && !metrics.SafetyExecutionTimeoutHit;
    if (durationOk && config.MaxDurationMs > 0U && config.DurationCountsConnected)
    {
        const bool hasActiveFrames =
            (metrics.FramesValid > 0ULL) &&
            (metrics.FramesValid < 2ULL || metrics.ActiveStreamingDurationUs > 0ULL);
        durationOk =
            metrics.DurationTargetReached &&
            (metrics.TotalConnectedDurationUs >= metrics.RequestedDurationUs) &&
            hasActiveFrames;
    }
    eval.DurationOk = durationOk;

    eval.OverallExitOk =
        SUCCEEDED(runHr) &&
        metrics.HostProcessExitedNormally &&
        metrics.TransportHealthy &&
        eval.IntegrityOk &&
        eval.MinFramesOk &&
        eval.MaxTargetOk &&
        eval.DurationOk &&
        eval.StimulusOk &&
        eval.TransportContractOk &&
        eval.GpuTransportOk &&
        eval.NvencOk &&
        eval.H264DecodeOk &&
        eval.H264PsnrOk &&
        eval.TimestampsOk &&
        eval.ResolutionOk;
    return eval;
}

} // namespace lumabridge::host
