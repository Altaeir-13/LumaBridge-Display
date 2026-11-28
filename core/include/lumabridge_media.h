// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef LUMABRIDGE_MEDIA_H
#define LUMABRIDGE_MEDIA_H

/* Platform-agnostic media encode/decode contract (`lumabridge-media`, C11 / C++20 compatible).
 * Native GPU surface descriptors remain inside platform adapters and NEVER cross FFI. */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum LbSurfaceHandleKind {
    LB_SURFACE_NONE = 0,
    LB_SURFACE_WIN_D3D11_TEXTURE = 1,
    LB_SURFACE_LINUX_DMABUF = 2,
    LB_SURFACE_LINUX_SHM_MEMFD = 3,
    LB_SURFACE_ANDROID_HARDWARE_BUFFER = 4,
    LB_SURFACE_CPU_LINEAR_DIAGNOSTIC = 5
} LbSurfaceHandleKind;

typedef struct LbOpaqueSurfaceHandle {
    uint32_t kind;
    uint32_t reserved0;
    uint64_t native_handle_or_ptr;
    uint64_t adapter_or_modifier;
    uint32_t fence_or_mutex_key;
    uint32_t data_size_bytes;
} LbOpaqueSurfaceHandle;

typedef struct LbEncoderConfig {
    uint32_t codec_id;
    uint32_t target_bitrate_bps;
    uint32_t max_bitrate_bps;
    uint16_t width;
    uint16_t height;
    uint16_t fps_num;
    uint16_t fps_den;
    uint8_t hw_required;
    uint8_t zero_b_frames;
    uint8_t repeat_sps_pps;
    uint8_t reserved0;
} LbEncoderConfig;

typedef struct LbDecoderConfig {
    uint32_t codec_id;
    uint16_t max_width;
    uint16_t max_height;
    uint8_t hw_required;
    uint8_t mailbox_one_slot;
    uint16_t reserved0;
    uint32_t reserved1;
} LbDecoderConfig;

typedef struct LbMediaBitrateFeedback {
    uint64_t session_id;
    uint32_t suggested_bitrate_bps;
    uint32_t packet_loss_ppm;
    uint32_t jitter_us;
    uint16_t display_id;
    uint8_t request_force_idr;
    uint8_t chain_broken;
} LbMediaBitrateFeedback;

#ifdef __cplusplus
}
#endif

#endif /* LUMABRIDGE_MEDIA_H */
