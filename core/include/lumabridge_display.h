// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef LUMABRIDGE_DISPLAY_H
#define LUMABRIDGE_DISPLAY_H

/* Platform-agnostic native display contract (`lumabridge-display`, C11 / C++20 compatible).
 * GPU/compositor handles (ID3D11Texture2D, DMA-BUF, AHardwareBuffer) NEVER cross into core/FFI. */

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum LbDisplayModeKind {
    LB_DISPLAY_MODE_MIRROR = 1,
    LB_DISPLAY_MODE_EXTEND = 2
} LbDisplayModeKind;

typedef enum LbPixelFormatKind {
    LB_PIXEL_FORMAT_BGRA8 = 1,
    LB_PIXEL_FORMAT_RGBA8 = 2,
    LB_PIXEL_FORMAT_NV12 = 3,
    LB_PIXEL_FORMAT_P010 = 4,
    LB_PIXEL_FORMAT_I420 = 5
} LbPixelFormatKind;

typedef enum LbRotationDeg {
    LB_ROTATION_0 = 0,
    LB_ROTATION_90 = 90,
    LB_ROTATION_180 = 180,
    LB_ROTATION_270 = 270
} LbRotationDeg;

typedef struct LbColorMetadata {
    uint32_t primaries;
    uint32_t transfer;
    uint32_t range;
    uint32_t reserved;
} LbColorMetadata;

typedef struct LbDisplayGeometry {
    uint16_t display_id;
    uint16_t width;
    uint16_t height;
    uint16_t fps_num;
    uint16_t fps_den;
    uint16_t scale_milli;
    uint16_t rotation_deg;
    uint16_t mode;
    int32_t pos_x;
    int32_t pos_y;
} LbDisplayGeometry;

typedef struct LbFrameDescriptor {
    uint64_t capture_monotonic_us;
    uint64_t encode_start_us;
    uint64_t encode_done_us;
    uint32_t frame_id;
    uint32_t stride_bytes;
    uint32_t pixel_format;
    uint16_t display_id;
    uint16_t width;
    uint16_t height;
    uint16_t rotation_deg;
    uint16_t scale_milli;
    uint8_t is_hw_protected;
    uint8_t reserved0;
    struct LbColorMetadata color;
} LbFrameDescriptor;

typedef struct LbDisplayCapabilities {
    uint32_t max_virtual_displays;
    uint32_t supports_mirror;
    uint32_t supports_extend;
    uint32_t supports_scale;
    uint32_t supports_rotation;
    uint32_t reserved0;
} LbDisplayCapabilities;

#ifdef __cplusplus
}
#endif

#endif /* LUMABRIDGE_DISPLAY_H */
