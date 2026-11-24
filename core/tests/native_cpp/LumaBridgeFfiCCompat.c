// SPDX-License-Identifier: Apache-2.0
#include "lumabridge_ffi.h"

#include <stddef.h>
#include <stdint.h>

/* Pure C11 compile-time layout and ABI surface checks for lumabridge_ffi.h */
_Static_assert(LB_FFI_ABI_MAJOR == 1, "LB_FFI_ABI_MAJOR must be 1");
_Static_assert(LB_FFI_ABI_MINOR == 0, "LB_FFI_ABI_MINOR must be 0");
_Static_assert(LB_FFI_MAX_FRAME_BYTES == (8u * 1024u * 1024u), "LB_FFI_MAX_FRAME_BYTES must be 8 MiB");
_Static_assert(LB_FFI_MIN_QUEUE_CAPACITY == 1u, "LB_FFI_MIN_QUEUE_CAPACITY must be 1");
_Static_assert(LB_FFI_MAX_QUEUE_CAPACITY == 256u, "LB_FFI_MAX_QUEUE_CAPACITY must be 256");

_Static_assert(sizeof(LbStatus) == sizeof(uint32_t), "LbStatus must be 32-bit");
_Static_assert(sizeof(LbCoreState) == sizeof(uint32_t), "LbCoreState must be 32-bit");
_Static_assert(sizeof(LbEncodedCodec) == sizeof(uint32_t), "LbEncodedCodec must be 32-bit");
_Static_assert(sizeof(LbCoreHandle *) == sizeof(void *), "Opaque handle pointer size check");

_Static_assert(sizeof(LbAbiHeader) == 16u, "LbAbiHeader size must be 16 bytes");
_Static_assert(_Alignof(LbAbiHeader) == 4u, "LbAbiHeader align must be 4 bytes");
_Static_assert((sizeof(LbEncodedFrameMeta) % 8u) == 0u, "LbEncodedFrameMeta must be 8-byte aligned");
_Static_assert((sizeof(LbOwnedBuffer) % sizeof(void *)) == 0u, "LbOwnedBuffer must align cleanly");
_Static_assert((sizeof(LbCoreConfig) % sizeof(void *)) == 0u, "LbCoreConfig must align cleanly");
_Static_assert((sizeof(LbCoreMetrics) % 8u) == 0u, "LbCoreMetrics must be 8-byte aligned");
_Static_assert((sizeof(LbGlobalResourceCounters) % 8u) == 0u, "LbGlobalResourceCounters must be 8-byte aligned");

void LbC11GetLayoutSignature(LbAbiLayoutSignature *out_sig) {
    if (out_sig == NULL) {
        return;
    }
    out_sig->abi.abi_major = LB_FFI_ABI_MAJOR;
    out_sig->abi.abi_minor = LB_FFI_ABI_MINOR;
    out_sig->abi.struct_size = (uint32_t)sizeof(LbAbiLayoutSignature);
    out_sig->abi.reserved = 0u;

    out_sig->size_abi_header = (uint32_t)sizeof(LbAbiHeader);
    out_sig->size_owned_buffer = (uint32_t)sizeof(LbOwnedBuffer);
    out_sig->size_encoded_frame_meta = (uint32_t)sizeof(LbEncodedFrameMeta);
    out_sig->size_core_config = (uint32_t)sizeof(LbCoreConfig);
    out_sig->size_core_metrics = (uint32_t)sizeof(LbCoreMetrics);
    out_sig->size_global_counters = (uint32_t)sizeof(LbGlobalResourceCounters);
    out_sig->offset_meta_codec = (uint32_t)offsetof(LbEncodedFrameMeta, codec);
    out_sig->offset_meta_gop_id = (uint32_t)offsetof(LbEncodedFrameMeta, gop_id);
    out_sig->offset_owned_release = (uint32_t)offsetof(LbOwnedBuffer, release);
    out_sig->offset_config_on_output = (uint32_t)offsetof(LbCoreConfig, on_output_packet);
}

LbStatus LbC11ProbeAbiVersion(uint32_t *out_major, uint32_t *out_minor) {
    return lb_core_abi_version(out_major, out_minor);
}
