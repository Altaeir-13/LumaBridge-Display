// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef LUMABRIDGE_INPUT_H
#define LUMABRIDGE_INPUT_H

/* Platform-agnostic normalized input contract (`lumabridge-input`, C11 / C++20 compatible).
 * All input permissions default to DENIED unless explicitly granted per-session with local consent. */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LB_INPUT_PERM_NONE    (0u)
#define LB_INPUT_PERM_POINTER (1u << 3)
#define LB_INPUT_PERM_KEYBOARD (1u << 4)
#define LB_INPUT_PERM_TOUCH   (1u << 5)
#define LB_INPUT_PERM_STYLUS  (1u << 6)

typedef enum LbInputEventKind {
    LB_INPUT_EVENT_POINTER_MOVE_ABS = 1,
    LB_INPUT_EVENT_POINTER_BUTTON = 2,
    LB_INPUT_EVENT_POINTER_SCROLL = 3,
    LB_INPUT_EVENT_KEY = 4,
    LB_INPUT_EVENT_TOUCH_CONTACT = 5,
    LB_INPUT_EVENT_STYLUS = 6
} LbInputEventKind;

typedef struct LbNormalizedInputEvent {
    uint32_t kind;
    uint16_t x_norm;
    uint16_t y_norm;
    uint16_t hid_usage_page;
    uint16_t hid_usage_id;
    int32_t scroll_delta_x_milli;
    int32_t scroll_delta_y_milli;
    uint16_t pressure_norm;
    uint8_t button_or_contact_id;
    uint8_t pressed_or_phase;
    int8_t tilt_x_deg;
    int8_t tilt_y_deg;
    uint8_t modifiers_or_buttons_mask;
    uint8_t reserved0;
} LbNormalizedInputEvent;

typedef struct LbInputBatchHeader {
    uint64_t session_id;
    uint64_t input_seq;
    uint16_t display_id;
    uint16_t event_count;
    uint32_t active_input_perm_mask;
} LbInputBatchHeader;

#ifdef __cplusplus
}
#endif

#endif /* LUMABRIDGE_INPUT_H */
