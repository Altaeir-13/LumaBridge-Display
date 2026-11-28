// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use lumabridge_security::certificate::verify_self_signed_ed25519_cert;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        let _ = verify_self_signed_ed25519_cert(data, 1_700_000_500);
        return;
    }
    let now = u64::from_be_bytes(data[..8].try_into().unwrap_or([0; 8]));
    let _ = verify_self_signed_ed25519_cert(&data[8..], now);
});
