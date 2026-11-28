// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use lumabridge_security::identity::{DeviceId, PublicIdentity};

fuzz_target!(|data: &[u8]| {
    let _ = DeviceId::from_spki_der(data);
    if let Ok(pub_id) = PublicIdentity::from_spki_der(data) {
        let split = data.len() / 2;
        let _ = pub_id.verify_strict(&data[..split], &data[split..]);
    }
});
