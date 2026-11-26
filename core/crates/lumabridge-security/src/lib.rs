// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cryptographic identity, RFC 9266 channel binding, RFC 9382 SPAKE2 / QR pairing,
//! mTLS policy, trust store, revocation, and authorization for `LumaBridge`.

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]

pub mod anti_replay;
pub mod authorization;
pub mod certificate;
pub mod channel_binding;
pub mod error;
pub mod identity;
pub mod pairing;
pub mod rate_limit;
pub mod secret;
pub mod session_token;
pub mod tls;
pub mod transcript;
pub mod trust_store;
