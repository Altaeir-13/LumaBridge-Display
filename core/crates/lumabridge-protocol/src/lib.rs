// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Transport-independent, bounded, deterministic implementation of the `LumaBridge` Wire Protocol (`LBWP v1`).

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]

pub mod cbor;
pub mod control;
pub mod error;
pub mod framing;
pub mod limits;
pub mod validation;
pub mod version;
