// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Operational encrypted `QUIC` (`RFC 9000` + `RFC 9221`) and `TCP / TLS 1.3` transport,
//! LAN discovery, DPLPMTUD/MTU budgeting, bounded media TX/RX scheduling, GOP recovery,
//! and peer-revocation connection management for `LumaBridge Display` (`M1.4`).

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::too_many_lines,
    clippy::cast_precision_loss
)]

pub mod config;
pub mod connection;
pub mod discovery;
pub mod error;
pub mod impairment;
pub mod metrics;
pub mod mtu;
pub mod queue;
pub mod quic;
pub mod tcp;
