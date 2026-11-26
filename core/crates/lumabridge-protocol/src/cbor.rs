// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Restricted deterministic CBOR profile (`LBWP-CBOR-v1`, RFC 8949 §4.2.1) built over `ciborium-ll`.
//!
//! # Guarantees
//! - Definite lengths only (no indefinite strings, arrays, maps, or `Break`).
//! - Minimal integer / length prefix widths enforced on every CBOR header.
//! - Maps restricted to non-negative integer keys (`Major Type 0`) in strictly ascending order.
//! - Duplicate keys rejected.
//! - Floats, semantic tags, `null`, `undefined`, and non-boolean simple values forbidden.
//! - Allocation bounds (`max_depth`, `max_map_entries`, `max_array_items`, `max_text_bytes`,
//!   `max_byte_string_bytes`, `max_total_items`, remaining input slice check) verified BEFORE allocating.
//! - Trailing bytes rejected.

use std::collections::BTreeSet;

use ciborium_ll::{Decoder, Encoder, Header};

use crate::error::CborError;
use crate::limits::CborLimits;

/// Decoding strictness mode distinguishing deterministic representation errors from
/// semantic compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CborDecodeMode {
    /// Normative RFC 8949 §4.2.1 mode: enforces minimal integer widths and strictly ascending map keys.
    #[default]
    StrictDeterministic,
    /// Diagnostic-only mode allowing non-minimal integer widths and unsorted map keys while still
    /// rejecting duplicate keys, forbidden types, indefinite lengths, invalid UTF-8, and bound violations.
    RelaxedOrderAndWidth,
}

/// Handling policy for unknown optional integer keys inside known CBOR message maps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnknownFieldPolicy {
    /// Validate unknown fields against all profile bounds/types/UTF-8 and skip up to
    /// `max_unknown_fields_per_map` entries.
    #[default]
    SkipBounded,
    /// Reject any unknown map key.
    Reject,
}

/// Combined decode options for `LBWP-CBOR-v1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CborDecodeOptions {
    pub limits: CborLimits,
    pub mode: CborDecodeMode,
    pub unknown_fields: UnknownFieldPolicy,
}

const fn minimal_arg_header_len(arg: u64) -> usize {
    if arg <= 23 {
        1
    } else if arg <= u8::MAX as u64 {
        2
    } else if arg <= u16::MAX as u64 {
        3
    } else if arg <= u32::MAX as u64 {
        5
    } else {
        9
    }
}

/// Deterministic CBOR encoder wrapper writing RFC 8949 §4.2.1 preferred representations.
pub struct CborMapEncoder<'a> {
    out: &'a mut Vec<u8>,
    last_key: Option<u64>,
    expected_entries: usize,
    written_entries: usize,
}

impl<'a> CborMapEncoder<'a> {
    /// Start encoding a definite-length CBOR map with `entry_count` entries.
    pub fn start(out: &'a mut Vec<u8>, entry_count: usize) -> Result<Self, CborError> {
        Encoder::from(&mut *out)
            .push(Header::Map(Some(entry_count)))
            .map_err(|_| CborError::EncodeBufferError)?;
        Ok(Self {
            out,
            last_key: None,
            expected_entries: entry_count,
            written_entries: 0,
        })
    }

    fn write_key(&mut self, key: u64) -> Result<(), CborError> {
        if let Some(prev) = self.last_key {
            if key <= prev {
                return Err(CborError::UnsortedMapKeys);
            }
        }
        if self.written_entries >= self.expected_entries {
            return Err(CborError::EncodeBufferError);
        }
        self.last_key = Some(key);
        self.written_entries += 1;
        Encoder::from(&mut *self.out)
            .push(Header::Positive(key))
            .map_err(|_| CborError::EncodeBufferError)
    }

    /// Encode an unsigned integer (`u64`) field under `key`.
    pub fn put_u64(&mut self, key: u64, val: u64) -> Result<(), CborError> {
        self.write_key(key)?;
        Encoder::from(&mut *self.out)
            .push(Header::Positive(val))
            .map_err(|_| CborError::EncodeBufferError)
    }

    /// Encode a signed integer (`i64`) field under `key`.
    pub fn put_i64(&mut self, key: u64, val: i64) -> Result<(), CborError> {
        self.write_key(key)?;
        let mut encoder = Encoder::from(&mut *self.out);
        write_i64(&mut encoder, val)
    }

    /// Encode a boolean field under `key`.
    pub fn put_bool(&mut self, key: u64, val: bool) -> Result<(), CborError> {
        self.write_key(key)?;
        Encoder::from(&mut *self.out)
            .push(Header::Simple(if val { 21 } else { 20 }))
            .map_err(|_| CborError::EncodeBufferError)
    }

    /// Encode a definite-length byte string field under `key`.
    pub fn put_bytes(&mut self, key: u64, val: &[u8]) -> Result<(), CborError> {
        self.write_key(key)?;
        Encoder::from(&mut *self.out)
            .bytes(val, None)
            .map_err(|_| CborError::EncodeBufferError)
    }

    /// Encode a definite-length UTF-8 text string field under `key`.
    pub fn put_text(&mut self, key: u64, val: &str) -> Result<(), CborError> {
        self.write_key(key)?;
        Encoder::from(&mut *self.out)
            .text(val, None)
            .map_err(|_| CborError::EncodeBufferError)
    }

    /// Encode a definite-length array field using a caller closure.
    pub fn put_array_with<F>(&mut self, key: u64, len: usize, f: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut CborArrayEncoder<'_>) -> Result<(), CborError>,
    {
        self.write_key(key)?;
        let mut arr = CborArrayEncoder::start(self.out, len)?;
        f(&mut arr)?;
        arr.finish()
    }

    /// Finish encoding and assert the declared map length matches written entries.
    pub fn finish(self) -> Result<(), CborError> {
        if self.written_entries != self.expected_entries {
            return Err(CborError::EncodeBufferError);
        }
        Ok(())
    }
}

/// Deterministic CBOR array encoder wrapper.
pub struct CborArrayEncoder<'a> {
    out: &'a mut Vec<u8>,
    expected_items: usize,
    written_items: usize,
}

impl<'a> CborArrayEncoder<'a> {
    /// Start encoding a definite-length CBOR array.
    pub fn start(out: &'a mut Vec<u8>, len: usize) -> Result<Self, CborError> {
        Encoder::from(&mut *out)
            .push(Header::Array(Some(len)))
            .map_err(|_| CborError::EncodeBufferError)?;
        Ok(Self {
            out,
            expected_items: len,
            written_items: 0,
        })
    }

    /// Push an unsigned integer element.
    pub fn push_u64(&mut self, val: u64) -> Result<(), CborError> {
        if self.written_items >= self.expected_items {
            return Err(CborError::EncodeBufferError);
        }
        self.written_items += 1;
        Encoder::from(&mut *self.out)
            .push(Header::Positive(val))
            .map_err(|_| CborError::EncodeBufferError)
    }

    /// Push a nested deterministic map built by `f`.
    pub fn push_map_with<F>(&mut self, entry_count: usize, f: F) -> Result<(), CborError>
    where
        F: FnOnce(&mut CborMapEncoder<'_>) -> Result<(), CborError>,
    {
        if self.written_items >= self.expected_items {
            return Err(CborError::EncodeBufferError);
        }
        self.written_items += 1;
        let mut map = CborMapEncoder::start(self.out, entry_count)?;
        f(&mut map)?;
        map.finish()
    }

    /// Finish encoding and assert all declared elements were written.
    pub fn finish(self) -> Result<(), CborError> {
        if self.written_items != self.expected_items {
            return Err(CborError::EncodeBufferError);
        }
        Ok(())
    }
}

fn write_i64(encoder: &mut Encoder<&mut Vec<u8>>, val: i64) -> Result<(), CborError> {
    if val >= 0 {
        encoder
            .push(Header::Positive(val.cast_unsigned()))
            .map_err(|_| CborError::EncodeBufferError)
    } else {
        // CBOR negative integer encodes `n = -1 - val` where `val < 0`.
        let encoded_n =
            u64::try_from(-1i128 - i128::from(val)).map_err(|_| CborError::EncodeBufferError)?;
        encoder
            .push(Header::Negative(encoded_n))
            .map_err(|_| CborError::EncodeBufferError)
    }
}

/// Stateful pull-based restricted CBOR decoder enforcing `LBWP-CBOR-v1`.
pub struct CborReader<'a> {
    decoder: Decoder<&'a [u8]>,
    total_len: usize,
    options: CborDecodeOptions,
    items_seen: usize,
}

impl<'a> CborReader<'a> {
    /// Construct a reader over an untrusted CBOR byte slice and validate profile limits.
    pub fn new(input: &'a [u8], options: CborDecodeOptions) -> Result<Self, CborError> {
        options
            .limits
            .validate()
            .map_err(|_| CborError::LimitExceeded("invalid CBOR limits configuration"))?;
        Ok(Self {
            decoder: Decoder::from(input),
            total_len: input.len(),
            options,
            items_seen: 0,
        })
    }

    fn remaining(&mut self) -> usize {
        self.total_len.saturating_sub(self.decoder.offset())
    }

    fn bump_item_count(&mut self) -> Result<(), CborError> {
        self.items_seen = self.items_seen.saturating_add(1);
        if self.items_seen > self.options.limits.max_total_items {
            return Err(CborError::LimitExceeded("max_total_items exceeded"));
        }
        Ok(())
    }

    fn pull_checked(&mut self) -> Result<Header, CborError> {
        self.bump_item_count()?;
        let start = self.decoder.offset();
        let hdr = self.decoder.pull().map_err(|e| map_ll_error(&e))?;
        let header_bytes = self.decoder.offset().saturating_sub(start);

        match hdr {
            Header::Positive(v) | Header::Negative(v) => {
                if self.options.mode == CborDecodeMode::StrictDeterministic
                    && header_bytes != minimal_arg_header_len(v)
                {
                    return Err(CborError::NonMinimalInteger);
                }
            }
            Header::Bytes(None)
            | Header::Text(None)
            | Header::Array(None)
            | Header::Map(None)
            | Header::Break => {
                return Err(CborError::IndefiniteLengthForbidden);
            }
            Header::Bytes(Some(n))
            | Header::Text(Some(n))
            | Header::Array(Some(n))
            | Header::Map(Some(n)) => {
                if self.options.mode == CborDecodeMode::StrictDeterministic
                    && header_bytes != minimal_arg_header_len(n as u64)
                {
                    return Err(CborError::NonMinimalInteger);
                }
            }
            Header::Tag(_) => return Err(CborError::ForbiddenType("CBOR tag")),
            Header::Float(_) => return Err(CborError::ForbiddenType("CBOR float")),
            Header::Simple(20 | 21) => {
                if self.options.mode == CborDecodeMode::StrictDeterministic && header_bytes != 1 {
                    return Err(CborError::NonMinimalInteger);
                }
            }
            Header::Simple(22) => return Err(CborError::ForbiddenType("CBOR null")),
            Header::Simple(23) => return Err(CborError::ForbiddenType("CBOR undefined")),
            Header::Simple(_) => return Err(CborError::ForbiddenType("CBOR simple value")),
        }

        Ok(hdr)
    }

    /// Assert that the entire CBOR input slice was consumed with zero trailing bytes.
    pub fn finish_exact(&mut self) -> Result<(), CborError> {
        if self.decoder.offset() != self.total_len {
            return Err(CborError::TrailingBytes);
        }
        Ok(())
    }

    /// Read a root CBOR map and invoke `handler` for every key-value pair while enforcing
    /// key uniqueness, deterministic ordering, depth limits, and bounded unknown-field skipping.
    pub fn read_map<F>(&mut self, depth: usize, mut handler: F) -> Result<(), CborError>
    where
        F: FnMut(&mut Self, u64) -> Result<bool, CborError>,
    {
        if depth > self.options.limits.max_depth {
            return Err(CborError::DepthExceeded);
        }
        let Header::Map(Some(entries)) = self.pull_checked()? else {
            return Err(CborError::TypeMismatch("expected CBOR map"));
        };
        if entries > self.options.limits.max_map_entries {
            return Err(CborError::LimitExceeded("max_map_entries exceeded"));
        }
        // Each map entry needs at least 2 bytes (1B key + 1B value) on the wire.
        let min_bytes = entries.saturating_mul(2);
        if min_bytes > self.remaining() {
            return Err(CborError::Truncated);
        }

        let mut prev_key: Option<u64> = None;
        let mut seen_relaxed = if self.options.mode == CborDecodeMode::RelaxedOrderAndWidth {
            Some(BTreeSet::new())
        } else {
            None
        };
        let mut unknown_count = 0usize;

        for _ in 0..entries {
            let Header::Positive(key) = self.pull_checked()? else {
                return Err(CborError::ForbiddenType("map key must be unsigned integer"));
            };

            match self.options.mode {
                CborDecodeMode::StrictDeterministic => {
                    if let Some(prev) = prev_key {
                        if key == prev {
                            return Err(CborError::DuplicateMapKey);
                        }
                        if key < prev {
                            return Err(CborError::UnsortedMapKeys);
                        }
                    }
                    prev_key = Some(key);
                }
                CborDecodeMode::RelaxedOrderAndWidth => {
                    if let Some(set) = seen_relaxed.as_mut() {
                        if !set.insert(key) {
                            return Err(CborError::DuplicateMapKey);
                        }
                    }
                }
            }

            let was_known = handler(self, key)?;
            if !was_known {
                if self.options.unknown_fields == UnknownFieldPolicy::Reject {
                    return Err(CborError::TypeMismatch("unknown map field rejected"));
                }
                unknown_count = unknown_count.saturating_add(1);
                if unknown_count > self.options.limits.max_unknown_fields_per_map {
                    return Err(CborError::LimitExceeded(
                        "max_unknown_fields_per_map exceeded",
                    ));
                }
                self.skip_value_bounded(depth + 1)?;
            }
        }

        Ok(())
    }

    /// Read a definite-length array up to `max_items` and invoke `item_fn` for each item.
    pub fn read_array<F>(
        &mut self,
        depth: usize,
        max_items: usize,
        field_name: &'static str,
        mut item_fn: F,
    ) -> Result<(), CborError>
    where
        F: FnMut(&mut Self, usize) -> Result<(), CborError>,
    {
        if depth > self.options.limits.max_depth {
            return Err(CborError::DepthExceeded);
        }
        let Header::Array(Some(len)) = self.pull_checked()? else {
            return Err(CborError::TypeMismatch(field_name));
        };
        let effective_max = max_items.min(self.options.limits.max_array_items);
        if len > effective_max {
            return Err(CborError::LimitExceeded(field_name));
        }
        // Each item occupies at least 1 byte.
        if len > self.remaining() {
            return Err(CborError::Truncated);
        }
        for idx in 0..len {
            item_fn(self, idx)?;
        }
        Ok(())
    }

    /// Read an unsigned integer field value (`u64`).
    pub fn read_u64(&mut self, field_name: &'static str) -> Result<u64, CborError> {
        match self.pull_checked()? {
            Header::Positive(v) => Ok(v),
            _ => Err(CborError::TypeMismatch(field_name)),
        }
    }

    /// Read an unsigned integer bounded to `u32`.
    pub fn read_u32(&mut self, field_name: &'static str) -> Result<u32, CborError> {
        let v = self.read_u64(field_name)?;
        u32::try_from(v).map_err(|_| CborError::ValueOutOfRange(field_name))
    }

    /// Read an unsigned integer bounded to `u16`.
    pub fn read_u16(&mut self, field_name: &'static str) -> Result<u16, CborError> {
        let v = self.read_u64(field_name)?;
        u16::try_from(v).map_err(|_| CborError::ValueOutOfRange(field_name))
    }

    /// Read a signed integer (`i64`) field value.
    pub fn read_i64(&mut self, field_name: &'static str) -> Result<i64, CborError> {
        match self.pull_checked()? {
            Header::Positive(v) => {
                i64::try_from(v).map_err(|_| CborError::ValueOutOfRange(field_name))
            }
            Header::Negative(n) => {
                let pos = i64::try_from(n).map_err(|_| CborError::ValueOutOfRange(field_name))?;
                (-1i64)
                    .checked_sub(pos)
                    .ok_or(CborError::ValueOutOfRange(field_name))
            }
            _ => Err(CborError::TypeMismatch(field_name)),
        }
    }

    /// Read a strict CBOR boolean (`false` / `true`).
    pub fn read_bool(&mut self, field_name: &'static str) -> Result<bool, CborError> {
        match self.pull_checked()? {
            Header::Simple(20) => Ok(false),
            Header::Simple(21) => Ok(true),
            _ => Err(CborError::TypeMismatch(field_name)),
        }
    }

    /// Read a definite-length byte string enforcing `max_len` and remaining slice length BEFORE allocation.
    pub fn read_bytes(
        &mut self,
        max_len: usize,
        field_name: &'static str,
    ) -> Result<Vec<u8>, CborError> {
        let Header::Bytes(Some(len)) = self.pull_checked()? else {
            return Err(CborError::TypeMismatch(field_name));
        };
        let effective_max = max_len.min(self.options.limits.max_byte_string_bytes);
        if len > effective_max {
            return Err(CborError::LimitExceeded(field_name));
        }
        if len > self.remaining() {
            return Err(CborError::Truncated);
        }

        let mut out = Vec::with_capacity(len);
        let mut segments = self.decoder.bytes(Some(len));
        let mut scratch = [0u8; 256];
        while let Some(mut segment) = segments.pull().map_err(|e| map_ll_error(&e))? {
            while let Some(chunk) = segment.pull(&mut scratch).map_err(|e| map_ll_error(&e))? {
                out.extend_from_slice(chunk);
            }
        }
        if out.len() != len {
            return Err(CborError::Truncated);
        }
        Ok(out)
    }

    /// Read a definite-length UTF-8 text string enforcing `max_bytes` and remaining slice length BEFORE allocation.
    pub fn read_text(
        &mut self,
        max_bytes: usize,
        field_name: &'static str,
    ) -> Result<String, CborError> {
        let Header::Text(Some(len)) = self.pull_checked()? else {
            return Err(CborError::TypeMismatch(field_name));
        };
        let effective_max = max_bytes.min(self.options.limits.max_text_bytes);
        if len > effective_max {
            return Err(CborError::LimitExceeded(field_name));
        }
        if len > self.remaining() {
            return Err(CborError::Truncated);
        }

        let mut out = String::with_capacity(len);
        let mut segments = self.decoder.text(Some(len));
        let mut scratch = [0u8; 256];
        while let Some(mut segment) = segments.pull().map_err(|e| map_ll_text_error(&e))? {
            while let Some(chunk) = segment
                .pull(&mut scratch)
                .map_err(|e| map_ll_text_error(&e))?
            {
                out.push_str(chunk);
            }
        }
        if out.len() != len {
            return Err(CborError::Truncated);
        }
        Ok(out)
    }

    fn skip_value_bounded(&mut self, depth: usize) -> Result<(), CborError> {
        if depth > self.options.limits.max_depth {
            return Err(CborError::DepthExceeded);
        }
        match self.pull_checked()? {
            Header::Positive(_) | Header::Negative(_) | Header::Simple(20 | 21) => Ok(()),
            Header::Bytes(Some(len)) => {
                if len > self.options.limits.max_byte_string_bytes {
                    return Err(CborError::LimitExceeded("unknown field bstr too large"));
                }
                if len > self.remaining() {
                    return Err(CborError::Truncated);
                }
                let mut segments = self.decoder.bytes(Some(len));
                let mut scratch = [0u8; 256];
                while let Some(mut segment) = segments.pull().map_err(|e| map_ll_error(&e))? {
                    while segment
                        .pull(&mut scratch)
                        .map_err(|e| map_ll_error(&e))?
                        .is_some()
                    {}
                }
                Ok(())
            }
            Header::Text(Some(len)) => {
                if len > self.options.limits.max_text_bytes {
                    return Err(CborError::LimitExceeded("unknown field tstr too large"));
                }
                if len > self.remaining() {
                    return Err(CborError::Truncated);
                }
                let mut segments = self.decoder.text(Some(len));
                let mut scratch = [0u8; 256];
                while let Some(mut segment) = segments.pull().map_err(|e| map_ll_text_error(&e))? {
                    while segment
                        .pull(&mut scratch)
                        .map_err(|e| map_ll_text_error(&e))?
                        .is_some()
                    {}
                }
                Ok(())
            }
            Header::Array(Some(len)) => {
                if len > self.options.limits.max_array_items {
                    return Err(CborError::LimitExceeded("unknown field array too large"));
                }
                if len > self.remaining() {
                    return Err(CborError::Truncated);
                }
                for _ in 0..len {
                    self.skip_value_bounded(depth + 1)?;
                }
                Ok(())
            }
            Header::Map(Some(entries)) => {
                if entries > self.options.limits.max_map_entries {
                    return Err(CborError::LimitExceeded("unknown field map too large"));
                }
                if entries.saturating_mul(2) > self.remaining() {
                    return Err(CborError::Truncated);
                }
                let mut prev_key: Option<u64> = None;
                let mut seen_relaxed = if self.options.mode == CborDecodeMode::RelaxedOrderAndWidth
                {
                    Some(BTreeSet::new())
                } else {
                    None
                };
                for _ in 0..entries {
                    let Header::Positive(k) = self.pull_checked()? else {
                        return Err(CborError::ForbiddenType(
                            "unknown nested map key must be unsigned integer",
                        ));
                    };
                    match self.options.mode {
                        CborDecodeMode::StrictDeterministic => {
                            if let Some(prev) = prev_key {
                                if k == prev {
                                    return Err(CborError::DuplicateMapKey);
                                }
                                if k < prev {
                                    return Err(CborError::UnsortedMapKeys);
                                }
                            }
                            prev_key = Some(k);
                        }
                        CborDecodeMode::RelaxedOrderAndWidth => {
                            if let Some(set) = seen_relaxed.as_mut() {
                                if !set.insert(k) {
                                    return Err(CborError::DuplicateMapKey);
                                }
                            }
                        }
                    }
                    self.skip_value_bounded(depth + 1)?;
                }
                Ok(())
            }
            _ => Err(CborError::ForbiddenType("unsupported CBOR item")),
        }
    }
}

fn map_ll_error<E>(err: &ciborium_ll::Error<E>) -> CborError {
    match err {
        ciborium_ll::Error::Io(_) => CborError::Truncated,
        ciborium_ll::Error::Syntax(_) => CborError::ForbiddenType("malformed CBOR syntax"),
    }
}

fn map_ll_text_error<E>(err: &ciborium_ll::Error<E>) -> CborError {
    match err {
        ciborium_ll::Error::Io(_) => CborError::Truncated,
        ciborium_ll::Error::Syntax(_) => CborError::InvalidUtf8,
    }
}
