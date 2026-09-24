//! Cumulative, in-memory query accounting. No runtime or canonical files are written.
use super::{artifact, index::ArtifactRef};
use crate::{CallContext, exact_read::read_bound_regular_file_limited};
use gtkg_protocol::FileReceiptRef;
use serde::{
    Deserialize, Serialize,
    de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    marker::PhantomData,
    path::Path,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostingRowsMode {
    Rows,
    Terms,
}

#[derive(Debug)]
pub struct PostingEnvelope<T> {
    pub header: Map<String, Value>,
    pub rows: Option<Vec<T>>,
    pub terms: Option<BTreeMap<String, Vec<T>>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryBudgetUsage {
    pub io_bytes: u64,
    pub wall_time_us: u64,
    pub posting_rows: u64,
    pub candidate_count: u64,
    pub initial_subqueries: u32,
    pub structural_expansions: u32,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryBudgetLimits {
    pub io_bytes: u64,
    pub wall_time_us: u64,
    pub posting_rows: u64,
    pub candidate_count: u64,
    pub initial_subqueries: u32,
    pub structural_expansions: u32,
}
impl QueryBudgetLimits {
    pub fn for_index(total_index_bytes: u64) -> Self {
        Self {
            io_bytes: (total_index_bytes / 20).min(64 * 1024 * 1024),
            wall_time_us: 5_000_000,
            posting_rows: 100_000,
            candidate_count: 2_000,
            initial_subqueries: 4,
            structural_expansions: 2,
        }
    }
    pub fn validate(&self) -> Result<(), String> {
        let fixed = Self::for_index(0);
        if self.io_bytes > 64 * 1024 * 1024
            || self.wall_time_us != fixed.wall_time_us
            || self.posting_rows != fixed.posting_rows
            || self.candidate_count != fixed.candidate_count
            || self.initial_subqueries != fixed.initial_subqueries
            || self.structural_expansions != fixed.structural_expansions
        {
            return Err("query budget limits differ from the frozen contract".into());
        }
        Ok(())
    }
}
#[derive(Debug)]
pub struct QueryMeter {
    consumed: QueryBudgetUsage,
    limits: QueryBudgetLimits,
    started: Instant,
}

/// Immutable bytes, digest and consumed byte count from one opened-handle read.
/// Only QueryMeter constructs it, after accounting for the read and its errors.
/// Borrowing the bytes cannot invalidate the accompanying digest.
pub(crate) struct MeteredRead {
    bytes: Vec<u8>,
    sha256: String,
    bytes_read: u64,
}

impl MeteredRead {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }

    pub(crate) fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl QueryMeter {
    pub fn new(usage: QueryBudgetUsage, limits: QueryBudgetLimits) -> Self {
        Self {
            consumed: usage,
            limits,
            started: Instant::now(),
        }
    }
    pub fn usage(&self) -> QueryBudgetUsage {
        let mut value = self.consumed.clone();
        value.wall_time_us = value
            .wall_time_us
            .saturating_add(self.started.elapsed().as_micros().min(u64::MAX as u128) as u64);
        value
    }
    pub fn limits(&self) -> &QueryBudgetLimits {
        &self.limits
    }
    pub fn remaining_io(&self) -> u64 {
        self.limits.io_bytes.saturating_sub(self.consumed.io_bytes)
    }
    pub fn check_time(&self) -> Result<(), String> {
        if self.usage().wall_time_us >= self.limits.wall_time_us {
            Err("E_QUERY_WALL_TIME_BUDGET".into())
        } else {
            Ok(())
        }
    }
    /// Bootstrap reads were bounded independently. Add, never replace, their cost.
    pub fn inherit(
        &mut self,
        prior: QueryBudgetUsage,
        limits: QueryBudgetLimits,
    ) -> Result<(), String> {
        limits.validate()?;
        self.consumed.io_bytes = self.consumed.io_bytes.saturating_add(prior.io_bytes);
        self.consumed.wall_time_us = self
            .consumed
            .wall_time_us
            .saturating_add(prior.wall_time_us);
        self.consumed.posting_rows = self
            .consumed
            .posting_rows
            .saturating_add(prior.posting_rows);
        self.consumed.candidate_count = self
            .consumed
            .candidate_count
            .saturating_add(prior.candidate_count);
        self.consumed.initial_subqueries = self
            .consumed
            .initial_subqueries
            .saturating_add(prior.initial_subqueries);
        self.consumed.structural_expansions = self
            .consumed
            .structural_expansions
            .saturating_add(prior.structural_expansions);
        self.limits = limits;
        Ok(())
    }
    pub fn charge_postings(&mut self, rows: u64) -> Result<(), String> {
        self.consumed.posting_rows = self.consumed.posting_rows.saturating_add(rows);
        if self.consumed.posting_rows > self.limits.posting_rows {
            Err("E_QUERY_POSTING_BUDGET".into())
        } else {
            self.check_time()
        }
    }
    /// Decode each actual row only after admission to the shared posting budget.
    /// Header keys are a whitelist; the caller validates required header values.
    pub fn decode_posting_rows<T: DeserializeOwned>(
        &mut self,
        raw: &[u8],
        mode: PostingRowsMode,
        header_keys: &[&str],
    ) -> Result<PostingEnvelope<T>, String> {
        self.check_time()?;
        let allowed: BTreeSet<_> = header_keys.iter().map(|s| s.to_string()).collect();
        if allowed.len() != header_keys.len()
            || allowed.contains("rows")
            || allowed.contains("terms")
        {
            return Err("invalid posting header whitelist".into());
        }
        let mut decoder = serde_json::Deserializer::from_slice(raw);
        let result = EnvelopeSeed::<T> {
            meter: self,
            mode,
            allowed,
            marker: PhantomData,
        }
        .deserialize(&mut decoder)
        .map_err(posting_decode_error)?;
        decoder.end().map_err(posting_decode_error)?;
        self.check_time()?;
        Ok(result)
    }
    pub fn read(
        &mut self,
        context: &CallContext,
        path: &Path,
        max_bytes: u64,
    ) -> Result<Vec<u8>, String> {
        self.read_bound(context, path, max_bytes)
            .map(MeteredRead::into_bytes)
    }

    pub(crate) fn read_bound(
        &mut self,
        context: &CallContext,
        path: &Path,
        max_bytes: u64,
    ) -> Result<MeteredRead, String> {
        self.check_time()?;
        let available = self.remaining_io();
        if available == 0 {
            return Err("E_QUERY_IO_BUDGET".into());
        }
        let max = available.min(max_bytes);
        let remaining_us = self
            .limits
            .wall_time_us
            .saturating_sub(self.usage().wall_time_us);
        let deadline = Instant::now().checked_add(Duration::from_micros(remaining_us));
        let mut actual = 0;
        let result = read_bound_regular_file_limited(context, path, max, deadline, &mut actual);
        self.consumed.io_bytes = self.consumed.io_bytes.saturating_add(actual);
        let read = result.map_err(|error| {
            if error.message == "E_EXACT_READ_BYTE_LIMIT" && available <= max_bytes {
                "E_QUERY_IO_BUDGET".into()
            } else {
                error.message
            }
        })?;
        self.check_time()?;
        Ok(MeteredRead {
            bytes: read.bytes,
            sha256: read.sha256,
            bytes_read: actual,
        })
    }
    pub fn read_reference<T: DeserializeOwned>(
        &mut self,
        context: &CallContext,
        workspace: &Path,
        reference: &FileReceiptRef,
        max_bytes: u64,
    ) -> Result<T, String> {
        reference.validate().map_err(|e| e.to_string())?;
        let root = artifact::workspace(context, workspace)?;
        let read = self.read_bound(context, &root.join(&reference.path), max_bytes)?;
        if read.sha256() != reference.sha256 {
            return Err("artifact digest mismatch".into());
        }
        serde_json::from_slice(read.bytes()).map_err(|e| e.to_string())
    }
    pub fn read_artifact<T: DeserializeOwned>(
        &mut self,
        context: &CallContext,
        workspace: &Path,
        reference: &ArtifactRef,
    ) -> Result<T, String> {
        let reference_without_len = FileReceiptRef {
            path: reference.path.clone(),
            sha256: reference.sha256.clone(),
        };
        reference_without_len
            .validate()
            .map_err(|e| e.to_string())?;
        let root = artifact::workspace(context, workspace)?;
        let read = self.read_bound(context, &root.join(&reference.path), reference.bytes)?;
        if read.bytes_read() != reference.bytes
            || read.bytes().len() as u64 != reference.bytes
            || read.sha256() != reference.sha256
        {
            return Err("artifact bytes/digest mismatch".into());
        }
        serde_json::from_slice(read.bytes()).map_err(|e| e.to_string())
    }
}

fn posting_decode_error(error: serde_json::Error) -> String {
    let message = error.to_string();
    for code in ["E_QUERY_POSTING_BUDGET", "E_QUERY_WALL_TIME_BUDGET"] {
        if message.starts_with(code) {
            return code.into();
        }
    }
    message
}

#[cfg(test)]
#[path = "../../tests/support/v04_metered_read_boundaries.rs"]
mod metered_read_boundary_tests;

struct RowSeed<'a, T> {
    meter: &'a mut QueryMeter,
    marker: PhantomData<T>,
}
impl<'de, T: Deserialize<'de>> DeserializeSeed<'de> for RowSeed<'_, T> {
    type Value = T;
    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<T, D::Error> {
        // SeqAccess calls this seed only when a next element actually exists.
        // Therefore an empty array at the exact limit is valid, while an excess
        // row is rejected before T::deserialize observes any of its body.
        if self.meter.consumed.posting_rows >= self.meter.limits.posting_rows {
            return Err(de::Error::custom("E_QUERY_POSTING_BUDGET"));
        }
        self.meter.check_time().map_err(de::Error::custom)?;
        self.meter.charge_postings(1).map_err(de::Error::custom)?;
        T::deserialize(decoder)
    }
}
struct RowsSeed<'a, T> {
    meter: &'a mut QueryMeter,
    marker: PhantomData<T>,
}
impl<'de, T: Deserialize<'de>> DeserializeSeed<'de> for RowsSeed<'_, T> {
    type Value = Vec<T>;
    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Vec<T>, D::Error> {
        decoder.deserialize_seq(self)
    }
}
impl<'de, T: Deserialize<'de>> Visitor<'de> for RowsSeed<'_, T> {
    type Value = Vec<T>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a bounded posting row array")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut rows: A) -> Result<Vec<T>, A::Error> {
        let mut output = Vec::new();
        while let Some(row) = rows.next_element_seed(RowSeed {
            meter: &mut *self.meter,
            marker: PhantomData,
        })? {
            output.push(row);
        }
        Ok(output)
    }
}
struct TermsSeed<'a, T> {
    meter: &'a mut QueryMeter,
    marker: PhantomData<T>,
}
impl<'de, T: Deserialize<'de>> DeserializeSeed<'de> for TermsSeed<'_, T> {
    type Value = BTreeMap<String, Vec<T>>;
    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        decoder.deserialize_map(self)
    }
}
impl<'de, T: Deserialize<'de>> Visitor<'de> for TermsSeed<'_, T> {
    type Value = BTreeMap<String, Vec<T>>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("term names mapped to bounded posting row arrays")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut terms: A) -> Result<Self::Value, A::Error> {
        let mut output = BTreeMap::new();
        while let Some(term) = terms.next_key::<String>()? {
            self.meter.check_time().map_err(de::Error::custom)?;
            if output.contains_key(&term) {
                return Err(de::Error::custom(format!("duplicate posting term: {term}")));
            }
            let rows = terms.next_value_seed(RowsSeed {
                meter: &mut *self.meter,
                marker: PhantomData,
            })?;
            output.insert(term, rows);
        }
        Ok(output)
    }
}
struct EnvelopeSeed<'a, T> {
    meter: &'a mut QueryMeter,
    mode: PostingRowsMode,
    allowed: BTreeSet<String>,
    marker: PhantomData<T>,
}
impl<'de, T: Deserialize<'de>> DeserializeSeed<'de> for EnvelopeSeed<'_, T> {
    type Value = PostingEnvelope<T>;
    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        decoder.deserialize_map(self)
    }
}
impl<'de, T: Deserialize<'de>> Visitor<'de> for EnvelopeSeed<'_, T> {
    type Value = PostingEnvelope<T>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a closed posting envelope")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut fields: A) -> Result<Self::Value, A::Error> {
        let mut output = PostingEnvelope {
            header: Map::new(),
            rows: None,
            terms: None,
        };
        let mut seen = BTreeSet::new();
        while let Some(key) = fields.next_key::<String>()? {
            self.meter.check_time().map_err(de::Error::custom)?;
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom(format!(
                    "duplicate posting envelope field: {key}"
                )));
            }
            if key == "rows" && self.mode == PostingRowsMode::Rows {
                output.rows = Some(fields.next_value_seed(RowsSeed {
                    meter: &mut *self.meter,
                    marker: PhantomData,
                })?);
            } else if key == "terms" && self.mode == PostingRowsMode::Terms {
                output.terms = Some(fields.next_value_seed(TermsSeed {
                    meter: &mut *self.meter,
                    marker: PhantomData,
                })?);
            } else if self.allowed.contains(&key) {
                output.header.insert(key, fields.next_value::<Value>()?);
            } else {
                // Do not deserialize the value of an unknown/other-mode field.
                return Err(de::Error::custom(format!(
                    "unknown posting envelope field: {key}"
                )));
            }
        }
        if (self.mode == PostingRowsMode::Rows && output.rows.is_none())
            || (self.mode == PostingRowsMode::Terms && output.terms.is_none())
        {
            return Err(de::Error::custom("posting envelope body field missing"));
        }
        Ok(output)
    }
}
