//! Source posting reader shared by all explicit QK query policies.
use super::super::query_meter::{PostingRowsMode, QueryMeter};
use super::*;
use gtkg_protocol::FileReceiptRef;
use index::ArtifactRef;

pub(super) fn load(
    context: &CallContext,
    root: &Path,
    m: &IndexManifest,
    term: &str,
    meter: &mut QueryMeter,
    reads: &mut u64,
) -> Result<Vec<Posting>, String> {
    let bucket = index::token_bucket(term);
    let Some(reference) = m
        .router
        .get(&bucket)
        .ok_or("source posting router incomplete")?
    else {
        return Ok(vec![]);
    };
    let mut shard = read_source_posting_shard(context, root, reference, meter, reads)?;
    index::validate_posting_container(m, &shard, &bucket)?;
    if !shard.partitions.is_empty() {
        let hash = artifact::digest(term.as_bytes());
        let prefix = &hash[7..10];
        let Some(reference) = shard
            .partitions
            .get(prefix)
            .ok_or("source posting partition absent")?
        else {
            return Ok(vec![]);
        };
        shard = read_source_posting_shard(context, root, reference, meter, reads)?;
        index::validate_posting_container(m, &shard, prefix)?;
    }
    for rows in shard.terms.values() {
        let mut previous = None;
        for p in rows {
            index::validate_posting(m, p)?;
            if previous.is_some_and(|id: &str| id >= p.chunk_id.as_str()) {
                return Err("source postings duplicate or unordered".into());
            }
            previous = Some(p.chunk_id.as_str());
        }
    }
    let found = shard.terms.remove(term).unwrap_or_default();
    if found.len() > m.total_chunks {
        return Err("source df exceeds chunk denominator".into());
    }
    Ok(found)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PostingHeader {
    schema: String,
    snapshot_id: String,
    index_root: String,
    bucket: String,
    #[serde(default)]
    partitions: BTreeMap<String, Option<ArtifactRef>>,
}
fn read_source_posting_shard(
    context: &CallContext,
    root: &Path,
    reference: &ArtifactRef,
    meter: &mut QueryMeter,
    reads: &mut u64,
) -> Result<index::PostingShard, String> {
    FileReceiptRef {
        path: reference.path.clone(),
        sha256: reference.sha256.clone(),
    }
    .validate()
    .map_err(|e| e.to_string())?;
    let read = meter.read_bound(context, &root.join(&reference.path), reference.bytes)?;
    if read.bytes_read() != reference.bytes
        || read.bytes().len() as u64 != reference.bytes
        || read.sha256() != reference.sha256
    {
        return Err("source posting bytes/digest mismatch".into());
    }
    *reads = reads.saturating_add(1);
    let decoded = meter.decode_posting_rows::<Posting>(
        read.bytes(),
        PostingRowsMode::Terms,
        &[
            "schema",
            "snapshot_id",
            "index_root",
            "bucket",
            "partitions",
        ],
    )?;
    let header: PostingHeader =
        serde_json::from_value(Value::Object(decoded.header)).map_err(|e| e.to_string())?;
    Ok(index::PostingShard {
        schema: header.schema,
        snapshot_id: header.snapshot_id,
        index_root: header.index_root,
        bucket: header.bucket,
        partitions: header.partitions,
        terms: decoded.terms.ok_or("source posting terms absent")?,
    })
}
