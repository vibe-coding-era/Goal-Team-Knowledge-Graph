#![allow(clippy::unwrap_used)]
use super::*;
use crate::{EffectPolicy, TransportKind};
use std::fs;
use tempfile::TempDir;

fn context() -> (TempDir, CallContext) {
    let temp = TempDir::new().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let context =
        CallContext::restricted(TransportKind::Test, vec![root], EffectPolicy::ReadOnly).unwrap();
    (temp, context)
}
fn meter() -> QueryMeter {
    QueryMeter::new(
        QueryBudgetUsage::default(),
        QueryBudgetLimits::for_index(20_000),
    )
}

#[test]
fn metered_read_keeps_bytes_digest_and_consumption_from_the_same_read() {
    let (_temp, context) = context();
    let root = context.workspace_root().unwrap();
    let path = root.join("data.json");
    let first = b"{\"version\":1}";
    let second = b"{\"version\":2}";
    fs::write(&path, first).unwrap();
    let mut meter = meter();
    let original = meter.read_bound(&context, &path, 100).unwrap();
    assert_eq!(original.bytes(), first);
    assert_eq!(original.sha256(), artifact::digest(first));
    assert_eq!(original.bytes_read(), first.len() as u64);
    fs::rename(&path, root.join("old-data.json")).unwrap();
    fs::write(&path, second).unwrap();
    assert_eq!(original.bytes(), first);
    assert_eq!(original.sha256(), artifact::digest(first));
    let current = meter.read_bound(&context, &path, 100).unwrap();
    assert_eq!(current.bytes(), second);
    assert_eq!(current.sha256(), artifact::digest(second));
    assert_ne!(original.sha256(), current.sha256());
    assert_eq!(meter.usage().io_bytes, (first.len() + second.len()) as u64);
    let owned = original.into_bytes();
    assert_eq!(owned, first); // consumes and drops the digest capability
}

#[test]
fn metered_digest_and_decode_failures_keep_actual_prior_io() {
    let (_temp, context) = context();
    let root = context.workspace_root().unwrap();
    let path = root.join("data.json");
    let good = b"{\"ok\":true}";
    fs::write(&path, good).unwrap();
    let mut meter = meter();
    let reference = FileReceiptRef {
        path: "data.json".into(),
        sha256: artifact::digest(good),
    };
    let parsed: Value = meter
        .read_reference(&context, root, &reference, 100)
        .unwrap();
    assert_eq!(parsed["ok"], true);
    let bad = b"{\"ok\":false}";
    fs::write(&path, bad).unwrap();
    assert!(
        meter
            .read_reference::<Value>(&context, root, &reference, 100)
            .is_err()
    );
    assert_eq!(meter.usage().io_bytes, (good.len() + bad.len()) as u64);
    let invalid = b"not json";
    fs::write(&path, invalid).unwrap();
    let invalid_ref = ArtifactRef {
        path: "data.json".into(),
        sha256: artifact::digest(invalid),
        bytes: invalid.len() as u64,
    };
    assert!(
        meter
            .read_artifact::<Value>(&context, root, &invalid_ref)
            .is_err()
    );
    assert_eq!(
        meter.usage().io_bytes,
        (good.len() + bad.len() + invalid.len()) as u64
    );
}

#[test]
fn metered_cap_and_missing_file_errors_do_not_reset_consumption() {
    let (_temp, context) = context();
    let root = context.workspace_root().unwrap();
    let path = root.join("data.json");
    fs::write(&path, b"12345").unwrap();
    let mut meter = meter();
    assert_eq!(meter.read(&context, &path, 5).unwrap(), b"12345");
    let previous = meter.usage().io_bytes;
    assert!(meter.read_bound(&context, &path, 2).is_err());
    assert_eq!(
        meter.usage().io_bytes,
        previous,
        "opened-handle length rejection reads zero content bytes"
    );
    assert!(meter.read_bound(&context, &root.join("absent"), 5).is_err());
    assert_eq!(meter.usage().io_bytes, previous);
}
