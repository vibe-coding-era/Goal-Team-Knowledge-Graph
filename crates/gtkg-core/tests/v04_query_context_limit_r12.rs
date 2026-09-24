//! Oversized output is rejected before reading any index, for every QK policy.
use gtkg_core::{CallContext,EffectPolicy,TransportKind,v04::query};
use gtkg_protocol::{FileReceiptRef,v04::{QueryPayload,Revision}};
#[test]
fn output_limit_is_checked_before_source_or_reviewed_index_io() {
    let dir=tempfile::tempdir().expect("temp");
    let ctx=CallContext::restricted(TransportKind::Test,vec![dir.path().to_owned()],EffectPolicy::ReadOnly).expect("context");
    for policy in ["gtkg.qk.query/v1","gtkg.qk.query/v2","gtkg.qk.query-reviewed-context/v1"] {
        let p=QueryPayload {payload_revision:Revision::R1,workspace_root:dir.path().to_owned(),index_ref:FileReceiptRef {path:"absent-index.json".into(),sha256:format!("sha256:{}","a".repeat(64))},query:"public boundary".into(),query_policy:policy.into(),max_results:1,max_tokens:8001,continuation:None};
        let error=query::search(&ctx,&p).expect_err("above output budget");
        assert!(error.contains("policy or bounds invalid"),"{policy}: should reject bounds before looking for an index: {error}");
        assert_eq!(std::fs::read_dir(dir.path()).expect("directory").count(),0);
    }
}
