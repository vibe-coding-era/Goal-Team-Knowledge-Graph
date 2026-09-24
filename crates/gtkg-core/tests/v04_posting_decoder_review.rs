//! Public synthetic row decoding boundary: no source/model/target execution.
#![allow(clippy::unwrap_used)]
use gtkg_core::v04::query_meter::{PostingRowsMode,QueryBudgetLimits,QueryBudgetUsage,QueryMeter};
use serde::{Deserialize,Deserializer};
use serde_json::json;
use std::sync::atomic::{AtomicUsize,Ordering};

static ATTEMPTS:AtomicUsize=AtomicUsize::new(0);
#[derive(Debug)]
struct Row { n:u32 }
impl<'de> Deserialize<'de> for Row {
    fn deserialize<D:Deserializer<'de>>(d:D)->Result<Self,D::Error>{
        ATTEMPTS.fetch_add(1,Ordering::SeqCst);
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {n:u32}
        Body::deserialize(d).map(|r|Self{n:r.n})
    }
}
fn meter(used:u64)->QueryMeter {
    ATTEMPTS.store(0,Ordering::SeqCst);
    QueryMeter::new(QueryBudgetUsage{posting_rows:used,io_bytes:71,..Default::default()},QueryBudgetLimits::for_index(10_000))
}
fn attempts()->usize{ATTEMPTS.load(Ordering::SeqCst)}

#[test]
fn actual_attempted_rows_never_exceed_shared_limit_and_errors_keep_consumption(){
    let mut m=meter(100_000);
    let empty=m.decode_posting_rows::<Row>(br#"{"schema":"fixture","rows":[]}"#,PostingRowsMode::Rows,&["schema"]).expect("an exactly exhausted allowance must still accept an empty array");
    assert!(empty.rows.unwrap().is_empty());assert_eq!(attempts(),0);assert_eq!(m.usage().posting_rows,100_000);

    let mut m=meter(99_999);
    let one=m.decode_posting_rows::<Row>(br#"{"schema":"fixture","rows":[{"n":1}]}"#,PostingRowsMode::Rows,&["schema"]).unwrap();
    assert_eq!(one.rows.unwrap()[0].n,1);assert_eq!(attempts(),1);assert_eq!(m.usage().posting_rows,100_000);assert_eq!(m.usage().io_bytes,71);

    let mut m=meter(99_999);
    let excess=m.decode_posting_rows::<Row>(br#"{"schema":"fixture","rows":[{"n":1},{"n":"must never decode"}]}"#,PostingRowsMode::Rows,&["schema"]).unwrap_err();
    assert_eq!(excess,"E_QUERY_POSTING_BUDGET");assert_eq!(attempts(),1);assert_eq!(m.usage().posting_rows,100_000);
    let again=m.decode_posting_rows::<Row>(br#"{"rows":[{"n":7}]}"#,PostingRowsMode::Rows,&[]).unwrap_err();
    assert_eq!(again,"E_QUERY_POSTING_BUDGET");assert_eq!(attempts(),1);assert_eq!(m.usage().posting_rows,100_000);

    let mut m=meter(0);
    assert!(m.decode_posting_rows::<Row>(br#"{"rows":[{"n":"bad"},{"n":2}]}"#,PostingRowsMode::Rows,&[]).is_err());
    assert_eq!(attempts(),1);assert_eq!(m.usage().posting_rows,1,"failed attempted rows must remain charged");

    let mut m=meter(99_999);
    let terms=m.decode_posting_rows::<Row>(br#"{"schema":"fixture","terms":{"empty":[],"first":[{"n":4}],"unrelated":[{"n":5}]}}"#,PostingRowsMode::Terms,&["schema"]).unwrap_err();
    assert_eq!(terms,"E_QUERY_POSTING_BUDGET");assert_eq!(attempts(),1);assert_eq!(m.usage().posting_rows,100_000);

    let mut m=meter(0);
    let terms=m.decode_posting_rows::<Row>(br#"{"schema":"fixture","terms":{"a":[{"n":8}],"b":[{"n":9}]}}"#,PostingRowsMode::Terms,&["schema"]).unwrap();
    assert!(terms.rows.is_none());assert_eq!(terms.header["schema"],"fixture");assert_eq!(terms.terms.unwrap()["b"][0].n,9);assert_eq!(attempts(),2);assert_eq!(m.usage().posting_rows,2);

    for (input,mode,want) in [
        (br#"{"unknown":[{"n":1}],"rows":[{"n":2}]}"#.as_slice(),PostingRowsMode::Rows,0),
        (br#"{"rows":[{"n":1}],"schema":"fixture","schema":"duplicate"}"#.as_slice(),PostingRowsMode::Rows,1),
        (br#"{"terms":{"a":[{"n":1}],"a":[{"n":2}]}}"#.as_slice(),PostingRowsMode::Terms,1),
        (br#"{"rows":[{"n":1}],"rows":[{"n":2}]}"#.as_slice(),PostingRowsMode::Rows,1),
        (br#"{"terms":{"a":[{"n":1}]}}"#.as_slice(),PostingRowsMode::Rows,0),
        (br#"{"rows":[]} trailing"#.as_slice(),PostingRowsMode::Rows,0),
        (br#"{"schema":"missing rows"}"#.as_slice(),PostingRowsMode::Rows,0),
    ] {
        let mut m=meter(0);assert!(m.decode_posting_rows::<Row>(input,mode,&["schema"]).is_err());assert_eq!(attempts(),want);assert_eq!(m.usage().posting_rows,want as u64);
    }
    let mut m=meter(0);
    let exact=serde_json::to_vec(&json!({"rows":(0..100_000).map(|n|json!({"n":n})).collect::<Vec<_>>()})).unwrap();
    let result=m.decode_posting_rows::<Row>(&exact,PostingRowsMode::Rows,&[]).unwrap();assert_eq!(result.rows.unwrap().len(),100_000);assert_eq!(attempts(),100_000);assert_eq!(m.usage().posting_rows,100_000);
}
