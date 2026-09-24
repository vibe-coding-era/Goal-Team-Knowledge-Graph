//! Query-to-authoring context-window integration, using original source coordinates.
use gtkg_core::v04::knowledge::*;
use gtkg_extract::v04::{AnalysisContext, Span};
use std::collections::BTreeMap;

fn source_span(source: &str, needle: &str) -> Span {
    let start=source.find(needle).unwrap();let end=start+needle.len();
    Span { byte_start:start,byte_end:end,line_start:source[..start].bytes().filter(|b|*b==b'\n').count()+1,
        line_end:source[..end-1].bytes().filter(|b|*b==b'\n').count()+1 }
}
fn inputs(source: &str) -> (KnowledgeSources,KnowledgeInput) {
    let s=KnowledgeSources { raw_sources:BTreeMap::from([("main.go".into(),source.as_bytes().to_vec())]),
        context:AnalysisContext { snapshot_id:"span-fixture".into(),..AnalysisContext::default() },call_proofs:vec![] };
    let input=KnowledgeInput { job_id:"span-job".into(),goal:KnowledgeGoal::SemanticUnderstanding,
        source_paths:vec!["main.go".into()],understanding_items:vec!["section".into()],prompt:"Explain the selected function".into(),
        policy:"span-policy".into(),max_context_units:8000,source_spans:BTreeMap::from([("main.go".into(),vec![source_span(source,"func Visible() {}\n")])]) };
    (s,input)
}
fn candidate(source: &str, name: &str) -> KnowledgeCandidate {
    let snippet=format!("func {name}() {{}}\n");
    KnowledgeCandidate { author_id:"fixture-author".into(),author_mode:AuthorMode::HumanAuthored,summary:format!("{name} is defined"),
        claims:vec![KnowledgeClaim { claim_id:"one".into(),understanding_item:"section".into(),natural_language:format!("{name} is defined"),
            body:ClaimBody::Structural { predicate:Predicate::Declares { path:"main.go".into(),name:name.into(),kind:"function".into() },polarity:true },
            citations:vec![Citation { path:"main.go".into(),file_sha256:digest(source.as_bytes()),span:source_span(source,&snippet),excerpt:snippet }] }] }
}
#[test]
fn a_large_source_can_supply_one_bounded_symbol_with_original_identity() {
    let source=format!("package p\n{}func Visible() {{}}\nfunc Hidden() {{}}\n","// padding\n".repeat(1200));
    let(s,i)=inputs(&source);let j=prepare_job(&i,&s).expect("selected symbol should fit regardless of original file size");
    assert_eq!(j.context.len(),1);assert_eq!(j.context[0].text,"func Visible() {}\n");
    assert_eq!(j.context[0].file_sha256,digest(source.as_bytes()));assert_eq!(j.context[0].span,i.source_spans["main.go"][0]);
    assert!(j.context[0].span.byte_start>8000);
    assert!(submit_proposal(&j,&candidate(&source,"Visible"),None,&s).is_ok());
    let mut full=i;full.source_spans.clear();assert!(prepare_job(&full,&s).is_err());
}
#[test]
fn a_claim_cannot_cite_an_unobserved_window_of_the_same_file() {
    let source="package p\nfunc Visible() {}\nfunc Hidden() {}\n";let(s,i)=inputs(source);let j=prepare_job(&i,&s).unwrap();
    assert!(submit_proposal(&j,&candidate(source,"Visible"),None,&s).is_ok());
    assert!(submit_proposal(&j,&candidate(source,"Hidden"),None,&s).is_err(),"same file hash does not mean the model saw Hidden");
}
#[test]
fn window_line_mismatch_unknown_path_overlap_and_invalid_utf8_boundary_fail() {
    let source="package p\n// 中\nfunc Visible() {}\nfunc Hidden() {}\n";let(s,i)=inputs(source);
    let mut wrong=i.clone();wrong.source_spans.get_mut("main.go").unwrap()[0].line_start=1;assert!(prepare_job(&wrong,&s).is_err());
    let mut unknown=i.clone();unknown.source_spans.insert("not-requested.go".into(),vec![i.source_spans["main.go"][0].clone()]);assert!(prepare_job(&unknown,&s).is_err());
    let mut overlap=i.clone();overlap.source_spans.get_mut("main.go").unwrap().push(i.source_spans["main.go"][0].clone());assert!(prepare_job(&overlap,&s).is_err());
    let mut invalid=i;let start=source.find('中').unwrap()+1;invalid.source_spans.insert("main.go".into(),vec![Span { byte_start:start,byte_end:start+1,line_start:2,line_end:2 }]);assert!(prepare_job(&invalid,&s).is_err());
}
#[test]
fn old_json_input_without_windows_keeps_explicit_whole_file_behavior() {
    let source="package p\nfunc Visible() {}\nfunc Hidden() {}\n";let(s,i)=inputs(source);
    let mut value=serde_json::to_value(i).unwrap();value.as_object_mut().unwrap().remove("source_spans");
    let old:KnowledgeInput=serde_json::from_value(value).unwrap();assert!(old.source_spans.is_empty());
    let job=prepare_job(&old,&s).unwrap();assert_eq!(job.context[0].text,source);assert_eq!(job.context[0].span.byte_start,0);
}
