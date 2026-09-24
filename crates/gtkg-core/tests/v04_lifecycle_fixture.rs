//! Real local Git/source/analysis/authoring fixture for lifecycle checks.
use gtkg_core::v04::{analysis, artifact, authoring, index, knowledge::*, source};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_extract::v04::{Span, binding};
use gtkg_protocol::{
    FileReceiptRef,
    v04::{ArtifactPayload, Revision},
};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

pub struct Fixture {
    pub temp: tempfile::TempDir,
    pub workspace: PathBuf,
    pub repository: PathBuf,
    pub context: CallContext,
}
fn git(path: &Path, args: &[&str]) -> String {
    let result = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(args)
        .output()
        .unwrap();
    assert!(result.status.success(), "git fixture failed");
    String::from_utf8(result.stdout).unwrap().trim().to_owned()
}
impl Fixture {
    pub fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("work");
        let repository = temp.path().join("repo");
        fs::create_dir(&workspace).unwrap();
        fs::create_dir(&repository).unwrap();
        git(&repository, &["init", "-q"]);
        let context = CallContext::restricted(
            TransportKind::Test,
            vec![workspace.clone(), repository.clone()],
            EffectPolicy::WorkspaceWrite,
        )
        .unwrap();
        Self {
            temp,
            workspace,
            repository,
            context,
        }
    }
    pub fn build(
        &self,
        revision: &str,
        extra: &[(&str, &str)],
        with_graph: bool,
    ) -> (FileReceiptRef, Vec<FileReceiptRef>, FileReceiptRef) {
        let main = "package p\nfunc Entry() {}\nfunc Run() { Entry() }\n";
        let mut files = vec![
            ("main.go", main),
            (
                "README.md",
                "# Entry\nEntry coordinates fixture requests.\n",
            ),
        ];
        files.extend_from_slice(extra);
        let mut stream = Vec::new();
        for (n, (_, text)) in files.iter().enumerate() {
            stream.extend(
                format!("blob\nmark :{}\ndata {}\n{}\n", n + 1, text.len(), text).as_bytes(),
            );
        }
        stream.extend(format!("commit refs/heads/{revision}\ncommitter Fixture <fixture@example.invalid> 0 +0000\ndata 8\nfixture\n\n").as_bytes());
        for (n, (path, _)) in files.iter().enumerate() {
            stream.extend(format!("M 100644 :{} {path}\n", n + 1).as_bytes());
        }
        stream.push(b'\n');
        let mut process = Command::new("git")
            .arg("-C")
            .arg(&self.repository)
            .args(["fast-import", "--quiet"])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        process.stdin.take().unwrap().write_all(&stream).unwrap();
        assert!(process.wait().unwrap().success());
        let commit = git(&self.repository, &["rev-parse", revision]);
        let tree = git(
            &self.repository,
            &["rev-parse", &format!("{revision}^{{tree}}")],
        );
        let archive = self.workspace.join(format!(".gtkg/qk/source-{revision}"));
        source::capture(&source::SourceCaptureRequest {
            repository_id: "fixture".into(),
            source_root: self.repository.clone(),
            source_commit: commit,
            expected_tree: tree,
            output_path: archive.clone(),
            policy: source::ScopePolicy::default(),
        })
        .unwrap();
        let source_ref = artifact::reference(
            &self.context,
            &self.workspace,
            &archive.join(source::LEDGER_FILE),
        )
        .unwrap();
        let payload = |r| ArtifactPayload {
            payload_revision: Revision::R1,
            workspace_root: self.workspace.clone(),
            artifact_ref: r,
        };
        let plan = analysis::plan(&self.context, &payload(source_ref.clone())).unwrap();
        let plan_ref: FileReceiptRef =
            serde_json::from_value(plan["artifact_ref"].clone()).unwrap();
        let candidate = analysis::build(&self.context, &payload(plan_ref.clone())).unwrap();
        let candidate_ref: FileReceiptRef =
            serde_json::from_value(candidate["artifact_ref"].clone()).unwrap();
        let (candidate, _): (analysis::AnalysisCandidate, _) =
            artifact::read(&self.context, &self.workspace, &candidate_ref).unwrap();
        let (plan, _): (analysis::AnalysisPlan, _) =
            artifact::read(&self.context, &self.workspace, &plan_ref).unwrap();
        let ledger = source::load_archive(&archive).unwrap();
        let raw = analysis::raw_code(&ledger, &archive).unwrap();
        let edges = binding::confirmed_edges(&candidate.proofs, &raw, &plan.context).unwrap();
        let index_ref = if with_graph {
            let graph = gtkg_core::v04::graph_projection::build(
                &self.context,
                &self.workspace,
                &source_ref,
                &candidate_ref,
                &candidate.proofs,
                &raw,
                &plan.context,
            )
            .unwrap();
            index::build_with_graph(
                &self.context,
                &self.workspace,
                &source_ref,
                &candidate.facts,
                &plan.context,
                Some(&graph),
            )
            .unwrap()
        } else {
            index::build_with_context(
                &self.context,
                &self.workspace,
                &source_ref,
                &candidate.facts,
                &plan.context,
            )
            .unwrap()
        };
        let verified = analysis::VerifiedAnalysis {
            schema: "gtkg.qk.analysis-verification/v1".into(),
            candidate_ref,
            plan_ref,
            source_ref,
            context: plan.context,
            snapshot_id: ledger.snapshot_id,
            source_tree: ledger.source_tree,
            source_commit: ledger.source_commit,
            total_calls: candidate.proofs.len(),
            confirmed_calls: edges.len(),
            edges,
            routes: candidate.routes,
            index_ref: Some(index_ref),
        };
        let verified_ref =
            artifact::publish(&self.context, &self.workspace, "verified", &verified).unwrap();
        analysis::load_verified(&self.context, &self.workspace, &verified_ref).unwrap();
        let (_, sources) =
            authoring::load_verified_sources(&self.context, &self.workspace, &verified_ref)
                .unwrap();
        let job = prepare_job(
            &KnowledgeInput {
                job_id: format!("job-{revision}"),
                goal: KnowledgeGoal::SemanticUnderstanding,
                source_paths: vec!["main.go".into()],
                understanding_items: vec!["entry".into()],
                prompt: "Explain the exact Entry declaration".into(),
                policy: "fixture".into(),
                max_context_units: 8000,
                source_spans: BTreeMap::new(),
            },
            &sources,
        )
        .unwrap();
        let job_ref = artifact::publish(
            &self.context,
            &self.workspace,
            "authoring-jobs",
            &authoring::JobArtifact {
                verified_ref: verified_ref.clone(),
                job: job.clone(),
            },
        )
        .unwrap();
        let candidate = KnowledgeCandidate {
            author_id: "fixture-human".into(),
            author_mode: AuthorMode::HumanAuthored,
            summary: "Entry definition".into(),
            claims: vec![KnowledgeClaim {
                claim_id: "entry".into(),
                understanding_item: "entry".into(),
                natural_language: "Entry is declared".into(),
                body: ClaimBody::Structural {
                    predicate: Predicate::Declares {
                        path: "main.go".into(),
                        name: "Entry".into(),
                        kind: "function".into(),
                    },
                    polarity: true,
                },
                citations: vec![Citation {
                    path: "main.go".into(),
                    file_sha256: digest(main.as_bytes()),
                    span: Span {
                        byte_start: 10,
                        byte_end: 26,
                        line_start: 2,
                        line_end: 2,
                    },
                    excerpt: "func Entry() {}\n".into(),
                }],
            }],
        };
        let output = serde_json::to_string(&candidate).unwrap();
        let record = GenerationExecutionRecord {
            schema: "gtkg.qk.generation-execution-record/v1".into(),
            job_digest: job.job_digest.clone(),
            context_digest: job.context_digest.clone(),
            prompt_digest: job.prompt_digest.clone(),
            policy_digest: job.policy_digest.clone(),
            author_id: candidate.author_id.clone(),
            author_mode: candidate.author_mode.clone(),
            execution_evidence: ExecutionEvidence::HumanRecorded,
            host_id: None,
            model_id: None,
            transcript: None,
            transcript_digest: None,
            output_digest: digest(output.as_bytes()),
            output,
            usage: Usage {
                input_tokens: None,
                output_tokens: None,
            },
        };
        let proposal = submit_proposal(&job, &candidate, Some(&record), &sources).unwrap();
        let proposal_ref = artifact::publish(
            &self.context,
            &self.workspace,
            "proposals",
            &authoring::ProposalArtifact {
                job_ref: job_ref.clone(),
                proposal: proposal.clone(),
            },
        )
        .unwrap();
        let reviews = ["review-a", "review-b"]
            .iter()
            .map(|id| IndependentReview {
                reviewer_id: id.to_string(),
                proposal_digest: proposal.proposal_digest.clone(),
                decisions: candidate
                    .claims
                    .iter()
                    .map(|c| ClaimReview {
                        claim_id: c.claim_id.clone(),
                        claim_digest: claim_digest(c).unwrap(),
                        judgment: Judgment::Supported,
                        reason: "Synthetic fixture source inspected".into(),
                    })
                    .collect(),
            })
            .collect::<Vec<_>>();
        let verification = review_proposal(&job, &proposal, &reviews, &sources).unwrap();
        let review_ref = artifact::publish(
            &self.context,
            &self.workspace,
            "knowledge-reviews",
            &authoring::ReviewArtifact {
                proposal_ref,
                verification: verification.clone(),
            },
        )
        .unwrap();
        let accepted = accept(&job, &proposal, &verification, &sources).unwrap();
        let okf = authoring::render_okf(&job, &accepted);
        let okf_ref =
            artifact::publish_text(&self.context, &self.workspace, "knowledge", &okf).unwrap();
        let accepted_ref = artifact::publish(
            &self.context,
            &self.workspace,
            "accepted",
            &authoring::AcceptedArtifact {
                review_ref,
                job_ref,
                accepted,
                okf_ref,
            },
        )
        .unwrap();
        authoring::accepted_chain(&self.context, &self.workspace, &accepted_ref).unwrap();
        let input = authoring::ViewsRequest {
            verified_ref: verified_ref.clone(),
            accepted_refs: vec![accepted_ref.clone()],
            input: ProjectKnowledgeInput {
                project_name: "Lifecycle fixture".into(),
                inventory_id: "shared".into(),
                modules: vec![],
                understanding_items: vec![ProjectUnderstandingItem {
                    item_id: "entry".into(),
                    question: "Where is Entry defined?".into(),
                    view: ProjectViewKind::Overview,
                    module_id: None,
                    aspect: None,
                }],
            },
        };
        let input_ref =
            artifact::publish(&self.context, &self.workspace, "inputs", &input).unwrap();
        let views: Value = authoring::create_views(&self.context, &payload(input_ref)).unwrap();
        (
            verified_ref,
            vec![accepted_ref],
            serde_json::from_value(views["artifact_ref"].clone()).unwrap(),
        )
    }
}
