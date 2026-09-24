#![allow(clippy::unwrap_used)]
use gtkg_core::v04::{
    artifact,
    index::*,
    source::{self, ScopePolicy, SourceCaptureRequest},
};
use gtkg_core::{CallContext, EffectPolicy, TransportKind};
use gtkg_extract::v04::{AnalysisContext, extract};
use gtkg_protocol::FileReceiptRef;
use std::{collections::BTreeSet, fs, path::Path, process::Command};
use tempfile::TempDir;
fn git(root: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().into()
}
fn fixture(
    files: &[(&str, &str)],
) -> (
    TempDir,
    CallContext,
    FileReceiptRef,
    source::SourceCoverageLedger,
) {
    let temp = TempDir::new().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let repo = root.join("repo");
    let work = root.join("work");
    fs::create_dir(&repo).unwrap();
    fs::create_dir(&work).unwrap();
    git(&repo, &["init", "-q"]);
    for (path, body) in files {
        let p = repo.join(path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }
    git(&repo, &["add", "."]);
    git(
        &repo,
        &[
            "-c",
            "user.name=QK Fixture",
            "-c",
            "user.email=qk@example.invalid",
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "--allow-empty",
            "-qm",
            "fixture",
        ],
    );
    let context = CallContext::restricted(
        TransportKind::Test,
        vec![work.clone(), repo.clone()],
        EffectPolicy::WorkspaceWrite,
    )
    .unwrap();
    let ledger = source::capture(&SourceCaptureRequest {
        repository_id: "fixture".into(),
        source_root: repo.clone(),
        source_commit: git(&repo, &["rev-parse", "HEAD"]),
        expected_tree: git(&repo, &["rev-parse", "HEAD^{tree}"]),
        output_path: work.join("archive"),
        policy: ScopePolicy::default(),
    })
    .unwrap();
    let reference = artifact::reference(
        &context,
        &work,
        &work.join("archive").join(source::LEDGER_FILE),
    )
    .unwrap();
    (temp, context, reference, ledger)
}
fn chunks(c: &CallContext, m: &IndexManifest, terms: &str) -> Vec<EvidenceChunk> {
    let mut ids = BTreeSet::new();
    let mut out = Vec::new();
    for term in tokenize(terms) {
        for p in load_postings(c, c.workspace_root().unwrap(), m, &term).unwrap() {
            if ids.insert(p.chunk_id.clone()) {
                out.push(load_chunk(c, c.workspace_root().unwrap(), m, &p).unwrap());
            }
        }
    }
    out
}
#[test]
fn unicode_original_spans_metadata_and_mixed_text_are_preserved() {
    let md = "---\nmodel: hidden_meta_unique\n---\n# 会话恢复\n原始中文🙂é正文 E_SESSION_LOST Agent.Session.resume\n";
    let cfg = "[provider]\nname = \"DeepSeek\"\nretry = 3\n";
    let (_t, c, reference, _) = fixture(&[("README.md", md), ("settings.toml", cfg)]);
    let r = build(&c, c.workspace_root().unwrap(), &reference, &[])
        .expect("text archive must build evidence index");
    let m = load_manifest(&c, c.workspace_root().unwrap(), &r).unwrap();
    assert_eq!(m.router.len(), 256);
    assert_eq!(m.chunk_router.len(), 256);
    assert!(
        chunks(&c, &m, "hidden_meta_unique").is_empty(),
        "frontmatter is not default body evidence"
    );
    let hit = chunks(
        &c,
        &m,
        "会话恢复 E_SESSION_LOST Agent.Session.resume DeepSeek",
    );
    assert!(hit.iter().any(|x| x.path == "README.md"));
    assert!(hit.iter().any(|x| x.path == "settings.toml"));
    for chunk in hit {
        let src = if chunk.path == "README.md" { md } else { cfg };
        assert_eq!(&src[chunk.byte_start..chunk.byte_end], chunk.text);
        assert_eq!(
            chunk.line_start,
            src[..chunk.byte_start]
                .bytes()
                .filter(|x| *x == b'\n')
                .count()
                + 1
        );
        assert_eq!(chunk.tokens, chunk.text.chars().count() as u32);
        assert!(chunk.tokens <= 1024);
        let (binding, ledger_bytes) =
            load_source_binding(&c, c.workspace_root().unwrap(), &m).unwrap();
        assert_eq!(
            validate_chunk_source(&c, c.workspace_root().unwrap(), &m, &chunk).unwrap(),
            ledger_bytes + src.len() as u64
        );
        assert_eq!(
            validate_chunk_source_with_binding(
                &c,
                c.workspace_root().unwrap(),
                &m,
                &chunk,
                &binding
            )
            .unwrap(),
            src.len() as u64
        );
    }
}
#[test]
fn verified_syntax_boundaries_and_unverified_fallback_are_distinct() {
    let src =
        "package p\nfunc First() { println(\"alpha\") }\nfunc Second() { println(\"beta\") }\n";
    let (_t, c, r, l) = fixture(&[("main.go", src)]);
    let mut ctx = AnalysisContext::default();
    ctx.snapshot_id = l.snapshot_id.clone();
    let facts = extract("main.go", src.as_bytes(), &ctx).unwrap();
    let idx = build(&c, c.workspace_root().unwrap(), &r, &[facts.clone()]).unwrap();
    let m = load_manifest(&c, c.workspace_root().unwrap(), &idx).unwrap();
    let found = chunks(&c, &m, "alpha beta");
    assert!(
        found
            .iter()
            .any(|x| x.parent.as_ref().is_some_and(|p| p.name == "First"))
    );
    assert!(
        found
            .iter()
            .any(|x| x.parent.as_ref().is_some_and(|p| p.name == "Second"))
    );
    assert!(
        found
            .iter()
            .all(|x| !(x.text.contains("func First") && x.text.contains("func Second")))
    );
    let plain = build(&c, c.workspace_root().unwrap(), &r, &[]).unwrap();
    let pm = load_manifest(&c, c.workspace_root().unwrap(), &plain).unwrap();
    assert!(
        chunks(&c, &pm, "alpha")
            .iter()
            .all(|x| x.role == "code_text_unverified")
    );
    assert_ne!(idx, plain);
    let mut bad = facts;
    bad.file_sha = format!("sha256:{}", "0".repeat(64));
    assert!(build(&c, c.workspace_root().unwrap(), &r, &[bad]).is_err());
}
#[test]
fn oversized_unicode_body_splits_at_safe_boundaries_and_links_neighbors() {
    let text = format!("# 大段\n{}\n", "中文🙂".repeat(1000));
    let (_t, c, r, _) = fixture(&[("big.md", &text)]);
    let index = build(&c, c.workspace_root().unwrap(), &r, &[]).unwrap();
    let m = load_manifest(&c, c.workspace_root().unwrap(), &index).unwrap();
    let mut found = chunks(&c, &m, "中文");
    assert!(found.len() >= 3);
    found.sort_by_key(|x| x.byte_start);
    for x in &found {
        assert!(x.tokens <= 1024);
        assert_eq!(&text[x.byte_start..x.byte_end], x.text);
        if let Some(next) = &x.next {
            let n = load_chunk_by_id(&c, c.workspace_root().unwrap(), &m, next).unwrap();
            assert_eq!(n.previous.as_ref(), Some(&x.id));
            assert_eq!(n.byte_start, x.byte_end);
        }
    }
}
#[test]
fn lexical_channels_keep_full_identifiers_case_collisions_cjk_and_real_tf() {
    let terms =
        tokenize("E_SOURCE_MISSING E_SOURCE_MISSING Agent.Session.resume 中文测试 Résumé résumé");
    assert_eq!(
        terms
            .iter()
            .filter(|t| t.as_str() == "exact:E_SOURCE_MISSING")
            .count(),
        2
    );
    assert!(terms.contains(&"exact:Agent.Session.resume".into()));
    assert!(terms.contains(&"fold:agent.session.resume".into()));
    assert!(terms.contains(&"cjk:中文".into()));
    assert!(terms.contains(&"exact:Résumé".into()));
    assert!(terms.contains(&"exact:résumé".into()));
    for t in terms {
        let b = token_bucket(&t);
        assert_eq!(b.len(), 2);
        assert!(b.bytes().all(|x| x.is_ascii_hexdigit()));
    }
    let (_t, c, r, _) = fixture(&[("a.md", "E_SOURCE_MISSING E_SOURCE_MISSING")]);
    let idx = build(&c, c.workspace_root().unwrap(), &r, &[]).unwrap();
    let m = load_manifest(&c, c.workspace_root().unwrap(), &idx).unwrap();
    let hits = load_postings(
        &c,
        c.workspace_root().unwrap(),
        &m,
        "exact:E_SOURCE_MISSING",
    )
    .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].term_frequency, 2);
}
#[test]
fn deterministic_rebuild_transfer_and_relative_paths() {
    let (t, c, r, _) = fixture(&[("a.md", "transferable evidence")]);
    let idx = build(&c, c.workspace_root().unwrap(), &r, &[]).unwrap();
    assert_eq!(
        idx,
        build(&c, c.workspace_root().unwrap(), &r, &[]).unwrap()
    );
    let bytes = fs::read(c.workspace_root().unwrap().join(&idx.path)).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains(t.path().to_str().unwrap()));
    let moved = t.path().join("moved");
    fs::rename(c.workspace_root().unwrap(), &moved).unwrap();
    let moved = fs::canonicalize(moved).unwrap();
    let c2 =
        CallContext::restricted(TransportKind::Test, vec![moved], EffectPolicy::ReadOnly).unwrap();
    let m = load_manifest(&c2, c2.workspace_root().unwrap(), &idx).unwrap();
    let h = chunks(&c2, &m, "transferable");
    assert_eq!(h.len(), 1);
    validate_chunk_source(&c2, c2.workspace_root().unwrap(), &m, &h[0]).unwrap();
}
#[test]
fn selected_shard_integrity_and_complete_router_fail_closed() {
    let (_t, c, r, _) = fixture(&[("a.md", "alpha token")]);
    let idx = build(&c, c.workspace_root().unwrap(), &r, &[]).unwrap();
    let m = load_manifest(&c, c.workspace_root().unwrap(), &idx).unwrap();
    let term = "exact:alpha";
    let p = load_postings(&c, c.workspace_root().unwrap(), &m, term).unwrap();
    assert!(!p.is_empty());
    let bucket = token_bucket(term);
    let route = m.router[&bucket].as_ref().unwrap();
    let shard_path = c.workspace_root().unwrap().join(&route.path);
    let original = fs::read(&shard_path).unwrap();
    fs::remove_file(&shard_path).unwrap();
    assert!(load_postings(&c, c.workspace_root().unwrap(), &m, term).is_err());
    fs::write(&shard_path, original).unwrap();
    fs::write(
        c.workspace_root().unwrap().join(&p[0].chunk_ref.path),
        b"{}",
    )
    .unwrap();
    assert!(load_chunk(&c, c.workspace_root().unwrap(), &m, &p[0]).is_err());
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(c.workspace_root().unwrap().join(&idx.path)).unwrap())
            .unwrap();
    value["router"].as_object_mut().unwrap().remove("00");
    let forged = c.workspace_root().unwrap().join("forged.json");
    fs::write(&forged, serde_json::to_vec(&value).unwrap()).unwrap();
    let forged_ref = artifact::reference(&c, c.workspace_root().unwrap(), &forged).unwrap();
    assert!(load_manifest(&c, c.workspace_root().unwrap(), &forged_ref).is_err());
}

#[test]
fn supplied_analysis_context_is_replayed_and_binding_reads_are_counted() {
    let src = "package p\nfunc F() {}\n";
    let (_t, c, r, l) = fixture(&[("main.go", src)]);
    let context = AnalysisContext {
        snapshot_id: l.snapshot_id.clone(),
        goos: "linux".into(),
        ..Default::default()
    };
    let facts = extract("main.go", src.as_bytes(), &context).unwrap();
    assert!(build(&c, c.workspace_root().unwrap(), &r, &[facts.clone()]).is_err());
    let index =
        build_with_context(&c, c.workspace_root().unwrap(), &r, &[facts], &context).unwrap();
    let manifest = load_manifest(&c, c.workspace_root().unwrap(), &index).unwrap();
    assert_eq!(
        manifest.analysis_context_digest,
        gtkg_extract::v04::context_digest(&context)
    );
    let (binding, read_bytes) =
        load_source_binding(&c, c.workspace_root().unwrap(), &manifest).unwrap();
    assert_eq!(
        read_bytes,
        fs::metadata(c.workspace_root().unwrap().join(&manifest.source_ref.path))
            .unwrap()
            .len()
    );
    let chunk = chunks(&c, &manifest, "F").pop().unwrap();
    assert_eq!(
        validate_chunk_source_with_binding(
            &c,
            c.workspace_root().unwrap(),
            &manifest,
            &chunk,
            &binding
        )
        .unwrap(),
        src.len() as u64
    );
    let (_other_t, other_c, other_r, _) = fixture(&[("other.md", "different source")]);
    let other_index = build(&other_c, other_c.workspace_root().unwrap(), &other_r, &[]).unwrap();
    let other_manifest =
        load_manifest(&other_c, other_c.workspace_root().unwrap(), &other_index).unwrap();
    let (other_binding, _) =
        load_source_binding(&other_c, other_c.workspace_root().unwrap(), &other_manifest).unwrap();
    assert!(
        validate_chunk_source_with_binding(
            &c,
            c.workspace_root().unwrap(),
            &manifest,
            &chunk,
            &other_binding
        )
        .is_err()
    );
}
