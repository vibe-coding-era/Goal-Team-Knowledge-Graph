//! H07 product-completion contracts for persistent per-path responsibilities.
//!
//! The original product definition requires multiple paths to carry different
//! functions. `gtkg.config/v2` persists the exact repo/path role and
//! include/exclude scopes, and `source.inspect` applies the same scope model to
//! the locked Git tree.

use std::fs;
use std::path::Path;
use std::process::Command;

use gtkg_core::file_model::sha256_file;
use gtkg_core::okf::parse_okf_concept;
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::{ErrorCode, ErrorEnvelope, OperationId, OperationRequest};
use serde_json::{Value, json};
use tempfile::tempdir;

#[test]
fn config_v2_persists_multiple_path_roles_and_closed_scopes() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path();
    let repository = root.join("repository");
    let templates = root.join("templates");
    fs::create_dir_all(&repository).unwrap();
    fs::create_dir_all(&templates).unwrap();
    let config_path = root.join("gtkg.json");
    fs::write(
        &config_path,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "gtkg.config/v2",
            "workspace_root": root,
            "storage_model": "okf-and-ordinary-files",
            "database_backend": null,
            "repositories": [
                {
                    "repo_id": "product-code",
                    "path": repository,
                    "role": "code",
                    "include": ["src"],
                    "exclude": ["src/generated"]
                },
                {
                    "repo_id": "product-docs",
                    "path": repository,
                    "role": "documentation",
                    "include": ["docs"],
                    "exclude": []
                }
            ],
            "template_catalog_roots": [templates],
            "node_endpoints": []
        }))
        .unwrap(),
    )
    .unwrap();
    let result = execute(
        root,
        OperationId::ConfigValidate,
        json!({"config_path": config_path}),
    );
    assert_eq!(result["valid"], true);
    assert_eq!(result["schema_version"], "gtkg.config/v2");
    assert_eq!(result["repository_root_count"], 2);
    assert_eq!(result["repository_role_count"], 2);
    assert_eq!(result["repositories"][0]["role"], "code");
    assert_eq!(result["repositories"][0]["include"], json!(["src"]));
    assert_eq!(
        result["repositories"][0]["exclude"],
        json!(["src/generated"])
    );
}

#[test]
fn source_inspect_applies_include_then_exclude_per_role() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path();
    let repository = root.join("repository");
    fs::create_dir_all(repository.join("src/generated")).unwrap();
    fs::create_dir_all(repository.join("docs")).unwrap();
    fs::write(repository.join("src/main.rs"), "pub fn main_entry() {}\n").unwrap();
    fs::write(
        repository.join("src/generated/bindings.rs"),
        "pub fn generated() {}\n",
    )
    .unwrap();
    fs::write(repository.join("docs/guide.md"), "# Guide\n").unwrap();
    init_git(&repository);
    let workspace = root.join("workspace");
    fs::create_dir_all(&workspace).unwrap();
    let result = execute(
        root,
        OperationId::SourceInspect,
        json!({
            "workspace_root": workspace,
            "repositories": [
                {
                    "repo_id": "product-code",
                    "path": repository,
                    "role": "code",
                    "include": ["src"],
                    "exclude": ["src/generated"]
                },
                {
                    "repo_id": "product-docs",
                    "path": repository,
                    "role": "documentation",
                    "include": ["docs"],
                    "exclude": []
                }
            ]
        }),
    );
    let entries = result["source_lock"]["entries"].as_array().unwrap();
    let observed = entries
        .iter()
        .map(|entry| {
            (
                entry["repo_id"].as_str().unwrap(),
                entry["logical_path"].as_str().unwrap(),
                entry["role"].as_str().unwrap(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        observed,
        vec![
            ("product-code", "src/main.rs", "code"),
            ("product-docs", "docs/guide.md", "documentation"),
        ]
    );
}

#[test]
fn source_inspect_can_consume_one_digest_bound_config_without_weakening_legacy_payloads() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path();
    let repository = root.join("repository");
    let templates = root.join("templates");
    fs::create_dir_all(repository.join("src/generated")).unwrap();
    fs::create_dir_all(repository.join("docs")).unwrap();
    fs::create_dir_all(&templates).unwrap();
    fs::write(repository.join("src/main.rs"), "pub fn main_entry() {}\n").unwrap();
    fs::write(
        repository.join("src/generated/bindings.rs"),
        "pub fn generated() {}\n",
    )
    .unwrap();
    fs::write(repository.join("docs/guide.md"), "# Guide\n").unwrap();
    init_git(&repository);

    let explicit_workspace = root.join("explicit-workspace");
    let config_workspace = root.join("config-workspace");
    fs::create_dir_all(&explicit_workspace).unwrap();
    fs::create_dir_all(&config_workspace).unwrap();
    let repositories = json!([
        {
            "repo_id": "product-code",
            "path": repository,
            "role": "code",
            "include": ["src"],
            "exclude": ["src/generated"]
        },
        {
            "repo_id": "product-docs",
            "path": repository,
            "role": "documentation",
            "include": ["docs"],
            "exclude": []
        }
    ]);
    let config_path = root.join("gtkg.json");
    fs::write(
        &config_path,
        serde_json::to_vec_pretty(&json!({
            "schema_version": "gtkg.config/v2",
            "workspace_root": config_workspace,
            "storage_model": "okf-and-ordinary-files",
            "database_backend": null,
            "repositories": repositories,
            "template_catalog_roots": [templates],
            "node_endpoints": []
        }))
        .unwrap(),
    )
    .unwrap();
    let expected_config_sha256 = sha256_file(&config_path).unwrap();

    let explicit = execute(
        root,
        OperationId::SourceInspect,
        json!({
            "workspace_root": explicit_workspace,
            "repositories": repositories,
        }),
    );
    let configured = execute(
        root,
        OperationId::SourceInspect,
        json!({
            "config_path": config_path,
            "expected_config_sha256": expected_config_sha256,
        }),
    );
    assert_eq!(configured["source_lock"], explicit["source_lock"]);
    assert_eq!(
        configured["source_lock_digest"],
        explicit["source_lock_digest"]
    );
    assert_eq!(configured["config_sha256"], expected_config_sha256);

    for (request_id, payload, expected_message) in [
        (
            "h07-config-drift",
            json!({
                "config_path": config_path,
                "expected_config_sha256": format!("sha256:{}", "0".repeat(64)),
            }),
            "digest",
        ),
        (
            "h07-dual-input",
            json!({
                "workspace_root": root.join("dual-workspace"),
                "repositories": repositories,
                "config_path": config_path,
                "expected_config_sha256": expected_config_sha256,
            }),
            "exactly one",
        ),
        ("h07-empty-input", json!({}), "exactly one"),
    ] {
        let error = execute_error(root, request_id, payload);
        assert_eq!(
            error.error.code,
            if request_id == "h07-config-drift" {
                ErrorCode::LockMismatch
            } else {
                ErrorCode::InvalidRequest
            }
        );
        assert!(
            error.error.message.contains(expected_message),
            "unexpected {request_id} error: {}",
            error.error.message
        );
    }
}

#[test]
fn codegraph_and_qoder_reference_is_versioned_okf_and_contains_product_copy() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("docs/reference/CodeGraph-Qoder-RepoWiki-reference.md");
    let source = fs::read_to_string(path).expect("product reference");
    let document = parse_okf_concept(&source).expect("product reference OKF");
    assert_eq!(document.frontmatter.kind, "Reference");
    assert_eq!(document.frontmatter.sources.len(), 3);
    assert!(document.frontmatter.sources.iter().all(|source| {
        source
            .resource
            .starts_with("https://github.com/codegraph-ai/")
            || source.resource.starts_with("https://docs.qoder.com/")
    }));
    let gtkg = document.frontmatter.gtkg.expect("reference extensions");
    assert_eq!(gtkg["document_version"].as_str(), Some("1.0.0"));
    assert_eq!(gtkg["evidence_scope"].as_str(), Some("informative-only"));
    assert!(document.body.contains("## 2. CodeGraph"));
    assert!(document.body.contains("## 3. Qoder RepoWiki"));
    assert!(document.body.contains("## 5. GTKG 正式参考文案"));
    assert!(
        document
            .body
            .contains("489ccf1612555510f8367e3e673181f6a1275fe4")
    );
}

#[test]
fn current_manual_is_official_okf_and_discloses_renderer_evidence_boundaries() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let source = fs::read_to_string(root.join("使用手册.md")).expect("manual");
    let document = parse_okf_concept(&source).expect("manual must be OKF concept");
    assert_eq!(document.frontmatter.kind, "User Manual");
    assert!(
        document
            .frontmatter
            .sources
            .iter()
            .all(|source| !source.resource.is_empty())
    );
    assert!(document.frontmatter.generated.is_none());
    assert!(document.frontmatter.verified.is_none());
    assert!(document.body.contains("official-a2ui-lit@0.10.3"));
    assert!(document.body.contains("`visual_threshold=not_run`"));
    assert!(root.join("docs/external-specs/okf-SPEC-v0.2.md").is_file());
    assert!(
        root.join("docs/reference/CodeGraph-Qoder-RepoWiki-reference.md")
            .is_file()
    );
}

fn execute(root: &Path, operation: OperationId, payload: Value) -> Value {
    let context = CallContext::restricted(
        TransportKind::Test,
        vec![root.to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    )
    .unwrap();
    Dispatcher
        .execute(
            &context,
            OperationRequest::new(operation, format!("h07-{}", operation.as_str()), payload),
        )
        .unwrap_or_else(|error| panic!("{} failed: {error:#?}", operation.as_str()))
        .result
}

fn execute_error(root: &Path, request_id: &str, payload: Value) -> ErrorEnvelope {
    let context = CallContext::restricted(
        TransportKind::Test,
        vec![root.to_path_buf()],
        EffectPolicy::WorkspaceWrite,
    )
    .unwrap();
    Dispatcher
        .execute(
            &context,
            OperationRequest::new(OperationId::SourceInspect, request_id, payload),
        )
        .expect_err("source.inspect request must fail closed")
}

fn init_git(root: &Path) {
    for arguments in [
        vec!["init"],
        vec!["config", "user.name", "GTKG Fixture"],
        vec!["config", "user.email", "fixture@invalid.example"],
        vec!["add", "-A"],
        vec!["commit", "-m", "fixture"],
    ] {
        let output = Command::new("/usr/bin/git")
            .arg("-C")
            .arg(root)
            .args(&arguments)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
