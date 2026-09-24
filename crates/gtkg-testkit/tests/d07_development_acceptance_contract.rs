use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

#[test]
fn thin_skill_candidate_has_the_exact_progressive_surface_and_only_calls_gtkg() {
    let skill_root = workspace_root().join("skills/goal-team-knowledge-graph");
    assert!(
        skill_root.is_dir(),
        "missing Skill candidate: {}",
        skill_root.display()
    );

    let files = regular_relative_files(&skill_root);
    assert_eq!(
        files,
        BTreeSet::from([
            "SKILL.md".to_owned(),
            "agents/openai.yaml".to_owned(),
            "references/operations.md".to_owned(),
            "references/workflows.md".to_owned(),
        ]),
        "Skill package exact-set drift"
    );
    assert!(files.iter().all(|path| !path.ends_with("README.md")));

    let skill = read(&skill_root.join("SKILL.md"));
    let (frontmatter, body) = split_frontmatter(&skill);
    let keys = frontmatter
        .lines()
        .filter_map(|line| line.split_once(':').map(|(key, _)| key.trim()))
        .collect::<BTreeSet<_>>();
    assert_eq!(keys, BTreeSet::from(["description", "name"]));
    assert!(frontmatter.contains("name: goal-team-knowledge-graph"));
    assert!(body.lines().count() < 500, "SKILL.md must stay concise");

    for required in [
        "gtkg op system.describe",
        "gtkg mcp serve --stdio",
        "summary.next",
        "summary.accept",
        "references/operations.md",
        "references/workflows.md",
        "E_SIDE_EFFECT_DENIED",
        "not_run",
    ] {
        assert!(body.contains(required), "SKILL.md missing {required}");
    }
    for boundary in [
        "Do not parse target documents or source code in the Skill",
        "Do not write canonical knowledge from the Skill",
        "Do not implement the build DAG or reducer in the Skill",
    ] {
        assert!(
            body.contains(boundary),
            "missing thin-Skill boundary: {boundary}"
        );
    }

    let metadata = read(&skill_root.join("agents/openai.yaml"));
    for required in [
        "display_name:",
        "short_description:",
        "default_prompt:",
        "$goal-team-knowledge-graph",
    ] {
        assert!(
            metadata.contains(required),
            "openai.yaml missing {required}"
        );
    }
    for forbidden in [
        "icon_small:",
        "icon_large:",
        "brand_color:",
        "dependencies:",
    ] {
        assert!(
            !metadata.contains(forbidden),
            "unrequested metadata field {forbidden}"
        );
    }

    let operations = read(&skill_root.join("references/operations.md"));
    for operation in PUBLIC_OPERATION_IDS {
        assert!(
            operations.contains(operation),
            "Skill reference misses {operation}"
        );
    }
    let workflows = read(&skill_root.join("references/workflows.md"));
    for phase in [
        "Discovery",
        "Build and summary handoff",
        "Verify and inspect",
        "External writes",
    ] {
        assert!(
            workflows.contains(phase),
            "workflow reference misses {phase}"
        );
    }
}

#[test]
fn every_prd_requirement_and_acceptance_condition_has_one_development_trace_row() {
    let root = workspace_root();
    let prd = read(&root.join("deliverables/goal-team-knowledge-graph/versions/V0.1/PRD.md"));
    let architecture =
        read(&root.join("deliverables/goal-team-knowledge-graph/versions/V0.1/ARCHITECTURE.md"));
    let task_list = read(&root.join("TaskList.md"));

    let requirement_section = section(&prd, "## 8. 功能需求", "## 10. CLI/MCP 产品操作面");
    let requirements = backticked_ids(requirement_section, &["FR-", "NFR-"]);
    let acceptance = backticked_ids(requirement_section, &["AC-FR-", "AC-NFR-"]);
    assert_eq!(requirements.len(), 36, "PRD Requirement denominator drift");
    assert_eq!(acceptance.len(), 36, "PRD AC denominator drift");

    let trace = section(
        &task_list,
        "### 15.3 Requirement/AC Development traceability",
        "### 15.4 Architecture acceptance projection",
    );
    for requirement in &requirements {
        let acceptance_id = format!("AC-{requirement}-01");
        let rows = trace
            .lines()
            .filter(|line| line.contains(&format!("`{requirement}`")))
            .collect::<Vec<_>>();
        assert_eq!(
            rows.len(),
            1,
            "{requirement} must have exactly one trace row"
        );
        let row = rows[0];
        assert!(
            row.contains(&format!("`{acceptance_id}`")),
            "{requirement} AC mismatch"
        );
        assert!(row.contains("D0"), "{requirement} has no D-task owner");
        assert!(
            [
                "current_development",
                "current_local_fixture",
                "blocked",
                "not_run"
            ]
            .iter()
            .any(|state| row.contains(state)),
            "{requirement} has no truthful evidence state"
        );
    }

    let architecture_acceptance = bare_ids(
        section(&architecture, "## 23. 验收设计", "## 24. 风险和开放决策"),
        &["AC-ARCH-"],
    );
    assert_eq!(architecture_acceptance.len(), 10);
    let architecture_trace = section(
        &task_list,
        "### 15.4 Architecture acceptance projection",
        "### 15.5 D07 evidence boundaries",
    );
    for acceptance_id in architecture_acceptance {
        assert_eq!(
            architecture_trace
                .matches(&format!("`{acceptance_id}`"))
                .count(),
            1,
            "{acceptance_id} must have exactly one projection row"
        );
    }
}

#[test]
fn runtime_help_explains_json_stdio_private_worker_and_copyable_examples() {
    let binary = gtkg_binary();
    let root = help(&binary, &["--help"]);
    for required in [
        "Examples:",
        "gtkg op system.describe --request - --output json",
        "gtkg mcp serve --stdio",
        "gtkg node serve --stdio",
    ] {
        assert!(root.contains(required), "root help missing {required}");
    }

    let op = help(&binary, &["op", "--help"]);
    for required in [
        "OperationRequest",
        "stdin",
        "--output json",
        "system.describe",
    ] {
        assert!(op.contains(required), "op help missing {required}");
    }
    let mcp = help(&binary, &["mcp", "serve", "--help"]);
    assert!(mcp.contains("MCP stdio"));
    assert!(mcp.contains("one JSON-RPC object per line"));
    let node = help(&binary, &["node", "serve", "--help"]);
    assert!(node.contains("private Worker"));
    assert!(node.contains("node.work.execute"));
}

#[test]
fn every_child_process_contract_honors_the_isolated_gtkg_binary_first() {
    let root = workspace_root();
    for relative in [
        "crates/gtkg-testkit/tests/d06_stdio_parity_contract.rs",
        "crates/gtkg-testkit/tests/d06_review_regression_contract.rs",
        "crates/gtkg-testkit/tests/d06_r8_regression_contract.rs",
        "crates/gtkg-testkit/tests/d06_r9_exact_read_contract.rs",
        "crates/gtkg-testkit/tests/d06_r10_rpc_error_contract.rs",
    ] {
        let source = read(&root.join(relative));
        let locator = section(&source, "fn gtkg_binary() -> PathBuf {", "\n}");
        let environment = locator
            .find("var_os(\"GTKG_BIN\")")
            .unwrap_or_else(|| panic!("{relative} ignores GTKG_BIN"));
        let fallback = locator
            .find("target/debug/gtkg")
            .unwrap_or_else(|| panic!("{relative} has no explicit development fallback"));
        assert!(
            environment < fallback,
            "{relative} checks stale fallback first"
        );
    }
}

#[test]
fn legacy_design_freeze_and_source_distribution_boundaries_are_explicit() {
    let root = workspace_root();
    for (relative, expected_sha256, expected_bytes) in LEGACY_FILES {
        let path = root.join(relative);
        let bytes =
            fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        assert_eq!(
            bytes.len(),
            expected_bytes,
            "legacy bytes drift: {relative}"
        );
        assert_eq!(
            sha256(&bytes),
            expected_sha256,
            "legacy digest drift: {relative}"
        );
        assert!(
            !fs::symlink_metadata(&path)
                .expect("legacy metadata")
                .file_type()
                .is_symlink()
        );
    }
    let template_index = read(&root.join("templates/design-deliverables/versions/V0.1/index.md"));
    assert!(template_index.contains("pending_git_binding"));
    let deliverable_index =
        read(&root.join("deliverables/goal-team-knowledge-graph/versions/V0.1/index.md"));
    assert!(deliverable_index.contains("implementation_status: \"not_run_at_design_freeze\""));

    let root_manifest = read(&root.join("Cargo.toml"));
    for member in [
        "crates/gtkg-protocol",
        "crates/gtkg-extract",
        "crates/gtkg-core",
        "crates/gtkg-app",
        "crates/gtkg-testkit",
    ] {
        assert!(root_manifest.contains(member), "workspace misses {member}");
    }
    assert!(read(&root.join("crates/gtkg-testkit/Cargo.toml")).contains("publish = false"));
    assert_eq!(
        ["gtkg-protocol", "gtkg-extract", "gtkg-core", "gtkg-app"]
            .iter()
            .filter(|name| read(&root.join(format!("crates/{name}/Cargo.toml"))).contains("[[bin]]"))
            .count(),
        1,
        "production workspace must publish exactly one binary target"
    );
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("testkit is inside workspace")
        .to_path_buf()
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn split_frontmatter(markdown: &str) -> (&str, &str) {
    let rest = markdown
        .strip_prefix("---\n")
        .expect("YAML frontmatter start");
    rest.split_once("\n---\n").expect("YAML frontmatter end")
}

fn section<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
    let (_, tail) = text
        .split_once(start)
        .unwrap_or_else(|| panic!("missing section start: {start}"));
    tail.split_once(end)
        .map(|(body, _)| body)
        .unwrap_or_else(|| panic!("missing section end: {end}"))
}

fn backticked_ids(text: &str, prefixes: &[&str]) -> BTreeSet<String> {
    text.split('`')
        .filter(|token| prefixes.iter().any(|prefix| token.starts_with(prefix)))
        .filter(|token| {
            token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        .map(str::to_owned)
        .collect()
}

fn bare_ids(text: &str, prefixes: &[&str]) -> BTreeSet<String> {
    text.split(|character: char| !(character.is_ascii_alphanumeric() || character == '-'))
        .filter(|token| prefixes.iter().any(|prefix| token.starts_with(prefix)))
        .map(str::to_owned)
        .collect()
}

fn regular_relative_files(root: &Path) -> BTreeSet<String> {
    fn visit(root: &Path, current: &Path, files: &mut BTreeSet<String>) {
        let entries = fs::read_dir(current)
            .unwrap_or_else(|error| panic!("read directory {}: {error}", current.display()));
        for entry in entries {
            let entry = entry.expect("directory entry");
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).expect("skill entry metadata");
            assert!(
                !metadata.file_type().is_symlink(),
                "Skill symlink: {}",
                path.display()
            );
            if metadata.is_dir() {
                visit(root, &path, files);
            } else if metadata.is_file() {
                files.insert(
                    path.strip_prefix(root)
                        .expect("Skill relative path")
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            } else {
                panic!("non-regular Skill entry: {}", path.display());
            }
        }
    }

    let mut files = BTreeSet::new();
    visit(root, root, &mut files);
    files
}

fn gtkg_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("GTKG_BIN") {
        let path = PathBuf::from(path);
        assert!(path.is_file(), "GTKG_BIN is not a file: {}", path.display());
        return path;
    }
    let path = workspace_root().join("target/debug/gtkg");
    assert!(
        path.is_file(),
        "build gtkg before running D07: {}",
        path.display()
    );
    path
}

fn help(binary: &Path, arguments: &[&str]) -> String {
    let output = Command::new(binary)
        .args(arguments)
        .output()
        .unwrap_or_else(|error| panic!("run gtkg {}: {error}", arguments.join(" ")));
    assert!(
        output.status.success(),
        "help command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("help is UTF-8")
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

const PUBLIC_OPERATION_IDS: [&str; 34] = [
    "system.describe",
    "config.validate",
    "source.inspect",
    "build.plan",
    "build.prepare",
    "summary.next",
    "summary.accept",
    "build.finalize",
    "run.get",
    "run.cancel",
    "bundle.verify",
    "bundle.query",
    "bundle.compare",
    "snapshot.create",
    "snapshot.verify",
    "snapshot.restore",
    "git.publish",
    "current.get",
    "current.activate",
    "node.describe",
    "federation.validate",
    "template.list",
    "template.resolve",
    "template.prefetch",
    "template.get",
    "template.validate",
    "template.derive",
    "template.publish",
    "deliverable.derive",
    "deliverable.publish",
    "a2ui.resolve",
    "a2ui.generate",
    "a2ui.get",
    "a2ui.validate",
];

const LEGACY_FILES: [(&str, &str, usize); 6] = [
    (
        "templates/design-deliverables/versions/V0.1/prd-template.md",
        "895659a0bd9d0df5a8b5669d2b511bbcc06e2d63c045afb68a3232029c28d382",
        23581,
    ),
    (
        "templates/design-deliverables/versions/V0.1/architecture-template.md",
        "8b62a9ef44e9ee8b302c28040b8dd0c6952daf9f4d2380ece3054b142d4c9712",
        34784,
    ),
    (
        "templates/design-deliverables/versions/V0.1/knowledge-wiki-prototype-template.md",
        "c930461da460d9730e743e599c3104213310c9169bde621982bab7d10e4efc54",
        5942,
    ),
    // Rev 18 G01 trusted plumbing delta: PRD/ARCHITECTURE were updated to record
    // OD-001..OD-005 dispositions; anchors migrated from design-freeze values
    // (PRD baecaae1…/47630, ARCHITECTURE 33ff90af…/40217) to the post-disposition
    // values below. No assertion semantics changed.
    (
        "deliverables/goal-team-knowledge-graph/versions/V0.1/PRD.md",
        "e65552c4112c64655299c6ba812c9bea8d9ae763aca4a10abbf14a9e3c7e5efc",
        48425,
    ),
    (
        "deliverables/goal-team-knowledge-graph/versions/V0.1/ARCHITECTURE.md",
        "e9a72a640335c90d1e44bb20f63d001a47a3dc49a86aa57e0c6dd07f5803896c",
        40692,
    ),
    (
        "deliverables/goal-team-knowledge-graph/versions/V0.1/knowledge-wiki.html",
        "98337ea504c356a9b3866c0e8cfeadb49b6b8f97a0b94287a49c3ed7e1380881",
        60009,
    ),
];
