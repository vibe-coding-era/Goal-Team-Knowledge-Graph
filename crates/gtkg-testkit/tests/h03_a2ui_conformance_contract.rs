//! H03 frozen contract: GTKG `a2ui.generate` output must conform to the
//! official Google A2UI v0.9.1 specification, not to the self-built
//! `local_test_catalog` fixture profile.
//!
//! Oracle (frozen locally, network access forbidden):
//! `docs/external-specs/a2ui-v0.9.1/` whose files are pinned by
//! `docs/external-specs/SHA256SUMS.txt`. Every test re-verifies the SHA-256 of
//! the oracle files before use so oracle drift fails closed.
//!
//! Official compliance points extracted from the oracle:
//! (a) `json/server_to_client.json`: every streamed message is exactly one of
//!     `createSurface` / `updateComponents` / `updateDataModel` /
//!     `deleteSurface` with `version` in {"v0.9", "v0.9.1"}; components must
//!     validate against `catalog.json#/$defs/anyComponent` (mapped to the
//!     official basic catalog per `docs/a2ui_protocol.md` "Swappable Catalogs
//!     & Validation"). Catalog components are closed objects
//!     (`unevaluatedProperties: false`), so GTKG's extra `sourceEntityId`
//!     property is non-conformant.
//! (b) `json/common_types.json` `$defs/Action`: an action is exactly
//!     `{event: {name, context?}}` or `{functionCall: {call, args?}}`; GTKG's
//!     `{"name": "route", "resource": ...}` shape is non-conformant.
//! (c) `catalogs/basic/catalog.json`: the production catalog identity must be
//!     the official basic catalog (`catalogId` == `$id` ==
//!     "https://a2ui.org/specification/v0_9/catalogs/basic/catalog.json"), not
//!     a `local_test_catalog` scope fixture.
//! (d) Evidence state machine: `a2ui_ready_summary` < `a2ui_generatable` <
//!     `renderer_replicable` < `verified_replica`. A generation receipt written
//!     before any locked-browser renderer smoke must not claim more than
//!     `a2ui_generatable`; GTKG currently stamps `renderer_replicable` at
//!     generation time (evidence overclaim, fixed under H04).
//!
//! Evaluator: this file carries a reduced JSON Schema 2020-12 evaluator
//! supporting exactly the keyword subset used by the frozen oracle schemas
//! ($ref across the four official documents, oneOf/anyOf/allOf/not, type,
//! enum, const, required, properties, additionalProperties,
//! unevaluatedProperties, items, minItems, minimum, minProperties,
//! maxProperties). `format`/`pattern`/`default`/`discriminator` are treated as
//! annotations. Fidelity is proven by the control test that replays the
//! official `test/cases/*` suites with their expected valid/invalid verdicts.
//!
//! H03 scope is test-only: the assertions below pin the official direction and
//! are expected to be RED until the A2UI migration (R4) lands.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gtkg_core::file_model::{sha256_file, tree_sha256};
use gtkg_core::{CallContext, Dispatcher, EffectPolicy, TransportKind};
use gtkg_protocol::{OperationId, OperationRequest, OperationResponse, canonical_json_sha256};
use serde_json::{Value, json};
use sha2::Digest;
use tempfile::{TempDir, tempdir};

const LOCAL_MESSAGE_OPERATIONS: [&str; 4] = [
    "createSurface",
    "updateComponents",
    "updateDataModel",
    "deleteSurface",
];

const ENTITY_FIXTURES: [(&str, &str, &str, &str); 12] = [
    (
        "app",
        "src/App.tsx",
        "app-shell-alpha",
        "gtkg-code-static-ts/v1",
    ),
    (
        "route",
        "src/routes.ts",
        "route-docs-bravo",
        "gtkg-code-static-ts/v1",
    ),
    (
        "surface",
        "src/KnowledgeSurface.tsx",
        "surface-wiki-charlie",
        "gtkg-code-static-ts/v1",
    ),
    (
        "component",
        "src/KnowledgeCard.tsx",
        "component-card-delta",
        "gtkg-code-static-ts/v1",
    ),
    (
        "layout",
        "src/layout.css",
        "layout-split-echo",
        "gtkg-css-static/v1",
    ),
    (
        "style_token",
        "src/tokens.css",
        "style-accent-foxtrot",
        "gtkg-css-static/v1",
    ),
    (
        "asset",
        "src/logo.svg",
        "asset-logo-golf",
        "gtkg-svg-static/v1",
    ),
    (
        "interaction",
        "src/OpenButton.tsx",
        "interaction-open-hotel",
        "gtkg-code-static-ts/v1",
    ),
    (
        "data_binding",
        "src/TitleBinding.tsx",
        "binding-title-india",
        "gtkg-code-static-ts/v1",
    ),
    (
        "ui_state",
        "src/state.ts",
        "state-loading-juliet",
        "gtkg-code-static-ts/v1",
    ),
    (
        "accessibility",
        "src/AccessibleNavigation.tsx",
        "a11y-main-kilo",
        "gtkg-code-static-ts/v1",
    ),
    (
        "evidence_ref",
        "src/evidence.md",
        "evidence-source-lima",
        "gtkg-markdown/v1",
    ),
];

#[test]
fn h03_oracle_files_match_frozen_sha256sums() {
    let verified = verify_oracle(&workspace_root());
    assert_eq!(
        verified.len(),
        15,
        "every file under docs/external-specs/a2ui-v0.9.1/ must be pinned"
    );
}

#[test]
fn h03_source_manifest_covers_the_exact_snapshot_with_truthful_provenance() {
    let root = workspace_root();
    let verified = verify_oracle(&root);
    let source: Value = read_json(&root.join("docs/external-specs/A2UI-SOURCE.json"));
    assert_eq!(source["schema_version"], "gtkg.external-spec-source/v1");
    let entries = source["entries"].as_array().expect("source entries");
    assert_eq!(entries.len(), 16, "15 oracle files plus the rendered page");
    let by_path = entries
        .iter()
        .map(|entry| (entry["path"].as_str().expect("source path"), entry))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(by_path.len(), entries.len(), "source paths must be unique");
    for (relative, digest) in verified {
        let name = relative.strip_prefix("a2ui-v0.9.1/").expect("oracle path");
        let entry = by_path
            .get(relative.as_str())
            .unwrap_or_else(|| panic!("source manifest missing {relative}"));
        assert_eq!(entry["sha256"], digest);
        let observed = sha256_hex(&oracle_path(&root, name));
        assert_eq!(observed, digest);
        if entry["conformance_role"] == "informational_only" {
            assert!(
                entry["source_kind"] == "retained_snapshot_unverified_origin"
                    || entry["source_kind"] == "a2ui_org_rendered_page"
            );
        } else {
            assert!(entry["source_url"].as_str().is_some());
        }
    }
    let html = by_path
        .get("a2ui-spec-v0.9.1.html")
        .expect("rendered page provenance");
    assert_eq!(
        html["sha256"],
        sha256_hex(&root.join("docs/external-specs/a2ui-spec-v0.9.1.html"))
    );
}

#[test]
fn h03_vendored_runtime_oracle_is_byte_identical_to_the_frozen_snapshot() {
    let root = workspace_root();
    let vendor = root.join("crates/gtkg-core/vendor/a2ui/v0_9_1");
    for (vendored, oracle) in [
        ("server_to_client.json", "json/server_to_client.json"),
        ("client_to_server.json", "json/client_to_server.json"),
        ("common_types.json", "json/common_types.json"),
        ("catalog.json", "catalogs/basic/catalog.json"),
        ("rules.txt", "catalogs/basic/rules.txt"),
    ] {
        assert_eq!(
            fs::read(vendor.join(vendored)).expect("vendored oracle"),
            fs::read(oracle_path(&root, oracle)).expect("frozen oracle"),
            "vendored A2UI oracle drifted: {vendored}"
        );
    }
}

#[test]
fn h03_official_cases_validate_with_frozen_evaluator() {
    let root = workspace_root();
    verify_oracle(&root);
    let schemas = OfficialSchemas::load(&root);
    for (case_file, schema) in [
        ("test/cases/button_checks.json", &schemas.server_to_client),
        ("test/cases/client_messages.json", &schemas.client_to_server),
    ] {
        let cases: Value = read_json(&oracle_path(&root, case_file));
        for case in cases["tests"].as_array().expect("official tests array") {
            let mut errors = Vec::new();
            schemas.validate(
                &case["data"],
                schema,
                schema,
                case["description"].as_str().unwrap_or("case"),
                &mut errors,
                0,
            );
            let expected = case["valid"].as_bool().expect("official valid flag");
            assert_eq!(
                errors.is_empty(),
                expected,
                "official case {:?} verdict mismatch: {errors:?}",
                case["description"]
            );
        }
    }
    // Official example stream: every line must validate against
    // server_to_client.json with catalog.json mapped to the basic catalog.
    let example =
        fs::read_to_string(oracle_path(&root, "test/cases/contact_form_example.jsonl")).unwrap();
    for (index, line) in example.lines().enumerate() {
        let message: Value = serde_json::from_str(line).expect("official example line");
        let mut errors = Vec::new();
        schemas.validate(
            &message,
            &schemas.server_to_client,
            &schemas.server_to_client,
            &format!("contact_form_example.jsonl:{index}"),
            &mut errors,
            0,
        );
        assert!(
            errors.is_empty(),
            "official contact_form example line {index} must validate: {errors:?}"
        );
    }
}

#[test]
fn h03_official_schema_rejects_closed_component_extras_and_ambiguous_actions() {
    let root = workspace_root();
    verify_oracle(&root);
    let schemas = OfficialSchemas::load(&root);

    let message = json!({
        "version": "v0.9",
        "updateComponents": {
            "surfaceId": "surface",
            "components": [{
                "id": "root",
                "component": "Text",
                "text": "Hello",
                "sourceEntityId": "forbidden-extra"
            }]
        }
    });
    let mut errors = Vec::new();
    schemas.validate(
        &message,
        &schemas.server_to_client,
        &schemas.server_to_client,
        "closed-component-extra",
        &mut errors,
        0,
    );
    assert!(
        !errors.is_empty(),
        "closed component extras must be rejected"
    );

    let action = json!({
        "event": {"name": "submit"},
        "functionCall": {"call": "openUrl"}
    });
    let action_schema = schemas
        .common_types
        .pointer("/$defs/Action")
        .expect("official Action schema");
    errors.clear();
    schemas.validate(
        &action,
        action_schema,
        &schemas.common_types,
        "ambiguous-action",
        &mut errors,
        0,
    );
    assert!(
        !errors.is_empty(),
        "an action containing both event and functionCall must fail oneOf"
    );
}

#[test]
fn h03_stream_messages_validate_against_official_server_to_client_schema() {
    let root = workspace_root();
    verify_oracle(&root);
    let schemas = OfficialSchemas::load(&root);
    let generated = Generated::new();
    let mut violations = Vec::new();
    for (index, message) in generated.stream.iter().enumerate() {
        schemas.validate(
            message,
            &schemas.server_to_client,
            &schemas.server_to_client,
            &format!("stream.jsonl:{index}"),
            &mut violations,
            0,
        );
    }
    assert!(
        violations.is_empty(),
        "GTKG stream must validate against official server_to_client.json \
         (basic catalog closure, unevaluatedProperties: false):\n{}",
        violations.join("\n")
    );
}

#[test]
fn h03_button_action_uses_official_event_or_function_call_shape() {
    let root = workspace_root();
    verify_oracle(&root);
    let schemas = OfficialSchemas::load(&root);
    let generated = Generated::new();
    let action_schema = schemas
        .common_types
        .pointer("/$defs/Action")
        .expect("official common_types Action definition");
    let mut violations = Vec::new();
    for component in generated.components() {
        if component["component"].as_str() != Some("Button") {
            continue;
        }
        schemas.validate(
            &component["action"],
            action_schema,
            &schemas.common_types,
            &format!("Button {:?}", component["id"]),
            &mut violations,
            0,
        );
    }
    assert!(
        violations.is_empty(),
        "GTKG Button actions must use the official {{event: {{name, context?}}}} \
         or {{functionCall: {{call, args?}}}} shape (common_types.json $defs/Action):\n{}",
        violations.join("\n")
    );
}

#[test]
fn h03_catalog_identity_is_official_basic_catalog_not_local_test_scope() {
    let root = workspace_root();
    verify_oracle(&root);
    let schemas = OfficialSchemas::load(&root);
    let official_catalog_id = schemas.catalog["catalogId"]
        .as_str()
        .expect("official basic catalog catalogId");
    // a2ui_protocol.md: catalog documents carry both `$id` and `catalogId`,
    // set to the same URI.
    assert_eq!(schemas.catalog["$id"].as_str(), Some(official_catalog_id));

    let generated = Generated::new();
    assert_eq!(
        generated.resolved.result["catalog_scope"].as_str(),
        Some("official_basic_catalog"),
        "production catalog scope must be the official basic catalog, \
         not the self-built local_test_catalog fixture"
    );
    assert_eq!(
        generated.resolved.result["a2ui_lock"]["catalog_id"].as_str(),
        Some(official_catalog_id),
        "resolution lock catalog_id must be the official basic catalog identity"
    );
    let create_surface = generated
        .stream
        .iter()
        .find_map(|message| message.get("createSurface"))
        .expect("stream createSurface");
    assert_eq!(
        create_surface["catalogId"].as_str(),
        Some(official_catalog_id),
        "stream createSurface.catalogId must name the official basic catalog"
    );
}

#[test]
fn h03_generation_receipt_evidence_state_capped_at_a2ui_generatable() {
    let root = workspace_root();
    verify_oracle(&root);
    let generated = Generated::new();
    // No locked-browser renderer smoke ran in this fixture, so nothing in the
    // generation outputs may claim more than `a2ui_generatable`.
    let manifest: Value = read_json(&generated.projection.join("projection-manifest.json"));
    for (label, state) in [
        (
            "a2ui.generate result",
            generated.response.result["evidence_state"].as_str(),
        ),
        (
            "projection-manifest.json",
            manifest["evidence_state"].as_str(),
        ),
    ] {
        let state = state.unwrap_or_else(|| panic!("{label} missing evidence_state"));
        let observed = evidence_rank(state)
            .unwrap_or_else(|| panic!("{label} has unknown evidence_state {state}"));
        let ceiling = evidence_rank("a2ui_generatable").expect("known state");
        assert!(
            observed <= ceiling,
            "{label} evidence_state {state} overclaims: generation without \
             renderer smoke must not exceed a2ui_generatable"
        );
    }
}

#[test]
fn h03_update_data_model_carries_selected_knowledge_content() {
    let root = workspace_root();
    verify_oracle(&root);
    let generated = Generated::new();
    let data_model = generated.data_model();

    // Data-binding contract: every absolute JSON Pointer bound by a component
    // must resolve against the delivered updateDataModel payloads.
    let mut unresolved = Vec::new();
    for component in generated.components() {
        for path in binding_paths(component) {
            if path.starts_with('/') && resolve_pointer(&data_model, &path).is_none() {
                unresolved.push(format!("component {:?} binding {path}", component["id"]));
            }
        }
    }
    assert!(
        unresolved.is_empty(),
        "component data bindings must resolve in the updateDataModel payloads:\n{}",
        unresolved.join("\n")
    );

    // Compliance direction: the selected knowledge document content is data
    // and must be delivered through updateDataModel, not baked into components
    // or dropped to hardcoded placeholders.
    let selected = generated.selected_resource();
    let selected_content = String::from_utf8(
        hex::decode(selected["content"].as_str().expect("selected content hex"))
            .expect("selected content bytes"),
    )
    .expect("selected content UTF-8");
    assert_eq!(
        data_model["document"]["body"], selected_content,
        "updateDataModel must carry the selected knowledge document content"
    );
}

struct OfficialSchemas {
    server_to_client: Value,
    client_to_server: Value,
    common_types: Value,
    catalog: Value,
}

impl OfficialSchemas {
    fn load(root: &Path) -> Self {
        Self {
            server_to_client: read_json(&oracle_path(root, "json/server_to_client.json")),
            client_to_server: read_json(&oracle_path(root, "json/client_to_server.json")),
            common_types: read_json(&oracle_path(root, "json/common_types.json")),
            catalog: read_json(&oracle_path(root, "catalogs/basic/catalog.json")),
        }
    }

    fn resolve<'a>(&'a self, current_root: &'a Value, reference: &str) -> (&'a Value, &'a Value) {
        let (base, fragment) = reference.split_once('#').unwrap_or((reference, ""));
        let root = if base.is_empty() {
            current_root
        } else {
            match base.rsplit('/').next().unwrap_or(base) {
                "catalog.json" => &self.catalog,
                "common_types.json" => &self.common_types,
                "client_to_server.json" => &self.client_to_server,
                "server_to_client.json" => &self.server_to_client,
                other => panic!("H03 evaluator cannot resolve $ref base {other}"),
            }
        };
        let target = if fragment.is_empty() {
            root
        } else {
            root.pointer(fragment)
                .unwrap_or_else(|| panic!("H03 evaluator unresolved $ref {reference}"))
        };
        (target, root)
    }

    fn validate(
        &self,
        instance: &Value,
        schema: &Value,
        root: &Value,
        path: &str,
        errors: &mut Vec<String>,
        depth: usize,
    ) {
        if depth > 96 {
            errors.push(format!("{path}: evaluator depth limit exceeded"));
            return;
        }
        let Some(object) = schema.as_object() else {
            if schema.as_bool() == Some(false) {
                errors.push(format!("{path}: rejected by false schema"));
            }
            return;
        };
        if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
            let (target, target_root) = self.resolve(root, reference);
            self.validate(instance, target, target_root, path, errors, depth + 1);
        }
        if let Some(kind) = object.get("type").and_then(Value::as_str) {
            let matches = match kind {
                "array" => instance.is_array(),
                "boolean" => instance.is_boolean(),
                "integer" => instance.as_i64().is_some() || instance.as_u64().is_some(),
                "null" => instance.is_null(),
                "number" => instance.is_number(),
                "object" => instance.is_object(),
                "string" => instance.is_string(),
                other => panic!("H03 evaluator unsupported type {other}"),
            };
            if !matches {
                errors.push(format!("{path}: expected schema type {kind}"));
            }
        }
        if let Some(expected) = object.get("const")
            && instance != expected
        {
            errors.push(format!("{path}: const mismatch (expected {expected})"));
        }
        if let Some(values) = object.get("enum").and_then(Value::as_array)
            && !values.contains(instance)
        {
            errors.push(format!("{path}: enum mismatch (value {instance})"));
        }
        if let Some(minimum) = object.get("minimum").and_then(Value::as_f64)
            && instance.as_f64().is_some_and(|value| value < minimum)
        {
            errors.push(format!("{path}: below minimum {minimum}"));
        }
        if let Some(minimum) = object.get("minItems").and_then(Value::as_u64)
            && instance
                .as_array()
                .is_some_and(|items| items.len() < minimum as usize)
        {
            errors.push(format!("{path}: fewer than minItems {minimum}"));
        }
        if let Some(bound) = object.get("minProperties").and_then(Value::as_u64)
            && instance
                .as_object()
                .is_some_and(|map| map.len() < bound as usize)
        {
            errors.push(format!("{path}: fewer than minProperties {bound}"));
        }
        if let Some(bound) = object.get("maxProperties").and_then(Value::as_u64)
            && instance
                .as_object()
                .is_some_and(|map| map.len() > bound as usize)
        {
            errors.push(format!("{path}: more than maxProperties {bound}"));
        }
        if let Some(required) = object.get("required").and_then(Value::as_array)
            && let Some(map) = instance.as_object()
        {
            for property in required.iter().filter_map(Value::as_str) {
                if !map.contains_key(property) {
                    errors.push(format!("{path}: missing required property {property}"));
                }
            }
        }
        let declared: BTreeSet<&str> = object
            .get("properties")
            .and_then(Value::as_object)
            .map(|properties| properties.keys().map(String::as_str).collect())
            .unwrap_or_default();
        if let Some(properties) = object.get("properties").and_then(Value::as_object)
            && let Some(map) = instance.as_object()
        {
            for (property, child_schema) in properties {
                if let Some(child) = map.get(property) {
                    self.validate(
                        child,
                        child_schema,
                        root,
                        &format!("{path}/{property}"),
                        errors,
                        depth + 1,
                    );
                }
            }
        }
        if let Some(map) = instance.as_object() {
            match object.get("additionalProperties") {
                Some(Value::Bool(false)) => {
                    for property in map.keys() {
                        if !declared.contains(property.as_str()) {
                            errors.push(format!("{path}: additional property {property}"));
                        }
                    }
                }
                Some(child_schema @ Value::Object(_)) => {
                    for (property, child) in map {
                        if !declared.contains(property.as_str()) {
                            self.validate(
                                child,
                                child_schema,
                                root,
                                &format!("{path}/{property}"),
                                errors,
                                depth + 1,
                            );
                        }
                    }
                }
                _ => {}
            }
        }
        if object.get("unevaluatedProperties").and_then(Value::as_bool) == Some(false)
            && let Some(map) = instance.as_object()
        {
            let mut evaluated = BTreeSet::new();
            self.collect_properties(schema, root, &mut evaluated, 0);
            for property in map.keys() {
                if !evaluated.contains(property.as_str()) {
                    errors.push(format!(
                        "{path}: unevaluated property {property} (catalog objects are closed)"
                    ));
                }
            }
        }
        if let Some(item_schema) = object.get("items")
            && let Some(items) = instance.as_array()
        {
            for (index, item) in items.iter().enumerate() {
                self.validate(
                    item,
                    item_schema,
                    root,
                    &format!("{path}/{index}"),
                    errors,
                    depth + 1,
                );
            }
        }
        if let Some(branches) = object.get("allOf").and_then(Value::as_array) {
            for branch in branches {
                self.validate(instance, branch, root, path, errors, depth + 1);
            }
        }
        if let Some(branches) = object.get("anyOf").and_then(Value::as_array) {
            let matched = branches
                .iter()
                .filter(|branch| {
                    let mut scratch = Vec::new();
                    self.validate(instance, branch, root, path, &mut scratch, depth + 1);
                    scratch.is_empty()
                })
                .count();
            if matched == 0 {
                errors.push(format!("{path}: anyOf matched no branch"));
            }
        }
        if let Some(branches) = object.get("oneOf").and_then(Value::as_array) {
            let mut matched = 0;
            let mut branch_errors = Vec::new();
            for (index, branch) in branches.iter().enumerate() {
                let mut scratch = Vec::new();
                self.validate(instance, branch, root, path, &mut scratch, depth + 1);
                if scratch.is_empty() {
                    matched += 1;
                } else {
                    branch_errors.push(format!("branch {index}: {}", scratch.join("; ")));
                }
            }
            if matched != 1 {
                errors.push(format!(
                    "{path}: oneOf matched {matched} branches ({})",
                    branch_errors.join(" | ")
                ));
            }
        }
        if let Some(negated) = object.get("not") {
            let mut scratch = Vec::new();
            self.validate(instance, negated, root, path, &mut scratch, depth + 1);
            if scratch.is_empty() {
                errors.push(format!("{path}: violated not constraint"));
            }
        }
    }

    fn collect_properties(
        &self,
        schema: &Value,
        root: &Value,
        set: &mut BTreeSet<String>,
        depth: usize,
    ) {
        if depth > 96 {
            return;
        }
        let Some(object) = schema.as_object() else {
            return;
        };
        if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
            let (target, target_root) = self.resolve(root, reference);
            self.collect_properties(target, target_root, set, depth + 1);
        }
        if let Some(properties) = object.get("properties").and_then(Value::as_object) {
            set.extend(properties.keys().cloned());
        }
        for keyword in ["allOf", "oneOf", "anyOf"] {
            if let Some(branches) = object.get(keyword).and_then(Value::as_array) {
                for branch in branches {
                    self.collect_properties(branch, root, set, depth + 1);
                }
            }
        }
    }
}

fn evidence_rank(state: &str) -> Option<u8> {
    match state {
        "a2ui_ready_summary" => Some(0),
        "a2ui_generatable" => Some(1),
        "renderer_replicable" => Some(2),
        "verified_replica" => Some(3),
        _ => None,
    }
}

fn binding_paths(value: &Value) -> Vec<String> {
    let mut paths = Vec::new();
    collect_binding_paths(value, &mut paths);
    paths
}

fn collect_binding_paths(value: &Value, paths: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            if let Some(path) = value.get("path").and_then(Value::as_str) {
                paths.push(path.to_owned());
            }
            for child in map.values() {
                collect_binding_paths(child, paths);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_binding_paths(item, paths);
            }
        }
        _ => {}
    }
}

fn resolve_pointer<'a>(model: &'a Value, pointer: &str) -> Option<&'a Value> {
    if pointer == "/" || pointer.is_empty() {
        return Some(model);
    }
    model.pointer(pointer)
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn oracle_path(root: &Path, relative: &str) -> PathBuf {
    root.join("docs/external-specs/a2ui-v0.9.1").join(relative)
}

fn verify_oracle(root: &Path) -> BTreeMap<String, String> {
    let sums = fs::read_to_string(root.join("docs/external-specs/SHA256SUMS.txt"))
        .expect("frozen SHA256SUMS.txt");
    let mut verified = BTreeMap::new();
    for line in sums.lines() {
        let Some((digest, relative)) = line.split_once("  ") else {
            continue;
        };
        let Some(name) = relative.strip_prefix("a2ui-v0.9.1/") else {
            continue;
        };
        let actual = sha256_hex(&oracle_path(root, name));
        assert_eq!(actual, digest, "A2UI oracle drifted: {relative}");
        verified.insert(relative.to_owned(), actual);
    }
    assert!(
        !verified.is_empty(),
        "SHA256SUMS.txt pins no a2ui-v0.9.1 oracle files"
    );
    verified
}

fn sha256_hex(path: &Path) -> String {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    hex::encode(sha2::Sha256::digest(bytes))
}

struct Generated {
    _temp: TempDir,
    projection: PathBuf,
    resolved: OperationResponse,
    response: OperationResponse,
    stream: Vec<Value>,
}

impl Generated {
    fn new() -> Self {
        let fixture = Fixture::new();
        let context = fixture.context();
        let resolved = fixture.resolve(&context);
        let response = execute_ok(
            &context,
            OperationId::A2uiGenerate,
            json!({
                "workspace_root": fixture.workspace,
                "expected_bundle_tree_sha256": fixture.bundle_tree_sha256,
                "bundle_path": fixture.bundle,
                "resolution_ref": resolved.result["resolution_ref"],
                "projection_version": "0.4.0",
            }),
        );
        let projection = PathBuf::from(
            response.result["projection_path"]
                .as_str()
                .expect("projection"),
        );
        let stream = fs::read_to_string(projection.join("a2ui/stream.jsonl"))
            .expect("stream.jsonl")
            .lines()
            .map(|line| serde_json::from_str(line).expect("stream line is JSON"))
            .collect();
        Self {
            _temp: fixture._temp,
            projection,
            resolved,
            response,
            stream,
        }
    }

    fn components(&self) -> Vec<&Value> {
        self.stream
            .iter()
            .filter_map(|message| message.get("updateComponents"))
            .flat_map(|update| update["components"].as_array().expect("components"))
            .collect()
    }

    fn data_model(&self) -> Value {
        let mut model = json!({});
        for message in &self.stream {
            if let Some(update) = message.get("updateDataModel") {
                let path = update["path"].as_str().unwrap_or("/");
                assert!(
                    path == "/" || path.is_empty(),
                    "H03 fixture expects whole-model updateDataModel, got path {path}"
                );
                if let Some(value) = update.get("value") {
                    model = value.clone();
                }
            }
        }
        model
    }

    fn selected_resource(&self) -> Value {
        let selected = fs::read_to_string(self.projection.join("wiki/bootstrap/selected.js"))
            .expect("selected bootstrap");
        let hex_body = selected
            .trim()
            .strip_prefix("globalThis.__GTKG_SELECTED_HEX__=\"")
            .and_then(|body| body.strip_suffix("\";"))
            .expect("selected bootstrap shape");
        serde_json::from_slice(&hex::decode(hex_body).expect("selected hex"))
            .expect("selected resource JSON")
    }
}

struct Fixture {
    _temp: TempDir,
    root: PathBuf,
    workspace: PathBuf,
    catalog: PathBuf,
    bundle: PathBuf,
    catalog_manifest_sha256: String,
    bundle_tree_sha256: String,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().to_path_buf();
        let workspace = root.join("workspace");
        let repository = root.join("frontend-repository");
        let template_catalog = root.join("template-catalog");
        let catalog = root.join("a2ui-catalog");
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(repository.join("src")).unwrap();

        let fixture_identity = canonical_json_sha256(&root.to_string_lossy().to_string()).unwrap();
        let fixture_nonce = &fixture_identity[7..15];
        for (kind, logical_path, marker_base, _) in ENTITY_FIXTURES {
            let marker = format!("{marker_base}-{fixture_nonce}");
            fs::write(
                repository.join(logical_path),
                frontend_fixture_source(kind, &marker),
            )
            .unwrap();
        }
        init_and_commit(&repository);
        create_template_catalog(&template_catalog);
        create_a2ui_catalog(&catalog);
        let catalog_manifest_sha256 = sha256_file(&catalog.join("manifest.json")).unwrap();

        let context = CallContext::restricted(
            TransportKind::Test,
            vec![root.clone()],
            EffectPolicy::WorkspaceWrite,
        )
        .unwrap();
        let inspected = execute_ok(
            &context,
            OperationId::SourceInspect,
            json!({
                "workspace_root": workspace,
                "repositories": [{
                    "repo_id": "frontend",
                    "path": repository,
                    "role": "frontend",
                    "include": []
                }]
            }),
        );
        let source_inspection_ref = inspected.result["inspection_ref"].clone();
        let template_resolved = execute_ok(
            &context,
            OperationId::TemplateResolve,
            json!({
                "workspace_root": workspace,
                "catalog_root": template_catalog,
                "template_id": "summary-template",
                "version": "0.1.0"
            }),
        );
        let template_validated = execute_ok(
            &context,
            OperationId::TemplateValidate,
            json!({
                "workspace_root": workspace,
                "resolution_ref": template_resolved.result["resolution_ref"]
            }),
        );
        let template_ref = template_validated.result["validation_ref"].clone();
        let mut plan_request = OperationRequest::new(
            OperationId::BuildPlan,
            "h03-build-plan",
            json!({
                "workspace_root": workspace,
                "mode": "full",
                "source_inspection_ref": source_inspection_ref,
                "template_validation_ref": template_ref,
                "baseline_bundle": null,
                "bundle_version": "51.0.0"
            }),
        );
        plan_request.locks = BTreeMap::from([
            (
                "source_inspection".to_owned(),
                source_inspection_ref["sha256"].as_str().unwrap().to_owned(),
            ),
            (
                "template_validation".to_owned(),
                template_ref["sha256"].as_str().unwrap().to_owned(),
            ),
        ]);
        let planned = Dispatcher
            .execute(&context, plan_request)
            .expect("build.plan");
        let run_id = planned.run_id.expect("run id");
        execute_ok_run(
            &context,
            OperationId::BuildPrepare,
            &run_id,
            "h03-build-prepare",
            json!({"workspace_root": workspace}),
        );
        loop {
            let next = execute_ok_run(
                &context,
                OperationId::SummaryNext,
                &run_id,
                "h03-summary-next",
                json!({"workspace_root": workspace}),
            );
            let Some(job) = next.result.get("job").filter(|value| !value.is_null()) else {
                break;
            };
            execute_ok_run(
                &context,
                OperationId::SummaryAccept,
                &run_id,
                &format!("h03-summary-{}", job["packet_id"].as_str().unwrap()),
                json!({
                    "workspace_root": workspace,
                    "packet_id": job["packet_id"],
                    "source_sha256": job["source_sha256"],
                    "template_manifest_sha256": job["template_manifest_sha256"],
                    "summary_markdown": format!(
                        "# Static frontend analysis\n\nrepo_id: {}\nlogical_path: {}\nextractor: gtkg-static-fixture/v1\n\n```text\n{}\n```",
                        job["repo_id"].as_str().unwrap(),
                        job["source_path"].as_str().unwrap(),
                        job["analysis_text"].as_str().unwrap()
                    )
                }),
            );
        }
        let finalized = execute_ok_run(
            &context,
            OperationId::BuildFinalize,
            &run_id,
            "h03-build-finalize",
            json!({"workspace_root": workspace}),
        );
        let bundle = PathBuf::from(finalized.result["bundle_path"].as_str().unwrap());
        let bundle_tree_sha256 = finalized.result["tree_digest"].as_str().unwrap().to_owned();
        assert_eq!(tree_sha256(&bundle).unwrap(), bundle_tree_sha256);

        Self {
            _temp: temp,
            root,
            workspace,
            catalog,
            bundle,
            catalog_manifest_sha256,
            bundle_tree_sha256,
        }
    }

    fn context(&self) -> CallContext {
        CallContext::restricted(
            TransportKind::Test,
            vec![self.root.clone()],
            EffectPolicy::WorkspaceWrite,
        )
        .unwrap()
    }

    fn resolve(&self, context: &CallContext) -> OperationResponse {
        execute_ok(
            context,
            OperationId::A2uiResolve,
            json!({
                "workspace_root": self.workspace,
                "catalog_root": self.catalog,
                "spec_version": "0.9.1",
                "profile_id": "gtkg-test-profile",
                "profile_version": "0.9.1",
                "catalog_id": "gtkg-test-catalog",
                "catalog_version": "0.1.0",
                "renderer_id": "gtkg-test-renderer",
                "renderer_version": "test-only",
                "expected_manifest_sha256": self.catalog_manifest_sha256,
            }),
        )
    }
}

fn execute_ok(context: &CallContext, operation: OperationId, payload: Value) -> OperationResponse {
    Dispatcher
        .execute(
            context,
            OperationRequest::new(operation, format!("h03-{}", operation.as_str()), payload),
        )
        .unwrap_or_else(|error| {
            panic!(
                "{} failed at {}: {}",
                operation.as_str(),
                error.error.stage,
                error.error.message
            )
        })
}

fn execute_ok_run(
    context: &CallContext,
    operation: OperationId,
    run_id: &str,
    request_id: &str,
    payload: Value,
) -> OperationResponse {
    let mut request = OperationRequest::new(operation, request_id, payload);
    request.run_id = Some(run_id.to_owned());
    Dispatcher
        .execute(context, request)
        .unwrap_or_else(|error| panic!("{} failed: {error:#?}", operation.as_str()))
}

fn create_a2ui_catalog(root: &Path) {
    fs::create_dir_all(root).unwrap();
    fs::write(
        root.join("schema.json"),
        serde_json::to_vec_pretty(&json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "urn:gtkg:a2ui-message:v0.9",
            "version": "v0.9.1",
            "type": "object",
            "required": ["version"],
            "properties": {
                "version": {"const": "v0.9"},
                "createSurface": {"$ref": "#/$defs/createSurface"},
                "updateComponents": {"$ref": "#/$defs/updateComponents"},
                "updateDataModel": {"$ref": "#/$defs/updateDataModel"},
                "deleteSurface": {"$ref": "#/$defs/deleteSurface"}
            },
            "oneOf": LOCAL_MESSAGE_OPERATIONS.map(|operation| json!({"required": [operation]})),
            "additionalProperties": false,
            "$defs": {
                "sourceEntityId": {"type": "string", "minLength": 1},
                "action": {
                    "type": "object",
                    "required": ["name", "resource"],
                    "properties": {
                        "name": {"const": "route"},
                        "resource": {"const": "selected_okf_document"}
                    },
                    "additionalProperties": false
                },
                "component": {
                    "type": "object",
                    "required": ["id", "component", "sourceEntityId"],
                    "properties": {
                        "id": {"type": "string", "minLength": 1},
                        "component": {"enum": ["Button", "Column", "List", "Row", "Text"]},
                        "sourceEntityId": {"$ref": "#/$defs/sourceEntityId"},
                        "children": {"type": "array", "items": {"type": "string"}},
                        "child": {"type": "string"},
                        "text": {"type": "object"},
                        "action": {"$ref": "#/$defs/action"}
                    },
                    "additionalProperties": false
                },
                "createSurface": {
                    "type": "object",
                    "required": ["surfaceId", "catalogId"],
                    "properties": {
                        "surfaceId": {"type": "string", "minLength": 1},
                        "catalogId": {"const": "gtkg-test-catalog"}
                    },
                    "additionalProperties": false
                },
                "updateComponents": {
                    "type": "object",
                    "required": ["surfaceId", "components"],
                    "properties": {
                        "surfaceId": {"type": "string", "minLength": 1},
                        "components": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/component"}}
                    },
                    "additionalProperties": false
                },
                "updateDataModel": {
                    "type": "object",
                    "required": ["surfaceId", "path", "value"],
                    "properties": {
                        "surfaceId": {"type": "string", "minLength": 1},
                        "path": {"const": "/"},
                        "value": {
                            "type": "object",
                            "required": ["sourceEntityIds"],
                            "properties": {
                                "sourceEntityIds": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/sourceEntityId"}},
                                "title": {"type": "string"}
                            },
                            "additionalProperties": false
                        }
                    },
                    "additionalProperties": false
                },
                "deleteSurface": {
                    "type": "object",
                    "required": ["surfaceId"],
                    "properties": {"surfaceId": {"type": "string", "minLength": 1}},
                    "additionalProperties": false
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        root.join("profile.json"),
        serde_json::to_vec_pretty(&json!({
            "schema_version": "gtkg.a2ui-profile/v1",
            "id": "gtkg-test-profile",
            "version": "0.9.1",
            "mime_type": "application/a2ui+json",
            "wire_version": "v0.9",
            "schema_id": "urn:gtkg:a2ui-message:v0.9",
            "common_types_id": "gtkg-test-common-types",
            "catalog_id": "gtkg-test-catalog",
            "catalog_version": "0.1.0"
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        root.join("common_types.json"),
        serde_json::to_vec_pretty(&json!({
            "schema_version": "gtkg.a2ui-common-types/v1",
            "id": "gtkg-test-common-types",
            "version": "0.1.0",
            "wire_version": "v0.9",
            "types": {
                "entity_id": {"type": "string", "min_length": 1},
                "action_name": {"enum": ["route"]},
                "resource": {"enum": ["selected_okf_document"]}
            }
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        root.join("catalog.json"),
        r#"{"id":"gtkg-test-catalog","version":"0.1.0","components":["Button","Column","List","Row","Text"],"actions":["gtkg.select_document"]}"#,
    )
    .unwrap();
    fs::write(
        root.join("renderer.json"),
        serde_json::to_vec_pretty(&json!({
            "schema_version": "gtkg.a2ui-renderer-contract/v1",
            "id": "gtkg-test-renderer",
            "version": "test-only",
            "status": "fixture_not_production",
            "catalog_id": "gtkg-test-catalog",
            "catalog_version": "0.1.0",
            "supported_components": ["Button", "Column", "List", "Row", "Text"],
            "supported_actions": ["gtkg.select_document"]
        }))
        .unwrap(),
    )
    .unwrap();
    let manifest = json!({
        "schema_version": "gtkg.a2ui-local-catalog-manifest/v1",
        "spec_version": "0.9.1",
        "profile": {"id": "gtkg-test-profile", "version": "0.9.1", "path": "profile.json", "sha256": sha256_file(&root.join("profile.json")).unwrap()},
        "schema": {"path": "schema.json", "sha256": sha256_file(&root.join("schema.json")).unwrap()},
        "common_types": {"id": "gtkg-test-common-types", "version": "0.1.0", "path": "common_types.json", "sha256": sha256_file(&root.join("common_types.json")).unwrap()},
        "catalog": {"id": "gtkg-test-catalog", "version": "0.1.0", "path": "catalog.json", "sha256": sha256_file(&root.join("catalog.json")).unwrap()},
        "renderer": {"id": "gtkg-test-renderer", "version": "test-only", "path": "renderer.json", "sha256": sha256_file(&root.join("renderer.json")).unwrap()},
        "scope": "local_test_catalog"
    });
    fs::write(
        root.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

fn create_template_catalog(catalog: &Path) {
    let staging = catalog.join("summary-template/versions/staging");
    fs::create_dir_all(&staging).unwrap();
    let template = staging.join("template.md");
    fs::write(
        &template,
        "---\ntype: template\ntitle: Summary\ndescription: H03 static analysis fixture\nresource: ./template.md\ntags: [fixture]\ngenerated: false\nverified: false\nstatus: validated\nsources: []\nokf_version: '0.2'\ngtkg:\n  schema: gtkg.template/v1\n---\n\n# Summary\n",
    )
    .unwrap();
    let manifest = json!({
        "schema_version": "gtkg.template-manifest/v1",
        "template_id": "summary-template",
        "version": "0.1.0",
        "template_file": "template.md",
        "template_sha256": sha256_file(&template).unwrap(),
        "slot_ids": ["summary"]
    });
    fs::write(
        staging.join("template-manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    let digest = canonical_json_sha256(&manifest).unwrap();
    fs::rename(
        &staging,
        staging
            .parent()
            .unwrap()
            .join(format!("v0.1.0--{}", &digest[7..19])),
    )
    .unwrap();
}

fn frontend_fixture_source(kind: &str, marker: &str) -> String {
    match kind {
        "app" => format!(
            "export function App() {{ return <div data-app-id=\"{marker}\"><KnowledgeSurface /></div>; }}\n"
        ),
        "route" => {
            format!("export const docsRoute = {{ id: \"{marker}\", path: \"/docs\" }} as const;\n")
        }
        "surface" => format!(
            "export function KnowledgeSurface() {{ return <main data-surface-id=\"{marker}\" />; }}\n"
        ),
        "component" => format!(
            "export function KnowledgeCard() {{ return <article data-component-id=\"{marker}\" />; }}\n"
        ),
        "layout" => {
            format!(".{marker} {{ display: grid; grid-template-columns: 20rem minmax(0, 1fr); }}\n")
        }
        "style_token" => format!(":root {{ --{marker}: #3366ff; }}\n"),
        "asset" => format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 16 16\"><symbol id=\"{marker}\"><path d=\"M0 0h1v1z\"/></symbol></svg>\n"
        ),
        "interaction" => format!(
            "export function OpenButton() {{ return <button onClick={{() => openKnowledge(\"{marker}\")}}>Open</button>; }}\n"
        ),
        "data_binding" => format!(
            "export function TitleBinding({{ model }}) {{ return <h1>{{model[\"{marker}\"]}}</h1>; }}\n"
        ),
        "ui_state" => format!(
            "export const initialUiState = {{ stateId: \"{marker}\", loading: true, error: null }} as const;\n"
        ),
        "accessibility" => format!(
            "export function AccessibleNavigation() {{ return <nav aria-label=\"{marker}\" />; }}\n"
        ),
        "evidence_ref" => format!(
            "---\ntype: evidence\ntitle: Unsafe <script>alert(1)</script>\ndescription: Static evidence reference\nresource: ./evidence.md\ntags: [frontend, evidence]\ngenerated: false\nverified: false\nstatus: candidate\nsources: []\nokf_version: '0.2'\ngtkg:\n  schema: gtkg.frontend-evidence/v1\n  evidence_ref: {marker}\n---\n\n# Evidence\n\n<img src=x onerror=alert(1)> [bad](javascript:alert(1)) <svg><foreignObject>bad</foreignObject></svg> ../../outside\n"
        ),
        other => panic!("unsupported frontend entity fixture {other}"),
    }
}

fn init_and_commit(root: &Path) {
    git(root, &["init"]);
    git(root, &["config", "user.name", "GTKG Fixture"]);
    git(root, &["config", "user.email", "fixture@invalid.example"]);
    git(root, &["add", "-A"]);
    git(root, &["commit", "-m", "fixture"]);
}

fn git(root: &Path, arguments: &[&str]) {
    let output = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(root)
        .args(arguments)
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

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
