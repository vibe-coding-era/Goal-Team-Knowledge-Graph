//! E02 frozen contract: AST/syntax-level semantic extraction for Rust, Python,
//! TypeScript, and JavaScript.
//!
//! Oracles:
//! (a) per-language definition precision/recall/F1 over the gold corpus is
//!     computable and F1 >= 0.90.
//! (b) per-language import/call edge F1 >= 0.80.
//! (c) every semantic record span selects its marker exactly in the source.
//! (d) extraction is deterministic: the same input twice yields the same
//!     semantics digest.
//! (e) syntax-error files degrade to the legacy lexical mode without panicking.
//! (f) target_process_count stays 0 and target content is never executed.
//!
//! Semantic records live in `observations` (legacy `observed_facts` are
//! untouched): `semantic_definitions`, `semantic_imports`, `semantic_calls`,
//! `semantic_inherits` hold sorted, deduplicated tab-separated record lines and
//! `semantics_digest` pins the deterministic digest of those sections.

use std::collections::BTreeSet;
use std::fs;

use gtkg_extract::{ExtractedDocument, extract_path};
use tempfile::tempdir;

const DEFINITION_F1_FLOOR: f64 = 0.90;
const EDGE_F1_FLOOR: f64 = 0.80;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DefinitionRecord {
    kind: String,
    name: String,
    start: usize,
    end: usize,
    line_start: u64,
    line_end: u64,
    signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SpanRecord {
    fields: Vec<String>,
    start: usize,
    end: usize,
    line: u64,
}

#[derive(Debug, Default)]
struct Semantics {
    mode: String,
    engine: String,
    definitions: Vec<DefinitionRecord>,
    imports: Vec<SpanRecord>,
    calls: Vec<SpanRecord>,
    inherits: Vec<SpanRecord>,
    digest: String,
}

fn parse_semantics(extracted: &ExtractedDocument) -> Semantics {
    let observations = &extracted.observations;
    let definitions = observations
        .get("semantic_definitions")
        .map(|section| {
            section
                .lines()
                .map(|line| {
                    let columns: Vec<&str> = line.split('\t').collect();
                    assert_eq!(columns.len(), 7, "definition record shape: {line}");
                    DefinitionRecord {
                        kind: columns[0].to_owned(),
                        name: columns[1].to_owned(),
                        start: columns[2].parse().expect("definition start"),
                        end: columns[3].parse().expect("definition end"),
                        line_start: columns[4].parse().expect("definition line start"),
                        line_end: columns[5].parse().expect("definition line end"),
                        signature: columns[6].to_owned(),
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    let parse_spans = |key: &str, arity: usize| -> Vec<SpanRecord> {
        observations
            .get(key)
            .map(|section| {
                section
                    .lines()
                    .map(|line| {
                        let columns: Vec<&str> = line.split('\t').collect();
                        assert_eq!(columns.len(), arity + 3, "{key} record shape: {line}");
                        SpanRecord {
                            fields: columns[..arity]
                                .iter()
                                .map(|field| (*field).to_owned())
                                .collect(),
                            start: columns[arity].parse().expect("span start"),
                            end: columns[arity + 1].parse().expect("span end"),
                            line: columns[arity + 2].parse().expect("span line"),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    Semantics {
        mode: observations
            .get("semantic_mode")
            .cloned()
            .unwrap_or_default(),
        engine: observations
            .get("semantic_engine")
            .cloned()
            .unwrap_or_default(),
        definitions,
        imports: parse_spans("semantic_imports", 1),
        calls: parse_spans("semantic_calls", 2),
        inherits: parse_spans("semantic_inherits", 2),
        digest: observations
            .get("semantics_digest")
            .cloned()
            .unwrap_or_default(),
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct F1 {
    precision: f64,
    recall: f64,
    f1: f64,
}

fn score<T: Ord>(gold: &BTreeSet<T>, observed: &BTreeSet<T>) -> F1 {
    let hits = gold.intersection(observed).count() as f64;
    let precision = if observed.is_empty() {
        0.0
    } else {
        hits / observed.len() as f64
    };
    let recall = if gold.is_empty() {
        1.0
    } else {
        hits / gold.len() as f64
    };
    let f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };
    F1 {
        precision,
        recall,
        f1,
    }
}

struct GoldCorpus {
    file_name: &'static str,
    source: &'static str,
    definitions: &'static [(&'static str, &'static str)],
    imports: &'static [&'static str],
    calls: &'static [(&'static str, &'static str)],
    inherits: &'static [(&'static str, &'static str)],
}

const RUST_CORPUS: GoldCorpus = GoldCorpus {
    file_name: "ledger.rs",
    source: r#"use std::collections::HashMap;
use crate::model::{Ledger, Entry};

pub mod ledger;

pub type AccountId = u64;
pub const MAX_RETRIES: u32 = 3;

pub struct Account {
    pub id: AccountId,
    pub name: String,
}

pub enum Status {
    Active,
    Closed,
}

pub trait Describe {
    fn describe(&self) -> String;
}

impl Describe for Account {
    fn describe(&self) -> String {
        self.name.clone()
    }
}

impl Account {
    pub fn new(id: AccountId, name: String) -> Self {
        Self { id, name }
    }

    pub fn rename(&mut self, name: String) {
        self.name = name;
    }
}

pub fn reconcile(account: &Account, ledger: &Ledger) -> bool {
    let described = account.describe();
    described.len() > 0 && ledger.is_empty()
}

fn load_entry(store: &HashMap<AccountId, Entry>) -> Option<&Entry> {
    store.values().next()
}

fn helper() {
    let account = Account::new(1, "cash".to_owned());
    reconcile(&account, &Ledger::default());
}
"#,
    definitions: &[
        ("module", "ledger"),
        ("type", "AccountId"),
        ("variable", "MAX_RETRIES"),
        ("struct", "Account"),
        ("field", "id"),
        ("field", "name"),
        ("enum", "Status"),
        ("trait", "Describe"),
        ("method", "describe"),
        ("impl", "Account"),
        ("method", "new"),
        ("method", "rename"),
        ("function", "reconcile"),
        ("function", "load_entry"),
        ("function", "helper"),
    ],
    imports: &[
        "std::collections::HashMap",
        "crate::model::Ledger",
        "crate::model::Entry",
    ],
    calls: &[
        ("describe", "clone"),
        ("reconcile", "describe"),
        ("reconcile", "len"),
        ("reconcile", "is_empty"),
        ("load_entry", "values"),
        ("load_entry", "next"),
        ("helper", "new"),
        ("helper", "to_owned"),
        ("helper", "reconcile"),
        ("helper", "default"),
    ],
    inherits: &[("Account", "Describe")],
};

const PYTHON_CORPUS: GoldCorpus = GoldCorpus {
    file_name: "ledger.py",
    source: r#"import json
import os.path
from typing import Optional
from pkg.model import Ledger, Entry

MAX_RETRIES = 3


class Base:
    def label(self):
        return "base"


class Account(Base):
    def __init__(self, account_id: int, name: str):
        self.account_id = account_id
        self.name = name

    def describe(self) -> str:
        return json.dumps({"id": self.account_id})


async def reconcile(account: Account, ledger: Ledger) -> bool:
    described = account.describe()
    return len(described) > 0


def load_entry(store: dict) -> Optional[Entry]:
    return next(iter(store.values()))


def helper():
    account = Account(1, "cash")
    return reconcile(account, Ledger())
"#,
    definitions: &[
        ("variable", "MAX_RETRIES"),
        ("class", "Base"),
        ("method", "label"),
        ("class", "Account"),
        ("method", "__init__"),
        ("method", "describe"),
        ("function", "reconcile"),
        ("function", "load_entry"),
        ("function", "helper"),
    ],
    imports: &[
        "json",
        "os.path",
        "typing.Optional",
        "pkg.model.Ledger",
        "pkg.model.Entry",
    ],
    calls: &[
        ("describe", "dumps"),
        ("reconcile", "describe"),
        ("reconcile", "len"),
        ("load_entry", "next"),
        ("load_entry", "iter"),
        ("load_entry", "values"),
        ("helper", "Account"),
        ("helper", "reconcile"),
        ("helper", "Ledger"),
    ],
    inherits: &[("Account", "Base")],
};

const TYPESCRIPT_CORPUS: GoldCorpus = GoldCorpus {
    file_name: "ledger.ts",
    source: r#"import { Ledger } from "./model/ledger";
import * as utils from "../utils";

export type AccountId = number;
export const MAX_RETRIES: number = 3;

export interface Describable {
  describe(): string;
}

export enum Status {
  Active,
  Closed,
}

export class Account implements Describable {
  id: AccountId;
  name: string;

  constructor(id: AccountId, name: string) {
    this.id = id;
    this.name = name;
  }

  describe(): string {
    return `${this.id}:${this.name}`;
  }
}

export class LedgerAccount extends Account {
  ledger: Ledger;

  audit(): string {
    return this.describe();
  }
}

export function reconcile(account: Account, ledger: Ledger): boolean {
  return account.describe().length > 0 && utils.check(ledger);
}

export function loadEntry(store: Map<AccountId, Entry>): Entry | undefined {
  return store.values().next().value;
}

const helper = (account: Account): string => {
  return reconcile(account, new Ledger()) ? "ok" : "no";
};
"#,
    definitions: &[
        ("type", "AccountId"),
        ("variable", "MAX_RETRIES"),
        ("interface", "Describable"),
        ("method", "describe"),
        ("enum", "Status"),
        ("class", "Account"),
        ("field", "id"),
        ("field", "name"),
        ("method", "constructor"),
        ("class", "LedgerAccount"),
        ("field", "ledger"),
        ("method", "audit"),
        ("function", "reconcile"),
        ("function", "loadEntry"),
        ("variable", "helper"),
    ],
    imports: &["./model/ledger", "../utils"],
    calls: &[
        ("reconcile", "describe"),
        ("reconcile", "check"),
        ("loadEntry", "values"),
        ("loadEntry", "next"),
        ("helper", "reconcile"),
        ("helper", "Ledger"),
        ("audit", "describe"),
    ],
    inherits: &[("Account", "Describable"), ("LedgerAccount", "Account")],
};

const JAVASCRIPT_CORPUS: GoldCorpus = GoldCorpus {
    file_name: "ledger.js",
    source: r#"import { Ledger } from "./model/ledger.js";
const utils = require("../utils");

class Account {
  constructor(id, name) {
    this.id = id;
    this.name = name;
  }

  describe() {
    return `${this.id}:${this.name}`;
  }
}

class LedgerAccount extends Account {
  audit() {
    return this.describe();
  }
}

function reconcile(account, ledger) {
  return account.describe().length > 0 && utils.check(ledger);
}

function loadEntry(store) {
  return store.values().next().value;
}

const helper = (account) => {
  return reconcile(account, new Ledger()) ? "ok" : "no";
};

module.exports = { reconcile, loadEntry, helper };
"#,
    definitions: &[
        ("variable", "utils"),
        ("class", "Account"),
        ("method", "constructor"),
        ("method", "describe"),
        ("class", "LedgerAccount"),
        ("method", "audit"),
        ("function", "reconcile"),
        ("function", "loadEntry"),
        ("variable", "helper"),
    ],
    imports: &["./model/ledger.js", "../utils"],
    calls: &[
        ("audit", "describe"),
        ("reconcile", "describe"),
        ("reconcile", "check"),
        ("loadEntry", "values"),
        ("loadEntry", "next"),
        ("helper", "reconcile"),
        ("helper", "Ledger"),
    ],
    inherits: &[("LedgerAccount", "Account")],
};

fn gold_definitions(corpus: &GoldCorpus) -> BTreeSet<(String, String)> {
    corpus
        .definitions
        .iter()
        .map(|(kind, name)| ((*kind).to_owned(), (*name).to_owned()))
        .collect()
}

fn observed_definitions(semantics: &Semantics) -> BTreeSet<(String, String)> {
    semantics
        .definitions
        .iter()
        .map(|record| (record.kind.clone(), record.name.clone()))
        .collect()
}

fn observed_edges(records: &[SpanRecord]) -> BTreeSet<Vec<String>> {
    records.iter().map(|record| record.fields.clone()).collect()
}

fn gold_edges(edges: &[(&str, &str)]) -> BTreeSet<Vec<String>> {
    edges
        .iter()
        .map(|(from, to)| vec![(*from).to_owned(), (*to).to_owned()])
        .collect()
}

fn extract_corpus(temp: &tempfile::TempDir, corpus: &GoldCorpus) -> ExtractedDocument {
    let path = temp.path().join(corpus.file_name);
    fs::write(&path, corpus.source).expect("write gold corpus source");
    extract_path(&path).expect("static extraction succeeds")
}

fn assert_language_contract(temp: &tempfile::TempDir, corpus: &GoldCorpus) -> Semantics {
    let sentinel = temp
        .path()
        .join(format!("{}.must-not-exist", corpus.file_name));
    let extracted = extract_corpus(temp, corpus);
    let semantics = parse_semantics(&extracted);

    assert_eq!(
        semantics.mode, "ast",
        "{} must be parsed at AST level",
        corpus.file_name
    );
    assert!(
        !semantics.engine.is_empty(),
        "{} must record the parsing engine",
        corpus.file_name
    );

    let gold_defs = gold_definitions(corpus);
    let observed_defs = observed_definitions(&semantics);
    let definition_score = score(&gold_defs, &observed_defs);
    assert!(
        definition_score.f1 >= DEFINITION_F1_FLOOR,
        "{} definition F1 {:.3} < {:.2} (precision {:.3}, recall {:.3})\nmissing: {:?}\nextra: {:?}",
        corpus.file_name,
        definition_score.f1,
        DEFINITION_F1_FLOOR,
        definition_score.precision,
        definition_score.recall,
        gold_defs.difference(&observed_defs).collect::<Vec<_>>(),
        observed_defs.difference(&gold_defs).collect::<Vec<_>>(),
    );

    let gold_imports: BTreeSet<Vec<String>> = corpus
        .imports
        .iter()
        .map(|module| vec![(*module).to_owned()])
        .collect();
    let import_score = score(&gold_imports, &observed_edges(&semantics.imports));
    let call_score = score(&gold_edges(corpus.calls), &observed_edges(&semantics.calls));
    let edge_f1 = (import_score.f1 + call_score.f1) / 2.0;
    assert!(
        import_score.f1 >= EDGE_F1_FLOOR && call_score.f1 >= EDGE_F1_FLOOR,
        "{} edge F1 below floor: import {:.3}, call {:.3} (floor {:.2})\nmissing imports: {:?}\nextra imports: {:?}\nmissing calls: {:?}\nextra calls: {:?}",
        corpus.file_name,
        import_score.f1,
        call_score.f1,
        EDGE_F1_FLOOR,
        gold_imports
            .difference(&observed_edges(&semantics.imports))
            .collect::<Vec<_>>(),
        observed_edges(&semantics.imports)
            .difference(&gold_imports)
            .collect::<Vec<_>>(),
        gold_edges(corpus.calls)
            .difference(&observed_edges(&semantics.calls))
            .collect::<Vec<_>>(),
        observed_edges(&semantics.calls)
            .difference(&gold_edges(corpus.calls))
            .collect::<Vec<_>>(),
    );
    assert!(
        edge_f1 >= EDGE_F1_FLOOR,
        "{} combined edge F1 {:.3} < {:.2}",
        corpus.file_name,
        edge_f1,
        EDGE_F1_FLOOR
    );

    let gold_inherits = gold_edges(corpus.inherits);
    let observed_inherits = observed_edges(&semantics.inherits);
    assert_eq!(
        gold_inherits, observed_inherits,
        "{} inherit/impl edges",
        corpus.file_name
    );

    assert_eq!(extracted.target_process_count, 0, "{}", corpus.file_name);
    assert!(!extracted.executed_target_content, "{}", corpus.file_name);
    assert!(
        !sentinel.exists(),
        "{} must never execute target content",
        corpus.file_name
    );
    semantics
}

#[test]
fn rust_ast_semantics_meet_frozen_f1_thresholds() {
    let temp = tempdir().expect("tempdir");
    assert_language_contract(&temp, &RUST_CORPUS);
}

#[test]
fn python_ast_semantics_meet_frozen_f1_thresholds() {
    let temp = tempdir().expect("tempdir");
    assert_language_contract(&temp, &PYTHON_CORPUS);
}

#[test]
fn typescript_ast_semantics_meet_frozen_f1_thresholds() {
    let temp = tempdir().expect("tempdir");
    assert_language_contract(&temp, &TYPESCRIPT_CORPUS);
}

#[test]
fn javascript_ast_semantics_meet_frozen_f1_thresholds() {
    let temp = tempdir().expect("tempdir");
    assert_language_contract(&temp, &JAVASCRIPT_CORPUS);
}

#[test]
fn semantic_record_spans_select_their_marker_exactly() {
    let temp = tempdir().expect("tempdir");
    for corpus in [
        &RUST_CORPUS,
        &PYTHON_CORPUS,
        &TYPESCRIPT_CORPUS,
        &JAVASCRIPT_CORPUS,
    ] {
        let extracted = extract_corpus(&temp, corpus);
        let semantics = parse_semantics(&extracted);
        let source = corpus.source;
        let line_of = |offset: usize| source[..offset].matches('\n').count() as u64 + 1;

        for record in &semantics.definitions {
            assert_eq!(
                source.get(record.start..record.end),
                Some(record.name.as_str()),
                "{} definition {}:{} span",
                corpus.file_name,
                record.kind,
                record.name
            );
            assert_eq!(record.line_start, line_of(record.start), "line start");
            assert!(record.line_end >= record.line_start, "line ordering");
            assert!(
                !record.signature.is_empty() && !record.signature.contains('\n'),
                "{} definition {} signature must be one normalized line",
                corpus.file_name,
                record.name
            );
        }
        for record in &semantics.imports {
            let module = &record.fields[0];
            let slice = source
                .get(record.start..record.end)
                .expect("import span in range");
            let last_segment = module
                .rsplit([':', '.'])
                .find(|segment| !segment.is_empty() && *segment != "*")
                .expect("import has a trailing segment");
            assert!(
                slice == module || slice == last_segment,
                "{} import span must select the written module path or its leaf: {module} vs {slice}",
                corpus.file_name
            );
            assert_eq!(record.line, line_of(record.start), "import line");
        }
        for record in &semantics.calls {
            let callee = &record.fields[1];
            assert_eq!(
                source.get(record.start..record.end),
                Some(callee.as_str()),
                "{} call {}->{} span",
                corpus.file_name,
                record.fields[0],
                callee
            );
            assert_eq!(record.line, line_of(record.start), "call line");
        }
        for record in &semantics.inherits {
            let parent = &record.fields[1];
            let slice = source
                .get(record.start..record.end)
                .expect("inherit span in range");
            let last_segment = parent.rsplit([':', '.']).next().expect("parent segment");
            assert!(
                slice == parent || slice == last_segment,
                "{} inherit span: {parent} vs {slice}",
                corpus.file_name
            );
        }
    }
}

#[test]
fn semantic_extraction_is_deterministic_across_runs() {
    let temp = tempdir().expect("tempdir");
    for corpus in [
        &RUST_CORPUS,
        &PYTHON_CORPUS,
        &TYPESCRIPT_CORPUS,
        &JAVASCRIPT_CORPUS,
    ] {
        let first = parse_semantics(&extract_corpus(&temp, corpus));
        let second = parse_semantics(&extract_corpus(&temp, corpus));
        assert!(
            first.digest.starts_with("sha256:"),
            "{} semantics digest",
            corpus.file_name
        );
        assert_eq!(
            first.digest, second.digest,
            "{} digest must be stable",
            corpus.file_name
        );
        assert_eq!(first.definitions, second.definitions);
        assert_eq!(first.imports, second.imports);
        assert_eq!(first.calls, second.calls);
        assert_eq!(first.inherits, second.inherits);
        for section in [
            "semantic_definitions",
            "semantic_imports",
            "semantic_calls",
            "semantic_inherits",
        ] {
            let third = extract_corpus(&temp, corpus);
            let section_text = third
                .observations
                .get(section)
                .expect("semantic section")
                .clone();
            let lines: Vec<&str> = section_text.lines().collect();
            let mut sorted = lines.clone();
            sorted.sort();
            sorted.dedup();
            assert_eq!(
                lines, sorted,
                "{section} must be a sorted deduplicated set for {}",
                corpus.file_name
            );
        }
    }
}

#[test]
fn syntax_errors_degrade_to_legacy_lexical_mode_without_panic() {
    let temp = tempdir().expect("tempdir");
    let fixtures: [(&str, &str, &str); 4] = [
        ("broken.rs", "pub fn broken( {\n", "function:broken"),
        ("broken.py", "def broken(:\n    pass\n", "function:broken"),
        (
            "broken.ts",
            "export function broken( {\n",
            "function:broken",
        ),
        ("broken.js", "function broken( {\n", "function:broken"),
    ];
    for (name, source, expected_symbol) in fixtures {
        let path = temp.path().join(name);
        fs::write(&path, source).expect("write broken fixture");
        let extracted = extract_path(&path).expect("parse failure must degrade, not error");
        let semantics = parse_semantics(&extracted);
        assert_eq!(
            semantics.mode, "fallback_lexical",
            "{name} must record the degraded semantic mode"
        );
        assert!(
            semantics.definitions.is_empty()
                && semantics.imports.is_empty()
                && semantics.calls.is_empty(),
            "{name} must not emit semantic records in fallback mode"
        );
        let symbols = extracted
            .observations
            .get("symbols")
            .expect("legacy lexical symbols survive fallback");
        assert!(
            symbols.lines().any(|symbol| symbol == expected_symbol),
            "{name} legacy lexical symbol {expected_symbol} survives fallback"
        );
        assert_eq!(extracted.target_process_count, 0, "{name}");
        assert!(!extracted.executed_target_content, "{name}");
    }
}

#[test]
fn lexical_facts_and_symbols_coexist_with_semantic_records() {
    let temp = tempdir().expect("tempdir");
    for corpus in [
        &RUST_CORPUS,
        &PYTHON_CORPUS,
        &TYPESCRIPT_CORPUS,
        &JAVASCRIPT_CORPUS,
    ] {
        let extracted = extract_corpus(&temp, corpus);
        let symbols = extracted
            .observations
            .get("symbols")
            .expect("legacy lexical symbols stay present");
        assert!(
            !symbols.is_empty(),
            "{} legacy lexical symbols stay present",
            corpus.file_name
        );
        for fact in &extracted.observed_facts {
            let start = fact.span.start as usize;
            let end = fact.span.end as usize;
            assert_eq!(
                corpus.source.as_bytes().get(start..end),
                Some(fact.marker_id.as_bytes()),
                "{} legacy fact span still selects its marker",
                corpus.file_name
            );
        }
    }
}
