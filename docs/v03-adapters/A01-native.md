# A01 Native Adapter

Status: `local_development_green`; independent semantic review is still a separate parent-graph gate.

## Scope and identity

The native adapter exposes the existing V0.2 Rust, Python, TypeScript, and JavaScript static extractors through A00's `ExternalFactBundleV1` interface. Its descriptor is digest-bound as:

- adapter id: `gtkg.adapter.native`
- adapter version: `0.3.0`
- adapter kind: `native`
- extractor source commit: `ad8b801fa53245336ef137b9f46d29742cc63af4`
- license: `Apache-2.0`
- trust policy: `gtkg.adapter-trust/v1`

`adapt_native_path_v1` accepts a validated `SourceSnapshotV2`, a snapshot logical path, and a caller-authorized physical read path. It refuses snapshot/admission/extractor-identity mismatch before producing a bundle.

## Projection contract

| V0.2 typed IR state | A00 candidate state | A00 trust state | Candidate ids |
|---|---|---|---|
| semantic node | `candidate_external` | `extracted` | not applicable |
| resolved same-file edge | `candidate_external` | `extracted` | exact resolved node id |
| ambiguous edge | `ambiguous` | `ambiguous` | all exact candidate node ids |
| unresolved edge | `locator_only` | `inferred` | empty |
| not-applicable edge | `locator_only` | `unverified` | empty |
| parser fallback | no semantic facts | no promoted trust | one `parser_fallback_lexical` omission |

Every admitted node, edge, and evidence span preserves the V0.2 stable id, kind/reference, logical path, source digest, byte range, snippet digest, and evidence references. A00 exact source replay remains the only path from `candidate_external` to `resolved_verified`; the adapter itself has no canonical authority.

## Side-effect boundary

The production path performs one caller-selected source-file content read. It reports and enforces:

- target process count: `0`
- executed target content: `false`
- network call count: `0`
- write count: `0`

It does not start language servers, runtimes, package managers, or sidecars. It does not write graph, index, Current, assistant configuration, or canonical state.

## Development evidence

The frozen test is `crates/gtkg-testkit/tests/v03_a01_native_adapter_contract.rs` with SHA-256 `fddf719d9645f0708bff214d5cc3c03cf9eaa3ad0d566c6a01a63636ac2a9027` for both Red and Green.

- Red: [`a01-red.json`](../../deliverables/v03-development/test-runs/a01-red.json)
- Green and affected surface: [`a01-green.json`](../../deliverables/v03-development/test-runs/a01-green.json)
- four valid and four malformed V0.3 fixtures are byte-identical to the frozen V0.2 T02 corpus counterparts
- A01 6/6, A00 6/6, V0.2 T02 8/8, V0.2 T05 7/7, and E02 semantics 8/8 passed
- scoped `rustfmt --check` and scoped clippy with `-D warnings` passed

## Explicit non-claims

This A01 evidence does not prove workspace import resolution, type/CFG/def-use/state-flow semantics, external-language coverage, adapter-join correctness, full V0.3 regression, Release, installation, publication, Provider behavior, or business acceptance. Those remain owned by their graph successors and final Development/Release gates.
