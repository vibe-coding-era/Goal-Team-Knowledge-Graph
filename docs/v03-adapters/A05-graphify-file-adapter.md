# A05 Graphify `graph.json` file adapter

## Scope

A05 consumes one caller-authorized, digest-pinned offline `graph.json`. It does not install or start Graphify, run target code, call a provider, access the network, write files, or obtain GTKG canonical-writer authority.

The reviewed producer identity is Graphify `0.9.52`, commit `680e3ed8edd3dc1fa1961050912941880b778207`, under Apache-2.0. The schema pin describes the exact node-link root and the node, link, and hyperedge identity fields reviewed at that commit. These pins establish an adapter contract; they do not claim that Graphify was installed or executed locally.

## Revision authority

`import_pinned_graphify_json_file_v1` and its immutable `bbdb7ca5…` test remain as a legacy regression so the original Red/Green history is reproducible. V1 is superseded by strict V2 and is not an A05 acceptance authority: its historical fixture does not require `graph.hyperedges` to equal the top-level hyperedge set.

`import_pinned_graphify_json_file_v2`, `GraphifyGraphPinV2`, and `GraphifyImportReceiptV2` are the acceptance-authoritative successor. V2 adds:

- an independent `MAX_GRAPHIFY_BYTES_V1` hard ceiling of 64 MiB applied beneath the caller pin;
- exact canonical-set equality between `graph.hyperedges` and top-level `hyperedges`, with duplicate rejection;
- official one-member and two-member hyperedge support before explicit V0.3 omission projection;
- exact blob pins for `export.py`, `validate.py`, `pyproject.toml`, `LICENSE`, and the extraction specification;
- receipt binding for both hyperedge slots and recomputed confidence, locator, denominator, and zero-effect counts.

The canonical schema material and derivation are frozen in `deliverables/v03-development/test-receipts/a05-upstream-pin.json`. Its schema digest is `sha256:3bad32555ba7930ca4856522d2a643cd70e1f305b1c2fd98ff1aa54bd34445ac`.

## Trust mapping

Graphify link confidence is mapped without promotion:

| Graphify confidence | GTKG trust | With source location | Without source location |
|---|---|---|---|
| `EXTRACTED` | `extracted` | `candidate_external` | `locator_only` |
| `INFERRED` | `inferred` | `candidate_external` | `locator_only` |
| `AMBIGUOUS` | `ambiguous` | `ambiguous` | `ambiguous` |

Graphify nodes have no confidence enum, so their trust remains `unverified`; a present source location makes the node a candidate locator, while a missing location remains `locator_only`.

`source_file` plus `source_location` is retained separately as a `GraphifySourceLocatorV1`. It is never converted into `ExternalEvidenceV1`, because `graph.json` does not carry exact source bytes, byte spans, or snippet digests. Consequently, A00 exact-source replay resolves zero Graphify facts until a later verifier supplies independently pinned source bytes.

## Closed denominator

Nodes and binary links are admitted as candidate facts. V0.3's external fact schema has no hyperedge representation, so every Graphify hyperedge is counted in `discovered_count` and emitted as an explicit omission whose reason retains its original confidence state. No hyperedge is silently dropped.

The receipt binds the file, schema, producer, license, source snapshot, source repository commit, adapter descriptor, bundle, all node/link/hyperedge counts, confidence counts, locator counts, and zero-effect counters.

## Fail-closed boundaries

Import rejects:

- file digest, schema, Graphify version/commit/license, source snapshot, or source repository identity drift;
- malformed or non-node-link root shapes;
- symlink, hardlink, non-regular, oversized, or identity-changing inputs;
- duplicate nodes/links/hyperedges or dangling endpoints/members;
- unsupported file types, unsafe source paths, invalid IDs/relations, and unbounded locations;
- confidence-score combinations outside Graphify's reviewed `EXTRACTED`, `INFERRED`, and `AMBIGUOUS` rubric.

## Verification

The immutable A05 contract is `sha256:bbdb7ca585573d6b9b06acd95d50cb65e3d2aa597ed00a6903770f97864bafd4`. Its first Red was unresolved adapter API (`E0432`). The implementation Green is 8/8 A05 tests, with 6/6 A00 integration tests and successful scoped Clippy checks. Development evidence does not prove a Graphify install, a real competitor export, Benchmark execution, Release, or external conformance.

The strict successor contract is `sha256:8b531aba30d8b1424e0e52dc68fa60893fbcddb80726011547bd2f3e1a54810a`. Its Red is the missing V2 API/pin/receipt surface; its Green is 7/7 successor tests. The affected chain is also Green for legacy V1 8/8, A00 6/6, and B00 6/6. Strict V2, rather than V1, supplies the accepted A05 result.

Primary reviewed sources:

- <https://github.com/Graphify-Labs/graphify/blob/680e3ed8edd3dc1fa1961050912941880b778207/graphify/export.py>
- <https://github.com/Graphify-Labs/graphify/blob/680e3ed8edd3dc1fa1961050912941880b778207/graphify/validate.py>
- <https://github.com/Graphify-Labs/graphify/blob/680e3ed8edd3dc1fa1961050912941880b778207/LICENSE>
