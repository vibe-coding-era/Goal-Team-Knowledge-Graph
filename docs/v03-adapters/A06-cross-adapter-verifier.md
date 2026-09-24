# A06 cross-adapter verifier Gate

## Outcome

A06 consumes real outputs from Native, SCIP, frozen LSP snapshot, CodeGraph community export, and strict Graphify V2. It validates each descriptor, bundle, source map, source locator set, import receipt, caller input budget, and independent semantic oracle before emitting one deterministic, non-canonical Gate receipt.

The original 9/9 candidate and its failed independent reviews remain preserved. Authoritative acceptance now routes only through `verify_adapter_gate_sealed_strict_v1`, which accepts sealed actual-input observations and a deserialized `AdapterTrustedOracleFixtureV1`. The fixture persists all 12 `AdapterSemanticOracleV1` expectations, source-judgment notes, expected oracle SHA, review-material SHA, and pin SHA; runtime submissions never generate its authority. The reviewed fixture is `trusted-oracle-pin.json`, expected oracle `sha256:f59b399229016b698332d27259f4e240a310e55e141643c5a4429266fe4bad91`.

Receipts carry a machine-readable authority state. `verify_adapter_gate_v1` returns `untrusted_legacy` with no trusted pin; the r3 pin-only compatibility path returns `trusted_pin_bound`; the r4 persisted-fixture compatibility path returns `trusted_fixture_bound` with trusted pin and canonical fixture digests but no actual-input binding. Plain or pin-only receipts cannot pass `validate_strict_against`, and none of these three states is authoritative after r5.

R5 adds the final authoritative input boundary. `AdapterSubmissionV1`, `untrusted_legacy`, `trusted_pin_bound`, and fixture-only `trusted_fixture_bound` remain readable but non-authoritative. Only `verify_adapter_gate_sealed_strict_v1` accepts `StrictAdapterSubmissionV1` with a `SealedInputObservationV1` byte slice and returns `trusted_fixture_input_bound`.

The sealed Gate computes actual byte length and SHA internally. It requires actual length to equal the legacy declaration, remain within the configured maximum and 64 MiB hard cap, and match the adapter import receipt's file SHA for SCIP/LSP/CodeGraph/Graphify. Native actual bytes must exactly equal the replay `source_files` bytes. The resulting sealed-input-set digest is part of the strict receipt and is recomputed by `validate_sealed_strict_against`.

The Gate is read-only. It never starts a target process, adapter daemon, provider, or network request; it writes neither intermediate nor canonical product state.

## Source replay and semantic target verification

A00 exact source replay remains the byte/span verifier. A06 additionally requires every evidence-bearing `candidate_external + extracted` fact to resolve through exact replay. Changed bytes, missing files, invalid spans, and inferred evidence presented as extracted fail closed.

Every imported edge has an expectation keyed by adapter descriptor digest and fact ID. The expectation binds candidate state, trust state, exact candidate node IDs, and accepted target references. Aliases are accepted only when frozen in this independent oracle and when at least one exact source snippet replays to an accepted reference. A single valid-looking but wrong known node ID is rejected.

## Receipt strict `validate_against`

Adapter self-validation is necessary but not sufficient. A06 recomputes receipt categories from the attached bundle and source locator set:

- SCIP symbols, relationships, documents, and denominator;
- LSP symbols versus diagnostics, relationships, ranges, and denominator;
- CodeGraph nodes, links, locator-only facts, evidence count, and denominator;
- Graphify V2 extracted/inferred/ambiguous relationships, hyperedge omissions, dual-slot count, locators, missing locations, locator-only facts, and denominator;
- Native source reads and zero-effect boundary.

This rejects a receipt whose categories were redistributed and then re-digested while its totals remained arithmetically valid.

The final Gate receipt is not allowed to self-attest. `AdapterGateReceiptV1::validate_sealed_strict_against` reruns the sealed trusted Gate from exact submissions, actual bytes, persisted oracle fixture, and verifier identity, then requires byte-equivalent structured fields. Re-digested mutations of evidence count, source-locator count, resolved count, input-set identity, sealed-input identity, or collision groups are rejected.

## Coverage, omissions, and collisions

The Gate requires exactly one of all five adapter kinds. Aggregate omission closure is `discovered = admitted + omitted`, with a required 10,000 basis points result and a non-zero denominator.

Stable node/edge-ID collisions, node/edge fact-ID collisions, and normalized same-name/target conflicts are recorded with all members. The collision report has no winner and no selected fact IDs. A06 itself is never canonical-eligible and has zero canonical writes.

## Independent input cap

`MAX_ADAPTER_INPUT_BYTES_V1` is 64 MiB and applies above every caller-supplied input bound. A configured bound above the cap, an observed input above its configured bound, or a zero-sized claimed input is rejected before semantic verification. This closes the A03 implementation-level cap successor at the A06 Gate without modifying the accepted A03 adapter.

## Verification and boundaries

The immutable r2 test is `sha256:cc7b1906bd185773e7608b749504233a340e4ade7a2f67918e515c9c490fdc3e`; the implementation is `sha256:24e20202b8c35b055cce3de39d8101d6b19ae300598c222e7b898c090582e69e`. A06 is 9/9 and A00–A05 affected tests are 54/54.

That r2 implementation is retained as the failed-review candidate. The trusted r3 successor test is `sha256:d793bd91030e4bc564fac34efa32f1fd655ccd1521ed7b074208453d1d49c169`; the current implementation is `sha256:e561af700719e9453cde65a74ccfc165319dddb4e3fd727aade1f59647452613`. The successor target is 12/12, including the original 9 tests plus three review-closing tests; A00–A05 remain 54/54.

R3 remains preserved as the pin-only review candidate. The persisted-oracle r4 test is `sha256:61747ae1396492c129ba3256c4f3ce9c330f5ad1d40a37fb2b105b1771414064`; the current implementation is `sha256:2fd1485e354561622d67952b3beb0882d6bed8c8165993e3f9bee2f5f4609997`. R4 is 15/15, r3 remains 12/12, the original candidate remains 9/9, and A00–A05 remain 54/54.

R4 remains preserved as the persisted-oracle but input-unbound candidate. The sealed-input r5 test is `sha256:315789f907b21950c171a20d458d9f548811a07d06ce98b6338611f1f7645a3d`; the current implementation is `sha256:0f956fb250b06751ab172d3fb4e0941fa1b195616b9ffd24ba9ee6fd7c3ecc0d`. R5 is 18/18, r4 remains 15/15, and A00–A05 remain 54/54.

P02 adapter/security behavior remains Green, but two whole-target legacy assertions are partial after parallel P03 changed the v2 implemented-operation and core-profile counts. A06 does not rewrite those P02 literals.

This is local Development evidence. It does not prove real CodeGraph/Graphify execution, Provider behavior, external semantic conformance, Benchmark results, Release/install, or business acceptance.
