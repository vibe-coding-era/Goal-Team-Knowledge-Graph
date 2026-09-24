# A03 Frozen LSP Snapshot Adapter

Status: `local_development_green`; Runtime + Semantic independent validation remains a separate
parent-graph gate.

## File-only identity contract

`import_pinned_lsp_snapshot_json_file_v1` reads one bounded regular, private-inode JSON file. On
Unix it opens the final component with `O_NOFOLLOW`, rejects symlinks and files with more than one
hardlink, and binds the pre-open, descriptor, post-read, and path-readback inode snapshots. The
caller pin and import receipt bind all of the following exact identities:

- snapshot raw-byte SHA-256;
- schema `gtkg.lsp-snapshot/v1` and schema SHA-256;
- LSP protocol `3.17` and position encoding `utf-8`;
- producer name, non-floating version, 40-hex commit, license, and configuration SHA-256;
- source snapshot SHA-256 and per-document source-byte SHA-256.

The adapter descriptor is `kind=lsp_snapshot`. Its digest also binds protocol, position encoding,
and producer configuration through closed identity-bearing capabilities, so the A00 bundle cannot
silently detach those inputs from the candidate graph.

## Frozen snapshot and range semantics

Only `capture.mode=frozen_file`, `deterministic=true`, and zero language-server/JSON-RPC counts are
accepted. A live response, daemon-produced response stream, or non-deterministic capture fails
before candidate facts are built. The importer never starts or contacts an LSP server.

LSP positions are accepted only when the exact pin says `utf-8`. Line characters are converted to
UTF-8 byte offsets and both ends must be Rust string boundaries. UTF-16 and UTF-32 are explicitly
unsupported rather than being misread as byte offsets. The fixture corpus includes CJK and emoji
spans plus a deliberately split UTF-8 code point.

## Candidate projection and A00 consumption

Symbols, full symbol ranges, selection ranges, diagnostics, and supported relationships are sorted
and mapped to digest-derived stable IDs. Exact source bytes and snippet digests accompany every
admitted fact. Every relationship range must be contained by its source symbol range and its exact
UTF-8 bytes must equal `target_reference`; a valid source span that selects a different identifier
is rejected before A00 can replay or promote it.

| Snapshot observation | Candidate state | Trust state |
|---|---|---|
| symbol or diagnostic with exact range | `candidate_external` | `extracted` |
| relationship with one known target | `candidate_external` | `extracted` |
| relationship with multiple/partially missing targets | `ambiguous` | `ambiguous` |
| relationship with no known target | `locator_only` | `unverified` |

These remain A00 candidate facts. Only `verify_external_fact_bundle_v1` can produce
`resolved_verified` after exact source replay; the A03 importer performs no canonical write.

## Fail-closed and side-effect boundary

Closed JSON decoding, file/schema/protocol/config/producer/source pins, source manifest replay,
stable denominator checks, relationship allowlisting, exact target text and range boundaries,
receipt digests, descriptor-bound no-follow open/readback, and symlink/hardlink rejection all fail
closed. Error families are `E_LSP_*`; schema, protocol, encoding, live response, non-determinism,
source tamper, range, bundle, and receipt failures remain distinct.

The production receipt requires all of these counters to be zero:

- `lsp_server_invocation_count`;
- `json_rpc_request_count` and `json_rpc_response_count`;
- `target_execution_count` and `network_call_count`;
- `write_count` and `canonical_write_count`.

## Development evidence

The frozen test is `crates/gtkg-testkit/tests/v03_a03_lsp_adapter_contract.rs` with SHA-256
`4f2627ea3551c8cbd14d30824d66d866dd4115bc7caa292593384bb4bfa8068f` for Red and Green.
The immutable security successor is
`crates/gtkg-testkit/tests/v03_a03_lsp_adapter_security_successor.rs` with SHA-256
`ac5e687a2793c90e12d464d6a41596359a9de98a06e533a8ccb7f83295debd3f`.

- Red: [`a03-red.json`](../../deliverables/v03-development/test-runs/a03-red.json)
- Green: [`a03-green.json`](../../deliverables/v03-development/test-runs/a03-green.json)
- Affected verification: [`a03-affected.json`](../../deliverables/v03-development/test-runs/a03-affected.json)
- Successor Red: [`a03-security-successor-red.json`](../../deliverables/v03-development/test-runs/a03-security-successor-red.json)
- Successor Green: [`a03-security-successor-green.json`](../../deliverables/v03-development/test-runs/a03-security-successor-green.json)
- Successor affected verification: [`a03-security-successor-affected.json`](../../deliverables/v03-development/test-runs/a03-security-successor-affected.json)
- A03 predecessor 7/7, A03 successor 6/6, A00 6/6, D03 4/4, A02 6/6, and A02
  successor 1/1 passed (30/30 total).
- scoped `rustfmt --check` and scoped Core/Testkit Clippy with `-D warnings` passed.

## Explicit non-claims

This local Development evidence does not prove a real LSP server run, arbitrary producer/schema
compatibility, UTF-16/UTF-32 conversion, all-language semantic parity, adapter-join correctness,
full V0.3 regression, Release, installation, publication, Provider behavior, or business
acceptance. A live LSP invocation is intentionally outside A03 and remains zero.
