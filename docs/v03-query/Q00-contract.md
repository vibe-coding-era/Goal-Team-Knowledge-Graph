# Q00 file-query contract

Q00 freezes the protocol and validation boundary consumed by Q01-Q06. It does
not build an index, route a query, read a shard, or replace any graph handler.

## Frozen identities

- `gtkg.query-index-manifest/v1` binds exact source, graph, overlay, tokenizer,
  shard denominator/catalog, catalog digests, and parser/resource budgets.
- `gtkg.lexical-shard/v1` binds Unicode version, normalized terms, scalar
  trigrams, FST digest, postings, evidence references, and raw-byte digest.
- `gtkg.adjacency-shard/v1` binds node bucket, direction, edge IDs, resolution
  states, and raw-byte digest.
- `gtkg.query-plan-receipt/v1` binds query/index identity, selected and excluded
  shards, bytes, latency, budget, truncation, and continuation.

All four Rust models use closed Serde/Schemars objects. Their JSON validators
first reject unknown fields and then apply semantic validation.

## Tokenizer rules

Tokenizer identity is
`gtkg.query.unicode17-nfc-ascii-cjk-trigram/v1`. The direct dependency is
`unicode-normalization 0.1.25`, whose runtime Unicode data identity must equal
`17.0.0`; drift fails closed.

1. Normalize input to NFC.
2. Fold ASCII identifier runs (`[A-Za-z0-9_]+`) to ASCII lowercase.
3. Preserve contiguous Han, Hiragana, Katakana, and Hangul runs.
4. Keep other Unicode alphanumeric runs together and lowercase them before a
   final NFC pass. Adjacent ASCII letters/digits remain in that Unicode word.
5. Emit unique, first-occurrence-ordered windows of exactly three Unicode
   scalar values. Terms shorter than three scalars use the exact-term path and
   have no trigram.
6. Distinct original forms that normalize to one term are `ambiguous`; marking
   that term `unique` is rejected as collision laundering.

## Frozen resource ceilings

| Field | Value |
|---|---:|
| manifest bytes | 4 MiB |
| one shard bytes | 64 MiB |
| shard count | 4,096 |
| records per shard | 1,000,000 |
| term scalars | 512 |
| postings per term | 100,000 |
| selected shards per ordinary query | 128 |
| ordinary-query bytes read | 64 MiB |
| response bytes | 8 MiB |

These are parser/resource ceilings, not Q05 performance proof. The shard
denominator must be non-zero and satisfy
`discovered = admitted + omitted`; admitted count must equal the manifest
catalog size. A zero denominator never passes.

## Validation boundary

Manifest validation requires both lexical and adjacency descriptor kinds,
strictly ordered unique IDs, non-empty bounded shard records, raw-byte SHA-256
identities, and recomputed catalog digests. Lexical validation enforces NFC,
explicit collision state, exact trigram union, ordered postings/evidence, and
posting budgets. Adjacency validation keeps edge IDs and resolution states in
an exact parallel vector. Plan receipts must partition the manifest shard set,
stay inside manifest-derived budgets, and carry a non-empty continuation when
truncated.

Q01 owns lexical index construction/search. Q02 owns adjacency catalogs and
routing. Q03 owns planner/lazy-reader behavior and receipt emission. Q04-Q06
own graph-handler migration, performance/security gates, and equivalence.

## TDD evidence

- Immutable test:
  `crates/gtkg-testkit/tests/v03_q00_index_schema_contract.rs`
- Test SHA-256:
  `sha256:7a800e816c0e6c1870045d5aecbe0484f515570b792f1d680458d19ead1760f1`
- Red receipt: `deliverables/v03-development/test-runs/q00-red.json`
- An intermediate isolated check passed 5/5 while the concurrently owned A00
  module was absent; that check remained diagnostic-only. After A00 restored
  the declared module, the canonical worktree passed Q00 5/5, D03 4/4,
  protocol/core library tests 6/6, Q00-scoped rustfmt, and clippy with
  `-D warnings`. Canonical Green is recorded in `q00-green.json`.
