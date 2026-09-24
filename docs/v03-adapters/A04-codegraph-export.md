# A04 CodeGraph community export adapter

## Identity boundary

The Development adapter is frozen to CodeGraph `0.20.1`, commit
`489ccf1612555510f8367e3e673181f6a1275fe4`, and `Apache-2.0`. CodeGraph does
not publish a schema identifier inside its JSON export. GTKG therefore binds
the exact upstream exporter source
`crates/codegraph/src/export/json.rs` at that commit; its byte SHA-256 is
`b7a9743ee957d11268c5e1c2342c14d6071ae3a69ed1ed52ada0e6ab997fd1f0`.

Primary pinned sources:

- <https://github.com/codegraph-ai/CodeGraph/blob/489ccf1612555510f8367e3e673181f6a1275fe4/crates/codegraph/src/export/json.rs>
- <https://github.com/codegraph-ai/CodeGraph/blob/489ccf1612555510f8367e3e673181f6a1275fe4/crates/codegraph/src/graph/types.rs>
- <https://github.com/codegraph-ai/CodeGraph/blob/489ccf1612555510f8367e3e673181f6a1275fe4/LICENSE>

The accepted root shape is exactly `nodes` plus `links`. Node and relationship
kinds are the closed enums published by the pinned source. Duplicate IDs,
dangling links, unknown graph kinds, schema wrappers, digest drift, symlinks,
non-regular files, and over-budget files fail closed.

## Trust mapping

The upstream community JSON exporter contains graph IDs, types, flexible
properties, and link endpoints. It does not contain original source bytes,
source-byte digests, or exact byte spans. Consequently:

- every imported node and link is `locator_only` + `unverified`;
- `evidence` and the source-byte replay map are empty;
- A00 verification returns `missing_evidence` for every fact;
- `resolved_verified_fact_ids`, `false_confirmed`, and canonical writes remain
  zero.

This is intentional. CodeGraph export facts may help locate candidates, but
the adapter cannot make them canonical authorities. A later format revision
would need source bytes plus exact replay evidence before any fact could be
upgraded.

## Effect boundary

The adapter reads one caller-authorized, digest-pinned regular file. It does
not install or start CodeGraph, execute target content, invoke a daemon, access
the network, or write files. The import receipt binds the export digest,
source-snapshot identity, descriptor, bundle, denominator, locator-only count,
and all zero-effect counters.

The A04 fixtures prove the adapter contract only. They do not claim that a
real CodeGraph installation or export was executed; B00 records the competitor
export state separately.
