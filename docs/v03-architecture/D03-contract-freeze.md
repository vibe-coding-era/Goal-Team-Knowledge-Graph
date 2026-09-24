---
type: GTKG V0.3 Architecture Contract
title: D03 Architecture and Identity Freeze
description: V0.3 operation ownership, discovery profiles, manifest identities, handler partitions, and failure-mode boundaries.
status: development_contract_frozen
product_version: V0.3
protocol_version: gtkg.protocol/v2
task: D03
---

# D03 Architecture and Identity Freeze

## Scope and non-claims

D03 freezes identities and ownership for the V0.3 implementation DAG. It does not add a
`gtkg.protocol/v3`, change the frozen v1 surface, or claim that a registry entry has a working
handler. `OperationBindingV2.availability` and `callability` mirror the current v2 registry; P00-P06
remain responsible for executable behavior, closed handler payloads, transport parity, and the
46/46 implementation gate.

The normative executable contracts are:

- `gtkg_protocol::v03`: operation bindings, discovery profiles, manifest identities, partition map,
  and failure-mode codebook;
- `gtkg_core::v03`: cross-contract closure validator;
- `v03_d03_architecture_contract`: immutable D03 TDD oracle.

## Ownership and data flow

```text
frozen v2 registry (46 IDs)
        |
        +--> OperationBindingV2 --> one handler_id + one partition + schema digest
        |
        +--> DiscoveryProfileV1 --> exact ordered set + default bit + digest
        |
        +--> manifest identity contracts
               |-- five adapter kinds
               |-- query index / query plan
               `-- install / assistant install
```

Every public v2 operation belongs to exactly one handler partition. The cross-contract validator
rejects missing/duplicate operation ownership, duplicate handler identities, invalid profile
digests, multiple defaults, and an `all` profile that differs from the closed v2 registry. It also
compares the complete ordered 12-partition map, all seven ordered profile sets and their frozen
digests, every required manifest identity field, and the exact FM-301..FM-318 mapping against D03
oracles; coverage-only equality is insufficient.

## Handler partitions

| Partition | Operation ownership |
|---|---|
| `system_config` | system.describe, config.validate, capability.describe |
| `source_analysis` | source.capture, analysis.plan, analysis.build, analysis.verify, build.finalize.v2 |
| `context_summary` | context.pack and the five summary operations |
| `run` | run.get, run.cancel |
| `bundle_migration` | bundle.verify, bundle.compare, bundle.migrate.v1_to_v2 |
| `snapshot` | snapshot.create, snapshot.verify, snapshot.restore |
| `git_current` | git.publish, current.get, current.activate |
| `node_federation` | node.describe, federation.validate |
| `template` | seven template operations |
| `deliverable` | deliverable.derive, deliverable.publish |
| `graph` | neighbors, path, impact, explain, trace, search |
| `a2ui` | resolve, generate, get, validate |

The partition is an ownership boundary, not a call router. Later P tasks may attach real handlers
without changing public IDs or silently moving an operation between owners.

## Discovery profiles

| Profile | Contract |
|---|---|
| `core` | default; exact 10-operation set from V0.3 PRD section 10.2 |
| `graph` | exact six graph operations |
| `authoring` | exact eight context/summary/verification/finalize operations |
| `lifecycle` | exact 13 run/bundle/snapshot/git/current/node/federation operations |
| `templates` | exact nine template/deliverable operations |
| `a2ui` | exact four A2UI operations |
| `all` | exact closed 46-operation v2 registry |

The digest binds profile ID, default state, ordered operation IDs, and contract version. Profiles
control discovery only; they do not alter operation semantics, effects, availability, callability,
or authorization. D03 stores the seven expected digest values as immutable contract constants, so
changing order, membership, profile ID, or default state fails the validator.

## Manifest identities

Five adapter identity contracts are frozen: `native`, `scip`, `lsp_snapshot`, `codegraph_export`,
and `graphify_export`. Every adapter identity binds adapter ID/version, schema digest, source commit,
license, capabilities, and trust-policy ID. Drift maps to `E_ADAPTER_IDENTITY_MISMATCH` and requires
a new revision; an external adapter cannot self-promote candidate facts to canonical facts.

The adapter boundary additionally freezes `gtkg.adapter-descriptor/v1`,
`gtkg.external-fact-bundle/v1`, and `gtkg.verified-fact-receipt/v1`. The bundle identity binds source
snapshot, descriptor, nodes, edges, evidence, candidate states, admitted/omitted denominator, and
bundle digest. Verification binds source replay, span, source bytes, resolution, reason, and
verifier identity.

`gtkg.query-index-manifest/v1` binds source, graph, overlay, tokenizer, shards, and budgets.
`gtkg.query-plan-receipt/v1` binds the query and index identities plus selected/excluded shards,
bytes, latency, budget, truncation, and continuation. `gtkg.lexical-shard/v1` and
`gtkg.adjacency-shard/v1` freeze the corresponding shard identity fields. Drift is
`E_QUERY_INDEX_STALE`; ordinary query implementations may not fall back to an eager full-graph
read.

`gtkg.install-manifest/v1` binds version, platform, files, modes, digests, and destinations.
`gtkg.assistant-install-receipt/v1` binds assistant/scope/target plus before, after, and managed-block
digests. These contracts freeze identity only; U00-U06 own installer behavior and readback.

## Failure modes

FM-301 through FM-318 are preserved as an 18-entry codebook. Stable implementation-facing codes
include `E_PROFILE_STALE`, `E_ADAPTER_IDENTITY_MISMATCH`, `E_TRUST_LAUNDERING`,
`E_QUERY_INDEX_STALE`, `E_QUERY_EAGER_READ`, and `E_INSTALL_CAS_CONFLICT`. Non-error outcomes such
as `NO_SIGNIFICANT_DIFFERENCE` remain explicit states rather than being converted to success or
failure. The codebook describes required fail-closed behavior; later task-owned handlers must
produce executable evidence before any behavior is accepted.
