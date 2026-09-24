# P04 Lifecycle Handlers

Status: `local_development_green`; P06 transport/conformance remains pending.

P04 implements nine v2 lifecycle operations: `build.finalize.v2`, `run.get`, `run.cancel`,
`bundle.verify`, `bundle.compare`, `bundle.migrate.v1_to_v2`, `snapshot.create`,
`snapshot.verify`, and `snapshot.restore`.

Finalize invokes the read-only P02 verification and P03 accepted-summary chain validators. It writes
only a semantic-digest candidate bundle and an immutable `candidate_ready` run state. The bundle
retains exact fact/claim receipts but is always `partial=true`, `a06_cross_adapter_status=not_run`,
and `canonical_eligible=false`; Git, Current, and canonical write counts remain zero.

Run state is event sourced. `run.get` is a pure exact read and never repairs. `run.cancel` checks the
caller-held receipt digest, writes one immutable cancelled successor, preserves the ready predecessor,
and is terminal-idempotent.

Bundle verification replays P02/P03 again. V1 migration never imports legacy facts as proven: the
legacy tree remains byte-identical, the new candidate has no accepted facts, and records
`provenance_state=not_proven` plus `migration_gap=true`. Snapshot create/verify bind the complete
candidate bundle; restore creates a new immutable Replay selector and performs no adapter refresh,
index write, assistant write, network call, Git operation, Current write, or canonical write.

Evidence:

- primary `d5216d73d3598fea127098a2dd34b581744c3f96784009355c9f96391ce92733`: Red 0/4, Green 4/4;
- P02/P03 chain successor `61700ffda3fcd4f86082dab3bf90c5b400e2ed859ae6d8ec52b3232b847ff935`: Green 1/1;
- migration/snapshot security successor `304628e5a4f3c8b9c97aac7957ab9d9c199cc3291d2ff7aea5da0549f8886c8c`: Green 3/3;
- CLI/MCP parity successor `8e8eb0ab44f3844dc46cc5c4e7ce0f85ba8aeb431e6acb390dfe665965405aa1`: Green 1/1;
- profile successor `269663c6defde3e806e970b249ebb6f1ffa15286bbce2fac5244a8bce0319cf5`: Green 1/1;
- P03 affected 8/8, P02 affected 13/13, v1 lifecycle/current/pipeline 13/13, D03 4/4;

## Legacy boundary successor R6

Independent correctness review rejected the earlier 10/10 candidate because a
rehashed migrated bundle could retain an absolute legacy path and replay it
without `CallContext` authorization, while empty or malformed legacy trees were
accepted. The immutable successor
`v03_p04_legacy_boundary_successor.rs`
(`0bca57a7c27e0bf4a5c43a65455eff1de2e3933869f95ea0187f8e09cf8f2123`)
preserves the 1/3 Red receipt and is now Green 3/3.

Migration now stores a validated workspace-relative legacy path. Migration,
bundle verification/comparison, and snapshot replay re-open that path through
the authorized workspace using descriptor-bound `openat` plus `O_NOFOLLOW`,
private-inode checks, bounded entry/depth/byte counters, and pre/post identity
readback. The exact root `manifest.json` must parse with
`schema_version = gtkg.bundle/v1`; empty, unknown, malformed, symlinked,
hard-linked, external, or drifting trees fail closed. This repair does not
promote legacy provenance, canonical eligibility, Current, Git, network,
publication, or install state.
- locked check, scoped Clippy `-D warnings`, app build, and scoped rustfmt passed.

All 46 operation implementations now exist, but that is not P06 completion. Full positive/negative
CLI/MCP denominator parity, release, publication, Current activation, installation, and business
acceptance remain unclaimed.
