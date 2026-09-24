---
title: GTKG V0.3 P01 System and Source Handlers
status: development_implemented
scope: local_development_only
---

# P01 System and Source Handlers

P01 binds four real handlers to the frozen `gtkg.protocol/v2` registry:
`system.describe`, `config.validate`, `capability.describe`, and `source.capture`.
Together with the six predecessor graph handlers, the current truthful intermediate surface is
10 implemented and callable operations out of 46. This is not the final P06 46/46 product gate.

## Closed payloads

| Operation | Required payload | Side effect |
|---|---|---|
| `system.describe` | `{}` | `read` |
| `config.validate` | `config_path` | `read` |
| `capability.describe` | `{}` | `read` |
| `source.capture` | `capture_mode`, `repository_id`, `source_root`, `output_path` | `run_local_write` |

Every implemented P01 payload is an object with `additionalProperties: false`. The public source
capture modes are `worktree_exact`, `directory_exact`, and `git_commit`. The internal
`supplied_manifest` path is deliberately not exposed because the v2 transport has no trusted
manifest-authority capability and must not infer one from caller text.

`system.describe` derives registry counts and operation disclosures from the same 46-entry v2
registry used by dispatch. `config.validate` delegates to the existing strict file-backed config
validator after exact caller-root authorization, preserving the no-database contract.
`capability.describe` reports the current partial Development surface and explicitly keeps target
execution, network, external Git writes, and Current writes false.

## SourceSnapshotV2 output

`source.capture` consumes the existing `SourceCaptureRequestV2` / `SourceSnapshotV2` boundary. It
preserves exact-set digest, omission denominator, eligibility, Git/directory identity, symlink and
hardlink rejection, and TOCTOU fail-closed behavior. The handler then validates the typed snapshot,
writes immutable JSON to the exact caller-selected output, and performs an exact private-inode
readback before returning success.

The output path must satisfy all of the following:

- remain below the caller's `CallContext` root;
- be below a private `.gtkg` directory;
- remain outside the captured source root;
- contain no symlink component;
- either be absent or already contain the identical snapshot bytes.

The response contains the complete `snapshot`, an artifact SHA-256 and exact-set SHA-256 in
`snapshot_ref`, and `canonical_write_count=0` / `external_write_count=0`. This run-local artifact
write never grants Current, external Git, Release, or installation authority.

## Fail-closed errors

Closed schema failures return `E_INVALID_REQUEST` at `payload-schema`. A valid `source.capture`
request under a read-only context returns `E_SIDE_EFFECT_DENIED` before filesystem work. Path,
symlink, Git identity, dirty source, source/output overlap, source drift, immutable conflict,
database, not-found, and I/O failures retain distinct v2 error codes. No failure silently lowers the
capture mode or returns a partial snapshot.

## Discovery and predecessor evidence

The default `core` profile still contains five successor operations without handlers, so live
`tools/list` remains fail-closed with `E_DEAD_TOOL_EXPOSED`; direct P01 CLI/MCP operation calls are
available and have byte-equivalent structured envelopes. P00's historical immutable assertions
that only six graph handlers exist, and V0.2 T08's historical assertion that `source.capture` is not
implemented, become successor-stale after this task. They are retained unchanged. D03 architecture,
V0.2 SourceSnapshot, and frozen v1 registry regressions remain Green.

## Verification

The immutable P01 contract is
`crates/gtkg-testkit/tests/v03_p01_system_source_contract.rs`, SHA-256
`83bcf9fb7dc0ce785c7a3a08b9e2abeef1d85be9cd3e9fe86c7b78407911bfcd`.
On macOS the deterministic TOCTOU observer uses the canonical temporary-root identity:

```sh
cargo build -p gtkg-app --bin gtkg
TMPDIR=/private/tmp cargo test -p gtkg-testkit --test v03_p01_system_source_contract
cargo clippy -p gtkg-protocol -p gtkg-core --lib -- -D warnings
```

Run receipts are stored under `deliverables/v03-development/test-runs/p01-*.json`.
