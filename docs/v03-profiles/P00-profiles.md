---
title: GTKG V0.3 P00 Operation Profiles
status: development_implemented
scope: local_development_only
---

# P00 Operation Profiles

P00 projects the frozen 46-operation v2 registry into seven ordered, digest-bound discovery
profiles. A profile changes discovery only; it does not change an operation's schema, side effect,
availability, callability, handler ownership, or authorization.

## Exact profiles

| Profile | Default | Operations | Contract digest |
|---|---:|---:|---|
| `core` | yes | 10 | `sha256:50263880d66cc5aa09ff9e2e3cf85956ad9dcea09a0f0925609f25bcac5f31a8` |
| `graph` | no | 6 | `sha256:86777e15e4f84ec49c94af68b83ce1910b85b42c6a66dfb61f69f40db878cd38` |
| `authoring` | no | 8 | `sha256:0a4ab7a650741b60d905baa747acd4f30c5d13da9ed61a9eb7e87fe654bffd75` |
| `lifecycle` | no | 13 | `sha256:1f8d7e6b63639aaa31b5eadf27875157ee03ecf6e2bba8b06fdae3551be10895` |
| `templates` | no | 9 | `sha256:dbd30e464b48599be2bd67f4922aabec68c3d7462d148c91b29b8746c3ec3b4a` |
| `a2ui` | no | 4 | `sha256:a9b24b739ce003567af3eb0629d51484f191be98d5c3fb8379fa8076ae0f0cac` |
| `all` | no | 46 | `sha256:5c718c85bcc4e65a3862ec591138e52506884200fffe9923f78ea6f3cd12826f` |

The digest binds the profile contract version, profile ID, default bit, and ordered operation IDs.
An optional caller-pinned digest must match exactly; drift returns `E_PROFILE_STALE` and is never
auto-upgraded. Unknown or case-drifted IDs return `E_PROFILE_UNKNOWN`.

## Live discovery boundary

Registry presence is not implementation. P00 preserves the current executable truth: only the six
graph handlers are implemented and callable. Live CLI/MCP discovery rejects any profile containing
an unimplemented operation with `E_DEAD_TOOL_EXPOSED`; therefore the current `graph` profile lists
six tools, while `core`, `authoring`, `lifecycle`, `templates`, `a2ui`, and `all` remain fail-closed
until their owning P tasks install real handlers. This is an intentional Development checkpoint,
not a claim that the final 46/46 product gate has passed.

Successful CLI and MCP discovery use the same projection:

```sh
gtkg v2-discover --profile graph
gtkg mcp serve --protocol v2 --profile graph --stdio
```

The default selector is `core`. At this checkpoint a bare `gtkg v2-discover` or v2 MCP
`tools/list` fails closed because nine of the ten core operations are not yet implemented. An
unselected operation is absent from a successful tools list. The profile does not become a new
authorization layer for direct operation calls.

## Verification

The immutable P00 contract test is
`crates/gtkg-testkit/tests/v03_p00_operation_profiles_contract.rs`, canonical SHA-256
`605310dc8d47885b9d3ac4e085d9fefadc72c1670cddd0ebb448c88412e93c51`.
Receipts are stored under `deliverables/v03-development/test-runs/p00-*.json`.
