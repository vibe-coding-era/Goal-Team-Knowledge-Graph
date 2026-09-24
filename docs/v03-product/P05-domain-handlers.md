# P05 v2 Domain Handlers

Status: `local_development_green`; P06 transport-wide 46/46 E2E remains pending.

## Exact handler set

P05 binds exactly 18 existing file-only domain operations into the v2 dispatcher:

- Git/Current: `git.publish`, `current.get`, `current.activate`;
- node/federation: `node.describe`, `federation.validate`;
- templates: `template.list`, `template.resolve`, `template.prefetch`, `template.get`,
  `template.validate`, `template.derive`, `template.publish`;
- deliverables: `deliverable.derive`, `deliverable.publish`;
- A2UI: `a2ui.resolve`, `a2ui.generate`, `a2ui.get`, `a2ui.validate`.

The v2 payload schema for each operation is projected from the matching frozen v1 operation
payload contract. Required and optional properties, nested receipt references, node/federation
objects, digest patterns, and `additionalProperties=false` therefore share one exact contract.
Runtime validation rejects unknown or missing fields before effect evaluation and then delegates
typed validation to the existing domain implementation.

## Semantic and effect mapping

`p05_domain` converts the v2 request into the same v1 `OperationRequest` and executes it through
the production dispatcher. This retains the existing path authorization, symlink/hardlink checks,
digest locks, immutable writes, Current exact readback, federation reduction, template lifecycle,
deliverable derivation, A2UI validation, and stable domain error stages. Every v1 error code used by
these domains has an exact v2 error-code projection.

Availability and callability remain separate:

| Operation | Availability | Callability in Development |
|---|---|---|
| `git.publish` | `implemented` | `denied_by_policy` |
| `current.activate` | `implemented` | `denied_by_policy` |
| `template.publish` | `implemented` | `denied_by_policy` |
| `deliverable.publish` | `implemented` | `denied_by_policy` |
| other 14 P05 operations | `implemented` | `callable` under their declared bounded effect |

Neither `ReadOnly` nor `WorkspaceWrite` grants external Git publication or Current activation.
Denied calls stop before path evaluation or writes. Local cache/draft/receipt operations require
their declared workspace effect and continue to use the v1 durable-write implementation.

`FileReceiptRef.path` remains a safe workspace-relative path. The v2 adapter does not rewrite it to
an absolute path; callers resolve it below the authorized workspace and can feed it unchanged into
the next receipt-consuming operation.

## Test evidence

The immutable primary contract is
`crates/gtkg-testkit/tests/v03_p05_domain_handlers_contract.rs`, SHA-256
`102b29274f1fb5c61f95acfad7981c3c8071ec43553718bcf8afd4753218ebfa`.

- Red: 0/5, all 18 operations were still `not_implemented`.
- Initial implementation candidate: 4/5; the only failure was a test oracle that interpreted a
  workspace-relative `FileReceiptRef` against the process working directory.
- The frozen Red and 4/5 observation are preserved. The immutable oracle successor is
  `crates/gtkg-testkit/tests/v03_p05_domain_handlers_readback_successor.rs`, SHA-256
  `7ee8110c39a23caac022aa66ce03ca6c831a27c310fa7948c7137ac8c974659e`.
- The profile successor is `crates/gtkg-testkit/tests/v03_p05_profile_successor.rs`, SHA-256
  `5229d86fc63c2f77c55a61fe8ca1194ceb3b473b8830762f17afbaf0a53201e8`.
- Active P05 assertions: primary unaffected 4/4 plus successors 2/2. Templates and A2UI are now
  live partitions; lifecycle and `all` remain fail-closed with 8 and 18 unimplemented handlers.
- v1 domain affected regression: D05 A2UI/template 6/6, federation/SB2 4/4, D06 lifecycle 5/5,
  D06 registry/effect schemas 4/4, and D03 architecture 4/4.
- Protocol/Core and both P05 tests pass scoped Clippy with `-D warnings`; all changed Rust files pass
  scoped `rustfmt --check`.

Historical P00/P01 implemented-count assertions are denominator checkpoints and are superseded by
P01/P05 additions rather than rewritten. The P01 source-capture TOCTOU contract passes in its
frozen `TMPDIR=/private/tmp` environment; the default macOS `/var` alias only exposes a
non-blocking test-path normalization improvement for I00. The unrelated v1 source repository
schema's missing `exclude` property remains outside P05 scope.

## Non-claims

P05 does not claim P06 CLI/MCP/profile parity, 46/46 availability, external publication, Current
activation, Release, installation, Provider behavior, or business acceptance. The `all` profile
must remain fail-closed until every remaining owning P task supplies its handlers.
