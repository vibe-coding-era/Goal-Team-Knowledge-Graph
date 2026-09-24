# P02 Analysis Handlers

Status: `local_development_green`; P03, P04, A06, and P06 remain pending.

P02 implements `analysis.plan`, `analysis.build`, and `analysis.verify` with closed v2 payloads.
Plan accepts one workspace/source snapshot receipt and a bounded, duplicate-free tagged selection
of Native, SCIP, frozen LSP, CodeGraph, or strict Graphify V2 inputs. Build writes an immutable
`gtkg.typed-candidate-ir/v1`; Verify re-executes the same file-only adapters and applies the A00
exact-source verifier before writing an immutable verification receipt.

Artifacts live at semantic-digest paths below `.gtkg/analysis/plans`, `candidates`, and
`verifications`. Their paths, self-digests, selection exact set, snapshot artifact/exact-set
identity, workspace root, adapter descriptors, bundles, import receipts, source digest sets, and
checked denominators are bound and read back. Request IDs never influence artifact identity.

SCIP and LSP separately bind their export-internal source-manifest digest and P02's selected
`SourceSnapshotV2.exact_set_sha256`; their embedded source bytes are accepted only when they also
equal the selected inventory and current private source-root bytes. CodeGraph and Graphify provide
locators but no source evidence, so their P02 verification yields no `resolved_verified` facts.
Graphify uses only `import_pinned_graphify_json_file_v2` and its five upstream blob pins.

P02 never flattens adapters into one authority-bearing graph. Candidate bundles remain independent;
`a06_cross_adapter_status=not_run`, `collision_check=not_run`, and `canonical_eligible=false` are
explicit. Target execution, process, network, provider, adapter write, canonical write, Current
write, Git publish, and external write counts remain zero.

Evidence:

- primary immutable test `e1640f692779ae8d7a61dbab0d00a3ac01a20d44f2bae4f3eefca35dd6691ec2`: Red 0/4, Green 4/4;
- orchestration successor `0f20e2fa6f229edeba9fa0cdf33148a0e6e75f760738f56605a06a986666f447`: Red 2/3, Green 3/3;
- profile successor `579121a95938b842cd7c303d8a0596088719d9e51290b9b4281ce0c2ee6adf4f`: Green 1/1;
- selected-snapshot successor `9873d2c7fa9e11e137766368786dbbce560e50b04fbfe48609784fcf2ce20432`: Red 0/1, Green 1/1;
- stored-plan binding successor `9b27345729a7659107c5744f4c42356767cdb63d567f58950f33fa5112b70ef8`: Red 0/1, Green 1/1;
- security matrix successor `b0828c04f7560e2626605996ff6950535019260c7bdf3d90eec5632cbf13c52c`: component-prevalidated Green 5/5, covering all effect denials, links/drift, duplicate/nested unknown input, concurrent convergence, partial-temp recovery, and no-clobber conflict;
- A00-A05 affected 54/54 and D03 4/4;
- scoped Protocol/Core/Testkit Clippy with `-D warnings` and scoped rustfmt check passed.

This evidence does not claim A06 cross-adapter collision/coverage closure, P03 summary/claim
semantics, P04 finalize/lifecycle semantics, P06 CLI/MCP 46/46 parity, Release, Current activation,
installation, Provider execution, or business acceptance.
