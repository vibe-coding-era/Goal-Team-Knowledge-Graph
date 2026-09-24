# P03 Context and Summary Handlers

Status: `local_development_green`; P04 and P06 remain pending.

P03 implements `context.pack`, `summary.job.next`, `summary.proposal.submit`,
`summary.verification.next`, `summary.verification.submit`, and `summary.accept.v2`.

`context.pack` invokes the read-only P02 chain validator, which replays candidate, plan, snapshot,
adapter imports, current source bytes, and every `VerifiedFactReceiptV1`, then returns a bounded, claim-free
inline context. `summary.job.next` deterministically binds only those selected fact receipts. Both
are true Read operations and write no artifact. `summary.verification.next` likewise returns an
inline independent verification job without writing.

Proposal, verification submit, and accept are CandidateWrite operations. They write immutable
semantic-digest receipts under `.gtkg/summary/{proposals,verifications,accepted}` with exact
readback. Stored receipts cannot self-prove: every consumer replays P02 verification, context, job,
decision identities, actor independence, self digests, semantic paths, and denominators.

Only `resolved_verified` P02 facts may be marked `supported`; locator/ambiguous facts require
abstention or conflict. Conflicts, rejected verification decisions, missing decisions, or a
proposer acting as verifier block acceptance. Successful acceptance remains
`status=candidate_accepted`, `a06_cross_adapter_status=not_run`, `canonical_eligible=false`, with
provider/network/Git/Current/canonical write counts all zero.

Wire `summary_text` is retained only as untrusted `proposer_note`. `asserted_claims` are derived
solely from Supported decisions over replayed `resolved_verified` receipts;
`verified_summary_text` remains null. Actor separation is reported as
`declared_distinct_not_attested`, not as authenticated independence.

Evidence:

- primary immutable `22832c9220d46c92f4dc70182c7aec4145ff72518ced65fdb57db5f24e2d0bd2`: Red 0/4, Green 4/4;
- trust successor `5a2ffe2c0bffcbdd4fe4c9c71e472b81521759c444056ebfeed12cb54fc1817f`: Green 1/1;
- CLI/MCP parity successor `0cf300b7461ceb391e0ddb4f5b671c3d15f28571bf1e33829e555c17867e042d`: Green 1/1;
- profile successor `ef43370014c16f1edb24d321625c81e18a0271c2fcace547b2a2da78fcebf0b7`: Green 1/1;
- chain-forgery successor `23a9ba48146df3542794e0c5e180d80dc28bc5ce0b477d9640ac186d935582d7`: Red 0/3, Green 3/3;
- P02 functional affected 13/13, P00 identity 1/1, P01 frozen-environment affected 2/2;
- scoped Protocol/Core/Testkit Clippy with `-D warnings`, app build, and scoped rustfmt passed.

This does not claim A06 completion, P04 finalize/lifecycle semantics, full P06 positive transport
parity, Provider execution, canonical knowledge, Current activation, Release, installation, or
business acceptance.
