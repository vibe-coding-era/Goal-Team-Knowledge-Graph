# A00 Adapter Trust Contract

A00 defines five pinned, file-only adapter identities and the only permitted
candidate states: `candidate_external`, `ambiguous`, and `locator_only`.
External facts never become canonical by self-report. Exact source bytes,
spans, descriptor/schema/license identity, omission denominator, evidence
trust and verifier identity must replay before a fact can become
`resolved_verified`.

The validator performs no target-code execution, no daemon or network call,
and no canonical write. Missing evidence and changed source stay non-confirming;
inferred-as-extracted input fails with `E_TRUST_LAUNDERING`.
