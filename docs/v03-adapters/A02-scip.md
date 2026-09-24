# A02 Pinned SCIP File Adapter

A02 accepts one regular, non-symlink SCIP JSON file only after exact file,
schema, tool version, tool commit, license, and source snapshot identities match
the caller's pin. The supported closed schema is `scip/0.4-json`; unknown JSON
fields, floating tool versions, invalid UTF-8 byte ranges, source digest drift,
and unknown relationship kinds fail closed.

The adapter deterministically sorts documents, symbols, occurrences, evidence,
nodes, and relationships. Stable IDs are digest-derived. It emits the A00
`ExternalFactBundleV1` candidate boundary with symbol facts, source spans, and
`reference|implementation|type_definition|definition` relationships. External
facts are not written to canonical state; exact source replay remains an A00
verifier responsibility.

The import receipt fixes `target_execution_count=0`, `network_call_count=0`,
`write_count=0`, and `canonical_write_count=0`. The fixture contract covers
input-order determinism, exact range readback, denominator closure, file and
identity tamper, schema drift, unknown relationships, and symlink rejection.

Error codes are `E_SCIP_FILE_INVALID`, `E_SCIP_JSON_INVALID`,
`E_SCIP_PIN_MISMATCH`, `E_SCIP_SCHEMA_UNSUPPORTED`,
`E_SCIP_SOURCE_TAMPERED`, `E_SCIP_RANGE_INVALID`,
`E_SCIP_RELATION_UNSUPPORTED`, `E_SCIP_BUNDLE_INVALID`, and
`E_SCIP_RECEIPT_INVALID`.
