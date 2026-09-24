# T04 External Holdout Annotation and Adjudication Packet

Status: `planned_not_run`; no gold labels are prefilled.

## Bound frozen source packet

- The only case inventory for this packet is
  `frozen-holdout-case-manifest.json`, manifest ID
  `t04-public-source-split-r1`.
- That manifest binds this packet's exact SHA-256, the selected source path,
  source digest, public repository commit/tree, declared license, category and
  calibration/evaluation/holdout split. It remains
  `candidate_only_not_annotation_locked` and `blocked`.
- This packet deliberately contains no labels, gold answers, model output or
  adjudication result. Annotators receive only the manifest's `holdout` cases;
  calibration and evaluation cases are excluded from their packet.

## Preconditions

- Use only a candidate from `candidate-external-repositories.json` after license review and source exact-set freeze.
- Keep calibration/evaluation/holdout source digests disjoint.
- Annotators receive only the frozen holdout packet and this guideline, not model outputs or calibration material.
- Each annotator uses a stable pseudonymous ID. The adjudicator must not be either annotator.

## Roles

| Role | Required action |
|---|---|
| Annotator A | Independently label every assigned case and record evidence spans. |
| Annotator B | Independently label the same cases without viewing A's labels. |
| Adjudicator | Resolve disagreements using source evidence and record the rationale. |

## Per-case record

| Field | Requirement |
|---|---|
| case_id | Stable ID bound to repository, commit, path and source SHA-256 |
| language / category | Rust/Python/TypeScript/JavaScript and fact family |
| evidence spans | Exact byte/line spans; no free-text-only evidence |
| label | Definition/import/reference/call/type/CFG/exception/def-use/state or explicit unsupported/unknown |
| resolution state | resolved/candidate/unknown/conflict with candidate IDs where applicable |
| annotator rationale | Source-grounded explanation, not model output |
| adjudication | required only when A and B disagree |

## Acceptance and privacy boundary

- Freeze the two annotation files, adjudication file and guideline with SHA-256 before any T15 semantic score.
- Report inter-annotator agreement and all unresolved conflicts; unresolved is not silently converted to resolved.
- Do not include credentials, personal data, chain-of-thought or provider outputs in the annotation package.
- Annotation completion unlocks only the corpus gate. It does not validate real Provider, current OKF, scale/security, Release or business outcomes.
