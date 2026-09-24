# Public source snapshot

This repository contains the GTKG source snapshot from local branch
`codex/develop-v0.4`, source commit `f9c9990d235e337ecebc46c86bacd13b63f90408`.
The package metadata remains at version 0.3.0; this snapshot also contains
V0.4 development and deployment work. See `deploy/README.md` for the current
local deployment scripts. This synchronization is not a Release or a claim
that all development, benchmark, or business acceptance gates have passed.

Included: the five Rust crates and their checked-in tests/vendor assets,
Cargo configuration and lockfile, deployment/build scripts, product Skill,
templates, product specifications and documentation. Source files are copied
from the named commit without code changes.

Excluded: local agent state and credentials, `.gtkg` runtime stores, build
outputs, generated bundles, model transcripts, private benchmark questions
and answers, captured target-repository data, and internal development logs.
Local Git history is retained locally and is not part of this source-only
snapshot because it contains those excluded artifacts. A small reviewed set
of historical fixtures required by compile-time test includes may remain in
`deliverables/`; broader historical evidence-dependent tests require their
original local data and are not claimed to be self-contained here.

No upstream source repository or private evaluation corpus is vendored as
part of this synchronization. The tracked public specifications and synthetic
test fixtures retain their original notices and provenance.
