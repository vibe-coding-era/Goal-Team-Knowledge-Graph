//! U04 r2 lint successor.
//!
//! U04-R1 is immutable because its first Red and Green are bound to its exact
//! bytes.  The historical file has one unused standard-library import, so
//! this target reuses its behavioral cases under a narrow module-local lint
//! allowance.  It changes neither the cases nor the U04 implementation.

#[allow(unused_imports)]
#[path = "v03_u04_evidence_drawer.rs"]
mod immutable_u04_r1;
