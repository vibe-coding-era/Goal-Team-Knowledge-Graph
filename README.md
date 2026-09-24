# GTKG

> 中文版：[README.zh-CN.md](README.zh-CN.md)

GTKG V0.3 is a local-first knowledge compiler and control plane for exact
source, evidence-bound claims, OKF knowledge, structural graphs, and Agent
queries. The workspace uses Rust 2024, one binary, one Core/Dispatcher, and
OKF and ordinary files. It has no database, hidden daemon, or required remote
service.

## Current Development status

V0.3 is in Development. The v1 public surface remains frozen at 34 operations;
the separate v2 registry contains 46 closed operation IDs. Registry presence,
handler implementation, callability, and successful invocation are different
facts. Current Task, test, and blocker evidence is recorded in
`V0.3TaskList.md`, `Banchmark.md`, and `deliverables/v03-development/`.

Development completion does not imply Release publication, installation,
Current activation, runtime completion, or business validation. Missing data
is reported as empty, unavailable, blocked, or not_run; GTKG does not seed
synthetic knowledge or fabricated benchmark receipts.

## Local Development build

The checked-in Rust toolchain is the only required compiler environment:

```bash
cargo build --locked -p gtkg-app
cargo test -p gtkg-testkit --test v03_u00_package_contract
```

These commands build or test the source tree. They do not install GTKG, write
assistant configuration, publish a Release, or activate Current. Install,
upgrade, rollback, and uninstall are owned by later V0.3 tasks and must not be
inferred from this package metadata.

## License and notices

GTKG is licensed under Apache-2.0. See `LICENSE` and `NOTICE`. The Development
package manifest is `scripts/package-manifest-v0.3.json`.
