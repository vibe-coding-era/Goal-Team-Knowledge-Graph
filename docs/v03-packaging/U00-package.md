# U00 Development Package Contract

U00 binds the GTKG V0.3 Development source identity to Apache-2.0 metadata,
the exact root license, NOTICE, README, `VERSION`, Cargo workspace version and
the closed Development package manifest.

The manifest is not a Release asset. It excludes Git metadata, build output,
worktrees, local memory, Development evidence and deliverables. Installation,
upgrade, rollback, publication and Current activation remain owned by later
tasks and are `not_run`.
