> 新的项目理解/知识召回请求先走 [V0.4 显式能力工作流](v04-workflow.md)。本文保留V1历史输入和旧包的原始路径。

# V1 Workflows

Load only the section needed for the current user request. Every step consumes exact IDs, paths, versions, and full digests returned by the previous Core operation.

## Discovery

1. Call `system.describe` and bind binary, Core, protocol, and operation-schema identity.
2. Call `config.validate` for an existing configuration file.
3. Call `source.inspect` for each explicitly selected Git repository and path role.
4. Resolve, prefetch, and validate an exact template version.
5. Describe nodes and validate federation/Sandbox locks when the run uses Workers.

Do not persist a branch, `latest`, or `CURRENT.json` as an exact identity.

## Build and summary handoff

1. Call `build.plan` with source-inspection and template-validation receipts.
2. Call `build.prepare` and retain its run identity.
3. Loop over `summary.next`.
4. Ask the host model to summarize only the returned AnalysisPacket under its constraints.
5. Submit the candidate with `summary.accept`; preserve the packet, source, and template digests.
6. Call `build.finalize` only after the Core reports all required candidates accepted.

The Skill does not read target files, merge Worker results, render OKF, or write indexes.

## Verify and inspect

- Pass the caller-held full tree digest to `bundle.verify`, `bundle.query`, or `bundle.compare`.
- Use `snapshot.create`, `snapshot.verify`, and `snapshot.restore` without overwriting prior versions.
- Use `a2ui.resolve`, `a2ui.generate`, `a2ui.get`, and `a2ui.validate` only with exact local catalog and generation receipts. In V0.1, `a2ui.generate` creates the offline Wiki inside the verified projection.
- Open that generated Wiki through `file://`; do not start a temporary server.
- Use `deliverable.derive` only when the user explicitly requests a versioned deliverable draft. It does not generate the Wiki.
- Use `run.get` for observation. It must not repair state as a side effect.

## External writes

Treat `git.publish`, `current.activate`, `template.publish`, and `deliverable.publish` as separately authorized operations. An ordinary `E_SIDE_EFFECT_DENIED` response is terminal for that request. Do not initialize a repository, commit, push, tag, add notes, install the Skill, or update Current outside the Core.

Report publication, Release, installation, host loading, and business validation as `not_run` unless their own receipts exist.
