# Public operations

Read this file only when selecting the next Core operation. Obtain live request schemas from `system.describe` or MCP `tools/list`; do not reconstruct payload fields from this reference.

| Group | Operation IDs |
|---|---|
| System | `system.describe`, `config.validate` |
| Source and build | `source.inspect`, `build.plan`, `build.prepare`, `build.finalize` |
| Summary | `summary.next`, `summary.accept` |
| Run | `run.get`, `run.cancel` |
| Bundle | `bundle.verify`, `bundle.query`, `bundle.compare` |
| Snapshot | `snapshot.create`, `snapshot.verify`, `snapshot.restore` |
| Git and Current | `git.publish`, `current.get`, `current.activate` |
| Node | `node.describe`, `federation.validate` |
| Template | `template.list`, `template.resolve`, `template.prefetch`, `template.get`, `template.validate`, `template.derive`, `template.publish` |
| Deliverable | `deliverable.derive`, `deliverable.publish` |
| A2UI | `a2ui.resolve`, `a2ui.generate`, `a2ui.get`, `a2ui.validate` |

There are exactly 34 public operations. `node.work.execute` is private Coordinator-to-Worker framing and must never be called as a public Tool.

## Side effects

Use the side-effect class disclosed by the Core. Ordinary CLI and MCP contexts deny Git/Current external writes. Do not retry a denied effect through another transport.
