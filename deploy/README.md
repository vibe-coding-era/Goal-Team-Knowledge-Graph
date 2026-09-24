# Deploying GTKG v0.4

GTKG is a local, single-binary, file-storage tool. It has **no installer, no
daemon, no service and no release channel** in this build — `git.publish`,
`current.activate` and `template.publish` all return `E_SIDE_EFFECT_DENIED`, and
`watch`/`poll`/`inotify` do not exist anywhere in the source. "Deploy" and "run
automatically" therefore mean:

| Layer | What it is | Provided by |
|---|---|---|
| 1. Binary | one static `gtkg` executable | `install.sh` |
| 2. Workspace | one directory holding a pinned source checkout plus `.gtkg/` state | `gtkg-workspace-init.sh` |
| 3. Automation | an external scheduler calling a shell script | `gtkg-pipeline.sh` + `install-launchd.sh` |
| 4. Consumption | MCP stdio for agents, static HTTP for humans | `gtkg-serve.sh` |
| 5. Interactive use | a prompt over the CLI (GTKG itself has no REPL) | `gtkg-shell.sh` |

Everything below was run and verified on macOS (aarch64). Nothing here needs
`sudo`; the install is user-local.

---

## 1. Install the binary

```bash
cd develops/v0.4
./deploy/install.sh                       # honours GTKG_PREFIX, default ~/.local
export PATH="$HOME/.local/bin:$PATH"
```

The script builds with `--release --locked --offline`, copies the binary, then
**reads its identity back** (`system.describe`: 34/34 operations,
`storage_model=okf-and-ordinary-files`, binary/core digests) and writes
`~/.local/share/gtkg/install-manifest.json`. It records what it did **not** do:
`release_published: false`, `system_installed: false`, `current_activated: false`,
`reproducible_build_verified: false`.

Verify:

```bash
gtkg --version
gtkg v2-discover --profile core        # 10 tools
gtkg v2-discover --profile all         # 46 tools
```

## 2. Create a workspace per repository

The authorization model forces this layout: the CLI's authorized root is the
**process working directory**, and the source, the host inputs and every output
must live under it.

```bash
export GTKG_ROOT="$HOME/gtkg"
./deploy/gtkg-workspace-init.sh \
    /path/to/some-git-repo \
    "$GTKG_ROOT/workspaces/serde" serde
```

This clones the repo, **pins** `source_commit` and `expected_tree`, and writes
`gtkg-run.json`:

```
$GTKG_ROOT/workspaces/serde/
├── serde/                     pinned source checkout
├── gtkg-run.json              the run config
└── .gtkg/                     runtime state and produced bundles
```

Now fill in the three things only you can decide:

| Field | Meaning |
|---|---|
| `understanding_items` | the questions the knowledge must answer. Must be non-empty, unique and **sorted**. |
| `windows` | `{"relative/path.py": [first_line, last_line]}` — the **only** bytes the author may read. The context budget is in Unicode codepoints (`max_context_units`, ≤ 8000), so never feed a whole large file. |
| `modules` | `{module_id, name, subsystem, language, source_paths}`; `source_paths` must be sorted, and `language` must match what the inventory derives. |

> `deliverable.derive` needs `item_id` to **equal** the question text. Core keys
> the coverage denominator by `item_id` but looks claims up by their
> `understanding_item`, so any other value silently reports zero coverage.

## 3. Turn on automation

```bash
./deploy/install-launchd.sh install "$GTKG_ROOT"
$EDITOR "$GTKG_ROOT/.env"          # DEEPSEEK_API_KEY=...   (file is 0600)
launchctl kickstart -p "gui/$(id -u)/com.gtkg.pipeline"
```

That installs `~/Library/LaunchAgents/com.gtkg.pipeline.plist` with
`StartInterval 21600` (6 h). The API key lives in `$GTKG_ROOT/.env` with mode
`0600` — **never** in the plist and never in the repository.

What the scheduled run does, per workspace:

1. **Skips** it if its pinned commit already produced a verified bundle
   (`GTKG_FORCE=1` overrides). A 6-hourly timer therefore does not burn a model
   call on unchanged source.
2. Otherwise runs the full chain: `source.capture` → `analysis.plan/build/verify`
   → `summary.job.next` → author → `proposal.submit` → 2 independent reviews →
   `accept.v2` → `deliverable.derive` → `build.finalize.v2` → `bundle.verify`.
3. Logs to `$GTKG_ROOT/logs/pipeline-<UTC>.log` and appends to
   `.gtkg/host/runs.json`.

Useful commands:

```bash
launchctl print "gui/$(id -u)/com.gtkg.pipeline"     # state / interval
launchctl kickstart -p "gui/$(id -u)/com.gtkg.pipeline"
./deploy/gtkg-pipeline.sh "$GTKG_ROOT" all           # run by hand, same path
./deploy/gtkg-pipeline.sh "$GTKG_ROOT" capture       # one stage only
./deploy/install-launchd.sh uninstall
```

**Other platforms.** The pipeline script is the entire automation surface, so on
Linux use a systemd timer or a cron entry calling the same
`gtkg-pipeline.sh <root> all`. Nothing else changes.

## 4. Serve the knowledge

```bash
./deploy/gtkg-serve.sh mcp graph          # MCP stdio for an agent host
./deploy/gtkg-serve.sh http 8421          # newest finalized bundle over loopback
```

* **MCP** exposes the v2 tool registry over stdio — `--profile graph` gives the
  six graph/query tools, `--profile all` all 46. No socket is opened.
* **HTTP** is a plain static server over the newest stamped bundle; the
  knowledge documents are at
  `http://127.0.0.1:8421/.gtkg/qk/knowledge/<sha256>.md`. It is a viewer, not
  part of the product, and it binds loopback only.
* Direct queries without a server:

  ```bash
  gtkg v2-op graph.search --profile graph --request - --output json <<'JSON'
  {"payload_revision":"gtkg.knowledge-quality/v0.4-r1","workspace_root":"...",
   "index_ref":{...},"query":"how are contexts pushed","query_policy":"gtkg.qk.query/v1",
   "max_results":10,"max_tokens":4000}
  JSON
  ```

## 5. Start an interactive session

GTKG's CLI is one-shot by design — there is no REPL and no daemon. `gtkg-shell.sh`
is a thin prompt over the real CLI that pins the binary, the workspace and the
envelope shape so you do not retype JSON:

```bash
./deploy/gtkg-shell.sh                 # newest workspace under $GTKG_ROOT
./deploy/gtkg-shell.sh ~/gtkg/workspaces/serde
```

```
gtkg:flask> help
gtkg:flask> status                     workspace, ledger, bundles
gtkg:flask> doc                        print the newest knowledge document
gtkg:flask> tools core                 the 10 core tools and their payload revisions
gtkg:flask> profile graph              switch the default v2 profile
gtkg:flask> op system.describe         v1, envelope built for you
gtkg:flask> v2op capability.describe   v2, envelope built for you
gtkg:flask> v2op graph.search {"payload_revision":"gtkg.knowledge-quality/v0.4-r1", ...}
gtkg:flask> quit
```

Everything it does is a real `gtkg` invocation; run `raw <op>` to see the
unformatted envelope. For an agent host use `gtkg-serve.sh mcp <profile>` instead.

## 6. Operating notes

**Each run finalizes its own bundle** named `<bundle_name>-<UTC stamp>`, because
a bundle destination is immutable and a model author produces different bytes
each time. `latest.json` in the bundles directory records the current one.

**Stage order matters.** Stages run in chain order and each consumes the previous
one's receipt. A single stage name reruns just that stage from the persisted
`.gtkg/host/state.json`, so `... finalize` after a failure does not re-run the
author.

**The author is retried, not trusted.** The driver rejects citations outside the
observed windows and repairs trailing commas, re-prompting up to three times
before failing. Core independently fails closed on anything the driver misses.

**What the run does not prove.** `llm_qa_validated` stays `false`,
`execution_assurance` is `host_observed/not_independently_attested`, coverage is
`declared_understanding_items_only`, and `bundle.verify` proves the reference
closure and source spans rather than answer quality. A single run is not a
benchmark.

## 7. Verified on this machine

```
install            ~/.local/bin/gtkg, 34/34 ops, identity read back
workspace          ~/gtkg/workspaces/flask, pinned d318b683 / a8da09a5
manual pipeline    0 failures, bundle flask-r1-20260920T121944Z
launchd kickstart  exit 0 (ran the full chain once, then skipped on the 2nd)
skip path          "already verified for commit d318b6834711"
MCP                tools/list -> 6 graph tools
HTTP               GET / = 200, GET /.../knowledge/<sha>.md = 200
shell              help/status/doc/profiles/tools/op/v2op/raw/ws all exercised
```
