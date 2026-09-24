# U05 Local Development Guide

This guide is a runnable, bounded guide for GTKG V0.3 **local Development**.
It uses a newly-created isolated temporary output root and the checked-out
source tree. It never targets a user home directory, a system installation
location, a real assistant configuration, or a target repository.

On macOS, create the output root under `/private/tmp`; on Linux, use `/tmp`.
The name must start with `gtkg-u05-docs-`, and it must be new and private. Use
a fresh empty root for `all`; a one-case command refuses to overwrite its own
case receipt.

```sh
# macOS
U05_DOCS_OUTPUT="$(mktemp -d /private/tmp/gtkg-u05-docs.XXXXXX)"

# Linux
U05_DOCS_OUTPUT="$(mktemp -d /tmp/gtkg-u05-docs.XXXXXX)"
```

The harness writes bounded logs and JSON receipts below that root. Keep the
root until the receipt has been inspected; its contents are local Development
evidence, not a package, Release asset, or product install receipt.

## Quickstart

Run the following command from the V0.3 worktree:

```sh
scripts/v03/run-u05-docs-as-tests.sh quickstart "$U05_DOCS_OUTPUT"
```

It builds only the local `gtkg` binary, then performs `v2-discover` for the
exact `core` profile and a read-only `system.describe` call. The receipt must
show the `core` profile and `scope=local_development_only`. It does not build
or execute a target repository, create a graph for user data, install a
package, register an assistant, or start a network listener.

## Privacy and telemetry

Check that assistant-configuration previews redact values and enforce bounded
input/profile handling:

```sh
scripts/v03/run-u05-docs-as-tests.sh privacy "$U05_DOCS_OUTPUT"
```

This test uses a temporary test fixture only. It does not open, scan, write,
or delete a real Codex, Claude Code, Cursor, or Gemini configuration.

Check the local evidence-drawer network counter separately:

```sh
scripts/v03/run-u05-docs-as-tests.sh telemetry "$U05_DOCS_OUTPUT"
```

The resulting assertion is limited to a local artifact projection with its
observed `network_calls=0` counter. GTKG V0.3 has no production telemetry
service established by this guide, and page-level observation is not a proof
of host-wide blocking: process-wide egress is not_verified. Provider, source,
PII, secret, and competitive telemetry evidence are not created by these
commands. B01 remains blocked because the three-system exact runtime and
telemetry readbacks are unavailable under the current local-only authority.

## Recovery

Exercise the capability-bound local installer fixture, including dry-run,
fault rollback, upgrade, rollback, exact managed-set uninstall, and reinstall:

```sh
scripts/v03/run-u05-docs-as-tests.sh recovery "$U05_DOCS_OUTPUT"
```

The fixture creates its own isolated capability root below the fixed OS
temporary area and checks readback before every lifecycle transition. It is a
development test of the U01 API, not a public `gtkg install` command and not
a system-level installation or rollback result.

## Performance

Run the existing Q05 reference-scale harness:

```sh
scripts/v03/run-u05-docs-as-tests.sh performance "$U05_DOCS_OUTPUT"
```

The command creates `performance-q05/receipt.json` below the isolated output
root. A matching local reference host can report `passed`; a host or
measurement mismatch is retained as `blocked_reference_host_or_measurement`.
Either outcome is a local Q05 observation with its own raw logs. It is not a
B04 competitive benchmark, install-to-first-query result, Explorer timing,
Release performance claim, or business metric.

## Uninstall

Exercise the non-destructive assistant-config uninstall boundary:

```sh
scripts/v03/run-u05-docs-as-tests.sh uninstall "$U05_DOCS_OUTPUT"
```

For a GTKG-created JSON target, the current API deliberately preserves a safe
empty `{}` residue and its directory rather than making a racy pathname unlink
claim. The command verifies that boundary in a temporary fixture. It never
deletes a real user configuration, a user directory, or a system install.

## Readback

To execute every documented case and obtain one bounded summary receipt, use:

```sh
scripts/v03/run-u05-docs-as-tests.sh all "$U05_DOCS_OUTPUT"
```

Inspect `$U05_DOCS_OUTPUT/u05-docs-as-tests-receipt.json`. It enumerates all
six cases and keeps `release_state`, `current_activation`, and
`external_runtime` as `not_run`; it keeps B01 as `blocked`.

## Explicit non-claims

These commands prove only local Development behavior and command/document
consistency. Release, publication, system installation, Current activation, and external runtime are not_run.
They do not complete B01/B02, produce a Release asset, install GTKG for a real
user, prove host-wide network denial, or validate a business outcome.
