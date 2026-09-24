# U02 Native Assistant Managed Configs

The U02 security successor keeps the first candidate and its failed review as
history, then adds a native-format V2 path:

- Codex uses TOML `[mcp_servers.gtkg]` with `command` and `args`.
- Claude Code project/user targets use JSON `mcpServers.gtkg`.
- Cursor project/user targets use JSON `mcpServers.gtkg`.
- Gemini CLI project/user targets use JSON `mcpServers.gtkg`.

The frozen stdio command is represented as an argument vector, never as a
shell string: `gtkg mcp serve --protocol v2 --profile <profile> --stdio`.
Profile identifiers accept only lowercase ASCII letters, digits, `-`, and `_`.
An existing non-matching `gtkg` entry is a conflict rather than user content
that GTKG may overwrite. Native `env` metadata identifies GTKG ownership and
whether GTKG created the parent/file; receipt-bound uninstall is the preferred
API and will not delete an unmarked look-alike entry.

On Unix, apply reopens the authorized root and every parent component with
directory descriptors plus `O_NOFOLLOW`. It binds CAS to content and inode,
rejects hardlinks, creates temporary files with `O_EXCL|O_NOFOLLOW`, preserves
the existing mode (or uses `0600` for a new file), and performs exact readback.
Existing targets use atomic exchange: the displaced inode is validated against
the preview before it is retired, and any mismatch is exchanged back. Missing
targets use atomic no-replace. A deterministic test hook proves the former
check/rename race is rejected. A second hook proves that a concurrent target
written after exchange is preserved rather than overwritten by stale rollback.
A no-op skips the write and keeps the inode.
Non-Unix platforms fail closed until equivalent descriptor semantics are
implemented.

JSON is edited with a validated span-aware object scanner. Only the
`mcpServers.gtkg` byte span is inserted or removed; duplicate keys fail closed,
and install followed by uninstall restores all non-managed bytes exactly,
including formatting, escaping, numeric spelling, and newline suffix. TOML is
parsed and edited with `toml_edit`. Configuration reads are capped with a
`MAX+1` reader, and preview debug output exposes lengths and digests rather than
configuration bodies.

Receipt-bound uninstall distinguishes a missing file from a preexisting empty
file and binds a privacy-safe root device/inode digest, preventing replay into
another root with identical bytes. A preexisting empty file is restored to
exact empty bytes. For a GTKG-created JSON file, uninstall deliberately retains
a valid empty `{}` residue and its directory: the current platform has no
unlink-if-inode primitive, so deleting by pathname after an identity check
would risk deleting a concurrent writer's replacement. Exact absence is
therefore a documented non-destructive P2, not a false success claim. Direct
uninstall remains available for compatibility, but product guidance binds the
lifecycle path to the install receipt.

Receipts contain schema, platform, assistant, scope, exact target file,
profile, before/after/managed digests, write and directory counts, sensitive
value count, secret-output count, mode, and readback state. They never contain
configuration values. Missing final newlines remain missing after install and
uninstall.

Native format references used for this Development implementation:

- Codex config editor source: https://github.com/openai/codex/blob/main/codex-rs/config/src/mcp_edit.rs
- Claude Code MCP scopes and `.mcp.json`: https://code.claude.com/docs/en/mcp
- Cursor `mcp.json`: https://docs.cursor.com/context/model-context-protocol
- Gemini CLI `settings.json`: https://google-gemini.github.io/gemini-cli/docs/tools/mcp-server.html

All tests use isolated temporary roots. Real user configuration, system-level
installation, Release, and external activation remain `not_run`.
