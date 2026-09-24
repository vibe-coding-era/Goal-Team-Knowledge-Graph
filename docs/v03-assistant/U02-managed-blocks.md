# U02 Assistant Managed Blocks

U02 implements preview, CAS-bound apply, exact readback and managed-block
removal for Codex, Claude Code, Cursor and Gemini CLI at user/project scope.
Tests use only isolated temporary roots; no real user configuration is read or
written. Existing user content is preserved, duplicate blocks and concurrent
drift fail closed, symlink escapes are rejected, and receipts contain only
paths, identities and digests rather than configuration bodies or secrets.
