# Q01 Deterministic Lexical Index

Q01 builds a deterministic lexical shard from bounded document records. The
shard contains a Unicode 17 NFC token exact set, a serialized finite-state trie
identity, scalar-trigram catalog, inverted postings with token positions, and
evidence references. Its content digest binds every field except the digest
field itself.

Exact ASCII and Unicode term lookup traverses the finite-state trie before an
inverted-posting lookup. Multi-token phrases intersect exact postings at
consecutive token positions. CJK substring lookup intersects trigram-to-term
candidates and then verifies the exact scalar substring, preventing a trigram
collision from becoming a positive result.

`LexicalIndexStateV1` applies an add/change/delete batch atomically and rejects
duplicate mutations or absent deletes. A shard built from the resulting state
is byte-identical to a full rebuild of the same document exact set, so deleted
or changed terms cannot survive as ghost postings.

The implementation is file-format preparation only: it performs no network,
database, daemon, provider, target-code execution, or filesystem write. Q03
still owns file-backed lazy planning and IO receipts, while Q04 owns switching
the public `graph.search` operation away from its predecessor path.
