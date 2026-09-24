# Q03 File-backed Lazy Query Runtime

Q03 adds an internal ordinary-file query runtime over the accepted Q00–Q02
index objects. It does not switch the six public graph operations; that remains
Q04. It also does not claim the 10k/10,001 performance gate, RSS targets, or
benchmark completion; those remain Q05 and B04.

## Sealed index and planning identities

`write_file_query_index_v1` publishes immutable lexical and adjacency shard
files plus one content-addressed `gtkg.file-query-index-manifest/v1`. The
manifest binds the exact source, graph, overlay, tokenizer, structural index,
lexical routing catalog, adjacency routing catalog, physical shard paths,
semantic shard digests, raw file digests, byte lengths, record counts, and the
closed Q00 budgets. Every file descriptor also carries the complete routing-key
exact set derived from that shard and, for lexical shards, the normalized-term
denominator. The manifest reconstructs the lexical catalog from those per-shard
sets. Its adjacency projection contains exactly two entries for every known
node—outgoing and incoming—including explicit `None` entries for directions
with no edge. Shard file names are deterministic SHA-256 derivations of their
exact shard IDs.

The writer also publishes `binding/current.json` after the immutable manifest.
That fixed, no-clobber binding carries the exact manifest artifact reference,
structural index identity, and source/graph/overlay identities. Production
planning and execution read it independently before accepting a caller-supplied
manifest reference. Re-sealing the manifest, catalogs, per-shard keys, and
explicit empty routes together therefore cannot replace the bound artifact.

Search planning consults only the embedded term/trigram/short-CJK-substring
routing catalog. One- and two-scalar CJK windows are explicit routes because
the accepted Q01 search semantics use substring matching below trigram length.
Adjacency planning consults only the Q02 node/direction routing catalog. The
planner freezes an exact selected/excluded partition and a semantic plan digest
before opening any shard. A missing lexical key is a legitimate no-answer. A
present key with no shard is rejected as a false-negative signal. Disjoint
phrase routes are also a legitimate no-answer because no shard can contain the
whole phrase.

When a selected shard is opened, the reader recomputes its complete routing-key
set from the actual normalized terms, trigrams, short CJK windows, or adjacency
records. It also checks lexical `record_count == postings.len()` and the exact
normalized-term denominator. Deleting and re-sealing a catalog route cannot
turn it into a legitimate no-answer while the bound per-shard exact set and
physical shard remain unchanged.

## Descriptor-bound lazy reads

Manifest and selected shard reads are rooted at the most specific authorized
directory. On Unix, every directory component and the final file are opened
with descriptor-relative `O_NOFOLLOW`; the final endpoint must be a private
regular inode. Hard links, symlinks, parent aliasing, device/inode replacement,
length drift, over-budget files, raw-byte digest drift, and semantic digest
drift fail closed. The opened descriptor and path inode are compared before and
after the bounded read. The manifest is read again after all selected shards,
so a concurrent index change yields a stale/rebuild signal.

Index-root, `shards`, and `manifests` directory creation begins by opening the
authorized root descriptor. Missing components are created with descriptor-
relative `mkdirat`, reopened with `O_NOFOLLOW`, and their parent directories are
synced. No path-based `create_dir_all` runs before root/parent verification.
Immutable publication also starts from the longest authorized lexical-root
descriptor and walks `.gtkg`, the index root, and every parent component with
`openat(O_NOFOLLOW)`; it never reopens `index_root` by path after authorization.
Temporary creation, atomic no-replace rename, readback, cleanup, and parent
sync all use the held directory descriptor.

An ordinary query opens only its selected shards. A no-answer opens zero
shards. `FileQueryPageV1` records measured manifest bytes, measured shard bytes,
response bytes, opened shard IDs/count, the exact selected/excluded partition,
and zero full-graph/database/network/daemon calls. Those counters are derived
from the actual reads rather than populated from a simulated backend.

## Bounded pages and continuation

Results are cut only at record boundaries. If `max_results` or the frozen
response-byte budget cuts a result set, the receipt is explicitly `truncated`
and carries an opaque `gtkgc1` continuation. A complete page cannot carry a
continuation. A record that cannot fit by itself fails with a resource-budget
error instead of silently disappearing.

The continuation is closed JSON encoded as opaque hex and digest-bound to the
query, file manifest, structural manifest, routing catalogs, selected shards,
frozen budgets, page size, next record offset, prior plan, and prior page. The
next execution reopens and revalidates the same manifest and rejects query,
manifest, routing, selection, page-size, budget, cursor, or token drift.

Continuation consumers use `execute_next_file_query_page_v1` and
`validate_next_page_against_v1` with the actual preceding page. The next request
must carry that page's exact issued token; its `prior_plan_sha256`,
`prior_page_sha256`, and `next_offset` must match the preceding page before and
after execution. Re-encoding a valid self-digest to skip or duplicate records is
therefore rejected by the predecessor-bound API.

The production first-page entrypoint is `execute_first_file_query_page_v1`; it
rejects every request carrying a continuation. The predecessor-less historical
`execute_file_query_page_v1` exists only under the `test-faults` feature to keep
the frozen pre-repair evidence executable and is not an authoritative runtime
surface.

Q03 Development evidence covers a 1,000-document single-shard smoke only.
Public graph handler cutover, 300-query correctness, 10k/10,001 scale, RSS and
latency targets, full/incremental joined equivalence, Release, install, and
external/business acceptance remain explicitly not run.
