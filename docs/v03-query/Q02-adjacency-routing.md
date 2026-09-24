# Q02 Deterministic Adjacency Routing

Q02 layers a closed routing payload over the frozen Q00
`gtkg.adjacency-shard/v1` header. Existing Q00 callers keep the original
`AdjacencyShardV1` identity, while `AdjacencyRoutingShardV1` binds each edge's
source, target, resolution state, evidence reference, and exact routing anchor.

Node IDs remain exact UTF-8 identities; they are not normalized or merged.
The first byte of SHA-256 over the exact node ID selects one of 256 stable
buckets. Outgoing records are routed by source node and incoming records by
target node. A catalog maps each non-empty `(node, direction)` pair to exactly
one `adj-<bucket>-<direction>` shard, so a route selects one shard without
scanning graph records in unrelated shards.

Every edge occurs exactly twice across the complete index: once in an outgoing
shard and once in an incoming shard. Both records must carry identical source,
target, resolution, and evidence identities. Validation rejects duplicate or
dangling nodes/edges, missing direction counterparts, ghost records, stale
routes, shard-boundary drift, descriptor drift, digest tampering, and open
denominators. Semantic shard and catalog digests exclude only their own digest
field, following the Q01 content-binding convention.

`AdjacencyIndexStateV1` applies an add/change/delete batch atomically. Deleting
a node removes all incident edges, and a subsequent index is byte-identical to
a full rebuild of the same final node/edge exact set. Duplicate mutations and
absent deletes fail closed.

The implementation is an in-memory ordinary-file projection builder and
router. It opens no database, network, daemon, provider, target process, or
filesystem path. Route receipts report zero full-graph, database, network, and
daemon reads. Q03 still owns loading only the selected shard from disk,
continuations, IO budgets, and `QueryPlanReceiptV1`; Q04 owns public graph
handler migration.
