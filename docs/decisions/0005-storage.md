# 0005. Storage: rusqlite with a statement registry, not sqlx

Status: accepted (M1)

## Context

The house style for Rust services is sqlx with compile-time checked queries. The daemon's store is different: one
synchronous writer thread on the packet path's event queue, a few readers, and a hard rule that every statement is
an index seek.

## Decision

- `rusqlite` (bundled SQLite), synchronous: no async runtime on the hot path.
- Every statement the daemon runs is in one registry (`store::STATEMENTS`). A test fills a database, runs `ANALYZE`,
  and fails on any `SCAN` of a growing table or `USE TEMP B-TREE` in `EXPLAIN QUERY PLAN` of any of them. The gate
  replaces sqlx's compile-time checks with something sqlx doesn't check at all: the plan.
- Repeated strings (executables, hosts) are interned in a `strings` table and cached in memory by the writer.
- Events are written in batches, one transaction each; pruning deletes in small chunks by indexed time.

## Evidence

The gate's first run caught the event page query: SQLite chose to scan `strings` and sort in a temporary B-tree.
`CROSS JOIN` fixes the loop order (events by primary key, newest first, then point lookups of the strings).
