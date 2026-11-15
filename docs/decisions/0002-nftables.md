# 0002. nf_tables and NFQUEUE through our own netlink code

Status: accepted (M0)

## Context

libnftables is GPL-2.0-only (incompatible with Apache-2.0) and reads every interval set of every table before any
element change (what made portcullis slow next to barbican). `rustables` is GPL-3.0. `libnetfilter_queue` is GPL.

## Decision

- `crates/netfilter` writes nf_tables batches and NFQUEUE messages itself, into reused buffers, and parses replies in
  place.
- The table is replaced in one batch (created, deleted, created again with its chains and rules). Nothing outside our
  table is ever listed or touched.
- New TCP connections (SYN only) and the first packets of other flows go to several queues, spread by flow hash.
  Queue overflow drops (`NFQA_CFG_F_FAIL_OPEN` cleared); only the "no daemon bound" bypass can fail open, by policy.
- The kernel reports the sending socket's uid and gid with each packet (`NFQA_CFG_F_UID_GID`).

## Evidence

`nftables/*` scenarios (the table as `nft` shows it, atomic replacement, other tables untouched) and `queue/*`
scenarios (a SYN held for 2 s then accepted connects; dropped never connects; fails closed with no daemon; fails open
with bypass).
