# 0013. A forwarded packet's sender is found through the bridge's forwarding database

Status: accepted (M7)

## Context

Containers on bridge networks (Docker's default, rootful Podman with netavark) and VMs on taps send packets that are
forwarded, never passing the host's `output` hook. The plan (§5.10) queues them in the `forward` chain and resolves
their namespace "from the ingress veth's peer". At the IP forward hook, though, the packet's input device is the
bridge (`docker0`), not the veth: the bridge port it came in through isn't part of the packet's metadata (only with
`br_netfilter`, which we don't want to require).

## Decision

- The table queues new flows in a `forward` base chain (priority -150, before NAT rewrites the source in
  postrouting), only from the bridges named in `forward_from` (Docker, Podman, CNI, libvirt, LXD and Incus bridges by
  default). A router's forwarded traffic isn't touched.
- The sender is found from the packet's link-layer source address, which NFQUEUE reports for packets that came in on
  an interface with one (`NFQA_HWADDR`):
  1. the bridge's forwarding database (`RTM_GETNEIGH`, `AF_BRIDGE`) gives the port behind which that address was
     seen;
  2. a veth port's link attributes name its peer's namespace by a namespace id local to the host's namespace
     (`IFLA_LINK_NETNSID`); ids are mapped to namespace inodes by asking for the id of one process in each namespace
     (`RTM_GETNSID` with `NETNSA_PID`); a tap port is a VM's;
  3. the flow is looked up in the attribution map as its sender recorded it: that namespace's inode and the tuple
     before NAT, which is the tuple at the forward hook.
- The lookups are cached per deciding thread. A stale entry (a container recreated with the same address behind a
  new veth) makes the flow lookup miss, never name another sender: the flow must exist in the namespace named, with
  that exact tuple. A miss is retried once without the caches.

## Consequences

- A spoofed source address can't borrow another container's identity, for the same reason: the victim namespace must
  have opened that exact flow.
- Containers whose traffic is routed rather than bridged (a point-to-point veth with no bridge) aren't covered by this;
  they are attributed through the routed interface's own peer once supported.
