---
title: Other firewalls
description: Running Snitchhiker next to Docker's, libvirt's and Podman's rules, portcullis and barbican.
sidebar:
  order: 7
---

Snitchhiker owns one table, `inet snitchhiker`, and changes nothing else. Its base chains hook `output` and `forward` at priority -150 (mangle), before NAT rewrites the source in postrouting, so it sees each connection as its program opened it. In nftables every base chain on a hook has to accept a packet for it to pass: Snitchhiker's deny holds whatever other tables say, and its allow doesn't override their drops. A connection passes when every firewall on the host lets it.

If a tool flushes the whole ruleset (`nft flush ruleset`, some firewall managers on reload), Snitchhiker notices its table is gone, puts it back, and raises an alert.

## Docker

Docker keeps its rules in its own tables (iptables-nft's `ip filter` and `ip nat`, or Docker 29's native nftables tables): bridge networks, port publishing, inter-container isolation. They work as before: Snitchhiker decides a container's outgoing connections in its `forward` chain before Docker's `FORWARD`, and Docker's NAT applies afterwards. Published ports (inbound) aren't asked about; the [system firewall](/guides/system-firewall/) filters inbound traffic.

## libvirt

libvirt's networks (`virbr0`) come with their own rules (NAT, DHCP, DNS for the guests), in iptables or in its nftables table. VMs on them are decided by name in Snitchhiker's `forward` chain, before libvirt's rules, which still apply.

## Podman

netavark's table (`inet netavark`) does Podman's NAT and port forwarding for rootful containers; rootless ones use pasta or slirp4netns. Both coexist: see [Containers and VMs](/guides/containers/#podman).

## portcullis

[portcullis](https://portcullis.arhipov.net/) limits Docker containers' egress by labels, in its own `inet` and `bridge` tables. Running both, a container's connection must be allowed by its labels in portcullis and by Snitchhiker's rules: portcullis for the policy written next to the service, Snitchhiker for asking about what nobody wrote down, with the program in the container. portcullis also filters container-to-container traffic on a bridge (its `bridge` table), which Snitchhiker doesn't look at.

## barbican

[barbican](https://barbican.arhipov.net/) bans abusive addresses in a `prerouting` chain at priority -190, before anything reaches a program, a container or a forwarded path. It decides inbound traffic, Snitchhiker outbound: they don't overlap.
