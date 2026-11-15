---
title: Containers and VMs
description: How Snitchhiker sees and decides the connections of containers, VMs and network namespaces, runtime by runtime.
sidebar:
  order: 6
---

Every connection has a **context**: the host, a container, a VM, or a named network namespace. Rules without a context hold on the host only, so allowing `/usr/bin/curl` doesn't let every `curl` in every container out. A container's connections are decided by the program in it (its path inside the container) and by the container itself: its runtime, name, image, labels and Compose service. Attribution is exact or it isn't made: what can't be known for certain is shown as unknown, and rules that need it don't match.

## Naming them in rules

| Key | Holds for |
| --- | --- |
| `container.compose = ["shop/web"]` | the containers of that Compose service (the stable choice) |
| `container.name = ["shop-web-1"]` | the container of that name |
| `container.image = ["glob:docker.io/library/node:*"]` | containers from those images |
| `container.label = ["tier=front"]` | containers with that label |
| `container.runtime`, `container.owner`, `container.id` | a runtime; the user a rootless container runs as; one container (ids change when it is recreated) |
| `vm.name = ["web"]`, `vm.uuid`, `vm.hypervisor` | a VM |
| `netns = ["vpn"]` | a named network namespace |
| `context = "any"` | everywhere, the host included |

Any of these limits the rule to that kind of context. A prompt from a container offers rules within it, narrowest first: this program in this Compose service (or container name, or image), any program in it, any container from its image, this exact container. The **Containers & VMs** page (desktop and phone) and `snitchhiker contexts` list the contexts connections came from and what each did; `snitchhiker contexts shop/web` shows its programs and the hosts they reached.

## Runtime by runtime

### Docker

- **Bridge networks** (the default, and Compose's): container traffic is forwarded from the bridge (`docker0`, `br-…`) and never passes the host's own sockets. Snitchhiker queues it in a `forward` chain and finds the sending container exactly: the frame's source address in the bridge's forwarding database gives the veth it came through, the veth names the container's namespace, and the connection is looked up as the program in it opened it, before NAT ([`forward_from`](/reference/configuration/#forward_from)).
- **`--network host`**: ordinary host sockets, decided in the host's `output` chain, with the container from the process's cgroup.
- Names, images, labels and Compose services come from Docker's API (`/run/docker.sock`).

### Podman

- **Rootful** containers on Podman's bridge (`podman0`, netavark) are decided as Docker's; their details come from Podman's own database (`/var/lib/containers/storage/db.sql`), with no socket to run.
- **Rootless** containers (as a user, with pasta or slirp4netns) reach the network through a helper that makes their connections on the host. Snitchhiker ties the helper to the container it serves, and from the container's first connection on decides **inside the container's own network namespace**: its table and queue there see each connection with its program, before the helper relays it. The first connection is decided as the container's alone (only rules on the container hold for it). The details come from the user's Podman database (`~/.local/share/containers/storage/db.sql`).

A process in a container holding `CAP_NET_ADMIN` in its namespace could delete Snitchhiker's table there: it is put back at once, with an alert. Docker and Podman don't grant that capability unless asked (`--cap-add NET_ADMIN`, `--privileged`).

### systemd-nspawn, LXC

Named by their cgroup (`systemd-nspawn@<name>.service`, `lxc.payload.<name>`): `container.runtime` is `nspawn` or `lxc`, and `container.name` the machine's name.

### VMs

A VM on a bridge (libvirt's default network `virbr0`, any tap on a bridge in [`forward_from`](/reference/configuration/#forward_from)) is named by the process holding its tap open, and that process's command line: QEMU's `-name guest=…` and `-uuid`, as libvirt starts it. Nothing inside a VM can be known from the host, so rules on a VM name the VM and destinations. A VM bridged straight onto the LAN with a physical interface isn't seen yet.

### Named network namespaces

A namespace made with `ip netns add` (a VPN's, a test's) is managed from the moment it is mounted under `/run/netns`: Snitchhiker decides inside it, and its connections carry its name.

## What isn't covered yet

- Containers on routed (not bridged) networks, and macvlan/ipvlan networks.
- Kubernetes (containerd and CRI-O through the CRI): their containers are named by runtime and id only.
- VMs bridged directly onto a physical interface.
