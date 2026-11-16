---
title: FAQ
description: Short answers to the questions people ask first, with links to the pages that say more.
sidebar:
  order: 4
---

## How is it different from OpenSnitch?

It does the same job (asking which programs may connect where), and imports OpenSnitch's rules and system firewall ([Coming from OpenSnitch](/guides/opensnitch/)). It differs in how it knows things and where it can be controlled:

- The program behind a connection is recorded by eBPF when the connection is opened, from the process that opens it, never guessed from timing; names come only from DNS answers to queries the process was seen to send ([How it works](/internals/how-it-works/)).
- Rules live in folders, have tiers with a fixed precedence (not alphabetical order), and come with a history you can undo.
- Containers, VMs and network namespaces are told apart, and decided by their names, images or Compose services ([Containers and VMs](/guides/containers/)).
- A node can be answered from a phone or from another machine, including headless servers ([Phones and remote nodes](/guides/remote/)), and coding agents can propose rules through MCP ([Agents](/guides/agents/)).

## Will it break my machine?

Not by being installed: the packages start in **monitor mode**, which records everything and blocks nothing ([Quick start](/start/quick-start/)). Once enforcing, what happens to connections no rule allows is yours to choose (`no_match`), and so is what happens while the daemon isn't running (`fail`: closed by default, open for a machine you reach over the network). Loopback and the daemon's own traffic are allowed by the built-in System folder.

## Does it slow the network down?

Only a connection's first packet goes to the daemon; the rest of an allowed connection never leaves the kernel. Deciding takes about a microsecond with ten thousand rules, and the daemon stays under 50 MB ([Performance budgets](/project/development/#performance-budgets)).

## What does it see of my traffic?

The program, user, destination (address, port, and the name the program looked up) and how many bytes went each way. It reads DNS answers to learn names, never the content of other traffic. All of it stays on the node, in its database, for [`retention_days`](/reference/configuration/#retention_days) (30 by default). Paired phones and other clients see it when they ask; a relay only forwards encrypted connections.

## Why does a rule on a host name not match?

The node knows a destination by name only if it saw the DNS answer. Programs that resolve names over HTTPS or with a resolver of their own make connections the node knows only by address. See [Troubleshooting](/guides/troubleshooting/#a-rule-doesnt-match).

## Does it work with Docker, Podman, libvirt?

Yes. Containers' connections are decided with rules that name the container (by name, image, Compose service, labels) and the program inside it, rootless Podman included; VMs on a bridge are decided by the VM's name. It coexists with the rules Docker, libvirt and firewalld make ([Coexistence](/guides/coexistence/)).

## Can I run it on a server without a screen?

Yes: that is what monitor mode, `snitchhiker learn` and the command line are for, and a phone or a desktop elsewhere can answer prompts and get alerts from it ([Quick start](/start/quick-start/), [Phones and remote nodes](/guides/remote/)).

## Can malware just turn it off?

Not without root. The daemon runs as root; clients reach it through a socket that only trusted, root-installed client binaries may use, and dangerous actions (turning interception off, allowing every program everywhere, pairing a device) need an administrator's password or an approval on another device. Malware running as you can make connections a prompt asks about, or propose rules as an agent would, but a person decides ([Security model](/internals/security/)). Malware running as root can do anything, including removing any firewall.

## Is it free?

Yes: `MIT OR Apache-2.0`, the eBPF programs `GPL-2.0-only OR MIT`.
