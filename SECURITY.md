# Security

Snitchhiker is a firewall: anything that lets a process get around it is a security issue. That includes:

- sending traffic that no rule allows, without being asked, or being taken for a program, container or VM a rule
  allows;
- a process that is not one of Snitchhiker's own apps changing rules or settings, answering prompts, disabling the
  firewall, pairing a device, or reading the connection history;
- reading or altering the desktop app's memory, or getting it to act for another process;
- impersonating a node or a paired device remotely, or a relay reading or forging what passes through it;
- an agent using the MCP interface getting more than it may: approving its own proposals or reading history outside
  its own processes.

The design's threat model and its known limits are in [docs/plan.md](docs/plan.md) ("Security model").

Please report issues privately, through
[GitHub's vulnerability reporting](https://github.com/nikarh/snitchhiker/security/advisories/new), not in a public
issue.
