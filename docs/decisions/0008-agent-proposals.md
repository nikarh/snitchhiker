# 0008. Agents propose, people decide: the agent socket and proposals

Status: accepted (M4)

## Context

Coding agents (Claude Code and others) need network access for a task now and then: a registry, an API, a forge.
Through prompts alone, a person sees "node → 104.16.x.x:443" with no context and answers blind. The plan (§5.11) has
agents *propose* precise rules with a reason, through an MCP server, for a person to approve.

An agent runs as the user, so its MCP server does too. Whatever the agent can call, any program of the user's can.

## Decision

- **A socket anyone may open, with nothing to take.** `/run/snitchhiker/agent.sock` (mode 0666) admits every local
  process in the *agent* role. That role can't change anything: it may check how a connection would be decided, list
  the connections its own processes were refused, propose rules, follow its proposals and withdraw them. A proposal
  changes nothing until a person approves it in a client of the admin role.
- **Provenance from the kernel.** The daemon identifies the caller by its pidfd: the MCP process, the agent that
  started it (its parent: `claude`, `node`), the agent's working directory (the project) and its login session. A
  proposal carries what the kernel said, not what the agent wrote. A process's *tree* is the agent and everything it
  started: its processes are the ones descended from the agent, each held by pid *and start time*, so a reused pid
  never counts.
- **Only its own history.** `recent_blocked` lists the connections refused, timed out or waiting from the agent's own
  tree, over the last hour; the node remembers the lineage of every connection it didn't allow, in memory, for that.
  Nothing else of the history reaches agents.
- **Shaped by the node.** Each proposed rule is shaped (`snitchhiker_core::proposal`): its program is the one the
  kernel saw for the agent's refused connections to those destinations, not the agent's word; a rule for any program
  everywhere is refused; any host, public-suffix wildcards, wide networks, the LAN and the metadata service, any port
  with a broad destination, replaceable binaries, and rules nothing refused matches are marked. A marked proposal takes
  step-up to approve.
- **Session-scoped by default.** An approved rule carries a `session` condition: it matches only processes descended
  from the agent (pid and start time), and goes when the agent exits. The person may choose a duration instead.
- **Stored and recorded.** Proposals are kept (pending, approved, denied, withdrawn, expired) with their provenance and
  the person's reason, which the agent is told. Approving makes the rules in `Agents/<agent>/<project>` as one batch
  of the history, undone like any other.
- **`snitchhiker mcp`.** The MCP server (stdio) is a subcommand of the CLI binary: nothing else to install, and it
  speaks to the agent socket like any other client. The protocol is the node's: the tools map one to one onto the
  agent role's requests.

## Consequences

- A same-user program can propose as much as an agent can; it gains nothing a prompt wouldn't give it, since a person
  approves. Its provenance shows it isn't a known agent.
- A prompt-injected agent can propose something harmful with a convincing reason. Shaping, the marks, the evidence
  of refused connections, and the session scope limit what a careless approval costs.
- Pre-authorized envelopes (automatic approval inside declared bounds) are left for later: off by default in the plan,
  and a dangerous action to set.
