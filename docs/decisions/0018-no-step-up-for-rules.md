# 0018. What rules say needs no step-up

Status: accepted

## Context

Step-up (polkit, or an approval on the node for a remote device) guarded some changes to the rules: a rule in force
that allowed "broadly" (naming no particular program and no particular destination), more than 20 rules turned off
at once, a prompt answered with a broad rule, and an agent's proposal with a marked rule. The threat is a process
running as the user that drives the app (input injection on X11, a compromised session) to let itself out.

That process doesn't need a broad rule. It can write a binary anywhere the user may write (the home directory) and
have the app add "allow that binary to anywhere": a rule naming a particular program, which needed no step-up. So the
check guarded nothing it was meant to. Making it consistent would mean step-up for every allow rule of a program a
user may replace: AppImages, toolchains, anything under the home directory, about half of all prompts. Meanwhile it
refused harmless changes: an import of a hundred rules from another firewall failed as a whole because two of them
used regular expressions for both the program and the host.

## Decision

- Changes to rules and folders take no step-up, whatever they leave in force: broad rules, rules enabled or moved out
  of a scoped folder, many rules turned off, undoing.
- Prompts answered with a rule of the client's own conditions take none.
- Agents' proposals are still shaped and their broad rules marked for the person approving them; approving takes no
  step-up.
- Step-up stays for what switches protection off wholesale or hands control to someone else: loosening the policy or
  keeping less history, letting in through the system firewall what it kept out, changing agents' envelopes, pairing a
  device, unpairing or muting another, a remote device's dangerous actions. (Trusted clients and the daemon's
  configuration are root's alone.) Decision 0019 took the policy, the history's retention and the system firewall out
  of this list for local clients, by the same reasoning.

## Consequences

A session of the app can make any rule, as it could already make any narrow one. Every change is in the history and
can be undone. The audit trail records the dangerous actions that remain.
