# 0019. Local settings need no step-up; the session is what to secure

Status: accepted (narrows 0018's list of what keeps step-up)

## Context

After decision 0018, step-up (polkit) still guarded a local client's changes that loosen protection as a whole:
switching the node to monitor mode, letting connections no rule decides through, keeping less history, letting in
through the system firewall what it kept out. The threat is the same as for rules: a process running as the user that
drives the app (injected input, a compromised session) to let itself out.

The same reasoning applies. Such a process doesn't need monitor mode: it can have the app make a rule for a program
of its own, which 0018 lets through. The password guarded nothing that wasn't open another way, and it was in the way:
under a session with no polkit agent (a bare window manager) polkit refuses at once, and a person could switch the
node to enforce but never back.

What does protect the app is the session it runs in: whether other processes can send it input or control its
window. Under X11 any client can; under Wayland, a compositor that offers virtual keyboards and pointers to any client
(`zwp_virtual_keyboard_manager_v1`, `zwlr_virtual_pointer_manager_v1`), a `/dev/uinput` the user may write, or window
management of other clients' windows (`zwlr_foreign_toplevel_management_v1`) opens the same door.

## Decision

- A local client changing the policy (mode, no_match, no_client, on_timeout, prompt timeout), the history's retention
  or the system firewall takes no step-up. The change is audited (`snitchhiker audit`, outcome *unchecked*) and kept
  in the history of changes, as before.
- Step-up stays where control passes to someone else: a remote device's dangerous actions (a local approval),
  pairing a device, unpairing or muting another, and agents' envelopes (proposals approved without anyone asking).
  These hand power to another party rather than change this machine's own settings.
- The desktop app checks its session and warns, with what it means and how to close it, when other processes can
  inject input or control its window: X11, a display server that isn't a known compositor, a compositor offering
  virtual input or foreign window management to any client, a writable `/dev/uinput`. Each check is exact: the
  registry's globals, the socket's peer, the device's permissions.

## Consequences

The person at the machine changes their own firewall's settings without a password, whatever their session runs.
The app's security rests on the session, and it says when the session is open to other processes, rather than on a
password that a compromised session could route around.
