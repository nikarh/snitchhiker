# 0009. The MCP server is written by hand, not with rmcp

Status: accepted (M4)

## Context

The plan named `rmcp`, the official Rust MCP SDK, for `snitchhiker mcp`. The server it needs is small: MCP over stdio
is JSON-RPC 2.0, one message a line, and the server answers four methods (`initialize`, `ping`, `tools/list`,
`tools/call`) for eight tools that each map onto one request of the agent socket. It has no resources, prompts,
sampling or HTTP transport.

`rmcp` is built on tokio, with schemars and proc macros for the tool definitions. Nothing else in the daemon's binary
uses tokio: the daemon and the command line are threads and blocking sockets. The command line is the daemon's binary
(one package, one file), so the SDK would add an async runtime and its build time to the root daemon for the sake of
a stdio loop.

## Decision

`snitchhiker mcp` (`crates/daemon/src/mcp.rs`) implements the stdio transport and the four methods directly on
`serde_json`, already a dependency. Tool schemas are written as JSON next to the tools. It answers with the protocol
version the client asks for when it knows it (2024-11-05 to 2025-11-25), and its newest otherwise.

## Consequences

- No new dependencies; the binary and its build stay as they were.
- Following MCP is our job: a new protocol version that changes the methods used here needs a change here. The
  methods used have been stable across every version so far, and a client that asks for an unknown version gets one
  this server speaks, as the specification allows.
- Should the server grow (resources, an HTTP transport, notifications of changed proposals), moving to `rmcp` can be
  reconsidered; the tools' behaviour lives in the node, not in the server.
