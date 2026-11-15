//! The daemon's parts, as a library: the binary (`main.rs`) wires them together, and the end-to-end scenarios
//! exercise them in the test VMs.

pub mod agents;
pub mod alerts;
pub mod api;
pub mod approvals;
pub mod blocklists;
pub mod cli;
pub mod config;
pub mod contexts;
pub mod dns;
pub mod forward;
pub mod hub;
pub mod learn;
pub mod lint;
pub mod locked;
pub mod logind;
pub mod managed;
pub mod mcp;
pub mod namespaces;
pub mod notify;
pub mod peer;
pub mod placement;
pub mod policy;
pub mod process;
pub mod prompts;
pub mod push;
pub mod remote;
pub mod router;
pub mod runtime;
pub mod stepup;
pub mod store;
pub mod system;
pub mod trust;
pub mod webhook;
