//! The daemon's parts, as a library: the binary (`main.rs`) wires them together, and the end-to-end scenarios
//! exercise them in the test VMs.

pub mod api;
pub mod cli;
pub mod config;
pub mod dns;
pub mod hub;
pub mod learn;
pub mod managed;
pub mod notify;
pub mod peer;
pub mod process;
pub mod prompts;
pub mod runtime;
pub mod store;
