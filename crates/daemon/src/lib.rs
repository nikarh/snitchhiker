//! The daemon's parts, as a library: the binary (`main.rs`) wires them together, and the end-to-end scenarios
//! exercise them in the test VMs.

pub mod alerts;
pub mod api;
pub mod cli;
pub mod config;
pub mod dns;
pub mod hub;
pub mod learn;
pub mod lint;
pub mod locked;
pub mod managed;
pub mod notify;
pub mod peer;
pub mod placement;
pub mod policy;
pub mod process;
pub mod prompts;
pub mod runtime;
pub mod stepup;
pub mod store;
pub mod system;
pub mod trust;
