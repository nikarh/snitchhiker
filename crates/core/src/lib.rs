//! The parts of Snitchhiker that do no I/O: the rule model, the matching engine, the query language and path
//! generalisation. Shared by the daemon and the clients.

pub mod context;
pub mod destination;
pub mod engine;
pub mod generalize;
pub mod lint;
pub mod opensnitch;
pub mod pattern;
pub mod proposal;
pub mod query;
pub mod rule;
pub mod spec;
pub mod suggest;
pub mod system;
