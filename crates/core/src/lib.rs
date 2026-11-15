//! The parts of Snitchhiker that do no I/O: the rule model, the matching engine, the query language and path
//! generalisation. Shared by the daemon and the clients.

pub mod destination;
pub mod engine;
pub mod generalize;
pub mod opensnitch;
pub mod pattern;
pub mod query;
pub mod rule;
pub mod spec;
pub mod suggest;
