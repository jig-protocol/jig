//! Integration test harness for the v0.0.2 hello-world milestone.
//!
//! Spawns real `jig-server` + `jig-nameserver` instances on random
//! `127.0.0.1:0` ports, each with a temp SQLite store. Tests drive
//! these via real HTTP / WSS using `reqwest` and `jig-client`.
//!
//! The harness exists because the unit tests in `jig-server` (notably
//! `v0_0_2_ws::tests`) only cover single-server flows. The H-series
//! acceptance tests need multi-server scenarios (federation, nameserver
//! mode), so this crate provides the shared boot + tear-down primitives.

pub mod harness;
