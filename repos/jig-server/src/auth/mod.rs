//! Authentication, admission, and authorization for jig-server.
//!
//! Three sequential gates, in this order:
//!
//! 1. **Authenticate** — do you hold the key for this DID?
//! 2. **Admit** — will this server talk to you at all?
//! 3. **Authorize** — may you do this, here?
//!
//! The order is load-bearing. A caller refused at admission must receive the
//! admission outcome, never the authorization one, because "you are not a
//! member" confirms the channel exists.
//!
//! Phase 1 establishes only the outcome and disclosure types. The gates
//! themselves arrive in phases 2 and 3.

pub mod disclosure;
pub mod outcome;

pub use disclosure::{DisclosurePolicy, audit_line};
pub use outcome::{Gate, GateOutcome};
