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
pub mod admission;
pub mod authenticate;
pub mod authorize;
pub mod disclosure;
pub mod outcome;
pub mod replay;
pub mod state;

pub use admission::{AdmissionPolicy, ReputationSource, ReputationView, admit};
pub use authenticate::{AuthProof, authenticate};
pub use authorize::{Visibility, authorize_read};
pub use disclosure::{DisclosurePolicy, audit_line};
pub use outcome::{Gate, GateOutcome};
pub use replay::{ReplayGuard, ReplayRejection};
pub use state::AuthState;
