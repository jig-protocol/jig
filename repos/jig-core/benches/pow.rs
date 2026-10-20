//! Proof-of-work throughput: digests per second on this machine, one core.
//!
//! JEP-0008 rule 19 asks a verifier to set `max_effort` so the slowest client
//! it means to serve finishes within `max_solve_secs`. This prints the rate
//! that sets those numbers: `cargo bench -p jig-core --bench pow`.
//!
//! No benchmark framework: one timed loop over the real digest is enough to
//! size an effort, and it adds nothing to the lockfile.

use std::hint::black_box;
use std::num::NonZeroU64;
use std::time::Instant;

use jig_core::pow::{Action, MAX_EFFORT, Puzzle};

const DIGESTS: u64 = 1 << 21;

fn main() {
    let binding = [0x11u8; 32];
    let puzzle = Puzzle::new(
        "did:jig:zverifier",
        "did:jig:zsubject",
        Action::NsRegister,
        &binding,
    );

    // Time the solver's own loop. At the largest effort almost no digest
    // passes, so the search runs the whole budget.
    let never = NonZeroU64::new(u64::MAX).unwrap();
    black_box(puzzle.try_solve(never, 0, 1 << 14));
    let start = Instant::now();
    black_box(puzzle.try_solve(never, 1 << 14, DIGESTS));
    let secs = start.elapsed().as_secs_f64();
    let rate = DIGESTS as f64 / secs;

    println!("pow digest: {rate:.0} digests/s on one core ({DIGESTS} in {secs:.3} s)");
    for bits in [16u32, 20, 24, 28] {
        let effort = 1u64 << bits;
        println!(
            "  expected solve at effort 2^{bits}: {:.2} s",
            effort as f64 / rate
        );
    }
    println!(
        "  MAX_EFFORT (2^{}) fits max_solve_secs = 10 at >= {:.0} digests/s",
        MAX_EFFORT.trailing_zeros(),
        MAX_EFFORT as f64 / 10.0
    );

    // One real solve, so the bench exercises the solver as well as the digest.
    let effort = NonZeroU64::new(1 << 16).unwrap();
    let start = Instant::now();
    let proof = puzzle.solve(effort);
    puzzle.check(&proof, effort).expect("a solved proof checks");
    println!(
        "  one solve at 2^16: {:.3} s",
        start.elapsed().as_secs_f64()
    );
}
