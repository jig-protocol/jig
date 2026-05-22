//! Deterministic pure computation test fixture
//! No WASI imports - pure computation that should be deterministic

#![no_std]
#![no_main]

#[no_mangle]
pub extern "C" fn run() -> i32 {
    // Pure deterministic computation
    let mut sum = 0i32;
    for i in 1..=100 {
        sum = sum.wrapping_add(i * i);
    }
    sum
}

// Panic handler for no_std
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
