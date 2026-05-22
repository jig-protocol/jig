//! Fuel-heavy computation test fixture
//! Designed to exhaust fuel limits for testing

#![no_std]
#![no_main]

#[no_mangle]
pub extern "C" fn run() -> i32 {
    // Heavy computation loop
    let mut sum = 0i32;
    for i in 0..1_000_000 {
        sum = sum.wrapping_add((i * 7 + 13) % 997);
    }
    sum
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
