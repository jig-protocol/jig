//! Hello World test fixture using WASI stdout
//! Uses WASI preview1 for compatibility with wasmtime-wasi

fn main() {
    println!("Hello from WASI!");
    println!("Deterministic output");
}
