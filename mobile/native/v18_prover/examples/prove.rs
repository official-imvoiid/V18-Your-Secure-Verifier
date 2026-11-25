//! Host test tool: `cargo run --release --example prove -- <wasm> <zkey> <vkey.json> <inputs.json> [cache_dir]`
//! Prints the prover's JSON answer. Used to check the prover on the PC before the phone.
fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 5 {
        eprintln!("usage: prove <wasm> <zkey> <vkey.json> <inputs.json> [cache_dir]");
        std::process::exit(2);
    }
    let inputs = std::fs::read_to_string(&a[4]).expect("read inputs");
    let out = v18_prover::prove_json(&a[1], &a[2], &a[3], &inputs, a.get(5).map(|s| s.as_str()));
    println!("{}", out);
}
