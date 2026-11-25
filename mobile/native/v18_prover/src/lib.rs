//! V18 Anon Aadhaar prover (Android, through Dart FFI).
//!
//! Makes the Groth16 proof for the official Anon Aadhaar v2 circuit:
//! 1. witness: the official `aadhaar-verifier.wasm` (circom witness generator),
//!    run with wasmer through `ark-circom`'s `WitnessCalculator`;
//! 2. proof: the official `circuit_final.zkey`, read by `ark-circom`'s
//!    `read_zkey`, proved with `ark-groth16` using `CircomReduction` (the
//!    snarkjs-compatible witness map), so `snarkjs.groth16.verify` with the
//!    official `vkey.json` accepts it;
//! 3. self-check: the proof is verified with the zkey's own verifying key
//!    before it is returned.
//!
//! No cryptography is written here: it only wires vetted libraries together.
//!
//! PRIVACY: the inputs hold the Aadhaar QR data. They are never logged,
//! written to disk or kept after the call. Only the proof and the public
//! signals (which reveal only "age above 18", the nullifier, the timestamp,
//! the UIDAI key hash and the signal hash) leave this function.


use std::ffi::{c_char, CStr, CString};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_circom::{CircomReduction, WitnessCalculator};

pub mod fastzkey;
use ark_ec::AffineRepr;
use ark_ff::{PrimeField, UniformRand};
use ark_groth16::{Groth16, Proof};
use ark_snark::SNARK;
use num_bigint::BigInt;
use serde_json::{json, Map, Value};
use wasmer::{Module, Store};

/// Stage of the running proof, for the progress bar (read from another thread).
/// 0 idle, 1 loading the witness program, 2 making the witness,
/// 3 loading the proving key, 4 proving, 5 checking, 6 done, 9 failed.
static STAGE: AtomicU32 = AtomicU32::new(0);

fn set_stage(s: u32) {
    STAGE.store(s, Ordering::SeqCst);
}

/// Public signal names of the Anon Aadhaar v2 circuit, in order
/// (outputs, then public inputs), as `@anon-aadhaar/core` reads them.
const SIGNAL_NAMES: [&str; 9] = [
    "pubkeyHash",
    "nullifier",
    "timestamp",
    "ageAbove18",
    "gender",
    "pincode",
    "state",
    "nullifierSeed",
    "signalHash",
];

#[derive(Debug)]
struct ProveError(String);

impl<E: std::fmt::Display> From<E> for ProveError {
    fn from(e: E) -> Self {
        ProveError(e.to_string())
    }
}

fn err(msg: &str) -> ProveError {
    ProveError(msg.to_string())
}

/// Parses `{"name": "123" | ["1","2",...] | 123}` into circom inputs.
fn parse_inputs(inputs_json: &str) -> Result<Vec<(String, Vec<BigInt>)>, ProveError> {
    let v: Value = serde_json::from_str(inputs_json)?;
    let obj = v.as_object().ok_or_else(|| err("inputs must be a JSON object"))?;
    let mut out = Vec::with_capacity(obj.len());
    for (k, val) in obj {
        let mut nums = Vec::new();
        collect_numbers(val, &mut nums)?;
        out.push((k.clone(), nums));
    }
    Ok(out)
}

fn collect_numbers(v: &Value, out: &mut Vec<BigInt>) -> Result<(), ProveError> {
    match v {
        Value::String(s) => out.push(
            s.parse::<BigInt>()
                .map_err(|_| err("input is not a decimal number"))?,
        ),
        Value::Number(n) => out.push(
            n.to_string()
                .parse::<BigInt>()
                .map_err(|_| err("input is not an integer"))?,
        ),
        Value::Array(a) => {
            for x in a {
                collect_numbers(x, out)?;
            }
        }
        _ => return Err(err("unsupported input value")),
    }
    Ok(())
}

fn fr_dec(x: &Fr) -> String {
    x.into_bigint().to_string()
}

fn fq_dec<F: PrimeField>(x: &F) -> String {
    x.into_bigint().to_string()
}

/// snarkjs JSON form of a Groth16 proof.
fn proof_json(p: &Proof<Bn254>) -> Result<Value, ProveError> {
    let a: &G1Affine = &p.a;
    let b: &G2Affine = &p.b;
    let c: &G1Affine = &p.c;
    let (ax, ay) = a.xy().ok_or_else(|| err("proof point A is at infinity"))?;
    let (bx, by) = b.xy().ok_or_else(|| err("proof point B is at infinity"))?;
    let (cx, cy) = c.xy().ok_or_else(|| err("proof point C is at infinity"))?;
    Ok(json!({
        "pi_a": [fq_dec(&ax), fq_dec(&ay), "1"],
        "pi_b": [
            [fq_dec(&bx.c0), fq_dec(&bx.c1)],
            [fq_dec(&by.c0), fq_dec(&by.c1)],
            ["1", "0"]
        ],
        "pi_c": [fq_dec(&cx), fq_dec(&cy), "1"],
        "protocol": "groth16",
        "curve": "bn128"
    }))
}

/// Loads the witness program, using a compiled copy in `cache_dir` when one
/// is there (compiling 10 MB of wasm takes a while on a phone).
fn load_module(store: &mut Store, wasm_path: &str, cache_dir: Option<&str>) -> Result<Module, ProveError> {
    let wasm = std::fs::read(wasm_path)?;
    let cache_file = cache_dir.map(|d| {
        // The cache name depends on the wasm bytes, so a new wasm never
        // reuses an old compiled copy.
        let mut h: u64 = 0xcbf29ce484222325;
        for b in &wasm {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        Path::new(d).join(format!(
            "aadhaar-verifier-{:016x}-{}-{}.wasmer",
            h,
            wasm.len(),
            std::env::consts::ARCH
        ))
    });
    if let Some(f) = &cache_file {
        if f.exists() {
            // SAFETY: the file is in the app's private storage and was
            // written by `Module::serialize` below from the checked wasm.
            if let Ok(m) = unsafe { Module::deserialize_from_file(store, f) } {
                return Ok(m);
            }
            let _ = std::fs::remove_file(f);
        }
    }
    let module = Module::new(store, &wasm)?;
    if let Some(f) = &cache_file {
        if let Ok(bytes) = module.serialize() {
            let tmp = f.with_extension("tmp");
            if std::fs::write(&tmp, &bytes).is_ok() {
                let _ = std::fs::rename(&tmp, f);
            }
        }
    }
    Ok(module)
}

fn prove_inner(
    wasm_path: &str,
    zkey_path: &str,
    vkey_path: &str,
    inputs_json: &str,
    cache_dir: Option<&str>,
) -> Result<Value, ProveError> {
    let t0 = Instant::now();
    let vkey: Value = serde_json::from_slice(&std::fs::read(vkey_path)?)?;
    set_stage(1);
    let inputs = parse_inputs(inputs_json)?;
    let mut store = Store::default();
    let module = load_module(&mut store, wasm_path, cache_dir)?;
    let mut calc = WitnessCalculator::from_module(&mut store, module)?;
    let t_wasm = t0.elapsed().as_millis();

    set_stage(2);
    let full_assignment = calc.calculate_witness_element::<Fr, _>(&mut store, inputs, true)?;
    drop(calc);
    drop(store);
    let t_witness = t0.elapsed().as_millis();

    set_stage(3);
    let file = File::open(zkey_path)?;
    let mut reader = BufReader::with_capacity(8 << 20, file);
    let (pk, index) = fastzkey::read(&mut reader).map_err(|e| ProveError(e.0))?;
    drop(reader);
    if !fastzkey::matches_vkey(&pk.vk, &vkey) {
        return Err(err("the proving key does not match the official verification key"));
    }
    let t_zkey = t0.elapsed().as_millis();

    set_stage(4);
    let num_inputs = index.num_instance_variables;
    let num_constraints = index.num_constraints;
    // circom's witness has nVars entries, signal 0 being the constant 1;
    // ark-circom counts that 1 in num_instance_variables (nPublic + 1).
    if full_assignment.len() != index.num_instance_variables + index.num_witness_variables - 1 {
        return Err(err("the witness does not fit this proving key"));
    }
    let matrices = vec![index.a, index.b];
    let mut rng = rand::rngs::OsRng;
    let r = Fr::rand(&mut rng);
    let s = Fr::rand(&mut rng);
    let proof = Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
        &pk,
        r,
        s,
        &matrices,
        num_inputs,
        num_constraints,
        &full_assignment,
    )?;
    drop(matrices);
    let t_prove = t0.elapsed().as_millis();

    set_stage(5);
    let public = &full_assignment[1..num_inputs];
    let pvk = Groth16::<Bn254>::process_vk(&pk.vk)?;
    if !Groth16::<Bn254>::verify_with_processed_vk(&pvk, public, &proof)? {
        return Err(err("the new proof did not pass its own check"));
    }
    let t_check = t0.elapsed().as_millis();

    let public_signals: Vec<String> = public.iter().map(fr_dec).collect();
    let mut named = Map::new();
    if public_signals.len() == SIGNAL_NAMES.len() {
        for (n, v) in SIGNAL_NAMES.iter().zip(&public_signals) {
            named.insert((*n).to_string(), Value::String(v.clone()));
        }
    }
    set_stage(6);
    Ok(json!({
        "proof": proof_json(&proof)?,
        "publicSignals": public_signals,
        "named": named,
        "timingsMs": {
            "loadWitnessProgram": t_wasm,
            "witness": t_witness - t_wasm,
            "loadProvingKey": t_zkey - t_witness,
            "prove": t_prove - t_zkey,
            "selfCheck": t_check - t_prove,
            "total": t_check,
        },
        "threads": rayon_threads(),
    }))
}

fn rayon_threads() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

/// Safe Rust entry point (used by the host test tool).
pub fn prove_json(
    wasm_path: &str,
    zkey_path: &str,
    vkey_path: &str,
    inputs_json: &str,
    cache_dir: Option<&str>,
) -> Value {
    match std::panic::catch_unwind(|| prove_inner(wasm_path, zkey_path, vkey_path, inputs_json, cache_dir)) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            set_stage(9);
            json!({ "error": e.0 })
        }
        Err(_) => {
            set_stage(9);
            json!({ "error": "the prover stopped unexpectedly" })
        }
    }
}

unsafe fn cstr<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    CStr::from_ptr(p).to_str().ok()
}

/// Makes the proof. Blocks until done (call it off the UI thread).
/// Returns a JSON string the caller must free with `v18_free_string`:
/// `{"proof", "publicSignals", "named", "timingsMs"}` or `{"error"}`.
///
/// # Safety
/// All pointers must be valid NUL-terminated UTF-8 strings (cache_dir may be null).
/// `vkey_path` is the official `vkey.json`; the zkey must match it.
#[no_mangle]
pub unsafe extern "C" fn v18_aa_prove(
    wasm_path: *const c_char,
    zkey_path: *const c_char,
    vkey_path: *const c_char,
    inputs_json: *const c_char,
    cache_dir: *const c_char,
) -> *mut c_char {
    set_stage(0);
    let out = match (cstr(wasm_path), cstr(zkey_path), cstr(vkey_path), cstr(inputs_json)) {
        (Some(w), Some(z), Some(v), Some(i)) => prove_json(w, z, v, i, cstr(cache_dir)),
        _ => json!({ "error": "bad arguments" }),
    };
    CString::new(out.to_string())
        .unwrap_or_else(|_| CString::new("{\"error\":\"output\"}").unwrap())
        .into_raw()
}

/// Current stage (see `STAGE`).
#[no_mangle]
pub extern "C" fn v18_aa_stage() -> u32 {
    STAGE.load(Ordering::SeqCst)
}

/// Frees a string returned by `v18_aa_prove`.
///
/// # Safety
/// `p` must come from `v18_aa_prove` and be freed only once.
#[no_mangle]
pub unsafe extern "C" fn v18_free_string(p: *mut c_char) {
    if !p.is_null() {
        drop(CString::from_raw(p));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn parses_inputs() {
        let v = parse_inputs(r#"{"a":"3","b":["1",2,["4"]]}"#).unwrap();
        let m: HashMap<_, _> = v.into_iter().collect();
        assert_eq!(m["a"], vec![BigInt::from(3)]);
        assert_eq!(m["b"], vec![BigInt::from(1), BigInt::from(2), BigInt::from(4)]);
        assert!(parse_inputs(r#"{"a":"x"}"#).is_err());
        assert!(parse_inputs("[]").is_err());
    }
}
