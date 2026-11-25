//! Fast reader for snarkjs Groth16 `.zkey` files (BN254).
//!
//! Derived from ark-circom 0.6.0 `src/zkey.rs` (MIT OR Apache-2.0, the
//! arkworks contributors): same file layout and the same field handling.
//! The only changes:
//! - points are built with `new_unchecked` (no on-curve or subgroup check).
//!   That check made loading the 612 MB Anon Aadhaar key take about a minute
//!   on a PC. It is not needed here because (1) the file's SHA-256 is pinned
//!   by the server manifest and checked on download, (2) the key's verifying
//!   key is compared with the official `vkey.json` below, and (3) every proof
//!   is verified with that verifying key before it leaves the prover;
//! - each section is read in one go and decoded in parallel (rayon);
//! - the A and B matrices are moved, not cloned (saves memory on phones).

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger256, PrimeField, Zero};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_relations::utils::matrix::Matrix;
use rayon::prelude::*;

pub struct ZkeyIndex {
    pub num_instance_variables: usize,
    pub num_witness_variables: usize,
    pub num_constraints: usize,
    pub a: Matrix<Fr>,
    pub b: Matrix<Fr>,
}

#[derive(Debug)]
pub struct ZkeyError(pub String);

impl From<std::io::Error> for ZkeyError {
    fn from(e: std::io::Error) -> Self {
        ZkeyError(e.to_string())
    }
}

fn bad(m: &str) -> ZkeyError {
    ZkeyError(m.to_string())
}

#[derive(Clone, Copy)]
struct Section {
    position: u64,
    size: u64,
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn bigint_at(b: &[u8]) -> BigInteger256 {
    let mut limbs = [0u64; 4];
    for (i, l) in limbs.iter_mut().enumerate() {
        let mut x = [0u8; 8];
        x.copy_from_slice(&b[i * 8..i * 8 + 8]);
        *l = u64::from_le_bytes(x);
    }
    BigInteger256::new(limbs)
}

/// Circom stores base field elements already in Montgomery form.
fn fq(b: &[u8]) -> Fq {
    Fq::new_unchecked(bigint_at(b))
}

fn g1(b: &[u8]) -> G1Affine {
    let x = fq(&b[0..32]);
    let y = fq(&b[32..64]);
    if x.is_zero() && y.is_zero() {
        G1Affine::identity()
    } else {
        G1Affine::new_unchecked(x, y)
    }
}

fn g2(b: &[u8]) -> G2Affine {
    let x = Fq2::new(fq(&b[0..32]), fq(&b[32..64]));
    let y = Fq2::new(fq(&b[64..96]), fq(&b[96..128]));
    if x.is_zero() && y.is_zero() {
        G2Affine::identity()
    } else {
        G2Affine::new_unchecked(x, y)
    }
}

/// snarkjs stores the coefficients multiplied by R^2 (see ark-circom).
fn fr_coef(b: &[u8]) -> Fr {
    Fr::new_unchecked(Fr::new_unchecked(bigint_at(b)).into_bigint())
}

struct File<'a, R> {
    sections: HashMap<u32, Section>,
    reader: &'a mut R,
}

impl<'a, R: Read + Seek> File<'a, R> {
    fn open(reader: &'a mut R) -> Result<Self, ZkeyError> {
        let mut head = [0u8; 12];
        reader.read_exact(&mut head)?;
        if &head[0..4] != b"zkey" {
            return Err(bad("not a zkey file"));
        }
        let n = u32_at(&head, 8);
        let mut sections = HashMap::new();
        for _ in 0..n {
            let mut h = [0u8; 12];
            reader.read_exact(&mut h)?;
            let id = u32_at(&h, 0);
            let size = u64::from_le_bytes(h[4..12].try_into().unwrap());
            let position = reader.stream_position()?;
            sections.entry(id).or_insert(Section { position, size });
            reader.seek(SeekFrom::Current(size as i64))?;
        }
        Ok(Self { sections, reader })
    }

    fn read_section(&mut self, id: u32, want: Option<usize>) -> Result<Vec<u8>, ZkeyError> {
        let s = *self.sections.get(&id).ok_or_else(|| bad("zkey section missing"))?;
        let len = match want {
            Some(w) if (w as u64) <= s.size => w,
            Some(_) => return Err(bad("zkey section too short")),
            None => s.size as usize,
        };
        self.reader.seek(SeekFrom::Start(s.position))?;
        let mut buf = vec![0u8; len];
        self.reader.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn g1s(&mut self, id: u32, n: usize) -> Result<Vec<G1Affine>, ZkeyError> {
        let buf = self.read_section(id, Some(n * 64))?;
        Ok(buf.par_chunks_exact(64).map(g1).collect())
    }

    fn g2s(&mut self, id: u32, n: usize) -> Result<Vec<G2Affine>, ZkeyError> {
        let buf = self.read_section(id, Some(n * 128))?;
        Ok(buf.par_chunks_exact(128).map(g2).collect())
    }
}

/// Reads the proving key and the A and B matrices.
pub fn read<R: Read + Seek>(reader: &mut R) -> Result<(ProvingKey<Bn254>, ZkeyIndex), ZkeyError> {
    let mut f = File::open(reader)?;

    // Section 1: prover type (1 = Groth16).
    let t = f.read_section(1, Some(4))?;
    if u32_at(&t, 0) != 1 {
        return Err(bad("zkey is not a Groth16 key"));
    }

    // Section 2: Groth16 header.
    let h = f.read_section(2, None)?;
    let n8q = u32_at(&h, 0) as usize;
    if n8q != 32 {
        return Err(bad("zkey is not for BN254"));
    }
    let mut o = 4 + 32;
    let n8r = u32_at(&h, o) as usize;
    if n8r != 32 {
        return Err(bad("zkey is not for BN254"));
    }
    o += 4 + 32;
    let n_vars = u32_at(&h, o) as usize;
    let n_public = u32_at(&h, o + 4) as usize;
    let domain_size = u32_at(&h, o + 8) as usize;
    o += 12;
    let need = o + 64 * 3 + 128 * 3;
    if h.len() < need {
        return Err(bad("zkey header too short"));
    }
    let alpha_g1 = g1(&h[o..o + 64]);
    let beta_g1 = g1(&h[o + 64..o + 128]);
    let beta_g2 = g2(&h[o + 128..o + 256]);
    let gamma_g2 = g2(&h[o + 256..o + 384]);
    let delta_g1 = g1(&h[o + 384..o + 448]);
    let delta_g2 = g2(&h[o + 448..o + 576]);

    let ic = f.g1s(3, n_public + 1)?;

    // Section 4: coefficients (matrix, constraint, signal, value).
    let c = f.read_section(4, None)?;
    let num_coeffs = u32_at(&c, 0) as usize;
    if c.len() < 4 + num_coeffs * 44 {
        return Err(bad("zkey coefficients too short"));
    }
    let mut matrices: [Vec<Vec<(Fr, usize)>>; 2] = [vec![vec![]; domain_size], vec![vec![]; domain_size]];
    let mut max_constraint = 0usize;
    for i in 0..num_coeffs {
        let e = &c[4 + i * 44..4 + (i + 1) * 44];
        let m = u32_at(e, 0) as usize;
        let constraint = u32_at(e, 4) as usize;
        let signal = u32_at(e, 8) as usize;
        if m > 1 || constraint >= domain_size {
            return Err(bad("zkey coefficient out of range"));
        }
        max_constraint = max_constraint.max(constraint);
        matrices[m][constraint].push((fr_coef(&e[12..44]), signal));
    }
    drop(c);
    if max_constraint < n_public {
        return Err(bad("zkey has too few constraints"));
    }
    // Same as ark-circom: drop the public-input constraints, arkworks adds them.
    let num_constraints = max_constraint - n_public;
    let [mut a, mut b] = matrices;
    a.truncate(num_constraints);
    b.truncate(num_constraints);

    let a_query = f.g1s(5, n_vars)?;
    let b_g1_query = f.g1s(6, n_vars)?;
    let b_g2_query = f.g2s(7, n_vars)?;
    let l_query = f.g1s(8, n_vars - n_public - 1)?;
    let h_query = f.g1s(9, domain_size)?;

    let vk = VerifyingKey::<Bn254> { alpha_g1, beta_g2, gamma_g2, delta_g2, gamma_abc_g1: ic };
    let pk = ProvingKey::<Bn254> { vk, beta_g1, delta_g1, a_query, b_g1_query, b_g2_query, h_query, l_query };
    let index = ZkeyIndex {
        num_instance_variables: n_public + 1,
        num_witness_variables: n_vars - n_public,
        num_constraints,
        a,
        b,
    };
    Ok((pk, index))
}

fn dec<F: PrimeField>(x: &F) -> String {
    x.into_bigint().to_string()
}

fn g1_json(p: &G1Affine) -> Vec<String> {
    match p.xy() {
        None => vec!["0".into(), "1".into(), "0".into()],
        Some((x, y)) => vec![dec(&x), dec(&y), "1".into()],
    }
}

fn g2_json(p: &G2Affine) -> Vec<Vec<String>> {
    match p.xy() {
        None => vec![vec!["0".into(), "0".into()], vec!["1".into(), "0".into()], vec!["0".into(), "0".into()]],
        Some((x, y)) => vec![
            vec![dec(&x.c0), dec(&x.c1)],
            vec![dec(&y.c0), dec(&y.c1)],
            vec!["1".into(), "0".into()],
        ],
    }
}

/// True when the zkey's verifying key equals the snarkjs `vkey.json`.
pub fn matches_vkey(vk: &VerifyingKey<Bn254>, vkey: &serde_json::Value) -> bool {
    let s = |v: &serde_json::Value| -> Option<Vec<String>> {
        v.as_array()?.iter().map(|x| x.as_str().map(|s| s.to_string())).collect()
    };
    let s2 = |v: &serde_json::Value| -> Option<Vec<Vec<String>>> { v.as_array()?.iter().map(s).collect() };
    let ok = (|| -> Option<bool> {
        if vkey.get("protocol")?.as_str()? != "groth16" {
            return Some(false);
        }
        let ic = vkey.get("IC")?.as_array()?;
        if ic.len() != vk.gamma_abc_g1.len() {
            return Some(false);
        }
        for (j, p) in ic.iter().zip(&vk.gamma_abc_g1) {
            if s(j)? != g1_json(p) {
                return Some(false);
            }
        }
        Some(
            s(vkey.get("vk_alpha_1")?)? == g1_json(&vk.alpha_g1)
                && s2(vkey.get("vk_beta_2")?)? == g2_json(&vk.beta_g2)
                && s2(vkey.get("vk_gamma_2")?)? == g2_json(&vk.gamma_g2)
                && s2(vkey.get("vk_delta_2")?)? == g2_json(&vk.delta_g2),
        )
    })();
    ok == Some(true)
}
