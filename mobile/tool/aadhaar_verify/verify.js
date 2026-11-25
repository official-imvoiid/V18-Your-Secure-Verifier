// Usage: node verify.js <vkey.json> <proof.json from the prover> [--expect-signal-hash <dec>]
// Prints JSON {snarkjs, anonAadhaar} and exits 0 only if both accept.
const fs = require('fs');
const snarkjs = require('snarkjs');
const aa = require('@anon-aadhaar/core');

async function main() {
  const [vkeyPath, proofPath] = process.argv.slice(2);
  const vkey = JSON.parse(fs.readFileSync(vkeyPath, 'utf8'));
  const out = JSON.parse(fs.readFileSync(proofPath, 'utf8'));
  const okSnark = await snarkjs.groth16.verify(vkey, out.publicSignals, out.proof);
  await aa.init({ wasmURL: '', zkeyURL: '', vkeyURL: vkeyPath, artifactsOrigin: aa.ArtifactsOrigin.local });
  const n = out.named;
  const pcd = {
    type: 'anon-aadhaar', id: 'v18-check', claim: {},
    proof: { groth16Proof: out.proof, pubkeyHash: n.pubkeyHash, timestamp: n.timestamp,
      nullifierSeed: n.nullifierSeed, nullifier: n.nullifier, signalHash: n.signalHash,
      ageAbove18: n.ageAbove18, gender: n.gender, pincode: n.pincode, state: n.state },
  };
  const okAa = await aa.verify(pcd, true);
  // A changed public value must be refused.
  const bad = JSON.parse(JSON.stringify(pcd));
  bad.proof.ageAbove18 = '0';
  const okBad = await aa.verify(bad, true);
  console.log(JSON.stringify({ snarkjs: okSnark, anonAadhaar: okAa, tamperedRefused: !okBad }));
  process.exit(okSnark && okAa && !okBad ? 0 : 1);
}
main().catch((e) => { console.error(e); process.exit(2); });
