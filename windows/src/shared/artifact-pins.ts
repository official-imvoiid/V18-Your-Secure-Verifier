// The exact Anon Aadhaar circuit files this version of V18 works with (PROTOCOL.md 4c.1).
// Official Anon Aadhaar v2.0.0 files (the set @anon-aadhaar/core 2.4.x uses), from
// https://anon-aadhaar-artifacts.s3.eu-central-1.amazonaws.com/v2.0.0/
// The server's manifest must list these same SHA-256 values, or V18 refuses to download anything.

export type ArtifactRole = 'wasm' | 'zkey' | 'vkey';

export const ARTIFACT_SET = 'anon-aadhaar-v2.0.0';

export const ARTIFACT_PINS: Record<ArtifactRole, { name: string; sha256: string; bytes: number }> = {
  wasm: { name: 'aadhaar-verifier.wasm', sha256: '4894923663fafda95beb70abca4112ea97a62058c9a46419a274f04236f10d4f', bytes: 10469686 },
  zkey: { name: 'circuit_final.zkey', sha256: '0d443ea85279b0370b53202f5e768ca9098cfcb5bb14f8ca8323d2266822c492', bytes: 612082146 },
  vkey: { name: 'vkey.json', sha256: '40f2ea24b56ffe2b6e6e3578053cbda15e773cb560697bac883a404077fcf177', bytes: 4388 },
};
