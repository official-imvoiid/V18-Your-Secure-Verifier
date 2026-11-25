// Types for the one function V18 uses from @anon-aadhaar/core (its own types ship as raw .ts
// sources that don't compile under this project's strict settings, so V18 imports the built
// dist file and declares just this part).
declare module '@anon-aadhaar/core/dist/index.js' {
  interface Arg<T> {
    argumentType: string;
    value?: T;
  }
  export interface AnonAadhaarArgs {
    qrDataPadded: Arg<string[]>;
    qrDataPaddedLength: Arg<string>;
    delimiterIndices: Arg<string[]>;
    signature: Arg<string[]>;
    pubKey: Arg<string[]>;
    nullifierSeed: Arg<string>;
    signalHash: Arg<string>;
    revealAgeAbove18: Arg<string>;
    revealGender: Arg<string>;
    revealPinCode: Arg<string>;
    revealState: Arg<string>;
  }
  export function generateArgs(opts: {
    qrData: string;
    certificateFile: string;
    nullifierSeed: number | bigint;
    fieldsToRevealArray?: ('revealAgeAbove18' | 'revealGender' | 'revealPinCode' | 'revealState')[];
    signal?: string;
  }): Promise<AnonAadhaarArgs>;
  export function hash(message: string | number | bigint): string;
  export const testPublicKeyHash: string;
  export const productionPublicKeyHash: string;
}
