import { BufferReader } from './buffer-reader.js';
import { TpmAlg } from './constants.js';

/** Decoded TPMT_SIGNATURE — either RSA or ECDSA. */
export type DecodedSignature = RSASignature | ECDSASignature;

export interface RSASignature {
  alg: number; // TpmAlg.RSASSA or TpmAlg.RSAPSS
  hashAlg: number;
  signature: Uint8Array;
}

export interface ECDSASignature {
  alg: number; // TpmAlg.ECDSA
  hashAlg: number;
  r: Uint8Array;
  s: Uint8Array;
}

/**
 * Decode TPMT_SIGNATURE from TPM wire format.
 *
 * Binary layout:
 *   sigAlg: uint16 (Algorithm)
 *   union based on sigAlg:
 *     RSA (RSASSA/RSAPSS):
 *       hashAlg:   uint16
 *       signature: TPM2B (uint16 len + bytes)
 *     ECC (ECDSA):
 *       hashAlg:   uint16
 *       R:         TPM2B (uint16 len + bytes)
 *       S:         TPM2B (uint16 len + bytes)
 */
export function decodeSignature(data: Uint8Array): DecodedSignature {
  const r = new BufferReader(data);
  const sigAlg = r.readUint16();

  switch (sigAlg) {
    case TpmAlg.RSASSA:
    case TpmAlg.RSAPSS: {
      const hashAlg = r.readUint16();
      const signature = r.readSizedBuffer();
      return { alg: sigAlg, hashAlg, signature };
    }
    case TpmAlg.ECDSA: {
      const hashAlg = r.readUint16();
      const ecR = r.readSizedBuffer();
      const ecS = r.readSizedBuffer();
      return { alg: sigAlg, hashAlg, r: ecR, s: ecS };
    }
    default:
      throw new Error(`unsupported signature algorithm: 0x${sigAlg.toString(16)}`);
  }
}

/** Type guard for ECDSA signatures. */
export function isECDSA(sig: DecodedSignature): sig is ECDSASignature {
  return sig.alg === TpmAlg.ECDSA;
}

/** Type guard for RSA signatures. */
export function isRSA(sig: DecodedSignature): sig is RSASignature {
  return sig.alg === TpmAlg.RSASSA || sig.alg === TpmAlg.RSAPSS;
}
