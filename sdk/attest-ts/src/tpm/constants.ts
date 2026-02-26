/** TPM 2.0 Algorithm IDs (TPM_ALG_ID) from TCG Algorithm Registry v1.27. */
export enum TpmAlg {
  RSA = 0x0001,
  SHA1 = 0x0004,
  HMAC = 0x0005,
  AES = 0x0006,
  KeyedHash = 0x0008,
  XOR = 0x000a,
  SHA256 = 0x000b,
  SHA384 = 0x000c,
  SHA512 = 0x000d,
  Null = 0x0010,
  RSASSA = 0x0014,
  RSAPSS = 0x0016,
  ECDSA = 0x0018,
  ECC = 0x0023,
  SymCipher = 0x0025,
}

/** TPM_ST (Structure Tags) for attestation types. */
export enum TpmSt {
  AttestCertify = 0x8017,
  AttestQuote = 0x8018,
  AttestCreation = 0x801a,
}

/** TPM_GENERATED_VALUE magic constant — present in all TPM-generated attestation data. */
export const TPM_GENERATED_VALUE = 0xff544347;

/** Hash algorithm digest sizes in bytes. */
export function hashAlgDigestSize(alg: number): number {
  switch (alg) {
    case TpmAlg.SHA1: return 20;
    case TpmAlg.SHA256: return 32;
    case TpmAlg.SHA384: return 48;
    case TpmAlg.SHA512: return 64;
    default: throw new Error(`unsupported hash algorithm: 0x${alg.toString(16)}`);
  }
}

/** Maps TPM hash algorithm to Node.js crypto hash name. */
export function hashAlgName(alg: number): string {
  switch (alg) {
    case TpmAlg.SHA1: return 'sha1';
    case TpmAlg.SHA256: return 'sha256';
    case TpmAlg.SHA384: return 'sha384';
    case TpmAlg.SHA512: return 'sha512';
    default: throw new Error(`unsupported hash algorithm: 0x${alg.toString(16)}`);
  }
}

/** Supported signature hash algorithms in preferred order. */
export const SIGNATURE_HASH_ALGS = [TpmAlg.SHA512, TpmAlg.SHA384, TpmAlg.SHA256] as const;
