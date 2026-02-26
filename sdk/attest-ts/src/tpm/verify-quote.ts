import { createHash, createVerify, timingSafeEqual, type KeyObject } from 'node:crypto';
import type { Quote, PCRs } from '../proto/layr_tpm_pb.js';
import { decodeSignature, isECDSA, isRSA, type DecodedSignature } from './decode-signature.js';
import { decodeAttestationData } from './decode-attestation.js';
import { TpmSt, hashAlgName, SIGNATURE_HASH_ALGS } from './constants.js';

/**
 * Verify a TPM quote — port of internal/quote.go VerifyQuote.
 *
 * Checks:
 * 1. Signature over quote bytes is valid (RSA PKCS#1v1.5 or ECDSA)
 * 2. Quote starts with TPM_GENERATED_VALUE
 * 3. Quote type is ATTEST_QUOTE
 * 4. ExtraData matches expected nonce (constant-time)
 * 5. PCR digest in quote matches hash of provided PCR values
 */
export function verifyQuote(
  quote: Quote,
  trustedPub: KeyObject,
  expectedNonce: Uint8Array,
): void {
  const quoteBytes = quote.quote;
  const rawSig = quote.rawSig;

  // 1. Decode and verify signature
  const sig = decodeSignature(rawSig);
  const hashAlg = getSignatureHashAlg(sig);
  verifySignature(trustedPub, hashAlg, quoteBytes, sig);

  // 2-3. Decode attestation data (checks magic = TPM_GENERATED_VALUE)
  const attestData = decodeAttestationData(quoteBytes);
  if (attestData.type !== TpmSt.AttestQuote) {
    throw new Error(`expected quote tag 0x${TpmSt.AttestQuote.toString(16)}, got: 0x${attestData.type.toString(16)}`);
  }

  const quoteInfo = attestData.attested;
  if (!quoteInfo) {
    throw new Error('attestation data does not contain quote info');
  }

  // 4. Constant-time compare extraData
  if (!safeEqual(attestData.extraData, expectedNonce)) {
    throw new Error('quote extraData did not match expected nonce');
  }

  // 5. Validate PCR digest
  validatePCRDigest(quoteInfo.pcrSelection, quoteInfo.pcrDigest, quote.pcrs!, hashAlg);
}

function getSignatureHashAlg(sig: DecodedSignature): number {
  const hashAlg = sig.hashAlg;

  for (const supported of SIGNATURE_HASH_ALGS) {
    if (hashAlg === supported) return hashAlg;
  }
  throw new Error(`unsupported signature hash algorithm: 0x${hashAlg.toString(16)}`);
}

function verifySignature(
  pub: KeyObject,
  hashAlg: number,
  data: Uint8Array,
  sig: DecodedSignature,
): void {
  const algName = hashAlgName(hashAlg);

  if (isECDSA(sig)) {
    // Encode R and S as DER for Node.js crypto
    const derSig = encodeECDSASignatureDER(sig.r, sig.s);
    const verifier = createVerify(algName);
    verifier.update(data);
    if (!verifier.verify({ key: pub, dsaEncoding: 'der' }, derSig)) {
      throw new Error('ECC signature verification failed');
    }
  } else if (isRSA(sig)) {
    const verifier = createVerify(algName);
    verifier.update(data);
    if (!verifier.verify(pub, sig.signature)) {
      throw new Error('RSASSA signature verification failed');
    }
  }
}

/**
 * Validate that the PCR digest in the quote matches hash(concat(PCR values in selection order)).
 */
function validatePCRDigest(
  pcrSelection: { hash: number; pcrs: number[] },
  expectedDigest: Uint8Array,
  pcrs: PCRs,
  hashAlg: number,
): void {
  // Check hash algorithm matches
  if (pcrs.hash !== pcrSelection.hash) {
    throw new Error('PCR hash algorithm does not match quote PCR selection');
  }

  // Check same PCR selection
  const pcrMap = pcrs.pcrs;
  const pcrKeys = Object.keys(pcrMap).map(Number).sort((a, b) => a - b);
  const selectionSorted = [...pcrSelection.pcrs].sort((a, b) => a - b);

  if (pcrKeys.length !== selectionSorted.length ||
      !pcrKeys.every((v, i) => v === selectionSorted[i])) {
    throw new Error('given PCRs and Quote do not have the same PCR selection');
  }

  // Compute PCR digest: hash(PCR[0] || PCR[1] || ... || PCR[23]) in index order
  const h = createHash(hashAlgName(hashAlg));
  for (let i = 0; i < 24; i++) {
    const val = pcrMap[i];
    if (val !== undefined) {
      h.update(val);
    }
  }
  const computedDigest = new Uint8Array(h.digest());

  if (!safeEqual(computedDigest, expectedDigest)) {
    throw new Error('given PCRs digest not matching');
  }
}

/** Constant-time comparison of two byte arrays. */
function safeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/** Encode ECDSA R, S values as DER SEQUENCE { INTEGER R, INTEGER S }. */
function encodeECDSASignatureDER(r: Uint8Array, s: Uint8Array): Uint8Array {
  const rInt = derInteger(r);
  const sInt = derInteger(s);
  const seqContent = concatBytes([rInt, sInt]);
  const seqLen = derLength(seqContent.length);
  return concatBytes([new Uint8Array([0x30]), seqLen, seqContent]);
}

function derInteger(value: Uint8Array): Uint8Array {
  // Strip leading zeros
  let start = 0;
  while (start < value.length - 1 && value[start] === 0) start++;
  let bytes = value.slice(start);
  // Add leading zero if high bit set (positive integer)
  if (bytes[0] & 0x80) {
    const padded = new Uint8Array(bytes.length + 1);
    padded.set(bytes, 1);
    bytes = padded;
  }
  const len = derLength(bytes.length);
  return concatBytes([new Uint8Array([0x02]), len, bytes]);
}

function derLength(len: number): Uint8Array {
  if (len < 0x80) return new Uint8Array([len]);
  if (len < 0x100) return new Uint8Array([0x81, len]);
  return new Uint8Array([0x82, (len >> 8) & 0xff, len & 0xff]);
}

function concatBytes(arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}
