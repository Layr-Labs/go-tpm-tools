import { createPublicKey, type KeyObject } from 'node:crypto';
import { BufferReader } from './buffer-reader.js';
import { TpmAlg } from './constants.js';

/** Decoded TPMT_PUBLIC — the parsed public key area. */
export interface DecodedPublic {
  type: number;      // TPM_ALG_ID (RSA or ECC)
  nameAlg: number;   // Hash algorithm for name computation
  attributes: number; // TPMA_OBJECT
  authPolicy: Uint8Array;
  keyObject: KeyObject;
}

/**
 * Decode TPMT_PUBLIC from TPM wire format and convert to Node.js KeyObject.
 *
 * Binary layout:
 *   type:       uint16 (Algorithm — RSA or ECC)
 *   nameAlg:    uint16 (Algorithm)
 *   attributes: uint32 (TPMA_OBJECT)
 *   authPolicy: TPM2B (uint16 len + bytes)
 *   parameters: TPMU_PUBLIC_PARMS (union based on type)
 *   unique:     TPMU_PUBLIC_ID (union based on type)
 */
export function decodePublic(data: Uint8Array): DecodedPublic {
  const r = new BufferReader(data);

  const type = r.readUint16();
  const nameAlg = r.readUint16();
  const attributes = r.readUint32();
  const authPolicy = r.readSizedBuffer();

  let keyObject: KeyObject;

  switch (type) {
    case TpmAlg.RSA:
      keyObject = decodeRSAPublic(r);
      break;
    case TpmAlg.ECC:
      keyObject = decodeECCPublic(r);
      break;
    default:
      throw new Error(`unsupported public key type: 0x${type.toString(16)}`);
  }

  return { type, nameAlg, attributes, authPolicy, keyObject };
}

/**
 * Decode RSA public key parameters and convert to KeyObject.
 *
 * Parameters layout:
 *   symmetric:   TPMT_SYM_DEF_OBJECT (variable)
 *   scheme:      TPMT_RSA_SCHEME (variable)
 *   keyBits:     uint16
 *   exponent:    uint32 (0 = default 65537)
 * Unique layout:
 *   modulus:     TPM2B (uint16 len + bytes)
 */
function decodeRSAPublic(r: BufferReader): KeyObject {
  // Skip symmetric scheme
  skipSymScheme(r);
  // Skip signing scheme
  skipSigScheme(r);

  r.readUint16(); // keyBits — not needed for key reconstruction
  const exponentRaw = r.readUint32();
  const exponent = exponentRaw === 0 ? 65537 : exponentRaw;
  const modulus = r.readSizedBuffer();

  // Build DER-encoded RSAPublicKey in PKCS#1 format, then wrap in SubjectPublicKeyInfo
  const modulusInt = asn1Integer(modulus);
  const exponentInt = asn1Integer(exponentToBytes(exponent));
  const rsaPublicKey = asn1Sequence([modulusInt, exponentInt]);

  // SubjectPublicKeyInfo wrapping
  const algorithmIdentifier = asn1Sequence([
    // OID 1.2.840.113549.1.1.1 (rsaEncryption)
    new Uint8Array([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]),
    // NULL parameters
    new Uint8Array([0x05, 0x00]),
  ]);
  const bitString = asn1BitString(rsaPublicKey);
  const spki = asn1Sequence([algorithmIdentifier, bitString]);

  return createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' });
}

/** ECC curve OID mapping. */
const eccCurveOids: Record<number, Uint8Array> = {
  // TPM ECC curve IDs to OID bytes
  0x0003: new Uint8Array([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]), // NIST P-256
  0x0004: new Uint8Array([0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]),                     // NIST P-384
  0x0005: new Uint8Array([0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23]),                     // NIST P-521
};

const eccCurvePointSizes: Record<number, number> = {
  0x0003: 32,  // P-256
  0x0004: 48,  // P-384
  0x0005: 66,  // P-521
};

/**
 * Decode ECC public key parameters and convert to KeyObject.
 *
 * Parameters layout:
 *   symmetric:  TPMT_SYM_DEF_OBJECT (variable)
 *   scheme:     TPMT_ECC_SCHEME (variable)
 *   curveID:    uint16
 *   kdfScheme:  TPMT_KDF_SCHEME (variable)
 * Unique layout:
 *   x:          TPM2B (uint16 len + bytes)
 *   y:          TPM2B (uint16 len + bytes)
 */
function decodeECCPublic(r: BufferReader): KeyObject {
  skipSymScheme(r);
  skipSigScheme(r);

  const curveID = r.readUint16();
  skipKdfScheme(r);

  const x = r.readSizedBuffer();
  const y = r.readSizedBuffer();

  const curveOid = eccCurveOids[curveID];
  if (!curveOid) {
    throw new Error(`unsupported ECC curve: 0x${curveID.toString(16)}`);
  }
  const pointSize = eccCurvePointSizes[curveID]!;

  // Uncompressed point: 0x04 || x (padded) || y (padded)
  const point = new Uint8Array(1 + pointSize * 2);
  point[0] = 0x04;
  point.set(padLeft(x, pointSize), 1);
  point.set(padLeft(y, pointSize), 1 + pointSize);

  // SubjectPublicKeyInfo for EC
  const algorithmIdentifier = asn1Sequence([
    // OID 1.2.840.10045.2.1 (ecPublicKey)
    new Uint8Array([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
    curveOid,
  ]);
  const bitString = asn1BitString(point);
  const spki = asn1Sequence([algorithmIdentifier, bitString]);

  return createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' });
}

// --- TPM scheme skipping helpers ---

function skipSymScheme(r: BufferReader): void {
  const alg = r.readUint16();
  if (alg !== TpmAlg.Null) {
    r.readUint16(); // keyBits
    r.readUint16(); // mode
  }
}

function skipSigScheme(r: BufferReader): void {
  const alg = r.readUint16();
  if (alg !== TpmAlg.Null) {
    r.readUint16(); // hash
  }
}

function skipKdfScheme(r: BufferReader): void {
  const alg = r.readUint16();
  if (alg !== TpmAlg.Null) {
    r.readUint16(); // hash
  }
}

// --- ASN.1 DER encoding helpers ---

function asn1Length(len: number): Uint8Array {
  if (len < 0x80) {
    return new Uint8Array([len]);
  } else if (len < 0x100) {
    return new Uint8Array([0x81, len]);
  } else if (len < 0x10000) {
    return new Uint8Array([0x82, (len >> 8) & 0xff, len & 0xff]);
  }
  throw new Error(`ASN.1 length too large: ${len}`);
}

function asn1Sequence(items: Uint8Array[]): Uint8Array {
  const content = concatBytes(items);
  const len = asn1Length(content.length);
  return concatBytes([new Uint8Array([0x30]), len, content]);
}

function asn1Integer(value: Uint8Array): Uint8Array {
  // Ensure positive integer (prepend 0x00 if high bit set)
  let bytes = value;
  if (bytes.length > 0 && bytes[0] & 0x80) {
    const padded = new Uint8Array(bytes.length + 1);
    padded.set(bytes, 1);
    bytes = padded;
  }
  // Strip leading zeros (except keep at least one byte, and keep padding byte)
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0 && !(bytes[start + 1] & 0x80)) {
    start++;
  }
  bytes = bytes.slice(start);

  const len = asn1Length(bytes.length);
  return concatBytes([new Uint8Array([0x02]), len, bytes]);
}

function asn1BitString(content: Uint8Array): Uint8Array {
  // 0x00 = no unused bits in last byte
  const len = asn1Length(content.length + 1);
  return concatBytes([new Uint8Array([0x03]), len, new Uint8Array([0x00]), content]);
}

function concatBytes(arrays: Uint8Array[]): Uint8Array {
  const totalLen = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

function exponentToBytes(exp: number): Uint8Array {
  const buf = new Uint8Array(4);
  buf[0] = (exp >> 24) & 0xff;
  buf[1] = (exp >> 16) & 0xff;
  buf[2] = (exp >> 8) & 0xff;
  buf[3] = exp & 0xff;
  // Strip leading zeros
  let start = 0;
  while (start < buf.length - 1 && buf[start] === 0) start++;
  return buf.slice(start);
}

function padLeft(data: Uint8Array, size: number): Uint8Array {
  if (data.length >= size) return data.slice(data.length - size);
  const padded = new Uint8Array(size);
  padded.set(data, size - data.length);
  return padded;
}
