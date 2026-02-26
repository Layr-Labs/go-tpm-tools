/**
 * SEV-SNP Attestation Report ABI binary reconstruction.
 *
 * Converts a parsed Report protobuf back into the AMD binary format
 * for signature verification.
 *
 * Port of go-sev-guest/abi/abi.go (ReportToAbiBytes, SignedComponent, ReportToSignatureDER)
 *
 * All multi-byte integers are little-endian.
 */

import type { Report } from '../proto/sevsnp_pb.js';

// --- Size constants (from go-sev-guest/abi/abi.go) ---

const REPORT_SIZE = 0x4a0;        // 1184 bytes total
const SIGNATURE_OFFSET = 0x2a0;   // 672 bytes: signed region ends here
const ECDSA_RS_SIZE = 72;         // Each R/S component in AMD format

/**
 * Reconstruct the signed component of a SEV-SNP report (first 672 bytes).
 * This is the data that AMD-SP signs with ECDSA-P384-SHA384.
 *
 * Layout (672 bytes / 0x2A0):
 *   version(4) + guestSvn(4) + policy(8) + familyId(16) + imageId(16) +
 *   vmpl(4) + signatureAlgo(4) + currentTcb(8) + platformInfo(8) +
 *   signerInfo(4) + reserved(4) + reportData(64) + measurement(48) +
 *   hostData(32) + idKeyDigest(48) + authorKeyDigest(48) + reportId(32) +
 *   reportIdMa(32) + reportedTcb(8) + chipId(64) + committedTcb(8) +
 *   currentBuild(1) + currentMinor(1) + currentMajor(1) + reserved(1) +
 *   committedBuild(1) + committedMinor(1) + committedMajor(1) + reserved(1) +
 *   launchTcb(8) + launchMitVector(8) + currentMitVector(8) + reserved(0x98)
 *   = 0x2A0 bytes
 */
export function reportToSignedBytes(report: Report): Uint8Array {
  const buf = new Uint8Array(SIGNATURE_OFFSET);
  const view = new DataView(buf.buffer);

  view.setUint32(0x000, report.version, true);
  view.setUint32(0x004, report.guestSvn, true);
  setBigUint64LE(view, 0x008, report.policy);
  copyFixed(buf, 0x010, report.familyId, 16);
  copyFixed(buf, 0x020, report.imageId, 16);
  view.setUint32(0x030, report.vmpl, true);
  view.setUint32(0x034, report.signatureAlgo, true);
  setBigUint64LE(view, 0x038, report.currentTcb);
  setBigUint64LE(view, 0x040, report.platformInfo);
  view.setUint32(0x048, report.signerInfo, true);
  // 0x04C: 4 bytes reserved (zeros)
  copyFixed(buf, 0x050, report.reportData, 64);
  copyFixed(buf, 0x090, report.measurement, 48);
  copyFixed(buf, 0x0c0, report.hostData, 32);
  copyFixed(buf, 0x0e0, report.idKeyDigest, 48);
  copyFixed(buf, 0x110, report.authorKeyDigest, 48);
  copyFixed(buf, 0x140, report.reportId, 32);
  copyFixed(buf, 0x160, report.reportIdMa, 32);
  setBigUint64LE(view, 0x180, report.reportedTcb);

  // 0x188: cpuid1eax_fms — proto stores as uint32 (CPUID EAX value),
  // but binary format stores decomposed family/model/stepping bytes.
  // For v2, the whole region 0x188..0x1A0 is reserved (zeros).
  if (report.version >= 3) {
    const [family, model, stepping] = fmsFromCpuid1Eax(report.cpuid1eaxFms);
    buf[0x188] = family;
    buf[0x189] = model;
    buf[0x18a] = stepping;
  }
  // 0x18B..0x1A0: reserved (zeros)

  copyFixed(buf, 0x1a0, report.chipId, 64);
  setBigUint64LE(view, 0x1e0, report.committedTcb);

  buf[0x1e8] = report.currentBuild;
  buf[0x1e9] = report.currentMinor;
  buf[0x1ea] = report.currentMajor;
  // 0x1EB: 1 byte reserved
  buf[0x1ec] = report.committedBuild;
  buf[0x1ed] = report.committedMinor;
  buf[0x1ee] = report.committedMajor;
  // 0x1EF: 1 byte reserved

  setBigUint64LE(view, 0x1f0, report.launchTcb);
  setBigUint64LE(view, 0x1f8, report.launchMitVector);
  setBigUint64LE(view, 0x200, report.currentMitVector);
  // 0x208..0x2A0: 0x98 bytes reserved (zeros)

  return buf;
}

/**
 * Convert the AMD little-endian ECDSA-P384 signature from a SEV-SNP report
 * into ASN.1 DER format suitable for Node.js crypto.verify().
 *
 * AMD stores R and S as 72-byte little-endian integers.
 * Standard crypto expects big-endian ASN.1 DER: SEQUENCE { INTEGER R, INTEGER S }.
 */
export function reportSignatureToDER(report: Report): Uint8Array {
  const sig = report.signature;
  if (sig.length < ECDSA_RS_SIZE * 2) {
    throw new Error(`SEV-SNP signature too short: ${sig.length} bytes, need at least ${ECDSA_RS_SIZE * 2}`);
  }

  // Extract R and S (72 bytes each, AMD little-endian)
  const rLE = sig.subarray(0, ECDSA_RS_SIZE);
  const sLE = sig.subarray(ECDSA_RS_SIZE, ECDSA_RS_SIZE * 2);

  // Reverse to big-endian and strip leading zeros
  const rBE = stripLeadingZeros(reverseBytes(rLE));
  const sBE = stripLeadingZeros(reverseBytes(sLE));

  // Encode as ASN.1 DER
  return encodeECDSASignatureDER(rBE, sBE);
}

/**
 * Reconstruct the full 1184-byte report binary from proto fields.
 * Useful for complete round-trip testing.
 */
export function reportToAbiBytes(report: Report): Uint8Array {
  const buf = new Uint8Array(REPORT_SIZE);

  // Copy signed component (first 672 bytes)
  const signed = reportToSignedBytes(report);
  buf.set(signed, 0);

  // Copy signature (512 bytes at offset 0x2A0)
  copyFixed(buf, SIGNATURE_OFFSET, report.signature, REPORT_SIZE - SIGNATURE_OFFSET);

  return buf;
}

// --- CPUID decomposition (port of go-sev-guest/abi FmsFromCpuid1Eax) ---

/**
 * Decompose a CPUID(1).EAX value into family, model, stepping bytes.
 * The binary ABI format stores these as 3 individual bytes, not the raw EAX value.
 */
function fmsFromCpuid1Eax(eax: number): [number, number, number] {
  const extendedFamily = (eax >>> 20) & 0xff;  // bits 27:20
  const extendedModel = (eax >>> 16) & 0xf;    // bits 19:16
  const familyID = (eax >>> 8) & 0xf;          // bits 11:8
  const modelID = (eax >>> 4) & 0xf;           // bits 7:4
  const stepping = eax & 0xf;                  // bits 3:0

  const family = extendedFamily + familyID;
  const model = (extendedModel << 4) | modelID;
  return [family, model, stepping];
}

// --- Internal helpers ---

function reverseBytes(src: Uint8Array): Uint8Array {
  const out = new Uint8Array(src.length);
  for (let i = 0; i < src.length; i++) {
    out[i] = src[src.length - 1 - i];
  }
  return out;
}

function stripLeadingZeros(data: Uint8Array): Uint8Array {
  let i = 0;
  while (i < data.length - 1 && data[i] === 0) {
    i++;
  }
  return data.subarray(i);
}

/**
 * Encode two big-endian unsigned integers as an ASN.1 DER ECDSA signature:
 * SEQUENCE { INTEGER r, INTEGER s }
 */
function encodeECDSASignatureDER(r: Uint8Array, s: Uint8Array): Uint8Array {
  const rDER = encodeASN1Integer(r);
  const sDER = encodeASN1Integer(s);
  const seqLen = rDER.length + sDER.length;
  const seqHeader = encodeDERLength(seqLen);

  const result = new Uint8Array(1 + seqHeader.length + seqLen);
  let offset = 0;
  result[offset++] = 0x30; // SEQUENCE tag
  result.set(seqHeader, offset);
  offset += seqHeader.length;
  result.set(rDER, offset);
  offset += rDER.length;
  result.set(sDER, offset);

  return result;
}

/** Encode a big-endian unsigned integer as ASN.1 DER INTEGER. */
function encodeASN1Integer(value: Uint8Array): Uint8Array {
  // If high bit is set, prepend a 0x00 byte to keep it positive
  const needsPad = value[0] >= 0x80;
  const intLen = value.length + (needsPad ? 1 : 0);
  const lenBytes = encodeDERLength(intLen);

  const result = new Uint8Array(1 + lenBytes.length + intLen);
  let offset = 0;
  result[offset++] = 0x02; // INTEGER tag
  result.set(lenBytes, offset);
  offset += lenBytes.length;
  if (needsPad) {
    result[offset++] = 0x00;
  }
  result.set(value, offset);

  return result;
}

/** Encode a DER length value. */
function encodeDERLength(length: number): Uint8Array {
  if (length < 0x80) {
    return new Uint8Array([length]);
  }
  if (length < 0x100) {
    return new Uint8Array([0x81, length]);
  }
  return new Uint8Array([0x82, (length >> 8) & 0xff, length & 0xff]);
}

/** Copy src into dst at offset, zero-padding or truncating to exactly `size` bytes. */
function copyFixed(dst: Uint8Array, offset: number, src: Uint8Array, size: number): void {
  const toCopy = Math.min(src.length, size);
  dst.set(src.subarray(0, toCopy), offset);
}

/** Write a BigInt as a little-endian uint64 at the given DataView offset. */
function setBigUint64LE(view: DataView, offset: number, value: bigint): void {
  view.setBigUint64(offset, value, true);
}
