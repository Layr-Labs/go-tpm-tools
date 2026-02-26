/**
 * TDX Quote V4 ABI binary reconstruction.
 *
 * Converts a parsed QuoteV4 protobuf back into Intel DCAP raw bytes
 * suitable for verification by @teekit/qvl.
 *
 * Port of go-tdx-guest/abi/abi.go (QuoteToAbiBytes, HeaderToAbiBytes, etc.)
 *
 * All multi-byte integers are little-endian. Byte-array fields are raw bytes.
 */

import type {
  QuoteV4,
  Header,
  TDQuoteBody,
  EnclaveReport,
  Ecdsa256BitQuoteV4AuthData,
} from '../proto/tdx_pb.js';

// --- Size constants (from go-tdx-guest/abi/abi.go) ---

const HEADER_SIZE = 0x30;           // 48 bytes
const TD_QUOTE_BODY_SIZE = 0x248;   // 584 bytes
const ENCLAVE_REPORT_SIZE = 0x180;  // 384 bytes
const SIGNATURE_SIZE = 0x40;        // 64 bytes
const ATTESTATION_KEY_SIZE = 0x40;  // 64 bytes
const RTMR_COUNT = 4;
const RTMR_SIZE = 0x30;            // 48 bytes

/**
 * Serialize a TDX QuoteV4 Header to 48-byte binary.
 *
 * Layout:
 *   version(2) + attestationKeyType(2) + teeType(4) + pceSvn(2) + qeSvn(2) +
 *   qeVendorId(16) + userData(20) = 48 bytes
 */
export function headerToBytes(header: Header): Uint8Array {
  const buf = new Uint8Array(HEADER_SIZE);
  const view = new DataView(buf.buffer);

  view.setUint16(0x00, header.version, true);
  view.setUint16(0x02, header.attestationKeyType, true);
  view.setUint32(0x04, header.teeType, true);
  copyFixed(buf, 0x08, header.pceSvn, 2);
  copyFixed(buf, 0x0a, header.qeSvn, 2);
  copyFixed(buf, 0x0c, header.qeVendorId, 16);
  copyFixed(buf, 0x1c, header.userData, 20);

  return buf;
}

/**
 * Serialize a TDQuoteBody to 584-byte binary.
 *
 * Layout:
 *   teeTcbSvn(16) + mrSeam(48) + mrSignerSeam(48) + seamAttributes(8) +
 *   tdAttributes(8) + xfam(8) + mrTd(48) + mrConfigId(48) + mrOwner(48) +
 *   mrOwnerConfig(48) + rtmrs(4×48) + reportData(64) = 584 bytes
 */
export function tdQuoteBodyToBytes(body: TDQuoteBody): Uint8Array {
  const buf = new Uint8Array(TD_QUOTE_BODY_SIZE);
  let offset = 0;

  const fields: [Uint8Array, number][] = [
    [body.teeTcbSvn, 16],
    [body.mrSeam, 48],
    [body.mrSignerSeam, 48],
    [body.seamAttributes, 8],
    [body.tdAttributes, 8],
    [body.xfam, 8],
    [body.mrTd, 48],
    [body.mrConfigId, 48],
    [body.mrOwner, 48],
    [body.mrOwnerConfig, 48],
  ];

  for (const [data, size] of fields) {
    copyFixed(buf, offset, data, size);
    offset += size;
  }

  // RTMRs: 4 × 48 bytes
  if (body.rtmrs.length !== RTMR_COUNT) {
    throw new Error(`expected ${RTMR_COUNT} RTMRs, got ${body.rtmrs.length}`);
  }
  for (let i = 0; i < RTMR_COUNT; i++) {
    copyFixed(buf, offset, body.rtmrs[i], RTMR_SIZE);
    offset += RTMR_SIZE;
  }

  // ReportData: 64 bytes
  copyFixed(buf, offset, body.reportData, 64);

  return buf;
}

/**
 * Serialize an EnclaveReport (QE Report) to 384-byte binary.
 *
 * Layout:
 *   cpuSvn(16) + miscSelect(4) + reserved1(28) + attributes(16) +
 *   mrEnclave(32) + reserved2(32) + mrSigner(32) + reserved3(96) +
 *   isvProdId(2) + isvSvn(2) + reserved4(60) + reportData(64) = 384 bytes
 */
export function enclaveReportToBytes(report: EnclaveReport): Uint8Array {
  const buf = new Uint8Array(ENCLAVE_REPORT_SIZE);
  const view = new DataView(buf.buffer);

  copyFixed(buf, 0x000, report.cpuSvn, 16);
  view.setUint32(0x010, report.miscSelect, true);
  copyFixed(buf, 0x014, report.reserved1, 28);
  copyFixed(buf, 0x030, report.attributes, 16);
  copyFixed(buf, 0x040, report.mrEnclave, 32);
  copyFixed(buf, 0x060, report.reserved2, 32);
  copyFixed(buf, 0x080, report.mrSigner, 32);
  copyFixed(buf, 0x0a0, report.reserved3, 96);
  view.setUint16(0x100, report.isvProdId, true);
  view.setUint16(0x102, report.isvSvn, true);
  copyFixed(buf, 0x104, report.reserved4, 60);
  copyFixed(buf, 0x140, report.reportData, 64);

  return buf;
}

/**
 * Serialize ECDSA256BitQuoteV4AuthData to binary.
 *
 * Variable-length layout:
 *   signature(64) + ecdsaAttestationKey(64) +
 *   certType(2) + certSize(4) +
 *   qeReport(384) + qeReportSignature(64) +
 *   qeAuthSize(2) + qeAuth(var) +
 *   pckChainType(2) + pckChainSize(4) + pckChain(var)
 */
export function authDataToBytes(authData: Ecdsa256BitQuoteV4AuthData): Uint8Array {
  const certData = authData.certificationData;
  if (!certData) {
    throw new Error('missing certification data in auth data');
  }

  const qeReportCertData = certData.qeReportCertificationData;
  if (!qeReportCertData) {
    throw new Error('missing QE report certification data');
  }

  const qeReport = qeReportCertData.qeReport;
  if (!qeReport) {
    throw new Error('missing QE report');
  }

  const qeAuthData = qeReportCertData.qeAuthData;
  const qeAuth = qeAuthData?.data ?? new Uint8Array(0);
  const qeAuthSize = qeAuth.length;

  const pckChainData = qeReportCertData.pckCertificateChainData;
  const pckChain = pckChainData?.pckCertChain ?? new Uint8Array(0);
  const pckChainSize = pckChain.length;

  // Calculate total size
  const qeReportCertBytes = ENCLAVE_REPORT_SIZE + SIGNATURE_SIZE + 2 + qeAuthSize + 2 + 4 + pckChainSize;
  const totalSize = SIGNATURE_SIZE + ATTESTATION_KEY_SIZE + 2 + 4 + qeReportCertBytes;

  const buf = new Uint8Array(totalSize);
  const view = new DataView(buf.buffer);
  let offset = 0;

  // Signature (64 bytes)
  copyFixed(buf, offset, authData.signature, SIGNATURE_SIZE);
  offset += SIGNATURE_SIZE;

  // ECDSA Attestation Key (64 bytes)
  copyFixed(buf, offset, authData.ecdsaAttestationKey, ATTESTATION_KEY_SIZE);
  offset += ATTESTATION_KEY_SIZE;

  // CertificationData header: type (2) + size (4)
  view.setUint16(offset, certData.certificateDataType, true);
  offset += 2;
  view.setUint32(offset, qeReportCertBytes, true);
  offset += 4;

  // QE Report (384 bytes)
  const qeReportBytes = enclaveReportToBytes(qeReport);
  buf.set(qeReportBytes, offset);
  offset += ENCLAVE_REPORT_SIZE;

  // QE Report Signature (64 bytes)
  copyFixed(buf, offset, qeReportCertData.qeReportSignature, SIGNATURE_SIZE);
  offset += SIGNATURE_SIZE;

  // QE Auth Data: size (2) + data (var)
  view.setUint16(offset, qeAuthSize, true);
  offset += 2;
  if (qeAuthSize > 0) {
    buf.set(qeAuth, offset);
    offset += qeAuthSize;
  }

  // PCK Certificate Chain Data: type (2) + size (4) + chain (var)
  view.setUint16(offset, pckChainData?.certificateDataType ?? 5, true);
  offset += 2;
  view.setUint32(offset, pckChainSize, true);
  offset += 4;
  if (pckChainSize > 0) {
    buf.set(pckChain, offset);
  }

  return buf;
}

/**
 * Reconstruct the full Intel DCAP binary quote from a QuoteV4 proto.
 *
 * Layout:
 *   header(48) + tdQuoteBody(584) + signedDataSize(4) + signedData(var) + extraBytes(var)
 */
export function quoteV4ToBytes(quote: QuoteV4): Uint8Array {
  if (!quote.header) throw new Error('missing quote header');
  if (!quote.tdQuoteBody) throw new Error('missing TD quote body');
  if (!quote.signedData) throw new Error('missing signed data');

  const headerBytes = headerToBytes(quote.header);
  const bodyBytes = tdQuoteBodyToBytes(quote.tdQuoteBody);
  const authBytes = authDataToBytes(quote.signedData);
  const extraBytes = quote.extraBytes;

  const totalSize = HEADER_SIZE + TD_QUOTE_BODY_SIZE + 4 + authBytes.length + extraBytes.length;
  const buf = new Uint8Array(totalSize);
  const view = new DataView(buf.buffer);
  let offset = 0;

  buf.set(headerBytes, offset);
  offset += HEADER_SIZE;

  buf.set(bodyBytes, offset);
  offset += TD_QUOTE_BODY_SIZE;

  view.setUint32(offset, authBytes.length, true);
  offset += 4;

  buf.set(authBytes, offset);
  offset += authBytes.length;

  if (extraBytes.length > 0) {
    buf.set(extraBytes, offset);
  }

  return buf;
}

// --- Helpers ---

/** Copy src into dst at offset, zero-padding or truncating to exactly `size` bytes. */
function copyFixed(dst: Uint8Array, offset: number, src: Uint8Array, size: number): void {
  const toCopy = Math.min(src.length, size);
  dst.set(src.subarray(0, toCopy), offset);
  // Remaining bytes are already zero from Uint8Array initialization
}
