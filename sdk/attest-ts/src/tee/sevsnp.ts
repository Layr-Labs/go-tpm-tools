import crypto, { X509Certificate } from 'node:crypto';
import type { Report, Attestation as SevSnpAttestation, CertificateChain } from '../proto/sevsnp_pb.js';
import { reportToSignedBytes, reportSignatureToDER } from './sevsnp-abi.js';

/** Options for SEV-SNP attestation verification. */
export interface SevSnpVerifyOpts {
  /** Expected report data (64 bytes). */
  expectedReportData?: Uint8Array;
}

/**
 * Verify an AMD SEV-SNP attestation: field validation, ECDSA-P384-SHA384
 * signature verification against VCEK cert, and certificate chain validation.
 *
 * Port of go-sev-guest verify.SnpAttestation.
 *
 * @param attestation - Parsed sevsnp.Attestation protobuf (report + certificateChain)
 * @param opts - Verification options
 * @throws If any validation or verification fails
 */
export function verifySevSnpAttestation(
  attestation: SevSnpAttestation,
  opts?: SevSnpVerifyOpts,
): void {
  const report = attestation.report;
  if (!report) {
    throw new Error('SEV-SNP report is null');
  }

  // Basic field validation
  verifySevSnpReport(report, opts);

  // Signature verification requires certificate chain
  const chain = attestation.certificateChain;
  if (!chain) {
    throw new Error('SEV-SNP certificate chain is missing');
  }

  // Determine signing cert: VCEK or VLEK
  const signingCertDER = chain.vcekCert.length > 0 ? chain.vcekCert : chain.vlekCert;
  if (signingCertDER.length === 0) {
    throw new Error('SEV-SNP attestation has neither VCEK nor VLEK certificate');
  }

  // Verify report signature against signing cert
  const signedBytes = reportToSignedBytes(report);
  const sigDER = reportSignatureToDER(report);
  const signingCert = new X509Certificate(signingCertDER);

  const valid = crypto.verify('sha384', signedBytes, signingCert.publicKey, sigDER);
  if (!valid) {
    throw new Error('SEV-SNP report signature verification failed');
  }

  // Validate certificate chain: signing cert → ASK → ARK
  validateSevSnpCertChain(signingCert, chain);
}

/**
 * Verify basic SEV-SNP report fields without cryptographic signature check.
 * Kept for backward compatibility.
 */
export function verifySevSnpReport(
  report: Report,
  opts?: SevSnpVerifyOpts,
): void {
  if (!report) {
    throw new Error('SEV-SNP report is null');
  }

  if (report.version < 2) {
    throw new Error(`unexpected SEV-SNP report version: ${report.version}`);
  }

  if (opts?.expectedReportData) {
    if (report.reportData.length !== 64) {
      throw new Error(`unexpected report_data length: ${report.reportData.length}`);
    }
    if (!bytesEqual(report.reportData, opts.expectedReportData)) {
      throw new Error('SEV-SNP report_data does not match expected value');
    }
  }

  if (report.measurement.length !== 48) {
    throw new Error(`unexpected measurement length: ${report.measurement.length}`);
  }
}

/**
 * Validate the SEV-SNP certificate chain:
 *   Signing cert (VCEK/VLEK) → ASK → ARK
 *
 * Each certificate must be signed by the next certificate in the chain.
 * The ARK must be self-signed.
 */
function validateSevSnpCertChain(signingCert: X509Certificate, chain: CertificateChain): void {
  if (chain.askCert.length === 0) {
    throw new Error('SEV-SNP ASK certificate is missing');
  }
  if (chain.arkCert.length === 0) {
    throw new Error('SEV-SNP ARK certificate is missing');
  }

  const ask = new X509Certificate(chain.askCert);
  const ark = new X509Certificate(chain.arkCert);

  // Signing cert (VCEK/VLEK) must be signed by ASK
  if (!signingCert.verify(ask.publicKey)) {
    throw new Error('SEV-SNP signing certificate (VCEK/VLEK) not signed by ASK');
  }

  // ASK must be signed by ARK
  if (!ask.verify(ark.publicKey)) {
    throw new Error('SEV-SNP ASK not signed by ARK');
  }

  // ARK must be self-signed
  if (!ark.verify(ark.publicKey)) {
    throw new Error('SEV-SNP ARK is not self-signed');
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
