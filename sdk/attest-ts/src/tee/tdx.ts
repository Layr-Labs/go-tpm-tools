import { verifyTdx, parseTdxQuote, type VerifyConfig, type TdxQuote } from '@teekit/qvl';

export { type TdxQuote };

/** Options for TDX quote verification. */
export interface TDXVerifyOpts {
  /** CRL (Certificate Revocation List) data for checking revoked certs. */
  crls?: Uint8Array[];
  /** Expected report data (64 bytes) — if set, must match the quote. */
  expectedReportData?: Uint8Array;
  /** Override the verification time (ms since epoch). */
  verifyAtTimeMs?: number;
}

/**
 * Verify a TDX attestation quote using @teekit/qvl.
 *
 * Validates the full chain of trust:
 * Intel SGX Root CA → PCK cert chain → QE signature → quote signature
 *
 * @param quoteBytes - Raw TDX quote bytes (as returned by the TDX device)
 * @param opts - Optional verification parameters
 * @throws If quote verification fails
 */
export async function verifyTDXQuote(
  quoteBytes: Uint8Array,
  opts?: TDXVerifyOpts,
): Promise<TdxQuote> {
  const config: Partial<VerifyConfig> = {};

  if (opts?.crls) {
    config.crls = opts.crls;
  }

  if (opts?.verifyAtTimeMs !== undefined) {
    config.date = opts.verifyAtTimeMs;
  }

  if (opts?.expectedReportData) {
    const reportDataHex = Buffer.from(opts.expectedReportData).toString('hex');
    config.verifyMeasurements = { reportData: reportDataHex };
  }

  const valid = await verifyTdx(quoteBytes, config as VerifyConfig);
  if (!valid) {
    throw new Error('TDX quote verification failed');
  }

  return parseTdxQuote(quoteBytes);
}

/**
 * Parse a TDX quote without full verification.
 * Useful for extracting measurements and report data for inspection.
 */
export function parseTDXQuote(quoteBytes: Uint8Array): TdxQuote {
  return parseTdxQuote(quoteBytes);
}
