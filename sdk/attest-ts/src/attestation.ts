import { X509Certificate } from 'node:crypto';
import { fromBinary } from '@bufbuild/protobuf';
import {
  type Attestation as AttestationProto,
  AttestationSchema,
  RestartPolicy,
} from './proto/layr_attest_pb.js';
import { HashAlgo } from './proto/layr_tpm_pb.js';
import { Platform, platformTag } from './types.js';
import type {
  ParsedAttestation,
  VerifiedTPMAttestation,
  VerifiedTEEAttestation,
  ContainerInfo,
} from './types.js';
import { computeTPMNonce, computeBoundNonce } from './nonce.js';
import { decodeAttestationData } from './tpm/decode-attestation.js';
import { decodePublic } from './tpm/decode-public.js';
import { verifyAttestation } from './server/verify.js';
import { ALL_ROOTS, ALL_INTERMEDIATES } from './server/ak-certs.js';
import {
  parseCosCELPCR,
  parseCosCELRTMR,
  type RegisterBank,
} from './server/eventlog.js';
import { TpmAlg } from './tpm/constants.js';
import { quoteV4ToBytes } from './tee/tdx-abi.js';
import { verifyTDXQuote } from './tee/tdx.js';
import { verifySevSnpAttestation } from './tee/sevsnp.js';

const TEE_REPORT_DATA_SIZE = 64;

/**
 * Parse raw attestation bytes into a ParsedAttestation.
 * Deserializes the protobuf and detects the platform (TDX, SEV-SNP, or Shielded VM).
 *
 * Port of attest.Parse from Go.
 */
export function parse(attestationBytes: Uint8Array): ParsedAttestation {
  const proto = fromBinary(AttestationSchema, attestationBytes);
  const platform = detectPlatform(proto);

  if (platform === Platform.Unknown) {
    throw new Error('unknown platform: no TEE or Shielded VM attestation found');
  }

  return { platform, proto };
}

/**
 * Verify the TPM layer: AK cert chain, PCR quotes, event log, and
 * TPM nonce (which includes the platform tag for anti-downgrade protection).
 *
 * Port of Attestation.VerifyTPM from Go.
 */
export async function verifyTPM(
  parsed: ParsedAttestation,
  challenge: Uint8Array,
  extraData?: Uint8Array,
): Promise<VerifiedTPMAttestation> {
  const { platform, proto: attestation } = parsed;

  // Compute expected TPM nonce with platform tag
  const tpmNonce = computeTPMNonce(challenge, platformTag(platform), extraData);

  // Quick check: decode the first quote to verify nonce match before full verification
  const quotes = attestation.quotes;
  if (quotes.length === 0) {
    throw new Error('no TPM quotes in attestation');
  }
  const quoteInfo = decodeAttestationData(quotes[0].quote);
  if (!bytesEqual(quoteInfo.extraData, tpmNonce)) {
    throw new Error('TPM nonce mismatch: quote contains different nonce than expected');
  }

  // Full TPM attestation verification
  const machineState = await verifyAttestation(attestation, {
    nonce: tpmNonce,
    trustedRootCerts: ALL_ROOTS,
    intermediateCerts: ALL_INTERMEDIATES,
  });

  return {
    platform,
    extraData: extraData ?? new Uint8Array(0),
    proto: attestation,
    machineState,
  };
}

/**
 * Verify the TEE layer: TEE quote signature and binding to TPM's AK.
 * Only valid for TDX and SEV-SNP platforms.
 *
 * Port of Attestation.VerifyBoundTEE from Go.
 */
export async function verifyBoundTEE(
  parsed: ParsedAttestation,
  challenge: Uint8Array,
  extraData?: Uint8Array,
): Promise<VerifiedTEEAttestation> {
  const { platform, proto: attestation } = parsed;

  if (platform !== Platform.IntelTDX && platform !== Platform.AMDSevSnp) {
    throw new Error(`TEE verification not available for platform ${platformTag(platform)}`);
  }

  // Extract AK public key DER for binding verification
  const akPubDER = extractAKPubDER(attestation);

  // Verify binding: ReportData == ComputeBoundNonce(challenge, akPubDER, extraData)
  const boundNonce = computeBoundNonce(challenge, akPubDER, extraData);
  verifyBinding(attestation, boundNonce, platform);

  // TEE quote signature verification
  switch (platform) {
    case Platform.IntelTDX: {
      if (attestation.teeAttestation.case !== 'tdxAttestation') {
        throw new Error('TDX attestation missing');
      }
      const rawBytes = quoteV4ToBytes(attestation.teeAttestation.value);
      await verifyTDXQuote(rawBytes);
      break;
    }
    case Platform.AMDSevSnp: {
      if (attestation.teeAttestation.case !== 'sevSnpAttestation') {
        throw new Error('SEV-SNP attestation missing');
      }
      verifySevSnpAttestation(attestation.teeAttestation.value);
      break;
    }
  }

  return {
    platform,
    extraData: extraData ?? new Uint8Array(0),
    proto: attestation,
  };
}

/**
 * Extract container claims from the canonical event log (COS CEL).
 * On TDX, the CEL is replayed against hardware RTMRs (SHA-384).
 * On SEV-SNP and Shielded VM, it is replayed against vTPM PCRs (SHA-256).
 *
 * Port of Attestation.ExtractContainerClaims from Go.
 */
export function extractContainerClaims(parsed: ParsedAttestation): ContainerInfo {
  const { platform, proto: attestation } = parsed;

  const cel = attestation.canonicalEventLog;
  if (cel.length === 0) {
    throw new Error('no canonical event log in attestation');
  }

  let cosState;
  if (platform === Platform.IntelTDX) {
    const rtmrBank = extractRTMRBank(attestation);
    cosState = parseCosCELRTMR(cel, rtmrBank);
  } else {
    const pcrBank = extractPCRBankFromQuotes(attestation, HashAlgo.SHA256);
    cosState = parseCosCELPCR(cel, pcrBank);
  }

  const container = cosState.container;
  if (!container) {
    throw new Error('canonical event log contains no container events');
  }

  return {
    imageReference: container.imageReference,
    imageDigest: container.imageDigest,
    imageId: container.imageId,
    restartPolicy: RestartPolicy[container.restartPolicy] ?? 'Unknown',
    args: container.args,
    envVars: container.envVars,
  };
}

// --- Internal helpers ---

function detectPlatform(attestation: AttestationProto): Platform {
  if (attestation.teeAttestation.case === 'tdxAttestation') {
    return Platform.IntelTDX;
  }
  if (attestation.teeAttestation.case === 'sevSnpAttestation') {
    return Platform.AMDSevSnp;
  }
  if (attestation.quotes.length > 0 && attestation.akCert.length > 0) {
    return Platform.GCPShieldedVM;
  }
  return Platform.Unknown;
}

function getReportData(attestation: AttestationProto, platform: Platform): Uint8Array | undefined {
  switch (platform) {
    case Platform.IntelTDX:
      return attestation.teeAttestation.case === 'tdxAttestation'
        ? attestation.teeAttestation.value.tdQuoteBody?.reportData
        : undefined;
    case Platform.AMDSevSnp:
      return attestation.teeAttestation.case === 'sevSnpAttestation'
        ? attestation.teeAttestation.value.report?.reportData
        : undefined;
    default:
      return undefined;
  }
}

/**
 * Extract and validate AK public key in SPKI DER format.
 * Parses the AK certificate, validates expiry, and extracts the public key.
 */
function extractAKPubDER(attestation: AttestationProto): Uint8Array {
  const akCertDER = attestation.akCert;
  if (akCertDER.length === 0) {
    throw new Error('no AK certificate in attestation');
  }

  const akCert = new X509Certificate(akCertDER);

  // Check validity window
  const now = new Date();
  if (now < new Date(akCert.validFrom)) {
    throw new Error(`AK certificate not yet valid (validFrom: ${akCert.validFrom})`);
  }
  if (now > new Date(akCert.validTo)) {
    throw new Error(`AK certificate expired (validTo: ${akCert.validTo})`);
  }

  // Export public key as SPKI DER
  const akPubDER = akCert.publicKey.export({ type: 'spki', format: 'der' });

  // Verify ak_pub field exists and matches the certificate
  if (attestation.akPub.length === 0) {
    throw new Error('no AK public key in attestation');
  }
  const decoded = decodePublic(attestation.akPub);
  const akPubFromTPM = decoded.keyObject.export({ type: 'spki', format: 'der' });

  if (!Buffer.from(akPubDER).equals(Buffer.from(akPubFromTPM))) {
    throw new Error('AK certificate public key does not match attestation ak_pub field');
  }

  return new Uint8Array(akPubDER);
}

/**
 * Verify that ReportData matches the expected bound nonce (full 64 bytes).
 */
function verifyBinding(attestation: AttestationProto, expectedBoundNonce: Uint8Array, platform: Platform): void {
  const reportData = getReportData(attestation, platform);

  if (!reportData || reportData.length !== TEE_REPORT_DATA_SIZE) {
    throw new Error(`report data length mismatch: got ${reportData?.length ?? 0} bytes, want ${TEE_REPORT_DATA_SIZE}`);
  }

  if (!bytesEqual(reportData, expectedBoundNonce)) {
    throw new Error('binding mismatch: ReportData does not match expected bound nonce');
  }
}

/** Build an RTMR register bank from the TDX quote body. */
function extractRTMRBank(attestation: AttestationProto): RegisterBank {
  if (attestation.teeAttestation.case !== 'tdxAttestation') {
    throw new Error('not a TDX attestation');
  }
  const rtmrs = attestation.teeAttestation.value.tdQuoteBody?.rtmrs;
  if (!rtmrs || rtmrs.length !== 4) {
    throw new Error(`expected 4 RTMRs, got ${rtmrs?.length ?? 0}`);
  }

  // CCMR index mapping: RTMR[0]→1, RTMR[1]→2, RTMR[2]→3, RTMR[3]→4
  const registers = new Map<number, Uint8Array>();
  for (let i = 0; i < 4; i++) {
    registers.set(i + 1, rtmrs[i]);
  }
  return { hashAlg: TpmAlg.SHA384, registers };
}

/** Find the PCR bank matching the given hash algo from quotes. */
function extractPCRBankFromQuotes(attestation: AttestationProto, hashAlgo: HashAlgo): RegisterBank {
  for (const quote of attestation.quotes) {
    const pcrs = quote.pcrs;
    if (pcrs && pcrs.hash === hashAlgo) {
      const registers = new Map<number, Uint8Array>();
      for (const [key, value] of Object.entries(pcrs.pcrs)) {
        registers.set(Number(key), value);
      }
      // Map HashAlgo enum to TpmAlg
      const algMap: Record<number, number> = {
        [HashAlgo.SHA1]: TpmAlg.SHA1,
        [HashAlgo.SHA256]: TpmAlg.SHA256,
        [HashAlgo.SHA384]: TpmAlg.SHA384,
        [HashAlgo.SHA512]: TpmAlg.SHA512,
      };
      return { hashAlg: algMap[hashAlgo] ?? TpmAlg.SHA256, registers };
    }
  }
  throw new Error(`no PCRs found matching hash ${HashAlgo[hashAlgo]}`);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
