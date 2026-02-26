import type { Attestation as AttestationProto } from './proto/layr_attest_pb.js';
import { HashAlgo } from './proto/layr_tpm_pb.js';
import { Platform, parseSevSnpPolicy } from './types.js';
import type {
  VerifiedTPMAttestation,
  VerifiedTEEAttestation,
  ExtractOptions,
  TPMClaims,
  TEEClaims,
  TDXClaims,
  SevSnpClaims,
} from './types.js';

/**
 * Extract TPM-layer claims from a verified TPM attestation.
 * Includes PCRs, GCE metadata, and hardened status.
 *
 * Port of VerifiedTPMAttestation.ExtractTPMClaims from Go.
 */
export function extractTPMClaims(
  verified: VerifiedTPMAttestation,
  opts: ExtractOptions,
): TPMClaims {
  const claims: TPMClaims = {
    platform: verified.platform,
    hardened: isHardened(verified.machineState.linuxKernel?.commandLine ?? ''),
    pcrs: extractPCRs(verified.proto, opts.pcrIndices),
  };

  const platformState = verified.machineState.platform;
  if (platformState?.instanceInfo) {
    const info = platformState.instanceInfo;
    claims.gce = {
      projectId: info.projectId,
      projectNumber: info.projectNumber,
      zone: info.zone,
      instanceId: info.instanceId,
      instanceName: info.instanceName,
    };
  }

  return claims;
}

/**
 * Extract TEE-specific claims (TDX or SEV-SNP) from a verified TEE attestation.
 *
 * Port of VerifiedTEEAttestation.ExtractTEEClaims from Go.
 */
export function extractTEEClaims(
  verified: VerifiedTEEAttestation,
): TEEClaims {
  const claims: TEEClaims = {
    platform: verified.platform,
  };

  switch (verified.platform) {
    case Platform.IntelTDX:
      claims.tdx = extractTDXClaims(verified.proto);
      break;
    case Platform.AMDSevSnp:
      claims.sevSnp = extractSevSnpClaims(verified.proto);
      break;
    default:
      throw new Error(`no TEE claims available for platform ${verified.platform}`);
  }

  return claims;
}

// --- Internal helpers ---

function extractPCRs(attestation: AttestationProto, indices: number[]): Map<number, Uint8Array> {
  for (const idx of indices) {
    if (idx > 23) {
      throw new Error(`invalid PCR index ${idx} (must be 0-23)`);
    }
  }

  let sha256PCRs: { [key: number]: Uint8Array } | undefined;
  for (const quote of attestation.quotes) {
    if (quote.pcrs && quote.pcrs.hash === HashAlgo.SHA256) {
      sha256PCRs = quote.pcrs.pcrs;
      break;
    }
  }
  if (!sha256PCRs) {
    throw new Error('attestation contains no SHA-256 PCR quotes');
  }

  const result = new Map<number, Uint8Array>();
  for (const idx of indices) {
    const val = sha256PCRs[idx];
    if (!val) {
      throw new Error(`PCR ${idx} not found in attestation`);
    }
    if (val.length !== 32) {
      throw new Error(`PCR ${idx} has invalid length: got ${val.length}, expected 32`);
    }
    result.set(idx, val);
  }

  return result;
}

function extractTDXClaims(attestation: AttestationProto): TDXClaims {
  if (attestation.teeAttestation.case !== 'tdxAttestation') {
    throw new Error('TDX attestation is nil');
  }

  const quoteBody = attestation.teeAttestation.value.tdQuoteBody;
  if (!quoteBody) {
    throw new Error('TDX quote body is nil');
  }

  const tdAttrs = quoteBody.tdAttributes;
  if (tdAttrs.length < 2) {
    throw new Error(`TD attributes too short: got ${tdAttrs.length} bytes, need at least 2`);
  }

  const claims: TDXClaims = {
    attributes: {
      debug: (tdAttrs[0] & 0x01) !== 0,
      septVEDisable: (tdAttrs[0] & 0x10) !== 0,
      pks: (tdAttrs[0] & 0x40) !== 0,
      kl: (tdAttrs[0] & 0x80) !== 0,
      perfMon: (tdAttrs[1] & 0x01) !== 0,
    },
    mrtd: new Uint8Array(48),
    rtmr0: new Uint8Array(48),
    rtmr1: new Uint8Array(48),
    rtmr2: new Uint8Array(48),
    rtmr3: new Uint8Array(48),
    teeTcbSvn: new Uint8Array(16),
  };

  // Extract TEE TCB SVN (must be exactly 16 bytes if present)
  if (quoteBody.teeTcbSvn.length > 0) {
    if (quoteBody.teeTcbSvn.length !== 16) {
      throw new Error(`invalid TeeTcbSvn length: got ${quoteBody.teeTcbSvn.length}, expected 16`);
    }
    claims.teeTcbSvn.set(quoteBody.teeTcbSvn);
  }

  // Extract MRTD (must be exactly 48 bytes if present)
  if (quoteBody.mrTd.length > 0) {
    if (quoteBody.mrTd.length !== 48) {
      throw new Error(`invalid MRTD length: got ${quoteBody.mrTd.length}, expected 48`);
    }
    claims.mrtd.set(quoteBody.mrTd);
  }

  // Extract RTMRs (each must be exactly 48 bytes if present)
  if (quoteBody.rtmrs.length > 0) {
    if (quoteBody.rtmrs.length !== 4) {
      throw new Error(`invalid RTMR count: got ${quoteBody.rtmrs.length}, expected 4`);
    }
    for (let i = 0; i < 4; i++) {
      if (quoteBody.rtmrs[i].length !== 48) {
        throw new Error(`invalid RTMR${i} length: got ${quoteBody.rtmrs[i].length}, expected 48`);
      }
    }
    claims.rtmr0.set(quoteBody.rtmrs[0]);
    claims.rtmr1.set(quoteBody.rtmrs[1]);
    claims.rtmr2.set(quoteBody.rtmrs[2]);
    claims.rtmr3.set(quoteBody.rtmrs[3]);
  }

  return claims;
}

function extractSevSnpClaims(attestation: AttestationProto): SevSnpClaims {
  if (attestation.teeAttestation.case !== 'sevSnpAttestation') {
    throw new Error('SEV-SNP attestation is nil');
  }

  const report = attestation.teeAttestation.value.report;
  if (!report) {
    throw new Error('SEV-SNP report is nil');
  }

  const policy = parseSevSnpPolicy(report.policy);

  const claims: SevSnpClaims = {
    currentTcb: report.currentTcb,
    reportedTcb: report.reportedTcb,
    committedTcb: report.committedTcb,
    guestSvn: report.guestSvn,
    policy,
    measurement: new Uint8Array(48),
    hostData: new Uint8Array(32),
  };

  // Extract Measurement (must be exactly 48 bytes if present)
  if (report.measurement.length > 0) {
    if (report.measurement.length !== 48) {
      throw new Error(`invalid Measurement length: got ${report.measurement.length}, expected 48`);
    }
    claims.measurement.set(report.measurement);
  }

  // Extract HostData (must be exactly 32 bytes if present)
  if (report.hostData.length > 0) {
    if (report.hostData.length !== 32) {
      throw new Error(`invalid HostData length: got ${report.hostData.length}, expected 32`);
    }
    claims.hostData.set(report.hostData);
  }

  return claims;
}

function isHardened(cmdline: string): boolean {
  return cmdline.split(/\s+/).includes('confidential-space.hardened=true');
}
