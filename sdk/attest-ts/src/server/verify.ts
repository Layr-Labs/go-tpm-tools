import { type KeyObject, X509Certificate } from 'node:crypto';
import type { Attestation, MachineState } from '../proto/layr_attest_pb.js';
import { MachineStateSchema } from '../proto/layr_attest_pb.js';
import type { Quote } from '../proto/layr_tpm_pb.js';
import { HashAlgo } from '../proto/layr_tpm_pb.js';
import { verifyQuote } from '../tpm/verify-quote.js';
import { decodePublic } from '../tpm/decode-public.js';
import { TpmAlg, SIGNATURE_HASH_ALGS } from '../tpm/constants.js';
import { verifyAKCert, getGCEInstanceInfoFromCert } from './ak-certs.js';
import { parseCosCELPCR, type RegisterBank } from './eventlog.js';
import { parsePCClientEventLog } from './raw-eventlog.js';
import { PlatformStateSchema } from '../proto/layr_attest_pb.js';
import { create } from '@bufbuild/protobuf';

/** Hash algorithms in preference order (SHA-512, SHA-384, SHA-256, SHA-1). */
const PCR_HASH_ALGS = [...SIGNATURE_HASH_ALGS, TpmAlg.SHA1] as const;

/** Maps proto HashAlgo enum to TpmAlg constants. */
function hashAlgoToTpmAlg(h: HashAlgo): number {
  switch (h) {
    case HashAlgo.SHA1: return TpmAlg.SHA1;
    case HashAlgo.SHA256: return TpmAlg.SHA256;
    case HashAlgo.SHA384: return TpmAlg.SHA384;
    case HashAlgo.SHA512: return TpmAlg.SHA512;
    default: return 0;
  }
}

/** Options for VerifyAttestation. */
export interface VerifyOpts {
  /** The nonce used when calling client.Attest. */
  nonce: Uint8Array;

  /**
   * Trusted public keys that can directly verify the AK.
   * Use this if you already know the AK — highest assurance.
   * Mutually exclusive with trustedRootCerts.
   */
  trustedAKs?: KeyObject[];

  /**
   * Trusted root CA certificates (X509Certificate) for AK cert chain validation.
   * Mutually exclusive with trustedAKs.
   */
  trustedRootCerts?: X509Certificate[];

  /** Additional intermediate certificates for chain building. */
  intermediateCerts?: X509Certificate[];

  /** Allow SHA-1 PCRs for verification (defaults to false). */
  allowSHA1?: boolean;
}

/**
 * Verify a TPM attestation: validate the AK, verify quote signatures,
 * replay event logs, and return the MachineState.
 *
 * Port of server.VerifyAttestation from Go.
 *
 * Checks:
 * 1. AK is trusted (via direct key or cert chain)
 * 2. Quote signature is valid (RSA PKCS#1v1.5 or ECDSA)
 * 3. Quote data is genuine TPM output (magic + type check)
 * 4. Quote nonce matches expected nonce
 * 5. PCR digest in quote matches provided PCR values
 * 6. COS Canonical Event Log replays correctly against PCR values
 */
export async function verifyAttestation(
  attestation: Attestation,
  opts: VerifyOpts,
): Promise<MachineState> {
  validateOpts(opts);

  const { machineState, akPubKey } = await validateAK(attestation, opts);

  let lastErr: Error | undefined;

  for (const quote of supportedQuotes(attestation.quotes)) {
    try {
      // Verify the quote signature and PCR binding
      verifyQuote(quote, akPubKey, opts.nonce);

      // Parse COS canonical event log against verified PCRs
      const pcrs = quote.pcrs;
      if (!pcrs) {
        throw new Error('quote is missing PCRs');
      }

      const tpmAlg = hashAlgoToTpmAlg(pcrs.hash);
      if (!opts.allowSHA1 && tpmAlg === TpmAlg.SHA1) {
        throw new Error('SHA-1 is not allowed for verification (set allowSHA1 to true to allow)');
      }

      // Build MachineState from COS CEL if present
      const resultState = create(MachineStateSchema);
      mergeState(resultState, machineState);

      if (attestation.canonicalEventLog.length > 0) {
        const pcrBank = buildPCRBank(pcrs.pcrs, tpmAlg);
        const cosState = parseCosCELPCR(attestation.canonicalEventLog, pcrBank);
        resultState.cos = cosState;
      }

      // Parse raw TCG PC Client event log for platform, EFI, GRUB state + kernel cmdline
      if (attestation.eventLog.length > 0) {
        const parsed = parsePCClientEventLog(attestation.eventLog, pcrs.pcrs, tpmAlg);
        resultState.rawEvents = parsed.events;
        if (parsed.grub) resultState.grub = parsed.grub;
        resultState.linuxKernel = parsed.linuxKernel;
        if (parsed.platform) {
          // Merge platform state; populate GCE instance info from AK cert if not already set
          if (!resultState.platform) {
            resultState.platform = parsed.platform;
          } else {
            if (parsed.platform.firmware.case) resultState.platform.firmware = parsed.platform.firmware;
            if (parsed.platform.technology) resultState.platform.technology = parsed.platform.technology;
          }
        }
        if (parsed.efi) resultState.efi = parsed.efi;
        // Non-fatal errors from event log parsing are accumulated but don't fail verification
        // (e.g., GRUB not found on non-GRUB VMs)
      }

      return resultState;
    } catch (err) {
      lastErr = err instanceof Error ? err : new Error(String(err));
    }
  }

  if (lastErr) {
    throw lastErr;
  }
  throw new Error('attestation does not contain a supported quote');
}

/** Validate VerifyOpts — exactly one trust mechanism must be provided. */
function validateOpts(opts: VerifyOpts): void {
  const hasAKs = opts.trustedAKs && opts.trustedAKs.length > 0;
  const hasCerts = opts.trustedRootCerts && opts.trustedRootCerts.length > 0;

  if (!hasAKs && !hasCerts) {
    throw new Error('no trust mechanism provided, either use trustedAKs or trustedRootCerts');
  }
  if (hasAKs && hasCerts) {
    throw new Error('multiple trust mechanisms provided, only use one of trustedAKs or trustedRootCerts');
  }
}

/**
 * Validate the AK: either via direct key comparison or cert chain.
 * Returns the starting MachineState and the AK public key.
 */
async function validateAK(
  attestation: Attestation,
  opts: VerifyOpts,
): Promise<{ machineState: MachineState; akPubKey: KeyObject }> {
  // If no AK cert or no root certs, use the AK public area
  if (attestation.akCert.length === 0 || !opts.trustedRootCerts || opts.trustedRootCerts.length === 0) {
    const decoded = decodePublic(attestation.akPub);
    const akPubKey = decoded.keyObject;

    if (opts.trustedAKs && opts.trustedAKs.length > 0) {
      validateAKPub(akPubKey, opts.trustedAKs);
    }

    return {
      machineState: create(MachineStateSchema),
      akPubKey,
    };
  }

  // AK cert path — validate chain
  const trustedRoots = opts.trustedRootCerts;
  const intermediates = [
    ...(opts.intermediateCerts ?? []),
    ...attestation.intermediateCerts.map((der) => new X509Certificate(der)),
  ];

  await verifyAKCert(attestation.akCert, trustedRoots, intermediates);

  const akCert = new X509Certificate(attestation.akCert);
  const akPubKey = akCert.publicKey;

  const ms = create(MachineStateSchema);

  // Extract GCE instance info from AK cert extension
  const gceInfo = getGCEInstanceInfoFromCert(attestation.akCert);
  if (gceInfo) {
    if (!ms.platform) {
      ms.platform = create(PlatformStateSchema);
    }
    ms.platform.instanceInfo = {
      $typeName: 'layr_attest.GCEInstanceInfo',
      zone: gceInfo.zone,
      projectId: gceInfo.projectId,
      projectNumber: gceInfo.projectNumber,
      instanceName: gceInfo.instanceName,
      instanceId: gceInfo.instanceId,
    };
  }

  return { machineState: ms, akPubKey };
}

/** Validate an AK public key against the list of trusted AKs. */
function validateAKPub(akPubKey: KeyObject, trustedAKs: KeyObject[]): void {
  const akDER = akPubKey.export({ type: 'spki', format: 'der' });
  for (const trusted of trustedAKs) {
    const trustedDER = trusted.export({ type: 'spki', format: 'der' });
    if (Buffer.from(akDER).equals(Buffer.from(trustedDER))) {
      return;
    }
  }
  throw new Error('AK public key not trusted');
}

/** Sort quotes by hash preference: SHA-512 > SHA-384 > SHA-256 > SHA-1. */
function supportedQuotes(quotes: Quote[]): Quote[] {
  const out: Quote[] = [];
  for (const alg of PCR_HASH_ALGS) {
    for (const quote of quotes) {
      if (quote.pcrs && hashAlgoToTpmAlg(quote.pcrs.hash) === alg) {
        out.push(quote);
        break;
      }
    }
  }
  return out;
}

/** Build a RegisterBank from proto PCRs map. */
function buildPCRBank(pcrMap: { [key: number]: Uint8Array }, hashAlg: number): RegisterBank {
  const registers = new Map<number, Uint8Array>();
  for (const [key, value] of Object.entries(pcrMap)) {
    registers.set(Number(key), value);
  }
  return { hashAlg, registers };
}

/** Shallow merge of source MachineState fields into target. */
function mergeState(target: MachineState, source: MachineState): void {
  if (source.platform) target.platform = source.platform;
  if (source.secureBoot) target.secureBoot = source.secureBoot;
  if (source.rawEvents.length > 0) target.rawEvents = source.rawEvents;
  if (source.grub) target.grub = source.grub;
  if (source.linuxKernel) target.linuxKernel = source.linuxKernel;
  if (source.cos) target.cos = source.cos;
  if (source.efi) target.efi = source.efi;
  if (source.teeAttestation.case) target.teeAttestation = source.teeAttestation;
}
