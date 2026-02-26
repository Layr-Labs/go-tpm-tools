import { createHash } from 'node:crypto';
import { BufferReader } from '../tpm/buffer-reader.js';
import { hashAlgName } from '../tpm/constants.js';
import type { AttestedCosState } from '../proto/layr_attest_pb.js';
import {
  AttestedCosStateSchema,
  ContainerStateSchema,
  HealthMonitoringStateSchema,
  GpuDeviceStateSchema,
  RestartPolicy,
  GPUDeviceCCMode,
} from '../proto/layr_attest_pb.js';
import { create } from '@bufbuild/protobuf';

// --- CEL TLV Constants (TCG_IWG_CEL_v1_r0p37) ---

const RECNUM_TYPE = 0;
/** PCR register type. */
export const PCR_TYPE = 1;
/** CCMR (Confidential Computing MR) register type. */
export const CCMR_TYPE = 108;
const DIGESTS_TYPE = 3;

const RECNUM_VALUE_LENGTH = 8;
const REG_INDEX_VALUE_LENGTH = 1;

// --- COS Event Constants ---

/** COS content TLV type in CEL records. */
const COS_EVENT_TYPE = 80;
/** PCR index for COS events. */
const COS_EVENT_PCR = 13;
/** CCELMR index for COS events (RTMR[3]). */
const COS_CCELMR_INDEX = 4;

/** COS event types (nested TLV type values). */
const enum CosType {
  ImageRef = 0,
  ImageDigest = 1,
  RestartPolicy = 2,
  ImageID = 3,
  Arg = 4,
  EnvVar = 5,
  OverrideArg = 6,
  OverrideEnv = 7,
  LaunchSeparator = 8,
  MemoryMonitor = 9,
  GpuCCMode = 10,
}

// --- CEL TLV Types ---

interface TLV {
  type: number;
  value: Uint8Array;
}

interface CELRecord {
  recNum: bigint;
  index: number;
  indexType: number;
  digests: Map<number, Uint8Array>; // TPM hash alg → digest
  content: TLV;
}

interface CosTlv {
  eventType: number;
  eventContent: Uint8Array;
}

/** A register bank: register index → digest value. */
export interface RegisterBank {
  hashAlg: number; // TpmAlg value
  registers: Map<number, Uint8Array>; // index → digest
}

// --- TLV Parsing ---

function unmarshalFirstTLV(r: BufferReader): TLV {
  const type = r.readUint8();
  const length = r.readUint32();
  const value = r.readBytes(length);
  return { type, value };
}

function unmarshalRecNum(tlv: TLV): bigint {
  if (tlv.type !== RECNUM_TYPE) {
    throw new Error(`TLV type ${tlv.type} is not a recnum field (expected ${RECNUM_TYPE})`);
  }
  if (tlv.value.length !== RECNUM_VALUE_LENGTH) {
    throw new Error(`recnum value length ${tlv.value.length} doesn't match expected ${RECNUM_VALUE_LENGTH}`);
  }
  const view = new DataView(tlv.value.buffer, tlv.value.byteOffset, tlv.value.byteLength);
  return view.getBigUint64(0, false);
}

function unmarshalIndex(tlv: TLV): { indexType: number; index: number } {
  if (tlv.type !== PCR_TYPE && tlv.type !== CCMR_TYPE) {
    throw new Error(`TLV type ${tlv.type} is not PCR (${PCR_TYPE}) or CCMR (${CCMR_TYPE})`);
  }
  if (tlv.value.length !== REG_INDEX_VALUE_LENGTH) {
    throw new Error(`register index value length ${tlv.value.length} doesn't match expected ${REG_INDEX_VALUE_LENGTH}`);
  }
  return { indexType: tlv.type, index: tlv.value[0] };
}

function unmarshalDigests(tlv: TLV): Map<number, Uint8Array> {
  if (tlv.type !== DIGESTS_TYPE) {
    throw new Error(`TLV type ${tlv.type} does not contain digests`);
  }

  const digestMap = new Map<number, Uint8Array>();
  const r = new BufferReader(tlv.value);
  while (r.remaining() > 0) {
    const digestTLV = unmarshalFirstTLV(r);
    // digestTLV.type is the TPM hash algorithm (uint8 of the 16-bit alg value)
    digestMap.set(digestTLV.type, digestTLV.value);
  }
  return digestMap;
}

// --- CEL Decode ---

function decodeCELRecord(r: BufferReader): CELRecord {
  const recnumTLV = unmarshalFirstTLV(r);
  const recNum = unmarshalRecNum(recnumTLV);

  const indexTLV = unmarshalFirstTLV(r);
  const { indexType, index } = unmarshalIndex(indexTLV);

  const digestsTLV = unmarshalFirstTLV(r);
  const digests = unmarshalDigests(digestsTLV);

  const content = unmarshalFirstTLV(r);

  return { recNum, index, indexType, digests, content };
}

function decodeCEL(data: Uint8Array): CELRecord[] {
  const records: CELRecord[] = [];
  const r = new BufferReader(data);
  while (r.remaining() > 0) {
    records.push(decodeCELRecord(r));
  }
  return records;
}

// --- CEL Replay ---

/**
 * Replay CEL records against a register bank and verify final digests match.
 * Implements the extend sequence: register[i] = hash(register[i] || digest).
 */
function replayCEL(records: CELRecord[], bank: RegisterBank): void {
  const algName = hashAlgName(bank.hashAlg);
  const digestSize = createHash(algName).digest().length;

  const replayed = new Map<number, Uint8Array>();

  for (const record of records) {
    const digest = record.digests.get(bank.hashAlg);
    if (!digest) {
      // Skip records that don't have a digest for this hash algorithm.
      // This happens when PCR bank is SHA-256 but CEL contains only CCMR/SHA-384 records.
      continue;
    }

    if (!replayed.has(record.index)) {
      replayed.set(record.index, new Uint8Array(digestSize));
    }

    const h = createHash(algName);
    h.update(replayed.get(record.index)!);
    h.update(digest);
    replayed.set(record.index, new Uint8Array(h.digest()));
  }

  const failedRegs: number[] = [];
  for (const [regIndex, replayDigest] of replayed) {
    const bankDigest = bank.registers.get(regIndex);
    if (!bankDigest) {
      throw new Error(`CEL contains record(s) for register ${regIndex} without a matching register in the given bank`);
    }
    if (!bytesEqual(bankDigest, replayDigest)) {
      failedRegs.push(regIndex);
    }
  }

  if (failedRegs.length > 0) {
    throw new Error(`CEL replay failed for registers: ${failedRegs.join(', ')}`);
  }
}

// --- COS TLV Parsing ---

function parseToCosTlv(tlv: TLV): CosTlv {
  if (tlv.type !== COS_EVENT_TYPE) {
    throw new Error(`TLV type ${tlv.type} is not a COS event (expected ${COS_EVENT_TYPE})`);
  }
  // Nested TLV: value is a marshaled TLV with [type:1][length:4][value:...]
  const r = new BufferReader(tlv.value);
  const nestedType = r.readUint8();
  const nestedLength = r.readUint32();
  const nestedValue = r.readBytes(nestedLength);
  return { eventType: nestedType, eventContent: nestedValue };
}

/**
 * Verify that the digest of a COS TLV content matches the stored digests.
 * The digest is computed over the full marshaled content TLV bytes.
 */
function verifyCosTlvDigests(cosTlv: CosTlv, digests: Map<number, Uint8Array>): void {
  // Reconstruct the full content TLV bytes: outer COS TLV wrapping inner COS event TLV
  const innerTLV = marshalTLV(cosTlv.eventType, cosTlv.eventContent);
  const outerTLV = marshalTLV(COS_EVENT_TYPE, innerTLV);

  for (const [hashAlg, expectedDigest] of digests) {
    const algName = hashAlgName(hashAlg);
    const h = createHash(algName);
    h.update(outerTLV);
    const computedDigest = new Uint8Array(h.digest());
    if (!bytesEqual(computedDigest, expectedDigest)) {
      throw new Error(`CEL record content digest verification failed for ${algName}`);
    }
  }
}

function marshalTLV(type: number, value: Uint8Array): Uint8Array {
  const buf = new Uint8Array(1 + 4 + value.length);
  buf[0] = type;
  const view = new DataView(buf.buffer);
  view.setUint32(1, value.length, false);
  buf.set(value, 5);
  return buf;
}

// --- Env var parsing ---

const envVarNameRegex = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

function parseEnvVar(envvar: string): [string, string] {
  const eqIdx = envvar.indexOf('=');
  if (eqIdx === -1) {
    throw new Error(`malformed env var, doesn't contain '=': [${envvar}]`);
  }
  const name = envvar.substring(0, eqIdx);
  const value = envvar.substring(eqIdx + 1);

  if (!envVarNameRegex.test(name)) {
    throw new Error(`malformed env name [${name}]`);
  }
  return [name, value];
}

// --- Restart policy / GPU CC mode string-to-enum mapping ---

const restartPolicyMap: Record<string, RestartPolicy> = {
  Always: RestartPolicy.Always,
  OnFailure: RestartPolicy.OnFailure,
  Never: RestartPolicy.Never,
};

const gpuCCModeMap: Record<string, GPUDeviceCCMode> = {
  UNSET: GPUDeviceCCMode.UNSET,
  ON: GPUDeviceCCMode.ON,
  OFF: GPUDeviceCCMode.OFF,
  DEVTOOLS: GPUDeviceCCMode.DEVTOOLS,
};

// --- COS State Extraction ---

function getVerifiedCosState(records: CELRecord[], registerType: number): AttestedCosState {
  const cosState = create(AttestedCosStateSchema);
  cosState.container = create(ContainerStateSchema);
  cosState.healthMonitoring = create(HealthMonitoringStateSchema);
  cosState.gpuDeviceState = create(GpuDeviceStateSchema);
  cosState.container.args = [];
  cosState.container.envVars = {};
  cosState.container.overriddenEnvVars = {};

  let seenSeparator = false;

  for (const record of records) {
    if (record.indexType !== registerType) {
      // Skip records with a different register type.
      // E.g., on TDX, PCR-based CEL parsing skips CCMR records and vice versa.
      continue;
    }

    // Validate register index
    if (record.indexType === PCR_TYPE) {
      if (record.index !== COS_EVENT_PCR) {
        throw new Error(`found unexpected PCR ${record.index} in COS CEL log`);
      }
    } else if (record.indexType === CCMR_TYPE) {
      if (record.index !== COS_CCELMR_INDEX) {
        throw new Error(`found unexpected CCELMR ${record.index} in COS CEL log`);
      }
    } else {
      throw new Error(`unknown COS CEL log index type ${record.indexType}`);
    }

    const cosTlv = parseToCosTlv(record.content);
    verifyCosTlvDigests(cosTlv, record.digests);

    if (seenSeparator) {
      throw new Error(`found COS Event Type ${cosTlv.eventType} after LaunchSeparator event`);
    }

    const content = new TextDecoder().decode(cosTlv.eventContent);

    switch (cosTlv.eventType) {
      case CosType.ImageRef:
        if (cosState.container!.imageReference !== '') {
          throw new Error('found more than one ImageRef event');
        }
        cosState.container!.imageReference = content;
        break;

      case CosType.ImageDigest:
        if (cosState.container!.imageDigest !== '') {
          throw new Error('found more than one ImageDigest event');
        }
        cosState.container!.imageDigest = content;
        break;

      case CosType.RestartPolicy: {
        const policy = restartPolicyMap[content];
        if (policy === undefined) {
          throw new Error(`unknown restart policy in COS eventlog: ${content}`);
        }
        cosState.container!.restartPolicy = policy;
        break;
      }

      case CosType.ImageID:
        if (cosState.container!.imageId !== '') {
          throw new Error('found more than one ImageId event');
        }
        cosState.container!.imageId = content;
        break;

      case CosType.EnvVar: {
        const [name, value] = parseEnvVar(content);
        cosState.container!.envVars[name] = value;
        break;
      }

      case CosType.Arg:
        cosState.container!.args.push(content);
        break;

      case CosType.OverrideArg:
        cosState.container!.overriddenArgs.push(content);
        break;

      case CosType.OverrideEnv: {
        const [name, value] = parseEnvVar(content);
        cosState.container!.overriddenEnvVars[name] = value;
        break;
      }

      case CosType.LaunchSeparator:
        seenSeparator = true;
        break;

      case CosType.MemoryMonitor: {
        const enabled = cosTlv.eventContent.length === 1 && cosTlv.eventContent[0] === 1;
        cosState.healthMonitoring!.memoryEnabled = enabled;
        break;
      }

      case CosType.GpuCCMode: {
        const mode = gpuCCModeMap[content];
        if (mode === undefined) {
          throw new Error(`unknown GPU device CC mode in COS eventlog: ${content}`);
        }
        cosState.gpuDeviceState!.ccMode = mode;
        break;
      }

      default:
        throw new Error(`found unknown COS Event Type ${cosTlv.eventType}`);
    }
  }

  return cosState;
}

// --- Public API ---

/**
 * Parse a COS CEL (Canonical Event Log) against a PCR bank.
 * Decodes CEL records, replays digests against PCR values, and extracts COS container state.
 *
 * Port of server.ParseCosCELPCR from Go.
 */
export function parseCosCELPCR(canonicalEventLog: Uint8Array, pcrBank: RegisterBank): AttestedCosState {
  return getCosStateFromCEL(canonicalEventLog, pcrBank, PCR_TYPE);
}

/**
 * Parse a COS CEL against an RTMR bank.
 * Decodes CEL records, replays digests against RTMR values, and extracts COS container state.
 *
 * Port of server.ParseCosCELRTMR from Go.
 */
export function parseCosCELRTMR(canonicalEventLog: Uint8Array, rtmrBank: RegisterBank): AttestedCosState {
  return getCosStateFromCEL(canonicalEventLog, rtmrBank, CCMR_TYPE);
}

function getCosStateFromCEL(rawCEL: Uint8Array, bank: RegisterBank, registerType: number): AttestedCosState {
  if (rawCEL.length === 0) {
    return create(AttestedCosStateSchema);
  }

  const records = decodeCEL(rawCEL);
  replayCEL(records, bank);
  return getVerifiedCosState(records, registerType);
}

// --- Helpers ---

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
