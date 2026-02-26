import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { parseCosCELPCR, parseCosCELRTMR, type RegisterBank, PCR_TYPE, CCMR_TYPE } from '../src/server/eventlog.js';
import { TpmAlg } from '../src/tpm/constants.js';
import { RestartPolicy, GPUDeviceCCMode } from '../src/proto/layr_attest_pb.js';

// --- CEL TLV encoding helpers (for test data) ---

function marshalTLV(type: number, value: Uint8Array): Uint8Array {
  const buf = new Uint8Array(1 + 4 + value.length);
  buf[0] = type;
  const view = new DataView(buf.buffer);
  view.setUint32(1, value.length, false);
  buf.set(value, 5);
  return buf;
}

function marshalRecNum(recNum: number): Uint8Array {
  const val = new Uint8Array(8);
  const view = new DataView(val.buffer);
  view.setBigUint64(0, BigInt(recNum), false);
  return marshalTLV(0, val);
}

function marshalIndex(indexType: number, index: number): Uint8Array {
  return marshalTLV(indexType, new Uint8Array([index]));
}

function marshalDigests(digestMap: Map<number, Uint8Array>): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const [alg, digest] of digestMap) {
    parts.push(marshalTLV(alg, digest));
  }
  return marshalTLV(3, concatBytes(parts));
}

function marshalCosContent(cosType: number, eventContent: Uint8Array): Uint8Array {
  // Inner TLV: [cosType][len][content]
  const innerTLV = marshalTLV(cosType, eventContent);
  // Outer COS TLV: [80][len][innerTLV]
  return marshalTLV(80, innerTLV);
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

/** Compute the digest of the full content TLV (as used for CEL extend). */
function computeContentDigest(cosType: number, eventContent: Uint8Array, hashAlg: string): Uint8Array {
  const innerTLV = marshalTLV(cosType, eventContent);
  const outerTLV = marshalTLV(80, innerTLV);
  const h = createHash(hashAlg);
  h.update(outerTLV);
  return new Uint8Array(h.digest());
}

/**
 * Build a complete CEL record and compute its digest.
 * Returns { recordBytes, digest } for building test data.
 */
function buildCELRecord(
  recNum: number,
  indexType: number,
  index: number,
  cosType: number,
  eventContent: Uint8Array,
  hashAlg: number,
  hashAlgName: string,
): { recordBytes: Uint8Array; digest: Uint8Array } {
  const digest = computeContentDigest(cosType, eventContent, hashAlgName);
  const digestMap = new Map<number, Uint8Array>();
  digestMap.set(hashAlg, digest);

  const recnumTLV = marshalRecNum(recNum);
  const indexTLV = marshalIndex(indexType, index);
  const digestsTLV = marshalDigests(digestMap);
  const contentTLV = marshalCosContent(cosType, eventContent);

  return {
    recordBytes: concatBytes([recnumTLV, indexTLV, digestsTLV, contentTLV]),
    digest,
  };
}

/**
 * Replay digests to compute the final PCR/RTMR value.
 * PCR extend: pcr = hash(pcr || digest)
 */
function replayDigests(digests: Uint8Array[], hashAlgName: string): Uint8Array {
  const digestSize = createHash(hashAlgName).digest().length;
  let pcr = new Uint8Array(digestSize);
  for (const d of digests) {
    const h = createHash(hashAlgName);
    h.update(pcr);
    h.update(d);
    pcr = new Uint8Array(h.digest());
  }
  return pcr;
}

const enc = new TextEncoder();

describe('CEL Event Log Parsing', () => {
  describe('parseCosCELPCR', () => {
    it('should parse a single ImageRef event', () => {
      const content = enc.encode('docker.io/library/nginx:latest');
      const { recordBytes, digest } = buildCELRecord(
        0, PCR_TYPE, 13, 0 /* ImageRef */, content, TpmAlg.SHA256, 'sha256',
      );

      const pcrValue = replayDigests([digest], 'sha256');
      const bank: RegisterBank = {
        hashAlg: TpmAlg.SHA256,
        registers: new Map([[13, pcrValue]]),
      };

      const state = parseCosCELPCR(recordBytes, bank);
      expect(state.container?.imageReference).toBe('docker.io/library/nginx:latest');
    });

    it('should parse multiple COS events', () => {
      const records: Uint8Array[] = [];
      const digests: Uint8Array[] = [];

      // ImageRef
      const r0 = buildCELRecord(0, PCR_TYPE, 13, 0, enc.encode('nginx:latest'), TpmAlg.SHA256, 'sha256');
      records.push(r0.recordBytes);
      digests.push(r0.digest);

      // ImageDigest
      const r1 = buildCELRecord(1, PCR_TYPE, 13, 1, enc.encode('sha256:abc123'), TpmAlg.SHA256, 'sha256');
      records.push(r1.recordBytes);
      digests.push(r1.digest);

      // ImageID
      const r2 = buildCELRecord(2, PCR_TYPE, 13, 3, enc.encode('sha256:def456'), TpmAlg.SHA256, 'sha256');
      records.push(r2.recordBytes);
      digests.push(r2.digest);

      // RestartPolicy
      const r3 = buildCELRecord(3, PCR_TYPE, 13, 2, enc.encode('Always'), TpmAlg.SHA256, 'sha256');
      records.push(r3.recordBytes);
      digests.push(r3.digest);

      // Arg
      const r4 = buildCELRecord(4, PCR_TYPE, 13, 4, enc.encode('--debug'), TpmAlg.SHA256, 'sha256');
      records.push(r4.recordBytes);
      digests.push(r4.digest);

      // EnvVar
      const r5 = buildCELRecord(5, PCR_TYPE, 13, 5, enc.encode('FOO=bar'), TpmAlg.SHA256, 'sha256');
      records.push(r5.recordBytes);
      digests.push(r5.digest);

      const pcrValue = replayDigests(digests, 'sha256');
      const bank: RegisterBank = {
        hashAlg: TpmAlg.SHA256,
        registers: new Map([[13, pcrValue]]),
      };

      const celBytes = concatBytes(records);
      const state = parseCosCELPCR(celBytes, bank);

      expect(state.container?.imageReference).toBe('nginx:latest');
      expect(state.container?.imageDigest).toBe('sha256:abc123');
      expect(state.container?.imageId).toBe('sha256:def456');
      expect(state.container?.restartPolicy).toBe(RestartPolicy.Always);
      expect(state.container?.args).toEqual(['--debug']);
      expect(state.container?.envVars).toEqual({ FOO: 'bar' });
    });

    it('should parse overridden args and env vars', () => {
      const records: Uint8Array[] = [];
      const digests: Uint8Array[] = [];

      const r0 = buildCELRecord(0, PCR_TYPE, 13, 6 /* OverrideArg */, enc.encode('--override'), TpmAlg.SHA256, 'sha256');
      records.push(r0.recordBytes);
      digests.push(r0.digest);

      const r1 = buildCELRecord(1, PCR_TYPE, 13, 7 /* OverrideEnv */, enc.encode('BAR=baz'), TpmAlg.SHA256, 'sha256');
      records.push(r1.recordBytes);
      digests.push(r1.digest);

      const pcrValue = replayDigests(digests, 'sha256');
      const bank: RegisterBank = {
        hashAlg: TpmAlg.SHA256,
        registers: new Map([[13, pcrValue]]),
      };

      const state = parseCosCELPCR(concatBytes(records), bank);
      expect(state.container?.overriddenArgs).toEqual(['--override']);
      expect(state.container?.overriddenEnvVars).toEqual({ BAR: 'baz' });
    });

    it('should parse LaunchSeparator', () => {
      const records: Uint8Array[] = [];
      const digests: Uint8Array[] = [];

      const r0 = buildCELRecord(0, PCR_TYPE, 13, 0, enc.encode('nginx:latest'), TpmAlg.SHA256, 'sha256');
      records.push(r0.recordBytes);
      digests.push(r0.digest);

      const r1 = buildCELRecord(1, PCR_TYPE, 13, 8 /* LaunchSeparator */, new Uint8Array(0), TpmAlg.SHA256, 'sha256');
      records.push(r1.recordBytes);
      digests.push(r1.digest);

      const pcrValue = replayDigests(digests, 'sha256');
      const bank: RegisterBank = {
        hashAlg: TpmAlg.SHA256,
        registers: new Map([[13, pcrValue]]),
      };

      const state = parseCosCELPCR(concatBytes(records), bank);
      expect(state.container?.imageReference).toBe('nginx:latest');
    });

    it('should reject events after LaunchSeparator', () => {
      const records: Uint8Array[] = [];
      const digests: Uint8Array[] = [];

      const r0 = buildCELRecord(0, PCR_TYPE, 13, 8 /* LaunchSeparator */, new Uint8Array(0), TpmAlg.SHA256, 'sha256');
      records.push(r0.recordBytes);
      digests.push(r0.digest);

      const r1 = buildCELRecord(1, PCR_TYPE, 13, 0, enc.encode('nginx:latest'), TpmAlg.SHA256, 'sha256');
      records.push(r1.recordBytes);
      digests.push(r1.digest);

      const pcrValue = replayDigests(digests, 'sha256');
      const bank: RegisterBank = {
        hashAlg: TpmAlg.SHA256,
        registers: new Map([[13, pcrValue]]),
      };

      expect(() => parseCosCELPCR(concatBytes(records), bank))
        .toThrow('after LaunchSeparator');
    });

    it('should reject duplicate ImageRef', () => {
      const records: Uint8Array[] = [];
      const digests: Uint8Array[] = [];

      const r0 = buildCELRecord(0, PCR_TYPE, 13, 0, enc.encode('nginx:1'), TpmAlg.SHA256, 'sha256');
      records.push(r0.recordBytes);
      digests.push(r0.digest);

      const r1 = buildCELRecord(1, PCR_TYPE, 13, 0, enc.encode('nginx:2'), TpmAlg.SHA256, 'sha256');
      records.push(r1.recordBytes);
      digests.push(r1.digest);

      const pcrValue = replayDigests(digests, 'sha256');
      const bank: RegisterBank = {
        hashAlg: TpmAlg.SHA256,
        registers: new Map([[13, pcrValue]]),
      };

      expect(() => parseCosCELPCR(concatBytes(records), bank))
        .toThrow('more than one ImageRef');
    });

    it('should reject wrong PCR index', () => {
      const content = enc.encode('nginx:latest');
      const { recordBytes, digest } = buildCELRecord(
        0, PCR_TYPE, 5 /* wrong */, 0, content, TpmAlg.SHA256, 'sha256',
      );

      const pcrValue = replayDigests([digest], 'sha256');
      const bank: RegisterBank = {
        hashAlg: TpmAlg.SHA256,
        registers: new Map([[5, pcrValue]]),
      };

      expect(() => parseCosCELPCR(recordBytes, bank))
        .toThrow('unexpected PCR 5');
    });

    it('should reject mismatching PCR replay', () => {
      const content = enc.encode('nginx:latest');
      const { recordBytes } = buildCELRecord(
        0, PCR_TYPE, 13, 0, content, TpmAlg.SHA256, 'sha256',
      );

      // Provide wrong PCR value
      const bank: RegisterBank = {
        hashAlg: TpmAlg.SHA256,
        registers: new Map([[13, new Uint8Array(32)]]),
      };

      expect(() => parseCosCELPCR(recordBytes, bank))
        .toThrow('CEL replay failed');
    });

    it('should handle MemoryMonitor enabled', () => {
      const records: Uint8Array[] = [];
      const digests: Uint8Array[] = [];

      const r0 = buildCELRecord(0, PCR_TYPE, 13, 9 /* MemoryMonitor */, new Uint8Array([1]), TpmAlg.SHA256, 'sha256');
      records.push(r0.recordBytes);
      digests.push(r0.digest);

      const pcrValue = replayDigests(digests, 'sha256');
      const bank: RegisterBank = {
        hashAlg: TpmAlg.SHA256,
        registers: new Map([[13, pcrValue]]),
      };

      const state = parseCosCELPCR(concatBytes(records), bank);
      expect(state.healthMonitoring?.memoryEnabled).toBe(true);
    });

    it('should handle GpuCCMode', () => {
      const records: Uint8Array[] = [];
      const digests: Uint8Array[] = [];

      const r0 = buildCELRecord(0, PCR_TYPE, 13, 10 /* GpuCCMode */, enc.encode('ON'), TpmAlg.SHA256, 'sha256');
      records.push(r0.recordBytes);
      digests.push(r0.digest);

      const pcrValue = replayDigests(digests, 'sha256');
      const bank: RegisterBank = {
        hashAlg: TpmAlg.SHA256,
        registers: new Map([[13, pcrValue]]),
      };

      const state = parseCosCELPCR(concatBytes(records), bank);
      expect(state.gpuDeviceState?.ccMode).toBe(GPUDeviceCCMode.ON);
    });

    it('should return empty state for empty event log', () => {
      const bank: RegisterBank = {
        hashAlg: TpmAlg.SHA256,
        registers: new Map(),
      };
      const state = parseCosCELPCR(new Uint8Array(0), bank);
      expect(state.container).toBeUndefined();
    });
  });

  describe('parseCosCELRTMR', () => {
    it('should parse RTMR-based COS events', () => {
      const records: Uint8Array[] = [];
      const digests: Uint8Array[] = [];

      const r0 = buildCELRecord(0, CCMR_TYPE, 4 /* CosCCELMRIndex */, 0, enc.encode('nginx:rtmr'), TpmAlg.SHA384, 'sha384');
      records.push(r0.recordBytes);
      digests.push(r0.digest);

      const rtmrValue = replayDigests(digests, 'sha384');
      const bank: RegisterBank = {
        hashAlg: TpmAlg.SHA384,
        registers: new Map([[4, rtmrValue]]),
      };

      const state = parseCosCELRTMR(concatBytes(records), bank);
      expect(state.container?.imageReference).toBe('nginx:rtmr');
    });

    it('should reject wrong CCELMR index', () => {
      const { recordBytes, digest } = buildCELRecord(
        0, CCMR_TYPE, 2 /* wrong */, 0, enc.encode('nginx'), TpmAlg.SHA384, 'sha384',
      );

      const rtmrValue = replayDigests([digest], 'sha384');
      const bank: RegisterBank = {
        hashAlg: TpmAlg.SHA384,
        registers: new Map([[2, rtmrValue]]),
      };

      expect(() => parseCosCELRTMR(recordBytes, bank))
        .toThrow('unexpected CCELMR 2');
    });
  });

  describe('env var parsing', () => {
    it('should reject malformed env var without =', () => {
      const records: Uint8Array[] = [];
      const digests: Uint8Array[] = [];

      const r0 = buildCELRecord(0, PCR_TYPE, 13, 5 /* EnvVar */, enc.encode('NOEQUALSSIGN'), TpmAlg.SHA256, 'sha256');
      records.push(r0.recordBytes);
      digests.push(r0.digest);

      const pcrValue = replayDigests(digests, 'sha256');
      const bank: RegisterBank = {
        hashAlg: TpmAlg.SHA256,
        registers: new Map([[13, pcrValue]]),
      };

      expect(() => parseCosCELPCR(concatBytes(records), bank))
        .toThrow("doesn't contain '='");
    });

    it('should reject malformed env var name', () => {
      const records: Uint8Array[] = [];
      const digests: Uint8Array[] = [];

      const r0 = buildCELRecord(0, PCR_TYPE, 13, 5, enc.encode('123BAD=val'), TpmAlg.SHA256, 'sha256');
      records.push(r0.recordBytes);
      digests.push(r0.digest);

      const pcrValue = replayDigests(digests, 'sha256');
      const bank: RegisterBank = {
        hashAlg: TpmAlg.SHA256,
        registers: new Map([[13, pcrValue]]),
      };

      expect(() => parseCosCELPCR(concatBytes(records), bank))
        .toThrow('malformed env name');
    });
  });
});
