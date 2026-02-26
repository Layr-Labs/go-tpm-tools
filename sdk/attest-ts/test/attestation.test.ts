import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, it, expect, beforeAll } from 'vitest';
import { parse, verifyTPM, verifyBoundTEE, extractContainerClaims } from '../src/attestation.js';
import { extractTPMClaims, extractTEEClaims } from '../src/extract.js';
import { Platform, platformTag } from '../src/types.js';
import { fromBinary } from '@bufbuild/protobuf';
import { AttestationSchema } from '../src/proto/layr_attest_pb.js';

// --- Test vector loading ---

interface TestVectorJSON {
  name: string;
  platform: string;
  hardened: boolean;
  attestation: string; // base64
  challenge: string;   // hex
  extra_data: string;  // hex
}

interface TestVector {
  name: string;
  platform: string;
  hardened: boolean;
  attestation: Uint8Array;
  challenge: Uint8Array;
  extraData: Uint8Array | undefined;
}

function expectedPlatform(s: string): Platform {
  switch (s) {
    case 'intel_tdx': return Platform.IntelTDX;
    case 'amd_sev_snp': return Platform.AMDSevSnp;
    case 'gcp_shielded_vm': return Platform.GCPShieldedVM;
    default: return Platform.Unknown;
  }
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function loadTestVectors(): TestVector[] | null {
  const path = resolve(__dirname, '../../testdata/attestations.json');
  if (!existsSync(path)) return null;

  const data = readFileSync(path, 'utf-8');
  const raw: TestVectorJSON[] = JSON.parse(data);
  if (raw.length === 0) return null;

  return raw.map((r) => ({
    name: r.name,
    platform: r.platform,
    hardened: r.hardened,
    attestation: Uint8Array.from(Buffer.from(r.attestation, 'base64')),
    challenge: hexToBytes(r.challenge),
    extraData: r.extra_data ? hexToBytes(r.extra_data) : undefined,
  }));
}

// --- Tests ---

let vectors: TestVector[] | null = null;

beforeAll(() => {
  vectors = loadTestVectors();
});

// =============================================================================
// Parse Tests
// =============================================================================

describe('parse', () => {
  it('parses all test vectors with correct platform', () => {
    if (!vectors) return; // skip if no test data

    for (const v of vectors) {
      const parsed = parse(v.attestation);
      const want = expectedPlatform(v.platform);
      expect(parsed.platform, `${v.name}: platform mismatch`).toBe(want);
    }
  });

  it('rejects invalid protobuf', () => {
    expect(() => parse(new Uint8Array([0xff, 0xfe, 0xfd]))).toThrow();
  });

  it('rejects empty attestation', () => {
    expect(() => parse(new Uint8Array(0))).toThrow(/unknown platform/);
  });
});

// =============================================================================
// VerifyTPM Tests
// =============================================================================

describe('verifyTPM', () => {
  it('verifies all test vectors', async () => {
    if (!vectors) return;

    for (const v of vectors) {
      const parsed = parse(v.attestation);
      const result = await verifyTPM(parsed, v.challenge, v.extraData);
      const want = expectedPlatform(v.platform);
      expect(result.platform, `${v.name}: platform mismatch`).toBe(want);
    }
  });

  it('rejects wrong challenge', async () => {
    if (!vectors) return;

    const v = vectors[0];
    const parsed = parse(v.attestation);
    const wrongChallenge = new Uint8Array(32); // all zeros
    await expect(verifyTPM(parsed, wrongChallenge, v.extraData)).rejects.toThrow(/mismatch/);
  });
});

// =============================================================================
// VerifyBoundTEE Tests
// =============================================================================

describe('verifyBoundTEE', () => {
  it('verifies TDX and SEV-SNP vectors, rejects Shielded VM', async () => {
    if (!vectors) return;

    for (const v of vectors) {
      const parsed = parse(v.attestation);
      const want = expectedPlatform(v.platform);

      if (want === Platform.GCPShieldedVM) {
        await expect(
          verifyBoundTEE(parsed, v.challenge, v.extraData),
        ).rejects.toThrow(/not available/);
      } else {
        const result = await verifyBoundTEE(parsed, v.challenge, v.extraData);
        expect(result.platform, `${v.name}: platform mismatch`).toBe(want);
      }
    }
  });
});

// =============================================================================
// ExtractTPMClaims Tests
// =============================================================================

describe('extractTPMClaims', () => {
  it('extracts claims for all test vectors', async () => {
    if (!vectors) return;

    for (const v of vectors) {
      const parsed = parse(v.attestation);
      const tpmResult = await verifyTPM(parsed, v.challenge, v.extraData);
      const claims = extractTPMClaims(tpmResult, { pcrIndices: [0, 4, 8, 9] });

      const want = expectedPlatform(v.platform);
      expect(claims.platform, `${v.name}: platform mismatch`).toBe(want);
      expect(claims.hardened, `${v.name}: hardened mismatch`).toBe(v.hardened);
      expect(claims.pcrs.size, `${v.name}: expected 4 PCRs`).toBe(4);

      for (const idx of [0, 4, 8, 9]) {
        expect(claims.pcrs.has(idx), `${v.name}: PCR ${idx} missing`).toBe(true);
      }
    }
  });

  it('rejects invalid PCR index', async () => {
    if (!vectors) return;

    const v = vectors[0];
    const parsed = parse(v.attestation);
    const tpmResult = await verifyTPM(parsed, v.challenge, v.extraData);

    expect(() => extractTPMClaims(tpmResult, { pcrIndices: [24] })).toThrow(/invalid PCR index/);
  });
});

// =============================================================================
// ExtractTEEClaims Tests
// =============================================================================

describe('extractTEEClaims', () => {
  it('extracts TDX and SEV-SNP claims', async () => {
    if (!vectors) return;

    for (const v of vectors) {
      const want = expectedPlatform(v.platform);
      if (want === Platform.GCPShieldedVM) continue;

      const parsed = parse(v.attestation);
      const teeResult = await verifyBoundTEE(parsed, v.challenge, v.extraData);
      const claims = extractTEEClaims(teeResult);

      expect(claims.platform, `${v.name}: platform mismatch`).toBe(want);

      if (want === Platform.IntelTDX) {
        expect(claims.tdx, `${v.name}: expected TDX claims`).toBeDefined();
        expect(claims.sevSnp, `${v.name}: unexpected SEV-SNP claims`).toBeUndefined();
      } else if (want === Platform.AMDSevSnp) {
        expect(claims.sevSnp, `${v.name}: expected SEV-SNP claims`).toBeDefined();
        expect(claims.tdx, `${v.name}: unexpected TDX claims`).toBeUndefined();
      }
    }
  });

  it('rejects Shielded VM', () => {
    // Construct a minimal verified TEE attestation with Shielded VM
    // This is a programming error path — verifyBoundTEE already rejects it
    const fakeVerified = {
      platform: Platform.GCPShieldedVM,
      extraData: new Uint8Array(0),
      proto: fromBinary(AttestationSchema, new Uint8Array(0)),
    };
    expect(() => extractTEEClaims(fakeVerified)).toThrow(/no TEE claims available/);
  });
});

// =============================================================================
// ExtractContainerClaims Tests
// =============================================================================

describe('extractContainerClaims', () => {
  it('extracts container info from canonical event log', () => {
    if (!vectors) return;

    for (const v of vectors) {
      const parsed = parse(v.attestation);

      // Check if this vector has a canonical event log
      if (parsed.proto.canonicalEventLog.length === 0) continue;

      const container = extractContainerClaims(parsed);
      expect(container.imageReference, `${v.name}: expected non-empty imageReference`).not.toBe('');
      expect(container.imageDigest, `${v.name}: expected non-empty imageDigest`).not.toBe('');
    }
  });
});

// =============================================================================
// Anti-Downgrade Tests
// =============================================================================

describe('anti-downgrade protection', () => {
  it('rejects stripped TEE quote (nonce mismatch)', async () => {
    if (!vectors) return;

    for (const v of vectors) {
      const want = expectedPlatform(v.platform);
      if (want === Platform.GCPShieldedVM) continue; // already shielded VM

      // Deserialize, strip TEE attestation, re-serialize
      const proto = fromBinary(AttestationSchema, v.attestation);
      proto.teeAttestation = { case: undefined, value: undefined };

      // Re-serialize by importing toBinary
      const { toBinary } = await import('@bufbuild/protobuf');
      const stripped = toBinary(AttestationSchema, proto);

      const att = parse(stripped);
      expect(att.platform, `${v.name}: expected Shielded VM after stripping`).toBe(Platform.GCPShieldedVM);

      // VerifyTPM must fail: quote was signed with original platform tag
      await expect(
        verifyTPM(att, v.challenge, v.extraData),
      ).rejects.toThrow(/mismatch/);
    }
  });
});

// =============================================================================
// Platform Tag Tests
// =============================================================================

describe('platformTag', () => {
  it('returns correct tags', () => {
    expect(platformTag(Platform.IntelTDX)).toBe('INTEL_TDX');
    expect(platformTag(Platform.AMDSevSnp)).toBe('AMD_SEV_SNP');
    expect(platformTag(Platform.GCPShieldedVM)).toBe('GCP_SHIELDED_VM');
  });

  it('throws for unknown platform', () => {
    expect(() => platformTag(Platform.Unknown)).toThrow();
  });
});
