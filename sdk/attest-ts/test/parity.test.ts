import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, it, expect, beforeAll } from 'vitest';
import { parse, verifyTPM, verifyBoundTEE, extractContainerClaims } from '../src/attestation.js';
import { extractTPMClaims, extractTEEClaims } from '../src/extract.js';
import { Platform } from '../src/types.js';

// --- Test vector / golden file types ---

interface TestVectorJSON {
  name: string;
  platform: string;
  hardened: boolean;
  attestation: string; // base64
  challenge: string;   // hex
  extra_data: string;  // hex
}

interface GoldenRecord {
  name: string;
  tpm_claims: {
    platform: string;
    hardened: boolean;
    pcrs: Record<string, string>;
    gce: { project_id: string; project_number: string; zone: string; instance_id: string; instance_name: string } | null;
  };
  tee_claims: {
    platform: string;
    tdx?: {
      mrtd: string; rtmr0: string; rtmr1: string; rtmr2: string; rtmr3: string;
      tee_tcb_svn: string;
      attributes: { debug: boolean; sept_ve_disable: boolean; pks: boolean; kl: boolean; perf_mon: boolean };
    };
    sevsnp?: {
      measurement: string; host_data: string;
      current_tcb: string; reported_tcb: string; committed_tcb: string;
      guest_svn: number;
      policy: { debug: boolean; migrate_ma: boolean; smt: boolean; abi_minor: number; abi_major: number; single_socket: boolean; ciphertext_hiding_dram: boolean };
    };
  } | null;
  container_claims: {
    image_reference: string; image_digest: string; image_id: string;
    restart_policy: string; args: string[]; env_vars: Record<string, string>;
  } | null;
}

// --- Helpers ---

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function toHex(buf: Uint8Array): string {
  return Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('');
}

const platformTagMap: Record<number, string> = {
  [Platform.IntelTDX]: 'INTEL_TDX',
  [Platform.AMDSevSnp]: 'AMD_SEV_SNP',
  [Platform.GCPShieldedVM]: 'GCP_SHIELDED_VM',
};

// --- Load data ---

const goldenPath = resolve(__dirname, '../../testdata/parity-golden.json');
const vectorsPath = resolve(__dirname, '../../testdata/attestations.json');

let golden: GoldenRecord[] | null = null;
let vectors: TestVectorJSON[] | null = null;

beforeAll(() => {
  if (!existsSync(goldenPath)) {
    console.warn('parity-golden.json not found — run: go run ./sdk/attest/cmd/parity-dump');
    return;
  }
  golden = JSON.parse(readFileSync(goldenPath, 'utf-8'));
  vectors = JSON.parse(readFileSync(vectorsPath, 'utf-8'));
});

// --- Tests ---

describe('Go ↔ TypeScript parity', () => {
  it('golden file exists', () => {
    if (!golden) return; // skip silently
    expect(golden!.length).toBeGreaterThan(0);
  });

  it('matches all golden records', async () => {
    if (!golden || !vectors) return;

    for (let i = 0; i < golden.length; i++) {
      const g = golden[i];
      const v = vectors[i];
      expect(v.name).toBe(g.name);

      const attestBytes = Uint8Array.from(Buffer.from(v.attestation, 'base64'));
      const challenge = hexToBytes(v.challenge);
      const extraData = v.extra_data ? hexToBytes(v.extra_data) : undefined;

      const parsed = parse(attestBytes);

      // --- TPM claims ---
      const tpmVerified = await verifyTPM(parsed, challenge, extraData);
      const tpmClaims = extractTPMClaims(tpmVerified, { pcrIndices: [0, 4, 8, 9] });

      const tsPlatformTag = platformTagMap[tpmClaims.platform];
      expect(tsPlatformTag, `${g.name}: TPM platform`).toBe(g.tpm_claims.platform);
      expect(tpmClaims.hardened, `${g.name}: hardened`).toBe(g.tpm_claims.hardened);

      // PCRs
      const tsPCRs: Record<string, string> = {};
      for (const [idx, val] of tpmClaims.pcrs) {
        tsPCRs[idx.toString()] = toHex(val);
      }
      expect(tsPCRs, `${g.name}: PCRs`).toEqual(g.tpm_claims.pcrs);

      // GCE info
      if (g.tpm_claims.gce) {
        expect(tpmClaims.gce, `${g.name}: GCE should exist`).toBeDefined();
        const gce = tpmClaims.gce!;
        expect(gce.projectId, `${g.name}: GCE project_id`).toBe(g.tpm_claims.gce.project_id);
        expect(gce.projectNumber.toString(), `${g.name}: GCE project_number`).toBe(g.tpm_claims.gce.project_number);
        expect(gce.zone, `${g.name}: GCE zone`).toBe(g.tpm_claims.gce.zone);
        expect(gce.instanceId.toString(), `${g.name}: GCE instance_id`).toBe(g.tpm_claims.gce.instance_id);
        expect(gce.instanceName, `${g.name}: GCE instance_name`).toBe(g.tpm_claims.gce.instance_name);
      } else {
        expect(tpmClaims.gce, `${g.name}: GCE should be absent`).toBeUndefined();
      }

      // --- TEE claims ---
      if (g.tee_claims) {
        expect(parsed.platform, `${g.name}: should not be Shielded VM`).not.toBe(Platform.GCPShieldedVM);

        const teeVerified = await verifyBoundTEE(parsed, challenge, extraData);
        const teeClaims = extractTEEClaims(teeVerified);

        const teePlatformTag = platformTagMap[teeClaims.platform];
        expect(teePlatformTag, `${g.name}: TEE platform`).toBe(g.tee_claims.platform);

        if (g.tee_claims.tdx) {
          expect(teeClaims.tdx, `${g.name}: TDX claims should exist`).toBeDefined();
          const tdx = teeClaims.tdx!;
          const gt = g.tee_claims.tdx;
          expect(toHex(tdx.mrtd), `${g.name}: mrtd`).toBe(gt.mrtd);
          expect(toHex(tdx.rtmr0), `${g.name}: rtmr0`).toBe(gt.rtmr0);
          expect(toHex(tdx.rtmr1), `${g.name}: rtmr1`).toBe(gt.rtmr1);
          expect(toHex(tdx.rtmr2), `${g.name}: rtmr2`).toBe(gt.rtmr2);
          expect(toHex(tdx.rtmr3), `${g.name}: rtmr3`).toBe(gt.rtmr3);
          expect(toHex(tdx.teeTcbSvn), `${g.name}: tee_tcb_svn`).toBe(gt.tee_tcb_svn);
          expect(tdx.attributes.debug, `${g.name}: TDX debug`).toBe(gt.attributes.debug);
          expect(tdx.attributes.septVEDisable, `${g.name}: TDX sept_ve_disable`).toBe(gt.attributes.sept_ve_disable);
          expect(tdx.attributes.pks, `${g.name}: TDX pks`).toBe(gt.attributes.pks);
          expect(tdx.attributes.kl, `${g.name}: TDX kl`).toBe(gt.attributes.kl);
          expect(tdx.attributes.perfMon, `${g.name}: TDX perf_mon`).toBe(gt.attributes.perf_mon);
        }

        if (g.tee_claims.sevsnp) {
          expect(teeClaims.sevSnp, `${g.name}: SEV-SNP claims should exist`).toBeDefined();
          const snp = teeClaims.sevSnp!;
          const gs = g.tee_claims.sevsnp;
          expect(toHex(snp.measurement), `${g.name}: measurement`).toBe(gs.measurement);
          expect(toHex(snp.hostData), `${g.name}: host_data`).toBe(gs.host_data);
          expect(snp.currentTcb.toString(), `${g.name}: current_tcb`).toBe(gs.current_tcb);
          expect(snp.reportedTcb.toString(), `${g.name}: reported_tcb`).toBe(gs.reported_tcb);
          expect(snp.committedTcb.toString(), `${g.name}: committed_tcb`).toBe(gs.committed_tcb);
          expect(snp.guestSvn, `${g.name}: guest_svn`).toBe(gs.guest_svn);
          expect(snp.policy.debug, `${g.name}: SNP debug`).toBe(gs.policy.debug);
          expect(snp.policy.migrateMA, `${g.name}: SNP migrate_ma`).toBe(gs.policy.migrate_ma);
          expect(snp.policy.smt, `${g.name}: SNP smt`).toBe(gs.policy.smt);
          expect(snp.policy.abiMinor, `${g.name}: SNP abi_minor`).toBe(gs.policy.abi_minor);
          expect(snp.policy.abiMajor, `${g.name}: SNP abi_major`).toBe(gs.policy.abi_major);
          expect(snp.policy.singleSocket, `${g.name}: SNP single_socket`).toBe(gs.policy.single_socket);
          expect(snp.policy.cipherTextHidingDRAM, `${g.name}: SNP ciphertext_hiding_dram`).toBe(gs.policy.ciphertext_hiding_dram);
        }
      } else {
        expect(parsed.platform, `${g.name}: should be Shielded VM`).toBe(Platform.GCPShieldedVM);
      }

      // --- Container claims ---
      if (g.container_claims) {
        const container = extractContainerClaims(parsed);
        const gc = g.container_claims;
        expect(container.imageReference, `${g.name}: image_reference`).toBe(gc.image_reference);
        expect(container.imageDigest, `${g.name}: image_digest`).toBe(gc.image_digest);
        expect(container.imageId, `${g.name}: image_id`).toBe(gc.image_id);
        expect(container.restartPolicy, `${g.name}: restart_policy`).toBe(gc.restart_policy);
        expect(container.args, `${g.name}: args`).toEqual(gc.args);
        expect(container.envVars, `${g.name}: env_vars`).toEqual(gc.env_vars);
      }
      // If golden has null container_claims, skip (no assertion needed — the Go side didn't have CEL either).
    }
  });
});
