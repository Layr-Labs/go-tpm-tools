import type { Attestation as AttestationProto } from './proto/layr_attest_pb.js';
import type { MachineState } from './proto/layr_attest_pb.js';

/** Platform represents the CVM technology type. */
export enum Platform {
  Unknown = -1,
  IntelTDX = 0,
  AMDSevSnp = 1,
  GCPShieldedVM = 2,
}

/** Platform tag constants for anti-downgrade protection in the TPM nonce. */
const platformTags: Record<Platform, string> = {
  [Platform.IntelTDX]: 'INTEL_TDX',
  [Platform.AMDSevSnp]: 'AMD_SEV_SNP',
  [Platform.GCPShieldedVM]: 'GCP_SHIELDED_VM',
  [Platform.Unknown]: '',
};

/** Returns the string tag used in TPM nonce computation. */
export function platformTag(p: Platform): string {
  const tag = platformTags[p];
  if (!tag) {
    throw new Error(`unknown platform: ${p}`);
  }
  return tag;
}

/** ExtractOptions configures claim extraction from a verified attestation. */
export interface ExtractOptions {
  /** PCR indices to extract (0-23). */
  pcrIndices: number[];
}

/** Parsed attestation ready for verification. */
export interface ParsedAttestation {
  platform: Platform;
  proto: AttestationProto;
}

/** Result of successful TPM verification. */
export interface VerifiedTPMAttestation {
  platform: Platform;
  extraData: Uint8Array;
  proto: AttestationProto;
  machineState: MachineState;
}

/** Result of successful TEE verification. */
export interface VerifiedTEEAttestation {
  platform: Platform;
  extraData: Uint8Array;
  proto: AttestationProto;
}

/** TEE-specific claims (TDX or SEV-SNP only). */
export interface TEEClaims {
  platform: Platform;
  tdx?: TDXClaims;
  sevSnp?: SevSnpClaims;
}

/** TPM-layer claims from a verified attestation. */
export interface TPMClaims {
  platform: Platform;
  hardened: boolean;
  gce?: GCEInfo;
  /** PCR index -> SHA-256 digest (32 bytes). */
  pcrs: Map<number, Uint8Array>;
}

/** Intel TDX claims from the TD Quote. */
export interface TDXClaims {
  mrtd: Uint8Array;       // 48 bytes
  rtmr0: Uint8Array;      // 48 bytes
  rtmr1: Uint8Array;      // 48 bytes
  rtmr2: Uint8Array;      // 48 bytes
  rtmr3: Uint8Array;      // 48 bytes
  teeTcbSvn: Uint8Array;  // 16 bytes
  attributes: TDAttributes;
}

/** TD attribute flags. */
export interface TDAttributes {
  debug: boolean;
  septVEDisable: boolean;
  pks: boolean;
  kl: boolean;
  perfMon: boolean;
}

/** AMD SEV-SNP claims from the attestation report. */
export interface SevSnpClaims {
  measurement: Uint8Array;  // 48 bytes
  hostData: Uint8Array;     // 32 bytes
  currentTcb: bigint;
  reportedTcb: bigint;
  committedTcb: bigint;
  guestSvn: number;
  policy: SevSnpPolicy;
}

/** SEV-SNP guest policy flags. */
export interface SevSnpPolicy {
  debug: boolean;
  migrateMA: boolean;
  smt: boolean;
  abiMinor: number;
  abiMajor: number;
  singleSocket: boolean;
  cipherTextHidingDRAM: boolean;
}

/** Container claims from COS CEL. */
export interface ContainerInfo {
  imageReference: string;
  imageDigest: string;
  imageId: string;
  restartPolicy: string;
  args: string[];
  envVars: Record<string, string>;
}

/** GCE instance metadata. */
export interface GCEInfo {
  projectId: string;
  projectNumber: bigint;
  zone: string;
  instanceId: bigint;
  instanceName: string;
}

/** Firmware endorsement verification result. */
export interface FirmwareEndorsement {
  svn: number;
  timestamp: Date;
  clSpec: bigint;
  uefiDigest: Uint8Array;  // SHA-384
}

/** Parse SEV-SNP guest policy from uint64 bitmask. */
export function parseSevSnpPolicy(guestPolicy: bigint): SevSnpPolicy {
  // Bit positions from go-sev-guest/abi/abi.go
  return {
    abiMinor: Number(guestPolicy & 0xffn),
    abiMajor: Number((guestPolicy >> 8n) & 0xffn),
    smt: (guestPolicy & (1n << 16n)) !== 0n,
    migrateMA: (guestPolicy & (1n << 18n)) !== 0n,
    debug: (guestPolicy & (1n << 19n)) !== 0n,
    singleSocket: (guestPolicy & (1n << 20n)) !== 0n,
    cipherTextHidingDRAM: (guestPolicy & (1n << 24n)) !== 0n,
  };
}
