// @layr-labs/attest - TypeScript TEE attestation verification SDK

// Core attestation API
export { parse, verifyTPM, verifyBoundTEE, extractContainerClaims } from './attestation.js';

// Claims extraction
export { extractTPMClaims, extractTEEClaims } from './extract.js';

// Firmware endorsement verification
export { verifyMRTD, verifySevSnpMeasurement, fetchRootsOfTrust, tdxObjectName, sevSnpObjectName, gceTcbURL } from './firmware.js';

// Nonce computation (for callers who generate attestations)
export { computeTPMNonce, computeBoundNonce } from './nonce.js';

// Types
export { Platform, platformTag, parseSevSnpPolicy } from './types.js';
export type {
  ParsedAttestation,
  VerifiedTPMAttestation,
  VerifiedTEEAttestation,
  ExtractOptions,
  TPMClaims,
  TEEClaims,
  TDXClaims,
  TDAttributes,
  SevSnpClaims,
  SevSnpPolicy,
  ContainerInfo,
  GCEInfo,
  FirmwareEndorsement,
} from './types.js';
