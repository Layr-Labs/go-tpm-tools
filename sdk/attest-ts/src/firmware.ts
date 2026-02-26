import { X509Certificate, verify as cryptoVerify, createPublicKey } from 'node:crypto';
import { fromBinary } from '@bufbuild/protobuf';
import {
  VMLaunchEndorsementSchema,
  VMGoldenMeasurementSchema,
} from './proto/endorsement_pb.js';
import type { VMGoldenMeasurement } from './proto/endorsement_pb.js';
import { Platform } from './types.js';
import type { FirmwareEndorsement } from './types.js';

/**
 * Base URL for Google's GCE TCB integrity endorsements.
 * From gce-tcb-verifier/verify/verify.go.
 */
const GCE_TCB_BASE_URL = 'https://storage.googleapis.com/gce_tcb_integrity/';

/**
 * URL to fetch Google's GCE TCB root certificate.
 * From gce-tcb-verifier/gcetcbendorsement/gcetcbendorsement.go.
 */
const DEFAULT_ROOT_URL = 'https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt';

/**
 * GCE UEFI family ID for SEV-SNP endorsements.
 * From go-sev-guest/abi/abi.go (sev.GCEUefiFamilyID).
 * This is the 16-byte family_id embedded in GCE's SEV-SNP UEFI firmware.
 */
const GCE_UEFI_FAMILY_ID = new Uint8Array([
  0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

// Cached root of trust (module-level singleton)
let cachedRootCert: X509Certificate | null = null;

/**
 * Compute the GCS object name for a TDX MRTD measurement.
 * Port of extracttdx.GCETcbObjectName from gce-tcb-verifier.
 */
export function tdxObjectName(mrtd: Uint8Array): string {
  return `tdx/${hexEncode(mrtd)}`;
}

/**
 * Compute the GCS object name for a SEV-SNP measurement.
 * Port of extractsev.GCETcbObjectName from gce-tcb-verifier.
 */
export function sevSnpObjectName(measurement: Uint8Array): string {
  return `sevsnp/${hexEncode(GCE_UEFI_FAMILY_ID)}_${hexEncode(measurement)}`;
}

/**
 * Construct the full endorsement URL from an object name.
 * Port of tcbv.GCETcbURL from gce-tcb-verifier.
 */
export function gceTcbURL(objectName: string): string {
  return `${GCE_TCB_BASE_URL}${objectName}`;
}

/**
 * Verify that a TDX MRTD value is endorsed by Google.
 * Fetches the endorsement from Google's TCB bucket, verifies the signature
 * chain, and confirms the MRTD matches a golden measurement.
 *
 * Port of attest.VerifyMRTD from Go.
 */
export async function verifyMRTD(mrtd: Uint8Array): Promise<FirmwareEndorsement> {
  validateMeasurement(mrtd);
  const rootCert = await getRootsOfTrust();
  const objectName = tdxObjectName(mrtd);
  return verifyMeasurementEndorsement(objectName, mrtd, Platform.IntelTDX, rootCert);
}

/**
 * Verify that a SEV-SNP MEASUREMENT is endorsed by Google.
 * Fetches the endorsement from Google's TCB bucket, verifies the signature
 * chain, and confirms the measurement matches a golden value.
 *
 * Port of attest.VerifySevSnpMeasurement from Go.
 */
export async function verifySevSnpMeasurement(measurement: Uint8Array): Promise<FirmwareEndorsement> {
  validateMeasurement(measurement);
  const rootCert = await getRootsOfTrust();
  const objectName = sevSnpObjectName(measurement);
  return verifyMeasurementEndorsement(objectName, measurement, Platform.AMDSevSnp, rootCert);
}

// --- Internal helpers ---

function validateMeasurement(measurement: Uint8Array): void {
  if (measurement.length !== 48) {
    throw new Error(`measurement must be 48 bytes (SHA-384), got ${measurement.length}`);
  }
}

async function verifyMeasurementEndorsement(
  objectName: string,
  measurement: Uint8Array,
  platform: Platform,
  rootCert: X509Certificate,
): Promise<FirmwareEndorsement> {
  const techName = platform === Platform.IntelTDX ? 'TDX MRTD' : 'SEV-SNP MEASUREMENT';
  const measurementHex = hexEncode(measurement);

  // Fetch endorsement from Google's GCE TCB integrity bucket
  const url = gceTcbURL(objectName);
  let endorsementBytes: Uint8Array;
  try {
    endorsementBytes = await fetchFromURL(url);
  } catch (err) {
    throw new Error(
      `${techName} ${measurementHex} not found in Google's endorsements - firmware not endorsed: ${err instanceof Error ? err.message : err}`,
    );
  }

  // Parse and verify the endorsement
  return verifyEndorsement(endorsementBytes, measurement, platform, rootCert);
}

/**
 * Parse and verify an endorsement protobuf.
 * 1. Deserialize VMLaunchEndorsement
 * 2. Deserialize VMGoldenMeasurement from serialized_uefi_golden
 * 3. Verify signature over serialized_uefi_golden using the signing cert
 * 4. Verify the signing cert chains to the trusted root
 * 5. Match measurement against golden measurement list
 * 6. Return extracted firmware info
 */
function verifyEndorsement(
  endorsementBytes: Uint8Array,
  expectedMeasurement: Uint8Array,
  platform: Platform,
  rootCert: X509Certificate,
): FirmwareEndorsement {
  // 1. Parse VMLaunchEndorsement
  const endorsement = fromBinary(VMLaunchEndorsementSchema, endorsementBytes);

  // 2. Parse VMGoldenMeasurement from the signed payload
  const golden = fromBinary(VMGoldenMeasurementSchema, endorsement.serializedUefiGolden);

  // 3. Verify signature over serialized_uefi_golden
  verifyEndorsementSignature(
    endorsement.serializedUefiGolden,
    endorsement.signature,
    golden,
    rootCert,
  );

  // 4. Match measurement and extract info
  switch (platform) {
    case Platform.IntelTDX:
      return extractTdxEndorsement(golden, expectedMeasurement);
    case Platform.AMDSevSnp:
      return extractSevSnpEndorsement(golden, expectedMeasurement);
    default:
      throw new Error(`unsupported platform: ${platform}`);
  }
}

/**
 * Verify the endorsement signature and certificate chain.
 *
 * The signing cert is in golden.cert (DER), the CA bundle in golden.caBundle (PEM).
 * Chain: signingCert → intermediates (ca_bundle) → rootCert
 */
function verifyEndorsementSignature(
  signedData: Uint8Array,
  signature: Uint8Array,
  golden: VMGoldenMeasurement,
  rootCert: X509Certificate,
): void {
  if (golden.cert.length === 0) {
    throw new Error('endorsement golden measurement has no signing certificate');
  }

  // Parse signing cert (DER)
  const signingCert = new X509Certificate(golden.cert);

  // Verify the signing cert chains to root
  // Parse intermediate certs from PEM ca_bundle
  const intermediates = parsePEMBundle(golden.caBundle);
  verifyCertChain(signingCert, intermediates, rootCert);

  // Verify the signature over the serialized golden measurement bytes
  const pubKey = createPublicKey(signingCert.publicKey);
  const valid = cryptoVerify(null, signedData, pubKey, signature);
  if (!valid) {
    throw new Error('endorsement signature verification failed');
  }
}

/**
 * Verify a certificate chains to the trusted root via intermediates.
 */
function verifyCertChain(
  leaf: X509Certificate,
  intermediates: X509Certificate[],
  root: X509Certificate,
): void {
  // Build ordered chain: leaf → intermediates → root
  const chain = [leaf, ...intermediates];

  // Verify each link in the chain
  for (let i = 0; i < chain.length; i++) {
    const cert = chain[i];
    const issuer = i + 1 < chain.length ? chain[i + 1] : root;

    // Verify cert was signed by issuer
    if (!cert.checkIssued(issuer)) {
      throw new Error(
        `certificate chain verification failed: cert[${i}] not issued by expected issuer`,
      );
    }

    // Check validity period
    const now = new Date();
    if (now < new Date(cert.validFrom) || now > new Date(cert.validTo)) {
      throw new Error(`certificate chain verification failed: cert[${i}] is expired or not yet valid`);
    }
  }

  // Verify root is self-signed (sanity check)
  if (!root.checkIssued(root)) {
    throw new Error('root certificate is not self-signed');
  }
}

/**
 * Parse PEM-encoded certificate bundle into X509Certificate array.
 */
function parsePEMBundle(pemBytes: Uint8Array): X509Certificate[] {
  if (pemBytes.length === 0) return [];

  const pemStr = new TextDecoder().decode(pemBytes);
  const certs: X509Certificate[] = [];
  const regex = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  let match;
  while ((match = regex.exec(pemStr)) !== null) {
    certs.push(new X509Certificate(match[0]));
  }
  return certs;
}

function extractTdxEndorsement(
  golden: VMGoldenMeasurement,
  expectedMRTD: Uint8Array,
): FirmwareEndorsement {
  const tdx = golden.tdx;
  if (!tdx) {
    throw new Error('endorsement does not contain TDX measurements');
  }

  const found = tdx.measurements.some((m) => bytesEqual(m.mrtd, expectedMRTD));
  if (!found) {
    throw new Error('MRTD does not match any measurement in endorsement');
  }

  return {
    svn: tdx.svn,
    uefiDigest: golden.digest,
    clSpec: golden.clSpec,
    timestamp: golden.timestamp ? new Date(Number(golden.timestamp.seconds) * 1000) : new Date(0),
  };
}

function extractSevSnpEndorsement(
  golden: VMGoldenMeasurement,
  expectedMeasurement: Uint8Array,
): FirmwareEndorsement {
  const sevsnp = golden.sevSnp;
  if (!sevsnp) {
    throw new Error('endorsement does not contain SEV-SNP measurements');
  }

  const found = Object.values(sevsnp.measurements).some((m) => bytesEqual(m, expectedMeasurement));
  if (!found) {
    throw new Error('MEASUREMENT does not match any measurement in endorsement');
  }

  return {
    svn: sevsnp.svn,
    uefiDigest: golden.digest,
    clSpec: golden.clSpec,
    timestamp: golden.timestamp ? new Date(Number(golden.timestamp.seconds) * 1000) : new Date(0),
  };
}

async function fetchFromURL(url: string): Promise<Uint8Array> {
  const resp = await fetch(url);
  if (!resp.ok) {
    throw new Error(`HTTP ${resp.status} from ${url}`);
  }
  return new Uint8Array(await resp.arrayBuffer());
}

/**
 * Fetch and cache Google's TCB root certificate.
 */
async function getRootsOfTrust(): Promise<X509Certificate> {
  if (cachedRootCert) {
    return cachedRootCert;
  }

  const resp = await fetch(DEFAULT_ROOT_URL);
  if (!resp.ok) {
    throw new Error(`failed to fetch TCB root certificate: HTTP ${resp.status}`);
  }

  const data = new Uint8Array(await resp.arrayBuffer());

  // Try parsing as DER first, then PEM
  try {
    cachedRootCert = new X509Certificate(data);
  } catch {
    const pemStr = new TextDecoder().decode(data);
    cachedRootCert = new X509Certificate(pemStr);
  }

  return cachedRootCert;
}

/**
 * Fetch and cache Google's TCB root certificate (public API for testing).
 */
export async function fetchRootsOfTrust(): Promise<X509Certificate> {
  return getRootsOfTrust();
}

function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
