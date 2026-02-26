import { X509Certificate } from 'node:crypto';
import * as peculiarX509 from '@peculiar/x509';

/** GCE EK/AK root and intermediate CA certificates (DER, base64-encoded). */

const TPM_EK_ROOT_1 =
  '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';

const GCP_EK_AK_CA_ROOT =
  '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';

const GCP_EK_AK_CA_INTERMEDIATE_V3 =
  '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';

function parseDERCert(b64: string): X509Certificate {
  const der = Buffer.from(b64, 'base64');
  return new X509Certificate(der);
}

/** All GCE EK root certificates. */
export const GCE_EK_ROOTS: X509Certificate[] = [
  parseDERCert(TPM_EK_ROOT_1),
];

/** All GCE EK intermediate certificates. */
export const GCE_EK_INTERMEDIATES: X509Certificate[] = [
  parseDERCert(TPM_EK_ROOT_1), // Root also serves as intermediate in some chains
];

/** All GCP CAS EK roots. */
export const GCP_CAS_EK_ROOTS: X509Certificate[] = [
  parseDERCert(GCP_EK_AK_CA_ROOT),
];

/** All GCP CAS EK intermediates. */
export const GCP_CAS_EK_INTERMEDIATES: X509Certificate[] = [
  parseDERCert(GCP_EK_AK_CA_INTERMEDIATE_V3),
];

/** All trusted root certificates (GCE + GCP CAS). */
export const ALL_ROOTS: X509Certificate[] = [
  ...GCE_EK_ROOTS,
  ...GCP_CAS_EK_ROOTS,
];

/** All trusted intermediate certificates. */
export const ALL_INTERMEDIATES: X509Certificate[] = [
  ...GCP_CAS_EK_INTERMEDIATES,
];

/**
 * Verify an AK certificate chains to one of the trusted roots.
 * Uses @peculiar/x509 for chain building/validation.
 */
export async function verifyAKCert(
  akCertDER: Uint8Array,
  trustedRoots: X509Certificate[],
  intermediateCerts: X509Certificate[],
): Promise<void> {
  if (trustedRoots.length === 0) {
    throw new Error('no trusted root certificates provided');
  }

  const akCert = new X509Certificate(akCertDER);

  // Try to verify against each root + intermediate combination
  for (const root of trustedRoots) {
    // Direct chain: AK cert signed by root
    if (akCert.verify(root.publicKey)) {
      return;
    }

    // Intermediate chain: AK cert signed by intermediate, intermediate signed by root
    for (const intermediate of intermediateCerts) {
      if (akCert.verify(intermediate.publicKey) && intermediate.verify(root.publicKey)) {
        return;
      }
    }
  }

  throw new Error('AK certificate did not chain to a trusted root');
}

/**
 * Extract GCE instance info from AK certificate extensions.
 * Parses the custom GCE extension OID 1.3.6.1.4.1.11129.2.1.21.
 */
export function getGCEInstanceInfoFromCert(akCertDER: Uint8Array): {
  zone: string;
  projectId: string;
  projectNumber: bigint;
  instanceName: string;
  instanceId: bigint;
} | null {
  const akCert = new X509Certificate(akCertDER);
  // The GCE instance info is in a custom X.509 extension
  // OID: 1.3.6.1.4.1.11129.2.1.21
  // We parse the subjectAltName or custom extensions to find it
  // Node.js X509Certificate doesn't directly expose arbitrary extensions,
  // so we use the raw DER and parse manually.
  const info = parseGCEExtension(akCert);
  return info;
}

/** GCE instance identity extension OID. */
const GCE_INSTANCE_INFO_OID = '1.3.6.1.4.1.11129.2.1.21';

/**
 * Parse the GCE instance info extension from an AK certificate.
 *
 * OID 1.3.6.1.4.1.11129.2.1.21 contains ASN.1 DER:
 * SEQUENCE {
 *   UTF8String zone,
 *   INTEGER projectNumber,
 *   UTF8String projectId,
 *   INTEGER instanceId,
 *   UTF8String instanceName,
 *   [EXPLICIT OPTIONAL] SEQUENCE {
 *     [0] EXPLICIT INTEGER securityVersion,
 *     [1] EXPLICIT BOOLEAN isProduction
 *   }
 * }
 *
 * Port of server/verify.go getInstanceInfoFromExtensions.
 */
function parseGCEExtension(cert: X509Certificate): {
  zone: string;
  projectId: string;
  projectNumber: bigint;
  instanceName: string;
  instanceId: bigint;
} | null {
  // Use @peculiar/x509 to access the extension by OID
  const pCert = new peculiarX509.X509Certificate(cert.raw);
  const ext = pCert.extensions.find(e => e.type === GCE_INSTANCE_INFO_OID);
  if (!ext) return null;

  // Parse the ASN.1 DER value
  const asn1 = parseASN1Sequence(new Uint8Array(ext.value));
  if (asn1.length < 5) return null;

  const zone = decodeUTF8String(asn1[0]);
  const projectNumber = decodeASN1Integer(asn1[1]);
  const projectId = decodeUTF8String(asn1[2]);
  const instanceId = decodeASN1Integer(asn1[3]);
  const instanceName = decodeUTF8String(asn1[4]);

  // Reject negative values
  if (projectNumber < 0n || instanceId < 0n) return null;

  // Check SecurityProperties if present
  if (asn1.length > 5) {
    const secProps = parseSecurityProperties(asn1[5]);
    if (secProps && !secProps.isProduction) {
      return null; // Reject non-production instances (matches Go behavior)
    }
  }

  return { zone, projectId, projectNumber, instanceName, instanceId };
}

// --- ASN.1 DER parsing helpers ---

interface ASN1Element {
  tag: number;
  constructed: boolean;
  value: Uint8Array;
}

function parseASN1Element(data: Uint8Array, offset: number): { element: ASN1Element; nextOffset: number } {
  if (offset >= data.length) throw new Error('ASN.1: unexpected end of data');

  const tag = data[offset++];
  const constructed = (tag & 0x20) !== 0;

  // Parse length
  let length: number;
  if (offset >= data.length) throw new Error('ASN.1: unexpected end of data reading length');
  const lenByte = data[offset++];
  if (lenByte < 0x80) {
    length = lenByte;
  } else {
    const numLenBytes = lenByte & 0x7f;
    if (numLenBytes > 4) throw new Error('ASN.1: length too large');
    length = 0;
    for (let i = 0; i < numLenBytes; i++) {
      if (offset >= data.length) throw new Error('ASN.1: unexpected end of data reading length bytes');
      length = (length << 8) | data[offset++];
    }
  }

  if (offset + length > data.length) throw new Error('ASN.1: value extends beyond data');
  const value = data.subarray(offset, offset + length);

  return { element: { tag, constructed, value }, nextOffset: offset + length };
}

function parseASN1Sequence(data: Uint8Array): ASN1Element[] {
  const { element } = parseASN1Element(data, 0);
  if ((element.tag & 0x1f) !== 0x10 || !element.constructed) {
    throw new Error('ASN.1: expected SEQUENCE');
  }
  return parseASN1Children(element.value);
}

function parseASN1Children(data: Uint8Array): ASN1Element[] {
  const children: ASN1Element[] = [];
  let offset = 0;
  while (offset < data.length) {
    const result = parseASN1Element(data, offset);
    children.push(result.element);
    offset = result.nextOffset;
  }
  return children;
}

function decodeUTF8String(element: ASN1Element): string {
  // Accept both UTF8String (0x0C) and other string types
  return new TextDecoder().decode(element.value);
}

function decodeASN1Integer(element: ASN1Element): bigint {
  if ((element.tag & 0x1f) !== 0x02) {
    throw new Error(`ASN.1: expected INTEGER, got tag 0x${element.tag.toString(16)}`);
  }
  const bytes = element.value;
  if (bytes.length === 0) return 0n;

  // Check sign bit
  const negative = (bytes[0] & 0x80) !== 0;
  let result = 0n;
  for (const b of bytes) {
    result = (result << 8n) | BigInt(b);
  }

  if (negative) {
    // Two's complement for negative
    result -= 1n << BigInt(bytes.length * 8);
  }

  return result;
}

function parseSecurityProperties(element: ASN1Element): { securityVersion: bigint; isProduction: boolean } | null {
  // SecurityProperties is an explicit context-tagged SEQUENCE
  // containing [0] EXPLICIT INTEGER and [1] EXPLICIT BOOLEAN
  try {
    let innerData = element.value;
    // If this is a constructed context tag, unwrap it
    if (element.constructed) {
      const children = parseASN1Children(innerData);
      if (children.length === 0) return null;
      // The inner element should be a SEQUENCE
      const inner = children[0];
      if (inner.constructed) {
        innerData = inner.value;
      } else {
        return null;
      }
    }

    const fields = parseASN1Children(innerData);
    let securityVersion = 0n;
    let isProduction = false;

    for (const field of fields) {
      // Context-specific tags: [0] = securityVersion, [1] = isProduction
      const ctxTag = field.tag & 0x1f;
      if (ctxTag === 0 && field.constructed) {
        const inner = parseASN1Children(field.value);
        if (inner.length > 0) {
          securityVersion = decodeASN1Integer(inner[0]);
        }
      } else if (ctxTag === 1 && field.constructed) {
        const inner = parseASN1Children(field.value);
        if (inner.length > 0 && inner[0].value.length > 0) {
          isProduction = inner[0].value[0] !== 0;
        }
      }
    }

    return { securityVersion, isProduction };
  } catch {
    return null;
  }
}
