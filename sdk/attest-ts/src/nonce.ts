import { createHash } from 'node:crypto';

/** Domain separator used in nonce computation. */
const WORKLOAD_ATTESTATION_LABEL = 'WORKLOAD_ATTESTATION';

/**
 * Derives a 32-byte nonce for TPM quotes.
 *
 * SHA256(label || platformTag || SHA256(challenge) || SHA256(extraData)?)
 *
 * The platformTag commits the detected platform into the TPM nonce, preventing
 * anti-downgrade attacks where a TEE quote is stripped to appear as Shielded VM.
 */
export function computeTPMNonce(
  challenge: Uint8Array,
  platformTag: string,
  extraData?: Uint8Array,
): Uint8Array {
  const h = createHash('sha256');
  h.update(WORKLOAD_ATTESTATION_LABEL);
  h.update(platformTag);
  h.update(createHash('sha256').update(challenge).digest());
  if (extraData && extraData.length > 0) {
    h.update(createHash('sha256').update(extraData).digest());
  }
  return new Uint8Array(h.digest());
}

/**
 * Derives a 64-byte nonce for TEE ReportData.
 *
 * SHA512(label || SHA512(challenge) || SHA512(akPubDER) || SHA512(extraData)?)
 *
 * Binds the TEE hardware quote to the TPM's AK public key.
 */
export function computeBoundNonce(
  challenge: Uint8Array,
  akPubDER: Uint8Array,
  extraData?: Uint8Array,
): Uint8Array {
  const h = createHash('sha512');
  h.update(WORKLOAD_ATTESTATION_LABEL);
  h.update(createHash('sha512').update(challenge).digest());
  h.update(createHash('sha512').update(akPubDER).digest());
  if (extraData && extraData.length > 0) {
    h.update(createHash('sha512').update(extraData).digest());
  }
  return new Uint8Array(h.digest());
}
