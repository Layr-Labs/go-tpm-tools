import { describe, it, expect } from 'vitest';
import { computeTPMNonce, computeBoundNonce } from '../src/nonce.js';
import { createHash } from 'node:crypto';

describe('computeTPMNonce', () => {
  it('produces a 32-byte SHA-256 nonce', () => {
    const challenge = new Uint8Array([1, 2, 3, 4]);
    const result = computeTPMNonce(challenge, 'INTEL_TDX');
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBe(32);
  });

  it('includes platform tag in computation (different tags produce different nonces)', () => {
    const challenge = new Uint8Array([1, 2, 3, 4]);
    const tdx = computeTPMNonce(challenge, 'INTEL_TDX');
    const sev = computeTPMNonce(challenge, 'AMD_SEV_SNP');
    const shielded = computeTPMNonce(challenge, 'GCP_SHIELDED_VM');
    expect(Buffer.from(tdx).equals(Buffer.from(sev))).toBe(false);
    expect(Buffer.from(tdx).equals(Buffer.from(shielded))).toBe(false);
    expect(Buffer.from(sev).equals(Buffer.from(shielded))).toBe(false);
  });

  it('includes extraData when provided', () => {
    const challenge = new Uint8Array([1, 2, 3, 4]);
    const noExtra = computeTPMNonce(challenge, 'INTEL_TDX');
    const withExtra = computeTPMNonce(challenge, 'INTEL_TDX', new Uint8Array([5, 6]));
    expect(Buffer.from(noExtra).equals(Buffer.from(withExtra))).toBe(false);
  });

  it('treats empty extraData same as no extraData', () => {
    const challenge = new Uint8Array([1, 2, 3, 4]);
    const noExtra = computeTPMNonce(challenge, 'INTEL_TDX');
    const emptyExtra = computeTPMNonce(challenge, 'INTEL_TDX', new Uint8Array(0));
    expect(Buffer.from(noExtra).equals(Buffer.from(emptyExtra))).toBe(true);
  });

  it('matches manual computation: SHA256(label || tag || SHA256(challenge))', () => {
    const challenge = new Uint8Array([0xaa, 0xbb, 0xcc]);
    const tag = 'INTEL_TDX';

    // Manual computation
    const challengeDigest = createHash('sha256').update(challenge).digest();
    const expected = createHash('sha256')
      .update('WORKLOAD_ATTESTATION')
      .update(tag)
      .update(challengeDigest)
      .digest();

    const result = computeTPMNonce(challenge, tag);
    expect(Buffer.from(result)).toEqual(expected);
  });
});

describe('computeBoundNonce', () => {
  it('produces a 64-byte SHA-512 nonce', () => {
    const challenge = new Uint8Array([1, 2, 3, 4]);
    const akPubDER = new Uint8Array([10, 20, 30, 40]);
    const result = computeBoundNonce(challenge, akPubDER);
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBe(64);
  });

  it('binds to AK public key (different keys produce different nonces)', () => {
    const challenge = new Uint8Array([1, 2, 3]);
    const ak1 = new Uint8Array([10, 20, 30]);
    const ak2 = new Uint8Array([40, 50, 60]);
    const nonce1 = computeBoundNonce(challenge, ak1);
    const nonce2 = computeBoundNonce(challenge, ak2);
    expect(Buffer.from(nonce1).equals(Buffer.from(nonce2))).toBe(false);
  });

  it('includes extraData when provided', () => {
    const challenge = new Uint8Array([1, 2, 3]);
    const akPubDER = new Uint8Array([10, 20, 30]);
    const noExtra = computeBoundNonce(challenge, akPubDER);
    const withExtra = computeBoundNonce(challenge, akPubDER, new Uint8Array([5, 6]));
    expect(Buffer.from(noExtra).equals(Buffer.from(withExtra))).toBe(false);
  });

  it('treats empty extraData same as no extraData', () => {
    const challenge = new Uint8Array([1, 2, 3]);
    const akPubDER = new Uint8Array([10, 20, 30]);
    const noExtra = computeBoundNonce(challenge, akPubDER);
    const emptyExtra = computeBoundNonce(challenge, akPubDER, new Uint8Array(0));
    expect(Buffer.from(noExtra).equals(Buffer.from(emptyExtra))).toBe(true);
  });

  it('matches manual computation: SHA512(label || SHA512(challenge) || SHA512(ak))', () => {
    const challenge = new Uint8Array([0xaa, 0xbb]);
    const akPubDER = new Uint8Array([0xcc, 0xdd]);

    const challengeDigest = createHash('sha512').update(challenge).digest();
    const akDigest = createHash('sha512').update(akPubDER).digest();
    const expected = createHash('sha512')
      .update('WORKLOAD_ATTESTATION')
      .update(challengeDigest)
      .update(akDigest)
      .digest();

    const result = computeBoundNonce(challenge, akPubDER);
    expect(Buffer.from(result)).toEqual(expected);
  });
});
