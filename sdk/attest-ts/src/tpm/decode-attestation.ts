import { BufferReader } from './buffer-reader.js';
import { TPM_GENERATED_VALUE, TpmSt } from './constants.js';

/** PCR selection from a quote. */
export interface PCRSelection {
  hash: number;  // TPM_ALG_ID
  pcrs: number[];
}

/** Decoded TPMS_ATTEST (attestation data from a TPM quote). */
export interface AttestationData {
  magic: number;
  type: number;
  qualifiedSigner: Uint8Array;
  extraData: Uint8Array;
  clock: bigint;
  resetCount: number;
  restartCount: number;
  safe: boolean;
  firmwareVersion: bigint;
  attested: QuoteInfo | null;
}

/** Decoded TPMS_QUOTE_INFO. */
export interface QuoteInfo {
  pcrSelection: PCRSelection;
  pcrDigest: Uint8Array;
}

/**
 * Decode TPMS_ATTEST from TPM wire format bytes.
 *
 * Binary layout:
 *   magic:            uint32 (must be 0xff544347)
 *   type:             uint16 (Tag — 0x8018 for quote)
 *   qualifiedSigner:  TPM2B_NAME (uint16 len + bytes)
 *   extraData:        TPM2B_DATA (uint16 len + bytes)
 *   clockInfo:        TPMS_CLOCK_INFO (8+4+4+1 = 17 bytes)
 *   firmwareVersion:  uint64
 *   attested:         TPMU_ATTEST (union, based on type)
 */
export function decodeAttestationData(data: Uint8Array): AttestationData {
  const r = new BufferReader(data);

  const magic = r.readUint32();
  if (magic !== TPM_GENERATED_VALUE) {
    throw new Error(
      `invalid magic: expected 0x${TPM_GENERATED_VALUE.toString(16)}, got 0x${magic.toString(16)}`,
    );
  }

  const type = r.readUint16();
  const qualifiedSigner = r.readSizedBuffer();
  const extraData = r.readSizedBuffer();

  // TPMS_CLOCK_INFO
  const clock = r.readUint64();
  const resetCount = r.readUint32();
  const restartCount = r.readUint32();
  const safe = r.readUint8() !== 0;

  const firmwareVersion = r.readUint64();

  // TPMU_ATTEST union
  let attested: QuoteInfo | null = null;
  if (type === TpmSt.AttestQuote) {
    attested = decodeQuoteInfo(r);
  }

  return {
    magic,
    type,
    qualifiedSigner,
    extraData,
    clock,
    resetCount,
    restartCount,
    safe,
    firmwareVersion,
    attested,
  };
}

/**
 * Decode TPMS_QUOTE_INFO from a BufferReader.
 *
 * Binary layout:
 *   TPML_PCR_SELECTION:
 *     count:   uint32
 *     per selection:
 *       hash:           uint16 (Algorithm)
 *       sizeofSelect:   uint8
 *       pcrSelect:      bytes[sizeofSelect] (bitmask)
 *   pcrDigest:  TPM2B_DIGEST (uint16 len + bytes)
 */
function decodeQuoteInfo(r: BufferReader): QuoteInfo {
  // TPML_PCR_SELECTION — we only need the first selection
  const count = r.readUint32();
  if (count === 0) {
    throw new Error('quote contains no PCR selections');
  }

  let pcrSelection: PCRSelection | null = null;
  for (let i = 0; i < count; i++) {
    const hash = r.readUint16();
    const sizeofSelect = r.readUint8();
    const selectBytes = r.readBytes(sizeofSelect);

    if (i === 0) {
      // Decode PCR bitmask
      const pcrs: number[] = [];
      for (let byteIdx = 0; byteIdx < selectBytes.length; byteIdx++) {
        for (let bitIdx = 0; bitIdx < 8; bitIdx++) {
          if (selectBytes[byteIdx] & (1 << bitIdx)) {
            pcrs.push(byteIdx * 8 + bitIdx);
          }
        }
      }
      pcrSelection = { hash, pcrs };
    }
  }

  const pcrDigest = r.readSizedBuffer();

  return {
    pcrSelection: pcrSelection!,
    pcrDigest,
  };
}
