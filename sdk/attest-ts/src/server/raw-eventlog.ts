import { createHash } from 'node:crypto';
import { hashAlgName } from '../tpm/constants.js';
import { create } from '@bufbuild/protobuf';
import type { Event, GrubState, LinuxKernelState, PlatformState, EfiState } from '../proto/layr_attest_pb.js';
import {
  EventSchema,
  GrubStateSchema,
  LinuxKernelStateSchema,
  PlatformStateSchema,
  EfiStateSchema,
  EfiAppSchema,
  GCEConfidentialTechnology,
} from '../proto/layr_attest_pb.js';
import { hashAlgDigestSize } from '../tpm/constants.js';

// --- Little-endian binary reader (TCG event logs use LE) ---

class LEReader {
  private view: DataView;
  private offset: number;

  constructor(data: Uint8Array) {
    this.view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    this.offset = 0;
  }

  remaining(): number { return this.view.byteLength - this.offset; }

  readUint16(): number {
    this.check(2);
    const val = this.view.getUint16(this.offset, true);
    this.offset += 2;
    return val;
  }

  readUint32(): number {
    this.check(4);
    const val = this.view.getUint32(this.offset, true);
    this.offset += 4;
    return val;
  }

  readUint8(): number {
    this.check(1);
    return this.view.getUint8(this.offset++);
  }

  readBytes(n: number): Uint8Array {
    this.check(n);
    const bytes = new Uint8Array(this.view.buffer, this.view.byteOffset + this.offset, n);
    this.offset += n;
    return new Uint8Array(bytes); // copy
  }

  private check(n: number): void {
    if (this.offset + n > this.view.byteLength) {
      throw new Error(`event log buffer overflow: need ${n} bytes at offset ${this.offset}, only ${this.remaining()} available`);
    }
  }
}

// --- TCG PC Client Event Types ---

const EV_NO_ACTION = 0x00000003;
const EV_SEPARATOR = 0x00000004;
const EV_EVENT_TAG = 0x00000006;
const EV_S_CRTM_VERSION = 0x00000008;
const EV_IPL = 0x0000000d;
const EV_NONHOST_INFO = 0x00000011;
const EV_EFI_BOOT_SERVICES_APPLICATION = 0x80000003;
const EV_EFI_ACTION = 0x80000007;

// --- Spec ID Event signature ---

const SPEC_ID_EVENT_SIGNATURE = 'Spec ID Event03\0';

// --- GRUB Prefixes ---

const GRUB_KERNEL_CMDLINE_PREFIXES = [
  'kernel_cmdline: ',
  'grub_kernel_cmdline ',
] as const;

const GRUB_VALID_PREFIXES = [
  'grub_cmd: ',
  'kernel_cmdline: ',
  'module_cmdline: ',
  'grub_kernel_cmdline ',
  'grub_cmd ',
] as const;

// --- Parsed Event Types ---

/** Digest algorithm info from Spec ID Event. */
interface DigestAlgorithm {
  algorithmId: number;
  digestSize: number;
}

/** A parsed TCG event with multi-algorithm digests. */
interface RawEvent {
  pcrIndex: number;
  eventType: number;
  digests: Map<number, Uint8Array>; // algorithmId → digest
  data: Uint8Array;
}

// --- Spec ID Event Parsing ---

function parseSpecIdEvent(data: Uint8Array): DigestAlgorithm[] {
  const sigBytes = data.subarray(0, 16);
  const sig = new TextDecoder('ascii').decode(sigBytes);
  if (sig !== SPEC_ID_EVENT_SIGNATURE) {
    throw new Error(`invalid Spec ID Event signature: "${sig.replace(/\0/g, '\\0')}"`);
  }

  const r = new LEReader(data.subarray(16));
  r.readUint32(); // platformClass
  r.readUint8();  // specVersionMinor
  r.readUint8();  // specVersionMajor
  r.readUint8();  // specErrata
  r.readUint8();  // uintnSize
  const numAlgorithms = r.readUint32();

  const algorithms: DigestAlgorithm[] = [];
  for (let i = 0; i < numAlgorithms; i++) {
    const algorithmId = r.readUint16();
    const digestSize = r.readUint16();
    algorithms.push({ algorithmId, digestSize });
  }

  return algorithms;
}

// --- TCG Event Log Parsing ---

/**
 * Parse a raw TCG PC Client event log.
 *
 * The first event is in legacy SHA-1 format (20-byte digest). Its data
 * contains a Spec ID Event that defines the supported hash algorithms.
 * All subsequent events use the crypto agile format with multi-algorithm digests.
 */
function parseTCGEventLog(rawLog: Uint8Array): { events: RawEvent[]; algorithms: DigestAlgorithm[] } {
  if (rawLog.length === 0) {
    return { events: [], algorithms: [] };
  }

  const r = new LEReader(rawLog);

  // --- First event: legacy SHA-1 format ---
  const firstPcrIndex = r.readUint32();
  const firstEventType = r.readUint32();
  const firstDigest = r.readBytes(20); // SHA-1 digest
  const firstDataSize = r.readUint32();
  const firstData = r.readBytes(firstDataSize);

  if (firstEventType !== EV_NO_ACTION) {
    throw new Error(`first event type must be EV_NO_ACTION (0x03), got 0x${firstEventType.toString(16)}`);
  }

  // Parse Spec ID Event to get algorithm info
  const algorithms = parseSpecIdEvent(firstData);
  if (algorithms.length === 0) {
    throw new Error('Spec ID Event contains no algorithms');
  }

  // Include the first event (Spec ID Event) in the event list
  const firstDigests = new Map<number, Uint8Array>();
  firstDigests.set(0x0004, firstDigest); // SHA-1 = 0x0004
  const events: RawEvent[] = [{
    pcrIndex: firstPcrIndex,
    eventType: firstEventType,
    digests: firstDigests,
    data: firstData,
  }];

  // --- Remaining events: crypto agile format ---
  while (r.remaining() > 0) {
    const pcrIndex = r.readUint32();
    const eventType = r.readUint32();
    const digestCount = r.readUint32();
    const digests = new Map<number, Uint8Array>();

    for (let i = 0; i < digestCount; i++) {
      const algId = r.readUint16();
      // Look up digest size from Spec ID Event algorithms
      const algInfo = algorithms.find(a => a.algorithmId === algId);
      if (!algInfo) {
        throw new Error(`unknown algorithm ID 0x${algId.toString(16)} in event log`);
      }
      const digest = r.readBytes(algInfo.digestSize);
      digests.set(algId, digest);
    }

    const dataSize = r.readUint32();
    const data = r.readBytes(dataSize);

    events.push({ pcrIndex, eventType, digests, data });
  }

  return { events, algorithms };
}

// --- Event Log Replay ---

/**
 * Replay events against expected PCR values for a given hash algorithm.
 * Returns true if replay matches. Extends: PCR[i] = Hash(PCR[i] || digest).
 *
 * EV_NO_ACTION events are skipped (not extended into PCRs).
 */
function replayEvents(
  events: RawEvent[],
  hashAlg: number,
  expectedPCRs: Map<number, Uint8Array>,
): void {
  const algName = hashAlgName(hashAlg);
  const digestSize = createHash(algName).digest().length;
  const replayed = new Map<number, Uint8Array>();

  for (const event of events) {
    // EV_NO_ACTION events are not extended
    if (event.eventType === EV_NO_ACTION) continue;

    const digest = event.digests.get(hashAlg);
    if (!digest) continue;

    if (!replayed.has(event.pcrIndex)) {
      replayed.set(event.pcrIndex, new Uint8Array(digestSize));
    }

    const h = createHash(algName);
    h.update(replayed.get(event.pcrIndex)!);
    h.update(digest);
    replayed.set(event.pcrIndex, new Uint8Array(h.digest()));
  }

  // Verify only PCRs that we have expected values for AND that appear in the event log
  const failedPCRs: number[] = [];
  for (const [pcrIndex, expected] of expectedPCRs) {
    const computed = replayed.get(pcrIndex);
    if (!computed) continue; // No events for this PCR
    if (!bytesEqual(computed, expected)) {
      failedPCRs.push(pcrIndex);
    }
  }

  if (failedPCRs.length > 0) {
    throw new Error(`event log replay failed for PCRs: ${failedPCRs.join(', ')}`);
  }
}

// --- Proto Event Conversion ---

/**
 * Convert raw events to proto Event objects with digest verification.
 * An event's digest is "verified" if hash(event.data) equals the stored digest.
 */
function convertToProtoEvents(events: RawEvent[], hashAlg: number): Event[] {
  const algName = hashAlgName(hashAlg);
  return events.map(raw => {
    const event = create(EventSchema);
    event.pcrIndex = raw.pcrIndex;
    event.untrustedType = raw.eventType;
    event.data = raw.data;

    const digest = raw.digests.get(hashAlg);
    if (digest) {
      event.digest = digest;
      const h = createHash(algName);
      h.update(raw.data);
      event.digestVerified = bytesEqual(new Uint8Array(h.digest()), digest);
    }

    return event;
  });
}

// --- GRUB State Extraction ---

/**
 * Extract GRUB state from verified event log events.
 * Looks for PCR 8 (GRUB commands) and PCR 9 (GRUB files) events of type EV_IPL.
 *
 * Port of server.getGrubState from Go.
 */
function getGrubState(hashAlg: number, events: Event[]): GrubState | undefined {
  const algName = hashAlgName(hashAlg);
  const grubState = create(GrubStateSchema);
  let hasData = false;

  for (const event of events) {
    const index = event.pcrIndex;
    if (index !== 8 && index !== 9) continue;

    // Skip EV_EVENT_TAG events (likely from Linux)
    if (event.untrustedType === EV_EVENT_TAG) continue;

    if (event.untrustedType !== EV_IPL) continue;

    if (index === 9) {
      grubState.files.push({
        $typeName: 'layr_attest.GrubFile',
        digest: event.digest,
        untrustedFilename: event.data,
      });
      hasData = true;
    } else if (index === 8) {
      const rawData = event.data;
      let suffixAt = -1;

      for (const prefix of GRUB_VALID_PREFIXES) {
        const prefixBytes = new TextEncoder().encode(prefix);
        if (rawData.length >= prefixBytes.length && startsWith(rawData, prefixBytes)) {
          suffixAt = prefixBytes.length;
          break;
        }
      }

      if (suffixAt === -1) continue; // Skip unrecognized prefixes

      // Verify digest of the command data portion
      const cmdData = rawData.subarray(suffixAt);
      if (cmdData.length > 0) {
        const h = createHash(algName);
        // Handle null-terminated strings: try with and without trailing null
        if (cmdData[cmdData.length - 1] === 0x00) {
          // Try with null first, then without
          h.update(cmdData);
          const digestWithNull = new Uint8Array(h.digest());
          if (!bytesEqual(digestWithNull, event.digest)) {
            const h2 = createHash(algName);
            h2.update(cmdData.subarray(0, cmdData.length - 1));
            const digestWithoutNull = new Uint8Array(h2.digest());
            if (!bytesEqual(digestWithoutNull, event.digest)) {
              throw new Error(`invalid GRUB event digest for PCR8 command: ${new TextDecoder().decode(rawData).substring(0, 80)}`);
            }
          }
        }
      }

      const command = new TextDecoder().decode(rawData);
      grubState.commands.push(command);
      hasData = true;
    }
  }

  if (!hasData) {
    throw new Error('no GRUB measurements found');
  }

  return grubState;
}

/**
 * Extract Linux kernel state from GRUB state.
 * Looks for the kernel command line in GRUB commands.
 *
 * Port of server.getLinuxKernelStateFromGRUB from Go.
 */
function getLinuxKernelStateFromGRUB(grub: GrubState): LinuxKernelState {
  const state = create(LinuxKernelStateSchema);
  let seen = false;

  for (const command of grub.commands) {
    let suffixAt = -1;
    for (const prefix of GRUB_KERNEL_CMDLINE_PREFIXES) {
      if (command.startsWith(prefix)) {
        suffixAt = prefix.length;
        break;
      }
    }
    if (suffixAt === -1) continue;

    if (seen) {
      throw new Error('more than one kernel commandline in GRUB commands');
    }
    seen = true;
    state.commandLine = command.substring(suffixAt);
  }

  return state;
}

// --- Platform State Extraction (PCR0 events) ---

/** GCE NonHostInfo signature prefix (16 bytes). */
const GCE_NONHOST_INFO_SIGNATURE = 'GCE NonHostInfo\0';

/** GCE NonHostInfo total expected size. */
const GCE_NONHOST_INFO_SIZE = 32;

/**
 * Map technology byte from NonHostInfo to GCEConfidentialTechnology enum.
 * Port of ParseGCENonHostInfo from Go.
 */
function parseGCENonHostInfoTech(techByte: number): GCEConfidentialTechnology {
  switch (techByte) {
    case 0: return GCEConfidentialTechnology.NONE;
    case 1: return GCEConfidentialTechnology.AMD_SEV;
    case 2: return GCEConfidentialTechnology.AMD_SEV_ES;
    case 3: return GCEConfidentialTechnology.INTEL_TDX;
    case 4: return GCEConfidentialTechnology.AMD_SEV_SNP;
    default: throw new Error(`unknown GCE confidential technology: ${techByte}`);
  }
}

/**
 * Try to parse the SCRTM version as a GCE firmware version (uint32 LE).
 * GCE firmware versions are encoded as 4-byte little-endian integers.
 * Returns the version number or null if the data isn't a valid GCE version.
 *
 * Port of ConvertSCRTMVersionToGCEFirmwareVersion from Go.
 */
function tryParseGCEFirmwareVersion(data: Uint8Array): number | null {
  // GCE firmware versions are null-terminated strings of decimal digits
  // that can be parsed as uint32. The Go implementation converts from
  // a string representation.
  const text = new TextDecoder().decode(data).replace(/\0+$/, '');
  const version = parseInt(text, 10);
  if (!isNaN(version) && version >= 0 && version <= 0xffffffff && String(version) === text) {
    return version;
  }
  return null;
}

/**
 * Extract platform state from PCR0 events.
 * Scans for EV_S_CRTM_VERSION and EV_NONHOST_INFO events before the separator.
 *
 * Port of server.getPlatformState from Go.
 */
export function getPlatformState(hashAlg: number, events: Event[]): PlatformState {
  const state = create(PlatformStateSchema);
  const algName = hashAlgName(hashAlg);

  for (const event of events) {
    if (event.pcrIndex !== 0) continue;

    // Stop at separator
    if (event.untrustedType === EV_SEPARATOR) {
      // Verify separator data is valid (0x00000000 or 0xFFFFFFFF)
      if (event.data.length === 4) {
        const sepVal = new DataView(event.data.buffer, event.data.byteOffset, 4).getUint32(0, true);
        if (sepVal !== 0x00000000 && sepVal !== 0xffffffff) {
          throw new Error(`invalid PCR0 separator value: 0x${sepVal.toString(16)}`);
        }
      }
      break;
    }

    if (event.untrustedType === EV_S_CRTM_VERSION) {
      // Verify digest of the version data
      const h = createHash(algName);
      h.update(event.data);
      const computed = new Uint8Array(h.digest());
      if (!bytesEqual(computed, event.digest)) {
        throw new Error('EV_S_CRTM_VERSION event digest mismatch');
      }

      const gceVersion = tryParseGCEFirmwareVersion(event.data);
      if (gceVersion !== null) {
        state.firmware = { case: 'gceVersion', value: gceVersion };
      } else {
        state.firmware = { case: 'scrtmVersionId', value: new Uint8Array(event.data) };
      }
    }

    if (event.untrustedType === EV_NONHOST_INFO) {
      // Verify digest
      const h = createHash(algName);
      h.update(event.data);
      const computed = new Uint8Array(h.digest());
      if (!bytesEqual(computed, event.digest)) {
        throw new Error('EV_NONHOST_INFO event digest mismatch');
      }

      if (event.data.length < GCE_NONHOST_INFO_SIZE) {
        throw new Error(`EV_NONHOST_INFO data too short: ${event.data.length} bytes`);
      }

      // Validate signature
      const sig = new TextDecoder('ascii').decode(event.data.subarray(0, 16));
      if (sig !== GCE_NONHOST_INFO_SIGNATURE) {
        throw new Error('invalid GCE NonHostInfo signature');
      }

      // Technology byte at offset 16
      state.technology = parseGCENonHostInfoTech(event.data[16]);
    }
  }

  return state;
}

// --- EFI State Extraction (PCR4/PCR5 events) ---

/** CallingEFIApplication action string for PCR4 EV_EFI_ACTION events. */
const CALLING_EFI_APPLICATION = 'Calling EFI Application from Boot Option';

/** ExitBootServicesInvocation action string for PCR5 EV_EFI_ACTION events. */
const EXIT_BOOT_SERVICES_INVOCATION = 'Exit Boot Services Invocation';

/**
 * Extract EFI boot state from PCR4 and PCR5 events.
 * Collects EFI application digests from PCR4 after seeing CallingEFIApplication,
 * and stops when ExitBootServicesInvocation is seen on PCR5.
 *
 * Port of server.getEfiState from Go.
 */
export function getEfiState(hashAlg: number, events: Event[]): EfiState | undefined {
  const algName = hashAlgName(hashAlg);
  const digestSize = hashAlgDigestSize(hashAlg);

  // Pre-compute expected digests for the action strings
  const callingEfiAppDigest = new Uint8Array(createHash(algName).update(CALLING_EFI_APPLICATION).digest());
  const exitBootServicesDigest = new Uint8Array(createHash(algName).update(EXIT_BOOT_SERVICES_INVOCATION).digest());

  const state = create(EfiStateSchema);
  let seenCallingEfiApp = false;
  let seenExitBootServices = false;

  for (const event of events) {
    if (seenExitBootServices) break;

    // Only process PCR4 and PCR5 events
    if (event.pcrIndex !== 4 && event.pcrIndex !== 5) continue;

    // Stop at separator for either PCR
    if (event.untrustedType === EV_SEPARATOR) continue;

    if (event.pcrIndex === 5) {
      // PCR5: look for ExitBootServicesInvocation
      if (event.untrustedType === EV_EFI_ACTION &&
          event.digest.length === digestSize &&
          bytesEqual(event.digest, exitBootServicesDigest)) {
        seenExitBootServices = true;
      }
      continue;
    }

    // PCR4 events
    if (event.untrustedType === EV_EFI_ACTION) {
      // Check for CallingEFIApplication
      if (event.digest.length === digestSize &&
          bytesEqual(event.digest, callingEfiAppDigest)) {
        seenCallingEfiApp = true;
      }
      continue;
    }

    if (event.untrustedType === EV_EFI_BOOT_SERVICES_APPLICATION) {
      if (!seenCallingEfiApp) {
        throw new Error('EFI boot services application event before CallingEFIApplication');
      }
      const app = create(EfiAppSchema);
      app.digest = event.digest;
      state.apps.push(app);
    }
  }

  // Only return EFI state if ExitBootServices was seen
  if (!seenExitBootServices) {
    return undefined;
  }

  return state;
}

// --- Public API ---

export interface ParsedEventLog {
  events: Event[];
  grub?: GrubState;
  linuxKernel: LinuxKernelState;
  platform?: PlatformState;
  efi?: EfiState;
  /** Non-fatal errors encountered during parsing. */
  errors: string[];
}

/**
 * Parse a raw TCG PC Client event log, replay against PCR values,
 * and extract GRUB + kernel state.
 *
 * Port of server.parsePCClientEventLog from Go.
 *
 * @param rawEventLog The raw binary event log bytes.
 * @param pcrMap PCR index → digest map from the verified TPM quote.
 * @param hashAlg TPM hash algorithm ID used for the PCRs.
 */
export function parsePCClientEventLog(
  rawEventLog: Uint8Array,
  pcrMap: { [key: number]: Uint8Array },
  hashAlg: number,
): ParsedEventLog {
  if (rawEventLog.length === 0) {
    return {
      events: [],
      linuxKernel: create(LinuxKernelStateSchema),
      errors: [],
    };
  }

  const errors: string[] = [];

  // 1. Parse the raw binary event log
  const { events: rawEvents } = parseTCGEventLog(rawEventLog);

  // 2. Build expected PCR map and replay
  const expectedPCRs = new Map<number, Uint8Array>();
  for (const [key, value] of Object.entries(pcrMap)) {
    expectedPCRs.set(Number(key), value);
  }
  replayEvents(rawEvents, hashAlg, expectedPCRs);

  // 3. Convert to proto events
  const protoEvents = convertToProtoEvents(rawEvents, hashAlg);

  // 4. Extract platform state (non-fatal)
  let platform: PlatformState | undefined;
  try {
    platform = getPlatformState(hashAlg, protoEvents);
  } catch (err) {
    errors.push(`platform state: ${err instanceof Error ? err.message : String(err)}`);
  }

  // 5. Extract EFI state (non-fatal)
  let efi: EfiState | undefined;
  try {
    efi = getEfiState(hashAlg, protoEvents);
  } catch (err) {
    errors.push(`EFI state: ${err instanceof Error ? err.message : String(err)}`);
  }

  // 6. Extract GRUB state (non-fatal — some VMs don't use GRUB)
  let grub: GrubState | undefined;
  try {
    grub = getGrubState(hashAlg, protoEvents);
  } catch (err) {
    errors.push(`GRUB state: ${err instanceof Error ? err.message : String(err)}`);
  }

  // 7. Extract kernel state from GRUB
  let linuxKernel: LinuxKernelState;
  if (grub) {
    linuxKernel = getLinuxKernelStateFromGRUB(grub);
  } else {
    linuxKernel = create(LinuxKernelStateSchema);
  }

  return { events: protoEvents, grub, linuxKernel, platform, efi, errors };
}

// --- Helpers ---

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function startsWith(data: Uint8Array, prefix: Uint8Array): boolean {
  if (data.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) {
    if (data[i] !== prefix[i]) return false;
  }
  return true;
}
