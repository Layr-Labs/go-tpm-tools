/**
 * Sequential big-endian binary reader for TPM 2.0 wire format.
 * All TPM structures use big-endian byte order.
 */
export class BufferReader {
  private view: DataView;
  private offset: number;

  constructor(data: Uint8Array) {
    this.view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    this.offset = 0;
  }

  /** Remaining bytes available. */
  remaining(): number {
    return this.view.byteLength - this.offset;
  }

  /** Read a uint8. */
  readUint8(): number {
    this.checkBounds(1);
    const val = this.view.getUint8(this.offset);
    this.offset += 1;
    return val;
  }

  /** Read a uint16 (big-endian). */
  readUint16(): number {
    this.checkBounds(2);
    const val = this.view.getUint16(this.offset, false);
    this.offset += 2;
    return val;
  }

  /** Read a uint32 (big-endian). */
  readUint32(): number {
    this.checkBounds(4);
    const val = this.view.getUint32(this.offset, false);
    this.offset += 4;
    return val;
  }

  /** Read a uint64 (big-endian). */
  readUint64(): bigint {
    this.checkBounds(8);
    const val = this.view.getBigUint64(this.offset, false);
    this.offset += 8;
    return val;
  }

  /** Read n raw bytes. */
  readBytes(n: number): Uint8Array {
    this.checkBounds(n);
    const bytes = new Uint8Array(this.view.buffer, this.view.byteOffset + this.offset, n);
    this.offset += n;
    // Return a copy to avoid aliasing issues
    return new Uint8Array(bytes);
  }

  /** Read a TPM2B (uint16 length-prefixed) byte buffer. */
  readSizedBuffer(): Uint8Array {
    const len = this.readUint16();
    return this.readBytes(len);
  }

  /** Read all remaining bytes. */
  readRest(): Uint8Array {
    return this.readBytes(this.remaining());
  }

  private checkBounds(n: number): void {
    if (this.offset + n > this.view.byteLength) {
      throw new Error(
        `buffer overflow: need ${n} bytes at offset ${this.offset}, but only ${this.remaining()} available`,
      );
    }
  }
}
