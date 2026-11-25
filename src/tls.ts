/**
 * TLS presentation language codec (RFC 8446 Section 3). Vector bounds count
 * elements, not bytes (protocol Section 2.1.2).
 */

export class DecodeError extends Error {
  override name = "DecodeError";
}

export class Writer {
  #buf = new Uint8Array(256);
  #view = new DataView(this.#buf.buffer);
  #len = 0;

  #reserve(n: number): number {
    const at = this.#len;
    if (at + n > this.#buf.length) {
      const next = new Uint8Array(Math.max(at + n, this.#buf.length * 2));
      next.set(this.#buf.subarray(0, at));
      this.#buf = next;
      this.#view = new DataView(next.buffer);
    }
    this.#len = at + n;
    return at;
  }

  u8(v: number): this {
    uint(v, 8);
    const at = this.#reserve(1);
    this.#view.setUint8(at, v);
    return this;
  }
  u16(v: number): this {
    uint(v, 16);
    const at = this.#reserve(2);
    this.#view.setUint16(at, v);
    return this;
  }
  u32(v: number): this {
    uint(v, 32);
    const at = this.#reserve(4);
    this.#view.setUint32(at, v);
    return this;
  }
  /** uint64 as a safe integer. Larger values are rejected rather than rounded. */
  u64(v: number): this {
    if (!Number.isSafeInteger(v) || v < 0) throw new RangeError("uint64 out of safe range");
    const at = this.#reserve(8);
    this.#view.setBigUint64(at, BigInt(v));
    return this;
  }
  /** Fixed-length bytes. */
  bytes(b: Uint8Array): this {
    const at = this.#reserve(b.length);
    this.#buf.set(b, at);
    return this;
  }
  /** opaque<0..2^(8*prefix)-1> */
  opaque(prefix: 1 | 2 | 4, b: Uint8Array): this {
    return this.count(prefix, b.length).bytes(b);
  }
  /** Length prefix for a vector of `count` elements. The caller writes the elements. */
  count(prefix: 1 | 2 | 4, count: number): this {
    return prefix === 1 ? this.u8(count) : prefix === 2 ? this.u16(count) : this.u32(count);
  }
  finish(): Uint8Array<ArrayBuffer> {
    return this.#buf.slice(0, this.#len);
  }
}

function uint(v: number, bits: number): void {
  if (!Number.isInteger(v) || v < 0 || v >= 2 ** bits) throw new RangeError(`uint${bits} out of range`);
}

export class Reader {
  readonly #buf: Uint8Array;
  readonly #view: DataView;
  #pos = 0;

  constructor(buf: Uint8Array) {
    this.#buf = buf;
    this.#view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  }

  get remaining(): number {
    return this.#buf.length - this.#pos;
  }

  #take(n: number): number {
    if (n > this.remaining) throw new DecodeError("truncated");
    const at = this.#pos;
    this.#pos += n;
    return at;
  }

  u8(): number {
    return this.#view.getUint8(this.#take(1));
  }
  u16(): number {
    return this.#view.getUint16(this.#take(2));
  }
  u32(): number {
    return this.#view.getUint32(this.#take(4));
  }
  u64(): number {
    const v = this.#view.getBigUint64(this.#take(8));
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new DecodeError("uint64 beyond 2^53-1");
    return Number(v);
  }
  /** Fixed-length bytes, copied so callers may retain them safely. */
  bytes(n: number): Uint8Array {
    const at = this.#take(n);
    return copy(this.#buf.subarray(at, at + n));
  }
  opaque(prefix: 1 | 2 | 4, max = Infinity): Uint8Array {
    const n = this.#lenPrefix(prefix);
    if (n > max) throw new DecodeError("vector exceeds limit");
    return this.bytes(n);
  }
  /**
   * Element count of a vector. Rejects counts that cannot fit in the remaining
   * input given each element's minimum encoded size, before any allocation.
   */
  count(prefix: 1 | 2 | 4, minElementSize: number, max = Infinity): number {
    const n = this.#lenPrefix(prefix);
    if (n > max) throw new DecodeError("vector exceeds limit");
    if (n * minElementSize > this.remaining) throw new DecodeError("truncated");
    return n;
  }
  /** optional<T> presence octet (Section 2.1.1). */
  present(): boolean {
    const p = this.u8();
    if (p > 1) throw new DecodeError("invalid optional");
    return p === 1;
  }
  #lenPrefix(prefix: 1 | 2 | 4): number {
    return prefix === 1 ? this.u8() : prefix === 2 ? this.u16() : this.u32();
  }
  /** Rejects trailing data. */
  end(): void {
    if (this.remaining !== 0) throw new DecodeError("trailing data");
  }
}

/** Decodes all of `buf` with `fn`. Trailing bytes are an error. */
/** An owned copy, as a plain Uint8Array. Node's Buffer.slice shares memory instead. */
export const copy = (b: Uint8Array): Uint8Array => new Uint8Array(b);

export function decode<T>(buf: Uint8Array, fn: (r: Reader) => T): T {
  const r = new Reader(buf);
  const v = fn(r);
  r.end();
  return v;
}
