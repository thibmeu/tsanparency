import { bytesToHex, hexToBytes } from "@noble/curves/utils.js";
import { expect, test } from "vitest";
import { DecodeError, Reader, Writer, decode } from "../src/tls.ts";

test("round trip", () => {
  const big = new Uint8Array(300).fill(5); // forces buffer growth
  const bytes = new Writer()
    .u8(1)
    .u16(2)
    .u32(3)
    .u64(2 ** 53 - 1)
    .opaque(1, hexToBytes("aa"))
    .opaque(4, big)
    .finish();
  const out = decode(bytes, (r) => [r.u8(), r.u16(), r.u32(), r.u64(), bytesToHex(r.opaque(1)), r.opaque(4).length]);
  expect(out).toEqual([1, 2, 3, 2 ** 53 - 1, "aa", 300]);
});

test("rejects malformed input", () => {
  expect(() => decode(hexToBytes("0100"), (r) => r.u8())).toThrow(DecodeError); // trailing
  expect(() => decode(hexToBytes("05aa"), (r) => r.opaque(1))).toThrow(DecodeError); // truncated
  expect(() => decode(hexToBytes("02aabb"), (r) => r.opaque(1, 1))).toThrow(DecodeError); // over limit
  expect(() => decode(hexToBytes("02"), (r) => r.present())).toThrow(DecodeError);
  expect(() => decode(hexToBytes("0020000000000000"), (r) => r.u64())).toThrow(DecodeError); // > 2^53-1
  // Count bounded by remaining input before any allocation.
  expect(() => new Reader(hexToBytes("ffffffff00")).count(4, 32)).toThrow(DecodeError);
});

test("rejects out-of-range writes without corrupting output", () => {
  const w = new Writer().u8(1);
  expect(() => w.u8(256)).toThrow(RangeError);
  expect(() => w.u32(-1)).toThrow(RangeError);
  expect(() => w.u64(2 ** 53)).toThrow(RangeError);
  expect(() => w.opaque(1, new Uint8Array(256))).toThrow(RangeError);
  expect(bytesToHex(w.finish())).toBe("01");
});

test("decoded bytes are copies", () => {
  const src = hexToBytes("01aa");
  const b = decode(src, (r) => r.opaque(1));
  src[1] = 0;
  expect(bytesToHex(b)).toBe("aa");
});
