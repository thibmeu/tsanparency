/** KT_128_SHA256_Ed25519 (Section 17.1) */
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToNumberLE, concatBytes, numberToBytesLE } from "@noble/curves/utils.js";
import { sha512 } from "@noble/hashes/sha2.js";
import type { CipherSuite } from "./crypto.ts";
import { type Vrf, ecvrf } from "./vrf.ts";

type EdPoint = InstanceType<typeof ed25519.Point>;

/** ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381 Section 5.5) with outputs truncated to 32 bytes */
const vrf: Vrf = ecvrf<EdPoint>({
  id: 0x03,
  hash: sha512,
  base: ed25519.Point.BASE,
  q: ed25519.Point.Fn.ORDER,
  ptLen: 32,
  toInt: bytesToNumberLE,
  toBytes: numberToBytesLE,
  encode: (p) => p.toBytes(),
  decode: (b) => {
    if (b.length !== 32) throw new Error("invalid point");
    return ed25519.Point.fromBytes(b);
  },
  hashToPoint: (h) => ed25519.Point.fromBytes(h.subarray(0, 32)).clearCofactor(),
  clearCofactor: (p) => p.clearCofactor(),
  secret(sk) {
    if (sk.length !== 32) throw new Error("invalid VRF secret key");
    // RFC 8032 Section 5.1.5 key expansion, then the nonce of Section 5.4.2.2
    const { scalar, prefix } = ed25519.utils.getExtendedPublicKey(sk);
    const q = ed25519.Point.Fn.ORDER;
    return { x: scalar, nonce: (hString) => bytesToNumberLE(sha512(concatBytes(prefix, hString))) % q };
  },
});

/** ECVRF-EDWARDS25519-SHA512-TAI, and Ed25519 signatures */
export const KT_128_SHA256_Ed25519: CipherSuite = {
  id: 0x0002,
  vrf,
  signature: { import: { name: "Ed25519" }, sign: { name: "Ed25519" } },
};
