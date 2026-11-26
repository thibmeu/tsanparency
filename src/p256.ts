/** KT_128_SHA256_P256 (Section 17.1) */
import { p256 } from "@noble/curves/nist.js";
import { bytesToNumberBE, concatBytes, createHmacDrbg, numberToBytesBE } from "@noble/curves/utils.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import type { CipherSuite } from "./crypto.ts";
import { type Vrf, ecvrf } from "./vrf.ts";

type P256Point = InstanceType<typeof p256.Point>;
const p256Drbg = createHmacDrbg<bigint>(32, 32, (k: Uint8Array, m: Uint8Array) => hmac(sha256, k, m));

/** ECVRF-P256-SHA256-TAI (RFC 9381 Section 5.5) */
const vrf: Vrf = ecvrf<P256Point>({
  id: 0x01,
  hash: sha256,
  base: p256.Point.BASE,
  q: p256.Point.Fn.ORDER,
  ptLen: 33,
  toInt: bytesToNumberBE,
  toBytes: numberToBytesBE,
  encode: (p) => p.toBytes(true),
  decode: (b) => {
    if (b.length !== 33) throw new Error("invalid point");
    return p256.Point.fromBytes(b);
  },
  hashToPoint: (h) => p256.Point.fromBytes(concatBytes(new Uint8Array([0x02]), h)),
  clearCofactor: (p) => p,
  secret(sk) {
    const q = p256.Point.Fn.ORDER;
    const x = sk.length === 32 ? bytesToNumberBE(sk) : 0n;
    if (x < 1n || x >= q) throw new Error("invalid VRF secret key");
    return {
      x,
      // RFC 6979 Section 3.2 with m set to h_string and no DSA suitability check (Section 5.4.2.1)
      nonce: (hString) => {
        const h1 = bytesToNumberBE(sha256(hString)) % q;
        const seed = concatBytes(numberToBytesBE(x, 32), numberToBytesBE(h1, 32));
        return p256Drbg(seed, (v) => {
          const k = bytesToNumberBE(v);
          return k >= 1n && k < q ? k : undefined;
        });
      },
    };
  },
});

/** ECVRF-P256-SHA256-TAI, and ECDSA over P-256 with SHA-256, uncompressed public keys and r || s signatures */
export const KT_128_SHA256_P256: CipherSuite = {
  id: 0x0001,
  vrf,
  signature: { import: { name: "ECDSA", namedCurve: "P-256" }, sign: { name: "ECDSA", hash: "SHA-256" } },
};
