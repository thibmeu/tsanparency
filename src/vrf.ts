/**
 * ECVRF with try-and-increment encode_to_curve (RFC 9381 Section 5), in the two
 * suites KT uses: ECVRF-P256-SHA256-TAI and ECVRF-EDWARDS25519-SHA512-TAI, the
 * latter with its output truncated to 32 bytes (protocol Section 17.1).
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import {
  bytesToNumberBE,
  bytesToNumberLE,
  concatBytes,
  createHmacDrbg,
  numberToBytesBE,
  numberToBytesLE,
} from "@noble/curves/utils.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";

interface Point<P> {
  add(o: P): P;
  subtract(o: P): P;
  multiply(k: bigint): P;
  multiplyUnsafe(k: bigint): P;
  precompute(w?: number, lazy?: boolean): P;
  toBytes(compressed?: boolean): Uint8Array;
  is0(): boolean;
  mulAddUnsafe?(a: bigint, other: P, b: bigint): P;
}

interface Suite<P extends Point<P>> {
  readonly id: number;
  readonly hash: (b: Uint8Array) => Uint8Array;
  readonly base: P;
  readonly q: bigint;
  readonly ptLen: number;
  readonly toInt: (b: Uint8Array) => bigint;
  readonly toBytes: (n: bigint, len: number) => Uint8Array;
  readonly encode: (p: P) => Uint8Array;
  /** string_to_point, throwing on anything that does not decode */
  readonly decode: (b: Uint8Array) => P;
  /** interpret_hash_value_as_a_point followed by the cofactor multiplication */
  readonly hashToPoint: (h: Uint8Array) => P;
  readonly clearCofactor: (p: P) => P;
  /** Derives the secret scalar x and the nonce generator from SK */
  readonly secret: (sk: Uint8Array) => { x: bigint; nonce: (hString: Uint8Array) => bigint };
}

const C_LEN = 16;

export interface VrfKey {
  /** Encoded public key, as in Configuration.vrf_public_key */
  readonly publicKey: Uint8Array;
  prove(alpha: Uint8Array): { proof: Uint8Array; output: Uint8Array };
}

export interface Vrf {
  /** VRF.Np */
  readonly proofLength: number;
  key(secretKey: Uint8Array): VrfKey;
  /**
   * ECVRF_verify with validate_key for one public key (Section 5.3). Returns the
   * 32-byte output, or null when the proof is invalid. Inputs are public, so this
   * runs in variable time.
   */
  verifier(publicKey: Uint8Array): (alpha: Uint8Array, proof: Uint8Array) => Uint8Array | null;
}

function ecvrf<P extends Point<P>>(s: Suite<P>): Vrf {
  const proofLength = s.ptLen + C_LEN + 32;
  const tag = (domain: number, ...parts: Uint8Array[]) =>
    s.hash(concatBytes(new Uint8Array([s.id, domain]), ...parts, new Uint8Array([0])));

  /**
   * Hashes the input with a one-byte counter until the result decodes to a point
   * (Section 5.4.1.1). Running time depends on alpha, so a party timing the
   * prover learns something about the label.
   */
  const encodeToCurve = (pk: Uint8Array, alpha: Uint8Array): P => {
    for (let ctr = 0; ctr < 256; ctr++) {
      const h = s.hash(concatBytes(new Uint8Array([s.id, 0x01]), pk, alpha, new Uint8Array([ctr, 0x00])));
      try {
        const H = s.hashToPoint(h);
        if (!H.is0()) return H;
      } catch {}
    }
    throw new Error("encode_to_curve failed");
  };

  /** Hash of the five points, truncated to cLen bytes (Section 5.4.3) */
  const challenge = (...points: P[]): bigint => s.toInt(tag(0x02, ...points.map(s.encode)).subarray(0, C_LEN));

  /** Hash of the cofactor times Gamma, truncated to VRF.Nh (Section 5.2) */
  const proofToHash = (gamma: P): Uint8Array => tag(0x03, s.encode(s.clearCofactor(gamma))).subarray(0, 32);

  return {
    proofLength,
    key(secretKey) {
      const { x, nonce } = s.secret(secretKey);
      const Y = s.base.multiply(x);
      const publicKey = s.encode(Y);
      return {
        publicKey,
        prove(alpha) {
          const H = encodeToCurve(publicKey, alpha);
          const gamma = H.multiply(x);
          const k = nonce(s.encode(H));
          const c = challenge(Y, H, gamma, s.base.multiply(k), H.multiply(k));
          const sc = (k + c * x) % s.q;
          const proof = concatBytes(s.encode(gamma), s.toBytes(c, C_LEN), s.toBytes(sc, 32));
          return { proof, output: proofToHash(gamma) };
        },
      };
    },
    verifier(publicKey) {
      const Y = s.decode(publicKey);
      if (s.clearCofactor(Y).is0()) throw new Error("invalid VRF public key");
      Y.precompute(4);
      return (alpha, proof) => {
        if (proof.length !== proofLength) return null;
        try {
          const gamma = s.decode(proof.subarray(0, s.ptLen));
          const c = s.toInt(proof.subarray(s.ptLen, s.ptLen + C_LEN));
          const sc = s.toInt(proof.subarray(s.ptLen + C_LEN));
          if (sc >= s.q) return null;
          const H = encodeToCurve(publicKey, alpha);
          const U = s.base.multiplyUnsafe(sc).subtract(Y.multiplyUnsafe(c));
          const V = H.mulAddUnsafe
            ? H.mulAddUnsafe(sc, gamma, (s.q - c) % s.q)
            : H.multiplyUnsafe(sc).subtract(gamma.multiplyUnsafe(c));
          return challenge(Y, H, gamma, U, V) === c ? proofToHash(gamma) : null;
        } catch {
          return null;
        }
      };
    },
  };
}

type P256Point = InstanceType<typeof p256.Point>;
const p256Drbg = createHmacDrbg<bigint>(32, 32, (k: Uint8Array, m: Uint8Array) => hmac(sha256, k, m));

/** ECVRF-P256-SHA256-TAI (RFC 9381 Section 5.5) */
export const P256_VRF: Vrf = ecvrf<P256Point>({
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

type EdPoint = InstanceType<typeof ed25519.Point>;

/** ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381 Section 5.5) with outputs truncated to 32 bytes */
export const ED25519_VRF: Vrf = ecvrf<EdPoint>({
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
