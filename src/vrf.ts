/** ECVRF with try-and-increment encode_to_curve (RFC 9381 Section 5) over a curve suite */
import { concatBytes } from "@noble/curves/utils.js";

export interface Point<P> {
  add(o: P): P;
  subtract(o: P): P;
  multiply(k: bigint): P;
  multiplyUnsafe(k: bigint): P;
  precompute(w?: number, lazy?: boolean): P;
  toBytes(compressed?: boolean): Uint8Array;
  is0(): boolean;
  mulAddUnsafe?(a: bigint, other: P, b: bigint): P;
}

export interface Suite<P extends Point<P>> {
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

export function ecvrf<P extends Point<P>>(s: Suite<P>): Vrf {
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
