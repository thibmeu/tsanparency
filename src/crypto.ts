/** Cipher suites and the computations of protocol Section 11 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import { concatBytes } from "@noble/curves/utils.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { Writer } from "./tls.ts";
import { ED25519_VRF, P256_VRF, type Vrf } from "./vrf.ts";

/** Hash.Nh and VRF.Nh, shared by both suites (Section 17.1) */
export const NH = 32;
/** Size of commitment openings */
export const NC = 16;
const KC = new Uint8Array([
  0xd8, 0x21, 0xf8, 0x79, 0x0d, 0x97, 0x70, 0x97, 0x96, 0xb4, 0xd7, 0x90, 0x33, 0x57, 0xc3, 0xf5,
]);

export const CipherSuite = { KT_128_SHA256_P256: 0x0001, KT_128_SHA256_Ed25519: 0x0002 } as const;
export type CipherSuite = (typeof CipherSuite)[keyof typeof CipherSuite];

export interface Suite {
  readonly vrf: Vrf;
  /** Web Crypto algorithm for tree head signatures */
  readonly signature: { readonly import: EcKeyImportParams | Algorithm; readonly sign: EcdsaParams | Algorithm };
  /** Throws unless the bytes encode a signature public key */
  readonly checkSignatureKey: (key: Uint8Array) => void;
}

/**
 * KT_128_SHA256_P256 signs with ECDSA over P-256 and SHA-256, with uncompressed
 * public keys and r || s signatures. KT_128_SHA256_Ed25519 signs with Ed25519.
 * Both hash with SHA-256 (Section 17.1).
 */
export const SUITES: Record<CipherSuite, Suite> = {
  [CipherSuite.KT_128_SHA256_P256]: {
    vrf: P256_VRF,
    signature: { import: { name: "ECDSA", namedCurve: "P-256" }, sign: { name: "ECDSA", hash: "SHA-256" } },
    checkSignatureKey: (k) => {
      if (k.length !== 65) throw new Error("signature key must be an uncompressed P-256 point");
      p256.Point.fromBytes(k);
    },
  },
  [CipherSuite.KT_128_SHA256_Ed25519]: {
    vrf: ED25519_VRF,
    signature: { import: { name: "Ed25519" }, sign: { name: "Ed25519" } },
    checkSignatureKey: (k) => {
      if (k.length !== 32) throw new Error("signature key must be an Ed25519 public key");
      ed25519.Point.fromBytes(k);
    },
  },
};

/** Trusted log configuration for Contact Monitoring mode (Section 11.2) */
export interface Configuration {
  readonly cipherSuite: CipherSuite;
  readonly signaturePublicKey: Uint8Array;
  readonly vrfPublicKey: Uint8Array;
  /** How far ahead of the local clock the rightmost timestamp may be, in milliseconds */
  readonly maxAhead: number;
  /** How far behind the local clock the rightmost timestamp may be, in milliseconds */
  readonly maxBehind: number;
  /** Expected interval between owner monitoring, in milliseconds (Section 6.1) */
  readonly reasonableMonitoringWindow: number;
  /** Age at which log entries expire, in milliseconds (Section 7.1) */
  readonly maximumLifetime?: number;
}

const CONTACT_MONITORING = 1;

export function suiteOf(c: Configuration): Suite {
  const suite = SUITES[c.cipherSuite];
  if (!suite) throw new Error("unsupported cipher suite");
  return suite;
}

/** TLS encoding of Configuration (Section 11.2). Throws on malformed keys or durations. */
export function encodeConfiguration(c: Configuration): Uint8Array {
  const suite = suiteOf(c);
  suite.checkSignatureKey(c.signaturePublicKey);
  suite.vrf.verifier(c.vrfPublicKey);
  const w = new Writer()
    .u16(c.cipherSuite)
    .u8(CONTACT_MONITORING)
    .opaque(2, c.signaturePublicKey)
    .opaque(2, c.vrfPublicKey)
    .u64(c.maxAhead)
    .u64(c.maxBehind)
    .u64(c.reasonableMonitoringWindow);
  // The maximum lifetime MUST be greater than zero and than the RMW (Section 7.1)
  if (c.maximumLifetime !== undefined && !(c.maximumLifetime > 0 && c.maximumLifetime > c.reasonableMonitoringWindow))
    throw new RangeError("maximum lifetime must exceed the reasonable monitoring window");
  if (c.maximumLifetime === undefined) w.u8(0);
  else w.u8(1).u64(c.maximumLifetime);
  return w.finish();
}

export const hash = (b: Uint8Array): Uint8Array => sha256(b);

/** TreeHeadTBS: the configuration, tree size and root that TreeHead.signature covers (Section 11.2) */
export const treeHeadTBS = (config: Uint8Array, treeSize: number, root: Uint8Array): Uint8Array<ArrayBuffer> =>
  new Writer().bytes(config).u64(treeSize).bytes(root).finish();

/** Verifier for TreeHead.signature, bound to one configuration */
export async function treeHeadVerifier(
  config: Configuration,
): Promise<(treeSize: number, root: Uint8Array, signature: Uint8Array) => Promise<boolean>> {
  const encoded = encodeConfiguration(config);
  const { signature } = suiteOf(config);
  const key = await crypto.subtle.importKey(
    "raw",
    config.signaturePublicKey as Uint8Array<ArrayBuffer>,
    signature.import,
    false,
    ["verify"],
  );
  return (treeSize, root, sig) => {
    if (sig.length !== 64 || root.length !== NH) return Promise.resolve(false);
    return crypto.subtle.verify(
      signature.sign,
      key,
      sig as Uint8Array<ArrayBuffer>,
      treeHeadTBS(encoded, treeSize, root),
    );
  };
}

/** VrfInput (Section 11.7). */
export const vrfInput = (label: Uint8Array, version: number): Uint8Array =>
  new Writer().opaque(1, label).u32(version).finish();

/** HMAC(Kc, CommitmentValue) (Section 11.6) with a contact-monitoring UpdateValue (Section 11.5). */
export const commitment = (opening: Uint8Array, label: Uint8Array, version: number, value: Uint8Array): Uint8Array => {
  if (opening.length !== NC) throw new Error("invalid opening");
  return hmac(sha256, KC, new Writer().bytes(opening).opaque(1, label).u32(version).opaque(4, value).finish());
};

/** Log tree leaf (Section 11.8). */
export const logLeaf = (timestamp: number, prefixRoot: Uint8Array): Uint8Array =>
  hash(new Writer().u64(timestamp).bytes(prefixRoot).finish());

/** Log tree parent: Hash(hashContent(left) || hashContent(right)), where hashContent prefixes 0x00 to a leaf and 0x01 to a parent (Section 11.8) */
export const logParent = (left: Uint8Array, leftIsLeaf: boolean, right: Uint8Array, rightIsLeaf: boolean) =>
  hash(concatBytes(new Uint8Array([leftIsLeaf ? 0 : 1]), left, new Uint8Array([rightIsLeaf ? 0 : 1]), right));

/** Prefix tree leaf (Section 11.9). */
export const prefixLeaf = (vrfOutput: Uint8Array, commitment: Uint8Array): Uint8Array =>
  hash(concatBytes(new Uint8Array([0x02]), vrfOutput, commitment));

/** Prefix tree parent: Hash(0x03 || left || right), with an all-zero value for a missing child (Section 11.9) */
export const prefixParent = (left: Uint8Array, right: Uint8Array): Uint8Array =>
  hash(concatBytes(new Uint8Array([0x03]), left, right));

/** Encoded VRF public key for a 32-byte VRF secret key, for building a Configuration */
export const vrfPublicKey = (cipherSuite: CipherSuite, secretKey: Uint8Array): Uint8Array =>
  SUITES[cipherSuite].vrf.key(secretKey).publicKey;
