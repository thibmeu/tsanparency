/** Cipher suites and the computations of protocol Section 11 */
import { concatBytes, equalBytes } from "@noble/curves/utils.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { Writer } from "./tls.ts";
import type { Vrf } from "./vrf.ts";

/** Hash.Nh and VRF.Nh, shared by both suites (Section 17.1) */
export const NH = 32;
/** Size of commitment openings */
export const NC = 16;
const KC = new Uint8Array([
  0xd8, 0x21, 0xf8, 0x79, 0x0d, 0x97, 0x70, 0x97, 0x96, 0xb4, 0xd7, 0x90, 0x33, 0x57, 0xc3, 0xf5,
]);

/** A KT cipher suite (Section 17.1). Both suites hash with SHA-256. */
export interface CipherSuite {
  /** Value in the KT Cipher Suites registry */
  readonly id: number;
  readonly vrf: Vrf;
  /** Web Crypto algorithm for tree head signatures */
  readonly signature: { readonly import: EcKeyImportParams | Algorithm; readonly sign: EcdsaParams | Algorithm };
}

/** Trusted log configuration, in Contact Monitoring or Third-Party Auditing mode (Section 11.2) */
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
  /** Third-Party Auditor attesting to the log's construction (Section 15.2) */
  readonly auditor?: {
    /** Signature public key for AuditorTreeHead */
    readonly publicKey: Uint8Array;
    /** How far the auditor may lag behind the rightmost log entry, in milliseconds */
    readonly maxLag: number;
    /** Position of the first log entry the auditor processed */
    readonly startPosition: number;
  };
}

const CONTACT_MONITORING = 1;
const THIRD_PARTY_AUDITING = 3;

/**
 * TLS encoding of Configuration (Section 11.2). Throws on invalid durations. Keys
 * are checked where they are used.
 */
export function encodeConfiguration(c: Configuration): Uint8Array {
  const w = new Writer()
    .u16(c.cipherSuite.id)
    .u8(c.auditor ? THIRD_PARTY_AUDITING : CONTACT_MONITORING)
    .opaque(2, c.signaturePublicKey)
    .opaque(2, c.vrfPublicKey);
  if (c.auditor) {
    w.u64(c.auditor.maxLag).u64(c.auditor.startPosition).opaque(2, c.auditor.publicKey);
  }
  w.u64(c.maxAhead).u64(c.maxBehind).u64(c.reasonableMonitoringWindow);
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

/** AuditorTreeHeadTBS: what AuditorTreeHead.signature covers (Section 11.3) */
export const auditorTreeHeadTBS = (
  config: Uint8Array,
  timestamp: number,
  treeSize: number,
  root: Uint8Array,
): Uint8Array<ArrayBuffer> => new Writer().bytes(config).u64(timestamp).u64(treeSize).bytes(root).finish();

async function verifier(config: Configuration, publicKey: Uint8Array) {
  const { signature } = config.cipherSuite;
  const key = await crypto.subtle.importKey("raw", publicKey as Uint8Array<ArrayBuffer>, signature.import, true, [
    "verify",
  ]);
  // Web Crypto accepts encodings the suite does not, such as compressed points
  if (!equalBytes(new Uint8Array(await crypto.subtle.exportKey("raw", key)), publicKey))
    throw new Error("public key is not in the suite's encoding");
  return (tbs: Uint8Array<ArrayBuffer>, sig: Uint8Array): Promise<boolean> =>
    sig.length === 64
      ? crypto.subtle.verify(signature.sign, key, sig as Uint8Array<ArrayBuffer>, tbs)
      : Promise.resolve(false);
}

/** Verifier for TreeHead.signature, bound to one configuration */
export async function treeHeadVerifier(
  config: Configuration,
): Promise<(treeSize: number, root: Uint8Array, signature: Uint8Array) => Promise<boolean>> {
  const encoded = encodeConfiguration(config);
  const verify = await verifier(config, config.signaturePublicKey);
  return (treeSize, root, sig) =>
    root.length === NH ? verify(treeHeadTBS(encoded, treeSize, root), sig) : Promise.resolve(false);
}

/** Verifier for AuditorTreeHead.signature, bound to a configuration with an auditor */
export async function auditorTreeHeadVerifier(
  config: Configuration,
): Promise<(timestamp: number, treeSize: number, root: Uint8Array, signature: Uint8Array) => Promise<boolean>> {
  if (!config.auditor) throw new Error("the configuration has no auditor");
  const encoded = encodeConfiguration(config);
  const verify = await verifier(config, config.auditor.publicKey);
  return (timestamp, treeSize, root, sig) =>
    root.length === NH ? verify(auditorTreeHeadTBS(encoded, timestamp, treeSize, root), sig) : Promise.resolve(false);
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
  cipherSuite.vrf.key(secretKey).publicKey;
