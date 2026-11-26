/** Third-Party Auditor (Section 15.2) */
import { equalBytes } from "@noble/curves/utils.js";
import { isDistinguished } from "./combined.ts";
import { type Configuration, NH, auditorTreeHeadTBS, encodeConfiguration, hash, logLeaf } from "./crypto.ts";
import { KTError, KTErrorCode } from "./errors.ts";
import { frontier } from "./ibst.ts";
import { appendLeaf, fullSubtrees, rootFromFullSubtrees } from "./logtree.ts";
import { type AuditorUpdate, decodeAuditorUpdate, encodeAuditorTreeHead } from "./messages.ts";
import { type Lookup, ResultType, insert, rebuild, remove, rootHash } from "./prefix.ts";
import { type Store, memoryStore } from "./store.ts";
import { Writer, copy, decode } from "./tls.ts";

/** What the auditor keeps of a verified log entry */
export interface AuditedEntry {
  /** Hash of the configuration and the trusted start the entry was verified under */
  readonly binding: Uint8Array;
  readonly timestamp: number;
  /** VRF outputs of the leaves the entry added and removed */
  readonly added: readonly Uint8Array[];
  readonly removed: readonly Uint8Array[];
  readonly prefixRoot: Uint8Array;
  /** Hash of the AuditorUpdate, so retrying the last one succeeds */
  readonly digest: Uint8Array;
}

export interface AuditorOptions {
  /** Web Crypto key pair for the suite's signature algorithm, matching the configuration's auditor key */
  readonly signingKey: CryptoKeyPair;
  /**
   * Trusted view of the log before `Configuration.auditor.startPosition`, from
   * `log.auditorStart`. Required when that position is not zero.
   */
  readonly start?: AuditorStart | undefined;
  /**
   * Where verified entries are persisted, trusted like the signing key, at positions
   * counted from the start. Defaults to memory.
   */
  readonly store?: Store<AuditedEntry>;
  /**
   * Leaves an update may name. The operator chooses VRF outputs the auditor cannot
   * check, so each leaf may cost a path of 256 nodes. Defaults to 1024.
   */
  readonly maxLeaves?: number;
  /** Milliseconds since the Unix epoch. Updates more than `maxAhead` past it are rejected. */
  readonly now?: () => number;
}

export interface Auditor {
  /** Number of log entries verified */
  readonly size: number;
  /** Verifies and stores the TLS-encoded AuditorUpdate for the log entry at `position`. Repeating the last one succeeds. */
  apply(position: number, update: Uint8Array): Promise<void>;
  /** TLS-encoded AuditorTreeHead covering every verified entry, signed once per size */
  head(): Promise<Uint8Array>;
}

/** What an auditor starting after the first log entry trusts about the log before it */
export interface AuditorStart {
  /** Prefix tree root of the entry before the start */
  readonly prefixRoot: Uint8Array;
  /** Log tree full subtree heads, left to right */
  readonly fullSubtrees: readonly Uint8Array[];
  /** Timestamps of the frontier entries, root first */
  readonly frontier: readonly number[];
}

/** The auditor's view of the log after `size` entries */
export interface AuditorState {
  size: number;
  /** Position counted for leaves added before the auditor started, the latest they could be */
  readonly unseen: number | undefined;
  prefixRoot: Uint8Array;
  fullSubtrees: Uint8Array[];
  /** Timestamps of the frontier entries, which decide where a removed leaf was published */
  readonly frontier: Map<number, number>;
  /** Position of the entry that added each leaf of the prefix tree, by VRF output */
  readonly positions: Map<string, number>;
}

/** VRF output as a map key. Comparing these strings orders the outputs bytewise. */
export const keyOf = (b: Uint8Array): string => String.fromCharCode(...b);

const ascending = (keys: readonly string[]): boolean => keys.every((k, i) => i === 0 || keys[i - 1]! < k);

/**
 * Checks an AuditorUpdate against the auditor's state and returns the new prefix
 * tree root (Section 15.2 steps 1 to 7). An update without changes keeps the root.
 * Throws if the update fails a check.
 */
export function audit(s: AuditorState, u: AuditorUpdate, reasonableMonitoringWindow: number): Uint8Array {
  if (u.timestamp < (s.frontier.get(s.size - 1) ?? 0)) throw new Error("timestamp decreases");
  const added = u.added.map((l) => keyOf(l.vrfOutput));
  const removed = u.removed.map((l) => keyOf(l.vrfOutput));
  const moved = u.leaves.map((l) => keyOf(l.vrfOutput));
  if (!ascending(added) || !ascending(removed) || !ascending(moved)) throw new Error("leaves unsorted or repeated");
  const isAdded = new Set(added);
  const commitments = new Map(u.removed.map((l, i) => [removed[i]!, l.commitment]));
  if (moved.some((k) => isAdded.has(k) || commitments.has(k))) throw new Error("moved leaf also added or removed");

  const { results, elements } = u.proof;
  if (results.length !== added.length + removed.length + moved.length) throw new Error("results do not match leaves");
  for (const [i, r] of results.entries()) {
    const inclusion = r.type === ResultType.Inclusion;
    if (i < added.length ? inclusion && !commitments.has(added[i]!) : !inclusion)
      throw new Error("unexpected search result");
  }

  // Each removed leaf was in a distinguished entry, counting the new one. A
  // distinguished entry has distinguished ancestors, one of them on the frontier.
  const c = {
    n: s.size + 1,
    timestamp: (x: number) => {
      const t = x === s.size ? u.timestamp : s.frontier.get(x);
      if (t === undefined) throw new Error("timestamp not retained");
      return t;
    },
  };
  for (const k of removed) {
    const p = s.positions.get(k) ?? s.unseen;
    if (p === undefined) throw new Error("removed leaf never added");
    if (!frontier(s.size).some((x) => x >= p && isDistinguished(c, reasonableMonitoringWindow, x)))
      throw new Error("removed leaf never published in a distinguished entry");
  }

  if (!results.length) {
    if (elements.length) throw new Error("prefix proof too long");
    return s.prefixRoot;
  }
  const lookups: Lookup[] = [...u.added, ...u.removed, ...u.leaves].map((l, i) => ({
    key: l.vrfOutput,
    result: results[i]!,
    commitment: i < added.length ? commitments.get(added[i]!) : l.commitment,
  }));
  let tree = rebuild(lookups, elements);
  if (!equalBytes(rootHash(tree), s.prefixRoot)) throw new Error("prefix root does not match");
  for (const l of u.removed) tree = remove(tree, l.vrfOutput);
  for (const l of u.added) tree = insert(tree, l.vrfOutput, l.commitment);
  return rootHash(tree);
}

function advance(s: AuditorState, e: AuditedEntry): void {
  for (const k of e.removed) s.positions.delete(keyOf(k));
  for (const k of e.added) s.positions.set(keyOf(k), s.size);
  s.fullSubtrees = appendLeaf(s.size, s.fullSubtrees, logLeaf(e.timestamp, e.prefixRoot));
  s.frontier.set(s.size, e.timestamp);
  s.size++;
  const kept = new Set(frontier(s.size));
  for (const x of s.frontier.keys()) if (!kept.has(x)) s.frontier.delete(x);
  s.prefixRoot = e.prefixRoot;
}

/** Opens an auditor for the log that `config` describes, restoring what `store` holds */
export async function openAuditor(config: Configuration, options: AuditorOptions): Promise<Auditor> {
  if (!config.auditor) throw new Error("the configuration has no auditor");
  const at = config.auditor.startPosition;
  const { start } = options;
  if (
    (at === 0) !== (start === undefined) ||
    (start && (start.fullSubtrees.length !== fullSubtrees(at).length || start.frontier.length !== frontier(at).length))
  )
    throw new Error("the start does not match the start position");
  const encoded = encodeConfiguration(config);
  const w = new Writer().bytes(encoded);
  if (start) {
    w.bytes(start.prefixRoot);
    for (const h of start.fullSubtrees) w.bytes(h);
    for (const t of start.frontier) w.u64(t);
  }
  const binding = hash(w.finish());
  const { signature } = config.cipherSuite;
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", options.signingKey.publicKey));
  if (!equalBytes(publicKey, config.auditor.publicKey)) throw new Error("key does not match the configuration");
  const store = options.store ?? memoryStore<AuditedEntry>();
  const rmw = config.reasonableMonitoringWindow;
  const maxLeaves = options.maxLeaves ?? 1024;
  const now = options.now ?? Date.now;

  const s: AuditorState = {
    size: at,
    unseen: at ? at - 1 : undefined,
    prefixRoot: start ? copy(start.prefixRoot) : new Uint8Array(NH),
    fullSubtrees: (start?.fullSubtrees ?? []).map(copy),
    frontier: new Map(at ? frontier(at).map((x, i) => [x, start!.frontier[i]!]) : []),
    positions: new Map(),
  };
  let last: AuditedEntry | undefined;
  let signed: { size: number; head: Uint8Array } | undefined;
  let broken: Error | undefined;
  let queue: Promise<unknown> = Promise.resolve();
  const serial = <T>(work: () => Promise<T>): Promise<T> => {
    const run = queue.then(work);
    queue = run.catch(() => {});
    return run;
  };

  /** Applies stored entries past the state */
  async function replay(): Promise<void> {
    try {
      for await (const e of store.read(s.size - at)) {
        if (!equalBytes(e.binding, binding)) throw new Error("entry verified under another configuration or start");
        advance(s, e);
        last = e;
      }
    } catch (e) {
      broken = new Error("the store does not hold a valid audit", { cause: e });
      throw broken;
    }
  }
  await replay();

  async function apply(position: number, bytes: Uint8Array): Promise<void> {
    if (broken) throw broken;
    const digest = hash(bytes);
    if (last && position === s.size - 1 && equalBytes(digest, last.digest)) return;
    if (position !== s.size) throw new KTError(KTErrorCode.Conflict);
    let update: AuditorUpdate;
    let prefixRoot: Uint8Array;
    try {
      update = decode(bytes, (r) => decodeAuditorUpdate(r, maxLeaves));
      if (update.timestamp > now() + config.maxAhead) throw new Error("timestamp ahead of the clock");
      prefixRoot = audit(s, update, rmw);
    } catch (e) {
      throw new KTError(KTErrorCode.InvalidRequest, { cause: e });
    }
    const entry: AuditedEntry = {
      binding,
      timestamp: update.timestamp,
      added: update.added.map((l) => l.vrfOutput),
      removed: update.removed.map((l) => l.vrfOutput),
      prefixRoot,
      digest,
    };
    try {
      await store.append(position - at, entry);
    } catch (e) {
      // The outcome is ambiguous: catch up with the store, and succeed if it holds this update
      await replay();
      if (last && s.size === position + 1 && equalBytes(last.digest, digest)) return;
      throw new KTError(KTErrorCode.Conflict, { cause: e });
    }
    advance(s, entry);
    last = entry;
  }

  async function head(): Promise<Uint8Array> {
    if (broken) throw broken;
    if (!last) throw new KTError(KTErrorCode.NotFound);
    if (signed?.size !== s.size) {
      const { size } = s;
      const tbs = auditorTreeHeadTBS(encoded, last.timestamp, size, rootFromFullSubtrees(size, s.fullSubtrees));
      const sig = new Uint8Array(await crypto.subtle.sign(signature.sign, options.signingKey.privateKey, tbs));
      signed = { size, head: encodeAuditorTreeHead({ timestamp: last.timestamp, treeSize: size, signature: sig }) };
    }
    return copy(signed.head);
  }

  return {
    get size() {
      return s.size;
    },
    apply: (position, update) => serial(() => apply(position, update)),
    head: () => serial(head),
  };
}
