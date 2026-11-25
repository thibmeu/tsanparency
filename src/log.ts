/** In-memory Transparency Log serving the user operations of Section 13 */
import { bytesToHex, equalBytes } from "@noble/curves/utils.js";
import {
  type Snapshot,
  Prover,
  contactMonitor,
  fixedVersionSearch,
  greatestVersionSearch,
  labelUpdate,
  ownerInit,
  ownerMonitor,
  updateView,
} from "./combined.ts";
import {
  type Configuration,
  NC,
  commitment,
  encodeConfiguration,
  logLeaf,
  logParent,
  suiteOf,
  treeHeadTBS,
  treeHeadVerifier,
  vrfInput,
} from "./crypto.ts";
import { KTError, KTErrorCode } from "./errors.ts";
import { ancestors } from "./ibst.ts";
import { baseLadder } from "./ladder.ts";
import { type Range, fullSubtrees, rootFromFullSubtrees } from "./logtree.ts";
import {
  type MonitorMapEntry,
  decodeContactMonitorRequest,
  decodeOwnerInitRequest,
  decodeOwnerMonitorRequest,
  decodeSearchRequest,
  decodeUpdateRequest,
  encodeContactMonitorResponse,
  encodeOwnerInitResponse,
  encodeOwnerMonitorResponse,
  encodeSearchResponse,
  encodeUpdateResponse,
} from "./messages.ts";
import { type Node, insert, rootHash } from "./prefix.ts";
import { type StoredVersion, type Store, memoryStore } from "./store.ts";
import { type Reader, decode } from "./tls.ts";
import { Operation } from "./client.ts";

export interface Authorization {
  readonly operation: Operation;
  readonly label: Uint8Array;
  readonly principal: string;
}

export interface Limits {
  readonly maxRequestBytes: number;
  readonly maxValueBytes: number;
  /** Concurrent `handle` calls before rejecting with Overloaded. */
  readonly maxActiveReads: number;
  /** Queued `append`/`tick` calls before rejecting with Overloaded. */
  readonly maxPendingWrites: number;
}

export interface LogOptions {
  /** Web Crypto key pair for the suite's signature algorithm, matching the configuration */
  readonly signingKey: CryptoKeyPair;
  /** 32-byte VRF secret key matching the configuration */
  readonly vrfSecretKey: Uint8Array;
  /**
   * Decides access per operation. Without it, Search is open, Contact Monitor is
   * open for versions the principal found, and owner operations are denied.
   */
  readonly authorize?: (request: Authorization) => boolean | Promise<boolean>;
  readonly limits?: Partial<Limits>;
  /** Where log entries are persisted. Defaults to memory. */
  readonly store?: Store;
  /** Milliseconds since the Unix epoch. */
  readonly now?: () => number;
}

export type Update = {
  readonly label: Uint8Array | string;
  /** null creates the label, and a number must equal the latest version */
  readonly expectedVersion: number | null;
} & (
  | { readonly value: Uint8Array }
  /** Consecutive new versions created in one log entry */
  | { readonly values: readonly Uint8Array[] }
);

export interface HandleOptions {
  readonly principal: string;
  readonly signal?: AbortSignal | undefined;
}

export interface Log {
  /** Number of published log entries. */
  readonly size: number;
  /** Adds new versions of a label and publishes them in a new log entry */
  append(update: Update, options?: { readonly signal?: AbortSignal }): Promise<{ version: number; position: number }>;
  /** Publishes a log entry without changes, keeping the tree head fresh. */
  tick(options?: { readonly signal?: AbortSignal }): Promise<void>;
  /** Answers a TLS-encoded request for `operation`. */
  handle(operation: Operation, request: Uint8Array, options: HandleOptions): Promise<Uint8Array>;
}

/** Distinguished entries proven per Owner Monitoring response (Section 8.3) */
const OWNER_LADDERS = 25;

const DEFAULT_LIMITS: Limits = {
  maxRequestBytes: 4096,
  maxValueBytes: 1 << 16,
  maxActiveReads: 64,
  maxPendingWrites: 64,
};

interface Version {
  readonly position: number;
  readonly opening: Uint8Array;
  readonly value: Uint8Array;
  readonly commitment: Uint8Array;
}

interface LabelState {
  readonly versions: Version[];
  /** VRF outputs, with proofs computed on first use */
  readonly vrf: Map<number, { output: Uint8Array; proof?: Uint8Array }>;
}

interface Entry {
  readonly timestamp: number;
  readonly root: Uint8Array;
  /** Cleared once the entry expires (Section 7.1, Appendix D) */
  tree: Node;
}

interface Head {
  readonly treeSize: number;
  readonly signature: Uint8Array;
}

export async function openLog(config: Configuration, options: LogOptions): Promise<Log> {
  const encodedConfig = encodeConfiguration(config);
  const suite = suiteOf(config);
  const vrf = suite.vrf.key(options.vrfSecretKey);
  const signingPublic = new Uint8Array(await crypto.subtle.exportKey("raw", options.signingKey.publicKey));
  if (!equalBytes(vrf.publicKey, config.vrfPublicKey) || !equalBytes(signingPublic, config.signaturePublicKey))
    throw new Error("keys do not match the configuration");
  const limits = { ...DEFAULT_LIMITS, ...options.limits };
  const now = options.now ?? Date.now;
  const params = {
    reasonableMonitoringWindow: config.reasonableMonitoringWindow,
    maximumLifetime: config.maximumLifetime,
  };

  const store = options.store ?? memoryStore();
  let lastRoot: Uint8Array | undefined;
  const entries: Entry[] = [];
  /** heads[k][i] is the head of the balanced subtree of size 2^k starting at i * 2^k. */
  const heads: Uint8Array[][] = [];
  const labels = new Map<string, LabelState>();
  const grants = new Map<string, Set<string>>();
  let head: Head | undefined;
  let writes: Promise<unknown> = Promise.resolve();
  let pendingWrites = 0;
  let activeReads = 0;

  const snapshot = (size: number): Snapshot => ({
    size,
    timestamp: (x) => entries[x]!.timestamp,
    prefixTree: (x) => {
      if (x < pruned) throw new KTError(KTErrorCode.Expired);
      return entries[x]!.tree;
    },
    prefixRoot: (x) => entries[x]!.root,
    head: (r: Range) => heads[Math.log2(r.size)]![r.start / r.size]!,
  });

  const vrfOf = (state: LabelState, label: Uint8Array, v: number) => {
    let out = state.vrf.get(v);
    if (!out?.proof) {
      const { proof, output } = vrf.prove(vrfInput(label, v));
      if (out && !equalBytes(out.output, output)) throw new Error("stored VRF output does not match the key");
      out = { proof, output };
      state.vrf.set(v, out);
    }
    return out as { output: Uint8Array; proof: Uint8Array };
  };
  const vrfOutput = (state: LabelState, label: Uint8Array, v: number) =>
    state.vrf.get(v)?.output ?? vrfOf(state, label, v).output;

  /** Appends a log entry, signs it, then makes it visible. Rolls back on failure. */
  /** Adds a log entry's leaf and the balanced subtree heads it completes, and returns the new root */
  function grow(timestamp: number, tree: Node): Uint8Array {
    const n = entries.length;
    entries.push({ timestamp, root: rootHash(tree), tree });
    let value = logLeaf(timestamp, rootHash(tree));
    for (let k = 0, i = n; ; k++, i = (i - 1) / 2) {
      (heads[k] ??= []).push(value);
      if (i % 2 === 0) break;
      value = logParent(heads[k]![i - 1]!, k === 0, value, k === 0);
    }
    return rootFromFullSubtrees(n + 1, fullSubtrees(n + 1).map(snapshot(n + 1).head));
  }

  let pruned = 0;
  /**
   * Drops the prefix trees of expired entries, keeping their root hashes for
   * inclusion proofs. Nodes still shared with newer trees stay reachable.
   */
  function prune(): void {
    const ml = config.maximumLifetime;
    if (ml === undefined) return;
    const rightmost = entries.at(-1)!.timestamp;
    for (; pruned < entries.length - 1 && rightmost - entries[pruned]!.timestamp >= ml; pruned++)
      entries[pruned]!.tree = null;
  }

  function shrinkTo(n: number): void {
    pruned = Math.min(pruned, n);
    entries.length = n;
    for (let k = 0, i = n; heads[k] && heads[k]!.length > i; k++, i = Math.floor(i / 2)) heads[k]!.length = i;
  }

  /**
   * Appends a log entry, signs it and stores it, then makes it visible. Rolls back
   * on failure, and catches up with the store when another writer got there first.
   */
  async function publish(tree: Node, versions: readonly StoredVersion[], rollback: () => void): Promise<number> {
    const n = entries.length;
    const timestamp = Math.max(now(), entries.at(-1)?.timestamp ?? 0);
    const root = grow(timestamp, tree);
    try {
      const tbs = treeHeadTBS(encodedConfig, n + 1, root);
      const signature = new Uint8Array(
        await crypto.subtle.sign(suite.signature.sign, options.signingKey.privateKey, tbs),
      );
      await store.append(n, { timestamp, versions, signature });
      head = { treeSize: n + 1, signature };
      prune();
      return n;
    } catch (e) {
      shrinkTo(n);
      rollback();
      await replay(n).catch(() => {});
      throw e;
    }
  }

  /** Rebuilds memory from stored entries at and after position `from` */
  async function replay(from: number): Promise<void> {
    for await (const e of store.read(from)) {
      const position = entries.length;
      let tree = entries.at(-1)?.tree ?? null;
      for (const v of e.versions) {
        const state = labelState(v.label);
        if (v.version !== state.versions.length) throw new Error("stored versions are not consecutive");
        const c = commitment(v.opening, v.label, v.version, v.value);
        tree = insert(tree, v.vrfOutput, c);
        state.versions.push({ position, opening: v.opening, value: v.value, commitment: c });
        state.vrf.set(v.version, { output: v.vrfOutput });
      }
      const root = grow(e.timestamp, tree);
      head = { treeSize: position + 1, signature: e.signature };
      lastRoot = root;
    }
    if (entries.length) prune();
  }

  function enqueue<T>(signal: AbortSignal | undefined, work: () => Promise<T>): Promise<T> {
    signal?.throwIfAborted();
    if (pendingWrites >= limits.maxPendingWrites) throw new KTError(KTErrorCode.Overloaded);
    pendingWrites++;
    const run = writes.then(() => {
      signal?.throwIfAborted();
      return work();
    });
    writes = run.then(
      () => pendingWrites--,
      () => pendingWrites--,
    );
    return run;
  }

  function lookup(label: Uint8Array, size: number) {
    const state = labels.get(bytesToHex(label));
    const greatest = state?.versions.findLastIndex((v) => v.position < size) ?? -1;
    if (!state || greatest < 0) throw new KTError(KTErrorCode.NotFound);
    return { state, greatest };
  }

  /** Label state for proofs, created empty so VRF proofs are cached for unused labels too */
  function labelState(label: Uint8Array): LabelState {
    const key = bytesToHex(label);
    let state = labels.get(key);
    if (!state) labels.set(key, (state = { versions: [], vrf: new Map() }));
    return state;
  }

  /** Greatest version as of log entry x */
  const greatestAt = (state: LabelState, x: number): number | undefined => {
    const v = state.versions.findLastIndex((e) => e.position <= x);
    return v < 0 ? undefined : v;
  };

  const prover = (state: LabelState, label: Uint8Array, n: number, last: number | undefined) => {
    const p = new Prover(snapshot(n), last ?? 0, (v) => vrfOf(state, label, v).output);
    updateView(p, last ?? 0);
    return p;
  };

  const steps = (
    state: LabelState,
    label: Uint8Array,
    versions: Iterable<number>,
    withCommitment: (v: number) => boolean,
  ) =>
    [...versions].map((v) => ({
      proof: vrfOf(state, label, v).proof,
      commitment: withCommitment(v) ? state.versions[v]!.commitment : undefined,
    }));

  const grantKey = (label: Uint8Array, version: number) => `${bytesToHex(label)}:${version}`;

  /** Checks a monitoring map against the rules of Sections 13.2 and 13.4 */
  function checkEntries(state: LabelState, entries: readonly MonitorMapEntry[], n: number, greatest: number): void {
    const versions = new Set<number>();
    for (const [i, e] of entries.entries()) {
      const first = state.versions[e.version]?.position;
      const valid =
        e.version <= greatest &&
        first !== undefined &&
        (e.position === first || ancestors(first, n).includes(e.position)) &&
        (i === 0 || entries[i - 1]!.position < e.position) &&
        !versions.has(e.version);
      if (!valid) throw new KTError(KTErrorCode.InvalidRequest);
      versions.add(e.version);
    }
  }

  /** Inserts consecutive versions of one label into a new log entry */
  async function insertVersions(label: Uint8Array, values: readonly Uint8Array[], expected: number | null) {
    const state = labelState(label);
    const latest = state.versions.length - 1;
    if ((expected ?? -1) !== latest) throw new KTError(KTErrorCode.Conflict);
    let tree = entries.at(-1)?.tree ?? null;
    const position = entries.length;
    const stored: StoredVersion[] = [];
    for (const value of values) {
      const version = state.versions.length;
      const opening = crypto.getRandomValues(new Uint8Array(NC));
      const c = commitment(opening, label, version, value);
      const output = vrfOutput(state, label, version);
      tree = insert(tree, output, c);
      state.versions.push({ position, opening, value, commitment: c });
      stored.push({ label, version, opening, value, vrfOutput: output });
    }
    await publish(tree, stored, () => {
      state.versions.length = latest + 1;
    });
    return { version: state.versions.length - 1, position };
  }

  const handlers: Record<Operation, (r: Reader, principal: string, current: Head) => Promise<Uint8Array>> = {
    async [Operation.Search](r, principal, current) {
      const req = decodeSearchRequest(r);
      const n = current.treeSize;
      checkLast(req.last, n);
      await authorize(Operation.Search, req.label, principal);
      const { state, greatest } = lookup(req.label, n);
      const t = req.version ?? greatest;
      if (t > greatest) throw new KTError(KTErrorCode.NotFound);
      const p = prover(state, req.label, n, req.last);
      if (req.version === undefined) greatestVersionSearch(p, params, t);
      else fixedVersionSearch(p, params, t);
      let granted = grants.get(principal);
      if (!granted) grants.set(principal, (granted = new Set()));
      granted.add(grantKey(req.label, t));
      const target = state.versions[t]!;
      return encodeSearchResponse(
        {
          treeHead: req.last === n ? undefined : current,
          version: t,
          opening: target.opening,
          value: target.value,
          binaryLadder: steps(state, req.label, baseLadder(t), (v) => v !== t && v <= greatest),
          search: p.finish(),
        },
        req.version !== undefined,
      );
    },

    async [Operation.ContactMonitor](r, principal, current) {
      const req = decodeContactMonitorRequest(r);
      const n = current.treeSize;
      checkLast(req.last, n);
      if (!req.entries.length) throw new KTError(KTErrorCode.InvalidRequest);
      // Users keep monitoring versions they looked up even once access is revoked (Section 13.2)
      const entitled = req.entries.every((e) => grants.get(principal)?.has(grantKey(req.label, e.version)));
      if (!entitled) await authorize(Operation.ContactMonitor, req.label, principal);
      const { state, greatest } = lookup(req.label, n);
      checkEntries(state, req.entries, n, greatest);
      const p = prover(state, req.label, n, req.last);
      contactMonitor(p, params, req.entries);
      return encodeContactMonitorResponse({ treeHead: req.last === n ? undefined : current, monitor: p.finish() });
    },

    async [Operation.OwnerInit](r, principal, current) {
      const req = decodeOwnerInitRequest(r);
      const n = current.treeSize;
      checkLast(req.last, n);
      await authorize(Operation.OwnerInit, req.label, principal);
      if (req.start !== undefined && req.start >= n) throw new KTError(KTErrorCode.InvalidRequest);
      const state = labelState(req.label);
      const p = prover(state, req.label, n, req.last);
      const { versions } = ownerInit(p, params, req.start, (_, x) => greatestAt(state, x));
      const greatestVersions = versions.filter((v) => v !== undefined);
      const ladder = new Set([0, ...greatestVersions.flatMap(baseLadder)]);
      const atStart = req.start === undefined ? -1 : (greatestAt(state, req.start) ?? -1);
      return encodeOwnerInitResponse({
        treeHead: req.last === n ? undefined : current,
        greatestVersions,
        binaryLadder: steps(
          state,
          req.label,
          [...ladder].sort((a, b) => a - b),
          (v) => v <= atStart,
        ),
        init: p.finish(),
      });
    },

    async [Operation.OwnerMonitor](r, principal, current) {
      const req = decodeOwnerMonitorRequest(r);
      const n = current.treeSize;
      checkLast(req.last, n);
      await authorize(Operation.OwnerMonitor, req.label, principal);
      const state = labelState(req.label);
      const greatest = state.versions.findLastIndex((v) => v.position < n);
      const advertised = req.greatestVersion ?? -1;
      const atStart = req.start === undefined ? -1 : (greatestAt(state, req.start) ?? -1);
      if ((req.start !== undefined && req.start >= n) || advertised > greatest || advertised < atStart)
        throw new KTError(KTErrorCode.InvalidRequest);
      checkEntries(state, req.entries, n, greatest);
      const p = prover(state, req.label, n, req.last);
      contactMonitor(p, params, req.entries, { start: req.start });
      let ladders = 0;
      const history = { greatestAt: (x: number) => greatestAt(state, x) };
      // The log stops at a version the owner does not know yet, or after enough ladders
      ownerMonitor(
        p,
        params,
        req.start,
        history,
        (x) => (greatestAt(state, x) ?? -1) > advertised || ladders++ >= OWNER_LADDERS,
      );
      return encodeOwnerMonitorResponse({ treeHead: req.last === n ? undefined : current, monitor: p.finish() });
    },

    async [Operation.Update](r, principal, current) {
      const req = decodeUpdateRequest(r);
      checkLast(req.last, current.treeSize);
      await authorize(Operation.Update, req.label, principal);
      const state = labelState(req.label);
      const advertised = req.greatestVersion ?? -1;
      const known = state.versions.findLastIndex((v) => v.position < current.treeSize);
      if (advertised > known || (advertised === known && !req.values.length))
        throw new KTError(KTErrorCode.InvalidRequest);
      if (req.values.some((v) => v.length > limits.maxValueBytes)) throw new KTError(KTErrorCode.InvalidRequest);
      // Report versions the owner has not seen yet, or create the requested ones
      let at = current;
      let disregarded = false;
      if (advertised < known) disregarded = true;
      else {
        await enqueue(undefined, () => insertVersions(req.label, req.values, req.greatestVersion ?? null));
        at = head!;
      }
      const n = at.treeSize;
      const position = state.versions[advertised + 1]!.position;
      const created = state.versions.filter((v, i) => i > advertised && v.position === position);
      const after = advertised + created.length;
      const before = req.greatestVersion;
      const p = prover(state, req.label, n, req.last);
      const history = {
        greatest: before,
        lastUpdate: before === undefined ? undefined : state.versions[before]!.position,
        greatestAt: (x: number) => greatestAt(state, x),
      };
      labelUpdate(p, params, history, position, created.length);
      // VRF proofs the owner lacks: the search ladder for the new greatest version and
      // each new version, less the search ladder it already knows (Section 9.1)
      const wanted = new Set([
        ...baseLadder(after),
        ...(created.length > 1 ? created.map((_, i) => advertised + 1 + i) : []),
      ]);
      for (const v of before === undefined ? [0] : baseLadder(before)) wanted.delete(v);
      return encodeUpdateResponse({
        treeHead: req.last === n ? undefined : at,
        position,
        values: disregarded ? created.map((v) => v.value) : [],
        openings: created.map((v) => v.opening),
        binaryLadder: steps(
          state,
          req.label,
          [...wanted].sort((a, b) => a - b),
          (v) => v < advertised,
        ),
        update: p.finish(),
      });
    },
  };

  function checkLast(last: number | undefined, n: number): void {
    if (last !== undefined && (last < 1 || last > n)) throw new KTError(KTErrorCode.InvalidRequest);
  }

  async function authorize(operation: Operation, label: Uint8Array, principal: string): Promise<void> {
    const allowed = (await options.authorize?.({ operation, label, principal })) ?? operation === Operation.Search;
    if (!allowed) throw new KTError(KTErrorCode.Unauthorized);
  }

  await replay(0);
  if (head && lastRoot) {
    const verify = await treeHeadVerifier(config);
    if (!(await verify(head.treeSize, lastRoot, head.signature)))
      throw new Error("stored log does not match the configuration");
  }

  return {
    get size() {
      return head?.treeSize ?? 0;
    },

    append(update, { signal } = {}) {
      const label = typeof update.label === "string" ? new TextEncoder().encode(update.label) : update.label.slice();
      const values = ("values" in update ? update.values : [update.value]).map((v) => v.slice());
      const expected = update.expectedVersion;
      if (
        label.length > 255 ||
        !values.length ||
        values.length > 255 ||
        values.some((v) => v.length > limits.maxValueBytes) ||
        (expected !== null && !Number.isSafeInteger(expected))
      )
        throw new KTError(KTErrorCode.InvalidRequest);
      return enqueue(signal, () => insertVersions(label, values, expected));
    },

    tick({ signal } = {}) {
      return enqueue(signal, async () => {
        await publish(entries.at(-1)?.tree ?? null, [], () => {});
      });
    },

    async handle(operation, request, { principal, signal }) {
      if (request.length > limits.maxRequestBytes) throw new KTError(KTErrorCode.InvalidRequest);
      const handler = handlers[operation];
      if (!handler) throw new KTError(KTErrorCode.InvalidRequest);
      if (activeReads >= limits.maxActiveReads) throw new KTError(KTErrorCode.Overloaded);
      activeReads++;
      try {
        signal?.throwIfAborted();
        const current = head;
        if (!current) throw new KTError(KTErrorCode.NotFound);
        return await decode(request, (r) => handler(r, principal, current));
      } catch (e) {
        if (e instanceof KTError || (e instanceof DOMException && e.name === "AbortError")) throw e;
        throw new KTError(KTErrorCode.InvalidRequest, { cause: e });
      } finally {
        activeReads--;
      }
    },
  };
}
