/** In-memory Transparency Log serving Search and Contact Monitor (Sections 9, 13). */
import { bytesToHex, equalBytes } from "@noble/curves/utils.js";
import { type Snapshot, Prover, contactMonitor, greatestVersionSearch, updateView } from "./combined.ts";
import {
  type Configuration,
  NC,
  commitment,
  encodeConfiguration,
  logLeaf,
  logParent,
  suiteOf,
  treeHeadTBS,
  vrfInput,
} from "./crypto.ts";
import { KTError, KTErrorCode } from "./errors.ts";
import { ancestors } from "./ibst.ts";
import { baseLadder } from "./ladder.ts";
import { type Range, fullSubtrees, rootFromFullSubtrees } from "./logtree.ts";
import {
  type ContactMonitorRequest,
  type SearchRequest,
  decodeContactMonitorRequest,
  decodeSearchRequest,
  encodeContactMonitorResponse,
  encodeSearchResponse,
} from "./messages.ts";
import { type Node, insert, rootHash } from "./prefix.ts";
import { DecodeError, decode } from "./tls.ts";
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
  /** Decides Search access. Monitor is also allowed for versions this principal found. */
  readonly authorize?: (request: Authorization) => boolean | Promise<boolean>;
  readonly limits?: Partial<Limits>;
  /** Milliseconds since the Unix epoch. */
  readonly now?: () => number;
}

export interface Update {
  readonly label: Uint8Array | string;
  readonly value: Uint8Array;
  /** null creates the label, and a number must equal the latest version */
  readonly expectedVersion: number | null;
}

export interface HandleOptions {
  readonly principal: string;
  readonly signal?: AbortSignal | undefined;
}

export interface Log {
  /** Number of published log entries. */
  readonly size: number;
  /** Adds a new version and publishes it in a new log entry. */
  append(update: Update, options?: { readonly signal?: AbortSignal }): Promise<{ version: number; position: number }>;
  /** Publishes a log entry without changes, keeping the tree head fresh. */
  tick(options?: { readonly signal?: AbortSignal }): Promise<void>;
  /** Answers a TLS-encoded request for `operation`. */
  handle(operation: Operation, request: Uint8Array, options: HandleOptions): Promise<Uint8Array>;
}

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
  readonly vrf: Map<number, { proof: Uint8Array; output: Uint8Array }>;
}

interface Entry {
  readonly timestamp: number;
  readonly tree: Node;
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
    prefixTree: (x) => entries[x]!.tree,
    head: (r: Range) => heads[Math.log2(r.size)]![r.start / r.size]!,
  });

  const vrfOf = (state: LabelState, label: Uint8Array, v: number) => {
    let out = state.vrf.get(v);
    if (!out) {
      const { proof, output } = vrf.prove(vrfInput(label, v));
      out = { proof, output };
      state.vrf.set(v, out);
    }
    return out;
  };

  /** Appends a log entry, signs it, then makes it visible. Rolls back on failure. */
  async function publish(tree: Node, rollback: () => void): Promise<number> {
    const n = entries.length;
    const timestamp = Math.max(now(), entries.at(-1)?.timestamp ?? 0);
    entries.push({ timestamp, tree });
    let value = logLeaf(timestamp, rootHash(tree));
    for (let k = 0, i = n; ; k++, i = (i - 1) / 2) {
      (heads[k] ??= []).push(value);
      if (i % 2 === 0) break;
      value = logParent(heads[k]![i - 1]!, k === 0, value, k === 0);
    }
    try {
      const size = n + 1;
      const root = rootFromFullSubtrees(size, fullSubtrees(size).map(snapshot(size).head));
      const tbs = treeHeadTBS(encodedConfig, size, root);
      const sig = await crypto.subtle.sign(suite.signature.sign, options.signingKey.privateKey, tbs);
      head = { treeSize: size, signature: new Uint8Array(sig) };
      return n;
    } catch (e) {
      entries.length = n;
      for (let k = 0, i = n; heads[k] && heads[k]!.length > i; k++, i = Math.floor(i / 2)) heads[k]!.length = i;
      rollback();
      throw e;
    }
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

  const grantKey = (label: Uint8Array, version: number) => `${bytesToHex(label)}:${version}`;

  async function search(principal: string, label: Uint8Array, last: number | undefined, current: Head) {
    const n = current.treeSize;
    const { state, greatest: t } = lookup(label, n);
    const prover = new Prover(snapshot(n), last ?? 0, (v) => vrfOf(state, label, v).output);
    updateView(prover, last ?? 0);
    greatestVersionSearch(prover, params, t);
    const target = state.versions[t]!;
    let granted = grants.get(principal);
    if (!granted) grants.set(principal, (granted = new Set()));
    granted.add(grantKey(label, t));
    return encodeSearchResponse({
      treeHead: last === n ? undefined : current,
      version: t,
      opening: target.opening,
      value: target.value,
      binaryLadder: baseLadder(t).map((v) => ({
        proof: vrfOf(state, label, v).proof,
        commitment: v < t ? state.versions[v]!.commitment : undefined,
      })),
      search: prover.finish(),
    });
  }

  function monitor(req: ContactMonitorRequest, current: Head) {
    const n = current.treeSize;
    const { state, greatest } = lookup(req.label, n);
    const versions = new Set<number>();
    for (const [i, e] of req.entries.entries()) {
      const first = state.versions[e.version]?.position;
      const valid =
        e.version <= greatest &&
        first !== undefined &&
        (e.position === first || ancestors(first, n).includes(e.position)) &&
        (i === 0 || req.entries[i - 1]!.position < e.position) &&
        !versions.has(e.version);
      if (!valid) throw new KTError(KTErrorCode.InvalidRequest);
      versions.add(e.version);
    }
    const prover = new Prover(snapshot(n), req.last ?? 0, (v) => vrfOf(state, req.label, v).output);
    updateView(prover, req.last ?? 0);
    try {
      contactMonitor(prover, params, req.entries);
    } catch (e) {
      if (e instanceof KTError) throw e;
      throw new KTError(KTErrorCode.InvalidRequest, { cause: e });
    }
    return encodeContactMonitorResponse({
      treeHead: req.last === n ? undefined : current,
      monitor: prover.finish(),
    });
  }

  return {
    get size() {
      return head?.treeSize ?? 0;
    },

    append(update, { signal } = {}) {
      const label = typeof update.label === "string" ? new TextEncoder().encode(update.label) : update.label.slice();
      const value = update.value.slice();
      const expected = update.expectedVersion;
      if (
        label.length > 255 ||
        value.length > limits.maxValueBytes ||
        (expected !== null && !Number.isSafeInteger(expected))
      )
        throw new KTError(KTErrorCode.InvalidRequest);
      return enqueue(signal, async () => {
        const key = bytesToHex(label);
        const state: LabelState = labels.get(key) ?? { versions: [], vrf: new Map() };
        const latest = state.versions.length - 1;
        if ((expected ?? -1) !== latest) throw new KTError(KTErrorCode.Conflict);
        const version = latest + 1;
        const opening = crypto.getRandomValues(new Uint8Array(NC));
        const c = commitment(opening, label, version, value);
        const tree = insert(entries.at(-1)?.tree ?? null, vrfOf(state, label, version).output, c);
        state.versions.push({ position: entries.length, opening, value, commitment: c });
        labels.set(key, state);
        const position = await publish(tree, () => {
          state.versions.pop();
          if (!state.versions.length) labels.delete(key);
        });
        return { version, position };
      });
    },

    tick({ signal } = {}) {
      return enqueue(signal, async () => {
        await publish(entries.at(-1)?.tree ?? null, () => {});
      });
    },

    async handle(operation, request, { principal, signal }) {
      if (request.length > limits.maxRequestBytes) throw new KTError(KTErrorCode.InvalidRequest);
      if (activeReads >= limits.maxActiveReads) throw new KTError(KTErrorCode.Overloaded);
      activeReads++;
      try {
        signal?.throwIfAborted();
        const current = head;
        if (!current) throw new KTError(KTErrorCode.NotFound);
        const req = parse(operation, request);
        const entries = "entries" in req ? req.entries : undefined;
        if (req.last !== undefined && (req.last < 1 || req.last > current.treeSize))
          throw new KTError(KTErrorCode.InvalidRequest);
        const allowed =
          (await options.authorize?.({ operation, label: req.label, principal })) ?? operation === Operation.Search;
        const entitled = entries?.every((e) => grants.get(principal)?.has(grantKey(req.label, e.version)));
        if (!allowed && !entitled) throw new KTError(KTErrorCode.Unauthorized);
        signal?.throwIfAborted();
        return entries
          ? monitor({ last: req.last, label: req.label, entries }, current)
          : await search(principal, req.label, req.last, current);
      } finally {
        activeReads--;
      }
    },
  };
}

function parse(operation: Operation, request: Uint8Array): SearchRequest | ContactMonitorRequest {
  try {
    if (operation === Operation.Search) return decode(request, decodeSearchRequest);
    if (operation === Operation.ContactMonitor) {
      const req = decode(request, decodeContactMonitorRequest);
      if (req.entries.length === 0) throw new DecodeError("no entries");
      return req;
    }
  } catch (e) {
    throw new KTError(KTErrorCode.InvalidRequest, { cause: e });
  }
  throw new KTError(KTErrorCode.InvalidRequest);
}
