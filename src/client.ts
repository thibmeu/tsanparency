/** Key Transparency client for Search and Contact Monitor (Sections 13.1, 13.2). */
import { concatBytes, equalBytes } from "@noble/curves/utils.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  type FrontierEntry,
  type LadderData,
  type View,
  Verifier,
  type OwnerHistory,
  type UpdateHistory,
  contactMonitor,
  fixedVersionSearch,
  greatestVersionSearch,
  labelUpdate,
  ownerInit,
  ownerMonitor,
  rightmostDistinguished,
  updateView,
} from "./combined.ts";
import {
  type Configuration,
  NH,
  commitment,
  encodeConfiguration,
  suiteOf,
  treeHeadVerifier,
  vrfInput,
} from "./crypto.ts";
import { KTError, KTErrorCode, isKTError } from "./errors.ts";
import { ancestors, frontier } from "./ibst.ts";
import { MAX_VERSION, baseLadder, monitoringLadder } from "./ladder.ts";
import { fullSubtrees, rootFromFullSubtrees } from "./logtree.ts";
import {
  type BinaryLadderStep,
  type MonitorMapEntry,
  decodeOwnerInitResponse,
  decodeOwnerMonitorResponse,
  decodeUpdateResponse,
  encodeOwnerInitRequest,
  encodeOwnerMonitorRequest,
  encodeUpdateRequest,
  type TreeHead,
  decodeContactMonitorResponse,
  decodeSearchResponse,
  encodeContactMonitorRequest,
  encodeSearchRequest,
} from "./messages.ts";
import { copy, decode } from "./tls.ts";

export const Operation = {
  Search: "search",
  ContactMonitor: "contactMonitor",
  OwnerInit: "ownerInit",
  OwnerMonitor: "ownerMonitor",
  Update: "update",
} as const;
export type Operation = (typeof Operation)[keyof typeof Operation];

/** Sends TLS-encoded request bytes for `operation` and returns the response bytes. */
export type Exchange = (
  operation: Operation,
  request: Uint8Array,
  options: { readonly signal?: AbortSignal | undefined; readonly maxResponseBytes: number },
) => Promise<Uint8Array>;

/** The last verified tree head, shared by all contacts of one log. */
export interface Checkpoint extends View {
  readonly binding: Uint8Array;
  readonly root: Uint8Array;
  readonly signature: Uint8Array;
}

export interface LadderEntry {
  readonly version: number;
  readonly vrfOutput: Uint8Array;
  readonly commitment: Uint8Array;
}

/** Per-label monitoring state (Section 8.2). */
export interface Contact {
  readonly binding: Uint8Array;
  readonly label: Uint8Array;
  /** Greatest version seen. Later searches may not return less. */
  readonly version: number;
  /** Commitment to the value of `version` */
  readonly commitment: Uint8Array;
  /** Map from log position to the version proven there, empty once distinguished entries cover them */
  readonly monitoring: readonly MonitorMapEntry[];
  /** VRF outputs and commitments needed for the monitoring ladders. */
  readonly ladder: readonly LadderEntry[];
}

export interface ContactState {
  readonly checkpoint: Checkpoint;
  readonly contact: Contact;
}

export interface OwnerState {
  readonly checkpoint: Checkpoint;
  readonly owner: Owner;
}

/** What a label owner retains about a version (Sections 8.3, 9.1) */
export interface OwnedVersion {
  readonly version: number;
  readonly vrfOutput: Uint8Array;
  /** Commitment of a version that exists */
  readonly commitment?: Uint8Array | undefined;
}

/** Label owner state (Sections 8.3, 9) */
export interface Owner {
  readonly binding: Uint8Array;
  readonly label: Uint8Array;
  /** Rightmost distinguished entry verified, absent before any */
  readonly start?: number | undefined;
  /** Greatest version at `start` and at each of its ancestors to its left, until the label is absent */
  readonly previous: readonly number[];
  /** Position of each version created after `start`, ascending */
  readonly upcoming: readonly number[];
  /** Contact monitoring map for versions inserted at entries that were not distinguished */
  readonly monitoring: readonly MonitorMapEntry[];
  /** VRF outputs and commitments for the ladders the owner verifies */
  readonly versions: readonly OwnedVersion[];
  /**
   * Greatest version known, or -1, when owner monitoring last stopped without
   * verifying anything. The log then claims a version the owner does not know,
   * which an update with no values must report.
   */
  readonly stalled?: number | undefined;
}

export interface UpdateResult extends OwnerState {
  /** Log entry holding the versions */
  readonly position: number;
  /** The versions created there, which are someone else's when `values` was disregarded */
  readonly versions: readonly { readonly version: number; readonly value: Uint8Array }[];
  /** Whether the log reported existing versions instead of creating the requested ones */
  readonly disregarded: boolean;
  /**
   * Whether inclusion of the versions is still unproven. At a distinguished entry
   * the log proves them later, through owner monitoring (Section 9.1).
   */
  readonly pending: boolean;
}

export interface CallOptions {
  readonly signal?: AbortSignal | undefined;
}

export interface Schedule {
  /**
   * Monitoring can complete an entry once the log's rightmost timestamp reaches
   * this: a new distinguished entry needs one RMW past the rightmost one. It is 0
   * when an entry can complete now. If a monitor call leaves the map unchanged,
   * back off before calling again.
   */
  readonly after: number;
  /**
   * Monitor before this, after which entries monitoring inspects may have expired
   * (Section 7.1), allowing for the log clock running maxAhead early. Only set when
   * the log has a maximum lifetime.
   */
  readonly before?: number;
}

export interface SearchOptions extends CallOptions {
  readonly checkpoint?: Checkpoint | undefined;
  readonly contact?: Contact | undefined;
  /** Looks up this version instead of the greatest one (Section 7) */
  readonly version?: number | undefined;
}

export interface SearchResult extends ContactState {
  readonly value: Uint8Array;
  readonly version: number;
}

export interface Client {
  /**
   * Greatest-version search, or fixed-version search when `version` is set.
   * Persist the checkpoint and contact before using `value`.
   */
  search(label: Uint8Array | string, options?: SearchOptions): Promise<SearchResult>;
  /**
   * When contact monitoring is due for this contact, or undefined when nothing needs
   * monitoring. Times are log timestamps in milliseconds since the epoch, which an
   * honest log keeps close to the local clock.
   */
  schedule(contact: Contact, options: { readonly checkpoint: Checkpoint }): Schedule | undefined;
  /** Contact monitoring. Returns the input state when nothing needs monitoring. */
  monitor(contact: Contact, options: CallOptions & { readonly checkpoint: Checkpoint }): Promise<ContactState>;
  /**
   * Takes ownership of a label from `start`, an unexpired distinguished entry, or
   * from the start of the log when absent (Section 13.3). Versions created after
   * the start are then learned with `update` and no values.
   */
  ownerInit(
    label: Uint8Array | string,
    options?: CallOptions & { readonly checkpoint?: Checkpoint | undefined; readonly start?: number | undefined },
  ): Promise<OwnerState>;
  /**
   * Creates new versions, or with no values learns versions created elsewhere
   * (Section 13.5). Call again while `disregarded` is set to catch up.
   */
  update(
    owner: Owner,
    values: readonly Uint8Array[],
    options: CallOptions & { readonly checkpoint: Checkpoint },
  ): Promise<UpdateResult>;
  /**
   * Owner monitoring (Section 13.4). Repeat until `done`, or call `update` with no
   * values when the log stops at a version the owner does not know yet.
   */
  ownerMonitor(
    owner: Owner,
    options: CallOptions & { readonly checkpoint: Checkpoint },
  ): Promise<OwnerState & { readonly done: boolean }>;
}

export interface ClientOptions {
  /** Milliseconds since the Unix epoch. */
  readonly now?: () => number;
  readonly maxResponseBytes?: number;
}

const DRAFT = utf8ToBytes("draft-ietf-keytrans-protocol-06");

export async function createClient(
  config: Configuration,
  exchange: Exchange,
  options: ClientOptions = {},
): Promise<Client> {
  const binding = sha256(concatBytes(DRAFT, encodeConfiguration(config)));
  const verifyHead = await treeHeadVerifier(config);
  const { vrf } = suiteOf(config);
  const vrfVerify = vrf.verifier(config.vrfPublicKey);
  const now = options.now ?? Date.now;
  const maxResponseBytes = options.maxResponseBytes ?? 1 << 20;

  async function call(op: Operation, request: Uint8Array, signal: AbortSignal | undefined): Promise<Uint8Array> {
    signal?.throwIfAborted();
    let response: Uint8Array;
    try {
      response = await exchange(op, request, { signal, maxResponseBytes });
    } catch (e) {
      if (signal?.aborted) throw signal.reason;
      if (isKTError(e)) throw e;
      throw new KTError(KTErrorCode.Transport, { cause: e });
    }
    signal?.throwIfAborted();
    if (!(response instanceof Uint8Array) || response.length > maxResponseBytes)
      throw new KTError(KTErrorCode.Transport);
    return response;
  }

  /** Verifies the combined proof, tree head and freshness, and returns the new checkpoint */
  async function conclude(
    verifier: Verifier,
    head: TreeHead | undefined,
    previous: Checkpoint | undefined,
    signal: AbortSignal | undefined,
  ): Promise<Checkpoint> {
    const { view, root } = verifier.finish();
    let signature: Uint8Array;
    if (head) {
      signal?.throwIfAborted();
      if (!(await verifyHead(head.treeSize, root, head.signature))) throw new Error("invalid tree head signature");
      signature = head.signature;
    } else {
      if (!previous || !equalBytes(root, previous.root)) throw new Error("root differs from the retained head");
      signature = previous.signature;
    }
    const rightmost = view.frontier.at(-1)!.timestamp;
    const t = now();
    if (rightmost > t + config.maxAhead || rightmost < t - config.maxBehind) throw new KTError(KTErrorCode.Stale);
    return { binding, ...view, root, signature };
  }

  /** New tree size, which must exceed the advertised one when the head is updated (Section 11.4) */
  function treeSize(head: TreeHead | undefined, last: number | undefined): number {
    const n = head ? head.treeSize : last;
    if (n === undefined || n < 1 || (head && last !== undefined && n <= last)) throw new Error("invalid tree size");
    return n;
  }

  const fail = (e: unknown): never => {
    if (isKTError(e) || (e instanceof DOMException && e.name === "AbortError")) throw e;
    throw new KTError(KTErrorCode.InvalidResponse, { cause: e });
  };

  const params = {
    reasonableMonitoringWindow: config.reasonableMonitoringWindow,
    maximumLifetime: config.maximumLifetime,
  };

  return {
    schedule(record, { checkpoint: saved }) {
      const checkpoint = checkCheckpoint(saved, binding);
      const map = checkContact(record, binding, record.label).monitoring;
      if (!map.length) return undefined;
      const rmw = config.reasonableMonitoringWindow;
      const ts = new Map(checkpoint.frontier.map((e) => [e.position, e.timestamp]));
      const view = { n: checkpoint.treeSize, timestamp: (x: number) => ts.get(x)!, ladder: () => {} };
      const d = rightmostDistinguished(view, rmw);
      // Frontier entries up to the rightmost distinguished one are all distinguished,
      // so an entry at or left of it completes on the next call
      const after = d !== undefined && map.some((e) => e.position <= d) ? 0 : (d === undefined ? 0 : ts.get(d)!) + rmw;
      const ml = config.maximumLifetime;
      if (ml === undefined) return { after };
      // Timestamps grow with position, so the newest frontier timestamp at or left of
      // an entry bounds its own from below, and entries monitoring inspects are newer
      const bounds = map.flatMap((e) => {
        const f = checkpoint.frontier.filter((x) => x.position <= e.position).at(-1);
        return f ? [f.timestamp + ml - config.maxAhead] : [];
      });
      return bounds.length ? { after, before: Math.min(...bounds) } : { after };
    },

    async search(label, { checkpoint: saved, contact: record, signal, version } = {}) {
      if (version !== undefined && !isUint(version, MAX_VERSION)) throw new KTError(KTErrorCode.InvalidRequest);
      const name = toLabel(label);
      const checkpoint = saved === undefined ? undefined : checkCheckpoint(saved, binding);
      if (record && !checkpoint) throw new KTError(KTErrorCode.InvalidState);
      const prior = record && checkContact(record, binding, name);
      const last = checkpoint?.treeSize;
      const bytes = await call(Operation.Search, encodeSearchRequest({ last, label: name, version }), signal);
      try {
        const res = decode(bytes, (r) => decodeSearchResponse(r, vrf.proofLength, version));
        const t = res.version;
        const versions = baseLadder(t);
        if (res.binaryLadder.length !== versions.length) throw new Error("unexpected binary ladder length");
        const n = treeSize(res.treeHead, last);
        if (prior && version === undefined && t < prior.version) throw new Error("greatest version went backwards");
        const target = commitment(res.opening, name, t, res.value);
        const data = new Map<number, LadderData>();
        for (const [i, v] of versions.entries()) {
          const step = res.binaryLadder[i]!;
          // Commitments cover every existing version but the target (Section 13.1)
          const present = step.commitment !== undefined;
          if (v === t ? present : v < t && !present) throw new Error("unexpected commitment");
          const vrfOutput = vrfVerify(vrfInput(name, v), step.proof);
          if (!vrfOutput) throw new Error("invalid VRF proof");
          data.set(v, { vrfOutput, commitment: v === t ? target : step.commitment });
        }
        const verifier = new Verifier(n, checkpoint, res.search, data);
        updateView(verifier, last ?? 0);
        const { terminal, distinguished } =
          version === undefined ? greatestVersionSearch(verifier, params, t) : fixedVersionSearch(verifier, params, t);
        const next = await conclude(verifier, res.treeHead, checkpoint, signal);
        if (prior) checkConsistent(prior, data);

        // The terminal entry must be monitored when it lies right of the rightmost
        // distinguished entry (Section 6.3). Versions created together share an entry,
        // where the greater version supersedes the lesser as in Section 8.2.
        const map = new Map((prior?.monitoring ?? []).map((e) => [e.position, e.version]));
        const tracked = [...map.values()].includes(t);
        const pending = distinguished === undefined || terminal > distinguished;
        if (pending && !tracked && !((map.get(terminal) ?? -1) > t)) map.set(terminal, t);
        const monitoring = shrink(map, n);
        const contact: Contact = {
          binding,
          label: name,
          ...(prior && prior.version > t
            ? { version: prior.version, commitment: prior.commitment }
            : { version: t, commitment: target }),
          monitoring,
          ladder: ladderFor(monitoring, prior?.ladder ?? [], data),
        };
        return { value: res.value, version: t, checkpoint: next, contact };
      } catch (e) {
        return fail(e);
      }
    },

    async monitor(record, { checkpoint: saved, signal }) {
      const name = toLabel(record.label);
      const checkpoint = checkCheckpoint(saved, binding);
      const contact = checkContact(record, binding, name);
      if (contact.monitoring.length === 0) return { checkpoint, contact };
      if (contact.monitoring.some((e) => e.position >= checkpoint.treeSize))
        throw new KTError(KTErrorCode.InvalidState);
      const last = checkpoint.treeSize;
      const request = encodeContactMonitorRequest({ last, label: name, entries: contact.monitoring });
      const bytes = await call(Operation.ContactMonitor, request, signal);
      try {
        const res = decode(bytes, decodeContactMonitorResponse);
        const n = treeSize(res.treeHead, last);
        const data = new Map(contact.ladder.map((e) => [e.version, e]));
        const verifier = new Verifier(n, checkpoint, res.monitor, data);
        updateView(verifier, last);
        const updated = contactMonitor(verifier, params, contact.monitoring);
        const next = await conclude(verifier, res.treeHead, checkpoint, signal);
        const monitoring = shrink(new Map(updated.map((e) => [e.position, e.version])), n);
        const ladder = ladderFor(monitoring, contact.ladder, data);
        return { checkpoint: next, contact: { ...contact, monitoring, ladder } };
      } catch (e) {
        return fail(e);
      }
    },

    async ownerInit(label, { checkpoint: saved, signal, start } = {}) {
      const name = toLabel(label);
      const checkpoint = saved === undefined ? undefined : checkCheckpoint(saved, binding);
      if (start !== undefined && !isUint(start)) throw new KTError(KTErrorCode.InvalidRequest);
      const last = checkpoint?.treeSize;
      const bytes = await call(Operation.OwnerInit, encodeOwnerInitRequest({ last, label: name, start }), signal);
      try {
        const res = decode(bytes, (r) => decodeOwnerInitResponse(r, vrf.proofLength));
        const n = treeSize(res.treeHead, last);
        const greatest = res.greatestVersions;
        // VRF proofs for version 0 and the search ladders of each greatest version, with
        // commitments for the versions that exist as of the start (Sections 8.3, 13.3)
        const versions = [...new Set([0, ...greatest.flatMap(baseLadder)])].sort((a, b) => a - b);
        const data = ladderData(name, versions, res.binaryLadder, (v) => v <= (greatest[0] ?? -1));
        const verifier = new Verifier(n, checkpoint, res.init, data);
        updateView(verifier, last ?? 0);
        const { list } = ownerInit(verifier, params, start, (i) => greatest[i]);
        if (greatest.length > list.length) throw new Error("too many greatest versions");
        const next = await conclude(verifier, res.treeHead, checkpoint, signal);
        const owner = retainOwner(
          { binding, label: name, start, previous: greatest, upcoming: [], monitoring: [], versions: [] },
          data,
        );
        return { checkpoint: next, owner };
      } catch (e) {
        return fail(e);
      }
    },

    async update(record, values, { checkpoint: saved, signal }) {
      const name = toLabel(record.label);
      const checkpoint = checkCheckpoint(saved, binding);
      const owner = checkOwner(record, binding, name);
      if (!Array.isArray(values) || values.length > 255 || !values.every((v) => v instanceof Uint8Array))
        throw new KTError(KTErrorCode.InvalidRequest);
      values = values.map(copy);
      const last = checkpoint.treeSize;
      const history = ownerHistory(owner);
      const before = history.greatest;
      const request = encodeUpdateRequest({ last, label: name, greatestVersion: before, values });
      let bytes: Uint8Array;
      try {
        bytes = await call(Operation.Update, request, signal);
      } catch (e) {
        // After owner monitoring stopped at an unknown version, the log must report it
        if (!values.length && owner.stalled !== undefined && isKTError(e, KTErrorCode.InvalidRequest))
          throw new KTError(KTErrorCode.InvalidResponse, { cause: e });
        throw e;
      }
      try {
        const res = decode(bytes, (r) => decodeUpdateResponse(r, vrf.proofLength));
        const n = treeSize(res.treeHead, last);
        if (res.position >= n) throw new Error("update position is outside the tree");
        if (history.lastUpdate !== undefined && res.position <= history.lastUpdate)
          throw new Error("update is not right of the previous one");
        const disregarded = res.values.length > 0;
        const created = disregarded ? res.values : values;
        if (!created.length || res.openings.length !== created.length) throw new Error("unexpected update info");
        const after = (before ?? -1) + created.length;
        if (after > MAX_VERSION) throw new Error("too many versions");
        // VRF proofs the owner lacks, with commitments only below its greatest version (Section 13.5)
        const wanted = new Set([
          ...baseLadder(after),
          ...(created.length > 1 ? created.map((_, i) => (before ?? -1) + 1 + i) : []),
        ]);
        for (const v of before === undefined ? [0] : baseLadder(before)) wanted.delete(v);
        const fresh = ladderData(
          name,
          [...wanted].sort((a, b) => a - b),
          res.binaryLadder,
          (v) => v < (before ?? -1),
        );
        const data = new Map<number, LadderData>(owner.versions.map((e) => [e.version, e]));
        for (const [v, d] of fresh)
          data.set(v, { ...data.get(v), ...d, commitment: d.commitment ?? data.get(v)?.commitment });
        created.forEach((value, i) => {
          const v = (before ?? -1) + 1 + i;
          const d = data.get(v);
          if (!d) throw new Error("missing VRF output for a new version");
          data.set(v, { vrfOutput: d.vrfOutput, commitment: commitment(res.openings[i]!, name, v, value) });
        });
        const verifier = new Verifier(n, checkpoint, res.update, data);
        updateView(verifier, last ?? 0);
        const distinguished = labelUpdate(verifier, params, history, res.position, created.length);
        const next = await conclude(verifier, res.treeHead, checkpoint, signal);
        // An update at an entry that is not distinguished is also contact monitored,
        // replacing entries for lesser versions on its path to the right (Section 9.1)
        let monitoring = owner.monitoring;
        if (!distinguished) {
          const right = new Set(ancestors(res.position, n).filter((a) => a > res.position));
          const map = new Map(
            monitoring
              .filter((e) => !(right.has(e.position) && e.version <= after))
              .map((e) => [e.position, e.version]),
          );
          map.set(res.position, after);
          monitoring = shrink(map, n);
        }
        const updated = retainOwner(
          {
            ...owner,
            upcoming: [...owner.upcoming, ...created.map(() => res.position)],
            monitoring,
            stalled: undefined,
          },
          data,
        );
        return {
          checkpoint: next,
          owner: updated,
          position: res.position,
          versions: created.map((value, i) => ({ version: (before ?? -1) + 1 + i, value })),
          disregarded,
          pending: distinguished,
        };
      } catch (e) {
        return fail(e);
      }
    },

    async ownerMonitor(record, { checkpoint: saved, signal }) {
      const name = toLabel(record.label);
      const checkpoint = checkCheckpoint(saved, binding);
      const owner = checkOwner(record, binding, name);
      if (owner.monitoring.some((e) => e.position >= checkpoint.treeSize)) throw new KTError(KTErrorCode.InvalidState);
      const last = checkpoint.treeSize;
      const history = ownerHistory(owner);
      const request = encodeOwnerMonitorRequest({
        last,
        label: name,
        entries: owner.monitoring,
        start: owner.start,
        greatestVersion: history.greatest,
      });
      const bytes = await call(Operation.OwnerMonitor, request, signal);
      try {
        const res = decode(bytes, decodeOwnerMonitorResponse);
        const n = treeSize(res.treeHead, last);
        const data = new Map<number, LadderData>(owner.versions.map((e) => [e.version, e]));
        const verifier = new Verifier(n, checkpoint, res.monitor, data);
        updateView(verifier, last);
        const updated = contactMonitor(verifier, params, owner.monitoring, { start: owner.start });
        const verified = ownerMonitor(verifier, params, owner.start, history, () => verifier.exhausted);
        const next = await conclude(verifier, res.treeHead, checkpoint, signal);
        const monitoring = shrink(new Map(updated.map((e) => [e.position, e.version])), n);
        const moved = verified === undefined ? owner : advanceStart(owner, history, verified);
        const ts = new Map(next.frontier.map((e) => [e.position, e.timestamp]));
        const view = { n, timestamp: (x: number) => ts.get(x)!, ladder: () => {} };
        const rightmost = rightmostDistinguished(view, config.reasonableMonitoringWindow);
        const done = rightmost === undefined || (moved.start !== undefined && moved.start >= rightmost);
        // Stopping twice without progress and without a new version to learn is a stall
        const greatest = history.greatest ?? -1;
        const stuck = verified === undefined && !done;
        if (stuck && owner.stalled === greatest) throw new Error("the log keeps stopping owner monitoring");
        const owned = retainOwner({ ...moved, monitoring, stalled: stuck ? greatest : undefined }, data);
        return { checkpoint: next, owner: owned, done };
      } catch (e) {
        return fail(e);
      }
    },
  };

  /** VRF outputs for `versions` from binary ladder steps, which carry commitments exactly where `committed` says */
  function ladderData(
    label: Uint8Array,
    versions: readonly number[],
    steps: readonly BinaryLadderStep[],
    committed: (v: number) => boolean,
  ): Map<number, LadderData> {
    if (steps.length !== versions.length) throw new Error("unexpected binary ladder length");
    const data = new Map<number, LadderData>();
    versions.forEach((v, i) => {
      const step = steps[i]!;
      if ((step.commitment !== undefined) !== committed(v)) throw new Error("unexpected commitment");
      const vrfOutput = vrfVerify(vrfInput(label, v), step.proof);
      if (!vrfOutput) throw new Error("invalid VRF proof");
      data.set(v, { vrfOutput, commitment: step.commitment });
    });
    return data;
  }
}

/** The owner's view of the label's history, as the algorithms of Sections 8.3 and 9.1 need it */
function ownerHistory(o: Owner): UpdateHistory {
  const base = o.previous[0] ?? -1;
  const left = o.start === undefined ? [] : leftPath(o.start);
  const at = (x: number): number | undefined => {
    let v: number;
    if (o.start !== undefined && x < o.start) {
      const i = left.indexOf(x);
      const p = o.previous[i + 1];
      return p;
    }
    v = base;
    for (const position of o.upcoming) if (position <= x) v++;
    return v < 0 ? undefined : v;
  };
  const greatest = base + o.upcoming.length;
  return {
    greatestAt: at,
    greatest: greatest < 0 ? undefined : greatest,
    lastUpdate: o.upcoming.at(-1) ?? o.start,
  };
}

/** Ancestors of x to its left, nearest first. They do not depend on the tree size. */
const leftPath = (x: number): number[] =>
  ancestors(x, x + 1)
    .filter((a) => a < x)
    .reverse();

/** Moves the owner's start to a newly verified distinguished entry */
function advanceStart(o: Owner, history: OwnerHistory, x: number): Owner {
  const previous: number[] = [];
  for (const y of [x, ...leftPath(x)]) {
    const v = history.greatestAt(y);
    if (v === undefined) break;
    previous.push(v);
  }
  return { ...o, start: x, previous, upcoming: o.upcoming.filter((p) => p > x) };
}

/** Keeps the VRF outputs and commitments the owner's future ladders need */
function retainOwner(o: Owner, fresh: ReadonlyMap<number, LadderData>): Owner {
  const known = new Map<number, LadderData>(o.versions.map((e) => [e.version, e]));
  for (const [v, d] of fresh)
    known.set(v, { vrfOutput: d.vrfOutput, commitment: d.commitment ?? known.get(v)?.commitment });
  const greatest = ownerHistory(o).greatest;
  const needed = new Set([0, ...o.monitoring.flatMap((e) => monitoringLadder(e.version))]);
  if (greatest !== undefined)
    for (let v = o.previous[0] ?? 0; v <= greatest; v++) for (const l of baseLadder(v)) needed.add(l);
  const versions = [...needed]
    .sort((a, b) => a - b)
    .map((version) => {
      const d = known.get(version);
      if (!d) throw new Error("missing VRF output for a retained version");
      return d.commitment
        ? { version, vrfOutput: d.vrfOutput, commitment: d.commitment }
        : { version, vrfOutput: d.vrfOutput };
    });
  return { ...o, versions };
}

function checkOwner(o: Owner, binding: Uint8Array, label: Uint8Array): Owner {
  const ok =
    typeof o === "object" &&
    isBytes(o.binding) &&
    equalBytes(o.binding, binding) &&
    isBytes(o.label) &&
    equalBytes(o.label, label) &&
    (o.start === undefined || isUint(o.start)) &&
    Array.isArray(o.previous) &&
    (o.start === undefined ? o.previous.length === 0 : o.previous.length <= 1 + leftPath(o.start).length) &&
    o.previous.every((v, i, a) => isUint(v, MAX_VERSION) && (i === 0 || v <= a[i - 1]!)) &&
    Array.isArray(o.upcoming) &&
    o.upcoming.every((p, i, a) => isUint(p) && (o.start === undefined || p > o.start) && (i === 0 || p >= a[i - 1]!)) &&
    Array.isArray(o.monitoring) &&
    o.monitoring.every(
      (e, i, a) =>
        isUint(e.position) &&
        isUint(e.version, MAX_VERSION) &&
        (i === 0 || (a[i - 1]!.position < e.position && a.findIndex((x) => x.version === e.version) === i)),
    ) &&
    (o.stalled === undefined || (Number.isSafeInteger(o.stalled) && o.stalled >= -1)) &&
    Array.isArray(o.versions) &&
    o.versions.every(
      (e, i, a) =>
        isUint(e.version, MAX_VERSION) &&
        (i === 0 || a[i - 1]!.version < e.version) &&
        isBytes(e.vrfOutput, NH) &&
        (e.commitment === undefined || isBytes(e.commitment, NH)),
    );
  if (!ok) throw new KTError(KTErrorCode.InvalidState);
  return o;
}

const toLabel = (label: Uint8Array | string): Uint8Array => {
  const b = typeof label === "string" ? utf8ToBytes(label) : label;
  if (!(b instanceof Uint8Array) || b.length > 255) throw new KTError(KTErrorCode.InvalidRequest);
  return copy(b);
};

/**
 * Drops an entry whose nearest ancestor to its right already holds a greater
 * version, which is what the next contact monitoring step would do anyway
 * (Section 8.2, step 3.1.1).
 */
function shrink(map: ReadonlyMap<number, number>, n: number): MonitorMapEntry[] {
  return [...map]
    .filter(([position, version]) => {
      const parent = ancestors(position, n)
        .filter((x) => x > position)
        .at(-1);
      return parent === undefined || !((map.get(parent) ?? -1) > version);
    })
    .map(([position, version]) => ({ position, version }))
    .sort((a, b) => a.position - b.position);
}

/** Rejects verified data contradicting what this contact already saw for the same versions */
function checkConsistent(prior: Contact, fresh: ReadonlyMap<number, LadderData>): void {
  const seen = new Map<number, { vrfOutput?: Uint8Array; commitment: Uint8Array }>(
    prior.ladder.map((e) => [e.version, e]),
  );
  const own = seen.get(prior.version);
  if (own && !equalBytes(own.commitment, prior.commitment)) throw new KTError(KTErrorCode.InvalidState);
  seen.set(prior.version, { ...own, commitment: prior.commitment });
  for (const [v, d] of fresh) {
    const s = seen.get(v);
    if (!s || !d.commitment) continue;
    if (!equalBytes(s.commitment, d.commitment) || (s.vrfOutput && !equalBytes(s.vrfOutput, d.vrfOutput)))
      throw new KTError(KTErrorCode.Equivocation);
  }
}

/** Ladder data for every version the monitoring map still needs. */
function ladderFor(
  monitoring: readonly MonitorMapEntry[],
  prior: readonly LadderEntry[],
  fresh: ReadonlyMap<number, LadderData>,
): LadderEntry[] {
  const known = new Map<number, LadderData>(prior.map((e) => [e.version, e]));
  for (const [v, d] of fresh) if (d.commitment) known.set(v, d);
  const needed = [...new Set(monitoring.flatMap((e) => monitoringLadder(e.version)))].sort((a, b) => a - b);
  return needed.map((version) => {
    const d = known.get(version);
    if (!d?.commitment) throw new Error("missing monitoring ladder data");
    return { version, vrfOutput: d.vrfOutput, commitment: d.commitment };
  });
}

const isBytes = (b: unknown, len?: number): b is Uint8Array =>
  b instanceof Uint8Array && (len === undefined || b.length === len);
const isUint = (x: unknown, max = Number.MAX_SAFE_INTEGER): x is number =>
  Number.isSafeInteger(x) && (x as number) >= 0 && (x as number) <= max;

/** Validates restored state before trusting it. */
function checkCheckpoint(c: Checkpoint, binding: Uint8Array): Checkpoint {
  const ok =
    c != null &&
    isBytes(c.binding) &&
    equalBytes(c.binding, binding) &&
    isUint(c.treeSize) &&
    c.treeSize > 0 &&
    isBytes(c.signature, 64) &&
    isBytes(c.root, NH) &&
    Array.isArray(c.fullSubtrees) &&
    c.fullSubtrees.length === fullSubtrees(c.treeSize).length &&
    c.fullSubtrees.every((h) => isBytes(h, NH)) &&
    Array.isArray(c.frontier) &&
    sameFrontier(c.frontier, frontier(c.treeSize)) &&
    equalBytes(rootFromFullSubtrees(c.treeSize, c.fullSubtrees), c.root);
  if (!ok) throw new KTError(KTErrorCode.InvalidState);
  return c;
}

const sameFrontier = (entries: readonly FrontierEntry[], positions: number[]): boolean =>
  entries.length === positions.length &&
  entries.every((e, i) => e.position === positions[i] && isUint(e.timestamp) && isBytes(e.prefixRoot, NH));

function checkContact(c: Contact, binding: Uint8Array, label: Uint8Array): Contact {
  const ok =
    typeof c === "object" &&
    isBytes(c.binding) &&
    equalBytes(c.binding, binding) &&
    isBytes(c.label) &&
    equalBytes(c.label, label) &&
    isUint(c.version, MAX_VERSION) &&
    isBytes(c.commitment, NH) &&
    Array.isArray(c.monitoring) &&
    c.monitoring.every(
      (e, i, a) =>
        isUint(e.position) &&
        isUint(e.version, c.version) &&
        (i === 0 || (a[i - 1]!.position < e.position && a.findIndex((x) => x.version === e.version) === i)),
    ) &&
    Array.isArray(c.ladder) &&
    c.ladder.every((e) => isUint(e.version, MAX_VERSION) && isBytes(e.vrfOutput, NH) && isBytes(e.commitment, NH));
  if (!ok) throw new KTError(KTErrorCode.InvalidState);
  return c;
}
