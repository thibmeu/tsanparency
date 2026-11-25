/**
 * Combined tree algorithms (Sections 4.2, 6.3, 8.2) over a {@link Context} that
 * either records a CombinedTreeProof (log) or consumes one (client), so both sides
 * agree on the contents and order of every field (Appendix C).
 */
import { equalBytes } from "@noble/curves/utils.js";
import { logLeaf } from "./crypto.ts";
import { KTError, KTErrorCode } from "./errors.ts";
import { ancestors, frontier, hasLeft, hasRight, left, right, root } from "./ibst.ts";
import { MAX_VERSION, baseLadder, monitoringLadder, searchLadder } from "./ladder.ts";
import { type Range, computeRoot, fullSubtrees } from "./logtree.ts";
import type { CombinedTreeProof, MonitorMapEntry } from "./messages.ts";
import { type Lookup, type Node, ResultType, contains, evaluate, prove } from "./prefix.ts";

export interface Context {
  /** Size of the tree being proven. */
  readonly n: number;
  timestamp(x: number): number;
  /** Runs one binary ladder against log entry x's prefix tree. */
  ladder(x: number, run: (probe: (version: number) => boolean) => void): void;
}

export interface Params {
  readonly reasonableMonitoringWindow: number;
  readonly maximumLifetime?: number | undefined;
}

/** Timestamps for updating a view from size m to c.n (Section 4.2, 12.3.1). */
export function updateView(c: Context, m: number): void {
  if (m === 0) {
    for (const x of frontier(c.n)) c.timestamp(x);
    return;
  }
  let x = m - 1;
  for (const a of ancestors(m - 1, c.n).reverse()) if (a >= m) c.timestamp((x = a));
  while (x !== c.n - 1) c.timestamp((x = right(x, c.n)));
}

/** Whether x is distinguished (Section 6.1), reading only the timestamps that decides it. */
export function isDistinguished(c: Context, rmw: number, x: number): boolean {
  let lo = 0;
  let hi = c.timestamp(c.n - 1);
  for (let node = root(c.n); ;) {
    if (hi - lo < rmw) return false;
    if (node === x) return true;
    if (x < node) {
      hi = c.timestamp(node);
      node = left(node);
    } else {
      lo = c.timestamp(node);
      node = right(node, c.n);
    }
  }
}

/** Rightmost distinguished log entry, which is always on the frontier (Appendix D) */
export function rightmostDistinguished(c: Context, rmw: number): number | undefined {
  const hi = c.timestamp(c.n - 1);
  let found: number | undefined;
  for (let x = root(c.n), lo = 0; hi - lo >= rmw; x = right(x, c.n)) {
    found = x;
    if (!hasRight(x, c.n)) break;
    lo = c.timestamp(x);
  }
  return found;
}

export interface SearchOutcome {
  /** Leftmost inspected log entry containing the target version. */
  readonly terminal: number;
  readonly distinguished: number | undefined;
}

/**
 * Lookups already answered in one response. A ladder may omit an inclusion proof
 * already given for an entry to its left, and a non-inclusion proof already given
 * for an entry to its right (Section 6.2).
 */
export class Omissions {
  readonly #included = new Map<number, number>();
  readonly #excluded = new Map<number, number>();

  known(x: number, v: number): boolean | undefined {
    const l = this.#included.get(v);
    if (l !== undefined && l < x) return true;
    const r = this.#excluded.get(v);
    if (r !== undefined && r > x) return false;
    return undefined;
  }

  record(x: number, v: number, included: boolean): void {
    const map = included ? this.#included : this.#excluded;
    const seen = map.get(v);
    if (seen === undefined || (included ? x < seen : x > seen)) map.set(v, x);
  }

  /** Records what a search ladder for t would show at x, where `greatest` is the greatest version there */
  assume(x: number, t: number, greatest: number | undefined): void {
    searchLadder(t, (v) => {
      const inc = greatest !== undefined && v <= greatest;
      this.record(x, v, inc);
      return inc;
    });
  }
}

/** Runs a search ladder for t at x, recording outcomes and omitting known ones, and returns its probe results */
function searchAt(c: Context, x: number, t: number, omit: Omissions | undefined): Map<number, boolean> {
  const seen = new Map<number, boolean>();
  c.ladder(x, (probe) =>
    searchLadder(t, (v) => {
      const inc = omit?.known(x, v) ?? probe(v);
      omit?.record(x, v, inc);
      seen.set(v, inc);
      return inc;
    }),
  );
  return seen;
}

/**
 * Search ladder at x proving that t is the greatest version there, or that no
 * version exists when t is undefined (Sections 8.3, 9.1)
 */
function exactLadder(c: Context, x: number, t: number | undefined, omit?: Omissions): void {
  for (const [v, inc] of searchAt(c, x, t ?? 0, omit))
    if (t === undefined ? inc : inc ? v > t : v <= t) throw new Error("binary ladder contradicts the greatest version");
}

/** Greatest-version search for claimed version t (Sections 6.3, 12.3.2) */
export function greatestVersionSearch(c: Context, p: Params, t: number): SearchOutcome {
  const distinguished = rightmostDistinguished(c, p.reasonableMonitoringWindow);
  const omit = new Omissions();
  let terminal: number | undefined;
  for (let x = distinguished ?? root(c.n); ; x = right(x, c.n)) {
    const rightmost = x === c.n - 1;
    // Every lookup above t must be a non-inclusion, and at the rightmost entry
    // every lookup at or below t an inclusion
    for (const [v, inc] of searchAt(c, x, t, omit)) {
      if (inc ? v > t : rightmost && v <= t) throw new Error("binary ladder contradicts the greatest version");
      if (v === t && inc && terminal === undefined) terminal = x;
    }
    if (rightmost) break;
  }
  return { terminal: terminal!, distinguished };
}

/**
 * Fixed-version search for version t (Sections 7.2, 12.3.3). Descends the implicit
 * binary search tree from the root: expired entries recurse right without a
 * ladder, and each ladder says whether the greatest version is below, equal to or
 * above t. Throws KTError(Expired) when t can only be found in expired entries.
 */
export function fixedVersionSearch(c: Context, p: Params, t: number): SearchOutcome {
  const rmw = p.reasonableMonitoringWindow;
  const expired = expiry(c, p);
  const omit = new Omissions();
  const inspected: { x: number; greatest: -1 | 0 | 1 }[] = [];
  let sawExpired = false;
  let x: number | undefined = root(c.n);
  while (x !== undefined) {
    if (expired(x)) {
      sawExpired = true;
      x = hasRight(x, c.n) ? right(x, c.n) : undefined;
      continue;
    }
    let greatest: -1 | 0 | 1 = 0;
    for (const [v, inc] of searchAt(c, x, t, omit)) {
      if (inc && v > t) greatest = 1;
      if (!inc && v <= t) greatest = -1;
    }
    inspected.push({ x, greatest });
    if (greatest === 0) {
      // Step 5: accept unless expired entries lie on the path, in which case the
      // entry itself or an unexpired distinguished ancestor to its left must vouch for it
      const at = x;
      const path = ancestors(at, c.n);
      if (path.some(expired)) {
        const vouched = [at, ...path.filter((a) => a < at)].some((a) => !expired(a) && isDistinguished(c, rmw, a));
        if (!vouched) throw new KTError(KTErrorCode.Expired);
      }
      return { terminal: at, distinguished: rightmostDistinguished(c, rmw) };
    }
    if (greatest < 0) x = hasRight(x, c.n) ? right(x, c.n) : undefined;
    else x = hasLeft(x) ? left(x) : undefined;
  }
  // Step 6: the leftmost inspected entry whose greatest version exceeds t
  const above = inspected.filter((e) => e.greatest > 0).sort((a, b) => a.x - b.x)[0];
  if (!above) throw new Error("target version does not exist");
  if (sawExpired) {
    const vouched = inspected.some((e) => e.x < above.x && !expired(e.x) && isDistinguished(c, rmw, e.x));
    if (!vouched) throw new KTError(KTErrorCode.Expired);
  }
  c.ladder(above.x, (probe) => {
    if (!probe(t)) throw new Error("target version does not exist");
  });
  return { terminal: above.x, distinguished: rightmostDistinguished(c, rmw) };
}

/** An entry is expired once the rightmost timestamp is a maximum lifetime past it (Section 7.1) */
function expiry(c: Context, p: Params): (x: number) => boolean {
  const ml = p.maximumLifetime;
  if (ml === undefined) return () => false;
  const rightmost = c.timestamp(c.n - 1);
  return (x) => rightmost - c.timestamp(x) >= ml;
}

/** Contact monitoring (Sections 8.2, 12.3.4). Returns the updated monitoring map. */
export function contactMonitor(
  c: Context,
  p: Params,
  entries: readonly MonitorMapEntry[],
  owner?: { readonly start?: number | undefined },
): MonitorMapEntry[] {
  const rmw = p.reasonableMonitoringWindow;
  const distinguished = (x: number): boolean => isDistinguished(c, rmw, x);
  const original = new Map(entries.map((e) => [e.position, e.version]));
  const current = new Map(original);
  const ladders = new Map<number, number>();
  for (const { position, version } of [...entries].sort((a, b) => b.position - a.position)) {
    if (distinguished(position)) continue;
    const list = ancestors(position, c.n)
      .filter((x) => x > position)
      .sort((a, b) => a - b);
    const stop = list.findIndex(distinguished);
    if (stop >= 0) list.length = stop + 1;
    // During owner monitoring, the second algorithm of Section 8.3 inspects that
    // final distinguished entry instead (Section 8.2, step 2.4)
    const deferred = stop >= 0 && owner !== undefined && (owner.start === undefined || position >= owner.start);
    if (deferred) list.length = stop;
    let at = position;
    for (const x of list) {
      const prior = original.get(x) ?? ladders.get(x);
      if (prior !== undefined) {
        if (prior <= version) throw new Error("monitoring map is inconsistent");
        current.delete(at);
        break;
      }
      const ts = c.timestamp(x);
      if (p.maximumLifetime !== undefined && c.timestamp(c.n - 1) - ts >= p.maximumLifetime)
        throw new KTError(KTErrorCode.Expired);
      c.ladder(x, (probe) => {
        for (const v of monitoringLadder(version)) if (!probe(v)) throw new Error("monitored version is missing");
      });
      ladders.set(x, version);
      current.delete(at);
      current.set(x, version);
      at = x;
    }
    // Owner monitoring now covers the deferred distinguished entry, so this one is done
    if (deferred && current.get(at) === version) current.delete(at);
  }
  return [...current]
    .filter(([x]) => !distinguished(x))
    .map(([position, version]) => ({ position, version }))
    .sort((a, b) => a.position - b.position);
}

/** What a label owner knows about the versions of its label */
export interface OwnerHistory {
  /** Greatest version that existed as of log entry x, if any */
  greatestAt(x: number): number | undefined;
}

/**
 * Owner initialization, first algorithm of Section 8.3 (Section 12.3.5). The start
 * must be an unexpired distinguished entry. The log then proves the greatest
 * version at the start and at each ancestor to its left, stopping before the
 * first expired one. `versionAt` gives the greatest version at the i-th listed
 * entry x, and each must be at most the one before. Returns the listed entries
 * and their versions.
 */
export function ownerInit(
  c: Context,
  p: Params,
  start: number | undefined,
  versionAt: (i: number, x: number) => number | undefined,
): { list: number[]; versions: (number | undefined)[] } {
  if (start === undefined) return { list: [], versions: [] };
  if (start >= c.n) throw new Error("start is outside the tree");
  for (const a of ancestors(start, c.n)) c.timestamp(a);
  c.timestamp(start);
  const expired = expiry(c, p);
  if (expired(start) || !isDistinguished(c, p.reasonableMonitoringWindow, start))
    throw new Error("start is not an unexpired distinguished entry");
  const list = [start];
  for (const a of ancestors(start, c.n).reverse()) {
    if (a > start) continue;
    if (expired(a)) break;
    list.push(a);
  }
  const versions = list.map((x, i) => versionAt(i, x));
  for (let i = 1; i < versions.length; i++) {
    const v = versions[i];
    if (v !== undefined && (versions[i - 1] === undefined || v > versions[i - 1]!))
      throw new Error("greatest versions must not increase to the left");
  }
  list.forEach((x, i) => exactLadder(c, x, versions[i]));
  return { list, versions };
}

/**
 * Owner monitoring, second algorithm of Section 8.3 (Section 12.3.6). Visits the
 * distinguished entries right of `start` in order and proves at each the greatest
 * version the owner expects there, until `stop` ends the response. Returns the
 * rightmost entry verified.
 */
export function ownerMonitor(
  c: Context,
  p: Params,
  start: number | undefined,
  owner: OwnerHistory,
  stop: (x: number) => boolean,
): number | undefined {
  const rmw = p.reasonableMonitoringWindow;
  let verified: number | undefined;
  let stopped = false;
  const walk = (x: number): void => {
    if (stopped || !isDistinguished(c, rmw, x)) return;
    if (start !== undefined && x <= start) {
      if (hasRight(x, c.n)) walk(right(x, c.n));
      return;
    }
    if (hasLeft(x)) walk(left(x));
    if (stopped || stop(x)) {
      stopped = true;
      return;
    }
    exactLadder(c, x, owner.greatestAt(x));
    verified = x;
    if (hasRight(x, c.n)) walk(right(x, c.n));
  };
  walk(root(c.n));
  return verified;
}

export interface UpdateHistory extends OwnerHistory {
  /** Greatest version before the update, if any */
  readonly greatest: number | undefined;
  /** Where that version was inserted, or the starting position if later */
  readonly lastUpdate: number | undefined;
}

/**
 * Proves that `created` new versions were inserted at `position` (Sections 9.1,
 * 12.3.7). Returns whether that entry is distinguished, in which case owner
 * monitoring covers it, and otherwise it joins the contact monitoring map.
 */
export function labelUpdate(c: Context, p: Params, owner: UpdateHistory, position: number, created: number): boolean {
  const rmw = p.reasonableMonitoringWindow;
  const before = owner.greatest;
  const after = (before ?? -1) + created;
  if (created < 1 || after > MAX_VERSION) throw new Error("unexpected number of new versions");
  const omit = new Omissions();
  // Phase 1: a greatest-version search of the previous tree, from the first entry
  // on its frontier that is not distinguished in the current tree. Lookups the
  // search would have made at its rightmost distinguished entry, or at entries
  // already checked by an earlier update, still count as made.
  if (position > 0) {
    const previous = frontier(position);
    const first = previous.findIndex((x) => !isDistinguished(c, rmw, x));
    if (first > 0 && before !== undefined)
      omit.assume(previous[first - 1]!, before, owner.greatestAt(previous[first - 1]!));
    for (const x of first < 0 ? [] : previous.slice(first)) {
      if (owner.lastUpdate !== undefined && x <= owner.lastUpdate) {
        if (before !== undefined) omit.assume(x, before, owner.greatestAt(x));
      } else exactLadder(c, x, before, omit);
    }
  }
  // Phase 2: how the versions were created at `position`
  const distinguished = isDistinguished(c, rmw, position);
  if (!distinguished) exactLadder(c, position, after, omit);
  const ladder = new Set(baseLadder(after));
  const extra: number[] = [];
  for (let v = (before ?? -1) + 1; v <= after; v++) if (!ladder.has(v)) extra.push(v);
  if (extra.length)
    c.ladder(position, (probe) => {
      for (const v of extra) if (!probe(v)) throw new Error("new version is missing");
    });
  return distinguished;
}

export interface FrontierEntry {
  readonly position: number;
  readonly timestamp: number;
  readonly prefixRoot: Uint8Array;
}

/** What a client retains about its last verified tree (Section 4.2). */
export interface View {
  readonly treeSize: number;
  readonly fullSubtrees: readonly Uint8Array[];
  readonly frontier: readonly FrontierEntry[];
}

/** Read access to a committed log snapshot. */
export interface Snapshot {
  readonly size: number;
  timestamp(x: number): number;
  /** Prefix tree of an entry, which may throw once the entry has been pruned */
  prefixTree(x: number): Node;
  prefixRoot(x: number): Uint8Array;
  /** Head of a balanced log subtree. */
  head(r: Range): Uint8Array;
}

/** Records a CombinedTreeProof while running the algorithms against the log. */
export class Prover implements Context {
  readonly n: number;
  readonly #log: Snapshot;
  readonly #m: number;
  readonly #keyOf: (v: number) => Uint8Array;
  readonly #ts = new Map<number, number>();
  readonly #retained: Set<number>;
  readonly #withLadder = new Set<number>();
  readonly #timestamps: number[] = [];
  readonly #proofs: CombinedTreeProof["prefixProofs"][number][] = [];

  constructor(log: Snapshot, m: number, keyOf: (v: number) => Uint8Array) {
    this.n = log.size;
    this.#log = log;
    this.#m = m;
    this.#keyOf = keyOf;
    this.#retained = new Set(m > 0 ? frontier(m) : []);
    for (const x of this.#retained) this.#ts.set(x, log.timestamp(x));
  }

  timestamp(x: number): number {
    let t = this.#ts.get(x);
    if (t === undefined) {
      t = this.#log.timestamp(x);
      this.#ts.set(x, t);
      this.#timestamps.push(t);
    }
    return t;
  }

  ladder(x: number, run: (probe: (version: number) => boolean) => void): void {
    this.timestamp(x);
    const tree = this.#log.prefixTree(x);
    const keys: Uint8Array[] = [];
    run((v) => {
      const k = this.#keyOf(v);
      keys.push(k);
      return contains(tree, k);
    });
    if (keys.length) {
      this.#proofs.push(prove(tree, keys));
      this.#withLadder.add(x);
    }
  }

  finish(): CombinedTreeProof {
    const log = this.#log;
    const provided = [...this.#ts.keys()].filter((x) => !this.#retained.has(x)).sort((a, b) => a - b);
    const leaves = new Map(provided.map((x) => [x, logLeaf(this.#ts.get(x)!, log.prefixRoot(x))]));
    const m = this.#m;
    const retained = m > 0 ? { size: m, heads: fullSubtrees(m).map((r) => log.head(r)) } : undefined;
    const inclusion: Uint8Array[] = [];
    computeRoot(this.n, leaves, retained, (r) => {
      const h = log.head(r);
      inclusion.push(h);
      return h;
    });
    return {
      timestamps: this.#timestamps,
      prefixProofs: this.#proofs,
      prefixRoots: provided.filter((x) => !this.#withLadder.has(x)).map((x) => log.prefixRoot(x)),
      inclusion,
    };
  }
}

export interface LadderData {
  readonly vrfOutput: Uint8Array;
  readonly commitment?: Uint8Array | undefined;
}

/** Consumes a CombinedTreeProof while running the algorithms. Throws on any mismatch. */
export class Verifier implements Context {
  readonly n: number;
  readonly #view: View | undefined;
  readonly #proof: CombinedTreeProof;
  readonly #data: ReadonlyMap<number, LadderData>;
  readonly #ts = new Map<number, number>();
  readonly #roots = new Map<number, Uint8Array>();
  readonly #provided: number[] = [];
  #nextTimestamp = 0;
  #nextProof = 0;

  constructor(n: number, view: View | undefined, proof: CombinedTreeProof, data: ReadonlyMap<number, LadderData>) {
    this.n = n;
    this.#view = view;
    this.#proof = proof;
    this.#data = data;
    for (const e of view?.frontier ?? []) {
      this.#ts.set(e.position, e.timestamp);
      this.#roots.set(e.position, e.prefixRoot);
    }
  }

  timestamp(x: number): number {
    let t = this.#ts.get(x);
    if (t === undefined) {
      t = this.#proof.timestamps[this.#nextTimestamp++];
      if (t === undefined) throw new Error("missing timestamp");
      this.#ts.set(x, t);
      this.#provided.push(x);
    }
    return t;
  }

  ladder(x: number, run: (probe: (version: number) => boolean) => void): void {
    this.timestamp(x);
    let proof: CombinedTreeProof["prefixProofs"][number] | undefined;
    const lookups: Lookup[] = [];
    run((v) => {
      proof ??= this.#proof.prefixProofs[this.#nextProof++];
      const result = proof?.results[lookups.length];
      const data = this.#data.get(v);
      if (!result || !data) throw new Error("missing lookup");
      lookups.push({ key: data.vrfOutput, result, commitment: data.commitment });
      return result.type === ResultType.Inclusion;
    });
    if (!proof) return;
    if (lookups.length !== proof.results.length) throw new Error("unexpected lookups");
    const computed = evaluate(lookups, proof.elements);
    const known = this.#roots.get(x);
    if (known && !equalBytes(known, computed)) throw new Error("prefix root mismatch");
    this.#roots.set(x, computed);
  }

  /** Whether prefix proofs remain, which is how a user sees the log stop owner monitoring (Section 8.3) */
  get exhausted(): boolean {
    return this.#nextProof >= this.#proof.prefixProofs.length;
  }

  /** Checks every field was fully consumed and returns the new view and log root. */
  finish(): { view: View; root: Uint8Array } {
    const p = this.#proof;
    if (this.#nextTimestamp !== p.timestamps.length || this.#nextProof !== p.prefixProofs.length)
      throw new Error("unused proof elements");
    const provided = [...this.#provided].sort((a, b) => a - b);
    let nextRoot = 0;
    for (const x of provided) {
      if (this.#roots.has(x)) continue;
      const r = p.prefixRoots[nextRoot++];
      if (!r) throw new Error("missing prefix root");
      this.#roots.set(x, r);
    }
    if (nextRoot !== p.prefixRoots.length) throw new Error("unused prefix roots");

    const known = [...this.#ts].sort((a, b) => a[0] - b[0]);
    for (let i = 1; i < known.length; i++)
      if (known[i]![1] < known[i - 1]![1]) throw new Error("timestamps are not monotonic");

    const leaves = new Map(provided.map((x) => [x, logLeaf(this.#ts.get(x)!, this.#roots.get(x)!)]));
    const view = this.#view;
    const retained = view ? { size: view.treeSize, heads: view.fullSubtrees } : undefined;
    let next = 0;
    const { root, full } = computeRoot(this.n, leaves, retained, () => {
      const e = p.inclusion[next++];
      if (!e) throw new Error("inclusion proof too short");
      return e;
    });
    if (next !== p.inclusion.length) throw new Error("inclusion proof too long");

    return {
      root,
      view: {
        treeSize: this.n,
        fullSubtrees: full,
        frontier: frontier(this.n).map((position) => ({
          position,
          timestamp: this.#ts.get(position)!,
          prefixRoot: this.#roots.get(position)!,
        })),
      },
    };
  }
}
