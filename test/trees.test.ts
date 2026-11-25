import { fc, test } from "@fast-check/vitest";
import { bytesToHex, equalBytes } from "@noble/curves/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect } from "vitest";
import { logLeaf, logParent } from "../src/crypto.ts";
import { ancestors, frontier, left, right, root } from "../src/ibst.ts";
import { MAX_VERSION, baseLadder, monitoringLadder, searchLadder } from "../src/ladder.ts";
import { computeRoot, fullSubtrees, rootFromFullSubtrees, type Range } from "../src/logtree.ts";
import { type Node, contains, evaluate, insert, prove, rootHash } from "../src/prefix.ts";

/** Parent map of the implicit binary search tree, straight from Section 4.1's inductive definition. */
function referenceParents(n: number): Map<number, number> {
  const parents = new Map<number, number>();
  const build = (offset: number, size: number, parent: number | undefined): void => {
    if (size === 0) return;
    const r = 2 ** Math.floor(Math.log2(size)) - 1;
    if (parent !== undefined) parents.set(offset + r, parent);
    build(offset, r, offset + r);
    build(offset + r + 1, size - r - 1, offset + r);
  };
  build(0, n, undefined);
  return parents;
}

describe("implicit binary search tree", () => {
  test.prop([fc.integer({ min: 1, max: 300 })])("matches the inductive definition", (n) => {
    const parents = referenceParents(n);
    for (let x = 0; x < n; x++) {
      const path: number[] = [];
      for (let p = parents.get(x); p !== undefined; p = parents.get(p)) path.unshift(p);
      expect(ancestors(x, n)).toEqual(path);
    }
    expect(frontier(n)[0]).toBe(root(n));
    expect(frontier(n).at(-1)).toBe(n - 1);
  });

  test.prop([fc.integer({ min: 1, max: 2 ** 40 }), fc.integer({ min: 0, max: 2 ** 40 })])(
    "ancestors are kept as the log grows",
    (m, extra) => {
      const n = m + extra;
      const x = m - 1;
      const before = ancestors(x, m);
      const after = new Set(ancestors(x, n));
      for (const a of before) expect(after.has(a)).toBe(true);
    },
  );

  test("Section 4.1 examples", () => {
    expect(frontier(50)).toEqual([31, 47, 49]);
    expect(frontier(13)).toEqual([7, 11, 12]);
    expect(right(7, 13)).toBe(11);
    expect(left(11)).toBe(9);
  });
});

/** search_binary_ladder(t, n) from Appendix B. */
function referenceSearchLadder(t: number, n: number): number[] {
  const out = baseLadder(n);
  const end = out.findIndex((v) => (v <= n && v > t) || (v > n && v <= t));
  return out.slice(0, end < 0 ? out.length : end + 1);
}

const version = fc.oneof(fc.integer({ min: 0, max: 200 }), fc.integer({ min: 0, max: MAX_VERSION }));

describe("binary ladder", () => {
  test("Section 5 example", () => {
    expect(baseLadder(6)).toEqual([0, 1, 3, 7, 5, 6]);
    expect(baseLadder(2)).toEqual([0, 1, 3, 2]);
    expect(baseLadder(MAX_VERSION).at(-1)).toBe(MAX_VERSION);
  });

  test.prop([version, version])("search ladder follows Appendix B without knowing n", (t, n) => {
    const seen: number[] = [];
    searchLadder(t, (v) => (seen.push(v), v <= n));
    expect(seen).toEqual(referenceSearchLadder(t, n));
  });

  test.prop([version])("base ladder pins the greatest version", (n) => {
    const ladder = baseLadder(n);
    expect(ladder).toContain(n);
    expect(new Set(ladder).size).toBe(ladder.length);
    expect(monitoringLadder(n).every((v) => v <= n && ladder.includes(v))).toBe(true);
  });

  // keytrans-verification TStar: two claims t1 != t2 share a lookup t1 < t* <= t2 whose
  // outcomes contradict, so no prefix tree can satisfy both ladders.
  test.prop([version, version])("ladders for different greatest versions conflict", (t1, t2) => {
    fc.pre(t1 !== t2);
    const a = new Map<number, boolean>();
    const b = new Map<number, boolean>();
    searchLadder(t1, (v) => (a.set(v, v <= t1), v <= t1));
    searchLadder(t2, (v) => (b.set(v, v <= t2), v <= t2));
    const conflict = [...a].some(([v, inc]) => b.has(v) && b.get(v) !== inc);
    expect(conflict).toBe(true);
  });

  test.prop([version, version])("search ladder never looks up a version twice or beyond 2^32-1", (t, n) => {
    const seen: number[] = [];
    searchLadder(t, (v) => (seen.push(v), v <= n));
    expect(new Set(seen).size).toBe(seen.length);
    expect(seen.every((v) => v <= MAX_VERSION)).toBe(true);
  });
});

const hash = (i: number): Uint8Array => sha256(new Uint8Array([i, i >> 8]));

/** All balanced subtree heads of a tree with n leaves, computed directly. */
function heads(n: number): Map<string, Uint8Array> {
  const out = new Map<string, Uint8Array>();
  for (let size = 1; size <= n; size *= 2)
    for (let start = 0; start + size <= n; start += size) {
      const v =
        size === 1
          ? logLeaf(start, hash(start))
          : logParent(
              out.get(`${start}:${size / 2}`)!,
              size === 2,
              out.get(`${start + size / 2}:${size / 2}`)!,
              size === 2,
            );
      out.set(`${start}:${size}`, v);
    }
  return out;
}
const key = (r: Range): string => `${r.start}:${r.size}`;

const logCase = fc.integer({ min: 1, max: 70 }).chain((n) =>
  fc.record({
    n: fc.constant(n),
    m: fc.integer({ min: 0, max: n }),
    leaves: fc.uniqueArray(fc.integer({ min: 0, max: n - 1 }), { minLength: 1, maxLength: 8 }),
  }),
);

function proveLog(n: number, m: number, leaves: number[]) {
  const all = heads(n);
  const known = new Map(leaves.map((i) => [i, logLeaf(i, hash(i))]));
  const retained = m ? { size: m, heads: fullSubtrees(m).map((r) => all.get(key(r))!) } : undefined;
  const elements: Uint8Array[] = [];
  const proved = computeRoot(n, known, retained, (r) => {
    const v = all.get(key(r));
    if (!v) throw new Error(`not balanced ${key(r)}`);
    elements.push(v);
    return v;
  });
  return { all, known, retained, elements, proved };
}

function verifyLog(
  n: number,
  known: Map<number, Uint8Array>,
  retained: ReturnType<typeof proveLog>["retained"],
  elements: Uint8Array[],
) {
  let i = 0;
  const out = computeRoot(n, known, retained, () => {
    const e = elements[i++];
    if (!e) throw new Error("short");
    return e;
  });
  if (i !== elements.length) throw new Error("long");
  return out;
}

describe("log tree", () => {
  test.prop([logCase])("batched inclusion and consistency proofs verify", ({ n, m, leaves }) => {
    const { all, known, retained, elements, proved } = proveLog(n, m, leaves);
    const expected = fullSubtrees(n).map((r) => all.get(key(r))!);
    expect(proved.full).toEqual(expected);
    expect(proved.root).toEqual(rootFromFullSubtrees(n, expected));
    expect(verifyLog(n, known, retained, elements).root).toEqual(proved.root);
  });

  test.prop([logCase, fc.nat(), fc.integer({ min: 0, max: 255 })])(
    "tampered elements, leaves or retained heads change the root or fail",
    ({ n, m, leaves }, at, flip) => {
      const { known, retained, elements, proved } = proveLog(n, m, leaves);
      const expected = proved.root.slice();
      const targets = [...elements, ...known.values(), ...(retained?.heads ?? [])];
      const victim = targets[at % targets.length]!;
      victim[flip % 32]! ^= 1 + (flip % 255);
      let root: Uint8Array | undefined;
      try {
        root = verifyLog(n, known, retained, elements).root;
      } catch {
        return;
      }
      expect(equalBytes(root, expected)).toBe(false);
    },
  );

  test("Appendix C.1 inclusion elements", () => {
    const { elements, all } = proveLog(13, 4, [7, 11, 12]);
    expect(elements).toEqual(["4:2", "6:1", "8:2", "10:1"].map((k) => all.get(k)));
  });
});

const prefixKey = fc
  .tuple(
    fc.integer({ min: 0, max: 7 }),
    fc.integer({ min: 0, max: 255 }),
    fc.uint8Array({ minLength: 32, maxLength: 32 }),
  )
  .map(([a, b, rest]) => {
    const k = new Uint8Array(32);
    k[0] = a << 5;
    k[1] = b;
    if (b % 4 === 0) k.set(rest.subarray(2), 2);
    return k;
  });
const hex = (b: Uint8Array): string => bytesToHex(b);
const uniqueKeys = (n: number) => fc.uniqueArray(prefixKey, { maxLength: n, selector: hex });

function build(keys: readonly Uint8Array[]): Node {
  let t: Node = null;
  for (const k of keys) t = insert(t, k, sha256(k));
  return t;
}

describe("prefix tree", () => {
  test.prop([uniqueKeys(40), uniqueKeys(10)])("search proofs verify against the root", (stored, queries) => {
    const t = build(stored);
    const lookups = [...stored.slice(0, 5), ...queries];
    fc.pre(lookups.length > 0);
    const proof = prove(t, lookups);
    for (const [i, k] of lookups.entries())
      expect(proof.results[i]!.type === 1).toBe(stored.some((s) => equalBytes(s, k)) && contains(t, k));
    const root = evaluate(
      lookups.map((k, i) => ({ key: k, result: proof.results[i]!, commitment: sha256(k) })),
      proof.elements,
    );
    expect(root).toEqual(rootHash(t));
  });

  test.prop([uniqueKeys(30), fc.integer()])("history independent", (keys, seed) => {
    const shuffled = [...keys].sort((a, b) => (hex(a) + seed).localeCompare(hex(b) + seed));
    expect(rootHash(build(shuffled))).toEqual(rootHash(build(keys)));
  });

  test.prop([uniqueKeys(30), prefixKey])("insertion leaves earlier versions untouched", (keys, extra) => {
    fc.pre(!keys.some((k) => equalBytes(k, extra)));
    const before = build(keys);
    const hashBefore = rootHash(before);
    insert(before, extra, sha256(extra));
    expect(rootHash(before)).toEqual(hashBefore);
    expect(contains(before, extra)).toBe(false);
  });

  test.prop([uniqueKeys(20), uniqueKeys(5), fc.nat(), fc.nat()])(
    "tampered proofs do not reproduce the root",
    (stored, queries, at, flip) => {
      fc.pre(queries.length > 0);
      const t = build(stored);
      const proof = prove(t, queries);
      const lookups = queries.map((k, i) => ({ key: k, result: proof.results[i]!, commitment: sha256(k) }));
      const pick = at % (proof.elements.length + lookups.length);
      if (pick < proof.elements.length) {
        const e = proof.elements[pick]!.slice();
        e[flip % 32]! ^= 1;
        (proof.elements as Uint8Array[])[pick] = e;
      } else {
        const l = lookups[pick - proof.elements.length]!;
        const c = l.commitment.slice();
        c[flip % 32]! ^= 1;
        lookups[pick - proof.elements.length] = { ...l, commitment: c, key: l.key };
        fc.pre(l.result.type === 1);
      }
      let root: Uint8Array | undefined;
      try {
        root = evaluate(lookups, proof.elements);
      } catch {
        return;
      }
      expect(equalBytes(root, rootHash(t))).toBe(false);
    },
  );
});
