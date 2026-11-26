/** Left-balanced log tree and batched inclusion/consistency proofs (Sections 3.2, 12.1). */
import { equalBytes } from "@noble/curves/utils.js";
import { logParent } from "./crypto.ts";

export interface Range {
  readonly start: number;
  readonly size: number;
}

const isPow2 = (n: number): boolean => n > 0 && 2 ** Math.floor(Math.log2(n)) === n;

function split(size: number): number {
  let p = 1;
  while (p * 2 < size) p *= 2;
  return p;
}

/** Heads of the largest balanced subtrees of a tree with n leaves, left to right. */
export function fullSubtrees(n: number): Range[] {
  const out: Range[] = [];
  for (let start = 0; start < n;) {
    let size = 1;
    while (size * 2 <= n - start) size *= 2;
    out.push({ start, size });
    start += size;
  }
  return out;
}

/** Root value from full subtree heads (right to left fold). */
export function rootFromFullSubtrees(n: number, heads: readonly Uint8Array[]): Uint8Array {
  const ranges = fullSubtrees(n);
  let acc = heads[heads.length - 1]!;
  let accIsLeaf = ranges[ranges.length - 1]!.size === 1;
  for (let i = heads.length - 2; i >= 0; i--) {
    acc = logParent(heads[i]!, ranges[i]!.size === 1, acc, accIsLeaf);
    accIsLeaf = false;
  }
  return acc;
}

/**
 * Full subtree heads of the tree with n + 1 leaves, from those of the tree with
 * n leaves and the value of the new leaf. Keeps a log tree in O(log n) space.
 */
export function appendLeaf(n: number, heads: readonly Uint8Array[], leaf: Uint8Array): Uint8Array[] {
  if (!Number.isSafeInteger(n) || n < 0 || heads.length !== fullSubtrees(n).length) {
    throw new Error("heads do not match the tree size");
  }
  const out = heads.slice();
  let value = leaf;
  // Each trailing one bit of n is a balanced subtree the new leaf completes
  for (let k = 0, i = n; i % 2 === 1; k++, i = (i - 1) / 2) value = logParent(out.pop()!, k === 0, value, k === 0);
  out.push(value);
  return out;
}

export interface Retained {
  readonly size: number;
  readonly heads: readonly Uint8Array[];
}

/**
 * Computes the root of a tree with n leaves from known leaf values, retained full
 * subtree heads, and balanced subtree heads supplied by `element` in left-to-right
 * order. The prover passes an `element` that records stored heads, the verifier one
 * that consumes the proof. Retained heads recomputed from leaves must match. With
 * `also`, the same elements also give the root at that smaller size (Section 12.3).
 */
export function computeRoot(
  n: number,
  leaves: ReadonlyMap<number, Uint8Array>,
  retained: Retained | undefined,
  element: (r: Range) => Uint8Array,
  also?: number,
): { root: Uint8Array; full: Uint8Array[]; alsoRoot?: Uint8Array } {
  const m = retained?.size ?? 0;
  const old = m > 0 ? fullSubtrees(m) : [];
  const fresh = fullSubtrees(n);
  const full: Uint8Array[] = Array.from({ length: fresh.length });
  const wanted = also === undefined ? [] : fullSubtrees(also);
  const alsoFull: Uint8Array[] = Array.from({ length: wanted.length });
  const sorted = [...leaves.keys()].sort((a, b) => a - b);
  const hasLeaf = (start: number, size: number): boolean => {
    let lo = 0;
    let hi = sorted.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (sorted[mid]! < start) lo = mid + 1;
      else hi = mid;
    }
    return lo < sorted.length && sorted[lo]! < start + size;
  };

  const node = (start: number, size: number): Uint8Array => {
    const i = old.findIndex((r) => r.start === start && r.size === size);
    const kept = i >= 0 ? retained!.heads[i]! : undefined;
    const any = hasLeaf(start, size);
    let value: Uint8Array;
    const covers = (r: Range) => start <= r.start && r.start + r.size <= start + size;
    const coversRetained = old.some(covers);
    // A head of the smaller tree inside this subtree must be computed on its own
    const holdsWanted = wanted.some((r) => covers(r) && r.size < size);
    if (kept && !any && !holdsWanted) value = kept;
    else if (!any && !coversRetained && !holdsWanted && isPow2(size)) value = element({ start, size });
    else if (size === 1) value = leaves.get(start)!;
    else {
      const k = split(size);
      value = logParent(node(start, k), k === 1, node(start + k, size - k), size - k === 1);
    }
    if (kept && !equalBytes(value, kept)) throw new Error("retained subtree mismatch");
    const j = fresh.findIndex((r) => r.start === start && r.size === size);
    if (j >= 0) full[j] = value;
    const k = wanted.findIndex((r) => r.start === start && r.size === size);
    if (k >= 0) alsoFull[k] = value;
    return value;
  };
  const root = node(0, n);
  return also === undefined ? { root, full } : { root, full, alsoRoot: rootFromFullSubtrees(also, alsoFull) };
}
