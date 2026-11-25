/** Persistent prefix tree and batched search proofs (Sections 3.3, 11.9, 12.2). */
import { equalBytes } from "@noble/curves/utils.js";
import { NH, prefixLeaf, prefixParent } from "./crypto.ts";

export const ResultType = { Inclusion: 1, NonInclusionLeaf: 2, NonInclusionParent: 3 } as const;
export type ResultType = (typeof ResultType)[keyof typeof ResultType];

export interface PrefixLeaf {
  readonly vrfOutput: Uint8Array;
  readonly commitment: Uint8Array;
}

export type PrefixSearchResult =
  | { readonly type: typeof ResultType.Inclusion | typeof ResultType.NonInclusionParent; readonly depth: number }
  | { readonly type: typeof ResultType.NonInclusionLeaf; readonly leaf: PrefixLeaf; readonly depth: number };

export interface PrefixProof {
  readonly results: readonly PrefixSearchResult[];
  readonly elements: readonly Uint8Array[];
}

const ZERO = new Uint8Array(NH);
const KEY_BITS = 8 * NH;
const bit = (key: Uint8Array, d: number): number => (key[d >> 3]! >> (7 - (d & 7))) & 1;

function sharesPrefix(a: Uint8Array, b: Uint8Array, d: number): boolean {
  for (let i = 0; i < d; i++) if (bit(a, i) !== bit(b, i)) return false;
  return true;
}

interface Leaf extends PrefixLeaf {
  readonly hash: Uint8Array;
}
interface Parent {
  readonly left: Node;
  readonly right: Node;
  readonly hash: Uint8Array;
}
/** An immutable prefix tree, where `null` is the empty tree */
export type Node = Leaf | Parent | null;

const isLeaf = (n: Leaf | Parent): n is Leaf => "vrfOutput" in n;
export const rootHash = (n: Node): Uint8Array => n?.hash ?? ZERO;

const leaf = (vrfOutput: Uint8Array, commitment: Uint8Array): Leaf => ({
  vrfOutput,
  commitment,
  hash: prefixLeaf(vrfOutput, commitment),
});
const parent = (left: Node, right: Node): Parent => ({
  left,
  right,
  hash: prefixParent(rootHash(left), rootHash(right)),
});

/** Returns a new tree mapping `key` to `commitment`, leaving the input unchanged */
export function insert(node: Node, key: Uint8Array, commitment: Uint8Array, d = 0): Node {
  if (node === null) return leaf(key, commitment);
  if (isLeaf(node)) {
    if (equalBytes(node.vrfOutput, key)) throw new Error("duplicate search key");
    if (d >= KEY_BITS) throw new Error("search key collision");
    const b = bit(key, d);
    const o = bit(node.vrfOutput, d);
    if (b === o) {
      const child = insert(node, key, commitment, d + 1);
      return b === 0 ? parent(child, null) : parent(null, child);
    }
    const fresh = leaf(key, commitment);
    return b === 0 ? parent(fresh, node) : parent(node, fresh);
  }
  return bit(key, d) === 0
    ? parent(insert(node.left, key, commitment, d + 1), node.right)
    : parent(node.left, insert(node.right, key, commitment, d + 1));
}

export function contains(node: Node, key: Uint8Array): boolean {
  for (let d = 0; node !== null; d++) {
    if (isLeaf(node)) return equalBytes(node.vrfOutput, key);
    node = bit(key, d) === 0 ? node.left : node.right;
  }
  return false;
}

/** Search proof for `keys`, results in request order (Section 12.2). */
export function prove(root: Node, keys: readonly Uint8Array[]): PrefixProof {
  const results: PrefixSearchResult[] = Array.from({ length: keys.length });
  const elements: Uint8Array[] = [];
  const walk = (node: Node, group: number[], d: number): void => {
    if (node === null) {
      for (const i of group) results[i] = { type: ResultType.NonInclusionParent, depth: d };
    } else if (isLeaf(node)) {
      for (const i of group)
        results[i] = equalBytes(node.vrfOutput, keys[i]!)
          ? { type: ResultType.Inclusion, depth: d }
          : { type: ResultType.NonInclusionLeaf, leaf: node, depth: d };
    } else {
      const l = group.filter((i) => bit(keys[i]!, d) === 0);
      const r = group.filter((i) => bit(keys[i]!, d) === 1);
      if (l.length) walk(node.left, l, d + 1);
      else elements.push(rootHash(node.left));
      if (r.length) walk(node.right, r, d + 1);
      else elements.push(rootHash(node.right));
    }
  };
  if (keys.length)
    walk(
      root,
      keys.map((_, i) => i),
      0,
    );
  return {
    results: results.map((r) => (r.type === ResultType.NonInclusionLeaf ? { ...r, leaf: copyLeaf(r.leaf) } : r)),
    elements,
  };
}

const copyLeaf = (l: PrefixLeaf): PrefixLeaf => ({ vrfOutput: l.vrfOutput, commitment: l.commitment });

export interface Lookup {
  readonly key: Uint8Array;
  readonly result: PrefixSearchResult;
  /** Commitment for the key, required for inclusion results */
  readonly commitment?: Uint8Array | undefined;
}

/** Hashes the search results with the proof elements, in the left/right arrangement given by the search key bits, to recompute the root (Section 12.2). Throws if malformed. */
export function evaluate(lookups: readonly Lookup[], elements: readonly Uint8Array[]): Uint8Array {
  let next = 0;
  const pop = (): Uint8Array => {
    const e = elements[next++];
    if (!e) throw new Error("prefix proof too short");
    return e;
  };
  const valueOf = ({ key, result, commitment }: Lookup, d: number): Uint8Array => {
    switch (result.type) {
      case ResultType.Inclusion:
        if (!commitment) throw new Error("missing commitment");
        return prefixLeaf(key, commitment);
      case ResultType.NonInclusionLeaf:
        if (equalBytes(result.leaf.vrfOutput, key) || !sharesPrefix(result.leaf.vrfOutput, key, d))
          throw new Error("misplaced leaf");
        return prefixLeaf(result.leaf.vrfOutput, result.leaf.commitment);
      case ResultType.NonInclusionParent:
        return ZERO;
    }
  };
  const walk = (group: readonly Lookup[], d: number): Uint8Array => {
    const terminal = group.filter((l) => l.result.depth === d);
    if (terminal.length) {
      if (terminal.length !== group.length) throw new Error("search continues past a leaf");
      const v = valueOf(group[0]!, d);
      for (const l of group.slice(1)) if (!equalBytes(valueOf(l, d), v)) throw new Error("inconsistent leaf");
      return v;
    }
    if (d >= KEY_BITS) throw new Error("depth out of range");
    const l = group.filter((x) => bit(x.key, d) === 0);
    const r = group.filter((x) => bit(x.key, d) === 1);
    const lv = l.length ? walk(l, d + 1) : pop();
    const rv = r.length ? walk(r, d + 1) : pop();
    return prefixParent(lv, rv);
  };
  if (!lookups.length) throw new Error("empty prefix proof");
  const root = walk(lookups, 0);
  if (next !== elements.length) throw new Error("prefix proof too long");
  return root;
}
