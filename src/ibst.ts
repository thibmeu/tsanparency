/**
 * Implicit binary search tree over log entries (Section 4.1, Appendix A).
 * Arithmetic instead of bitwise operators keeps indices exact up to 2^53.
 */

function level(x: number): number {
  let k = 0;
  while (x % 2 === 1) {
    x = (x - 1) / 2;
    k++;
  }
  return k;
}

export function root(n: number): number {
  let p = 1;
  while (p * 2 <= n) p *= 2;
  return p - 1;
}

export function left(x: number): number {
  const k = level(x);
  if (k === 0) throw new RangeError("node has no left child");
  return x - 2 ** (k - 1);
}

export function right(x: number, n: number): number {
  const k = level(x);
  if (k === 0 || x === n - 1) throw new RangeError("node has no right child");
  x += 2 ** (k - 1);
  while (x >= n) x = left(x);
  return x;
}

export const hasLeft = (x: number): boolean => x % 2 === 1;
export const hasRight = (x: number, n: number): boolean => x % 2 === 1 && x !== n - 1;

/** Root, its right child, and so on down to entry n - 1. */
export function frontier(n: number): number[] {
  const out = [root(n)];
  for (let x = out[0]!; x !== n - 1;) out.push((x = right(x, n)));
  return out;
}

/** Ancestors of x in a tree of size n, root first. */
export function ancestors(x: number, n: number): number[] {
  const out: number[] = [];
  for (let c = root(n); c !== x; c = x < c ? left(c) : right(c, n)) out.push(c);
  return out;
}
