/** Binary ladders (Section 5, Appendix B). */

export const MAX_VERSION = 2 ** 32 - 1;

/** Versions looked up to establish that n is the greatest version. */
export function baseLadder(n: number): number[] {
  const out: number[] = [];
  let lo = -1;
  let hi = -1;
  for (let i = 0; ; i++) {
    const v = 2 ** i - 1;
    out.push(v);
    if (v > n) {
      lo = 2 ** (i - 1) - 1;
      hi = v;
      break;
    }
  }
  while (lo + 1 < hi) {
    const v = Math.floor((lo + hi) / 2);
    out.push(v);
    if (v <= n && v <= MAX_VERSION) lo = v;
    else hi = v;
  }
  return out.filter((v) => v <= MAX_VERSION);
}

/** VRF proofs needed to advance an owner from one greatest version to another. */
export function updateLadder(before: number, after: number): number[] {
  const wanted = new Set(baseLadder(after));
  for (let v = before + 1; v <= after; v++) wanted.add(v);
  for (const v of before < 0 ? [0] : baseLadder(before)) wanted.delete(v);
  return [...wanted].sort((a, b) => a - b);
}

/** Lookups of a monitoring binary ladder for target t (Section 8.1). */
export const monitoringLadder = (t: number): number[] => baseLadder(t).filter((v) => v <= t);

/**
 * Runs a search binary ladder for target t (Section 6.2). `probe(v)` reports
 * whether version v is included. The ladder stops at the first inclusion above t
 * or non-inclusion at or below t. The greatest version stays unknown to the
 * caller, so the ladder adapts to each outcome like base_binary_ladder(n).
 */
export function searchLadder(t: number, probe: (v: number) => boolean): void {
  const look = (v: number): boolean | undefined => {
    if (v > MAX_VERSION) return false;
    const inc = probe(v);
    return (inc && v > t) || (!inc && v <= t) ? undefined : inc;
  };
  let lo = -1;
  let hi = -1;
  for (let i = 0; ; i++) {
    const v = 2 ** i - 1;
    const inc = look(v);
    if (inc === undefined) return;
    if (!inc) {
      lo = 2 ** (i - 1) - 1;
      hi = v;
      break;
    }
  }
  while (lo + 1 < hi) {
    const v = Math.floor((lo + hi) / 2);
    const inc = look(v);
    if (inc === undefined) return;
    if (inc) lo = v;
    else hi = v;
  }
}
