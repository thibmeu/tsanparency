/** Wire messages for Search and Contact Monitor (Sections 11.4, 12, 13.1, 13.2). */
import { NC, NH } from "./crypto.ts";
import { type PrefixProof, type PrefixSearchResult, ResultType } from "./prefix.ts";
import { DecodeError, type Reader, Writer } from "./tls.ts";

/** A binary ladder never has more than 65 lookups. Bounding counts keeps hostile lengths cheap. */
const MAX_RESULTS = 128;
const MAX_KEY_BITS = 8 * NH;

export interface TreeHead {
  readonly treeSize: number;
  readonly signature: Uint8Array;
}

export interface CombinedTreeProof {
  readonly timestamps: readonly number[];
  readonly prefixProofs: readonly PrefixProof[];
  readonly prefixRoots: readonly Uint8Array[];
  readonly inclusion: readonly Uint8Array[];
}

export interface BinaryLadderStep {
  readonly proof: Uint8Array;
  readonly commitment?: Uint8Array | undefined;
}

export interface SearchRequest {
  readonly last?: number | undefined;
  readonly label: Uint8Array;
}

export interface SearchResponse {
  /** Absent when the log reuses the advertised tree head. */
  readonly treeHead?: TreeHead | undefined;
  readonly version: number;
  readonly opening: Uint8Array;
  readonly value: Uint8Array;
  readonly binaryLadder: readonly BinaryLadderStep[];
  readonly search: CombinedTreeProof;
}

export interface MonitorMapEntry {
  readonly position: number;
  readonly version: number;
}

export interface ContactMonitorRequest {
  readonly last?: number | undefined;
  readonly label: Uint8Array;
  readonly entries: readonly MonitorMapEntry[];
}

export interface ContactMonitorResponse {
  readonly treeHead?: TreeHead | undefined;
  readonly monitor: CombinedTreeProof;
}

const writeLast = (w: Writer, last: number | undefined): Writer => (last === undefined ? w.u8(0) : w.u8(1).u64(last));
const readLast = (r: Reader): number | undefined => (r.present() ? r.u64() : undefined);

function writeTreeHead(w: Writer, h: TreeHead | undefined): void {
  if (!h) w.u8(1);
  else w.u8(2).u64(h.treeSize).opaque(2, h.signature);
}

function readTreeHead(r: Reader): TreeHead | undefined {
  const type = r.u8();
  if (type === 1) return undefined;
  if (type !== 2) throw new DecodeError("invalid head type");
  return { treeSize: r.u64(), signature: r.opaque(2, 64) };
}

function writeCombined(w: Writer, p: CombinedTreeProof): void {
  w.count(1, p.timestamps.length);
  for (const t of p.timestamps) w.u64(t);
  w.count(1, p.prefixProofs.length);
  for (const pp of p.prefixProofs) {
    w.count(4, pp.results.length);
    for (const res of pp.results) {
      w.u8(res.type);
      if (res.type === ResultType.NonInclusionLeaf) w.bytes(res.leaf.vrfOutput).bytes(res.leaf.commitment);
      w.u8(res.depth);
    }
    w.count(4, pp.elements.length);
    for (const e of pp.elements) w.bytes(e);
  }
  w.count(1, p.prefixRoots.length);
  for (const root of p.prefixRoots) w.bytes(root);
  w.count(2, p.inclusion.length);
  for (const e of p.inclusion) w.bytes(e);
}

function readResult(r: Reader): PrefixSearchResult {
  const type = r.u8();
  if (type === ResultType.NonInclusionLeaf) {
    const leaf = { vrfOutput: r.bytes(NH), commitment: r.bytes(NH) };
    return { type, leaf, depth: r.u8() };
  }
  if (type !== ResultType.Inclusion && type !== ResultType.NonInclusionParent) throw new DecodeError("invalid result");
  return { type, depth: r.u8() };
}

function readCombined(r: Reader): CombinedTreeProof {
  const timestamps = Array.from({ length: r.count(1, 8) }, () => r.u64());
  const prefixProofs = Array.from({ length: r.count(1, 8) }, () => {
    const results = Array.from({ length: r.count(4, 2, MAX_RESULTS) }, () => readResult(r));
    const elements = Array.from({ length: r.count(4, NH, results.length * MAX_KEY_BITS) }, () => r.bytes(NH));
    return { results, elements };
  });
  const prefixRoots = Array.from({ length: r.count(1, NH) }, () => r.bytes(NH));
  const inclusion = Array.from({ length: r.count(2, NH) }, () => r.bytes(NH));
  return { timestamps, prefixProofs, prefixRoots, inclusion };
}

export function encodeSearchRequest(req: SearchRequest): Uint8Array {
  return writeLast(new Writer(), req.last).opaque(1, req.label).u8(0).finish();
}

export function decodeSearchRequest(r: Reader): SearchRequest {
  const last = readLast(r);
  const label = r.opaque(1);
  if (r.present()) throw new DecodeError("fixed-version search is not supported");
  return { last, label };
}

export function encodeSearchResponse(res: SearchResponse): Uint8Array {
  const w = new Writer();
  writeTreeHead(w, res.treeHead);
  w.u32(res.version).bytes(res.opening).opaque(4, res.value);
  w.count(1, res.binaryLadder.length);
  for (const step of res.binaryLadder) {
    w.bytes(step.proof);
    if (step.commitment) w.u8(1).bytes(step.commitment);
    else w.u8(0);
  }
  writeCombined(w, res.search);
  return w.finish();
}

/** `proofLength` is VRF.Np for the configured cipher suite */
export function decodeSearchResponse(r: Reader, proofLength: number): SearchResponse {
  const treeHead = readTreeHead(r);
  const version = r.u32();
  const opening = r.bytes(NC);
  const value = r.opaque(4);
  const binaryLadder = Array.from({ length: r.count(1, proofLength + 1) }, () => ({
    proof: r.bytes(proofLength),
    commitment: r.present() ? r.bytes(NH) : undefined,
  }));
  return { treeHead, version, opening, value, binaryLadder, search: readCombined(r) };
}

export function encodeContactMonitorRequest(req: ContactMonitorRequest): Uint8Array {
  const w = writeLast(new Writer(), req.last).opaque(1, req.label).count(1, req.entries.length);
  for (const e of req.entries) w.u64(e.position).u32(e.version);
  return w.finish();
}

export function decodeContactMonitorRequest(r: Reader): ContactMonitorRequest {
  const last = readLast(r);
  const label = r.opaque(1);
  const entries = Array.from({ length: r.count(1, 12) }, () => ({ position: r.u64(), version: r.u32() }));
  return { last, label, entries };
}

export function encodeContactMonitorResponse(res: ContactMonitorResponse): Uint8Array {
  const w = new Writer();
  writeTreeHead(w, res.treeHead);
  writeCombined(w, res.monitor);
  return w.finish();
}

export function decodeContactMonitorResponse(r: Reader): ContactMonitorResponse {
  return { treeHead: readTreeHead(r), monitor: readCombined(r) };
}
