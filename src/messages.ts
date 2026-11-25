/** Wire messages for Search and Contact Monitor (Sections 11.4, 12, 13.1, 13.2). */
import { NC, NH } from "./crypto.ts";
import { type PrefixProof, type PrefixSearchResult, ResultType } from "./prefix.ts";
import { DecodeError, type Reader, Writer } from "./tls.ts";

/** A binary ladder never has more than 65 lookups. Bounding counts keeps hostile lengths cheap. */
/** Results per prefix proof, enough for every new version of a 255 value update */
const MAX_RESULTS = 256;
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
  /** Absent for a greatest-version search */
  readonly version?: number | undefined;
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
  const w = writeLast(new Writer(), req.last).opaque(1, req.label);
  return (req.version === undefined ? w.u8(0) : w.u8(1).u32(req.version)).finish();
}

export function decodeSearchRequest(r: Reader): SearchRequest {
  const last = readLast(r);
  const label = r.opaque(1);
  return { last, label, version: r.present() ? r.u32() : undefined };
}

/** `fixed` omits the version, which a fixed-version request already names */
export function encodeSearchResponse(res: SearchResponse, fixed = false): Uint8Array {
  const w = new Writer();
  writeTreeHead(w, res.treeHead);
  if (!fixed) w.u32(res.version);
  w.bytes(res.opening).opaque(4, res.value);
  w.count(1, res.binaryLadder.length);
  for (const step of res.binaryLadder) {
    w.bytes(step.proof);
    if (step.commitment) w.u8(1).bytes(step.commitment);
    else w.u8(0);
  }
  writeCombined(w, res.search);
  return w.finish();
}

/**
 * `proofLength` is VRF.Np for the configured cipher suite, and `fixed` the
 * version of a fixed-version request, which the response then omits
 */
export function decodeSearchResponse(r: Reader, proofLength: number, fixed?: number): SearchResponse {
  const treeHead = readTreeHead(r);
  const version = fixed ?? r.u32();
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

export interface OwnerInitRequest {
  readonly last?: number | undefined;
  readonly label: Uint8Array;
  /** Distinguished entry where ownership starts, or absent for the start of the log */
  readonly start?: number | undefined;
}

export interface OwnerInitResponse {
  readonly treeHead?: TreeHead | undefined;
  /** Greatest version at each listed entry, until the first where the label does not exist */
  readonly greatestVersions: readonly number[];
  readonly binaryLadder: readonly BinaryLadderStep[];
  readonly init: CombinedTreeProof;
}

export interface OwnerMonitorRequest {
  readonly last?: number | undefined;
  readonly label: Uint8Array;
  readonly entries: readonly MonitorMapEntry[];
  /** Rightmost distinguished entry the owner verified */
  readonly start?: number | undefined;
  readonly greatestVersion?: number | undefined;
}

export interface OwnerMonitorResponse {
  readonly treeHead?: TreeHead | undefined;
  readonly monitor: CombinedTreeProof;
}

export interface UpdateRequest {
  readonly last?: number | undefined;
  readonly label: Uint8Array;
  readonly greatestVersion?: number | undefined;
  readonly values: readonly Uint8Array[];
}

export interface UpdateResponse {
  readonly treeHead?: TreeHead | undefined;
  /** Log entry where the versions were inserted */
  readonly position: number;
  /** Values of existing versions, when the request's values were disregarded */
  readonly values: readonly Uint8Array[];
  /** Commitment opening of each new version */
  readonly openings: readonly Uint8Array[];
  readonly binaryLadder: readonly BinaryLadderStep[];
  readonly update: CombinedTreeProof;
}

const writeOptU64 = (w: Writer, v: number | undefined): Writer => (v === undefined ? w.u8(0) : w.u8(1).u64(v));
const writeOptU32 = (w: Writer, v: number | undefined): Writer => (v === undefined ? w.u8(0) : w.u8(1).u32(v));

function writeLadder(w: Writer, prefix: 1 | 2, steps: readonly BinaryLadderStep[]): void {
  w.count(prefix, steps.length);
  for (const step of steps) {
    w.bytes(step.proof);
    if (step.commitment) w.u8(1).bytes(step.commitment);
    else w.u8(0);
  }
}

const readLadder = (r: Reader, prefix: 1 | 2, proofLength: number): BinaryLadderStep[] =>
  Array.from({ length: r.count(prefix, proofLength + 1) }, () => ({
    proof: r.bytes(proofLength),
    commitment: r.present() ? r.bytes(NH) : undefined,
  }));

export function encodeOwnerInitRequest(req: OwnerInitRequest): Uint8Array {
  return writeOptU64(writeLast(new Writer(), req.last).opaque(1, req.label), req.start).finish();
}

export function decodeOwnerInitRequest(r: Reader): OwnerInitRequest {
  return { last: readLast(r), label: r.opaque(1), start: r.present() ? r.u64() : undefined };
}

export function encodeOwnerInitResponse(res: OwnerInitResponse): Uint8Array {
  const w = new Writer();
  writeTreeHead(w, res.treeHead);
  w.count(1, res.greatestVersions.length);
  for (const v of res.greatestVersions) w.u32(v);
  writeLadder(w, 2, res.binaryLadder);
  writeCombined(w, res.init);
  return w.finish();
}

export function decodeOwnerInitResponse(r: Reader, proofLength: number): OwnerInitResponse {
  const treeHead = readTreeHead(r);
  const greatestVersions = Array.from({ length: r.count(1, 4) }, () => r.u32());
  return { treeHead, greatestVersions, binaryLadder: readLadder(r, 2, proofLength), init: readCombined(r) };
}

export function encodeOwnerMonitorRequest(req: OwnerMonitorRequest): Uint8Array {
  const w = writeLast(new Writer(), req.last).opaque(1, req.label).count(1, req.entries.length);
  for (const e of req.entries) w.u64(e.position).u32(e.version);
  return writeOptU32(writeOptU64(w, req.start), req.greatestVersion).finish();
}

export function decodeOwnerMonitorRequest(r: Reader): OwnerMonitorRequest {
  const last = readLast(r);
  const label = r.opaque(1);
  const entries = Array.from({ length: r.count(1, 12) }, () => ({ position: r.u64(), version: r.u32() }));
  const start = r.present() ? r.u64() : undefined;
  return { last, label, entries, start, greatestVersion: r.present() ? r.u32() : undefined };
}

export function encodeOwnerMonitorResponse(res: OwnerMonitorResponse): Uint8Array {
  const w = new Writer();
  writeTreeHead(w, res.treeHead);
  writeCombined(w, res.monitor);
  return w.finish();
}

export const decodeOwnerMonitorResponse = (r: Reader): OwnerMonitorResponse => ({
  treeHead: readTreeHead(r),
  monitor: readCombined(r),
});

export function encodeUpdateRequest(req: UpdateRequest): Uint8Array {
  const w = writeOptU32(writeLast(new Writer(), req.last).opaque(1, req.label), req.greatestVersion);
  w.count(1, req.values.length);
  for (const v of req.values) w.opaque(4, v);
  return w.finish();
}

export function decodeUpdateRequest(r: Reader): UpdateRequest {
  const last = readLast(r);
  const label = r.opaque(1);
  const greatestVersion = r.present() ? r.u32() : undefined;
  const values = Array.from({ length: r.count(1, 4) }, () => r.opaque(4));
  return { last, label, greatestVersion, values };
}

/** UpdateResponse for Contact Monitoring mode, where UpdateInfo is only the opening */
export function encodeUpdateResponse(res: UpdateResponse): Uint8Array {
  const w = new Writer();
  writeTreeHead(w, res.treeHead);
  w.u64(res.position).count(1, res.values.length);
  for (const v of res.values) w.opaque(4, v);
  w.count(1, res.openings.length);
  for (const o of res.openings) w.bytes(o);
  writeLadder(w, 1, res.binaryLadder);
  writeCombined(w, res.update);
  return w.finish();
}

export function decodeUpdateResponse(r: Reader, proofLength: number): UpdateResponse {
  const treeHead = readTreeHead(r);
  const position = r.u64();
  const values = Array.from({ length: r.count(1, 4) }, () => r.opaque(4));
  const openings = Array.from({ length: r.count(1, NC) }, () => r.bytes(NC));
  return { treeHead, position, values, openings, binaryLadder: readLadder(r, 1, proofLength), update: readCombined(r) };
}
