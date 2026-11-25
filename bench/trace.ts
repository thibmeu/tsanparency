/**
 * Writes a CPU profile and a sampling heap profile of one operation to bench/.trace/.
 * Open <op>.cpuprofile in speedscope.app or Chrome DevTools (Performance), and
 * <op>.heapprofile in Chrome DevTools (Memory). Node only, never shipped.
 *
 * Run: OP=search npm run bench:trace   (OP is search, append or monitor)
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { Session } from "node:inspector/promises";
import { fixture } from "./fixtures.ts";

const { OP = "search", ITERS = "50" } = process.env;
const f = await fixture();
let i = 0;
const ops: Record<string, () => Promise<unknown>> = {
  search: () => f.client.search(`user-${i++ % 500}`, f.initial),
  append: () => f.append(`user-${i++ % 500}`),
};
const op = ops[OP];
if (!op) throw new Error(`OP is one of ${Object.keys(ops).join(", ")}`);

const session = new Session();
session.connect();
await session.post("Profiler.enable");
await session.post("HeapProfiler.enable");
await session.post("Profiler.start");
await session.post("HeapProfiler.startSampling", { samplingInterval: 1024 });
for (let n = 0; n < Number(ITERS); n++) await op();
const { profile: heap } = await session.post("HeapProfiler.stopSampling");
const { profile: cpu } = await session.post("Profiler.stop");
mkdirSync("bench/.trace", { recursive: true });
writeFileSync(`bench/.trace/${OP}.cpuprofile`, JSON.stringify(cpu));
writeFileSync(`bench/.trace/${OP}.heapprofile`, JSON.stringify(heap));
console.log(`wrote bench/.trace/${OP}.cpuprofile and bench/.trace/${OP}.heapprofile`);
