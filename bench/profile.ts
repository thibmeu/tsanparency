/**
 * Self time by function for each hot path, sampled with V8's CPU profiler.
 * Frames under src/ are the optimisation surface. Node only, never shipped.
 *
 * Run: npm run bench:profile
 */
import { Session } from "node:inspector/promises";
import { fixture } from "./fixtures.ts";

interface CallFrame {
  functionName: string;
  url: string;
  lineNumber: number;
}
interface CpuProfile {
  nodes: { id: number; callFrame: CallFrame }[];
  samples: number[];
  timeDeltas: number[];
}

const name = (f: CallFrame) =>
  `${f.functionName || "(anonymous)"}  ${f.url ? f.url.replace(/^.*\/(src|node_modules)\//, "$1/") + ":" + (f.lineNumber + 1) : "(native)"}`;

async function profile(session: Session, label: string, iters: number, fn: () => Promise<unknown>) {
  for (let i = 0; i < 5; i++) await fn();
  await session.post("Profiler.start");
  const t = performance.now();
  for (let i = 0; i < iters; i++) await fn();
  const ms = (performance.now() - t) / iters;
  const { profile } = (await session.post("Profiler.stop")) as { profile: CpuProfile };
  const frames = new Map(profile.nodes.map((n) => [n.id, n.callFrame]));
  const self = new Map<string, number>();
  profile.samples.forEach((id, i) => {
    const k = name(frames.get(id)!);
    self.set(k, (self.get(k) ?? 0) + profile.timeDeltas[i]! / 1000);
  });
  const total = [...self.values()].reduce((a, b) => a + b, 0);
  console.log(`\n${label}: ${ms.toFixed(2)} ms/op`);
  for (const [k, v] of [...self].sort((a, b) => b[1] - a[1]).slice(0, 12))
    console.log(`  ${((100 * v) / total).toFixed(1).padStart(5)}%  ${k}`);
}

const f = await fixture();
const session = new Session();
session.connect();
await session.post("Profiler.enable");
await session.post("Profiler.setSamplingInterval", { interval: 100 });

let i = 0;
await profile(session, "search, first contact", 50, () => f.client.search(`user-${i++ % 500}`, f.initial));
const found = await f.client.search("user-1", f.initial);
await profile(session, "search, returning", 50, () =>
  f.client.search("user-2", { checkpoint: found.state.checkpoint }),
);
await profile(session, "append", 200, () => f.append(`user-${i++ % 500}`));
