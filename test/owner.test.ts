import { fc, test } from "@fast-check/vitest";
import { describe, expect } from "vitest";
import { type Client, KTErrorCode, type State, createClient, isKTError } from "../src/index.ts";
import { decodeOwnerMonitorRequest, encodeOwnerMonitorRequest, encodeUpdateRequest } from "../src/messages.ts";
import { Operation } from "../src/client.ts";
import { decode } from "../src/tls.ts";
import { RMW, SUITE_NAMES, type World, world } from "./harness.ts";

const bytes = (s: string) => new TextEncoder().encode(s);
const text = (b: Uint8Array) => new TextDecoder().decode(b);
const owners = (w: World) => w.client("owner");
const open = { authorize: () => true };

/** Learns every version created elsewhere, one log entry at a time */
async function catchUp(client: Client, state: State): Promise<State> {
  for (;;) {
    const r = await client.update("alice", [], state).catch((e) => e);
    if (isKTError(r, KTErrorCode.InvalidRequest)) return state;
    if (r instanceof Error) throw r;
    state = r.state;
  }
}

async function monitorUntilDone(w: World, client: Client, state: State): Promise<State> {
  for (let i = 0; i < 64; i++) {
    const r = await client.ownerMonitor("alice", state);
    state = r.state;
    if (r.done && !state.owner!.monitoring.length) return state;
    if (!r.done) state = await catchUp(client, state);
    w.clock.now += RMW / 2;
    await w.log.tick();
  }
  throw new Error("owner monitoring did not finish");
}

describe.each(SUITE_NAMES)("label owner with %s", (_, cipherSuite) => {
  test("creates versions from the start of the log and monitors them", async () => {
    const w = await world({ cipherSuite }, open);
    await w.log.tick();
    const client = await owners(w);
    let state: State = (await client.ownerInit("alice", client.initialState())).state;
    const first = await client.update("alice", [bytes("k0")], state);
    expect(first.versions.map((v) => v.version)).toEqual([0]);
    expect(first.disregarded).toBe(false);
    state = first.state;
    w.clock.now += 10;
    const batch = await client.update("alice", [bytes("k1"), bytes("k2"), bytes("k3")], state);
    expect(batch.versions.map((v) => v.version)).toEqual([1, 2, 3]);
    state = batch.state;

    const reader = await w.client("bob");
    const found = await reader.search("alice", reader.initialState());
    expect(text(found.value)).toBe("k3");
    expect(text((await reader.search("alice", found.state, { version: 2 })).value)).toBe("k2");

    state = await monitorUntilDone(w, client, state);
    expect(state.owner!.start).toBeDefined();
  });

  test("learns versions created by someone else", async () => {
    const w = await world({ cipherSuite }, open);
    await w.log.append({ label: "alice", value: bytes("a0"), expectedVersion: null });
    const client = await owners(w);
    let state: State = (await client.ownerInit("alice", client.initialState())).state;
    w.clock.now += 10;
    await w.log.append({ label: "alice", values: [bytes("a1"), bytes("a2")], expectedVersion: 0 });
    const r = await client.update("alice", [], state);
    expect(r.disregarded).toBe(true);
    expect(r.versions.map((v) => text(v.value))).toEqual(["a0"]);
    state = await catchUp(client, r.state);
    expect(state.owner!.upcoming).toHaveLength(3);
    const own = await client.update("alice", [bytes("mine")], state);
    expect(own.versions).toEqual([{ version: 3, value: bytes("mine") }]);
  });

  test("starts at a distinguished entry", async () => {
    const w = await world({ cipherSuite }, open);
    await w.log.append({ label: "alice", value: bytes("a0"), expectedVersion: null });
    w.clock.now += 2 * RMW;
    await w.log.append({ label: "alice", value: bytes("a1"), expectedVersion: 0 });
    w.clock.now += 10;
    await w.log.tick();
    const client = await owners(w);
    // Entry 1 is the root of a three entry tree, distinguished once the log is older than the RMW
    const init = await client.ownerInit("alice", client.initialState(), { start: 1 });
    expect(init.state.owner.previous).toEqual([1]);
    const bad = await client.ownerInit("alice", client.initialState(), { start: 2 }).catch((e) => e);
    expect(isKTError(bad, KTErrorCode.InvalidRequest)).toBe(true);
    await monitorUntilDone(w, client, init.state);
  });

  test("a log that stops owner monitoring at a version it will not report is caught", async () => {
    const w = await world({ cipherSuite }, open);
    await w.log.append({ label: "alice", value: bytes("k0"), expectedVersion: null });
    // Advertising no greatest version makes the log stop at the first entry holding one
    const exchange = w.exchange("owner");
    const client = await createClient(
      w.config,
      async (op, req, opts) => {
        if (op !== "ownerMonitor") return exchange(op, req, opts);
        const r = decode(req, decodeOwnerMonitorRequest);
        return exchange(op, encodeOwnerMonitorRequest({ ...r, greatestVersion: undefined, start: undefined }), opts);
      },
      { now: () => w.clock.now },
    );
    let state: State = (await client.ownerInit("alice", client.initialState())).state;
    state = (await client.update("alice", [], state)).state;
    for (let i = 0; i < 4; i++) {
      w.clock.now += 2 * RMW;
      await w.log.tick();
    }
    const stopped = await client.ownerMonitor("alice", state);
    expect(stopped.done).toBe(false);
    expect(stopped.state.owner!.stalled).toBe(0);
    const err = await client.update("alice", [], stopped.state).catch((e) => e);
    expect(isKTError(err, KTErrorCode.InvalidResponse)).toBe(true);
    const again = await client.ownerMonitor("alice", stopped.state).catch((e) => e);
    expect(isKTError(again, KTErrorCode.InvalidResponse)).toBe(true);
  });

  test("an Update rejected for trailing bytes creates nothing", async () => {
    const w = await world({ cipherSuite }, { authorize: async () => true });
    await w.log.tick();
    const size = w.log.size;
    const request = encodeUpdateRequest({ label: bytes("alice"), values: [bytes("k0")] });
    const err = await w.log
      .handle(Operation.Update, new Uint8Array([...request, 0]), { principal: "owner" })
      .catch((e) => e);
    expect(isKTError(err, KTErrorCode.InvalidRequest)).toBe(true);
    await w.log.tick();
    expect(w.log.size).toBe(size + 1);
    const reader = await w.client("bob");
    const missing = await reader.search("alice", reader.initialState()).catch((e) => e);
    expect(isKTError(missing, KTErrorCode.NotFound)).toBe(true);
  });

  test("contact operations keep owner state", async () => {
    const w = await world({ cipherSuite }, open);
    await w.log.tick();
    const client = await owners(w);
    let state: State = (await client.ownerInit("alice", client.initialState())).state;
    state = (await client.update("alice", [bytes("k0")], state)).state;
    for (let i = 0; i < 3; i++) {
      w.clock.now += RMW;
      await w.log.tick();
      state = structuredClone((await client.search("alice", state)).state);
      expect(state.owner?.label).toEqual(bytes("alice"));
      state = structuredClone((await client.monitor("alice", state)).state);
      expect(state.owner?.label).toEqual(bytes("alice"));
      state = (await client.update("alice", [bytes(`k${i + 1}`)], state)).state;
    }
    await monitorUntilDone(w, client, state);
  });

  test("versions at a distinguished entry stay pending until owner monitoring", async () => {
    for (const [ticks, pending] of [
      [1, true],
      [2, false],
    ] as const) {
      const w = await world({ cipherSuite }, open);
      for (let i = 0; i < ticks; i++) await w.log.tick();
      const client = await owners(w);
      const state = (await client.ownerInit("alice", client.initialState())).state;
      // Someone else creates the version, so its value comes from the log
      await w.log.append({ label: "alice", value: bytes("theirs"), expectedVersion: null });
      const r = await client.update("alice", [], state);
      expect([r.disregarded, r.pending]).toEqual([true, pending]);
      await monitorUntilDone(w, client, r.state);
    }
  });

  test("a first batch of 200 versions verifies", async () => {
    const w = await world({ cipherSuite }, open);
    await w.log.tick();
    const client = await owners(w);
    const state = (await client.ownerInit("alice", client.initialState())).state;
    const values = Array.from({ length: 200 }, (_, i) => new Uint8Array([i]));
    const r = await client.update("alice", values, state);
    expect(r.versions).toHaveLength(200);
    const reader = await w.client("bob");
    expect((await reader.search("alice", reader.initialState(), { version: 150 })).value).toEqual(values[150]);
  });

  test("owner operations need authorization", async () => {
    const w = await world({ cipherSuite });
    await w.log.tick();
    const client = await owners(w);
    const err = await client.ownerInit("alice", client.initialState()).catch((e) => e);
    expect(isKTError(err, KTErrorCode.Unauthorized)).toBe(true);
  });

  type Step = { kind: "own" | "other"; count: number } | { kind: "tick" | "monitor"; gap: number };
  const step: fc.Arbitrary<Step> = fc.oneof(
    fc.record({ kind: fc.constantFrom("own" as const, "other" as const), count: fc.integer({ min: 1, max: 3 }) }),
    fc.record({
      kind: fc.constantFrom("tick" as const, "monitor" as const),
      gap: fc.integer({ min: 0, max: 2 * RMW }),
    }),
  );

  test.prop([fc.array(step, { minLength: 1, maxLength: 14 })], { numRuns: 15, timeout: 120_000 })(
    "an honest log never fails its owner, and owner monitoring completes",
    async (steps) => {
      const w = await world({ cipherSuite }, open);
      await w.log.tick();
      const client = await owners(w);
      let state: State = (await client.ownerInit("alice", client.initialState())).state;
      let versions = 0;
      for (const s of steps) {
        if (s.kind === "other") {
          w.clock.now += 1;
          const values = Array.from({ length: s.count }, (_, i) => bytes(`other-${versions + i}`));
          await w.log.append({ label: "alice", values, expectedVersion: versions ? versions - 1 : null });
          versions += s.count;
        } else if (s.kind === "own") {
          state = await catchUp(client, state);
          w.clock.now += 1;
          const values = Array.from({ length: s.count }, (_, i) => bytes(`own-${versions + i}`));
          state = (await client.update("alice", values, state)).state;
          versions += s.count;
        } else if ("gap" in s) {
          w.clock.now += s.gap;
          await w.log.tick();
          if (s.kind === "monitor") {
            const r = await client.ownerMonitor("alice", state);
            state = r.done ? r.state : await catchUp(client, r.state);
          }
        }
      }
      state = await catchUp(client, state);
      state = await monitorUntilDone(w, client, state);
    },
  );
});
