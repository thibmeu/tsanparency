import { fc, test } from "@fast-check/vitest";
import { describe, expect } from "vitest";
import { type Client, type State, KTErrorCode, isKTError } from "../src/index.ts";
import { CipherSuite } from "../src/crypto.ts";
import { RMW, SUITE_NAMES, type World, world } from "./harness.ts";

const LABELS = ["alice", "bob", "carol"] as const;
type Label = (typeof LABELS)[number];
const bytes = (s: string) => new TextEncoder().encode(s);

type Op =
  | { kind: "append"; label: Label; advance: number }
  | { kind: "tick"; advance: number }
  | { kind: "search"; who: number; label: Label }
  | { kind: "monitor"; who: number; label: Label }
  | { kind: "fixed"; who: number; label: Label; version: number };

const label = fc.constantFrom(...LABELS);
const advance = fc.integer({ min: 0, max: 2 * RMW });
const who = fc.integer({ min: 0, max: 1 });
const op: fc.Arbitrary<Op> = fc.oneof(
  fc.record({ kind: fc.constant("append" as const), label, advance }),
  fc.record({ kind: fc.constant("tick" as const), advance }),
  fc.record({ kind: fc.constant("search" as const), who, label }),
  fc.record({ kind: fc.constant("monitor" as const), who, label }),
  fc.record({ kind: fc.constant("fixed" as const), who, label, version: fc.nat({ max: 6 }) }),
);

/** A user's persisted state: one shared checkpoint plus a contact per label. */
interface Store {
  checkpoint: State["checkpoint"];
  contacts: Map<string, NonNullable<State["contact"]>>;
}

const stateFor = (s: Store, l: string): State => ({ checkpoint: s.checkpoint, contact: s.contacts.get(l) });
function commit(s: Store, l: string, next: State): void {
  s.checkpoint = next.checkpoint;
  if (next.contact) s.contacts.set(l, next.contact);
}

/** Replays ops against an honest log, checking every answer against a model. */
async function replay(
  w: World,
  clients: Client[],
  stores: Store[],
  ops: readonly Op[],
  model = new Map<string, string[]>(),
): Promise<Map<string, string[]>> {
  for (const o of ops) {
    if (o.kind === "append" || o.kind === "tick") {
      w.clock.now += o.advance;
      if (o.kind === "tick") await w.log.tick();
      else {
        const versions = model.get(o.label) ?? [];
        const value = `${o.label}-${versions.length}`;
        await w.log.append({
          label: o.label,
          value: bytes(value),
          expectedVersion: versions.length ? versions.length - 1 : null,
        });
        model.set(o.label, [...versions, value]);
      }
      continue;
    }
    if (w.log.size === 0) continue;
    const store = stores[o.who % stores.length]!;
    const client = clients[o.who % clients.length]!;
    if (o.kind === "search") {
      const versions = model.get(o.label);
      const result = await client.search(o.label, stateFor(store, o.label)).catch((e) => e);
      if (!versions) {
        expect(isKTError(result, KTErrorCode.NotFound)).toBe(true);
        continue;
      }
      expect(result).not.toBeInstanceOf(Error);
      expect(new TextDecoder().decode(result.value)).toBe(versions.at(-1));
      expect(result.version).toBe(versions.length - 1);
      commit(store, o.label, result.state);
    } else if (o.kind === "fixed") {
      const versions = model.get(o.label);
      const result = await client.search(o.label, stateFor(store, o.label), { version: o.version }).catch((e) => e);
      if (!versions || o.version >= versions.length) {
        expect(isKTError(result, KTErrorCode.NotFound)).toBe(true);
        continue;
      }
      expect(result).not.toBeInstanceOf(Error);
      expect(new TextDecoder().decode(result.value)).toBe(versions[o.version]);
      commit(store, o.label, result.state);
    } else if (store.contacts.has(o.label)) {
      commit(store, o.label, (await client.monitor(o.label, stateFor(store, o.label))).state);
    }
  }
  return model;
}

async function setup(n: number, cipherSuite: CipherSuite) {
  const w = await world({ cipherSuite });
  const clients = await Promise.all(Array.from({ length: n }, (_, i) => w.client(`user-${i}`)));
  const stores: Store[] = clients.map((c) => ({ checkpoint: c.initialState().checkpoint, contacts: new Map() }));
  return { w, clients, stores };
}

const seeded = () => new Map([["alice", ["v0"]]]);
const history = fc.array(op, { minLength: 1, maxLength: 20 });
// FC_RUNS deepens the search on Node. Browsers and workerd have no process.
const runs = Number(globalThis.process?.env.FC_RUNS ?? 25);
const opts = { numRuns: runs, timeout: 60_000 };

describe.each(SUITE_NAMES)("protocol guarantees with %s", (_, cipherSuite) => {
  test.prop([history], opts)(
    "honest log: every search returns the latest value and monitoring verifies",
    async (ops) => {
      const { w, clients, stores } = await setup(2, cipherSuite);
      await replay(w, clients, stores, ops);
    },
  );

  test.prop([history, fc.nat(), fc.integer({ min: 0, max: 7 }), fc.constantFrom("flip", "truncate", "extend")], opts)(
    "any modified response is rejected and leaves state untouched",
    async (ops, at, bit, how) => {
      const { w, clients, stores } = await setup(1, cipherSuite);
      await w.log.append({ label: "alice", value: bytes("v0"), expectedVersion: null });
      await replay(w, clients, stores, ops, seeded());
      const store = stores[0]!;
      const before = structuredClone(stateFor(store, "alice"));
      const tamper = (r: Uint8Array): Uint8Array => {
        if (how === "truncate") return r.subarray(0, at % r.length);
        if (how === "extend") return new Uint8Array([...r, at & 0xff]);
        const copy = r.slice();
        copy[at % copy.length]! ^= 1 << bit;
        return copy;
      };
      const client = await w.client("user-0", tamper);
      const input = stateFor(store, "alice");
      const result = await client.search("alice", input).catch((e) => e);
      expect(isKTError(result, KTErrorCode.InvalidResponse)).toBe(true);
      expect(input).toEqual(before);
      if (input.contact?.monitoring.length) {
        const monitored = await client.monitor("alice", input).catch((e) => e);
        expect(isKTError(monitored, KTErrorCode.InvalidResponse)).toBe(true);
        expect(input).toEqual(before);
      }
    },
  );

  test.prop([history, history], opts)(
    "a log whose history diverges from the verified checkpoint is rejected (fork detection)",
    async (a, b) => {
      const honest = await setup(1, cipherSuite);
      await honest.w.log.append({ label: "alice", value: bytes("v0"), expectedVersion: null });
      await replay(honest.w, honest.clients, honest.stores, a, seeded());
      const fork = await world({ cipherSuite });
      fork.clock.now = honest.w.clock.now;
      await fork.log.append({ label: "alice", value: bytes("v0"), expectedVersion: null });
      for (let i = 1; i < honest.w.log.size + b.length; i++) await fork.log.tick();
      const client = await fork.client("user-0");
      const result = await client.search("alice", stateFor(honest.stores[0]!, "alice")).catch((e) => e);
      if (honest.stores[0]!.checkpoint === null) expect(result).not.toBeInstanceOf(Error);
      else expect(isKTError(result, KTErrorCode.InvalidResponse)).toBe(true);
    },
  );

  test.prop([fc.array(fc.integer({ min: 1, max: RMW - 1 }), { minLength: 1, maxLength: 4 })], opts)(
    "monitoring terminates when the log publishes at least once per RMW (Appendix D)",
    async (gaps) => {
      const { w, clients, stores } = await setup(1, cipherSuite);
      await w.log.append({ label: "alice", value: bytes("v0"), expectedVersion: null });
      for (const g of gaps) {
        w.clock.now += g;
        await w.log.tick();
      }
      await w.log.append({ label: "alice", value: bytes("v1"), expectedVersion: 0 });
      const store = stores[0]!;
      commit(store, "alice", (await clients[0]!.search("alice", stateFor(store, "alice"))).state);
      let rounds = 0;
      while (store.contacts.get("alice")!.monitoring.length) {
        expect(rounds++).toBeLessThan(64);
        for (const g of gaps) {
          w.clock.now += g;
          await w.log.tick();
        }
        commit(store, "alice", (await clients[0]!.monitor("alice", stateFor(store, "alice"))).state);
      }
    },
  );

  test.prop([fc.integer({ min: 1, max: RMW - 1 }), fc.integer({ min: 0, max: 5 }), fc.boolean()], opts)(
    "monitoring when due finishes within a few rounds and never hits an expired entry",
    async (gap, extra, research) => {
      const w = await world({ cipherSuite, maximumLifetime: 3 * RMW, maxAhead: 100 });
      const client = await w.client("user-0");
      const tick = async () => {
        w.clock.now += gap;
        await w.log.tick();
      };
      await w.log.append({ label: "alice", value: bytes("v0"), expectedVersion: null });
      for (let i = 0; i < extra; i++) await tick();
      w.clock.now += gap;
      await w.log.append({ label: "alice", value: bytes("v1"), expectedVersion: 0 });
      let state: State = (await client.search("alice", client.initialState())).state;
      for (let round = 0; state.contact!.monitoring.length; round++) {
        expect(round).toBeLessThan(4);
        const due = client.schedule(state)!;
        expect(due.before! - due.after).toBeGreaterThan(0);
        while (w.clock.now + gap < due.after) await tick();
        await tick();
        expect(w.clock.now).toBeLessThan(due.before!);
        // A search in between must not push the schedule past its deadline
        if (research) state = (await client.search("alice", state)).state;
        const again = client.schedule(state);
        if (again?.before !== undefined) expect(again.after).toBeLessThanOrEqual(again.before);
        state = (await client.monitor("alice", state)).state;
      }
      expect(client.schedule(state)).toBeUndefined();
    },
  );

  test.prop([fc.array(fc.integer({ min: 0, max: 3 * RMW }), { minLength: 1, maxLength: 12 }), fc.nat()], opts)(
    "fixed-version search with a maximum lifetime returns the right value or reports expiry",
    async (gaps, pick) => {
      const w = await world({ cipherSuite, maximumLifetime: 2 * RMW });
      const client = await w.client("user-0");
      const values: string[] = [];
      for (const [i, gap] of gaps.entries()) {
        w.clock.now += gap;
        if (i % 2) await w.log.tick();
        else {
          values.push(`v${values.length}`);
          await w.log.append({
            label: "alice",
            value: bytes(values.at(-1)!),
            expectedVersion: values.length - 2 < 0 ? null : values.length - 2,
          });
        }
      }
      const version = pick % values.length;
      const result = await client.search("alice", client.initialState(), { version }).catch((e) => e);
      if (isKTError(result, KTErrorCode.Expired)) return;
      expect(result).not.toBeInstanceOf(Error);
      expect(new TextDecoder().decode(result.value)).toBe(values[version]);
    },
  );

  test.prop([fc.array(fc.boolean(), { minLength: 2, maxLength: 12 })], opts)(
    "searches concurrent with publication see a consistent snapshot",
    async (schedule) => {
      const { w, clients, stores } = await setup(1, cipherSuite);
      await w.log.append({ label: "alice", value: bytes("alice-0"), expectedVersion: null });
      let expected = 0;
      const work = schedule.map((write) => {
        if (write) {
          const version = expected++;
          w.clock.now += 1;
          return w.log.append({ label: "alice", value: bytes(`alice-${version + 1}`), expectedVersion: version });
        }
        return clients[0]!.search("alice", stateFor(stores[0]!, "alice")).then((r) => {
          expect(new TextDecoder().decode(r.value)).toBe(`alice-${r.version}`);
          expect(r.state.checkpoint.treeSize).toBeGreaterThan(r.version);
        });
      });
      await Promise.all(work);
    },
  );

  test.prop([fc.integer({ min: 2, max: 8 })], opts)(
    "racing appends with the same expected version: one wins",
    async (n) => {
      const { w } = await setup(0, cipherSuite);
      await w.log.append({ label: "alice", value: bytes("v0"), expectedVersion: null });
      const results = await Promise.allSettled(
        Array.from({ length: n }, (_, i) =>
          w.log.append({ label: "alice", value: bytes(`v1-${i}`), expectedVersion: 0 }),
        ),
      );
      expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
      for (const r of results)
        if (r.status === "rejected") expect(isKTError(r.reason, KTErrorCode.Conflict)).toBe(true);
    },
  );

  test.prop([history], opts)("state survives a structured-clone round trip", async (ops) => {
    const { w, clients, stores } = await setup(1, cipherSuite);
    await w.log.append({ label: "alice", value: bytes("v0"), expectedVersion: null });
    await replay(w, clients, stores, ops, seeded());
    const restored = structuredClone(stateFor(stores[0]!, "alice"));
    const r = await clients[0]!.search("alice", restored);
    expect(r.state.contact.label).toEqual(bytes("alice"));
  });

  test.prop([fc.uint8Array({ maxLength: 512 })], opts)("arbitrary responses never crash the client", async (junk) => {
    const { w } = await setup(0, cipherSuite);
    await w.log.append({ label: "alice", value: bytes("v0"), expectedVersion: null });
    const client = await w.client("user-0", () => junk);
    const result = await client.search("alice", client.initialState()).catch((e) => e);
    expect(isKTError(result, KTErrorCode.InvalidResponse)).toBe(true);
  });
});
