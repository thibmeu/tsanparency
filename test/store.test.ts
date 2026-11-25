import { fc, test } from "@fast-check/vitest";
import { describe, expect } from "vitest";
import { type Store, type StoredEntry, memoryStore } from "../src/index.ts";
import { SUITE_NAMES, world } from "./harness.ts";

const bytes = (s: string) => new TextEncoder().encode(s);

describe.each(SUITE_NAMES)("durable store with %s", (_, cipherSuite) => {
  test.prop(
    [fc.array(fc.oneof(fc.constant("tick"), fc.constantFrom("alice", "bob")), { minLength: 1, maxLength: 10 })],
    {
      numRuns: 10,
    },
  )("a log reopened from its store answers byte for byte the same", async (ops) => {
    const store = memoryStore();
    const w = await world({ cipherSuite }, { store });
    const versions = new Map<string, number>();
    for (const op of ops) {
      w.clock.now += 10;
      if (op === "tick") await w.log.tick();
      else {
        const v = versions.get(op);
        versions.set(op, (v ?? -1) + 1);
        await w.log.append({ label: op, value: bytes(`${op}-${v}`), expectedVersion: v ?? null });
      }
    }
    const reopened = await world({ cipherSuite }, { store });
    expect(reopened.log.size).toBe(w.log.size);
    const client = await w.client("bob");
    for (const label of versions.keys()) {
      const found = await client.search(label, client.initialState());
      const request = new TextEncoder().encode(label);
      const ask = (log: typeof w.log) =>
        log.handle("search", new Uint8Array([0, request.length, ...request, 0]), { principal: "bob" });
      expect(await ask(reopened.log)).toEqual(await ask(w.log));
      // State verified against the first instance keeps verifying against the second
      const again = await (await reopened.client("bob")).search(label, found.state);
      expect(again.version).toBe(found.version);
    }
  });

  test("a second writer on the same store detects the first and catches up", async () => {
    const store = memoryStore();
    const a = await world({ cipherSuite }, { store });
    await a.log.append({ label: "alice", value: bytes("a0"), expectedVersion: null });
    const b = await world({ cipherSuite }, { store });
    await a.log.append({ label: "alice", value: bytes("a1"), expectedVersion: 0 });
    await expect(b.log.append({ label: "alice", value: bytes("b1"), expectedVersion: 0 })).rejects.toThrow();
    expect(b.log.size).toBe(2);
    await b.log.append({ label: "alice", value: bytes("b2"), expectedVersion: 1 });
    const found = await (await b.client("bob")).search("alice", (await b.client("bob")).initialState());
    expect(found.version).toBe(2);
  });

  test("refuses a store that does not match the configuration", async () => {
    const store = memoryStore();
    const w = await world({ cipherSuite }, { store });
    await w.log.append({ label: "alice", value: bytes("a0"), expectedVersion: null });
    const tampered: Store = {
      async *read(from) {
        for await (const e of store.read(from)) {
          const v = e.versions.map((x) => ({ ...x, value: bytes("forged") }));
          yield { ...e, versions: v } satisfies StoredEntry;
        }
      },
      append: (p, e) => store.append(p, e),
    };
    await expect(world({ cipherSuite }, { store: tampered })).rejects.toThrow();
    // The same entries under another configuration fail the tree head signature
    await expect(world({ cipherSuite, maxAhead: w.config.maxAhead + 1 }, { store })).rejects.toThrow();
  });

  test("catching up from a store with a forged entry breaks the log instead of serving it", async () => {
    const store = memoryStore();
    const a = await world({ cipherSuite }, { store });
    await a.log.append({ label: "alice", value: bytes("a0"), expectedVersion: null });
    const forger: Store = {
      read: (from) => store.read(from),
      async append(p, e) {
        await store.append(p, { ...e, signature: new Uint8Array(e.signature.length) });
        throw new Error("lost connection");
      },
    };
    const b = await world({ cipherSuite }, { store: forger });
    await expect(b.log.append({ label: "alice", value: bytes("b1"), expectedVersion: 0 })).rejects.toThrow();
    await expect(b.log.tick()).rejects.toThrow("valid log");
    const client = await b.client("bob");
    await expect(client.search("alice", client.initialState())).rejects.toThrow();
  });

  test("an append that stored before failing still succeeds", async () => {
    const store = memoryStore();
    const flaky: Store = {
      read: (from) => store.read(from),
      async append(p, e) {
        await store.append(p, e);
        throw new Error("timeout after commit");
      },
    };
    const w = await world({ cipherSuite }, { store: flaky });
    const { version, position } = await w.log.append({ label: "alice", value: bytes("a0"), expectedVersion: null });
    expect([version, position, w.log.size]).toEqual([0, 0, 1]);
    const client = await w.client("bob");
    expect((await client.search("alice", client.initialState())).version).toBe(0);
  });

  test("a truncated store is detected with the last known size", async () => {
    const store = memoryStore();
    const w = await world({ cipherSuite }, { store });
    await w.log.tick();
    await w.log.tick();
    const truncated: Store = {
      async *read(from) {
        let i = from;
        for await (const e of store.read(from)) if (i++ < 1) yield e;
      },
      append: (p, e) => store.append(p, e),
    };
    await expect(world({ cipherSuite }, { store: truncated, minimumSize: 2 })).rejects.toThrow("lost entries");
  });

  test("an in-flight read keeps its snapshot provable while newer entries prune", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let held = false;
    const w = await world(
      { cipherSuite, maximumLifetime: 3000, maxAhead: 100 },
      {
        authorize: async () => {
          if (!held) {
            held = true;
            await gate;
          }
          return true;
        },
      },
    );
    await w.log.append({ label: "alice", value: bytes("a0"), expectedVersion: null });
    w.clock.now += 1000;
    await w.log.append({ label: "alice", value: bytes("a1"), expectedVersion: 0 });
    const client = await w.client("bob");
    const pending = client.search("alice", client.initialState(), { version: 0 });
    for (let i = 0; i < 6; i++) {
      w.clock.now += 1000;
      await w.log.tick();
    }
    release();
    expect(new TextDecoder().decode((await pending).value)).toBe("a0");
  });
});
