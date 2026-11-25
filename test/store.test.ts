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
});
