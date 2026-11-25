import { describe, expect, test } from "vitest";
import { KTErrorCode, isKTError } from "../src/index.ts";
import { RMW, world } from "./harness.ts";

const text = (b: Uint8Array) => new TextDecoder().decode(b);
const bytes = (s: string) => new TextEncoder().encode(s);

describe("search and monitor against an honest log", () => {
  test("first lookup, then monitoring until a distinguished entry covers it", async () => {
    const w = await world();
    await w.log.append({ label: "alice", value: bytes("key-0"), expectedVersion: null });
    const client = await w.client("bob");

    const found = await client.search("alice", client.initialState());
    expect(text(found.value)).toBe("key-0");
    expect(found.version).toBe(0);
    expect(found.state.checkpoint.treeSize).toBe(1);

    w.clock.now += 10;
    await w.log.tick();
    w.clock.now += 10;
    await w.log.append({ label: "alice", value: bytes("key-1"), expectedVersion: 0 });
    const second = await client.search("alice", found.state);
    expect(text(second.value)).toBe("key-1");
    expect(second.state.contact.monitoring.length).toBeGreaterThan(0);

    let state = second.state as Parameters<typeof client.monitor>[1];
    for (let i = 0; i < 12 && state.contact!.monitoring.length; i++) {
      w.clock.now += RMW / 2;
      await w.log.tick();
      state = (await client.monitor("alice", state)).state;
    }
    expect(state.contact!.monitoring).toEqual([]);
  });

  test("a newer version terminating where an older one is monitored replaces it", async () => {
    const w = await world();
    const append = async (value: string, expectedVersion: number | null) => {
      w.clock.now += 10;
      await w.log.append({ label: "alice", value: bytes(value), expectedVersion });
    };
    for (let v = 0; v < 3; v++) await append(`v${v}`, v ? v - 1 : null);
    w.clock.now += 10;
    await w.log.tick();
    await append("v3", 2);
    const client = await w.client("bob");
    const a = await client.search("alice", client.initialState());
    expect(a.state.contact.monitoring).toEqual([{ position: 4, version: 3 }]);
    await append("v4", 3);
    const b = await client.monitor("alice", a.state);
    expect(b.state.contact!.monitoring).toEqual([{ position: 5, version: 3 }]);
    const c = await client.search("alice", b.state);
    expect(c.version).toBe(4);
    expect(c.state.contact.monitoring).toEqual([{ position: 5, version: 4 }]);
  });

  test("an entry covered by a greater version at its nearest right ancestor is dropped", async () => {
    const w = await world();
    const append = async (value: string, expectedVersion: number | null) => {
      w.clock.now += 10;
      await w.log.append({ label: "alice", value: bytes(value), expectedVersion });
    };
    for (let v = 0; v < 3; v++) await append(`v${v}`, v ? v - 1 : null);
    w.clock.now += 10;
    await w.log.tick();
    await append("v3", 2);
    const client = await w.client("bob");
    const a = await client.search("alice", client.initialState());
    expect(a.state.contact.monitoring).toEqual([{ position: 4, version: 3 }]);
    await append("v4", 3);
    const b = await client.search("alice", a.state);
    expect(b.state.contact.monitoring).toEqual([{ position: 5, version: 4 }]);
    expect(b.state.contact.ladder.map((e) => e.version)).toEqual([0, 1, 3, 4]);
  });

  test("expired entries are pruned, so monitoring too late reports expiry", async () => {
    const w = await world({ maximumLifetime: 3 * RMW, maxAhead: 100 });
    await w.log.append({ label: "alice", value: bytes("v0"), expectedVersion: null });
    w.clock.now += 10;
    await w.log.tick();
    w.clock.now += 10;
    await w.log.append({ label: "alice", value: bytes("v1"), expectedVersion: 0 });
    const client = await w.client("bob");
    const found = await client.search("alice", client.initialState());
    expect(found.state.contact.monitoring.length).toBeGreaterThan(0);
    const due = client.schedule(found.state)!;
    for (let i = 0; i < 12; i++) {
      w.clock.now += RMW / 2;
      await w.log.tick();
    }
    expect(w.clock.now).toBeGreaterThan(due.before!);
    const late = await client.monitor("alice", found.state).catch((e) => e);
    expect(isKTError(late, KTErrorCode.Expired)).toBe(true);
    // The value is still found, from unexpired entries
    expect(text((await client.search("alice", found.state)).value)).toBe("v1");
  });

  test("reuses the advertised head when nothing changed", async () => {
    const w = await world();
    await w.log.append({ label: "alice", value: bytes("k"), expectedVersion: null });
    const client = await w.client("bob");
    const a = await client.search("alice", client.initialState());
    const b = await client.search("alice", a.state);
    expect(b.state.checkpoint.treeSize).toBe(a.state.checkpoint.treeSize);
    expect(b.state.checkpoint.signature).toEqual(a.state.checkpoint.signature);
  });

  test("rejects stale heads", async () => {
    const w = await world();
    await w.log.append({ label: "alice", value: bytes("k"), expectedVersion: null });
    const client = await w.client("bob");
    w.clock.now += w.config.maxBehind + 1;
    const err = await client.search("alice", client.initialState()).catch((e) => e);
    expect(isKTError(err, KTErrorCode.Stale)).toBe(true);
  });

  test("rejects state from another label", async () => {
    const w = await world();
    await w.log.append({ label: "alice", value: bytes("k"), expectedVersion: null });
    await w.log.append({ label: "carol", value: bytes("k"), expectedVersion: null });
    const client = await w.client("bob");
    const a = await client.search("alice", client.initialState());
    const err = await client.search("carol", a.state).catch((e) => e);
    expect(isKTError(err, KTErrorCode.InvalidState)).toBe(true);
  });

  test("cancellation surfaces the abort reason", async () => {
    const w = await world();
    await w.log.append({ label: "alice", value: bytes("k"), expectedVersion: null });
    const client = await w.client("bob");
    const controller = new AbortController();
    controller.abort();
    const err = await client.search("alice", client.initialState(), { signal: controller.signal }).catch((e) => e);
    expect(err).toBe(controller.signal.reason);
  });
});
