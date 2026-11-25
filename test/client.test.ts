import { describe, expect, test } from "vitest";
import { type ContactState, KTErrorCode, isKTError } from "../src/index.ts";
import { decode } from "../src/tls.ts";
import { RMW, world } from "./harness.ts";

const text = (b: Uint8Array) => new TextDecoder().decode(b);
const bytes = (s: string) => new TextEncoder().encode(s);

describe("search and monitor against an honest log", () => {
  test("first lookup, then monitoring until a distinguished entry covers it", async () => {
    const w = await world();
    await w.log.append({ label: "alice", value: bytes("key-0"), expectedVersion: null });
    const client = await w.client("bob");

    const found = await client.search("alice");
    expect(text(found.value)).toBe("key-0");
    expect(found.version).toBe(0);
    expect(found.checkpoint.treeSize).toBe(1);

    w.clock.now += 10;
    await w.log.tick();
    w.clock.now += 10;
    await w.log.append({ label: "alice", value: bytes("key-1"), expectedVersion: 0 });
    const second = await client.search("alice", { checkpoint: found.checkpoint, contact: found.contact });
    expect(text(second.value)).toBe("key-1");
    expect(second.contact.monitoring.length).toBeGreaterThan(0);

    let state: ContactState = second;
    for (let i = 0; i < 12 && state.contact.monitoring.length; i++) {
      w.clock.now += RMW / 2;
      await w.log.tick();
      state = await client.monitor(state.contact, state);
    }
    expect(state.contact.monitoring).toEqual([]);
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
    const a = await client.search("alice");
    expect(a.contact.monitoring).toEqual([{ position: 4, version: 3 }]);
    await append("v4", 3);
    const b = await client.monitor(a.contact, a);
    expect(b.contact.monitoring).toEqual([{ position: 5, version: 3 }]);
    const c = await client.search("alice", { checkpoint: b.checkpoint, contact: b.contact });
    expect(c.version).toBe(4);
    expect(c.contact.monitoring).toEqual([{ position: 5, version: 4 }]);
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
    const a = await client.search("alice");
    expect(a.contact.monitoring).toEqual([{ position: 4, version: 3 }]);
    await append("v4", 3);
    const b = await client.search("alice", { checkpoint: a.checkpoint, contact: a.contact });
    expect(b.contact.monitoring).toEqual([{ position: 5, version: 4 }]);
    expect(b.contact.ladder.map((e) => e.version)).toEqual([0, 1, 3, 4]);
  });

  test("expired entries are pruned, so monitoring too late reports expiry", async () => {
    const w = await world({ maximumLifetime: 3 * RMW, maxAhead: 100 });
    await w.log.append({ label: "alice", value: bytes("v0"), expectedVersion: null });
    w.clock.now += 10;
    await w.log.tick();
    w.clock.now += 10;
    await w.log.append({ label: "alice", value: bytes("v1"), expectedVersion: 0 });
    const client = await w.client("bob");
    const found = await client.search("alice");
    expect(found.contact.monitoring.length).toBeGreaterThan(0);
    const due = client.schedule(found.contact, found)!;
    for (let i = 0; i < 12; i++) {
      w.clock.now += RMW / 2;
      await w.log.tick();
    }
    expect(w.clock.now).toBeGreaterThan(due.before!);
    const late = await client.monitor(found.contact, found).catch((e) => e);
    expect(isKTError(late, KTErrorCode.Expired)).toBe(true);
    // The value is still found, from unexpired entries
    expect(text((await client.search("alice", { checkpoint: found.checkpoint, contact: found.contact })).value)).toBe(
      "v1",
    );
  });

  test("monitoring survives revoked access, within the grant table's bound", async () => {
    let open = true;
    const w = await world({}, { authorize: () => open, limits: { maxGrants: 1 } });
    const history = async (label: string) => {
      await w.log.append({ label, value: bytes("v0"), expectedVersion: null });
      w.clock.now += 10;
      await w.log.tick();
      w.clock.now += 10;
      await w.log.append({ label, value: bytes("v1"), expectedVersion: 0 });
    };
    await history("alice");
    const client = await w.client("bob");
    const alice = await client.search("alice");
    await history("carol");
    expect(alice.contact.monitoring.length).toBeGreaterThan(0);
    open = false;
    await client.monitor(alice.contact, alice);
    // Finding another label evicts the only grant, so monitoring now needs authorization
    open = true;
    await client.search("carol", { checkpoint: alice.checkpoint });
    open = false;
    const denied = await client.monitor(alice.contact, alice).catch((e) => e);
    expect(isKTError(denied, KTErrorCode.Unauthorized)).toBe(true);
  });

  test("looking up an older version of a batch keeps monitoring the greatest", async () => {
    const w = await world();
    await w.log.tick();
    await w.log.tick();
    await w.log.append({ label: "alice", values: [bytes("a0"), bytes("a1"), bytes("a2")], expectedVersion: null });
    const client = await w.client("bob");
    const greatest = await client.search("alice");
    expect(greatest.contact.monitoring).toEqual([{ position: 2, version: 2 }]);
    const older = await client.search("alice", {
      checkpoint: greatest.checkpoint,
      contact: greatest.contact,
      version: 0,
    });
    expect(older.contact.monitoring).toEqual([{ position: 2, version: 2 }]);
  });

  test.skipIf(typeof globalThis.Buffer !== "function")("reused Node buffers do not change stored values", async () => {
    const w = await world();
    const value = Buffer.from("v0");
    await w.log.append({ label: Buffer.from("alice"), value, expectedVersion: null });
    value.fill(0);
    const client = await w.client("bob");
    expect(text((await client.search("alice")).value)).toBe("v0");
    const wire = Buffer.from([0, 2, 0x61, 0x62]);
    const decoded = decode(wire, (r) => r.opaque(2));
    wire.fill(0);
    expect(text(decoded)).toBe("ab");
  });

  test("reuses the advertised head when nothing changed", async () => {
    const w = await world();
    await w.log.append({ label: "alice", value: bytes("k"), expectedVersion: null });
    const client = await w.client("bob");
    const a = await client.search("alice");
    const b = await client.search("alice", { checkpoint: a.checkpoint, contact: a.contact });
    expect(b.checkpoint.treeSize).toBe(a.checkpoint.treeSize);
    expect(b.checkpoint.signature).toEqual(a.checkpoint.signature);
  });

  test("rejects stale heads", async () => {
    const w = await world();
    await w.log.append({ label: "alice", value: bytes("k"), expectedVersion: null });
    const client = await w.client("bob");
    w.clock.now += w.config.maxBehind + 1;
    const err = await client.search("alice").catch((e) => e);
    expect(isKTError(err, KTErrorCode.Stale)).toBe(true);
  });

  test("rejects state from another label", async () => {
    const w = await world();
    await w.log.append({ label: "alice", value: bytes("k"), expectedVersion: null });
    await w.log.append({ label: "carol", value: bytes("k"), expectedVersion: null });
    const client = await w.client("bob");
    const a = await client.search("alice");
    const err = await client.search("carol", { checkpoint: a.checkpoint, contact: a.contact }).catch((e) => e);
    expect(isKTError(err, KTErrorCode.InvalidState)).toBe(true);
  });

  test("cancellation surfaces the abort reason", async () => {
    const w = await world();
    await w.log.append({ label: "alice", value: bytes("k"), expectedVersion: null });
    const client = await w.client("bob");
    const controller = new AbortController();
    controller.abort();
    const err = await client.search("alice", { signal: controller.signal }).catch((e) => e);
    expect(err).toBe(controller.signal.reason);
  });
});
