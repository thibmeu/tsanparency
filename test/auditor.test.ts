import { fc, test } from "@fast-check/vitest";
import { bytesToHex, concatBytes, hexToBytes as hex } from "@noble/curves/utils.js";
import { describe, expect } from "vitest";
import { type AuditorState, audit, keyOf } from "../src/auditor.ts";
import { auditorTreeHeadVerifier, commitment, logLeaf, treeHeadVerifier } from "../src/crypto.ts";
import { frontier } from "../src/ibst.ts";
import { appendLeaf, rootFromFullSubtrees } from "../src/logtree.ts";
import { decodeAuditorTreeHead, decodeAuditorUpdate, encodeAuditorUpdate } from "../src/messages.ts";
import { type Node, insert, rootHash } from "../src/prefix.ts";
import { decode } from "../src/tls.ts";
import {
  type AuditedEntry,
  type Auditor,
  type ContactState,
  KTErrorCode,
  type StoredEntry,
  isKTError,
  memoryStore,
  openAuditor,
} from "../src/index.ts";
import { SUITE_NAMES, type World, world } from "./harness.ts";
import v_auditor from "./vectors/or13/auditor-update.json" with { type: "json" };
import v_mutation from "./vectors/or13/prefix-mutation.json" with { type: "json" };

const bytes = (s: string) => new TextEncoder().encode(s);
const readUpdate = (r: Parameters<typeof decodeAuditorUpdate>[0]) => decodeAuditorUpdate(r, 1024);
const leaf = (l: { vrf_output: string; commitment: string }) => ({
  vrfOutput: hex(l.vrf_output),
  commitment: hex(l.commitment),
});

interface VectorState {
  log_size: number;
  log_full_subtrees: string[];
  prefix_root: string;
  previous_timestamp: number;
  frontier_timestamps: number[];
  inserted?: { vrf_output: string; position: number }[];
}

/** Auditor state from a vector, where leaves of unknown origin were added in the first entry */
const stateOf = (i: VectorState): AuditorState => ({
  size: i.log_size,
  prefixRoot: hex(i.prefix_root),
  fullSubtrees: i.log_full_subtrees.map(hex),
  frontier: new Map(i.log_size ? frontier(i.log_size).map((x, j) => [x, i.frontier_timestamps[j]!]) : []),
  unseen: 0,
  positions: new Map((i.inserted ?? []).map((e) => [keyOf(hex(e.vrf_output)), e.position])),
});

describe("katie auditor updates (Section 15.2)", () => {
  test.each(v_auditor.cases)("$name", ({ name, input, expect: want }) => {
    const encoded = hex(want.encoding);
    const s = stateOf(input);
    const run = () => {
      const u = decode(encoded, readUpdate);
      expect(encodeAuditorUpdate(u)).toEqual(encoded);
      return { u, prefixRoot: audit(s, u, input.window) };
    };
    // katie rejects an update without changes, which a quiet log publishes on every tick
    if (name === "change-nothing") return expect(run().prefixRoot).toEqual(s.prefixRoot);
    if (want.verdict === "rejected") return expect(run).toThrow();
    const { u, prefixRoot } = run();
    const full = appendLeaf(s.size, s.fullSubtrees, logLeaf(u.timestamp, prefixRoot));
    expect(s.size + 1).toBe(want.tree_size);
    expect(bytesToHex(rootFromFullSubtrees(s.size + 1, full))).toBe(want.log_root);
  });

  test.each(v_mutation.cases)("mutation $name", ({ input, expect: want }) => {
    const update = {
      timestamp: 1_700_000_060_000,
      added: input.add.map(leaf),
      removed: input.remove.map(leaf),
      leaves: want.leaves.map(leaf),
      proof: { results: [], elements: [] },
    };
    // An empty proof encodes as its two vector lengths, which the vector's proof replaces
    const encoded = concatBytes(encodeAuditorUpdate(update).subarray(0, -8), hex(want.proof));
    const s = stateOf({
      log_size: 1,
      log_full_subtrees: [bytesToHex(logLeaf(1_700_000_000_000, hex(want.before)))],
      prefix_root: want.before,
      previous_timestamp: 1_700_000_000_000,
      frontier_timestamps: [1_700_000_000_000],
    });
    expect(bytesToHex(audit(s, decode(encoded, readUpdate), 1000))).toBe(want.peer_after);
  });
});

/** Log tree roots after each stored entry, rebuilt from the versions it added */
function roots(entries: readonly StoredEntry[]): Uint8Array[] {
  let tree: Node = null;
  let full: Uint8Array[] = [];
  return entries.map((e, n) => {
    for (const v of e.versions) tree = insert(tree, v.vrfOutput, commitment(v.opening, v.label, v.version, v.value));
    full = appendLeaf(n, full, logLeaf(e.timestamp, rootHash(tree)));
    return rootFromFullSubtrees(n + 1, full);
  });
}

describe.each(SUITE_NAMES)("auditor with %s", (_, cipherSuite) => {
  const setup = async (startPosition = 0) => {
    const pair = (await crypto.subtle.generateKey(cipherSuite.signature.import, false, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    const logStore = memoryStore();
    const w = await world({ cipherSuite, auditor: { publicKey, maxLag: 60_000, startPosition } }, { store: logStore });
    return { key: { pair }, logStore, w };
  };

  test.prop([fc.array(fc.constantFrom("tick", "alice", "bob", "batch"), { minLength: 1, maxLength: 12 }), fc.nat()], {
    numRuns: 10,
  })("signs the root the log signed, for every entry an honest log publishes from its start", async (ops, k) => {
    const at = k % ops.length;
    const { key, logStore, w } = await setup(at);
    const versions = new Map<string, number>();
    for (const op of ops) {
      w.clock.now += 400;
      if (op === "tick") await w.log.tick();
      else {
        const label = op === "batch" ? "carol" : op;
        const v = versions.get(label);
        const values = Array.from({ length: op === "batch" ? 3 : 1 }, (_, i) => bytes(`${label}-${v}-${i}`));
        versions.set(label, (v ?? -1) + values.length);
        await w.log.append({ label, values, expectedVersion: v ?? null });
      }
    }
    const stored: StoredEntry[] = [];
    for await (const e of logStore.read(0)) stored.push(e);
    const verifyLog = await treeHeadVerifier(w.config);
    const verifyAuditor = await auditorTreeHeadVerifier(w.config);
    const options = {
      signingKey: key.pair,
      store: memoryStore<AuditedEntry>(),
      start: at ? w.log.auditorStart(at) : undefined,
    };
    const auditor = await openAuditor(w.config, options);
    for (const [n, root] of roots(stored).entries()) {
      if (n < at) continue;
      await auditor.apply(n, w.log.auditorUpdate(n));
      const head = decode(await auditor.head(), decodeAuditorTreeHead);
      expect(head).toMatchObject({ timestamp: stored[n]!.timestamp, treeSize: n + 1 });
      expect(await verifyLog(n + 1, root, stored[n]!.signature)).toBe(true);
      expect(await verifyAuditor(head.timestamp, n + 1, root, head.signature)).toBe(true);
    }
    expect((await openAuditor(w.config, options)).size).toBe(stored.length);
  });

  test("keeps its head across restarts, retries and rejected updates", async () => {
    const { key, w } = await setup();
    for (const label of ["alice", "bob", "carol"]) {
      w.clock.now += 400;
      await w.log.append({ label, value: bytes(label), expectedVersion: null });
    }
    const store = memoryStore<AuditedEntry>();
    const first = await openAuditor(w.config, { signingKey: key.pair, store });
    await expect(first.head()).rejects.toMatchObject({ code: KTErrorCode.NotFound });
    await first.apply(0, w.log.auditorUpdate(0));
    await first.apply(1, w.log.auditorUpdate(1));
    const head = await first.head();
    // ECDSA signatures are randomized, so equal bytes mean one signature per size
    expect(await first.head()).toEqual(head);
    (await first.head()).fill(0);
    expect(await first.head()).toEqual(head);
    const start = w.log.auditorStart(2);
    start.prefixRoot.fill(0);
    start.fullSubtrees[0]!.fill(0);
    const again = w.log.auditorStart(2);
    expect(again.prefixRoot).not.toEqual(start.prefixRoot);
    expect(again.fullSubtrees[0]).not.toEqual(start.fullSubtrees[0]);

    // A store verified under one window cannot be signed under another
    const other = { ...w.config, reasonableMonitoringWindow: w.config.reasonableMonitoringWindow + 1 };
    await expect(openAuditor(other, { signingKey: key.pair, store })).rejects.toThrow();
    const auditor = await openAuditor(w.config, { signingKey: key.pair, store });
    expect(auditor.size).toBe(2);
    await auditor.apply(1, w.log.auditorUpdate(1));
    const reopened = decode(await auditor.head(), decodeAuditorTreeHead);
    expect(reopened).toMatchObject({ ...decode(head, decodeAuditorTreeHead), signature: reopened.signature });
    await expect(auditor.apply(0, w.log.auditorUpdate(0))).rejects.toMatchObject({ code: KTErrorCode.Conflict });
    await expect(auditor.apply(1, w.log.auditorUpdate(2))).rejects.toMatchObject({ code: KTErrorCode.Conflict });
    await expect(auditor.apply(3, w.log.auditorUpdate(2))).rejects.toMatchObject({ code: KTErrorCode.Conflict });

    // Adding bob's leaf again, with the proof for carol's, fails verification
    const carol = decode(w.log.auditorUpdate(2), readUpdate);
    const wrong = encodeAuditorUpdate({ ...carol, added: decode(w.log.auditorUpdate(1), readUpdate).added });
    await expect(auditor.apply(2, wrong)).rejects.toMatchObject({ code: KTErrorCode.InvalidRequest });
    expect(auditor.size).toBe(2);
    await auditor.apply(2, w.log.auditorUpdate(2));
    expect(auditor.size).toBe(3);

    const bounded = await openAuditor(w.config, { signingKey: key.pair, maxLeaves: 0 });
    await expect(bounded.apply(0, w.log.auditorUpdate(0))).rejects.toMatchObject({ code: KTErrorCode.InvalidRequest });
    const behind = await openAuditor(w.config, {
      signingKey: key.pair,
      now: () => w.clock.now - w.config.maxAhead - 2000,
    });
    await expect(behind.apply(0, w.log.auditorUpdate(0))).rejects.toMatchObject({ code: KTErrorCode.InvalidRequest });
  });

  /** Brings the auditor to `size` entries and gives the log its head */
  async function audit(w: World, auditor: Auditor, size: number) {
    for (let n = auditor.size; n < size; n++) await auditor.apply(n, w.log.auditorUpdate(n));
    await w.log.acceptAuditorHead(await auditor.head());
  }

  test.prop([fc.array(fc.tuple(fc.constantFrom("tick", "alice", "bob"), fc.nat(3)), { minLength: 1, maxLength: 10 })], {
    numRuns: 10,
  })("clients verify search and monitoring through an auditor that lags", async (ops) => {
    const { key, w } = await setup();
    const auditor = await openAuditor(w.config, { signingKey: key.pair });
    const client = await w.client("bob");
    const versions = new Map<string, number>();
    let state: ContactState | undefined;
    for (const [op, lag] of ops) {
      w.clock.now += 400;
      if (op === "tick") await w.log.tick();
      else {
        const v = versions.get(op);
        versions.set(op, (v ?? -1) + 1);
        await w.log.append({ label: op, value: bytes(`${op}-${v}`), expectedVersion: v ?? null });
      }
      await audit(w, auditor, Math.max(1, w.log.size - lag));
      const found = await client.search(op === "tick" ? "alice" : op, { checkpoint: state?.checkpoint }).catch((e) => {
        if (!isKTError(e, KTErrorCode.NotFound)) throw e;
      });
      if (!found) continue;
      expect(found.checkpoint.auditor!.treeSize).toBe(auditor.size);
      state = await client.monitor(found.contact, { checkpoint: found.checkpoint });
    }
  });

  test.prop([fc.nat(18 + 63), fc.integer({ min: 1, max: 255 })], { numRuns: 30 })(
    "any change to the auditor tree head of a response is rejected",
    async (offset, flip) => {
      const { key, w } = await setup();
      await w.log.append({ label: "alice", value: bytes("a"), expectedVersion: null });
      await audit(w, await openAuditor(w.config, { signingKey: key.pair }), 1);
      // FullTreeHead: head type, tree size, signature length, 64-byte signature, then AuditorTreeHead
      const client = await w.client("bob", (r) => {
        const out = r.slice();
        out[1 + 8 + 2 + 64 + offset]! ^= flip;
        return out;
      });
      await expect(client.search("alice")).rejects.toMatchObject({ code: KTErrorCode.InvalidResponse });
    },
  );

  test("the log serves only verified auditor heads, and clients only fresh ones", async () => {
    const { key, w } = await setup();
    await w.log.append({ label: "alice", value: bytes("a"), expectedVersion: null });
    const client = await w.client("bob");
    await expect(client.search("alice")).rejects.toMatchObject({ code: KTErrorCode.NotFound });
    const auditor = await openAuditor(w.config, { signingKey: key.pair });
    await auditor.apply(0, w.log.auditorUpdate(0));
    const head = await auditor.head();
    const forged = head.slice();
    forged[forged.length - 1]! ^= 1;
    await expect(w.log.acceptAuditorHead(forged)).rejects.toMatchObject({ code: KTErrorCode.InvalidRequest });
    await w.log.acceptAuditorHead(head);
    const first = await client.search("alice");

    // The log keeps publishing while the auditor stops, until clients refuse the gap
    for (let t = 0; t <= w.config.auditor!.maxLag; t += 30_000) {
      w.clock.now += 30_000;
      await w.log.tick();
    }
    await expect(client.search("alice", first)).rejects.toMatchObject({ code: KTErrorCode.Stale });
    await audit(w, auditor, w.log.size);
    expect((await client.search("alice", first)).checkpoint.auditor!.treeSize).toBe(w.log.size);
  });
});
