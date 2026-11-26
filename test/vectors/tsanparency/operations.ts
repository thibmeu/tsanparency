import assert from "node:assert/strict";
import { mock } from "node:test";
import { bytesToHex as hex, hexToBytes } from "@noble/curves/utils.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  KTErrorCode,
  Operation,
  openAuditor,
  rootFromFullSubtrees,
  createClient,
  memoryStore,
  openLog,
} from "../../../src/index.ts";
import { auditorTreeHeadVerifier, commitment } from "../../../src/crypto.ts";
import * as m from "../../../src/messages.ts";

import { decode, Writer } from "../../../src/tls.ts";
import { prefix, label, seed, timing, type Emit } from "./primitives.ts";
import { KT_128_SHA256_Ed25519 } from "../../../src/index.ts";

const ladder = (steps: readonly m.BinaryLadderStep[]) =>
  steps.map((s) => ({ proof: hex(s.proof), commitment: s.commitment && hex(s.commitment) }));
const combined = (p: m.CombinedTreeProof) => ({
  timestamps: p.timestamps,
  prefix_proofs: p.prefixProofs.map(prefix),
  prefix_roots: p.prefixRoots.map(hex),
  inclusion: p.inclusion.map(hex),
});
function head(h: m.TreeHead | undefined) {
  const w = new Writer();
  m.writeTreeHead(w, h);
  return hex(w.finish());
}

export async function operations(emit: Emit) {
  let time = 100;
  const now = () => time;
  const raw = ed25519.getPublicKey(seed);
  const pkcs8 = Uint8Array.from([...hexToBytes("302e020100300506032b657004220420"), ...seed]);
  const signingKey = {
    publicKey: await crypto.subtle.importKey("raw", Uint8Array.from(raw), "Ed25519", true, ["verify"]),
    privateKey: await crypto.subtle.importKey("pkcs8", pkcs8, "Ed25519", false, ["sign"]),
  };
  const vrf = KT_128_SHA256_Ed25519.vrf.key(seed);
  const config = {
    ...timing,
    cipherSuite: KT_128_SHA256_Ed25519,
    signaturePublicKey: raw,
    vrfPublicKey: vrf.publicKey,
  };
  const store = memoryStore();
  const log = await openLog(config, { now, store, signingKey, vrfSecretKey: seed, authorize: () => true });
  const handle = (op: Operation, req: Uint8Array) => log.handle(op, req, { principal: "owner" });
  let lastBytes: Uint8Array = new Uint8Array();
  const client = await createClient(config, async (op, req) => (lastBytes = await handle(op, req)), { now });
  const searches = [],
    monitors = [],
    updates = [];
  const common = async () => {
    const mutations = [],
      entry_timestamps = [];
    for await (const entry of store.read(0)) {
      mutations.push({ add: entry.versions.map((v) => ({ label: hex(v.label), value: hex(v.value) })) });
      entry_timestamps.push(entry.timestamp);
    }
    return {
      mode: 1,
      label: hex(label),
      signature_public_key: hex(raw),
      vrf_public_key: hex(vrf.publicKey),
      monitoring_window: 50,
      mutations,
      entry_timestamps,
    };
  };
  const known = async () => {
    const all = [];
    for await (const e of store.read(0))
      for (const v of e.versions)
        all.push({
          version: v.version,
          vrf_output: hex(v.vrfOutput),
          commitment: hex(commitment(v.opening, label, v.version, v.value)),
        });
    return all;
  };
  // Only this generator process uses repeatable commitment openings.
  let counter = 0;
  const random = mock.method(crypto, "getRandomValues", (buffer: Uint8Array) => buffer.fill(++counter));
  try {
    await log.append({ label, value: Uint8Array.of(1), expectedVersion: null });
    const initial = await client.ownerInit(label, { start: 0 });
    const init = decode(lastBytes, (r) => m.decodeOwnerInitResponse(r, false, 80));
    monitors.push({
      name: "owner-starts-at-version-zero",
      input: {
        ...(await common()),
        operation: "owner-init",
        entries: [],
        start: 0,
        known_versions: [],
        maximum_lifetime: 0,
      },
      expect: {
        tree_size: 1,
        response: hex(lastBytes),
        full_tree_head: head(init.treeHead),
        greatest_versions: init.greatestVersions,
        binary_ladder: ladder(init.binaryLadder),
        ...combined(init.init),
      },
    });
    time++;
    for (const [name, values] of [
      ["created", [Uint8Array.of(2)]],
      ["catch-up", []],
    ] as const) {
      const result = await client.update(initial.owner, values, initial);
      if (result.disregarded !== (name === "catch-up")) throw Error("unexpected update branch");
      const res = decode(lastBytes, (r) => m.decodeUpdateResponse(r, false, 80));
      const proof = new Writer();
      m.writeCombined(proof, res.update);
      const keys = new Map(
        initial.owner.versions.map((v) => [
          v.version,
          { version: v.version, vrf_output: hex(v.vrfOutput), commitment: v.commitment && hex(v.commitment) },
        ]),
      );
      for (const v of result.owner.versions)
        keys.set(v.version, {
          version: v.version,
          vrf_output: hex(v.vrfOutput),
          commitment: v.commitment && hex(v.commitment),
        });
      updates.push({
        name,
        input: {
          ...(await common()),
          tree_size: log.size,
          position: res.position,
          versions: 1,
          owner: { starting: 0, version_at_starting: 0, upcoming: [] },
          last: 1,
          ladder: [...keys.values()],
          note: name,
        },
        expect: {
          ...combined(res.update),
          proof: hex(proof.finish()),
          distinguished: result.pending,
          ...(!result.pending ? { contact: { position: res.position, version: 1 } } : {}),
          envelope: {
            encoding: hex(lastBytes),
            values: res.values.map(hex),
            openings: res.openings.map(hex),
            full_tree_head: head(res.treeHead),
            binary_ladder: ladder(res.binaryLadder),
          },
        },
      });
    }
    time++;
    await log.append({ label, value: Uint8Array.of(3), expectedVersion: 1 });
    for (const version of [undefined, 0]) {
      await client.search(label, { version });
      const res = decode(lastBytes, (r) => m.decodeSearchResponse(r, false, 80, version));
      searches.push({
        name: version === undefined ? "latest" : "historical",
        input: { ...(await common()), version, max_ahead: 10, max_behind: 100, maximum_lifetime: 0 },
        expect: {
          tree_size: log.size,
          response: hex(lastBytes),
          full_tree_head: head(res.treeHead),
          opening: hex(res.opening),
          version: version === undefined ? res.version : undefined,
          binary_ladder: ladder(res.binaryLadder),
          ...combined(res.search),
        },
      });
    }
    const entries = [{ position: 2, version: 2 }];
    time += 50;
    await log.tick();
    for (const operation of ["contact", "owner-monitor"]) {
      const request = { label, entries, start: 0, greatestVersion: 2 };
      const bytes =
        operation === "contact"
          ? await handle(Operation.ContactMonitor, m.encodeContactMonitorRequest(request))
          : await handle(Operation.OwnerMonitor, m.encodeOwnerMonitorRequest(request));
      const res = decode(bytes, (r) =>
        (operation === "contact" ? m.decodeContactMonitorResponse : m.decodeOwnerMonitorResponse)(r, false),
      );
      const versions = await known();
      const absent = vrf.prove(new Writer().opaque(1, label).u32(3).finish());
      monitors.push({
        name: operation + "-after-tick",
        input: {
          ...(await common()),
          operation,
          entries,
          start: 0,
          greatest_version: 2,
          known_versions: [...versions, { version: 3, vrf_output: hex(absent.output) }],
          maximum_lifetime: 0,
        },
        expect: {
          tree_size: log.size,
          response: hex(bytes),
          full_tree_head: head(res.treeHead),
          ...combined(res.monitor),
        },
      });
    }
    const auditConfig = { ...config, auditor: { publicKey: raw, maxLag: 100, startPosition: 0 } };
    const auditor = await openAuditor(auditConfig, { signingKey, now });
    const verify = await auditorTreeHeadVerifier(auditConfig);
    const auditCases = [];
    const prefixEntries: { vrf_output: string; commitment: string }[] = [];
    const inserted: { vrf_output: string; position: number }[] = [];
    for (const position of [0, 1]) {
      const bytes = log.auditorUpdate(position);
      const update = decode(bytes, (r) => m.decodeAuditorUpdate(r, 1024));
      const added = update.added.map((l) => ({ vrf_output: hex(l.vrfOutput), commitment: hex(l.commitment) }));
      const start = position ? log.auditorStart(position) : undefined;
      const input = {
        entries: [...prefixEntries],
        inserted: [...inserted],
        first_entry: position === 0,
        log_size: position,
        window: config.reasonableMonitoringWindow,
        previous_timestamp: start?.frontier.at(-1) ?? 0,
        prefix_root: hex(start?.prefixRoot ?? new Uint8Array(32)),
        log_full_subtrees: start?.fullSubtrees.map(hex) ?? [],
        frontier_timestamps: start?.frontier ?? [],
        timestamp: update.timestamp,
        added,
        removed: [],
      };
      if (position) {
        const timestamp = input.previous_timestamp - 1;
        const earlier = m.encodeAuditorUpdate({ ...update, timestamp });
        await assert.rejects(auditor.apply(position, earlier), { code: KTErrorCode.InvalidRequest });
        auditCases.push({
          name: "retained-head-rejects-earlier-update",
          input: { ...input, timestamp },
          expect: { encoding: hex(earlier), verdict: "rejected" },
        });
      }
      await auditor.apply(position, bytes);
      const signed = decode(await auditor.head(), m.decodeAuditorTreeHead);
      const root = rootFromFullSubtrees(position + 1, log.auditorStart(position + 1).fullSubtrees);
      assert.equal(signed.treeSize, position + 1);
      assert.ok(await verify(signed.timestamp, signed.treeSize, root, signed.signature));
      auditCases.push({
        name: position ? "extend-retained-head" : "first-signed-head",
        input,
        expect: { encoding: hex(bytes), verdict: "accepted", tree_size: signed.treeSize, log_root: hex(root) },
      });
      prefixEntries.push(...added);
      inserted.push(...added.map((l) => ({ vrf_output: l.vrf_output, position })));
    }
    emit(
      "auditor-update",
      "§15.2",
      "Initial and retained heads, including timestamp ordering. Each accepted root was verified against the TypeScript auditor signature.",
      auditCases,
      2,
    );
  } finally {
    random.mock.restore();
  }
  emit("search", "§13.1", "Greatest and fixed searches of the same three-version label.", searches, 2);
  emit(
    "monitor",
    "§13.2–§13.4",
    "Initialize at version zero, then monitor after a tick crosses the window.",
    monitors,
    2,
  );
  emit(
    "update",
    "§9.1, §13.5",
    "One owner creates a version. Another at the same checkpoint learns its value. Both envelopes include the complete proof.",
    updates,
    2,
  );
}
