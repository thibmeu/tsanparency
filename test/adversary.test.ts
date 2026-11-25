/** Misbehaving logs built from the shared engine, which honest clients must catch */
import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, test } from "vitest";
import { Prover, type Snapshot, greatestVersionSearch, updateView } from "../src/combined.ts";
import { SUITES, commitment, encodeConfiguration, logLeaf, logParent, treeHeadTBS, vrfInput } from "../src/crypto.ts";
import { type Exchange, KTErrorCode, createClient } from "../src/index.ts";
import { type Range, fullSubtrees, rootFromFullSubtrees } from "../src/logtree.ts";
import { decodeSearchRequest, encodeSearchResponse } from "../src/messages.ts";
import { type Node, insert, rootHash } from "../src/prefix.ts";
import { decode } from "../src/tls.ts";
import { SUITE_NAMES, configuration } from "./harness.ts";

const enc = new TextEncoder();
const label = enc.encode("alice");

/**
 * A log whose entries the test writes directly. It signs whatever it holds and
 * answers greatest-version searches for version 0 of "alice".
 */
async function rogueLog(cipherSuite: (typeof SUITE_NAMES)[number][1]) {
  const suite = SUITES[cipherSuite];
  const pair = (await crypto.subtle.generateKey(suite.signature.import, false, ["sign", "verify"])) as CryptoKeyPair;
  const vrf = suite.vrf.key(new Uint8Array(32).fill(7));
  const config = await configuration({
    cipherSuite,
    signaturePublicKey: new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)),
    vrfPublicKey: vrf.publicKey,
  });
  const clock = { now: 1_700_000_000_000 };
  const entries: { timestamp: number; tree: Node; value?: { opening: Uint8Array; value: Uint8Array } }[] = [];
  const key0 = vrf.prove(vrfInput(label, 0));

  const push = (value?: string) => {
    clock.now += 10;
    const v =
      value === undefined
        ? undefined
        : { opening: sha256(enc.encode(value)).subarray(0, 16), value: enc.encode(value) };
    const tree = v ? insert(null, key0.output, commitment(v.opening, label, 0, v.value)) : null;
    entries.push({ timestamp: clock.now, tree, ...(v && { value: v }) });
  };
  const head = (r: Range): Uint8Array =>
    r.size === 1
      ? logLeaf(entries[r.start]!.timestamp, rootHash(entries[r.start]!.tree))
      : logParent(
          head({ start: r.start, size: r.size / 2 }),
          r.size === 2,
          head({ start: r.start + r.size / 2, size: r.size / 2 }),
          r.size === 2,
        );

  const exchange: Exchange = async (_, request) => {
    const n = entries.length;
    const req = decode(request, decodeSearchRequest);
    const snapshot: Snapshot = {
      size: n,
      timestamp: (x) => entries[x]!.timestamp,
      prefixTree: (x) => entries[x]!.tree,
      prefixRoot: (x) => rootHash(entries[x]!.tree),
      head,
    };
    const prover = new Prover(snapshot, req.last ?? 0, (v) => vrf.prove(vrfInput(label, v)).output);
    updateView(prover, req.last ?? 0);
    greatestVersionSearch(prover, config, 0);
    const root = rootFromFullSubtrees(n, fullSubtrees(n).map(head));
    const tbs = treeHeadTBS(encodeConfiguration(config), n, root);
    const signature = new Uint8Array(await crypto.subtle.sign(suite.signature.sign, pair.privateKey, tbs));
    const shown = entries[n - 1]!.value!;
    return encodeSearchResponse({
      treeHead: { treeSize: n, signature },
      version: 0,
      opening: shown.opening,
      value: shown.value,
      binaryLadder: [{ proof: key0.proof }, { proof: vrf.prove(vrfInput(label, 1)).proof }],
      search: prover.finish(),
    });
  };
  const client = await createClient(config, exchange, { now: () => clock.now });
  return { push, client };
}

describe.each(SUITE_NAMES)("misbehaving log with %s", (_, cipherSuite) => {
  test("swapping the commitment of a version already shown is equivocation", async () => {
    const { push, client } = await rogueLog(cipherSuite);
    push();
    push();
    push("FAKE-KEY");
    const first = await client.search("alice");
    expect(first.contact.monitoring).toEqual([{ position: 2, version: 0 }]);
    push("real-key");
    push("real-key");
    const err = await client.search("alice", { checkpoint: first.checkpoint, contact: first.contact }).catch((e) => e);
    expect(err?.code, String(err?.cause ?? err)).toBe(KTErrorCode.Equivocation);
  });
});
