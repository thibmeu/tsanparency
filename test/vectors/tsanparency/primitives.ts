import { bytesToHex as hex } from "@noble/curves/utils.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import {
  auditorTreeHeadTBS,
  commitment,
  encodeConfiguration,
  hash,
  logLeaf,
  treeHeadTBS,
  treeHeadVerifier,
  vrfInput,
} from "../../../src/crypto.ts";
import { searchLadder, baseLadder } from "../../../src/ladder.ts";
import { ancestors, frontier, root, left, right, hasLeft, hasRight } from "../../../src/ibst.ts";
import { isDistinguished, rightmostDistinguished, updateView } from "../../../src/combined.ts";
import { computeRoot, fullSubtrees } from "../../../src/logtree.ts";
import { encodeAuditorTreeHead, writeTreeHead, writePrefixProof } from "../../../src/messages.ts";
import { type Node, type PrefixProof, insert, prove, rootHash } from "../../../src/prefix.ts";
import { KT_128_SHA256_Ed25519, KT_128_SHA256_P256 } from "../../../src/index.ts";
import { Writer } from "../../../src/tls.ts";

export type Emit = (file: string, section: string, notes: string, cases: unknown[], suite?: number) => void;
export const seed = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
export const label = Uint8Array.of(0, 255);
export const timing = { maxAhead: 10, maxBehind: 100, reasonableMonitoringWindow: 50 };

export function prefix(pp: PrefixProof) {
  const w = new Writer();
  writePrefixProof(w, pp);
  return {
    encoding: hex(w.finish()),
    elements: pp.elements.map(hex),
    results: pp.results.map((r) => ({
      result_type: r.type,
      depth: r.depth,
      ...("leaf" in r ? { leaf: { vrf_output: hex(r.leaf.vrfOutput), commitment: hex(r.leaf.commitment) } } : {}),
    })),
  };
}

export async function primitives(emit: Emit) {
  const version = 0xffff_fffe;
  const alpha = vrfInput(label, version);
  const opening = seed.slice(0, 16);
  const value = Uint8Array.of(0xff, 0);
  const c = commitment(opening, label, version, value);
  const cv = new Writer().bytes(opening).opaque(1, label).u32(version).opaque(4, value).finish();
  emit(
    "commitment",
    "§11.6",
    "Binary label and value with a high unsigned version.",
    [
      {
        name: "binary-label-high-version",
        input: { label: hex(label), version, opening: hex(opening), update: { value: hex(value) } },
        expect: { commitment: hex(c), commitment_value: hex(cv) },
      },
    ],
    2,
  );
  const size = 5;
  const times = [0, 49, 50, 50, 100];
  const entries = times.map((timestamp, i) => ({ timestamp, prefix_tree: hex(hash(Uint8Array.of(i))) }));
  const leaves = times.map((t, i) => logLeaf(t, hash(Uint8Array.of(i))));
  function subtree(start: number, length: number) {
    const known = new Map(leaves.slice(start, start + length).map((leaf, i) => [i, leaf]));
    return computeRoot(length, known, undefined, () => {
      throw Error("missing leaf");
    }).root;
  }
  const elements: Uint8Array[] = [];
  const known = new Map([1, 4].map((i) => [i, leaves[i]!]));
  const retained = { size: 3, heads: fullSubtrees(3).map((r) => subtree(r.start, r.size)) };
  const tree = computeRoot(size, known, retained, (r) => {
    const h = subtree(r.start, r.size);
    elements.push(h);
    return h;
  });
  const wire = new Writer().count(2, elements.length);
  for (const h of elements) wire.bytes(h);
  emit("log-tree", "§12.1", "One batch proves a retained leaf and a new leaf after an unbalanced checkpoint.", [
    {
      name: "retained-three-to-five",
      input: { entries, requests: [{ proven_leaves: [1, 4], retained_size: 3 }] },
      expect: {
        root: hex(tree.root),
        full_subtrees: tree.full.map(hex),
        leaf_values: leaves.map(hex),
        proofs: [{ proof: hex(wire.finish()), elements: elements.map(hex) }],
      },
    },
  ]);
  for (const suite of [1, 2] as const) {
    const key = (suite === 1 ? KT_128_SHA256_P256.vrf : KT_128_SHA256_Ed25519.vrf).key(seed);
    const suffix = suite === 1 ? "-p256" : "";
    const { proof, output } = key.prove(alpha);
    const input = { private_key: hex(seed), public_key: hex(key.publicKey), label: hex(label), version };
    emit(
      "vrf" + suffix,
      "§11.7",
      "The same proof must fail for the adjacent version.",
      [
        {
          name: "binary-label-high-version",
          input,
          expect: { vrf_input: hex(alpha), proof: hex(proof), output: hex(output) },
        },
        {
          name: "wrong-version",
          input: { ...input, version: version + 1, proof: hex(proof) },
          expect: { error: true },
        },
      ],
      suite,
    );
    const pub = suite === 1 ? p256.getPublicKey(seed, false) : ed25519.getPublicKey(seed);
    const cfg = {
      ...timing,
      cipherSuite: suite === 1 ? KT_128_SHA256_P256 : KT_128_SHA256_Ed25519,
      signaturePublicKey: pub,
      vrfPublicKey: key.publicKey,
    };
    const signer = suite === 1 ? p256 : ed25519;
    const auditorSeed = Uint8Array.from(seed).reverse();
    const auditor = {
      publicKey: suite === 1 ? p256.getPublicKey(auditorSeed, false) : ed25519.getPublicKey(auditorSeed),
      startPosition: 2,
      maxLag: 50,
    };
    const cases = [];
    for (const authority of [undefined, auditor]) {
      const config = authority ? { ...cfg, auditor: authority } : cfg;
      const encoded = encodeConfiguration(config);
      const tbs = treeHeadTBS(encoded, size, tree.root);
      const signature = signer.sign(tbs, seed);
      if (!(await (await treeHeadVerifier(config))(size, tree.root, signature))) throw Error("bad signature");
      const timestamp = times[size - 1]!;
      const auditorTbs = auditorTreeHeadTBS(encoded, timestamp, size, tree.root);
      const signed = authority && { timestamp, treeSize: size, signature: signer.sign(auditorTbs, auditorSeed) };
      const full = new Writer();
      writeTreeHead(full, { treeSize: size, signature, auditor: signed });
      cases.push({
        name: authority ? "distinct-auditor-key-nonzero-start" : "signed-five-entry-root",
        input: {
          mode: authority ? 3 : 1,
          signature_public_key: hex(pub),
          vrf_public_key: hex(key.publicKey),
          max_ahead: cfg.maxAhead,
          max_behind: cfg.maxBehind,
          reasonable_monitoring_window: cfg.reasonableMonitoringWindow,
          tree_size: size,
          root: hex(tree.root),
          ...(authority && {
            auditor_public_key: hex(authority.publicKey),
            auditor_start_pos: authority.startPosition,
            max_auditor_lag: authority.maxLag,
            auditor_timestamp: timestamp,
          }),
        },
        expect: {
          configuration: hex(encoded),
          tree_head_tbs: hex(tbs),
          tree_head: hex(new Writer().u64(size).opaque(2, signature).finish()),
          signature: hex(signature),
          full_tree_head_same: "01",
          full_tree_head_updated: hex(full.finish()),
          ...(signed && {
            auditor_tree_head_tbs: hex(auditorTbs),
            auditor_tree_head: hex(encodeAuditorTreeHead(signed)),
          }),
        },
      });
    }
    emit(
      "tree-head" + suffix,
      "§11.2–11.4",
      "Operator and auditor sign the same five-entry root with distinct keys.",
      cases,
      suite,
    );
  }
  const keys = [0, 1, 128].map((v) => new Uint8Array(32).fill(v));
  const commits = keys.map(hash);
  const trie = keys.reduce<Node>((node, k, i) => insert(node, k, commits[i]!), null);
  const queries = [keys[1]!, new Uint8Array(32).fill(3), keys[2]!];
  const pp = prove(trie, queries);
  const proof = prefix(pp);
  emit("prefix-tree", "§12.2", "Membership and absence share a prefix in the same lookup.", [
    {
      name: "mixed-batch",
      input: {
        entries: keys.map((k, i) => ({ vrf_output: hex(k), commitment: hex(commits[i]!) })),
        searches: queries.map(hex),
      },
      expect: {
        root: hex(rootHash(trie)),
        proof: proof.encoding,
        results: proof.results,
        elements: proof.elements,
        commitments: [hex(commits[1]!), "", hex(commits[2]!)],
      },
    },
  ]);
  emit("binary-ladder", "§5", "Upper unsigned boundary with one missing version.", [
    {
      name: "penultimate-version",
      input: { kind: "base", greatest: version },
      expect: { versions: baseLadder(version) },
    },
  ]);
  emit("log-math", "§12.1", "Coordinates of the retained subtree heads.", [
    {
      name: "five-leaf-frontier",
      input: { kind: "full-subtrees", size },
      expect: { indices: fullSubtrees(size).map((r) => 2 * r.start + r.size - 1) },
    },
  ]);
  emit(
    "ladder-interpretation",
    "§6.2",
    "A search stops on either side of its target.",
    [1, 3].map((greatest) => {
      const target = 2,
        ladder: number[] = [],
        results: boolean[] = [];
      searchLadder(target, (v) => {
        ladder.push(v);
        results.push(v <= greatest);
        return v <= greatest;
      });
      return {
        name: "target-two-greatest-" + greatest,
        input: { target, greatest, ladder, results },
        expect: { verdict: Math.sign(greatest - target) },
      };
    }),
  );
  emit(
    "tampered",
    "§11.6",
    "A commitment binds the version.",
    [
      {
        name: "adjacent-version",
        input: {
          kind: "commitment",
          opening: hex(opening),
          label: hex(label),
          version: version + 1,
          update: { value: hex(value) },
          commitment: hex(c),
        },
        expect: { error: true, tamper: "Adjacent version with the original opening." },
      },
    ],
    2,
  );
  const added = queries[1]!,
    addedCommit = hash(added),
    insertion = prefix(prove(trie, [added]));
  const before = hex(rootHash(trie)),
    after = hex(rootHash(insert(trie, added, addedCommit)));
  emit("prefix-mutation", "§12.2", "Insertion at a shared prefix.", [
    {
      name: "insert-absent-key",
      input: {
        entries: keys.map((k, i) => ({ vrf_output: hex(k), commitment: hex(commits[i]!) })),
        add: [{ vrf_output: hex(added), commitment: hex(addedCommit) }],
        remove: [],
      },
      expect: {
        before,
        after,
        peer_before: before,
        peer_after: after,
        proof: insertion.encoding,
        results: insertion.results,
        elements: insertion.elements,
        leaves: [],
      },
    },
  ]);
  const nodes = Array.from({ length: size }, (_, index) => ({
    index,
    left: hasLeft(index) ? left(index) : null,
    right: hasRight(index, size) ? right(index, size) : null,
  }));
  emit("ibst", "§4.1", "Incomplete final subtree.", [
    { name: "five-entry-tree", input: { size }, expect: { root: root(size), frontier: frontier(size), nodes } },
  ]);
  const reads = new Set<number>();
  const ctx = {
    n: size,
    timestamp: (i: number) => {
      reads.add(i);
      return times[i]!;
    },
    ladder: () => {},
  };
  updateView(ctx, 3);
  emit("update-view", "§4.2", "Extend a three-entry checkpoint across a subtree boundary.", [
    { name: "three-to-five", input: { size, advertised: 3 }, expect: { entries: [...reads] } },
  ]);
  reads.clear();
  const last = rightmostDistinguished(ctx, 50);
  const requested_rightmost = [...reads];
  reads.clear();
  const previous = [...ancestors(size - 1, size)].reverse().find((i) => isDistinguished(ctx, 50, i));
  const requested_previous = [...reads];
  emit("distinguished", "§6.1", "Timestamps exactly one window apart.", [
    {
      name: "equal-window",
      input: { size, window: 50, timestamps: times },
      expect: {
        rightmost: last,
        previous_rightmost: previous,
        requested_rightmost,
        requested_previous,
        requested: [...new Set([...requested_previous, ...requested_rightmost])].sort((a, b) => a - b),
      },
    },
  ]);
}
