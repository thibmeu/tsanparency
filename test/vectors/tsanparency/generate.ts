import { operations } from "./operations.ts";
import { primitives, type Emit } from "./primitives.ts";
import { readFileSync, writeFileSync } from "node:fs";
import { bytesToHex } from "@noble/curves/utils.js";
import { encodeUpdateRequest } from "../../../src/messages.ts";
import { logLeaf } from "../../../src/crypto.ts";
import { appendLeaf, rootFromFullSubtrees } from "../../../src/logtree.ts";

function save(file: string, data: unknown) {
  const path = new URL(file + ".json", import.meta.url);
  const bytes = JSON.stringify(data, null, 2) + "\n";
  if (process.argv.includes("--check")) {
    if (readFileSync(path, "utf8") !== bytes) throw Error(file + ".json differs from the generator");
  } else writeFileSync(path, bytes);
}

const timestamp = 1_800_000_000_000;
const root = new Uint8Array(32);
const leaves = [];
const cases = [];
let heads: Uint8Array[] = [];
for (let i = 0; i < 9; i++) {
  const time = timestamp + Math.floor(i / 2);
  const leaf = logLeaf(time, root);
  leaves.push(bytesToHex(leaf));
  heads = appendLeaf(i, heads, leaf);
  const size = i + 1;
  cases.push({
    name: `empty-prefix-ticks-size-${size}`,
    input: { entries: [{ prefix_tree: bytesToHex(root), timestamp: time }], leaves: [...leaves], size },
    expect: { full_subtrees: heads.map(bytesToHex), root: bytesToHex(rootFromFullSubtrees(size, heads)) },
  });
}

const generator = { impl: "tsanparency", sha: "b8563c2436202c456e5e8c792a8aac25124face2" };
const vectors = {
  primitive: "log-append",
  draft: "draft-ietf-keytrans-protocol-06 §3.2, §11.8",
  generator,
  cipher_suite: 2,
  notes:
    "Empty prefix tree across ticks. Consecutive entries can share a timestamp. Sizes 7, 8 and 9 cover the carry into a balanced subtree and the next append.",
  cases,
};
save("log-append", vectors);

const batches = [
  { name: "first-batch-255-empty-values", values: Array.from({ length: 255 }, () => new Uint8Array()) },
  { name: "value-crosses-4k-request-boundary", values: [new Uint8Array(4096).fill(0xa5)] },
];
const label = new Uint8Array([0x00, 0xff]);
const requests = {
  primitive: "requests",
  draft: "draft-ietf-keytrans-protocol-06 §13.5",
  generator,
  cipher_suite: 2,
  notes: "UpdateRequest boundaries for the element count and encoded message size.",
  cases: batches.map(({ name, values }) => ({
    name,
    input: { kind: "update-request", label: bytesToHex(label), last: 1, values: values.map(bytesToHex) },
    expect: { encoding: bytesToHex(encodeUpdateRequest({ label, last: 1, values })) },
  })),
};
save("requests", requests);

const emit: Emit = (file, section, notes, cases, suite) => {
  const data = {
    primitive: file.replace(/-p256$/, ""),
    draft: "draft-ietf-keytrans-protocol-06 " + section,
    generator:
      file === "auditor-update" || file.startsWith("tree-head")
        ? { ...generator, sha: "12f0195f16f41a41189e77494ca4c81e34cfa56c" }
        : generator,
    cipher_suite: suite,
    notes,
    cases,
  };
  save(file, data);
};
await primitives(emit);
await operations(emit);
