/**
 * Minified and gzipped size of each entry point as an application imports it,
 * failing when a bundle keeps a curve it does not use. Never shipped.
 *
 * Run: npm run size
 */
import { gzipSync } from "node:zlib";
import { build } from "esbuild";

const entries: [name: string, imports: string, curves: ("weierstrass" | "edwards")[]][] = [
  ["appendLeaf", "appendLeaf", []],
  ["P-256 client", "createClient, KT_128_SHA256_P256", ["weierstrass"]],
  ["Ed25519 client", "createClient, KT_128_SHA256_Ed25519", ["edwards"]],
  ["Ed25519 log", "openLog, KT_128_SHA256_Ed25519", ["edwards"]],
  ["Ed25519 auditor", "openAuditor, KT_128_SHA256_Ed25519", ["edwards"]],
];

let failed = false;
for (const [name, imports, curves] of entries) {
  const { outputFiles, metafile } = await build({
    stdin: { contents: `export { ${imports} } from "./src/index.ts";`, resolveDir: process.cwd(), loader: "ts" },
    bundle: true,
    minify: true,
    format: "esm",
    platform: "neutral",
    write: false,
    metafile: true,
  });
  const out = outputFiles[0]!.contents;
  const inputs = Object.entries(Object.values(metafile.outputs)[0]!.inputs);
  const kept = (["weierstrass", "edwards"] as const).filter((c) =>
    inputs.some(([path, { bytesInOutput }]) => path.includes(`abstract/${c}`) && bytesInOutput > 0),
  );
  const extra = kept.filter((c) => !curves.includes(c));
  failed ||= extra.length > 0;
  const note = extra.length ? `  unexpected ${extra.join(", ")}` : "";
  console.log(
    `${name.padEnd(16)} ${String(out.length).padStart(7)} B  ${String(gzipSync(out).length).padStart(6)} B gzip${note}`,
  );
}
if (failed) process.exit(1);
