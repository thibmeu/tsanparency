/**
 * Heap retained per log entry, with and without a maximum lifetime, so pruning's
 * effect is visible. Node only, never shipped.
 *
 * Run: node --expose-gc bench/memory.ts
 */
import { CipherSuite, openLog, vrfPublicKey } from "../src/index.ts";

const gc = (globalThis as { gc?: () => void }).gc;
if (!gc) throw new Error("run with --expose-gc");
const ENTRIES = Number(process.env.ENTRIES ?? 3000);

for (const maximumLifetime of process.env.ML ? [Number(process.env.ML)] : [undefined]) {
  const signingKey = (await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])) as CryptoKeyPair;
  const vrfSecretKey = new Uint8Array(32).fill(3);
  let now = 1_700_000_000_000;
  const log = await openLog(
    {
      cipherSuite: CipherSuite.KT_128_SHA256_Ed25519,
      signaturePublicKey: new Uint8Array(await crypto.subtle.exportKey("raw", signingKey.publicKey)),
      vrfPublicKey: vrfPublicKey(CipherSuite.KT_128_SHA256_Ed25519, vrfSecretKey),
      maxAhead: 1e12,
      maxBehind: 1e12,
      reasonableMonitoringWindow: 10_000,
      ...(maximumLifetime && { maximumLifetime }),
    },
    { signingKey, vrfSecretKey, now: () => now },
  );
  const settle = async () => {
    for (let i = 0; i < 4; i++) {
      gc();
      await new Promise((r) => setTimeout(r, 0));
    }
    return process.memoryUsage().heapUsed;
  };
  const before = await settle();
  const versions = new Map<number, number>();
  for (let i = 0; i < ENTRIES; i++) {
    now += 1000;
    const label = i % 200;
    const v = versions.get(label);
    versions.set(label, (v ?? -1) + 1);
    await log.append({ label: `user-${label}`, value: new Uint8Array(32), expectedVersion: v ?? null });
  }
  const perEntry = ((await settle()) - before) / ENTRIES / 1024;
  console.log(
    `maximum lifetime ${maximumLifetime ?? "none"}: ${perEntry.toFixed(2)} KiB per entry (${log.size} entries)`,
  );
}
