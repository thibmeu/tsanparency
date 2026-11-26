/**
 * The measurements of the cross-implementation comparison: VRF prove and verify,
 * append, and a first-contact greatest-version search split between log and
 * client, over 1000 entries and 200 labels. Never shipped.
 *
 * Run: node bench/compare.ts, or under workerd with bench/workerd.sh
 */
import {
  type Exchange,
  createClient,
  openLog,
  vrfPublicKey,
  KT_128_SHA256_Ed25519,
  KT_128_SHA256_P256,
} from "../src/index.ts";

// Means rather than medians, since workerd only advances its clock by whole milliseconds
const mean = (xs: number[]) => xs.reduce((a, b) => a + b, 0) / xs.length;
async function time(n: number, f: () => unknown): Promise<number> {
  for (let i = 0; i < 20; i++) await f();
  const t = performance.now();
  for (let i = 0; i < n; i++) await f();
  return (performance.now() - t) / n;
}

const alpha = new TextEncoder().encode("alice@example.com");
export async function compare(print: (line: string) => void): Promise<void> {
  for (const [name, cipherSuite] of Object.entries({ KT_128_SHA256_P256, KT_128_SHA256_Ed25519 })) {
    const { vrf, signature } = cipherSuite;
    const key = vrf.key(new Uint8Array(32).fill(7));
    const { proof } = key.prove(alpha);
    const verify = vrf.verifier(key.publicKey);
    print(`ours ${name} vrf prove ${(await time(200, () => key.prove(alpha))).toFixed(3)} ms`);
    print(`ours ${name} vrf verify ${(await time(200, () => verify(alpha, proof))).toFixed(3)} ms`);

    const signingKey = (await crypto.subtle.generateKey(signature.import, false, ["sign", "verify"])) as CryptoKeyPair;
    const vrfSecretKey = new Uint8Array(32).fill(7);
    let now = 1_700_000_000_000;
    const config = {
      cipherSuite,
      signaturePublicKey: new Uint8Array(await crypto.subtle.exportKey("raw", signingKey.publicKey)),
      vrfPublicKey: vrfPublicKey(cipherSuite, vrfSecretKey),
      maxAhead: 1e12,
      maxBehind: 1e12,
      reasonableMonitoringWindow: 60_000,
    };
    const log = await openLog(config, { signingKey, vrfSecretKey, now: () => now });
    const versions = new Map<number, number>();
    const appends: number[] = [];
    for (let i = 0; i < 1000; i++) {
      now += 1;
      const label = i % 200;
      const v = versions.get(label);
      versions.set(label, (v ?? -1) + 1);
      const t = performance.now();
      await log.append({ label: `user-${label}`, value: new Uint8Array(32), expectedVersion: v ?? null });
      appends.push(performance.now() - t);
    }
    print(`ours ${name} append ${mean(appends).toFixed(3)} ms`);
    const serverT: number[] = [];
    const exchange: Exchange = async (op, req) => {
      const t = performance.now();
      const res = await log.handle(op, req, { principal: "p" });
      serverT.push(performance.now() - t);
      return res;
    };
    const client = await createClient(config, exchange, { now: () => now });
    const clientT: number[] = [];
    for (let i = 0; i < 100; i++) {
      const t = performance.now();
      await client.search(`user-${i % 200}`);
      clientT.push(performance.now() - t - serverT.at(-1)!);
    }
    print(`ours ${name} search log ${mean(serverT).toFixed(3)} ms`);
    print(`ours ${name} search client ${mean(clientT).toFixed(3)} ms`);
  }
}

if (import.meta.main) await compare(console.log);
