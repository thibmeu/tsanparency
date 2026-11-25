/** A log with `entries` appends over `labels` labels, and a client wired to it in-process. */
import { type Exchange, createClient, openLog } from "../src/index.ts";
import { CipherSuite, SUITES } from "../src/crypto.ts";

export async function fixture(entries = Number(process.env.ENTRIES ?? 2000), labels = 500) {
  const cipherSuite =
    process.env.SUITE === "ed25519" ? CipherSuite.KT_128_SHA256_Ed25519 : CipherSuite.KT_128_SHA256_P256;
  const suite = SUITES[cipherSuite];
  const vrfSecretKey = new Uint8Array(32).fill(7);
  const signingKey = (await crypto.subtle.generateKey(suite.signature.import, false, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const config = {
    cipherSuite,
    signaturePublicKey: new Uint8Array(await crypto.subtle.exportKey("raw", signingKey.publicKey)),
    vrfPublicKey: suite.vrf.key(vrfSecretKey).publicKey,
    maxAhead: 1e12,
    maxBehind: 1e12,
    reasonableMonitoringWindow: 60_000,
  };
  const clock = { now: 1_700_000_000_000 };
  const log = await openLog(config, { signingKey, vrfSecretKey, now: () => clock.now });
  const versions = new Map<string, number>();
  const append = (label: string) => {
    clock.now += 1000;
    const v = versions.get(label);
    versions.set(label, (v ?? -1) + 1);
    return log.append({ label, value: new Uint8Array(32), expectedVersion: v ?? null });
  };
  for (let i = 0; i < entries; i++) await append(`user-${i % labels}`);
  const exchange: Exchange = (op, req, { signal }) => log.handle(op, req, { principal: "p", signal });
  const client = await createClient(config, exchange, { now: () => clock.now });
  return { config, log, clock, client, exchange, append };
}
