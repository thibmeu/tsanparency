import {
  type Configuration,
  type Exchange,
  createClient,
  openLog,
  vrfPublicKey,
  KT_128_SHA256_Ed25519,
} from "../src/index.ts";

const text = (b: Uint8Array) => new TextDecoder().decode(b);
const assert = (ok: boolean, msg: string) => {
  if (!ok) throw new Error(msg);
};

const signingKey = (await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])) as CryptoKeyPair;
const vrfSecretKey = crypto.getRandomValues(new Uint8Array(32));
const config: Configuration = {
  cipherSuite: KT_128_SHA256_Ed25519,
  signaturePublicKey: new Uint8Array(await crypto.subtle.exportKey("raw", signingKey.publicKey)),
  vrfPublicKey: vrfPublicKey(KT_128_SHA256_Ed25519, vrfSecretKey),
  maxAhead: 10_000,
  maxBehind: 60_000,
  reasonableMonitoringWindow: 60_000,
};
let time = Date.now();
const now = () => time;
const log = await openLog(config, { signingKey, vrfSecretKey, now });
await log.append({ label: "alice@example.com", value: new TextEncoder().encode("alice-key-1"), expectedVersion: null });
const exchange: Exchange = (operation, request, { signal }) =>
  log.handle(operation, request, { principal: "bob", signal });

const client = await createClient(config, exchange, { now });
const alice = await client.search("alice@example.com");
assert(text(alice.value) === "alice-key-1", "unexpected key");
console.log(`found ${text(alice.value)} at version ${alice.version}`);

await log.append({ label: "bob@example.com", value: new TextEncoder().encode("bob-key-1"), expectedVersion: null });
for (let i = 0; i < 3; i++) {
  time += config.maxBehind / 2;
  await log.tick();
}
const bob = await client.search("bob@example.com", { checkpoint: alice.checkpoint });
const restored = structuredClone({ checkpoint: bob.checkpoint, contact: alice.contact });
const checked = await client.monitor(restored.contact, { checkpoint: restored.checkpoint });
assert(checked.checkpoint.treeSize === log.size, "unexpected checkpoint");
console.log(`Alice has ${checked.contact.monitoring.length} entries left to monitor`);
