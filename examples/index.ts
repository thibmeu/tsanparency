/**
 * The three examples from the README, run end to end against an in-memory log.
 * Run: npm run examples   (or bun run examples/index.ts)
 */
import {
  CipherSuite,
  type Configuration,
  type Exchange,
  type State,
  createClient,
  openLog,
  vrfPublicKey,
} from "../src/index.ts";

const text = (b: Uint8Array) => new TextDecoder().decode(b);
const assert = (ok: boolean, msg: string) => {
  if (!ok) throw new Error(msg);
};

// 3. Run a log: open it, append one binding, and serve requests through its binary handler.
const signingKey = (await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])) as CryptoKeyPair;
const vrfSecretKey = crypto.getRandomValues(new Uint8Array(32));
const config: Configuration = {
  cipherSuite: CipherSuite.KT_128_SHA256_Ed25519,
  signaturePublicKey: new Uint8Array(await crypto.subtle.exportKey("raw", signingKey.publicKey)),
  vrfPublicKey: vrfPublicKey(CipherSuite.KT_128_SHA256_Ed25519, vrfSecretKey),
  maxAhead: 10_000,
  maxBehind: 60_000,
  reasonableMonitoringWindow: 60_000,
};
const log = await openLog(config, { signingKey, vrfSecretKey });
await log.append({ label: "alice@example.com", value: new TextEncoder().encode("alice-key-1"), expectedVersion: null });
const exchange: Exchange = (operation, request, { signal }) =>
  log.handle(operation, request, { principal: "bob", signal });

// 1. First lookup: trusted configuration, a byte transport and a label give a verified key and state.
const client = await createClient(config, exchange);
const found = await client.search("alice@example.com", client.initialState());
assert(text(found.value) === "alice-key-1", "unexpected key");
console.log(`found ${text(found.value)} at version ${found.version}`);

// 2. Monitor after restart: state survives the deployment's serializer, here structured clone.
const restored: State = structuredClone(found.state);
const checked = await client.monitor("alice@example.com", restored);
assert(checked.state.checkpoint !== null, "lost checkpoint");
console.log(`monitored, ${checked.state.contact?.monitoring.length ?? 0} entries left to monitor`);
