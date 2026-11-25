import { hexToBytes } from "@noble/curves/utils.js";
import { type Configuration, type Exchange, type Log, type LogOptions, createClient, openLog } from "../src/index.ts";
import { CipherSuite, SUITES } from "../src/crypto.ts";

const VRF_SECRET = hexToBytes("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");

const keys = new Map<CipherSuite, Promise<{ pair: CryptoKeyPair; raw: Uint8Array }>>();
function signingKey(suite: CipherSuite) {
  let k = keys.get(suite);
  if (!k) {
    k = (async () => {
      const pair = (await crypto.subtle.generateKey(SUITES[suite].signature.import, false, [
        "sign",
        "verify",
      ])) as CryptoKeyPair;
      return { pair, raw: new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)) };
    })();
    keys.set(suite, k);
  }
  return k;
}

export const RMW = 1000;
export const SUITE_NAMES = Object.entries(CipherSuite) as [string, CipherSuite][];

export async function configuration(overrides: Partial<Configuration> = {}): Promise<Configuration> {
  const cipherSuite = overrides.cipherSuite ?? CipherSuite.KT_128_SHA256_P256;
  return {
    cipherSuite,
    signaturePublicKey: (await signingKey(cipherSuite)).raw,
    vrfPublicKey: SUITES[cipherSuite].vrf.key(VRF_SECRET).publicKey,
    maxAhead: 10_000,
    maxBehind: 60_000,
    reasonableMonitoringWindow: RMW,
    ...overrides,
  };
}

export interface World {
  readonly config: Configuration;
  readonly log: Log;
  readonly clock: { now: number };
  /** Forwards requests to the log, optionally rewriting responses */
  exchange(principal: string, tamper?: (response: Uint8Array) => Uint8Array): Exchange;
  client(principal: string, tamper?: (response: Uint8Array) => Uint8Array): ReturnType<typeof createClient>;
}

export async function world(
  overrides: Partial<Configuration> = {},
  logOptions: Partial<LogOptions> = {},
): Promise<World> {
  const config = await configuration(overrides);
  const clock = { now: 1_700_000_000_000 };
  const { pair } = await signingKey(config.cipherSuite);
  const log = await openLog(config, {
    signingKey: pair,
    vrfSecretKey: VRF_SECRET,
    now: () => clock.now,
    ...logOptions,
  });
  const exchange =
    (principal: string, tamper?: (r: Uint8Array) => Uint8Array): Exchange =>
    async (operation, request, { signal }) => {
      const response = await log.handle(operation, request, { principal, signal });
      return tamper ? tamper(response) : response;
    };
  return {
    config,
    log,
    clock,
    exchange,
    client: (principal, tamper) => createClient(config, exchange(principal, tamper), { now: () => clock.now }),
  };
}
