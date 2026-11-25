import { p256 } from "@noble/curves/nist.js";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/curves/utils.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { expect, test } from "vitest";
import {
  CipherSuite,
  commitment,
  encodeConfiguration,
  logLeaf,
  logParent,
  treeHeadVerifier,
  vrfInput,
} from "../src/crypto.ts";
import { P256_VRF } from "../src/vrf.ts";

const vrf = P256_VRF.key(hexToBytes("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"));

async function setup() {
  const keys = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const signaturePublicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
  const config = {
    cipherSuite: CipherSuite.KT_128_SHA256_P256,
    signaturePublicKey,
    vrfPublicKey: vrf.publicKey,
    maxAhead: 1,
    maxBehind: 2,
    reasonableMonitoringWindow: 3,
  };
  return { keys, config };
}

test("Configuration and TreeHeadTBS encoding, signature verification", async () => {
  const { keys, config } = await setup();
  const encoded = encodeConfiguration(config);
  // ciphersuite, mode, sig key<2>, vrf key<2>, three uint64, absent optional
  expect(bytesToHex(encoded)).toBe(
    "0001" +
      "01" +
      "0041" +
      bytesToHex(config.signaturePublicKey) +
      "0021" +
      bytesToHex(vrf.publicKey) +
      "0000000000000001" +
      "0000000000000002" +
      "0000000000000003" +
      "00",
  );
  expect(bytesToHex(encodeConfiguration({ ...config, maximumLifetime: 4 }).subarray(-9))).toBe("010000000000000004");

  const root = new Uint8Array(32).fill(7);
  const tbs = concatBytes(encoded, hexToBytes("000000000000000a"), root);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keys.privateKey, tbs));
  const verify = await treeHeadVerifier(config);
  expect(await verify(10, root, sig)).toBe(true);
  expect(await verify(11, root, sig)).toBe(false);
  expect(await verify(10, new Uint8Array(32), sig)).toBe(false);
  expect(await verify(10, root, sig.subarray(1))).toBe(false);
  // A signature under a different configuration does not verify.
  expect(await (await treeHeadVerifier({ ...config, maxAhead: 9 }))(10, root, sig)).toBe(false);
});

test("rejects malformed configuration keys", () => {
  const bad = {
    cipherSuite: CipherSuite.KT_128_SHA256_P256,
    signaturePublicKey: vrf.publicKey,
    vrfPublicKey: vrf.publicKey,
    maxAhead: 0,
    maxBehind: 0,
    reasonableMonitoringWindow: 0,
  };
  expect(() => encodeConfiguration(bad)).toThrow();
  const uncompressed = p256.Point.fromBytes(vrf.publicKey).toBytes(false);
  expect(() => encodeConfiguration({ ...bad, signaturePublicKey: uncompressed, maxAhead: -1 })).toThrow(RangeError);
});

test("commitment, VRF input and log hashing layouts", () => {
  const label = new TextEncoder().encode("alice");
  expect(bytesToHex(vrfInput(label, 2))).toBe("05616c69636500000002");
  const opening = new Uint8Array(16).fill(1);
  const expected = hmac(
    sha256,
    hexToBytes("d821f8790d97709796b4d7903357c3f5"),
    hexToBytes("01".repeat(16) + "05616c696365" + "00000002" + "00000003abcdef"),
  );
  expect(commitment(opening, label, 2, hexToBytes("abcdef"))).toEqual(expected);
  const root = new Uint8Array(32).fill(9);
  expect(logLeaf(5, root)).toEqual(sha256(concatBytes(hexToBytes("0000000000000005"), root)));
  expect(logParent(root, true, root, false)).toEqual(
    sha256(concatBytes(hexToBytes("00"), root, hexToBytes("01"), root)),
  );
  expect(() => vrfInput(new Uint8Array(256), 0)).toThrow(RangeError);
});
