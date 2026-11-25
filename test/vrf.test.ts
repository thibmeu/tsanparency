import { bytesToHex, hexToBytes } from "@noble/curves/utils.js";
import { describe, expect, test } from "vitest";
import { ED25519_VRF, P256_VRF, type Vrf } from "../src/vrf.ts";

const suites: [string, Vrf, { sk: string; pk: string; alpha: string; pi: string; beta: string }[]][] = [
  [
    "ECVRF-P256-SHA256-TAI (RFC 9381 Appendix B.1)",
    P256_VRF,
    [
      {
        sk: "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        pk: "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
        alpha: "73616d706c65",
        pi: "035b5c726e8c0e2c488a107c600578ee75cb702343c153cb1eb8dec77f4b5071b4a53f0a46f018bc2c56e58d383f2305e0975972c26feea0eb122fe7893c15af376b33edf7de17c6ea056d4d82de6bc02f",
        beta: "a3ad7b0ef73d8fc6655053ea22f9bede8c743f08bbed3d38821f0e16474b505e",
      },
      {
        sk: "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        pk: "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
        alpha: "74657374",
        pi: "034dac60aba508ba0c01aa9be80377ebd7562c4a52d74722e0abae7dc3080ddb56c19e067b15a8a8174905b13617804534214f935b94c2287f797e393eb0816969d864f37625b443f30f1a5a33f2b3c854",
        beta: "a284f94ceec2ff4b3794629da7cbafa49121972671b466cab4ce170aa365f26d",
      },
      {
        sk: "2ca1411a41b17b24cc8c3b089cfd033f1920202a6c0de8abb97df1498d50d2c8",
        pk: "03596375e6ce57e0f20294fc46bdfcfd19a39f8161b58695b3ec5b3d16427c274d",
        alpha:
          "4578616d706c65207573696e67204543445341206b65792066726f6d20417070656e646978204c2e342e32206f6620414e53492e58392d36322d32303035",
        pi: "03d03398bf53aa23831d7d1b2937e005fb0062cbefa06796579f2a1fc7e7b8c667d091c00b0f5c3619d10ecea44363b5a599cadc5b2957e223fec62e81f7b4825fc799a771a3d7334b9186bdbee87316b1",
        beta: "90871e06da5caa39a3c61578ebb844de8635e27ac0b13e829997d0d95dd98c19",
      },
    ],
  ],
  [
    "ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381 Appendix B.3), output truncated to 32 bytes",
    ED25519_VRF,
    [
      {
        sk: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        pk: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        alpha: "",
        pi: "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805",
        beta: "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff",
      },
      {
        sk: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        pk: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        alpha: "72",
        pi: "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02",
        beta: "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb",
      },
      {
        sk: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        pk: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        alpha: "af82",
        pi: "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e",
        beta: "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c45",
      },
    ],
  ],
];

describe.each(suites)("%s", (_, vrf, vectors) => {
  test.each(vectors)("alpha=$alpha", ({ sk, pk, alpha, pi, beta }) => {
    const key = vrf.key(hexToBytes(sk));
    expect(bytesToHex(key.publicKey)).toBe(pk);
    const { proof, output } = key.prove(hexToBytes(alpha));
    expect(bytesToHex(proof)).toBe(pi);
    expect(bytesToHex(output)).toBe(beta);
    expect(bytesToHex(vrf.verifier(hexToBytes(pk))(hexToBytes(alpha), proof)!)).toBe(beta);
  });

  test("rejects tampered proofs, inputs and keys", () => {
    const { pk, alpha, pi } = vectors[0]!;
    const verify = vrf.verifier(hexToBytes(pk));
    const proof = hexToBytes(pi);
    for (const i of [0, 1, proof.length - 48, proof.length - 33, proof.length - 32, proof.length - 1]) {
      const bad = proof.slice();
      bad[i]! ^= 1;
      expect(verify(hexToBytes(alpha), bad)).toBeNull();
    }
    expect(verify(hexToBytes("00ff"), proof)).toBeNull();
    expect(verify(hexToBytes(alpha), proof.subarray(1))).toBeNull();
    expect(vrf.verifier(hexToBytes(vectors[2]!.pk))(hexToBytes(alpha), proof)).toBeNull();
    const bigS = proof.slice();
    bigS.fill(0xff, proof.length - 32);
    expect(verify(hexToBytes(alpha), bigS)).toBeNull();
  });
});
