# tsanparency

Key Transparency ([draft-ietf-keytrans-protocol-06](https://datatracker.ietf.org/doc/html/draft-ietf-keytrans-protocol-06)) for TypeScript: a client and an embeddable log, in Contact Monitoring mode.

- Cipher suites `KT_128_SHA256_P256` and `KT_128_SHA256_Ed25519`
- Greatest-version and fixed-version Search, Contact Monitor, and the owner operations: Owner Initialization, Owner Monitoring and Updating a Label
- Runs on Node, Bun, browsers and Cloudflare Workers, using Web Crypto for signatures

Interoperates with [Bren2010/katie](https://github.com/Bren2010/katie) and uses test vectors published by [OR13/kt](https://github.com/OR13/kt).

## Usage

```ts
import { createClient, openLog } from "tsanparency";

// Log side: append a binding and answer TLS-encoded requests
const log = await openLog(config, { signingKey, vrfSecretKey });
await log.append({ label: "alice@example.com", value: aliceKey, expectedVersion: null });
await log.append({ label: "bob@example.com", value: bobKey, expectedVersion: null });

// Client side: the application owns transport and storage
const client = await createClient(config, (operation, request, { signal }) =>
  log.handle(operation, request, { principal: "bob", signal }),
);
const alice = await client.search("alice@example.com");
await persist(alice.checkpoint, alice.contact);

const bob = await client.search("bob@example.com", { checkpoint: alice.checkpoint });
await persist(bob.checkpoint, bob.contact);

const checked = await client.monitor(alice.contact, { checkpoint: bob.checkpoint });
await persist(checked.checkpoint, checked.contact);
```

Logs persist one record per entry through a `Store` (`memoryStore()` by default): implement `read` and an atomic `append` at a position to back it with a database. A log with a maximum lifetime drops the prefix trees of expired entries.

To follow the log tree without a log, `appendLeaf(size, fullSubtrees, leaf)` folds one leaf value into the full subtree heads, and `rootFromFullSubtrees` gives the root.

Keep one checkpoint per log and a contact or owner record for each label you track. Save the returned checkpoint and record together before using a result. If calls overlap, check that both stored records still match what the call started from before replacing them. The records support structured clone and IndexedDB.

To look up an older version, pass `{ checkpoint, contact, version }` to `search`. Call `schedule(contact, { checkpoint })` to find out when monitoring is due. For a label you own, `ownerInit(label, { checkpoint })` returns an owner record for `update(owner, values, { checkpoint })` and `ownerMonitor(owner, { checkpoint })`.

See [examples/index.ts](examples/index.ts) for a runnable version.

## Development

```sh
npm test              # Node
npm run test:browser  # Chromium and Firefox
npm run test:workers  # workerd
npm run bench:profile # self time by function
npm run bench:trace   # CPU and heap profiles for speedscope or Chrome DevTools
npm run bench:memory  # heap retained per log entry, with and without pruning
node bench/compare.ts # VRF, append and search timings, or bench/workerd.sh for workerd
```

## License

MIT
