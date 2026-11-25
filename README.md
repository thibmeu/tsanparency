# tsanparency

Key Transparency ([draft-ietf-keytrans-protocol-06](https://datatracker.ietf.org/doc/html/draft-ietf-keytrans-protocol-06)) for TypeScript: a client and an embeddable log, in Contact Monitoring mode.

- Cipher suites `KT_128_SHA256_P256` and `KT_128_SHA256_Ed25519`
- Greatest-version and fixed-version Search, and Contact Monitor
- Runs on Node, Bun, browsers and Cloudflare Workers, using Web Crypto for signatures

Interoperates with [Bren2010/katie](https://github.com/Bren2010/katie) and uses test vectors published by [OR13/kt](https://github.com/OR13/kt).

## Usage

```ts
import { createClient, openLog } from "tsanparency";

// Log side: append a binding and answer TLS-encoded requests
const log = await openLog(config, { signingKey, vrfSecretKey });
await log.append({ label: "alice@example.com", value: key, expectedVersion: null });

// Client side: the application owns transport and storage
const client = await createClient(config, (operation, request, { signal }) =>
  log.handle(operation, request, { principal: "bob", signal }),
);
const found = await client.search("alice@example.com", client.initialState());
await persist(found.state); // before using the key
const older = await client.search("alice@example.com", found.state, { version: 0 });

// Monitor when due: client.schedule(state) says when monitoring can complete an entry,
// and by when it must happen if the log has a maximum lifetime
const due = client.schedule(found.state);
const checked = await client.monitor("alice@example.com", found.state);
```

Verified state is plain data with numbers and `Uint8Array`s, so it survives structured clone and IndexedDB. Persist the new state before using a result: a response that fails verification never changes it.

See [examples/index.ts](examples/index.ts) for a runnable version.

## Development

```sh
npm test              # Node
npm run test:browser  # Chromium and Firefox
npm run test:workers  # workerd
npm run bench:profile # self time by function
npm run bench:trace   # CPU and heap profiles for speedscope or Chrome DevTools
```

## License

MIT
