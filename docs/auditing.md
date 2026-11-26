# Auditor API

An independent auditor opens its store and applies one encoded update per log position, from the configured start position. Starting after the first entry, it trusts the log tree, prefix root and frontier timestamps from `log.auditorStart`, and counts leaves it never saw added as added just before its start. The application handles delivery, as it does for the client transport.

```ts
const auditor = await openAuditor(config, { signingKey, store });
await auditor.apply(position, log.auditorUpdate(position));
const head = await auditor.head();
```

`openAuditor` restores the last verified position and tree state. `apply` verifies the timestamp, against the previous entry and the clock, and the prefix-tree mutation, including whether a removed leaf reached a distinguished entry. It appends the resulting log leaf and atomically stores what it keeps of the entry. Retrying the last identical update succeeds, and a gap, conflicting update or failed proof leaves the store intact. `head` signs once per tree size, so catching up costs one signature. [Protocol §15.2](https://www.ietf.org/archive/id/draft-ietf-keytrans-protocol-06.html#section-15.2)

The operator passes the auditor head to `log.acceptAuditorHead`, which checks its signature against the log root at that size and includes it in updated responses. The client checks the auditor signature against the root at the audited size, enforces the configured lag and auditor continuity, and saves the head with its checkpoint. The auditor key stays with the auditor. [Protocol §§11.2–11.4](https://www.ietf.org/archive/id/draft-ietf-keytrans-protocol-06.html#section-11.2)

The katie update and mutation vectors cover proof verification, and a restart-and-retry test covers the store boundary. The auditor accepts an update without changes, which a quiet log publishes on every tick, although OR13 and katie reject its empty proof. [OR13 interoperability notes](https://github.com/OR13/kt/blob/7ba65f1/docs/interop.md)
