/**
 * Durable storage for a log. The log serves reads from memory and persists one
 * record per log entry, from which it rebuilds every tree when it opens.
 */

/** A version of a label created in a log entry */
export interface StoredVersion {
  readonly label: Uint8Array;
  readonly version: number;
  readonly opening: Uint8Array;
  readonly value: Uint8Array;
  /** VRF output of the label-version pair, so opening does not re-run the VRF */
  readonly vrfOutput: Uint8Array;
}

/** Everything a log entry adds, along with the tree head that covers it */
export interface StoredEntry {
  /** Milliseconds since the Unix epoch */
  readonly timestamp: number;
  readonly versions: readonly StoredVersion[];
  /** TreeHead.signature for the tree ending at this entry */
  readonly signature: Uint8Array;
}

export interface Store {
  /** Committed entries from position `from` onward, in order */
  read(from: number): AsyncIterable<StoredEntry>;
  /**
   * Stores `entry` at `position` atomically. Throws if an entry already exists
   * there, which is how concurrent writers on one store detect each other.
   */
  append(position: number, entry: StoredEntry): Promise<void>;
}

/** A store that keeps entries in memory, for tests and ephemeral logs */
export function memoryStore(): Store {
  const entries: StoredEntry[] = [];
  return {
    async *read(from) {
      for (let i = from; i < entries.length; i++) yield entries[i]!;
    },
    async append(position, entry) {
      if (position !== entries.length) throw new Error("log entry already stored");
      entries.push(entry);
    },
  };
}
