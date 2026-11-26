export const KTErrorCode = {
  /** The exchange failed or returned too many bytes. */
  Transport: "TRANSPORT",
  /** The log's host failed, such as its `authorize` callback. */
  Internal: "INTERNAL",
  /** The log shed load to protect itself. Retry later. */
  Overloaded: "OVERLOADED",
  /** A response failed verification. Persisted state is unaffected. */
  InvalidResponse: "INVALID_RESPONSE",
  /** The rightmost log entry is outside the configured clock bounds. */
  Stale: "STALE",
  /** Monitoring reached an expired log entry (Section 7.1). */
  Expired: "EXPIRED",
  /**
   * The log showed two different commitments or VRF outputs for one label
   * version in fully verified responses. This is evidence of misbehaviour.
   */
  Equivocation: "EQUIVOCATION",
  /** State does not belong to this configuration or label, or is malformed. */
  InvalidState: "INVALID_STATE",
  /** A request is malformed or inconsistent with the log. */
  InvalidRequest: "INVALID_REQUEST",
  /** The principal may not perform this operation. */
  Unauthorized: "UNAUTHORIZED",
  /** The label does not exist. */
  NotFound: "NOT_FOUND",
  /** The expected version did not match the latest version. */
  Conflict: "CONFLICT",
} as const;

export type KTErrorCode = (typeof KTErrorCode)[keyof typeof KTErrorCode];

export class KTError extends Error {
  override name = "KTError";
  readonly code: KTErrorCode;

  constructor(code: KTErrorCode, options?: ErrorOptions) {
    super(`KT error: ${code}`, options);
    this.code = code;
  }
}

export const isKTError = (e: unknown, code?: KTErrorCode): e is KTError =>
  e instanceof KTError && (code === undefined || e.code === code);
