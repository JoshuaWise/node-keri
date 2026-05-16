/**
 * Profile constants. The KERI Direct JSON Profile v1 is the only profile
 * recognized by this library. Anything outside the lists below must be
 * rejected by feature gates rather than silently accepted.
 */

export const KERI_PROFILE_NAME = 'KERI Direct JSON Profile v1';

export const SUPPORTED_KEY_ALGORITHM = 'Ed25519' as const;
export type SupportedKeyAlgorithm = typeof SUPPORTED_KEY_ALGORITHM;

/**
 * The *default* digest algorithm — used for generation when a caller does not
 * pick one, and the algorithm of the all-important inception SAID/AID unless
 * overridden. Verification is not limited to it: a KEL may use any digest
 * algorithm with a registered implementation (see `digestAlgorithms`), and
 * `DIGEST_CODES` / `DEFAULT_DIGEST_CODE` name the codes involved.
 */
export const SUPPORTED_DIGEST_ALGORITHM = 'SHA-256' as const;
export type SupportedDigestAlgorithm = typeof SUPPORTED_DIGEST_ALGORITHM;

export const ED25519_PUBLIC_KEY_BYTES = 32;
export const ED25519_PRIVATE_SEED_BYTES = 32;
export const ED25519_SIGNATURE_BYTES = 64;
export const SHA256_DIGEST_BYTES = 32;
