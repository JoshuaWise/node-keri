/**
 * Profile constants. The KERI Direct JSON Profile v1 is the only profile
 * recognized by this library. Anything outside the lists below must be
 * rejected by feature gates rather than silently accepted.
 */

export const KERI_PROFILE_NAME = 'KERI Direct JSON Profile v1';

export const SUPPORTED_KEY_ALGORITHM = 'ed25519' as const;
export type SupportedKeyAlgorithm = typeof SUPPORTED_KEY_ALGORITHM;

export const ED25519_PUBLIC_KEY_BYTES = 32;
export const ED25519_SIGNATURE_BYTES = 64;
