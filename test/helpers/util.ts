import { Buffer } from 'node:buffer';
import { createHash, createPrivateKey } from 'node:crypto';
import { SignedKeriEvent } from '../../src/event/types';
import { parseKel } from '../../src/event/stream';
import { InvalidArgumentError, MalformedInputError } from '../../src/profile/errors';
import { decodeDigest } from '../../src/cesr/decode';
import { encodeDigest } from '../../src/cesr/encode';
import { CesrDigest } from '../../src/cesr/qualified';
import { CESR_DIGEST_SHA256 } from '../../src/cesr/codes';
import { KeyPair, asPrivateKey, keyPairFromPrivateKey } from '../../src/crypto/keypair';
import { DEFAULT_DIGEST_CODE } from '../../src/crypto/digests';
import { saidPlaceholder } from '../../src/event/digest';

/**
 * Parse a single event frame into its `SignedKeriEvent`. Throws
 * `MalformedInputError` if `frame` is not exactly one well-formed frame
 * (trailing bytes, or no event, are rejected).
 *
 * Like `parseKel`, this is for inspecting the in-memory shape of a wire-form
 * event; it does not verify the event.
 */
export function parseSignedEvent(frame: string): SignedKeriEvent {
	const events = parseKel(frame);
	if (events.length !== 1) {
		throw new MalformedInputError(
			`expected exactly one event frame, parsed ${events.length}`
		);
	}
	return events[0]!;
}

export function sha256(input: Readonly<Uint8Array>): Uint8Array {
	return new Uint8Array(createHash('sha256').update(input).digest());
}

export function fillSeed(byte: number): Uint8Array {
	return new Uint8Array(32).fill(byte);
}

/** Decode a CESR-qualified SHA-256 digest (code `I`), specifically. */
export function decodeDigestSha256(qb64: string): Uint8Array {
	const { raw, code } = decodeDigest(qb64);
	if (code !== CESR_DIGEST_SHA256.code) {
		throw new MalformedInputError('expected SHA256 digest');
	}
	return raw;
}

/** CESR-qualify a 32-byte SHA-256 digest (code `I`), specifically. */
export function encodeDigestSha256(raw: Readonly<Uint8Array>): CesrDigest {
	return encodeDigest(CESR_DIGEST_SHA256.code, raw) as CesrDigest;
}

// PKCS#8 ASN.1 DER prefix for an Ed25519 private key (RFC 8410); the 32-byte
// seed follows immediately after. Mirrors the library's internal constant —
// kept here so deterministic, seed-based test keypairs live with the rest of
// the test fixtures rather than in production source.
const ED25519_PKCS8_PREFIX = new Uint8Array([
	0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
	0x04, 0x20,
]);

const ED25519_PRIVATE_SEED_BYTES = 32;

/**
 * Construct a KeyPair from a 32-byte Ed25519 seed, for deterministic test
 * vectors. The public half is derived from the seed by Node.
 */
export function keyPairFromSeed(seed: Readonly<Uint8Array>): KeyPair {
	if (seed.length !== ED25519_PRIVATE_SEED_BYTES) {
		throw new InvalidArgumentError(
			`Ed25519 seed must be ${ED25519_PRIVATE_SEED_BYTES} bytes`
		);
	}
	const der = Buffer.concat([ED25519_PKCS8_PREFIX, seed]);
	const privateKey = createPrivateKey({
		key: Buffer.from(der),
		format: 'der',
		type: 'pkcs8',
	});
	return keyPairFromPrivateKey(asPrivateKey(privateKey));
}

/**
 * The SAID placeholder for the default (SHA-256) digest — 44 `#` characters.
 * Tests use it to write literal SAID-bearing event fields; production code
 * calls the `saidPlaceholder()` function directly.
 */
export const SAID_PLACEHOLDER: string = saidPlaceholder(DEFAULT_DIGEST_CODE);
