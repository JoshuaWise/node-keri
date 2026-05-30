import { createHash } from 'node:crypto';
import { SignedKeriEvent } from '../../src/event/types';
import { parseKel } from '../../src/event/stream';
import { MalformedInputError } from '../../src/profile/errors';
import { decodeDigest } from '../../src/cesr/decode';
import { encodeDigest } from '../../src/cesr/encode';
import { CesrDigest } from '../../src/cesr/qualified';
import { CESR_DIGEST_SHA256 } from '../../src/cesr/codes';

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
