/**
 * Self-addressing identifier (SAID) computation for KERI events.
 *
 * KERI's "self-addressing" rule binds an event to a digest of its own
 * canonical bytes. Because the digest itself is one of the fields, naïvely
 * digesting would be circular; the convention is to first substitute the
 * SAID-bearing fields with a fixed-length placeholder, canonicalize, hash,
 * and then write the resulting digest back into those fields. The
 * substitution preserves byte length (placeholder length === digest length)
 * so the canonical bytes used for the digest and for the final event differ
 * only in the placeholder positions.
 *
 * The `v` (version) string carries the serialized byte size in 6 hex chars,
 * also of fixed length, so populating it likewise preserves byte length.
 * That lets us:
 *   1. canonicalize once with placeholders + size=000000 to learn the size,
 *   2. canonicalize again with the real size in `v` (still placeholders for
 *      the SAID fields) — this is what gets hashed,
 *   3. write the SAID back into the SAID-bearing fields for the final event.
 */

import { utf8Encode } from '../bytes/utf8';
import { CESR_DIGEST_SHA256 } from '../cesr/codes';
import { encodeDigestSha256, encodePublicKeyEd25519 } from '../cesr/encode';
import { CesrDigest } from '../cesr/qualified';
import { sha256 } from '../crypto/hash';
import { KeriPublicKey, assertPublicKey } from '../crypto/keypair';
import { CanonicalJsonError, InvalidArgumentError } from '../profile/errors';
import { canonicalizeJson } from './canonical-json';

/** Length of the qb64 form of a SHA-256 digest under code `I` (44 chars). */
const SAID_LENGTH = CESR_DIGEST_SHA256.fs;

/**
 * Placeholder string used in SAID-bearing fields prior to digesting. Any
 * single character outside the base64url alphabet works; `#` is conventional
 * in KERI tooling and makes the placeholder visually distinct in dumps.
 */
export const SAID_PLACEHOLDER = '#'.repeat(SAID_LENGTH) as string;

const VERSION_PROTOCOL = 'KERI';
const VERSION_NUMBER = '10';
const VERSION_FORMAT = 'JSON';
const VERSION_SIZE_HEX_LENGTH = 6;
const VERSION_TERMINATOR = '_';
const VERSION_PREFIX = VERSION_PROTOCOL + VERSION_NUMBER + VERSION_FORMAT;

/** Total length of the version string, e.g. `KERI10JSON0000ff_` (17 chars). */
export const KERI_VERSION_STRING_LENGTH =
	VERSION_PREFIX.length + VERSION_SIZE_HEX_LENGTH + VERSION_TERMINATOR.length;

/** Largest event size representable in the 6-hex-char size field. */
const MAX_EVENT_SIZE = 0xffffff;

/** Build a version string for `size` bytes. */
export function formatKeriVersionString(size: number): string {
	if (!Number.isInteger(size) || size < 0) {
		throw new InvalidArgumentError(
			'event size must be a non-negative integer'
		);
	}
	if (size > MAX_EVENT_SIZE) {
		throw new CanonicalJsonError(
			`event size ${size} exceeds maximum ${MAX_EVENT_SIZE}`
		);
	}
	return (
		VERSION_PREFIX
		+ size.toString(16).padStart(VERSION_SIZE_HEX_LENGTH, '0')
		+ VERSION_TERMINATOR
	);
}

/** Version string used during the size-discovery pass. */
const PLACEHOLDER_VERSION_STRING = formatKeriVersionString(0);

export interface SaidComputation {
	/** The qb64 SAID. */
	readonly said: CesrDigest;
	/** The version string that should be embedded into the final event. */
	readonly versionString: string;
	/** Canonical bytes that were hashed; equals the bytes of the final
	 *  event with the SAID fields holding their placeholder values. */
	readonly digestedBytes: Uint8Array;
}

/**
 * Compute the SAID for `partialEvent`, a plain object representing the event
 * with `v` and the SAID-bearing fields *omitted* (they are filled in by this
 * function). The caller passes the names of the SAID-bearing fields:
 *   - `['d']` for rotation and interaction events
 *   - `['d', 'i']` for inception (the AID is itself the SAID)
 */
export function computeEventSaid(
	partialEvent: Readonly<Record<string, unknown>>,
	saidFields: readonly string[]
): SaidComputation {
	if (saidFields.length === 0) {
		throw new InvalidArgumentError('saidFields must be non-empty');
	}
	for (const f of saidFields) {
		if (f === 'v') {
			throw new InvalidArgumentError(
				'`v` is filled in automatically and cannot be a SAID field'
			);
		}
		if (Object.prototype.hasOwnProperty.call(partialEvent, f)) {
			throw new InvalidArgumentError(
				`partial event must not contain SAID field '${f}'`
			);
		}
	}
	if (Object.prototype.hasOwnProperty.call(partialEvent, 'v')) {
		throw new InvalidArgumentError(
			'partial event must not contain a `v` field'
		);
	}

	const placeholders: Record<string, string> = {};
	for (const f of saidFields) placeholders[f] = SAID_PLACEHOLDER;

	// Pass 1 — placeholder size, placeholder SAIDs. We only need the byte
	// length here; the bytes themselves are discarded.
	const draft = { ...partialEvent, ...placeholders, v: PLACEHOLDER_VERSION_STRING };
	const draftBytes = canonicalizeJson(draft);
	const versionString = formatKeriVersionString(draftBytes.length);

	// Pass 2 — real size in v, still placeholder SAIDs. These are the bytes
	// that the SAID is computed over.
	const sized = { ...partialEvent, ...placeholders, v: versionString };
	const digestedBytes = canonicalizeJson(sized);
	if (digestedBytes.length !== draftBytes.length) {
		// Both passes use fixed-width substitutions, so the byte size cannot
		// change between them. If it did, our placeholder accounting is wrong
		// and the resulting SAID would not be reproducible.
		throw new CanonicalJsonError(
			'event byte size changed between SAID passes — invariant broken'
		);
	}

	const digest = sha256(digestedBytes);
	const said = encodeDigestSha256(digest);
	return { said, versionString, digestedBytes };
}

/**
 * Compute the pre-rotation commitment for `nextPublicKey`.
 *
 * The commitment is the qb64 SHA-256 of the *qb64-encoded* next public key.
 * Hashing the qualified form (rather than raw bytes) binds the commitment
 * to the algorithm as well as the bytes, so a future rotation cannot
 * substitute a different key type while preserving the digest.
 */
export function deriveNextKeyCommitment(
	nextPublicKey: KeriPublicKey
): CesrDigest {
	assertPublicKey(nextPublicKey);
	const qb64 = encodePublicKeyEd25519(nextPublicKey.raw);
	return encodeDigestSha256(sha256(utf8Encode(qb64)));
}
