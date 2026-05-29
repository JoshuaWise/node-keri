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
import { digestSpecForCode } from '../cesr/codes';
import { encodeDigest, encodePublicKeyEd25519 } from '../cesr/encode';
import { CesrDigest } from '../cesr/qualified';
import { DEFAULT_DIGEST_CODE, runDigest } from '../crypto/digests';
import { KeriPublicKey, assertPublicKey } from '../crypto/keypair';
import { CanonicalJsonError, InvalidArgumentError } from '../profile/errors';
import { canonicalizeJson } from './canonical-json';
import { toCanonicalEvent } from './field-order';

/**
 * The placeholder for a SAID-bearing field is a run of `#` — a character
 * outside the base64url alphabet, conventional in KERI tooling — exactly as
 * long as the qb64 digest it stands in for. Its length therefore depends on
 * the digest algorithm (44 chars for a 256-bit code, 88 for a 512-bit one),
 * so the placeholder substitution preserves the event's byte length.
 */
export function saidPlaceholder(digestCode: string = DEFAULT_DIGEST_CODE): string {
	return '#'.repeat(digestSpecForCode(digestCode).fs);
}

/**
 * The SAID placeholder for the default (SHA-256) digest — 44 `#` characters.
 * Events digested with another algorithm need `saidPlaceholder(code)` instead.
 */
export const SAID_PLACEHOLDER: string = saidPlaceholder(DEFAULT_DIGEST_CODE);

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
		throw new InvalidArgumentError('event size must be a non-negative integer');
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
	readonly digestedBytes: Readonly<Uint8Array>;
}

/**
 * Compute the SAID for an event from its `fields`, under digest `digestCode`.
 *
 * `fields` carries the event body — `t`, the SAID-bearing fields already
 * present as a placeholder (`d`, plus `i` for inception, whose AID *is* the
 * SAID), and the remaining fields — in any order; `toCanonicalEvent` reorders
 * it into KERI canonical field order before serialization. `v` is omitted by
 * the caller and filled in here.
 *
 * `digestCode` selects the hash algorithm — defaulting to SHA-256. The `d`
 * placeholder the caller passes must be exactly as long as a qb64 digest under
 * that code (use `saidPlaceholder(digestCode)`); a mismatch is a programmer
 * error and throws, because it would break the byte-length accounting below.
 *
 * The two-pass version-string sizing is unchanged: both passes differ only in
 * the value of `v`, which is a fixed-length string, so the byte size is stable
 * across them.
 */
export function computeEventSaid(
	fields: Readonly<Record<string, unknown>>,
	digestCode: string = DEFAULT_DIGEST_CODE
): SaidComputation {
	const spec = digestSpecForCode(digestCode);
	if (typeof fields.d === 'string' && fields.d.length !== spec.fs) {
		throw new InvalidArgumentError(
			`SAID placeholder must be ${spec.fs} characters for digest code `
				+ `'${digestCode}', got ${fields.d.length}`
		);
	}

	// Pass 1 — placeholder version string. We only need the byte length here;
	// the bytes themselves are discarded.
	const draftBytes = canonicalizeJson(
		toCanonicalEvent({ ...fields, v: PLACEHOLDER_VERSION_STRING })
	);
	const versionString = formatKeriVersionString(draftBytes.length);

	// Pass 2 — real size in `v`, still placeholder SAIDs. These are the bytes
	// the SAID is computed over.
	const digestedBytes = canonicalizeJson(
		toCanonicalEvent({ ...fields, v: versionString })
	);
	if (digestedBytes.length !== draftBytes.length) {
		// Both passes use fixed-width substitutions, so the byte size cannot
		// change between them. If it did, our placeholder accounting is wrong
		// and the resulting SAID would not be reproducible.
		throw new CanonicalJsonError(
			'event byte size changed between SAID passes — invariant broken'
		);
	}

	const digest = runDigest(digestCode, digestedBytes);
	const said = encodeDigest(digestCode, digest);
	return { said, versionString, digestedBytes };
}

/**
 * Compute the pre-rotation commitment for `nextPublicKey`, under `digestCode`.
 *
 * The commitment is the qb64 digest of the *qb64-encoded* next public key.
 * Hashing the qualified form (rather than raw bytes) binds the commitment to
 * the key's algorithm as well as its bytes. `digestCode` defaults to SHA-256;
 * a rotation that reveals this key must recompute the commitment under the
 * *same* code, which it reads from the prior commitment itself — so a KEL may
 * carry commitments under different algorithms across rotations.
 */
export function deriveNextKeyCommitment(
	nextPublicKey: KeriPublicKey,
	digestCode: string = DEFAULT_DIGEST_CODE
): CesrDigest {
	assertPublicKey(nextPublicKey);
	const qb64 = encodePublicKeyEd25519(nextPublicKey.raw);
	return encodeDigest(digestCode, runDigest(digestCode, utf8Encode(qb64)));
}
