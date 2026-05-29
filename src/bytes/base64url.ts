import { Buffer } from 'node:buffer';
import { MalformedInputError } from '../profile/errors';

/**
 * Base64url encode without padding. Output uses the URL-safe alphabet
 * (`A-Z a-z 0-9 - _`) and never contains `=`.
 */
export function base64urlEncode(bytes: Readonly<Uint8Array>): string {
	return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString(
		'base64url'
	);
}

/**
 * The 64-character base64url alphabet, in value order. Index `i` is the
 * character for the 6-bit value `i`. Used by `intToB64` / `b64ToInt`, which
 * encode small integers — CESR signature/counter indices — as base64 text,
 * and by the CESR digest registry as the character set of every code.
 */
export const B64_ALPHABET =
	'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/**
 * Encode a non-negative integer as exactly `length` base64url characters,
 * most-significant character first.
 *
 * This is the CESR convention for the "soft" (variable) part of a code — for
 * example the index embedded in an indexed signature, or the count in a
 * counter. Throws `MalformedInputError` when `value` is negative, non-integer,
 * or too large to fit in `length` characters (`64 ** length`).
 */
export function intToB64(value: number, length: number): string {
	if (!Number.isInteger(value) || value < 0) {
		throw new MalformedInputError('intToB64 requires a non-negative integer');
	}
	if (!Number.isInteger(length) || length < 1) {
		throw new MalformedInputError('intToB64 length must be a positive integer');
	}
	let remaining = value;
	let out = '';
	for (let i = 0; i < length; i++) {
		out = B64_ALPHABET[remaining & 0x3f] + out;
		remaining = Math.floor(remaining / 64);
	}
	if (remaining !== 0) {
		throw new MalformedInputError(
			`value ${value} does not fit in ${length} base64url character(s)`
		);
	}
	return out;
}

/**
 * Decode a base64url string back into the integer `intToB64` would have
 * produced it from. Throws `MalformedInputError` on any non-alphabet
 * character or an empty string.
 */
export function b64ToInt(text: string): number {
	if (typeof text !== 'string' || text.length === 0) {
		throw new MalformedInputError('b64ToInt requires a non-empty string');
	}
	let value = 0;
	for (const ch of text) {
		const digit = B64_ALPHABET.indexOf(ch);
		if (digit < 0) {
			throw new MalformedInputError(`invalid base64url character '${ch}'`);
		}
		value = value * 64 + digit;
	}
	return value;
}

/**
 * Strict base64url decode. Rejects:
 *   - any character outside `A-Z a-z 0-9 - _`
 *   - padding (`=`)
 *   - inputs whose length implies trailing garbage bits (e.g. a single
 *     character cannot encode any byte)
 */
export function base64urlDecode(encoded: string): Uint8Array {
	if (typeof encoded !== 'string') {
		throw new MalformedInputError('base64url input must be a string');
	}
	if (!/^[A-Za-z0-9_-]*$/.test(encoded)) {
		throw new MalformedInputError('invalid base64url character');
	}
	if (encoded.length % 4 === 1) {
		throw new MalformedInputError('invalid base64url length');
	}
	const bytes = new Uint8Array(Buffer.from(encoded, 'base64url'));
	// Round-trip protects against truncated final group: e.g. a 2-char input
	// where the trailing bits of the second character are nonzero would
	// silently lose information through Buffer's lenient decoder.
	const reEncoded = Buffer.from(bytes).toString('base64url');
	if (reEncoded !== encoded) {
		throw new MalformedInputError('non-canonical base64url encoding');
	}
	return bytes;
}
