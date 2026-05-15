import { Buffer } from 'node:buffer';
import { MalformedInputError } from '../profile/errors';

/**
 * Base64url encode without padding. Output uses the URL-safe alphabet
 * (`A-Z a-z 0-9 - _`) and never contains `=`.
 */
export function base64urlEncode(bytes: Uint8Array): string {
	return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString(
		'base64url'
	);
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
