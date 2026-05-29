import { createHash } from 'node:crypto';
import { SHA256_DIGEST_BYTES } from '../profile/constants';

/** SHA-256 of `input`. Always 32 bytes. */
export function sha256(input: Readonly<Uint8Array>): Uint8Array {
	const out = new Uint8Array(createHash('sha256').update(input).digest());
	// Defensive: createHash should always produce a 32-byte digest. If a
	// future Node release changes that, fail loudly rather than producing
	// truncated commitments.
	if (out.length !== SHA256_DIGEST_BYTES) {
		throw new Error('sha256 digest length mismatch');
	}
	return out;
}
