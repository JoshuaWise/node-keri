import { randomBytes as nodeRandomBytes } from 'node:crypto';
import { InvalidArgumentError } from '../profile/errors';

/** Cryptographically secure random bytes. Synchronous. */
export function randomBytes(size: number): Uint8Array {
	if (!Number.isInteger(size) || size < 0) {
		throw new InvalidArgumentError(
			'size must be a non-negative integer'
		);
	}
	return new Uint8Array(nodeRandomBytes(size));
}
