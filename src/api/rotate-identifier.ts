/**
 * `rotateIdentifier` — the high-level entry point for rolling an
 * identifier's signing key forward.
 *
 * It wraps `createRotationEvent`. The distinctive part of its contract is
 * `currentPrivateKey`: this is the private half of the key being rotated
 * *to* — i.e. the pre-rotation key whose digest the previous event committed
 * as `n[0]`. Its public half is derived here and must reproduce that
 * commitment, a check `createRotationEvent` performs and will reject.
 */

import { bytesEqual } from '../bytes/compare';
import {
	KeriPrivateKey,
	KeriPublicKey,
	assertPublicKey,
	keyPairFromPrivateKey,
} from '../crypto/keypair';
import { createRotationEvent } from '../event/rotation';
import { KeriState, TransferableKeriState } from '../kel/state';
import { InvalidArgumentError } from '../profile/errors';

export interface RotateIdentifierInput {
	/** Trusted state from the prior event — output of a create/rotate/interact. */
	readonly state: KeriState;
	/**
	 * Private half of the key being rotated to. Its public half must hash to
	 * `state.nextKeyCommitment`; otherwise the rotation is rejected.
	 */
	readonly currentPrivateKey: KeriPrivateKey;
	/**
	 * Public half of the freshly chosen pre-rotation key for the *next*
	 * rotation. Only its digest is committed now; the caller keeps the matching
	 * private half to rotate again later.
	 */
	readonly nextPublicKey: KeriPublicKey;
	/**
	 * CESR digest code for the rotation event's SAID and new next-key
	 * commitment. Defaults to SHA-256 (`I`). The prior commitment is always
	 * re-checked under its own original algorithm, so KELs may mix codes.
	 */
	readonly digestCode?: string;
}

export interface RotateIdentifierResult {
	/** The signed rotation event, as a CESR stream frame (the wire form). */
	readonly event: string;
	/** Replay-equivalent state after applying the rotation. */
	readonly state: TransferableKeriState;
}

/** Rotate an identifier's signing key, revealing the pre-rotated key. */
export function rotateIdentifier(input: RotateIdentifierInput): RotateIdentifierResult {
	if (input === null || typeof input !== 'object') {
		throw new InvalidArgumentError('rotateIdentifier requires an input object');
	}
	// Assert before touching `.raw` below so a malformed key surfaces as
	// InvalidArgumentError rather than a TypeError.
	assertPublicKey(input.nextPublicKey);

	// `keyPairFromPrivateKey` asserts the argument is a KeriPrivateKey.
	const newCurrentKeyPair = keyPairFromPrivateKey(input.currentPrivateKey);

	// Same independence requirement as inception: the new signing key and the
	// freshly committed next key must differ, or pre-rotation buys nothing.
	if (bytesEqual(newCurrentKeyPair.publicKey.raw, input.nextPublicKey.raw)) {
		throw new InvalidArgumentError(
			'the rotated-to key and nextPublicKey must be distinct keys'
		);
	}

	const { event, state } = createRotationEvent({
		state: input.state,
		newCurrentKeyPair,
		nextPublicKey: input.nextPublicKey,
		digestCode: input.digestCode,
	});

	return { event, state };
}
