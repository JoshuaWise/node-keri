/**
 * Standalone signature verification for an event/qb64-key/qb64-signature
 * triple. KEL replay (Milestone 4) does the heavier work of binding a
 * signature to the *currently authoritative* key for an AID; this helper
 * just answers "did this exact key sign this exact event".
 */

import { decodePublicKeyEd25519, decodeSignatureEd25519 } from '../cesr/decode';
import { CesrPublicKey, CesrSignature } from '../cesr/qualified';
import { verify } from '../crypto/ed25519';
import { publicKeyFromRaw } from '../crypto/keypair';
import { MalformedInputError } from '../profile/errors';
import { KeriEvent } from './types';
import { serializeEvent } from './sign';

/**
 * Verify `signature` over the canonical bytes of `event` under `publicKey`.
 *
 * Returns `false` (not throws) for cryptographic failure. A malformed CESR
 * code or length is a structural error and is thrown as MalformedInputError
 * by the decoders — we don't catch those because they indicate the caller
 * passed the wrong shape of input rather than an authentic-but-bad signature.
 */
export function verifyEventSignature(
	event: KeriEvent,
	publicKey: CesrPublicKey,
	signature: CesrSignature
): boolean {
	if (typeof publicKey !== 'string') {
		throw new MalformedInputError('publicKey must be a CESR-qualified string');
	}
	if (typeof signature !== 'string') {
		throw new MalformedInputError('signature must be a CESR-qualified string');
	}
	const pkRaw = decodePublicKeyEd25519(publicKey);
	const sigRaw = decodeSignatureEd25519(signature);
	const wrappedKey = publicKeyFromRaw(pkRaw);
	return verify(wrappedKey, serializeEvent(event), sigRaw);
}
