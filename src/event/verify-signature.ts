/**
 * Standalone signature verification for an event/qb64-key/qb64-signature
 * triple. KEL replay (Milestone 4) does the heavier work of binding a
 * signature to the *currently authoritative* key for an AID; this helper
 * just answers "did this exact key sign this exact event".
 */

import {
	decodeIndexedSignatureEd25519,
	decodeVerificationKeyEd25519,
} from '../cesr/decode';
import { CesrIndexedSignature, CesrPublicKey } from '../cesr/qualified';
import { verify } from '../crypto/ed25519';
import { publicKeyFromRaw } from '../crypto/keypair';
import { MalformedInputError } from '../profile/errors';
import { KeriEvent } from './types';
import { serializeEvent } from './sign';

/**
 * Verify indexed `signature` over the canonical bytes of `event` under
 * `publicKey`.
 *
 * `signature` is a CESR indexed signature (a "Siger"); only its raw 64 bytes
 * matter here, since the caller has already chosen which key to check against.
 * The index it carries is the replay verifier's concern — `verifyKel` checks
 * it points at key 0, the only key this single-key profile permits.
 *
 * Returns `false` (not throws) for cryptographic failure. A malformed CESR
 * code or length is a structural error and is thrown as MalformedInputError
 * by the decoders — we don't catch those because they indicate the caller
 * passed the wrong shape of input rather than an authentic-but-bad signature.
 */
export function verifyEventSignature(
	event: KeriEvent,
	publicKey: CesrPublicKey,
	signature: CesrIndexedSignature
): boolean {
	if (typeof publicKey !== 'string') {
		throw new MalformedInputError('publicKey must be a CESR-qualified string');
	}
	if (typeof signature !== 'string') {
		throw new MalformedInputError('signature must be a CESR-qualified string');
	}
	// `publicKey` may be a transferable (`D`) or non-transferable (`B`) key —
	// the latter is the signing key of a non-transferable inception event.
	const pkRaw = decodeVerificationKeyEd25519(publicKey);
	const sigRaw = decodeIndexedSignatureEd25519(signature).raw;
	const wrappedKey = publicKeyFromRaw(pkRaw);
	return verify(wrappedKey, serializeEvent(event), sigRaw);
}
