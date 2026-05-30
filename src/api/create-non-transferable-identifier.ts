/**
 * `createNonTransferableIdentifier` — mint a non-transferable `did:keri`
 * identifier.
 *
 * A non-transferable identifier is a *basic prefix*: the AID **is** the
 * controller's `B`-coded Ed25519 public key. It is self-certifying — there is
 * no inception event and no KEL at all — and it can never rotate, so there is
 * no pre-rotation commitment and nothing to sign at creation. The controller
 * keeps the matching private key to sign messages with (`createSignature`),
 * which counterparties verify with `verifySignature` / `verifySignatureWithDid`
 * passing the **empty string** `''` for the KEL.
 *
 * Contrast `createIdentifier`, which mints a *transferable* AID with a signed
 * inception event and a replayable KEL. This function consumes only the public
 * key — that is all a basic prefix commits to — and returns no event.
 */

import { encodeNonTransferablePublicKeyEd25519 } from '../cesr/encode';
import {
	PublicKey,
	assertPublicKey,
	rawPublicKey,
} from '../crypto/keypair';
import { Aid, DidKeri, aidFromNonTransferableKey, formatDidKeri } from '../did/did-keri';
import { NonTransferableKeriState } from '../kel/state';
import { InvalidArgumentError } from '../profile/errors';

export interface CreateNonTransferableIdentifierInput {
	/**
	 * Public half of the controlling key. The AID is derived directly from it —
	 * a basic prefix is self-certifying — and the caller keeps the matching
	 * private half to sign with. (No private key is consumed here: minting a
	 * non-transferable identifier signs nothing.)
	 */
	readonly publicKey: PublicKey;
}

export interface CreateNonTransferableIdentifierResult {
	readonly did: DidKeri;
	readonly aid: Aid;
	/**
	 * Replay-equivalent state for the identifier. It has `transferable: false`
	 * and carries no event-derived fields — there is no KEL. It is the same
	 * state `verifyIdentifier` / `verifyDid` reconstruct for this AID from the
	 * empty-string "no KEL" value, so it may be treated as trusted in-process.
	 */
	readonly state: NonTransferableKeriState;
}

/**
 * Mint a non-transferable `did:keri` identifier from its controlling public
 * key. There is no KEL: verify or resolve the result by passing `''` as the
 * KEL.
 */
export function createNonTransferableIdentifier(
	input: CreateNonTransferableIdentifierInput
): CreateNonTransferableIdentifierResult {
	if (input === null || typeof input !== 'object') {
		throw new InvalidArgumentError(
			'createNonTransferableIdentifier requires an input object'
		);
	}
	// Surface a missing or malformed key as InvalidArgumentError before use.
	assertPublicKey(input.publicKey);

	// The AID *is* the `B`-coded basic prefix of the key; `currentPublicKey` is
	// that same qb64 string — a non-transferable AID is its own signing key.
	const cesrKey = encodeNonTransferablePublicKeyEd25519(rawPublicKey(input.publicKey));
	const aid = aidFromNonTransferableKey(cesrKey);
	const did = formatDidKeri(aid);

	const state: NonTransferableKeriState = {
		aid,
		did,
		lastSequenceNumber: 0,
		currentPublicKey: cesrKey,
		transferable: false,
		deactivated: false,
	};

	return { did, aid, state };
}
