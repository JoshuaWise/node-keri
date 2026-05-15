/**
 * `createIdentifier` — the high-level entry point for minting a new
 * transferable `did:keri` identifier.
 *
 * It is a thin, ergonomic wrapper over `createInceptionEvent`: it supplies
 * fresh Ed25519 keypairs when the caller does not, and returns everything a
 * caller needs to keep — the DID, both keypairs, the signed inception event,
 * and the replay-derived initial state — in one object.
 *
 * The caller is responsible for storing the returned key material. The
 * library holds no state of its own.
 */

import { bytesEqual } from '../bytes/compare';
import {
	KeriKeyPair,
	assertPrivateKey,
	assertPublicKey,
	generateKeyPair,
} from '../crypto/keypair';
import { Aid, DidKeri } from '../did/did-keri';
import { createInceptionEvent } from '../event/inception';
import { SignedKeriEvent } from '../event/types';
import { KeriState } from '../kel/state';
import { InvalidArgumentError } from '../profile/errors';

export interface CreateIdentifierInput {
	/** Current signing keypair. A fresh one is generated when omitted. */
	readonly currentKeyPair?: KeriKeyPair;
	/** Pre-rotation keypair. A fresh one is generated when omitted. */
	readonly nextKeyPair?: KeriKeyPair;
}

export interface CreateIdentifierResult {
	readonly did: DidKeri;
	readonly aid: Aid;
	/** The current signing keypair — supplied or freshly generated. */
	readonly currentKeyPair: KeriKeyPair;
	/** The pre-rotation keypair — its private half is needed to rotate later. */
	readonly nextKeyPair: KeriKeyPair;
	readonly inceptionEvent: SignedKeriEvent;
	/** Replay-derived initial state (sequence 0). */
	readonly state: KeriState;
}

/**
 * Create a new `did:keri` identifier.
 *
 * Note on `metadata`: the suggested API shape lists an optional `metadata`
 * field, but inception events in the Direct JSON Profile carry no seals
 * (`a` is fixed empty), so there is nowhere to anchor it. Rather than accept
 * a parameter that silently does nothing, this profile omits it — anchor
 * application data with an interaction event instead.
 */
export function createIdentifier(
	input: CreateIdentifierInput = {}
): CreateIdentifierResult {
	if (input === null || typeof input !== 'object') {
		throw new InvalidArgumentError('createIdentifier requires an input object');
	}

	const currentKeyPair = input.currentKeyPair ?? generateKeyPair();
	const nextKeyPair = input.nextKeyPair ?? generateKeyPair();

	// Validate keypair shape before touching `.publicKey.raw` below, so a
	// malformed keypair surfaces as InvalidArgumentError rather than a
	// TypeError. `createInceptionEvent` re-asserts, but only after this point.
	assertPublicKey(currentKeyPair?.publicKey);
	assertPrivateKey(currentKeyPair?.privateKey);
	assertPublicKey(nextKeyPair?.publicKey);
	assertPrivateKey(nextKeyPair?.privateKey);

	// Pre-rotation is only meaningful if the next key is independent of the
	// current one: reusing the same key means the next-key digest reveals the
	// active signing key and a rotation commits to nothing new. The event
	// constructors do not enforce this, so the ergonomic API does.
	if (bytesEqual(currentKeyPair.publicKey.raw, nextKeyPair.publicKey.raw)) {
		throw new InvalidArgumentError(
			'currentKeyPair and nextKeyPair must be distinct keys'
		);
	}

	const { signedEvent, state } = createInceptionEvent({
		currentKeyPair,
		nextPublicKey: nextKeyPair.publicKey,
	});

	return {
		did: state.did,
		aid: state.aid,
		currentKeyPair,
		nextKeyPair,
		inceptionEvent: signedEvent,
		state,
	};
}
