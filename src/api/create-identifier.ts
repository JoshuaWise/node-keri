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
import { TransferableKeriState } from '../kel/state';
import { InvalidArgumentError } from '../profile/errors';

export interface CreateIdentifierInput {
	/** Current signing keypair. A fresh one is generated when omitted. */
	readonly currentKeyPair?: KeriKeyPair;
	/** Pre-rotation keypair. A fresh one is generated when omitted. */
	readonly nextKeyPair?: KeriKeyPair;
	/**
	 * CESR digest code for the inception event's SAID, AID, and next-key
	 * commitment. Defaults to SHA-256 (`I`). Pass another code — see
	 * `DIGEST_CODES` and `digestAlgorithms` — to mint an identifier under a
	 * different hash; requesting an unavailable algorithm throws.
	 */
	readonly digestCode?: string;
	/**
	 * Mint an *establishment-only* identifier — inception sets the `EO`
	 * configuration trait and the resulting KEL will accept only `icp` and
	 * `rot` events. `interactIdentifier` will refuse the identifier from then
	 * on, and an `ixn` appended out of band is rejected on replay. Defaults
	 * to `false`.
	 */
	readonly establishmentOnly?: boolean;
}

export interface CreateIdentifierResult {
	readonly did: DidKeri;
	readonly aid: Aid;
	/** The current signing keypair — supplied or freshly generated. */
	readonly currentKeyPair: KeriKeyPair;
	/** The pre-rotation keypair — its private half is needed to rotate later. */
	readonly nextKeyPair: KeriKeyPair;
	/** The signed inception event, as a CESR stream frame — the KEL's wire form. */
	readonly inceptionEvent: string;
	/** Replay-derived initial state (sequence 0) — always transferable. */
	readonly state: TransferableKeriState;
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

	const { event, state } = createInceptionEvent({
		currentKeyPair,
		nextPublicKey: nextKeyPair.publicKey,
		digestCode: input.digestCode,
		establishmentOnly: input.establishmentOnly,
	});

	return {
		did: state.did,
		aid: state.aid,
		currentKeyPair,
		nextKeyPair,
		inceptionEvent: event,
		state,
	};
}
