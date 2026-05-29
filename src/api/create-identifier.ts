/**
 * `createIdentifier` — the high-level entry point for minting a new
 * transferable `did:keri` identifier.
 *
 * It is a thin, ergonomic wrapper over `createInceptionEvent`: the caller
 * supplies the minimal key material the inception event actually consumes —
 * the current signing key's *private* half (its public half is derived) and
 * the pre-rotation key's *public* half (only its digest is committed) — and
 * gets back the DID, the signed inception event, and the replay-derived
 * initial state.
 *
 * The caller already holds the key material it passed in, so this returns
 * none of its own. Keep the current private key to sign with and the
 * pre-rotation private key to rotate to later. The library holds no state.
 */

import { bytesEqual } from '../bytes/compare';
import {
	KeriPrivateKey,
	KeriPublicKey,
	assertPublicKey,
	keyPairFromPrivateKey,
} from '../crypto/keypair';
import { Aid, DidKeri } from '../did/did-keri';
import { createInceptionEvent } from '../event/inception';
import { TransferableKeriState } from '../kel/state';
import { InvalidArgumentError } from '../profile/errors';

export interface CreateIdentifierInput {
	/**
	 * Private half of the current signing key. Required — its public half is
	 * derived here and disclosed as `k[0]`, and it signs the inception event.
	 */
	readonly currentPrivateKey: KeriPrivateKey;
	/**
	 * Public half of the pre-rotation key. Required — only its digest is
	 * committed now (`n[0]`); the caller keeps the matching private half to
	 * rotate to later.
	 */
	readonly nextPublicKey: KeriPublicKey;
	/**
	 * Mint an *establishment-only* identifier — inception sets the `EO`
	 * configuration trait and the resulting KEL will accept only `icp` and
	 * `rot` events. `interactIdentifier` will refuse the identifier from then
	 * on, and an `ixn` appended out of band is rejected on replay. Defaults
	 * to `false`.
	 */
	readonly establishmentOnly?: boolean;
	/**
	 * CESR digest code for the inception event's SAID, AID, and next-key
	 * commitment. Defaults to SHA-256 (`I`). Pass another code — see
	 * `DIGEST_CODES` and `digestAlgorithms` — to mint an identifier under a
	 * different hash; requesting an unavailable algorithm throws.
	 */
	readonly digestCode?: string;
}

export interface CreateIdentifierResult {
	readonly did: DidKeri;
	readonly aid: Aid;
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
export function createIdentifier(input: CreateIdentifierInput): CreateIdentifierResult {
	if (input === null || typeof input !== 'object') {
		throw new InvalidArgumentError('createIdentifier requires an input object');
	}

	// Derive the current keypair from its private half. `keyPairFromPrivateKey`
	// asserts the argument is a KeriPrivateKey, so a missing or malformed
	// current key surfaces as InvalidArgumentError here.
	const currentKeyPair = keyPairFromPrivateKey(input.currentPrivateKey);
	// Assert before touching `.raw` below so a malformed next key likewise
	// surfaces as InvalidArgumentError rather than a TypeError.
	assertPublicKey(input.nextPublicKey);

	// Pre-rotation is only meaningful if the next key is independent of the
	// current one: reusing the same key means the next-key digest reveals the
	// active signing key and a rotation commits to nothing new. The event
	// constructors do not enforce this, so the ergonomic API does.
	if (bytesEqual(currentKeyPair.publicKey.raw, input.nextPublicKey.raw)) {
		throw new InvalidArgumentError(
			'currentPrivateKey and nextPublicKey must be distinct keys'
		);
	}

	const { event, state } = createInceptionEvent({
		currentKeyPair,
		nextPublicKey: input.nextPublicKey,
		establishmentOnly: input.establishmentOnly,
		digestCode: input.digestCode,
	});

	return {
		did: state.did,
		aid: state.aid,
		inceptionEvent: event,
		state,
	};
}
