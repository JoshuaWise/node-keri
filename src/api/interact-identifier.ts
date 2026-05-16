/**
 * `interactIdentifier` — the high-level entry point for anchoring data to an
 * identifier with an interaction event.
 *
 * It wraps `createInteractionEvent`. Like `rotateIdentifier`, it accepts the
 * bare private key of the currently authoritative signing key and derives the
 * public half itself — so the high-level API is uniform: every wrapper takes
 * a `currentPrivateKey` and returns its event under a `*Event`-named field,
 * never a full keypair and never the generic `signedEvent`.
 */

import { KeriPrivateKey, keyPairFromPrivateKey } from '../crypto/keypair';
import { createInteractionEvent } from '../event/interaction';
import { SignedKeriEvent } from '../event/types';
import { KeriState } from '../kel/state';
import { InvalidArgumentError } from '../profile/errors';

export interface InteractIdentifierInput {
	/** Trusted state from the prior event — output of a create/rotate/interact. */
	readonly state: KeriState;
	/**
	 * Private half of the currently authoritative signing key. Its public half
	 * must equal `state.currentPublicKey`; otherwise the interaction is rejected.
	 */
	readonly currentPrivateKey: KeriPrivateKey;
	/** Optional anchored data; each entry must be canonical-JSON-serializable. */
	readonly data?: readonly unknown[];
	/**
	 * CESR digest code for the interaction event's SAID. Defaults to
	 * SHA-256 (`I`).
	 */
	readonly digestCode?: string;
}

export interface InteractIdentifierResult {
	readonly interactionEvent: SignedKeriEvent;
	/** Replay-equivalent state after applying the interaction. */
	readonly state: KeriState;
}

/** Anchor data to an identifier with an interaction event. */
export function interactIdentifier(
	input: InteractIdentifierInput
): InteractIdentifierResult {
	if (input === null || typeof input !== 'object') {
		throw new InvalidArgumentError('interactIdentifier requires an input object');
	}

	// `keyPairFromPrivateKey` asserts the argument is a KeriPrivateKey; the
	// event constructor then re-checks the derived public half against
	// `state.currentPublicKey`.
	const currentKeyPair = keyPairFromPrivateKey(input.currentPrivateKey);

	const { signedEvent, state } = createInteractionEvent({
		state: input.state,
		currentKeyPair,
		data: input.data,
		digestCode: input.digestCode,
	});

	return { interactionEvent: signedEvent, state };
}
