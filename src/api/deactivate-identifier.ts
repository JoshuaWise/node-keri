/**
 * `deactivateIdentifier` — the high-level entry point for permanently
 * abandoning a `did:keri` identifier.
 *
 * Per the `did:keri` method, deactivation is a rotation to zero forward
 * (next) controlling keys: it terminates the ability to recover the identifier
 * and marks it abandoned. After it, the KEL is closed — `verifyIdentifier` rejects
 * any further event, and `verifySignatureWithDid` no longer trusts the DID.
 *
 * It wraps `createDeactivationEvent`. Like `rotateIdentifier`, it takes the
 * bare private key of the key being revealed — the pre-rotation key whose
 * digest the previous event committed as `n[0]` — and derives the public half
 * itself, keeping the high-level API uniform.
 *
 * This step is irreversible. There is no inverse operation.
 */

import { PrivateKey, keyPairFromPrivateKey } from '../crypto/keypair';
import { createDeactivationEvent } from '../event/deactivation';
import { DeactivatedKeriState, KeriState } from '../kel/state';
import { InvalidArgumentError } from '../profile/errors';

export interface DeactivateIdentifierInput {
	/** Trusted state from the prior event — output of a create/rotate/interact. */
	readonly state: KeriState;
	/**
	 * Private half of the key being rotated to. Its public half must hash to
	 * `state.nextKeyCommitment`; otherwise the deactivation is rejected.
	 */
	readonly newPrivateKey: PrivateKey;
	/**
	 * CESR digest code for the deactivation event's SAID. Defaults to
	 * SHA-256 (`I`). A deactivation commits to no next key, so this affects
	 * only the event's own `d`.
	 */
	readonly digestCode?: string;
}

export interface DeactivateIdentifierResult {
	/** The signed deactivation event, as a CESR stream frame (the wire form). */
	readonly event: string;
	/** Replay-equivalent state after the deactivation — always deactivated. */
	readonly state: DeactivatedKeriState;
}

/**
 * Permanently deactivate an identifier by rotating to zero next keys.
 *
 * The returned `event` is the final frame of the identifier's KEL; append it
 * as the last event. The returned `state` has `deactivated === true`
 * and `transferable === false` — it cannot be rotated, interacted with, or
 * deactivated again.
 */
export function deactivateIdentifier(
	input: DeactivateIdentifierInput
): DeactivateIdentifierResult {
	if (input === null || typeof input !== 'object') {
		throw new InvalidArgumentError('deactivateIdentifier requires an input object');
	}

	// `keyPairFromPrivateKey` asserts the argument is a PrivateKey; the
	// event constructor then re-checks the derived public half against
	// `state.nextKeyCommitment`.
	const revealedKeyPair = keyPairFromPrivateKey(input.newPrivateKey);

	const { event, state } = createDeactivationEvent({
		state: input.state,
		revealedKeyPair,
		digestCode: input.digestCode,
	});

	return { event, state };
}
