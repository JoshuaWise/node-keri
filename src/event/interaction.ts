/**
 * Interaction event constructor.
 *
 * Interaction events advance the KEL without rotating keys: they anchor
 * arbitrary application data in `a` under the current signing authority.
 * The signing key must therefore match the AID's current public key —
 * a constructor-time check, in addition to the verifier-time check
 * Milestone 4 will perform on replay.
 */

import { encodePublicKeyEd25519 } from '../cesr/encode';
import { KeriKeyPair, assertPrivateKey, assertPublicKey } from '../crypto/keypair';
import { KeriState } from '../kel/state';
import { CanonicalJsonError, InvalidArgumentError } from '../profile/errors';
import { canonicalizeJson } from './canonical-json';
import { SAID_PLACEHOLDER, computeEventSaid } from './digest';
import { signEvent } from './sign';
import { InteractionEvent, SignedKeriEvent } from './types';

export interface CreateInteractionInput {
	readonly state: KeriState;
	/** Current keypair: must match `state.currentPublicKey`. */
	readonly currentKeyPair: KeriKeyPair;
	/**
	 * Optional anchored data. Each entry is canonicalized as JSON, so it must
	 * obey the canonical-JSON rules (no NaN, no functions, plain objects only,
	 * etc.). An empty `a` is permitted and is the right choice when the event
	 * is purely a "heartbeat" advancing the sequence.
	 */
	readonly data?: readonly unknown[];
}

export interface CreateInteractionResult {
	readonly signedEvent: SignedKeriEvent;
	readonly state: KeriState;
}

export function createInteractionEvent(
	input: CreateInteractionInput
): CreateInteractionResult {
	assertPublicKey(input.currentKeyPair.publicKey);
	assertPrivateKey(input.currentKeyPair.privateKey);

	const currentQb64 = encodePublicKeyEd25519(input.currentKeyPair.publicKey.raw);
	if (currentQb64 !== input.state.currentPublicKey) {
		throw new InvalidArgumentError(
			'interaction signing key does not match the current public key'
		);
	}

	const anchors: readonly unknown[] = input.data ?? [];
	if (!Array.isArray(anchors)) {
		throw new InvalidArgumentError('data must be an array');
	}
	// Validate that the anchors are canonical-JSON-serializable up front.
	// Without this the failure surfaces inside computeEventSaid as a
	// CanonicalJsonError, which is technically the right error code but
	// the call stack is harder to read. Doing it here lets callers
	// distinguish "my anchor is bad" from "library bug".
	try {
		canonicalizeJson(anchors);
	} catch (err) {
		if (err instanceof CanonicalJsonError) {
			throw new InvalidArgumentError(
				`interaction data is not canonical-JSON-serializable: ${err.message}`
			);
		}
		throw err;
	}

	const nextSeq = input.state.sequenceNumber + 1;
	if (!Number.isSafeInteger(nextSeq)) {
		throw new InvalidArgumentError('sequence number overflow');
	}

	// `d` holds the placeholder while the SAID is computed; fields are listed
	// in KERI canonical order.
	const partial = {
		t: 'ixn' as const,
		d: SAID_PLACEHOLDER,
		i: input.state.aid,
		s: nextSeq.toString(16),
		p: input.state.lastEventDigest,
		a: anchors,
	};

	const { said, versionString } = computeEventSaid(partial);

	const event: InteractionEvent = {
		v: versionString,
		t: 'ixn',
		d: said,
		i: input.state.aid,
		s: partial.s,
		p: input.state.lastEventDigest,
		a: anchors,
	};

	const signed = signEvent(event, input.currentKeyPair.privateKey);

	const newState: KeriState = {
		aid: input.state.aid,
		did: input.state.did,
		sequenceNumber: nextSeq,
		lastEventDigest: said,
		currentPublicKey: input.state.currentPublicKey,
		nextKeyCommitment: input.state.nextKeyCommitment,
		transferable: true,
		eventType: 'ixn',
	};

	return { signedEvent: signed, state: newState };
}
