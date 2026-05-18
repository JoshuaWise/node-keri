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
import { DEFAULT_DIGEST_CODE } from '../crypto/digests';
import { KeriKeyPair, assertPrivateKey, assertPublicKey } from '../crypto/keypair';
import { KeriState, TransferableKeriState } from '../kel/state';
import { CanonicalJsonError, InvalidArgumentError } from '../profile/errors';
import { canonicalizeJson } from './canonical-json';
import { computeEventSaid, saidPlaceholder } from './digest';
import { signEvent } from './sign';
import { encodeEventFrame } from './stream';
import { InteractionEvent } from './types';

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
	/**
	 * CESR digest code for this event's SAID. Defaults to SHA-256 (`I`).
	 * Interaction events carry no next-key commitment, so this affects only
	 * the event's own `d`.
	 */
	readonly digestCode?: string;
}

export interface CreateInteractionResult {
	/** The signed interaction event, as a CESR stream frame (the wire form). */
	readonly event: string;
	/** Replay-derived state after the interaction — always transferable. */
	readonly state: TransferableKeriState;
}

export function createInteractionEvent(
	input: CreateInteractionInput
): CreateInteractionResult {
	assertPublicKey(input.currentKeyPair.publicKey);
	assertPrivateKey(input.currentKeyPair.privateKey);

	// A non-transferable identifier's KEL ends at inception: it cannot anchor
	// interaction events. (node-keri never mints one, but a verified state for
	// a non-transferable AID can still reach this constructor.)
	if (input.state.transferable === false) {
		throw new InvalidArgumentError(
			'a non-transferable identifier cannot anchor interaction events'
		);
	}

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
	const digestCode = input.digestCode ?? DEFAULT_DIGEST_CODE;
	const partial = {
		t: 'ixn' as const,
		d: saidPlaceholder(digestCode),
		i: input.state.aid,
		s: nextSeq.toString(16),
		p: input.state.lastEventDigest,
		a: anchors,
	};

	const { said, versionString } = computeEventSaid(partial, digestCode);

	const event: InteractionEvent = {
		v: versionString,
		t: 'ixn',
		d: said,
		i: input.state.aid,
		s: partial.s,
		p: input.state.lastEventDigest,
		a: anchors,
	};

	const frame = encodeEventFrame(signEvent(event, input.currentKeyPair.privateKey));

	const newState: TransferableKeriState = {
		aid: input.state.aid,
		did: input.state.did,
		sequenceNumber: nextSeq,
		lastEventDigest: said,
		currentPublicKey: input.state.currentPublicKey,
		nextKeyCommitment: input.state.nextKeyCommitment,
		transferable: true,
		eventType: 'ixn',
	};

	return { event: frame, state: newState };
}
