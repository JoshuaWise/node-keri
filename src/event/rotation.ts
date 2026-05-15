/**
 * Rotation event constructor.
 *
 * A rotation discloses the key that was previously *committed to* as the
 * next-key digest, and freshly commits to a new next-key. The rotation
 * event is signed by the new current key — i.e. the key being revealed.
 * KERI's pre-rotation guarantee is that the disclosed key, when hashed,
 * matches the prior commitment; this constructor enforces that invariant
 * at construction time so the resulting event is always self-consistent.
 */

import { encodePublicKeyEd25519 } from '../cesr/encode';
import { KeriKeyPair, KeriPublicKey, assertPrivateKey, assertPublicKey } from '../crypto/keypair';
import { KeriState } from '../kel/state';
import { InvalidArgumentError } from '../profile/errors';
import { SAID_PLACEHOLDER, computeEventSaid, deriveNextKeyCommitment } from './digest';
import { signEvent } from './sign';
import { RotationEvent, SignedKeriEvent } from './types';

export interface CreateRotationInput {
	/** Trusted state from the prior event (output of inception/rotation/ixn). */
	readonly state: KeriState;
	/** The new current keypair: its public key must match `state.nextKeyCommitment`. */
	readonly newCurrentKeyPair: KeriKeyPair;
	/** Public half of the freshly chosen next keypair. */
	readonly nextPublicKey: KeriPublicKey;
}

export interface CreateRotationResult {
	readonly signedEvent: SignedKeriEvent;
	readonly state: KeriState;
}

export function createRotationEvent(
	input: CreateRotationInput
): CreateRotationResult {
	assertPublicKey(input.newCurrentKeyPair.publicKey);
	assertPrivateKey(input.newCurrentKeyPair.privateKey);
	assertPublicKey(input.nextPublicKey);

	const newCurrentQb64 = encodePublicKeyEd25519(
		input.newCurrentKeyPair.publicKey.raw
	);
	const newCurrentCommitment = deriveNextKeyCommitment(
		input.newCurrentKeyPair.publicKey
	);
	if (newCurrentCommitment !== input.state.nextKeyCommitment) {
		// The disclosed key isn't the one that was pre-rotated to. Building
		// the event anyway would produce something `verifyKel` would reject;
		// fail fast so the caller can recover before persisting it anywhere.
		throw new InvalidArgumentError(
			'rotation key does not match the prior next-key commitment'
		);
	}

	const newNextCommitment = deriveNextKeyCommitment(input.nextPublicKey);
	const nextSeq = input.state.sequenceNumber + 1;
	if (!Number.isSafeInteger(nextSeq)) {
		throw new InvalidArgumentError('sequence number overflow');
	}

	// `d` holds the placeholder while the SAID is computed; fields are listed
	// in KERI canonical order.
	const partial = {
		t: 'rot' as const,
		d: SAID_PLACEHOLDER,
		i: input.state.aid,
		s: nextSeq.toString(16),
		p: input.state.lastEventDigest,
		kt: '1' as const,
		k: [newCurrentQb64] as const,
		nt: '1' as const,
		n: [newNextCommitment] as const,
		bt: '0' as const,
		br: [] as const,
		ba: [] as const,
		a: [] as const,
	};

	const { said, versionString } = computeEventSaid(partial);

	const event: RotationEvent = {
		v: versionString,
		t: 'rot',
		d: said,
		i: input.state.aid,
		s: partial.s,
		p: input.state.lastEventDigest,
		kt: partial.kt,
		k: partial.k,
		nt: partial.nt,
		n: partial.n,
		bt: partial.bt,
		br: partial.br,
		ba: partial.ba,
		a: partial.a,
	};

	const signed = signEvent(event, input.newCurrentKeyPair.privateKey);

	const newState: KeriState = {
		aid: input.state.aid,
		did: input.state.did,
		sequenceNumber: nextSeq,
		lastEventDigest: said,
		currentPublicKey: newCurrentQb64,
		nextKeyCommitment: newNextCommitment,
		transferable: true,
		eventType: 'rot',
	};

	return { signedEvent: signed, state: newState };
}
