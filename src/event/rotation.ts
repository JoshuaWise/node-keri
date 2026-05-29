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

import { digestCodeOf } from '../cesr/codes';
import { encodePublicKeyEd25519 } from '../cesr/encode';
import { DEFAULT_DIGEST_CODE } from '../crypto/digests';
import {
	KeriKeyPair,
	KeriPublicKey,
	assertPrivateKey,
	assertPublicKey,
} from '../crypto/keypair';
import { KeriState, TransferableKeriState } from '../kel/state';
import { InvalidArgumentError } from '../profile/errors';
import { computeEventSaid, deriveNextKeyCommitment, saidPlaceholder } from './digest';
import { signEvent } from './sign';
import { encodeEventFrame } from './stream';
import { RotationEvent } from './types';

export interface CreateRotationInput {
	/** Trusted state from the prior event (output of inception/rotation/ixn). */
	readonly state: KeriState;
	/** The new current keypair: its public key must match `state.nextKeyCommitment`. */
	readonly newCurrentKeyPair: KeriKeyPair;
	/** Public half of the freshly chosen next keypair. */
	readonly nextPublicKey: KeriPublicKey;
	/**
	 * CESR digest code for this event's SAID and *new* next-key commitment.
	 * Defaults to SHA-256 (`I`). The prior commitment being revealed is always
	 * re-checked under whatever code it was originally made with, so rotations
	 * may switch algorithms freely.
	 */
	readonly digestCode?: string;
}

export interface CreateRotationResult {
	/** The signed rotation event, as a CESR stream frame (the wire form). */
	readonly event: string;
	/** Replay-derived state after the rotation — always transferable. */
	readonly state: TransferableKeriState;
}

export function createRotationEvent(input: CreateRotationInput): CreateRotationResult {
	assertPublicKey(input.newCurrentKeyPair.publicKey);
	assertPrivateKey(input.newCurrentKeyPair.privateKey);
	assertPublicKey(input.nextPublicKey);

	// An identifier that committed to no next key cannot be rotated — whether
	// it never had one (a non-transferable AID) or gave it up (a deactivated
	// one). To deactivate a live identifier, use `createDeactivationEvent`.
	if (input.state.transferable === false) {
		throw new InvalidArgumentError(
			input.state.deactivated
				? 'a deactivated identifier cannot be rotated'
				: 'a non-transferable identifier cannot be rotated'
		);
	}

	const digestCode = input.digestCode ?? DEFAULT_DIGEST_CODE;
	const newCurrentQb64 = encodePublicKeyEd25519(input.newCurrentKeyPair.publicKey.raw);
	// The prior commitment must be reproduced under the algorithm it was
	// *originally* made with — read from the commitment's own CESR code — not
	// under the code chosen for this event.
	const priorCommitmentCode = digestCodeOf(input.state.nextKeyCommitment);
	const newCurrentCommitment = deriveNextKeyCommitment(
		input.newCurrentKeyPair.publicKey,
		priorCommitmentCode
	);
	if (newCurrentCommitment !== input.state.nextKeyCommitment) {
		// The disclosed key isn't the one that was pre-rotated to. Building
		// the event anyway would produce something `verifyKel` would reject;
		// fail fast so the caller can recover before persisting it anywhere.
		throw new InvalidArgumentError(
			'rotation key does not match the prior next-key commitment'
		);
	}

	const newNextCommitment = deriveNextKeyCommitment(input.nextPublicKey, digestCode);
	const nextSeq = input.state.sequenceNumber + 1;
	if (!Number.isSafeInteger(nextSeq)) {
		throw new InvalidArgumentError('sequence number overflow');
	}

	// `d` holds the placeholder while the SAID is computed; fields are listed
	// in KERI canonical order.
	const partial = {
		t: 'rot' as const,
		d: saidPlaceholder(digestCode),
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

	const { said, versionString } = computeEventSaid(partial, digestCode);

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

	const frame = encodeEventFrame(signEvent(event, input.newCurrentKeyPair.privateKey));

	const newState: TransferableKeriState = {
		aid: input.state.aid,
		did: input.state.did,
		sequenceNumber: nextSeq,
		lastEventDigest: said,
		currentPublicKey: newCurrentQb64,
		nextKeyCommitment: newNextCommitment,
		transferable: true,
		eventType: 'rot',
		// `EO` is set at inception and inherited unchanged — a rotation never
		// introduces or clears it. Forward whatever the prior state carried.
		...(input.state.establishmentOnly ? { establishmentOnly: true as const } : {}),
	};

	return { event: frame, state: newState };
}
