/**
 * Deactivation event constructor.
 *
 * Deactivating a `did:keri` identifier is, mechanically, a rotation that
 * commits to no next key: `nt` is `"0"` and `n` is empty. It still reveals the
 * pre-rotated key in `k` and is signed by it — exactly like an ordinary
 * rotation, so the event is authorized by the key the prior event committed
 * to — but because it commits to nothing, no further event can ever extend the
 * KEL. The identifier is permanently abandoned: its recovery path is gone.
 *
 * This mirrors `createRotationEvent`; the difference is that there is no
 * `nextPublicKey` (there is no next key) and the resulting state is a
 * `DeactivatedKeriState` rather than a `TransferableKeriState`.
 */

import { digestCodeOf } from '../cesr/codes';
import { encodePublicKeyEd25519 } from '../cesr/encode';
import { DEFAULT_DIGEST_CODE } from '../crypto/digests';
import { KeriKeyPair, assertPrivateKey, assertPublicKey } from '../crypto/keypair';
import { DeactivatedKeriState, KeriState } from '../kel/state';
import { InvalidArgumentError } from '../profile/errors';
import { computeEventSaid, deriveNextKeyCommitment, saidPlaceholder } from './digest';
import { signEvent } from './sign';
import { encodeEventFrame } from './stream';
import { DeactivationEvent } from './types';

export interface CreateDeactivationInput {
	/** Trusted state from the prior event (output of inception/rotation/ixn). */
	readonly state: KeriState;
	/**
	 * The pre-rotated keypair being revealed: its public key must match
	 * `state.nextKeyCommitment`, and its private half signs the event — the
	 * same key an ordinary rotation would reveal.
	 */
	readonly revealedKeyPair: KeriKeyPair;
	/**
	 * CESR digest code for this event's SAID. Defaults to SHA-256 (`I`). A
	 * deactivation commits to no next key, so this affects only the event's
	 * own `d`. The prior commitment being revealed is re-checked under whatever
	 * code it was originally made with.
	 */
	readonly digestCode?: string;
}

export interface CreateDeactivationResult {
	/** The signed deactivation event, as a CESR stream frame (the wire form). */
	readonly event: string;
	/** Replay-derived state after the deactivation — always deactivated. */
	readonly state: DeactivatedKeriState;
}

export function createDeactivationEvent(
	input: CreateDeactivationInput
): CreateDeactivationResult {
	assertPublicKey(input.revealedKeyPair.publicKey);
	assertPrivateKey(input.revealedKeyPair.privateKey);

	// Only a transferable, still-live identifier can be deactivated. A
	// non-transferable AID committed to no next key at inception and a
	// deactivated one already committed to none — neither can rotate, and
	// deactivation is a rotation.
	if (input.state.transferable === false) {
		throw new InvalidArgumentError(
			input.state.deactivated
				? 'this identifier is already deactivated'
				: 'a non-transferable identifier cannot be deactivated'
		);
	}

	const digestCode = input.digestCode ?? DEFAULT_DIGEST_CODE;
	const revealedQb64 = encodePublicKeyEd25519(input.revealedKeyPair.publicKey.raw);
	// The revealed key must reproduce the prior next-key commitment, recomputed
	// under the algorithm that commitment names in its own CESR code.
	const priorCommitmentCode = digestCodeOf(input.state.nextKeyCommitment);
	const revealedCommitment = deriveNextKeyCommitment(
		input.revealedKeyPair.publicKey,
		priorCommitmentCode
	);
	if (revealedCommitment !== input.state.nextKeyCommitment) {
		// The disclosed key isn't the one that was pre-rotated to. Building the
		// event anyway would produce something `verifyKel` would reject; fail
		// fast so the caller can recover before persisting it anywhere.
		throw new InvalidArgumentError(
			'deactivation key does not match the prior next-key commitment'
		);
	}

	const nextSeq = input.state.lastSequenceNumber + 1;
	if (!Number.isSafeInteger(nextSeq)) {
		throw new InvalidArgumentError('sequence number overflow');
	}

	// `d` holds the placeholder while the SAID is computed; fields are listed
	// in KERI canonical order. `nt`/`n` are empty — the deactivation marker.
	const partial = {
		t: 'rot' as const,
		d: saidPlaceholder(digestCode),
		i: input.state.aid,
		s: nextSeq.toString(16),
		p: input.state.lastEventDigest,
		kt: '1' as const,
		k: [revealedQb64] as const,
		nt: '0' as const,
		n: [] as const,
		bt: '0' as const,
		br: [] as const,
		ba: [] as const,
		a: [] as const,
	};

	const { said, versionString } = computeEventSaid(partial, digestCode);

	const event: DeactivationEvent = {
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

	const frame = encodeEventFrame(signEvent(event, input.revealedKeyPair.privateKey));

	const newState: DeactivatedKeriState = {
		aid: input.state.aid,
		did: input.state.did,
		lastSequenceNumber: nextSeq,
		lastEventType: 'rot',
		lastEventDigest: said,
		transferable: false,
		deactivated: true,
		// `EO` is set at inception and never changes — preserve it through
		// deactivation for completeness even though the KEL has now closed.
		establishmentOnly: input.state.establishmentOnly,
	};

	return { event: frame, state: newState };
}
