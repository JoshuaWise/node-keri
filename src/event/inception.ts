/**
 * Inception event constructor.
 *
 * Inception establishes a new transferable AID. The event commits to:
 *   - the current signing key (`k[0]`),
 *   - the digest of the next signing key (`n[0]`, the pre-rotation),
 * and is signed by the current key. The event's SAID *is* the AID — both
 * `d` and `i` get the same self-addressing digest.
 */

import { encodePublicKeyEd25519 } from '../cesr/encode';
import { KeriKeyPair, KeriPublicKey, assertPrivateKey, assertPublicKey } from '../crypto/keypair';
import { aidFromSaid, formatDidKeri } from '../did/did-keri';
import { KeriState } from '../kel/state';
import {
	SAID_PLACEHOLDER,
	computeEventSaid,
	deriveNextKeyCommitment,
} from './digest';
import { signEvent } from './sign';
import { InceptionEvent, SignedKeriEvent } from './types';

export interface CreateInceptionInput {
	/** Current keypair: its public half is disclosed and its private half signs. */
	readonly currentKeyPair: KeriKeyPair;
	/** Public half of the next keypair — only the digest is committed now. */
	readonly nextPublicKey: KeriPublicKey;
}

export interface CreateInceptionResult {
	readonly signedEvent: SignedKeriEvent;
	readonly state: KeriState;
}

export function createInceptionEvent(
	input: CreateInceptionInput
): CreateInceptionResult {
	assertPublicKey(input.currentKeyPair.publicKey);
	assertPrivateKey(input.currentKeyPair.privateKey);
	assertPublicKey(input.nextPublicKey);

	const currentKeyQb64 = encodePublicKeyEd25519(
		input.currentKeyPair.publicKey.raw
	);
	const nextCommitment = deriveNextKeyCommitment(input.nextPublicKey);

	// `d` and `i` are the SAID-bearing fields for inception: they hold the
	// fixed-length placeholder while the SAID is computed, then take the SAID
	// itself in the final event. Fields are listed in KERI canonical order.
	const partial = {
		t: 'icp' as const,
		d: SAID_PLACEHOLDER,
		i: SAID_PLACEHOLDER,
		s: '0',
		kt: '1' as const,
		k: [currentKeyQb64] as const,
		nt: '1' as const,
		n: [nextCommitment] as const,
		bt: '0' as const,
		b: [] as const,
		c: [] as const,
		a: [] as const,
	};

	const { said, versionString } = computeEventSaid(partial);
	const aid = aidFromSaid(said);

	const event: InceptionEvent = {
		v: versionString,
		t: 'icp',
		d: said,
		i: aid, // for inception, the AID *is* the SAID by construction
		s: partial.s,
		kt: partial.kt,
		k: partial.k,
		nt: partial.nt,
		n: partial.n,
		bt: partial.bt,
		b: partial.b,
		c: partial.c,
		a: partial.a,
	};

	const signed = signEvent(event, input.currentKeyPair.privateKey);

	const state: KeriState = {
		aid,
		did: formatDidKeri(aid),
		sequenceNumber: 0,
		lastEventDigest: said,
		currentPublicKey: currentKeyQb64,
		nextKeyCommitment: nextCommitment,
		transferable: true,
		eventType: 'icp',
	};

	return { signedEvent: signed, state };
}

// Re-export so that consumers building on top of inception don't have to
// reach into the digest module for what is conceptually a key-management op.
export { deriveNextKeyCommitment, SAID_PLACEHOLDER };
