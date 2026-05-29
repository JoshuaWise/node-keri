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
import { DEFAULT_DIGEST_CODE } from '../crypto/digests';
import {
	KeriKeyPair,
	KeriPublicKey,
	assertPrivateKey,
	assertPublicKey,
} from '../crypto/keypair';
import { aidFromSaid, formatDidKeri } from '../did/did-keri';
import { TransferableKeriState } from '../kel/state';
import { computeEventSaid, deriveNextKeyCommitment, saidPlaceholder } from './digest';
import { signEvent } from './sign';
import { encodeEventFrame } from './stream';
import {
	InceptionConfigTraits,
	InceptionEvent,
	KERI_CONFIG_TRAIT_ESTABLISHMENT_ONLY,
} from './types';

export interface CreateInceptionInput {
	/** Current keypair: its public half is disclosed and its private half signs. */
	readonly currentKeyPair: KeriKeyPair;
	/** Public half of the next keypair — only the digest is committed now. */
	readonly nextPublicKey: KeriPublicKey;
	/**
	 * CESR digest code for this event's SAID and next-key commitment.
	 * Defaults to SHA-256 (`I`). Any code with a registered implementation
	 * (see `digestAlgorithms`) is accepted; an unavailable one throws.
	 */
	readonly digestCode?: string;
	/**
	 * Set the `EO` ("establishment only") configuration trait on the inception
	 * event. The resulting identifier accepts only establishment events
	 * (`icp`, `rot`) in its KEL — `interactIdentifier` and
	 * `createInteractionEvent` will refuse it, and replay rejects an `ixn`
	 * appended later. The trait is inception-only: it is set here and inherited
	 * unchanged by every later event of the KEL. Defaults to `false`.
	 */
	readonly establishmentOnly?: boolean;
}

export interface CreateInceptionResult {
	/** The signed inception event, as a CESR stream frame (the wire form). */
	readonly event: string;
	/** Replay-derived initial state. node-keri mints only transferable AIDs. */
	readonly state: TransferableKeriState;
}

export function createInceptionEvent(input: CreateInceptionInput): CreateInceptionResult {
	assertPublicKey(input.currentKeyPair.publicKey);
	assertPrivateKey(input.currentKeyPair.privateKey);
	assertPublicKey(input.nextPublicKey);

	const digestCode = input.digestCode ?? DEFAULT_DIGEST_CODE;
	const currentKeyQb64 = encodePublicKeyEd25519(input.currentKeyPair.publicKey.raw);
	const nextCommitment = deriveNextKeyCommitment(input.nextPublicKey, digestCode);

	// `c` carries `['EO']` only when the caller asked for an establishment-only
	// identifier — by default it is empty.
	const establishmentOnly = input.establishmentOnly === true;
	const configTraits: InceptionConfigTraits = establishmentOnly
		? ([KERI_CONFIG_TRAIT_ESTABLISHMENT_ONLY] as const)
		: ([] as const);

	// `d` and `i` are the SAID-bearing fields for inception: they hold the
	// fixed-length placeholder while the SAID is computed, then take the SAID
	// itself in the final event. Fields are listed in KERI canonical order.
	const placeholder = saidPlaceholder(digestCode);
	const partial = {
		t: 'icp' as const,
		d: placeholder,
		i: placeholder,
		s: '0',
		kt: '1' as const,
		k: [currentKeyQb64] as const,
		nt: '1' as const,
		n: [nextCommitment] as const,
		bt: '0' as const,
		b: [] as const,
		c: configTraits,
		a: [] as const,
	};

	const { said, versionString } = computeEventSaid(partial, digestCode);
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

	const frame = encodeEventFrame(signEvent(event, input.currentKeyPair.privateKey));

	const state: TransferableKeriState = {
		aid,
		did: formatDidKeri(aid),
		sequenceNumber: 0,
		lastEventDigest: said,
		currentPublicKey: currentKeyQb64,
		nextKeyCommitment: nextCommitment,
		transferable: true,
		eventType: 'icp',
		...(establishmentOnly ? { establishmentOnly: true as const } : {}),
	};

	return { event: frame, state };
}

// Re-export so that consumers building on top of inception don't have to
// reach into the digest module for what is conceptually a key-management op.
export { deriveNextKeyCommitment, saidPlaceholder, SAID_PLACEHOLDER } from './digest';
