/**
 * `verifyIdentifier` — the public entry point for verifying an identifier's
 * key state.
 *
 * It enforces the *argument* contract (throwing `InvalidArgumentError` for a
 * caller that passes the wrong shape entirely) and then verifies:
 *   - a non-transferable AID given the empty-string "no KEL" value resolves
 *     straight from its self-certifying `B`-coded prefix — the AID *is* the
 *     signing key, so there are no events to replay; or
 *   - otherwise the KEL is replayed from inception by `replayKel`, which
 *     returns a discriminated result for every data-level failure.
 *
 * The split mirrors the error policy of the library: throwing is reserved for
 * programmer errors, while anything that could legitimately arrive from an
 * untrusted source — a malformed, tampered, reordered, or hostile KEL — is a
 * `{ ok: false, error }` result the caller is expected to handle.
 *
 * `verifyDid` is the DID-level counterpart: it parses a `did:keri` DID down to
 * its AID and delegates here, so the empty-string "no KEL" handling for a
 * non-transferable identifier is shared by both.
 */

import { decodeNonTransferablePublicKeyEd25519 } from '../cesr/decode';
import { CesrPublicKey } from '../cesr/qualified';
import { Aid, formatDidKeri } from '../did/did-keri';
import { NonTransferableKeriState } from '../kel/state';
import { InvalidArgumentError, MalformedInputError } from '../profile/errors';
import { VerifyIdentifierResult, replayKel } from '../kel/replay';

export type { VerifyIdentifierResult } from '../kel/replay';

export interface VerifyIdentifierInput {
	/** The identifier whose latest key state to reconstruct and verify. */
	readonly aid: Aid;
	/**
	 * The full key event log as a CESR stream — the event frames, inception
	 * first, concatenated in order. Build one by joining the wire-form events
	 * returned by `createIdentifier` / `rotateIdentifier` / `interactOnIdentifier`.
	 *
	 * The **empty string** `''` stands for "no KEL": valid only for a
	 * self-certifying non-transferable AID, whose key *is* the AID. A
	 * transferable AID must supply a real, non-empty KEL (an empty one is
	 * reported as `EMPTY_KEL`).
	 */
	readonly kel: string;
}

/**
 * Verify an identifier and reconstruct its latest authoritative state.
 *
 * On success the returned `state` is the only `KeriState` in the library a
 * caller may treat as verified — it was derived solely by replaying the KEL
 * from inception (or, for a bare non-transferable AID, read from the
 * self-certifying prefix), never trusted from the input.
 */
export function verifyIdentifier(input: VerifyIdentifierInput): VerifyIdentifierResult {
	if (input === null || typeof input !== 'object') {
		throw new InvalidArgumentError('verifyIdentifier requires an input object');
	}
	if (typeof input.aid !== 'string' || input.aid.length === 0) {
		throw new InvalidArgumentError(
			'verifyIdentifier requires a non-empty `aid` string'
		);
	}
	if (typeof input.kel !== 'string') {
		throw new InvalidArgumentError('verifyIdentifier requires a `kel` string');
	}

	// A non-transferable AID with no KEL (the empty-string sentinel) is
	// self-certifying — its `B`-coded basic prefix *is* the signing key — so it
	// is resolved straight from the prefix, with no events to replay. A
	// transferable AID with an empty KEL falls through to `replayKel`, which
	// reports `EMPTY_KEL`.
	if (input.kel === '' && isNonTransferableAid(input.aid)) {
		return { ok: true, state: bareNonTransferableState(input.aid) };
	}
	return replayKel(input.aid, input.kel);
}

/** Whether `aid` is a non-transferable basic prefix (a `B`-coded Ed25519 key). */
function isNonTransferableAid(aid: string): boolean {
	try {
		decodeNonTransferablePublicKeyEd25519(aid);
		return true;
	} catch (err) {
		// Any other AID form (a digest, or garbage) is simply not non-transferable.
		if (err instanceof MalformedInputError) return false;
		throw err;
	}
}

/**
 * Build the state of a bare non-transferable AID verified with no KEL. The AID
 * *is* the signing key, so `currentPublicKey` is the AID itself; the
 * event-derived fields (`lastEventDigest` / `lastEventType`) are absent, which
 * is what distinguishes a bare AID from one verified from a single-event KEL
 * (both report `lastSequenceNumber: 0`).
 */
function bareNonTransferableState(aid: Aid): NonTransferableKeriState {
	return {
		aid,
		did: formatDidKeri(aid),
		lastSequenceNumber: 0,
		currentPublicKey: aid as unknown as CesrPublicKey,
		transferable: false,
		deactivated: false,
	};
}
