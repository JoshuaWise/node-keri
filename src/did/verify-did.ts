/**
 * Local `did:keri` verification.
 *
 * `verifyDid` is offline by construction: the caller supplies the KEL, and the
 * library never discovers, fetches, or persists anything. It parses a
 * `did:keri` DID down to its AID and delegates to `verifyIdentifier`, so the
 * two are exact counterparts — `verifyDid` is "parse the DID, then verify the
 * identifier". Projecting the verified state into a DID document is a separate,
 * caller-driven step: `createDidDocument()`.
 *
 * A non-transferable DID is self-certifying — the AID *is* the signing key —
 * so it verifies with no KEL at all: pass the empty string `''` for `kel`.
 * `verifyIdentifier` handles that case (shared with direct AID callers), so it
 * is not special-cased here.
 *
 * The result uses the library's discriminated `{ ok }` shape rather than the
 * W3C DID Resolution metadata envelope. That keeps it consistent with
 * `verifyIdentifier` and surfaces the same typed `KeriVerificationError` union,
 * so a caller handles a tampered KEL and a malformed DID through one mechanism.
 * A caller that needs the W3C envelope can map this result onto it directly.
 */

import { VerifyIdentifierResult, verifyIdentifier } from '../api/verify-identifier';
import { InvalidArgumentError } from '../profile/errors';
import { ParsedDidKeri, parseDidKeri } from './did-keri';

export interface VerifyDidInput {
	/** The `did:keri` DID to verify. */
	readonly did: string;
	/**
	 * The full key event log for the DID's identifier, as a CESR stream.
	 *
	 * The **empty string** `''` stands for "no KEL" — valid only for a
	 * self-certifying non-transferable DID, which verifies straight from its
	 * prefix. A transferable DID must supply a real, non-empty KEL.
	 */
	readonly kel: string;
}

/**
 * Discriminated result of verifying a `did:keri` DID — identical to
 * `verifyIdentifier`'s result, since `verifyDid` delegates to it.
 */
export type VerifyDidResult = VerifyIdentifierResult;

/**
 * Verify a `did:keri` DID against a caller-supplied KEL.
 *
 * On success `state` is the only `KeriState` the caller may treat as trusted —
 * it carries the `deactivated` flag and (via `lastSequenceNumber`) the KEL
 * length directly. Project it into a W3C DID document with
 * `createDidDocument()` when one is needed. Any data-level failure — a
 * malformed DID, or a KEL that is empty, tampered, reordered, or for a
 * different identifier — is returned as `{ ok: false }`. Throwing is reserved
 * for a caller that violates the argument contract.
 *
 * A non-transferable DID verifies with `kel: ''` (no KEL): it is
 * self-certifying, so the state is read straight from the prefix.
 */
export function verifyDid(input: VerifyDidInput): VerifyDidResult {
	if (input === null || typeof input !== 'object') {
		throw new InvalidArgumentError('verifyDid requires an input object');
	}
	if (typeof input.did !== 'string') {
		throw new InvalidArgumentError('verifyDid requires a `did` string');
	}
	if (typeof input.kel !== 'string') {
		throw new InvalidArgumentError('verifyDid requires a `kel` string');
	}

	// A malformed DID is untrusted input, not a programmer error: convert the
	// throw from `parseDidKeri` into an `INVALID_DID` result.
	let parsed: ParsedDidKeri;
	try {
		parsed = parseDidKeri(input.did);
	} catch (err) {
		if (err instanceof InvalidArgumentError) {
			return {
				ok: false,
				error: { code: 'INVALID_DID', message: err.message },
			};
		}
		throw err;
	}

	// Delegate to the AID-level verifier. It handles both a real KEL (replayed
	// from inception, with the AID binding enforced) and the empty-string "no
	// KEL" value for a self-certifying non-transferable DID.
	return verifyIdentifier({ aid: parsed.aid, kel: input.kel });
}
