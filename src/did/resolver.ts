/**
 * Local `did:keri` resolution.
 *
 * `resolveDid` is offline by construction: the caller supplies the full KEL,
 * and the library never discovers, fetches, or persists anything. Resolution
 * is exactly "verify this KEL against the DID's AID, then project the
 * verified latest state into a DID document".
 *
 * The result uses the library's discriminated `{ ok }` shape rather than the
 * W3C DID Resolution metadata envelope. That keeps it consistent with
 * `verifyKel` and surfaces the same typed `KeriVerificationError` union, so a
 * caller handles a tampered KEL and a malformed DID through one mechanism. A
 * caller that needs the W3C envelope can map this result onto it directly.
 */

import { verifyKel } from '../api/verify-kel';
import { SignedKeriEvent } from '../event/types';
import { KeriState } from '../kel/state';
import { InvalidArgumentError, KeriVerificationError } from '../profile/errors';
import { DidKeri, ParsedDidKeri, parseDidKeri } from './did-keri';
import { DidDocument, createDidDocument } from './document';

export interface ResolveDidInput {
	/** The `did:keri` DID to resolve. */
	readonly did: DidKeri;
	/** The full key event log for the DID's identifier, inception first. */
	readonly kel: readonly SignedKeriEvent[];
	readonly options?: {
		/** When true, the verified KEL is echoed back in the metadata. */
		readonly includeKel?: boolean;
	};
}

/** Side information about a successful resolution. */
export interface DidResolutionMetadata {
	/** The replay-verified latest state of the identifier. */
	readonly state: KeriState;
	/** Number of events in the verified KEL. */
	readonly eventCount: number;
	/** The verified KEL — present only when `options.includeKel` was set. */
	readonly kel?: readonly SignedKeriEvent[];
}

/** Discriminated result of resolving a `did:keri` DID. */
export type DidResolutionResult =
	| { ok: true; didDocument: DidDocument; metadata: DidResolutionMetadata }
	| { ok: false; error: KeriVerificationError };

/**
 * Resolve a `did:keri` DID against a caller-supplied KEL.
 *
 * On success the `didDocument` reflects the latest *verified* key state and
 * `metadata.state` is the only `KeriState` the caller may treat as trusted.
 * Any data-level failure — a malformed DID, or a KEL that is empty, tampered,
 * reordered, or for a different identifier — is returned as `{ ok: false }`.
 * Throwing is reserved for a caller that violates the argument contract.
 */
export function resolveDid(input: ResolveDidInput): DidResolutionResult {
	if (input === null || typeof input !== 'object') {
		throw new InvalidArgumentError('resolveDid requires an input object');
	}
	if (typeof input.did !== 'string') {
		throw new InvalidArgumentError('resolveDid requires a `did` string');
	}
	if (!Array.isArray(input.kel)) {
		throw new InvalidArgumentError('resolveDid requires a `kel` array');
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

	const verification = verifyKel({ aid: parsed.aid, events: input.kel });
	if (!verification.ok) {
		return { ok: false, error: verification.error };
	}

	const didDocument = createDidDocument({
		did: parsed.did,
		state: verification.state,
	});

	const metadata: DidResolutionMetadata = {
		state: verification.state,
		eventCount: input.kel.length,
		...(input.options?.includeKel ? { kel: input.kel.slice() } : {}),
	};
	return { ok: true, didDocument, metadata };
}
