/**
 * Local `did:keri` resolution.
 *
 * `resolveDid` is offline by construction: the caller supplies the KEL, and
 * the library never discovers, fetches, or persists anything. Resolution is
 * exactly "verify this KEL against the DID's AID and return the verified
 * latest state". Projecting that state into a DID document is a separate,
 * caller-driven step: `createDidDocument(state)`.
 *
 * A non-transferable DID is self-certifying — the AID *is* the signing key —
 * so it resolves with no KEL at all: pass the empty string `''` for `kel`.
 *
 * The result uses the library's discriminated `{ ok }` shape rather than the
 * W3C DID Resolution metadata envelope. That keeps it consistent with
 * `verifyKel` and surfaces the same typed `KeriVerificationError` union, so a
 * caller handles a tampered KEL and a malformed DID through one mechanism. A
 * caller that needs the W3C envelope can map this result onto it directly.
 */

import { verifyKel } from '../api/verify-kel';
import { CesrPublicKey } from '../cesr/qualified';
import { KeriState, NonTransferableKeriState } from '../kel/state';
import { InvalidArgumentError, KeriVerificationError } from '../profile/errors';
import { DidKeri, ParsedDidKeri, parseDidKeri } from './did-keri';

export interface ResolveDidInput {
	/** The `did:keri` DID to resolve. */
	readonly did: DidKeri;
	/**
	 * The full key event log for the DID's identifier, as a CESR stream.
	 *
	 * The **empty string** `''` stands for "no KEL" — valid only for a
	 * self-certifying non-transferable DID, which resolves straight from its
	 * prefix. A transferable DID must supply a real, non-empty KEL.
	 */
	readonly kel: string;
}

/** Discriminated result of resolving a `did:keri` DID. */
export type DidResolutionResult =
	| { ok: true; state: KeriState }
	| { ok: false; error: KeriVerificationError };

/**
 * Resolve a `did:keri` DID against a caller-supplied KEL.
 *
 * On success `state` is the only `KeriState` the caller may treat as trusted —
 * it carries the `deactivated` flag and (via `lastSequenceNumber`) the KEL
 * length directly. Project it into a W3C DID document with
 * `createDidDocument(state)` when one is needed. Any data-level failure — a
 * malformed DID, or a KEL that is empty, tampered, reordered, or for a
 * different identifier — is returned as `{ ok: false }`. Throwing is reserved
 * for a caller that violates the argument contract.
 *
 * A non-transferable DID resolves with `kel: ''` (no KEL): it is
 * self-certifying, so the state is projected straight from the prefix.
 */
export function resolveDid(input: ResolveDidInput): DidResolutionResult {
	if (input === null || typeof input !== 'object') {
		throw new InvalidArgumentError('resolveDid requires an input object');
	}
	if (typeof input.did !== 'string') {
		throw new InvalidArgumentError('resolveDid requires a `did` string');
	}
	if (typeof input.kel !== 'string') {
		throw new InvalidArgumentError('resolveDid requires a `kel` string');
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

	// A non-transferable DID with no KEL (the empty-string sentinel) is
	// self-certifying — resolve it straight from the prefix, no replay.
	if (input.kel === '' && !parsed.transferable) {
		return resolveBareNonTransferable(parsed);
	}

	const verification = verifyKel({ aid: parsed.aid, kel: input.kel });
	if (!verification.ok) {
		return { ok: false, error: verification.error };
	}

	return { ok: true, state: verification.state };
}

/**
 * Resolve a non-transferable DID that was given no KEL. The AID *is* the
 * signing key — a `B`-coded basic prefix is self-certifying — so the state is
 * projected straight from it, with no events to replay.
 *
 * There is no KEL: the returned `state` omits `lastEventDigest` / `eventType`,
 * which is what distinguishes a bare AID from one verified from a single-event
 * KEL (both report `sequenceNumber: 0`).
 */
function resolveBareNonTransferable(parsed: ParsedDidKeri): DidResolutionResult {
	const state: NonTransferableKeriState = {
		aid: parsed.aid,
		did: parsed.did,
		lastSequenceNumber: 0,
		// A non-transferable AID *is* its qb64 public key; that is the whole
		// point of a basic prefix. `lastEventDigest` / `eventType` are absent —
		// there is no event.
		currentPublicKey: parsed.aid as unknown as CesrPublicKey,
		transferable: false,
		deactivated: false,
	};
	return { ok: true, state };
}
