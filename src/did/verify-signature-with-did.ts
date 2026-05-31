/**
 * `verifySignatureWithDid` — verify that a payload was signed by the key
 * currently authoritative for a `did:keri` identifier.
 *
 * This is the DID-level signed-verification entry point. The caller already has
 * (or just received) a sender DID, a payload, a detached signature, and — for a
 * transferable DID — the sender's KEL. It parses the DID down to its AID and
 * delegates to `verifySignature`, so the two are exact counterparts:
 * `verifySignatureWithDid` is "parse the DID, then verify the signature against
 * the identifier".
 *
 * `kel` is always required, but an **empty string** stands for "no KEL" — the
 * right value for a self-certifying non-transferable DID, whose key is the AID
 * itself. A transferable DID must supply a real, non-empty KEL.
 *
 * It returns `false` — never throws — for every *data-level* failure: a
 * malformed DID, a non-verifying KEL, a KEL belonging to a different
 * identifier, a KEL for a deactivated (abandoned) identifier, an empty KEL for
 * a transferable DID, a malformed signature, or a genuine signature mismatch.
 * All of those are untrusted-input outcomes a caller routinely sees. Throwing
 * is reserved for a caller that violates the argument contract outright.
 */

import { InvalidArgumentError } from '../profile/errors';
import { verifySignature } from '../api/verify-signature';
import { ParsedDidKeri, parseDidKeri } from './did-keri';

export interface VerifySignatureWithDidInput {
	/** The signer's `did:keri` DID. */
	readonly did: string;
	/**
	 * The signer's full key event log, as a CESR stream (inception first).
	 *
	 * Always required, but the **empty string** `''` stands for "no KEL" — the
	 * right value for a self-certifying non-transferable DID, whose key is the
	 * AID itself. A transferable DID must supply a real, non-empty KEL.
	 */
	readonly kel: string;
	/** The exact bytes that were signed. */
	readonly payload: Readonly<Uint8Array>;
	/**
	 * A detached CESR-qualified Ed25519 signature over `payload`. This is a
	 * non-indexed signature (a "Cigar", code `0B`) — the form for signatures
	 * over arbitrary payloads, as opposed to the indexed signatures attached
	 * to KEL events.
	 */
	readonly signature: string;
}

/**
 * Verify `signature` over `payload` against the key `did` makes authoritative,
 * by parsing the DID down to its AID and delegating to `verifySignature`.
 */
export function verifySignatureWithDid(input: VerifySignatureWithDidInput): boolean {
	if (input === null || typeof input !== 'object') {
		throw new InvalidArgumentError('verifySignatureWithDid requires an input object');
	}
	if (typeof input.did !== 'string') {
		throw new InvalidArgumentError('verifySignatureWithDid requires a `did` string');
	}
	if (typeof input.kel !== 'string') {
		throw new InvalidArgumentError('verifySignatureWithDid requires a `kel` string');
	}
	if (!(input.payload instanceof Uint8Array)) {
		throw new InvalidArgumentError(
			'verifySignatureWithDid requires a `payload` Uint8Array'
		);
	}
	if (typeof input.signature !== 'string') {
		throw new InvalidArgumentError(
			'verifySignatureWithDid requires a `signature` string'
		);
	}

	// A malformed DID is untrusted input: report it as a verification miss,
	// not a thrown error.
	let parsed: ParsedDidKeri;
	try {
		parsed = parseDidKeri(input.did);
	} catch (err) {
		if (err instanceof InvalidArgumentError) return false;
		throw err;
	}

	// Everything else — the empty-string "no KEL" handling, KEL replay, the AID
	// binding, the deactivation check, and the actual signature check — is the
	// AID-level primitive's job.
	return verifySignature({
		aid: parsed.aid,
		kel: input.kel,
		payload: input.payload,
		signature: input.signature,
	});
}
