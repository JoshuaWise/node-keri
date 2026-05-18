/**
 * `verifySignatureWithDid` — verify that a payload was signed by the key
 * currently authoritative for a `did:keri` identifier.
 *
 * This is the signed verification primitive. The caller already has (or just
 * received) a sender DID, a payload, a detached signature, and — for a
 * transferable DID — the sender's KEL. It answers a single boolean question:
 * "does this signature verify under the key this DID makes authoritative?"
 *
 * `kel` is always required, but an **empty string** stands for "no KEL":
 *   - With a non-empty `kel`, the key is whatever replaying that KEL yields —
 *     it must verify and belong to the DID's AID. This is the only form a
 *     transferable DID can be verified with.
 *   - With an empty `kel`, the DID must be a *non-transferable* AID: it is
 *     itself the signing key (a `B`-coded basic prefix is self-certifying), so
 *     the key is read straight from the AID. A transferable DID with no KEL
 *     cannot be verified.
 *
 * It returns `false` — never throws — for every *data-level* failure: a
 * malformed DID, a non-verifying KEL, a KEL belonging to a different
 * identifier, an empty KEL for a transferable DID, a malformed signature, or a
 * genuine signature mismatch. All of those are untrusted-input outcomes a
 * caller routinely sees. Throwing is reserved for a caller that violates the
 * argument contract outright.
 */

import {
	decodeNonTransferablePublicKeyEd25519,
	decodeSignatureEd25519,
	decodeVerificationKeyEd25519,
} from '../cesr/decode';
import { CesrSignature } from '../cesr/qualified';
import { verify } from '../crypto/ed25519';
import { publicKeyFromRaw } from '../crypto/keypair';
import { DidKeri, ParsedDidKeri, parseDidKeri } from '../did/did-keri';
import { InvalidArgumentError, MalformedInputError } from '../profile/errors';
import { verifyKel } from './verify-kel';

export interface VerifySignatureWithDidInput {
	/** The signer's `did:keri` DID. */
	readonly did: DidKeri;
	/**
	 * The signer's full key event log, as a CESR stream (inception first).
	 *
	 * Always required, but the **empty string** `''` stands for "no KEL" — the
	 * right value for a self-certifying non-transferable DID, whose key is the
	 * AID itself. A transferable DID must supply a real, non-empty KEL.
	 */
	readonly kel: string;
	/** The exact bytes that were signed. */
	readonly payload: Uint8Array;
	/**
	 * A detached CESR-qualified Ed25519 signature over `payload`. This is a
	 * non-indexed signature (a "Cigar", code `0B`) — the form for signatures
	 * over arbitrary payloads, as opposed to the indexed signatures attached
	 * to KEL events.
	 */
	readonly signature: CesrSignature;
}

/**
 * Verify `signature` over `payload` against the key `did` makes authoritative
 * — replayed from `kel` when one is supplied, or read from the AID itself for
 * a non-transferable DID given the empty-string "no KEL" value.
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

	// A structurally malformed signature (wrong CESR code or length) is also
	// untrusted input — treat it as a non-verifying signature.
	let signatureRaw: Uint8Array;
	try {
		signatureRaw = decodeSignatureEd25519(input.signature);
	} catch (err) {
		if (err instanceof MalformedInputError) return false;
		throw err;
	}

	// Establish the authoritative signing key.
	let publicKeyRaw: Uint8Array;
	if (input.kel === '' && !parsed.transferable) {
		// No KEL, non-transferable DID: the `B`-coded basic prefix *is* the
		// signing key — self-certifying — so it is read straight from the AID.
		// `parseDidKeri` already confirmed the prefix is a well-formed `B` key,
		// so this decode cannot fail.
		publicKeyRaw = decodeNonTransferablePublicKeyEd25519(parsed.aid);
	} else {
		// Otherwise the key is whatever replaying the KEL yields. The KEL must
		// verify *and* belong to this DID's identifier — `verifyKel` enforces
		// the AID binding, so a KEL for some other identifier fails here, as
		// does an empty KEL for a transferable DID (`EMPTY_KEL`).
		// `currentPublicKey` then came out of replay, so it is well-formed by
		// construction and decoding it cannot fail.
		const verification = verifyKel({ aid: parsed.aid, kel: input.kel });
		if (!verification.ok) return false;
		publicKeyRaw = decodeVerificationKeyEd25519(verification.state.currentPublicKey);
	}

	return verify(publicKeyFromRaw(publicKeyRaw), input.payload, signatureRaw);
}
