/**
 * `verifySignature` — verify that a payload was signed by the key currently
 * authoritative for a KERI identifier (an AID).
 *
 * This is the AID-level signed-verification primitive. The caller has an AID, a
 * payload, a detached signature, and — for a transferable identifier — the
 * identifier's KEL. It answers a single boolean question: "does this signature
 * verify under the key this identifier makes authoritative?"
 *
 * `kel` is always required, but an **empty string** stands for "no KEL":
 *   - With a non-empty `kel`, the key is whatever verifying that KEL yields —
 *     it must verify and belong to `aid`. This is the only form a transferable
 *     identifier can be verified with.
 *   - With an empty `kel` and a *non-transferable* AID, the AID is itself the
 *     signing key (a `B`-coded basic prefix is self-certifying), so the key is
 *     read straight from it. A transferable AID with no KEL cannot be verified.
 *
 * It returns `false` — never throws — for every *data-level* failure: an AID
 * whose KEL does not verify, a KEL belonging to a different identifier, a KEL
 * for a deactivated (abandoned) identifier, an empty KEL for a transferable
 * AID, a malformed signature, or a genuine signature mismatch. Throwing is
 * reserved for a caller that violates the argument contract outright.
 *
 * `verifySignatureWithDid` is the DID-level counterpart: it parses a `did:keri`
 * DID down to its AID and delegates here.
 */

import { decodeSignatureEd25519, decodeVerificationKeyEd25519 } from '../cesr/decode';
import { verify } from '../crypto/ed25519';
import { publicKeyFromRaw } from '../crypto/keypair';
import { InvalidArgumentError, MalformedInputError } from '../profile/errors';
import { verifyIdentifier } from './verify-identifier';

export interface VerifySignatureInput {
	/** The signer's identifier (AID). */
	readonly aid: string;
	/**
	 * The signer's full key event log, as a CESR stream (inception first).
	 *
	 * Always required, but the **empty string** `''` stands for "no KEL" — the
	 * right value for a self-certifying non-transferable AID, whose key is the
	 * AID itself. A transferable AID must supply a real, non-empty KEL.
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
 * Verify `signature` over `payload` against the key `aid` makes authoritative
 * — verified from `kel` when one is supplied, or read from the AID itself for a
 * non-transferable identifier given the empty-string "no KEL" value.
 */
export function verifySignature(input: VerifySignatureInput): boolean {
	if (input === null || typeof input !== 'object') {
		throw new InvalidArgumentError('verifySignature requires an input object');
	}
	if (typeof input.aid !== 'string' || input.aid.length === 0) {
		throw new InvalidArgumentError(
			'verifySignature requires a non-empty `aid` string'
		);
	}
	if (typeof input.kel !== 'string') {
		throw new InvalidArgumentError('verifySignature requires a `kel` string');
	}
	if (!(input.payload instanceof Uint8Array)) {
		throw new InvalidArgumentError('verifySignature requires a `payload` Uint8Array');
	}
	if (typeof input.signature !== 'string') {
		throw new InvalidArgumentError('verifySignature requires a `signature` string');
	}

	// A structurally malformed signature (wrong CESR code or length) is
	// untrusted input — treat it as a non-verifying signature, not an error.
	let signatureRaw: Uint8Array;
	try {
		signatureRaw = decodeSignatureEd25519(input.signature);
	} catch (err) {
		if (err instanceof MalformedInputError) return false;
		throw err;
	}

	// Establish the authoritative signing key. `verifyIdentifier` handles both
	// a real KEL (replayed, with the AID binding enforced — so a KEL for some
	// other identifier fails here, as does an empty KEL for a transferable AID)
	// and the empty-string "no KEL" value for a self-certifying non-transferable
	// AID, where the key is the AID itself.
	const verification = verifyIdentifier({ aid: input.aid, kel: input.kel });
	if (!verification.ok) return false;
	// A deactivated identifier has been abandoned: it makes no key
	// authoritative, so nothing verifies against it — even a signature its last
	// key produced before deactivation is no longer trusted.
	if (verification.state.deactivated) return false;
	// `currentPublicKey` came out of replay (or is the AID itself), so it is
	// well-formed by construction and decoding it cannot fail.
	const publicKeyRaw = decodeVerificationKeyEd25519(
		verification.state.currentPublicKey
	);
	return verify(publicKeyFromRaw(publicKeyRaw), input.payload, signatureRaw);
}
