/**
 * `verifySignatureWithDid` — verify that a payload was signed by the key
 * currently authoritative for a `did:keri` identifier.
 *
 * This is the signed verification primitive. The caller already has
 * (or just received) a sender DID, the sender's KEL, a payload, and a
 * detached signature. This function answers a single boolean question:
 * "does this signature verify under the latest key the KEL establishes for
 * this DID?"
 *
 * It returns `false` — never throws — for every *data-level* failure: a
 * malformed DID, a KEL that does not verify, a KEL belonging to a different
 * identifier, a malformed signature, or a genuine signature mismatch. All of
 * those are untrusted-input outcomes a caller routinely sees. Throwing is
 * reserved for a caller that violates the argument contract outright.
 */

import { decodePublicKeyEd25519, decodeSignatureEd25519 } from '../cesr/decode';
import { CesrSignature } from '../cesr/qualified';
import { verify } from '../crypto/ed25519';
import { publicKeyFromRaw } from '../crypto/keypair';
import { DidKeri, parseDidKeri } from '../did/did-keri';
import { SignedKeriEvent } from '../event/types';
import { InvalidArgumentError, MalformedInputError } from '../profile/errors';
import { verifyKel } from './verify-kel';

export interface VerifySignatureWithDidInput {
	/** The signer's `did:keri` DID. */
	readonly did: DidKeri;
	/** The signer's full key event log, inception first. */
	readonly kel: readonly SignedKeriEvent[];
	/** The exact bytes that were signed. */
	readonly payload: Uint8Array;
	/** A detached CESR-qualified Ed25519 signature over `payload`. */
	readonly signature: CesrSignature;
}

/**
 * Verify `signature` over `payload` against the current key of `did`,
 * established by replaying `kel`.
 */
export function verifySignatureWithDid(input: VerifySignatureWithDidInput): boolean {
	if (input === null || typeof input !== 'object') {
		throw new InvalidArgumentError('verifySignatureWithDid requires an input object');
	}
	if (typeof input.did !== 'string') {
		throw new InvalidArgumentError('verifySignatureWithDid requires a `did` string');
	}
	if (!Array.isArray(input.kel)) {
		throw new InvalidArgumentError('verifySignatureWithDid requires a `kel` array');
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
	let aid;
	try {
		aid = parseDidKeri(input.did).aid;
	} catch (err) {
		if (err instanceof InvalidArgumentError) return false;
		throw err;
	}

	// The KEL must verify *and* belong to this DID's identifier. `verifyKel`
	// enforces the AID binding, so a KEL for some other identifier fails here.
	const verification = verifyKel({ aid, events: input.kel });
	if (!verification.ok) return false;

	// A structurally malformed signature (wrong CESR code or length) is also
	// untrusted input — treat it as a non-verifying signature.
	let signatureRaw: Uint8Array;
	try {
		signatureRaw = decodeSignatureEd25519(input.signature);
	} catch (err) {
		if (err instanceof MalformedInputError) return false;
		throw err;
	}

	// `currentPublicKey` came out of replay, so it is well-formed by
	// construction; decoding it cannot legitimately fail.
	const publicKeyRaw = decodePublicKeyEd25519(verification.state.currentPublicKey);
	return verify(publicKeyFromRaw(publicKeyRaw), input.payload, signatureRaw);
}
