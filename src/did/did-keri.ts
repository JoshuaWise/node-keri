/**
 * Branded string types for KERI Autonomic Identifiers (AIDs) and `did:keri`
 * DIDs, plus the `did:keri` formatter and parser.
 *
 * Document generation and resolution live in sibling modules (`document.ts`,
 * `resolver.ts`); this file owns the identifier syntax itself — the types,
 * the `did:keri:<aid>` formatter, and the strict offline parser.
 */

import { decodeDigest, decodeNonTransferablePublicKeyEd25519 } from '../cesr/decode';
import { CesrDigest } from '../cesr/qualified';
import { InvalidArgumentError, MalformedInputError } from '../profile/errors';

declare const aidBrand: unique symbol;
declare const didBrand: unique symbol;

/**
 * A KERI Autonomic Identifier. An AID is one of two forms:
 *   - a *transferable*, self-addressing identifier — a CESR-qualified digest,
 *     the SAID of an inception event (44 characters for a 256-bit digest, 88
 *     for a 512-bit one; SHA-256 by default); or
 *   - a *non-transferable* identifier — a basic prefix that is itself the
 *     controller's `B`-coded Ed25519 key (44 characters).
 *
 * node-keri generates only the transferable form; it verifies both.
 */
export type Aid = string & { readonly [aidBrand]: 'Aid' };

/** A `did:keri:<aid>` DID URL. */
export type DidKeri = string & { readonly [didBrand]: 'DidKeri' };

export const DID_KERI_PREFIX = 'did:keri:';

/**
 * Wrap a SAID as the AID of a transferable single-key identifier. AID
 * derivation is structural — the AID *is* the SAID of the inception event —
 * so this is just a brand cast guarded against accidentally typing some
 * other CesrDigest as an AID.
 */
export function aidFromSaid(said: CesrDigest): Aid {
	return said as unknown as Aid;
}

/** Build the `did:keri:<aid>` DID for a given AID. */
export function formatDidKeri(aid: Aid): DidKeri {
	if (typeof aid !== 'string' || aid.length === 0) {
		throw new InvalidArgumentError('aid must be a non-empty string');
	}
	return (DID_KERI_PREFIX + aid) as DidKeri;
}

/** A `did:keri` DID decomposed into its method and method-specific id. */
export interface ParsedDidKeri {
	/** The original DID string, unchanged. */
	readonly did: DidKeri;
	/** Always `'keri'` — the only method this library understands. */
	readonly method: 'keri';
	/** The method-specific identifier: the controller's AID. */
	readonly aid: Aid;
	/**
	 * Whether the AID is transferable. `true` for a self-addressing digest — a
	 * rotatable identifier whose key state must be replayed from a KEL.
	 * `false` for a non-transferable basic prefix — the controller's `B`-coded
	 * Ed25519 key itself, which can never rotate and is self-certifying (the
	 * signing key is read straight from the AID, no KEL required).
	 */
	readonly transferable: boolean;
}

/**
 * Parse a `did:keri:<aid>` string into its components.
 *
 * Parsing is strict and offline. The method-specific id must be a well-formed
 * AID — either a CESR-qualified digest under an algorithm node-keri recognizes
 * (a code with a registered implementation — see `digestAlgorithms`) for a
 * transferable AID, or a CESR-qualified non-transferable (`B`) Ed25519 key for
 * a non-transferable one — and no DID-URL syntax (path, query, or fragment) is
 * accepted, since resolution operates on bare DIDs. A string that fails either
 * rule throws `InvalidArgumentError`; callers
 * parsing DIDs that arrive from untrusted input should prefer `verifyDid`,
 * which reports the same failure as an `INVALID_DID` result rather than
 * throwing.
 */
export function parseDidKeri(did: string): ParsedDidKeri {
	if (typeof did !== 'string') {
		throw new InvalidArgumentError('did must be a string');
	}
	if (!did.startsWith(DID_KERI_PREFIX)) {
		throw new InvalidArgumentError(`did must start with '${DID_KERI_PREFIX}'`);
	}
	const aid = did.slice(DID_KERI_PREFIX.length);
	if (aid.length === 0) {
		throw new InvalidArgumentError(
			'did:keri is missing its method-specific identifier'
		);
	}
	for (const component of ['/', '?', '#']) {
		if (aid.includes(component)) {
			throw new InvalidArgumentError(
				`did:keri does not accept a DID-URL '${component}' component`
			);
		}
	}
	// The AID is either a transferable, self-addressing digest or a
	// non-transferable basic prefix (a `B`-coded Ed25519 key). Both decoders
	// enforce the derivation code, the fixed length, and pad-bit canonicality;
	// the decoded bytes themselves are not needed here. Try the digest form
	// first — it is the form node-keri itself mints — then the key form, and
	// record which one matched.
	let transferable: boolean;
	try {
		decodeDigest(aid);
		transferable = true;
	} catch (digestErr) {
		if (!(digestErr instanceof MalformedInputError)) throw digestErr;
		try {
			decodeNonTransferablePublicKeyEd25519(aid);
			transferable = false;
		} catch (keyErr) {
			if (keyErr instanceof MalformedInputError) {
				throw new InvalidArgumentError(
					'did:keri identifier is not a valid AID: it is neither a '
						+ `recognized digest nor a non-transferable key (${digestErr.message})`
				);
			}
			throw keyErr;
		}
	}
	return {
		did: did as DidKeri,
		method: 'keri',
		aid: aid as unknown as Aid,
		transferable,
	};
}
