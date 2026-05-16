/**
 * Branded string types for KERI Autonomic Identifiers (AIDs) and `did:keri`
 * DIDs, plus the `did:keri` formatter and parser.
 *
 * Document generation and resolution live in sibling modules (`document.ts`,
 * `resolver.ts`); this file owns the identifier syntax itself — the types,
 * the `did:keri:<aid>` formatter, and the strict offline parser.
 */

import { decodeDigest } from '../cesr/decode';
import { CesrDigest } from '../cesr/qualified';
import { InvalidArgumentError, MalformedInputError } from '../profile/errors';

declare const aidBrand: unique symbol;
declare const didBrand: unique symbol;

/**
 * A KERI Autonomic Identifier. In this profile every AID is a transferable,
 * self-addressing identifier derived from an inception event, so the
 * underlying string is a CESR-qualified digest. Its algorithm is whatever the
 * inception event used — SHA-256 by default — so the string is 44 characters
 * for a 256-bit digest or 88 for a 512-bit one.
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
}

/**
 * Parse a `did:keri:<aid>` string into its components.
 *
 * Parsing is strict and offline. The method-specific id must be a well-formed
 * CESR-qualified digest under an algorithm node-keri recognizes (a code with a
 * registered implementation — see `digestAlgorithms`), and no DID-URL syntax
 * (path, query, or fragment) is accepted, since resolution operates on bare
 * DIDs. A string that fails either rule throws `InvalidArgumentError`; callers
 * parsing DIDs that arrive from untrusted input should prefer `resolveDid`,
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
	// The AID must be a canonically-encoded CESR digest under a recognized
	// algorithm. `decodeDigest` enforces the derivation code (and that an
	// implementation is registered for it), the fixed length, and pad-bit
	// canonicality; the decoded bytes themselves are not needed here.
	try {
		decodeDigest(aid);
	} catch (err) {
		if (err instanceof MalformedInputError) {
			throw new InvalidArgumentError(
				`did:keri identifier is not a valid AID: ${err.message}`
			);
		}
		throw err;
	}
	return {
		did: did as DidKeri,
		method: 'keri',
		aid: aid as unknown as Aid,
	};
}
