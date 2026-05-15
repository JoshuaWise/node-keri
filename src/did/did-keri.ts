/**
 * Branded string types for KERI Autonomic Identifiers (AIDs) and `did:keri`
 * DIDs, plus a minimal formatter.
 *
 * The full DID surface — parsing, resolution, document generation — is
 * Milestone 5. This file only defines the types and the trivial formatter
 * needed by the event constructors so that state objects can carry both an
 * AID and a DID without importing from a not-yet-existing module.
 */

import { CesrDigest } from '../cesr/qualified';
import { InvalidArgumentError } from '../profile/errors';

declare const aidBrand: unique symbol;
declare const didBrand: unique symbol;

/**
 * A KERI Autonomic Identifier. In this profile every AID is a transferable,
 * self-addressing identifier derived from an inception event, so the
 * underlying string is a CESR-qualified SHA-256 digest (code `I`, 44 chars).
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
