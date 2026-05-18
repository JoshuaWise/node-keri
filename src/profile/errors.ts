/**
 * Typed error hierarchy for the KERI library.
 *
 * Throwing is reserved for programmer errors (invalid arguments, malformed key
 * objects, unsupported algorithms requested by the caller). KEL replay and
 * signature verification return discriminated result objects rather than
 * throwing — see `KeriVerificationError`.
 */

export class KeriError extends Error {
	constructor(message: string) {
		super(message);
		this.name = new.target.name;
	}
}

/** The caller passed an argument that does not satisfy the function's contract. */
export class InvalidArgumentError extends KeriError {}

/** A requested algorithm or derivation code is outside the supported profile. */
export class UnsupportedAlgorithmError extends KeriError {}

/** Input data could be parsed structurally but failed integrity validation. */
export class MalformedInputError extends KeriError {}

/** A value rejected by canonical JSON serialization rules. */
export class CanonicalJsonError extends KeriError {}

/**
 * Discriminated error type returned by KEL verification. Concrete codes are
 * filled in by later milestones; the union is declared here so foundation
 * code can already reference it without circular dependencies.
 */
export type KeriVerificationError =
	| { code: 'EMPTY_KEL' }
	| { code: 'INVALID_DID'; message: string }
	| { code: 'UNSUPPORTED_FEATURE'; feature: string }
	| { code: 'INVALID_EVENT_TYPE'; eventType: string }
	| { code: 'NON_TRANSFERABLE_NOT_EXTENSIBLE'; eventType: string }
	| { code: 'INVALID_SEQUENCE'; expected: number; actual: number }
	| { code: 'INVALID_PREVIOUS_DIGEST' }
	| { code: 'INVALID_EVENT_DIGEST' }
	| { code: 'INVALID_SIGNATURE' }
	| { code: 'INVALID_NEXT_KEY_COMMITMENT' }
	| { code: 'INVALID_CESR_CODE'; value: string }
	| { code: 'NON_CANONICAL_EVENT' }
	| { code: 'MALFORMED_STREAM'; message: string };
