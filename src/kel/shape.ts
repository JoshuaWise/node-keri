/**
 * Shared structural validation helpers for KEL replay.
 *
 * These helpers turn an untrusted, loosely-typed field value into a
 * profile-conformant one, or a `KeriVerificationError` describing exactly how
 * it deviates from the KERI Direct JSON Profile v1. They never throw for data
 * defects — the decoders' `MalformedInputError` is caught and converted; any
 * other throw is a genuine programmer error and is allowed to propagate.
 *
 * Fail-closed mapping: the profile deliberately pins multisig, witness,
 * delegation, and configuration fields to fixed sentinel values. Any deviation
 * from a sentinel — including a missing or wrongly-typed field — is reported as
 * `UNSUPPORTED_FEATURE`, because an event shape the profile does not explicitly
 * permit is, by definition, an unsupported one. More specific defects map to
 * their dedicated codes: bad CESR primitives to `INVALID_CESR_CODE`, a
 * non-canonical sequence number or version string to `NON_CANONICAL_EVENT`.
 */

import {
	decodeDigest,
	decodePublicKeyEd25519,
	decodeSignatureEd25519,
} from '../cesr/decode';
import {
	KeriVerificationError,
	MalformedInputError,
	UnsupportedAlgorithmError,
} from '../profile/errors';

/** Result of a structural validation pass over a single event. */
export type ShapeResult<T> =
	| { ok: true; value: T }
	| { ok: false; error: KeriVerificationError };

/** Canonical lowercase-hex sequence number: `0`, or no-leading-zero hex. */
const CANONICAL_HEX = /^(?:0|[1-9a-f][0-9a-f]*)$/;

/** True for a non-null, non-array object — the shape every event must have. */
export function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Render an arbitrary value for inclusion in a diagnostic error message. */
export function describe(value: unknown): string {
	if (value === undefined) return '<missing>';
	if (value === null) return '<null>';
	if (typeof value === 'string') return value;
	return `<${typeof value}>`;
}

/** Validate that `value` decodes under `decode`; returns the error or `null`. */
function checkCesr(
	decode: (s: string) => Uint8Array,
	value: unknown
): KeriVerificationError | null {
	if (typeof value !== 'string') {
		return { code: 'INVALID_CESR_CODE', value: describe(value) };
	}
	try {
		decode(value);
		return null;
	} catch (err) {
		if (err instanceof MalformedInputError) {
			return { code: 'INVALID_CESR_CODE', value };
		}
		throw err;
	}
}

/**
 * A field that must be a CESR-qualified digest under *some* algorithm node-keri
 * recognizes — any code with a registered implementation (see
 * `digestAlgorithms`). A digest under an unregistered or structurally invalid
 * code is rejected with `INVALID_CESR_CODE`, so the verifier fails closed on a
 * hash it could not recompute.
 */
export function checkDigest(value: unknown): KeriVerificationError | null {
	if (typeof value !== 'string') {
		return { code: 'INVALID_CESR_CODE', value: describe(value) };
	}
	try {
		decodeDigest(value);
		return null;
	} catch (err) {
		if (
			err instanceof MalformedInputError
			|| err instanceof UnsupportedAlgorithmError
		) {
			return { code: 'INVALID_CESR_CODE', value };
		}
		throw err;
	}
}

/** A field that must be a CESR-qualified Ed25519 signature (code `0B`). */
export function checkSignature(value: unknown): KeriVerificationError | null {
	return checkCesr(decodeSignatureEd25519, value);
}

/**
 * A `k` / `n` list: exactly one entry, itself a valid CESR primitive of the
 * given `kind`. More than one entry is multisig, which the profile excludes.
 */
export function checkSingleton(
	field: unknown,
	kind: 'key' | 'digest'
): KeriVerificationError | null {
	if (!Array.isArray(field)) {
		return {
			code: 'UNSUPPORTED_FEATURE',
			feature: `key/next list must be an array, got ${describe(field)}`,
		};
	}
	if (field.length !== 1) {
		return {
			code: 'UNSUPPORTED_FEATURE',
			feature: `multisig: expected exactly 1 key, got ${field.length}`,
		};
	}
	return kind === 'key'
		? checkCesr(decodePublicKeyEd25519, field[0])
		: checkDigest(field[0]);
}

/** A field that must equal the single permitted sentinel value. */
export function checkSentinel(
	value: unknown,
	expected: string,
	feature: string
): KeriVerificationError | null {
	if (value === expected) return null;
	return {
		code: 'UNSUPPORTED_FEATURE',
		feature: `${feature} must be ${JSON.stringify(expected)}, got ${describe(value)}`,
	};
}

/** A field that must be present and an empty array (an excluded feature slot). */
export function checkEmptyArray(
	value: unknown,
	feature: string
): KeriVerificationError | null {
	if (Array.isArray(value) && value.length === 0) return null;
	return { code: 'UNSUPPORTED_FEATURE', feature };
}

/** A field that must be an array; contents are unconstrained (interaction `a`). */
export function checkArray(
	value: unknown,
	feature: string
): KeriVerificationError | null {
	if (Array.isArray(value)) return null;
	return { code: 'UNSUPPORTED_FEATURE', feature };
}

/** The sequence number string: must be present and canonical lowercase hex. */
export function checkSequenceString(value: unknown): KeriVerificationError | null {
	if (typeof value === 'string' && CANONICAL_HEX.test(value)) return null;
	return { code: 'NON_CANONICAL_EVENT' };
}

/**
 * The version string must be present and a string. Its *value* (protocol,
 * format, size) is checked in replay against the recomputed version string,
 * because that requires canonicalizing the whole event.
 */
export function checkVersionString(value: unknown): KeriVerificationError | null {
	if (typeof value === 'string') return null;
	return { code: 'NON_CANONICAL_EVENT' };
}

/** Reject the first key found outside the profile-permitted set. */
export function checkExactKeys(
	event: Record<string, unknown>,
	allowed: readonly string[]
): KeriVerificationError | null {
	const permitted = new Set(allowed);
	for (const key of Object.keys(event)) {
		if (!permitted.has(key)) {
			return {
				code: 'UNSUPPORTED_FEATURE',
				feature: `unknown field '${key}'`,
			};
		}
	}
	return null;
}

/** Return the first non-null error in `checks`, or `null` if all passed. */
export function firstError(
	checks: readonly (KeriVerificationError | null)[]
): KeriVerificationError | null {
	for (const err of checks) {
		if (err) return err;
	}
	return null;
}
