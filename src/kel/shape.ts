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
	decodeIndexedSignatureEd25519,
	decodeNonTransferablePublicKeyEd25519,
	decodePublicKeyEd25519,
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

/**
 * A controller signature: a CESR-qualified *indexed* Ed25519 signature (a
 * "Siger", code `A`) whose index points at key 0. This profile is single-key,
 * so the only valid index is 0 — any other index references a key position
 * that does not exist and is rejected as an unsupported (multi-key) feature.
 */
export function checkSignature(value: unknown): KeriVerificationError | null {
	if (typeof value !== 'string') {
		return { code: 'INVALID_CESR_CODE', value: describe(value) };
	}
	let index: number;
	try {
		index = decodeIndexedSignatureEd25519(value).index;
	} catch (err) {
		if (err instanceof MalformedInputError) {
			return { code: 'INVALID_CESR_CODE', value };
		}
		throw err;
	}
	if (index !== 0) {
		return {
			code: 'UNSUPPORTED_FEATURE',
			feature: `signature index must be 0, got ${index}`,
		};
	}
	return null;
}

/**
 * A `k` / `n` list: exactly one entry, itself a valid CESR primitive of the
 * given `kind`. More than one entry is multisig, which the profile excludes.
 *
 * `kind` selects the entry's expected primitive: a transferable Ed25519 key
 * (`'key'`, code `D`), a non-transferable Ed25519 key (`'ntkey'`, code `B` —
 * only ever a non-transferable inception's `k`), or a digest (`'digest'`).
 */
export function checkSingleton(
	field: unknown,
	kind: 'key' | 'ntkey' | 'digest'
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
	if (kind === 'digest') return checkDigest(field[0]);
	if (kind === 'ntkey') {
		return checkCesr(decodeNonTransferablePublicKeyEd25519, field[0]);
	}
	return checkCesr(decodePublicKeyEd25519, field[0]);
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

/**
 * Validate an inception event's `c` (configuration traits) array. The profile
 * recognizes exactly one trait — `EO` ("establishment only") — and rejects
 * every other configuration the broader KERI spec defines (`DND`, `RB`, `NB`,
 * `NRB`, `DID`), since none of them maps onto this single-controller library.
 *
 * Returns the structural error (or `null`) alongside the decoded
 * `establishmentOnly` flag, so callers learn in one pass both that the field
 * is well-formed and which configuration it selects.
 */
export function checkConfigTraits(value: unknown): {
	error: KeriVerificationError | null;
	establishmentOnly: boolean;
} {
	if (!Array.isArray(value)) {
		return {
			error: {
				code: 'UNSUPPORTED_FEATURE',
				feature: `configuration traits must be an array, got ${describe(value)}`,
			},
			establishmentOnly: false,
		};
	}
	if (value.length === 0) return { error: null, establishmentOnly: false };
	if (value.length === 1 && value[0] === 'EO') {
		return { error: null, establishmentOnly: true };
	}
	return {
		error: {
			code: 'UNSUPPORTED_FEATURE',
			feature: `unsupported configuration traits: ${JSON.stringify(value)}`,
		},
		establishmentOnly: false,
	};
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
