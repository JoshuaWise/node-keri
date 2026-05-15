/**
 * CESR derivation code table for the KERI Direct JSON Profile v1.
 *
 * Each entry describes a "Matter" primitive: a fixed-length raw byte payload
 * paired with a multi-character text code. The qualified ("qb64") text form
 * is built by prepending `ps` zero bytes to the raw payload, base64url-
 * encoding the result, then replacing the leading `ps` base64 characters
 * (which are always `A` = 0) with the code prefix — `hs` hard characters
 * followed by `ss` "soft" characters that carry a small variable value (the
 * index of an indexed signature).
 *
 * This profile is restricted to codes where `hs + ss === ps`. That rules out
 * the longer "1AAB"-style codes and lets the encode/decode helpers share a
 * single straightforward substitution. Plain Matter primitives have `ss === 0`
 * (so `hs === ps`); indexed primitives carry a non-zero `ss`. Any future code
 * added here must satisfy the `hs + ss === ps` invariant.
 */

import { MalformedInputError, UnsupportedAlgorithmError } from '../profile/errors';

export interface CesrCodeSpec {
	/** The text code prefix (also the "hard" portion). */
	readonly code: string;
	/** Hard size — number of characters consumed by the code prefix. */
	readonly hs: number;
	/** Soft size — characters carrying a variable value. 0 for plain Matter
	 *  primitives; non-zero for indexed primitives (the signature index). */
	readonly ss: number;
	/** Raw size — number of payload bytes after the code is stripped. */
	readonly rs: number;
	/** Pad size — number of zero bytes prepended to the payload before base64. */
	readonly ps: number;
	/** Fully qualified size — total character length of the qb64 form. */
	readonly fs: number;
	/** Human-readable label, used in error messages. */
	readonly label: string;
}

/**
 * Build a code spec with an explicit hard size `hs` and soft size `ss`. The
 * encoder/decoder rely on the code prefix (`hs + ss` characters) replacing
 * exactly `ps` leading 'A' characters, so `hs + ss === ps` must hold.
 */
function makeSpec(
	code: string,
	hs: number,
	ss: number,
	rs: number,
	label: string
): CesrCodeSpec {
	const ps = (3 - (rs % 3)) % 3;
	if (hs + ss !== ps) {
		// Codes that violate this (e.g. the 4-character `1AAB` family) need a
		// different substitution strategy and are out of scope for this profile.
		throw new Error(
			`CESR code '${code}' has hs+ss=${hs + ss} but ps=${ps}; `
				+ 'only hs+ss===ps codes are supported'
		);
	}
	if (code.length !== hs) {
		throw new Error(
			`CESR code '${code}' length ${code.length} does not match hs=${hs}`
		);
	}
	const fs = ((ps + rs) / 3) * 4;
	return { code, hs, ss, rs, ps, fs, label };
}

/** A plain (non-indexed) Matter primitive: `ss === 0`, so `hs === ps`. */
function spec(code: string, rs: number, label: string): CesrCodeSpec {
	return makeSpec(code, code.length, 0, rs, label);
}

/** Ed25519 verification key, transferable (rotatable) variant. */
export const CESR_PUBLIC_KEY_ED25519 = spec('D', 32, 'Ed25519 public key');

/** Ed25519 signature, non-indexed (a "Cigar"). */
export const CESR_SIGNATURE_ED25519 = spec('0B', 64, 'Ed25519 signature');

/**
 * Ed25519 indexed signature (a "Siger"). The 1-character hard code `A` is
 * followed by a 1-character soft field encoding the index of the signing key
 * within the establishment event's key list. KERI attaches controller
 * signatures on KEL events in this indexed form.
 */
export const CESR_INDEXED_SIGNATURE_ED25519 = makeSpec(
	'A',
	1,
	1,
	64,
	'Ed25519 indexed signature'
);

/** SHA-256 digest. */
export const CESR_DIGEST_SHA256 = spec('I', 32, 'SHA-256 digest');

/**
 * Every code recognized by the library. Used for diagnostic messages when a
 * decoder is handed a string with the wrong-but-known prefix.
 */
export const ALL_CODES: readonly CesrCodeSpec[] = Object.freeze([
	CESR_PUBLIC_KEY_ED25519,
	CESR_SIGNATURE_ED25519,
	CESR_INDEXED_SIGNATURE_ED25519,
	CESR_DIGEST_SHA256,
]);

/**
 * Build the CESR code spec for a digest derivation `code`.
 *
 * Unlike public keys and signatures — which have one fixed code each — digests
 * are algorithm-agile: a KERI digest carries a derivation code that names its
 * hash algorithm, and a KEL may mix several. KERI's digest codes are also
 * self-describing about width: a one-character code denotes a 256-bit (32-byte)
 * digest and a `0`-prefixed two-character code denotes a 512-bit (64-byte) one.
 * Those are the only two widths this library supports; both satisfy the
 * `hs === ps` invariant, so the shared substitution still applies.
 *
 * This builds the *structural* spec only — it says nothing about whether an
 * implementation for the algorithm is available. `UnsupportedAlgorithmError`
 * is thrown for a code whose shape is neither supported width.
 */
export function digestSpecForCode(code: string, label?: string): CesrCodeSpec {
	if (typeof code !== 'string' || code.length === 0) {
		throw new UnsupportedAlgorithmError('digest code must be a non-empty string');
	}
	const named = label ?? `digest (code '${code}')`;
	if (code.length === 1) {
		return spec(code, 32, named);
	}
	if (code.length === 2 && code[0] === '0') {
		return spec(code, 64, named);
	}
	throw new UnsupportedAlgorithmError(
		`unsupported digest code '${code}': only 256-bit (one-character) and `
			+ '512-bit (`0`-prefixed two-character) digest codes are supported'
	);
}

/**
 * Read the CESR derivation code from the start of a qualified digest string.
 *
 * A leading `0` marks a two-character code; otherwise the code is the single
 * leading character. This only *reads* the code — it does not check that the
 * code is known or that the rest of the string is well-formed, so callers
 * must still resolve and decode it.
 */
export function digestCodeOf(qb64: string): string {
	if (typeof qb64 !== 'string' || qb64.length === 0) {
		throw new MalformedInputError('digest must be a non-empty string');
	}
	// `charAt` (unlike indexing) is typed `string`, and the length check above
	// guarantees index 0 exists.
	const first = qb64.charAt(0);
	return first === '0' ? qb64.slice(0, 2) : first;
}
