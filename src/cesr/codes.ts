/**
 * CESR derivation code table for the KERI Direct JSON Profile v1.
 *
 * Each entry describes a "Matter" primitive: a fixed-length raw byte payload
 * paired with a multi-character text code. The qualified ("qb64") text form
 * is built by prepending `ps` zero bytes to the raw payload, base64url-
 * encoding the result, then replacing the leading `ps` base64 characters
 * (which are always `A` = 0) with the `hs`-character code prefix.
 *
 * This profile is intentionally restricted to codes where `hs === ps`. That
 * rules out the longer "1AAB"-style 4-character codes and lets the
 * encode/decode helpers share a single straightforward substitution. Any
 * future code added here must satisfy the same invariant.
 */

export interface CesrCodeSpec {
	/** The text code prefix (also the "hard" portion). */
	readonly code: string;
	/** Hard size — number of characters consumed by the code prefix. */
	readonly hs: number;
	/** Soft size — variable-length size field. Always 0 in this subset. */
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

function spec(code: string, rs: number, label: string): CesrCodeSpec {
	const ps = (3 - (rs % 3)) % 3;
	const hs = code.length;
	if (hs !== ps) {
		// Encoder/decoder rely on the assumption that the code prefix replaces
		// exactly `ps` leading 'A' characters. Codes with hs > ps (e.g. the
		// 4-character `1AAB` family) need a different substitution strategy
		// and are out of scope for this profile.
		throw new Error(
			`CESR code '${code}' has hs=${hs} but ps=${ps}; only hs===ps codes are supported`
		);
	}
	const fs = ((ps + rs) / 3) * 4;
	return { code, hs, ss: 0, rs, ps, fs, label };
}

/** Ed25519 verification key, transferable (rotatable) variant. */
export const CESR_PUBLIC_KEY_ED25519 = spec(
	'D',
	32,
	'Ed25519 public key'
);

/** Ed25519 signature. */
export const CESR_SIGNATURE_ED25519 = spec('0B', 64, 'Ed25519 signature');

/** SHA-256 digest. */
export const CESR_DIGEST_SHA256 = spec('I', 32, 'SHA-256 digest');

/**
 * Every code recognized by the library. Used for diagnostic messages when a
 * decoder is handed a string with the wrong-but-known prefix.
 */
export const ALL_CODES: readonly CesrCodeSpec[] = Object.freeze([
	CESR_PUBLIC_KEY_ED25519,
	CESR_SIGNATURE_ED25519,
	CESR_DIGEST_SHA256,
]);
