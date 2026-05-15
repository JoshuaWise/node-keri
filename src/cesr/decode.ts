import { base64urlDecode, b64ToInt } from '../bytes/base64url';
import { isRegisteredDigestCode } from '../crypto/digests';
import { MalformedInputError } from '../profile/errors';
import {
	ALL_CODES,
	CESR_DIGEST_SHA256,
	CESR_INDEXED_SIGNATURE_ED25519,
	CESR_PUBLIC_KEY_ED25519,
	CESR_SIGNATURE_ED25519,
	CesrCodeSpec,
	digestCodeOf,
	digestSpecForCode,
} from './codes';

/**
 * Reverse of `encodeMatter`. Validates that:
 *   - the input is a string of exactly `spec.fs` characters,
 *   - the leading `spec.hs` characters equal the expected code,
 *   - the trailing characters decode under the standard base64url alphabet
 *     and round-trip canonically (this is enforced by `base64urlDecode`),
 *   - the leading `spec.ps` "pad" bytes of the decoded payload are zero.
 *
 * The last check is what catches non-canonical encodings: the high bits of
 * the first base64 character after the code prefix must be zero, because we
 * replaced exactly `ps` zero bytes with the code. If those bits aren't zero,
 * the original prefix concealed bits that a canonical encoder would have
 * placed elsewhere — a malleable form.
 */
function decodeMatter(spec: CesrCodeSpec, qb64: string): Uint8Array {
	if (typeof qb64 !== 'string') {
		throw new MalformedInputError(`${spec.label} must be a string`);
	}
	if (qb64.length !== spec.fs) {
		throw new MalformedInputError(
			`${spec.label} must be ${spec.fs} characters, got ${qb64.length}`
		);
	}
	if (qb64.slice(0, spec.hs) !== spec.code) {
		const found = qb64.slice(0, spec.hs);
		const alternative = findKnownCodeAt(qb64);
		if (alternative && alternative.code !== spec.code) {
			throw new MalformedInputError(
				`expected ${spec.label} (code '${spec.code}'), got ${alternative.label} (code '${alternative.code}')`
			);
		}
		throw new MalformedInputError(
			`expected ${spec.label} code '${spec.code}', got '${found}'`
		);
	}
	// `hs === ps` for every plain code, so substituting the prefix with `ps`
	// copies of 'A' yields a valid base64url string of length `fs`.
	const substituted = 'A'.repeat(spec.ps) + qb64.slice(spec.hs);
	const decoded = base64urlDecode(substituted);
	for (let i = 0; i < spec.ps; i++) {
		if (decoded[i] !== 0) {
			throw new MalformedInputError(
				`non-canonical ${spec.label}: leading pad bits must be zero`
			);
		}
	}
	return decoded.slice(spec.ps);
}

/**
 * Reverse of `encodeIndexedSignatureEd25519`. An indexed primitive's prefix is
 * `hs` code characters plus `ss` "soft" characters carrying the index, and
 * together they are `ps` long — so the substitution drops `hs + ss` characters
 * and prepends `ps` copies of 'A'. The index is read from the soft field.
 */
function decodeIndexedMatter(
	spec: CesrCodeSpec,
	qb64: string
): { raw: Uint8Array; index: number } {
	if (typeof qb64 !== 'string') {
		throw new MalformedInputError(`${spec.label} must be a string`);
	}
	if (qb64.length !== spec.fs) {
		throw new MalformedInputError(
			`${spec.label} must be ${spec.fs} characters, got ${qb64.length}`
		);
	}
	if (qb64.slice(0, spec.hs) !== spec.code) {
		const found = qb64.slice(0, spec.hs);
		const alternative = findKnownCodeAt(qb64);
		if (alternative && alternative.code !== spec.code) {
			throw new MalformedInputError(
				`expected ${spec.label} (code '${spec.code}'), got ${alternative.label} (code '${alternative.code}')`
			);
		}
		throw new MalformedInputError(
			`expected ${spec.label} code '${spec.code}', got '${found}'`
		);
	}
	const index = b64ToInt(qb64.slice(spec.hs, spec.hs + spec.ss));
	const substituted = 'A'.repeat(spec.ps) + qb64.slice(spec.hs + spec.ss);
	const decoded = base64urlDecode(substituted);
	for (let i = 0; i < spec.ps; i++) {
		if (decoded[i] !== 0) {
			throw new MalformedInputError(
				`non-canonical ${spec.label}: leading pad bits must be zero`
			);
		}
	}
	return { raw: decoded.slice(spec.ps), index };
}

/**
 * Look up the longest known code whose prefix matches the start of `qb64`.
 * Used purely to produce a clearer error when the caller passed a valid
 * primitive of the wrong type (e.g. a signature where a public key was
 * expected). Returns `undefined` if no known code matches.
 */
function findKnownCodeAt(qb64: string): CesrCodeSpec | undefined {
	let best: CesrCodeSpec | undefined;
	for (const candidate of ALL_CODES) {
		if (qb64.length < candidate.hs) continue;
		if (qb64.slice(0, candidate.hs) !== candidate.code) continue;
		if (!best || candidate.hs > best.hs) best = candidate;
	}
	return best;
}

/** Decode a CESR-qualified Ed25519 public key (code `D`). */
export function decodePublicKeyEd25519(qb64: string): Uint8Array {
	return decodeMatter(CESR_PUBLIC_KEY_ED25519, qb64);
}

/** Decode a CESR-qualified Ed25519 signature, non-indexed (code `0B`). */
export function decodeSignatureEd25519(qb64: string): Uint8Array {
	return decodeMatter(CESR_SIGNATURE_ED25519, qb64);
}

/**
 * Decode a CESR-qualified indexed Ed25519 signature (a "Siger", code `A`),
 * returning both the 64 raw signature bytes and the signing-key `index`
 * carried in the code's soft field.
 */
export function decodeIndexedSignatureEd25519(qb64: string): {
	raw: Uint8Array;
	index: number;
} {
	return decodeIndexedMatter(CESR_INDEXED_SIGNATURE_ED25519, qb64);
}

/**
 * Read just the signing-key index from an indexed Ed25519 signature, without
 * exposing the raw signature bytes. Convenience for callers that only need to
 * know which key in the establishment event's list a Siger claims to be from.
 */
export function signatureIndex(qb64: string): number {
	return decodeIndexedSignatureEd25519(qb64).index;
}

/** Decode a CESR-qualified SHA-256 digest (code `I`), specifically. */
export function decodeDigestSha256(qb64: string): Uint8Array {
	return decodeMatter(CESR_DIGEST_SHA256, qb64);
}

/**
 * Decode any CESR-qualified digest whose algorithm node-keri recognizes.
 *
 * "Recognizes" means the derivation code has an implementation registered in
 * `digestAlgorithms` — a built-in native hash, or one a caller has added by
 * monkey-patching that registry. A digest under an unregistered (or
 * structurally invalid) code is rejected with `MalformedInputError`: the
 * library never accepts a hash it could not recompute. The returned `code` is
 * the detected derivation code, so callers can recompute under the same
 * algorithm.
 */
export function decodeDigest(qb64: string): { raw: Uint8Array; code: string } {
	if (typeof qb64 !== 'string') {
		throw new MalformedInputError('digest must be a string');
	}
	const code = digestCodeOf(qb64);
	if (!isRegisteredDigestCode(code)) {
		throw new MalformedInputError(
			`unrecognized or unavailable digest code '${code}'`
		);
	}
	// `code` came from `digestCodeOf`, so its shape is always a valid digest
	// width and `digestSpecForCode` will not throw here.
	const raw = decodeMatter(digestSpecForCode(code), qb64);
	return { raw, code };
}
