/**
 * Digest algorithm registry for CESR-qualified digests.
 *
 * KERI digests are self-describing: every qualified digest carries a CESR
 * derivation code that names its hash algorithm. node-keri keys this registry
 * by that code, so a KEL may freely mix algorithms — each event's `d`, `i`,
 * `p`, and next-key digest is recomputed under whatever algorithm its own code
 * declares, never under a single KEL-wide assumption.
 *
 * The policy is "support any available 256-bit or 512-bit hash":
 *   - node-keri auto-registers every native `node:crypto` hash it can use —
 *     SHA2-256/512, SHA3-256/512, BLAKE2s-256, BLAKE2b-512 — but only those
 *     the linked OpenSSL actually provides (`getHashes()` is the source of
 *     truth, since SHA3 and BLAKE2 availability is build-dependent).
 *   - a digest under a code with no registered implementation is rejected;
 *     the library fails closed rather than accept a hash it cannot recompute.
 *   - SHA2-256 (`I`) is always present and is the default for generation.
 *
 * `digestAlgorithms` is a null-prototype object so it is safe to index with an
 * untrusted code (no `__proto__` / `constructor` footguns) and carries no
 * inherited keys. It is intentionally mutable: a caller may add an algorithm
 * node-keri does not ship — e.g. Blake3-256 — by assigning an entry, after
 * which decoding, verification, and generation all accept that code:
 *
 * ```ts
 * import { digestAlgorithms } from 'node-keri';
 * digestAlgorithms['E'] = { name: 'Blake3-256', hash: myBlake3_256 };
 * ```
 */

import { createHash, getHashes } from 'node:crypto';
import { digestSpecForCode } from '../cesr/codes';
import { UnsupportedAlgorithmError } from '../profile/errors';

/** A hash algorithm registered against a CESR digest derivation code. */
export interface DigestAlgorithm {
	/** Human-readable name, used only in diagnostics. */
	readonly name: string;
	/**
	 * Compute the raw digest of `input`. Must return exactly 32 bytes for a
	 * 256-bit (one-character) code or 64 bytes for a 512-bit (`0`-prefixed)
	 * code; a result of any other length or type is rejected by `runDigest`.
	 */
	hash(input: Uint8Array): Uint8Array;
}

/**
 * Well-known CESR digest derivation codes, for callers that prefer a name to
 * a bare character. `BLAKE3_256` and `BLAKE2B_256` have no native Node.js
 * implementation — they are listed so a caller can register one against the
 * conventional code.
 */
export const DIGEST_CODES = Object.freeze({
	SHA2_256: 'I',
	SHA2_512: '0G',
	SHA3_256: 'H',
	SHA3_512: '0E',
	BLAKE2B_512: '0F',
	BLAKE2S_256: 'G',
	BLAKE2B_256: 'F',
	BLAKE3_256: 'E',
});

/** The digest code used for generation when a caller does not pick one. */
export const DEFAULT_DIGEST_CODE: string = DIGEST_CODES.SHA2_256;

/**
 * The live registry of digest implementations, keyed by CESR derivation code.
 * Monkey-patchable — see the module comment.
 *
 * The value type is `DigestAlgorithm | undefined` deliberately: the registry is
 * sparse (only registered codes have entries) and null-prototyped, so indexing
 * with an arbitrary — possibly untrusted — code yields `undefined`. Encoding
 * that in the type forces every reader to handle the absent case.
 */
export const digestAlgorithms: Record<string, DigestAlgorithm | undefined> =
	Object.create(null);

/** One-shot hash through `node:crypto`. */
function nodeHash(nodeName: string, input: Uint8Array): Uint8Array {
	return new Uint8Array(createHash(nodeName).update(input).digest());
}

/**
 * Native hashes node-keri registers automatically — paired with their
 * `node:crypto` algorithm name. Only those `getHashes()` reports are added.
 */
const NATIVE_DIGESTS: ReadonlyArray<{
	code: string;
	name: string;
	nodeName: string;
}> = [
	{ code: DIGEST_CODES.SHA2_256, name: 'SHA2-256', nodeName: 'sha256' },
	{ code: DIGEST_CODES.SHA2_512, name: 'SHA2-512', nodeName: 'sha512' },
	{ code: DIGEST_CODES.SHA3_256, name: 'SHA3-256', nodeName: 'sha3-256' },
	{ code: DIGEST_CODES.SHA3_512, name: 'SHA3-512', nodeName: 'sha3-512' },
	{ code: DIGEST_CODES.BLAKE2S_256, name: 'BLAKE2s-256', nodeName: 'blake2s256' },
	{ code: DIGEST_CODES.BLAKE2B_512, name: 'BLAKE2b-512', nodeName: 'blake2b512' },
];

(function registerNativeDigests(): void {
	// `getHashes()` names are matched case-insensitively: the precise casing
	// OpenSSL reports has varied across Node releases.
	const available = new Set(getHashes().map((h) => h.toLowerCase()));
	for (const d of NATIVE_DIGESTS) {
		if (!available.has(d.nodeName)) continue;
		digestAlgorithms[d.code] = Object.freeze({
			name: d.name,
			hash: (input: Uint8Array): Uint8Array => nodeHash(d.nodeName, input),
		});
	}
	// SHA-256 is the default generation algorithm and the AID/SAID workhorse;
	// a runtime without it cannot host this library.
	if (!digestAlgorithms[DEFAULT_DIGEST_CODE]) {
		throw new Error('node-keri requires SHA-256 (`sha256`) support in node:crypto');
	}
})();

/** True when `code` has a registered — and therefore available — implementation. */
export function isRegisteredDigestCode(code: unknown): code is string {
	return typeof code === 'string' && digestAlgorithms[code] !== undefined;
}

/**
 * Hash `input` with the algorithm registered for CESR digest `code`.
 *
 * Throws `UnsupportedAlgorithmError` when the code's shape is not a supported
 * digest width, when no implementation is registered for it, or when a
 * registered implementation returns a result of the wrong type or length —
 * the last guards against a faulty monkey-patched algorithm.
 *
 * If a registered implementation itself *throws*, that exception is not caught
 * or wrapped: it propagates unchanged. A faulty registered algorithm is a
 * programmer error, not the hostile input the verifier turns into a result.
 */
export function runDigest(code: string, input: Uint8Array): Uint8Array {
	const spec = digestSpecForCode(code);
	const algorithm = digestAlgorithms[code];
	if (!algorithm || typeof algorithm.hash !== 'function') {
		throw new UnsupportedAlgorithmError(
			`no digest implementation is registered for CESR code '${code}'`
		);
	}
	const out = algorithm.hash(input);
	if (!(out instanceof Uint8Array)) {
		throw new UnsupportedAlgorithmError(
			`digest implementation for code '${code}' did not return a Uint8Array`
		);
	}
	if (out.length !== spec.rs) {
		throw new UnsupportedAlgorithmError(
			`digest implementation for code '${code}' returned ${out.length} bytes, `
				+ `expected ${spec.rs}`
		);
	}
	return out;
}
