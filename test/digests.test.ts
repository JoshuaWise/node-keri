/**
 * Tests for the digest algorithm registry (`src/crypto/digests.ts`).
 *
 * Covers the native auto-registration, `runDigest` dispatch and its
 * fail-closed guards, and the monkey-patch path a caller uses to add an
 * algorithm node-keri does not ship.
 */

import { createHash } from 'node:crypto';
import {
	DEFAULT_DIGEST_CODE,
	DIGEST_CODES,
	DigestAlgorithm,
	digestAlgorithms,
	isRegisteredDigestCode,
	runDigest,
} from '../src/crypto/digests';
import { utf8Encode } from '../src/bytes/utf8';
import { UnsupportedAlgorithmError } from '../src/profile/errors';
import { sha256 } from './helpers/util';

/** Snapshot the registry so a test's monkey-patches never leak to the next. */
let snapshot: Record<string, DigestAlgorithm | undefined>;
beforeEach(() => {
	snapshot = {};
	for (const code of Object.keys(digestAlgorithms)) {
		snapshot[code] = digestAlgorithms[code];
	}
});
afterEach(() => {
	// `digestAlgorithms` is sealed, so its entries are cleared by reassignment
	// to `undefined` rather than `delete`d, then restored from the snapshot.
	for (const code of Object.keys(digestAlgorithms)) digestAlgorithms[code] = undefined;
	for (const code of Object.keys(snapshot)) digestAlgorithms[code] = snapshot[code];
});

/** The six native codes node-keri tries to auto-register, with sizes. */
const NATIVE: ReadonlyArray<{ code: string; nodeName: string; size: number }> = [
	{ code: DIGEST_CODES.SHA2_256, nodeName: 'sha256', size: 32 },
	{ code: DIGEST_CODES.SHA2_512, nodeName: 'sha512', size: 64 },
	{ code: DIGEST_CODES.SHA3_256, nodeName: 'sha3-256', size: 32 },
	{ code: DIGEST_CODES.SHA3_512, nodeName: 'sha3-512', size: 64 },
	{ code: DIGEST_CODES.BLAKE2S_256, nodeName: 'blake2s256', size: 32 },
	{ code: DIGEST_CODES.BLAKE2B_512, nodeName: 'blake2b512', size: 64 },
];

describe('digestAlgorithms registry', () => {
	test('is a null-prototype object', () => {
		expect(Object.getPrototypeOf(digestAlgorithms)).toBeNull();
		// A hostile code never resolves to an inherited member.
		expect(digestAlgorithms['__proto__']).toBeUndefined();
		expect(digestAlgorithms['constructor']).toBeUndefined();
	});

	test('SHA-256 is always registered and is the default code', () => {
		expect(DEFAULT_DIGEST_CODE).toBe('I');
		expect(isRegisteredDigestCode('I')).toBe(true);
		expect(typeof digestAlgorithms['I']!.hash).toBe('function');
	});

	test('every registered native algorithm matches node:crypto exactly', () => {
		const input = utf8Encode('keri digest registry');
		for (const { code, nodeName, size } of NATIVE) {
			if (!isRegisteredDigestCode(code)) continue; // build-dependent
			const out = runDigest(code, input);
			expect(out.length).toBe(size);
			const expected = new Uint8Array(createHash(nodeName).update(input).digest());
			expect(Array.from(out)).toEqual(Array.from(expected));
		}
	});

	test('the SHA-256 entry agrees with the sha256 helper', () => {
		const input = utf8Encode('abc');
		expect(Array.from(runDigest('I', input))).toEqual(Array.from(sha256(input)));
	});

	test('DIGEST_CODES is frozen and names the conventional codes', () => {
		expect(Object.isFrozen(DIGEST_CODES)).toBe(true);
		expect(DIGEST_CODES.SHA2_256).toBe('I');
		expect(DIGEST_CODES.SHA2_512).toBe('0G');
		expect(DIGEST_CODES.SHA3_256).toBe('H');
		expect(DIGEST_CODES.BLAKE3_256).toBe('E');
	});
});

describe('isRegisteredDigestCode', () => {
	test('false for non-strings and unregistered codes', () => {
		expect(isRegisteredDigestCode(undefined)).toBe(false);
		expect(isRegisteredDigestCode(42)).toBe(false);
		// `E` (Blake3) has no native implementation.
		expect(isRegisteredDigestCode('E')).toBe(false);
		expect(isRegisteredDigestCode('ZZ')).toBe(false);
	});
});

describe('runDigest — fail-closed guards', () => {
	test('throws for a well-formed but unregistered code', () => {
		expect(() => runDigest('E', utf8Encode('x'))).toThrow(UnsupportedAlgorithmError);
	});

	test('throws for a structurally invalid digest code', () => {
		expect(() => runDigest('XYZ', utf8Encode('x'))).toThrow(
			UnsupportedAlgorithmError
		);
		expect(() => runDigest('', utf8Encode('x'))).toThrow(UnsupportedAlgorithmError);
	});

	test('throws when a registered implementation returns the wrong length', () => {
		// `F` is a one-character (256-bit) code: a 64-byte result is invalid.
		digestAlgorithms['F'] = {
			name: 'broken',
			hash: () => new Uint8Array(64),
		};
		expect(() => runDigest('F', utf8Encode('x'))).toThrow(UnsupportedAlgorithmError);
	});

	test('throws when a registered implementation returns a non-Uint8Array', () => {
		digestAlgorithms['F'] = {
			name: 'broken',
			hash: () => 'not bytes' as unknown as Uint8Array,
		};
		expect(() => runDigest('F', utf8Encode('x'))).toThrow(UnsupportedAlgorithmError);
	});

	test('throws when a 512-bit code implementation returns the wrong length', () => {
		// `0Z` is a `0`-prefixed (512-bit) code: a 32-byte result is invalid.
		digestAlgorithms['0Z'] = {
			name: 'broken',
			hash: () => new Uint8Array(32),
		};
		expect(() => runDigest('0Z', utf8Encode('x'))).toThrow(UnsupportedAlgorithmError);
	});

	test('a throwing implementation bubbles its error up unchanged', () => {
		// A faulty registered algorithm is a programmer error, not hostile
		// input: `runDigest` does not wrap or swallow the throw, so the
		// caller's own exception propagates verbatim.
		digestAlgorithms['F'] = {
			name: 'explodes',
			hash: () => {
				throw new RangeError('algorithm went boom');
			},
		};
		expect(() => runDigest('F', utf8Encode('x'))).toThrow(RangeError);
		expect(() => runDigest('F', utf8Encode('x'))).toThrow('algorithm went boom');
	});
});

describe('runDigest — monkey-patched algorithm', () => {
	test('a caller-registered algorithm becomes usable', () => {
		// Stand-in for an algorithm node-keri does not ship: a deterministic
		// 32-byte hash registered under the otherwise-unused Blake2b-256 code.
		const doubleSha = (input: Uint8Array): Uint8Array => sha256(sha256(input));
		expect(isRegisteredDigestCode('F')).toBe(false);

		digestAlgorithms['F'] = { name: 'double-SHA256', hash: doubleSha };

		expect(isRegisteredDigestCode('F')).toBe(true);
		const input = utf8Encode('payload');
		expect(Array.from(runDigest('F', input))).toEqual(Array.from(doubleSha(input)));
	});

	test('the patch does not leak across tests (registry was restored)', () => {
		// `afterEach` removed the previous test's `F` entry.
		expect(isRegisteredDigestCode('F')).toBe(false);
	});
});
