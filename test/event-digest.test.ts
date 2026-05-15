import { utf8Decode, utf8Encode } from '../src/bytes/utf8';
import { canonicalizeJson } from '../src/event/canonical-json';
import {
	KERI_VERSION_STRING_LENGTH,
	SAID_PLACEHOLDER,
	computeEventSaid,
	deriveNextKeyCommitment,
	formatKeriVersionString,
} from '../src/event/digest';
import { decodeDigestSha256 } from '../src/cesr/decode';
import { sha256 } from '../src/crypto/hash';
import { encodePublicKeyEd25519 } from '../src/cesr/encode';
import { keyPairFromSeed } from '../src/crypto/keypair';
import {
	CanonicalJsonError,
	InvalidArgumentError,
} from '../src/profile/errors';

function fillSeed(byte: number): Uint8Array {
	return new Uint8Array(32).fill(byte);
}

describe('formatKeriVersionString', () => {
	test('produces a fixed 17-character string with size in 6 hex chars', () => {
		expect(formatKeriVersionString(0)).toBe('KERI10JSON000000_');
		expect(formatKeriVersionString(255)).toBe('KERI10JSON0000ff_');
		expect(formatKeriVersionString(0xffffff)).toBe('KERI10JSONffffff_');
		// Length is constant regardless of size value.
		expect(formatKeriVersionString(1).length).toBe(KERI_VERSION_STRING_LENGTH);
		expect(formatKeriVersionString(0xfffff).length).toBe(
			KERI_VERSION_STRING_LENGTH
		);
	});

	test('rejects non-integer or negative sizes', () => {
		expect(() => formatKeriVersionString(-1)).toThrow(InvalidArgumentError);
		expect(() => formatKeriVersionString(1.5)).toThrow(InvalidArgumentError);
		expect(() => formatKeriVersionString(NaN)).toThrow(InvalidArgumentError);
	});

	test('rejects sizes that overflow the 6-char hex field', () => {
		expect(() => formatKeriVersionString(0x1000000)).toThrow(
			CanonicalJsonError
		);
	});
});

describe('SAID_PLACEHOLDER', () => {
	test('is 44 `#` characters', () => {
		expect(SAID_PLACEHOLDER).toBe('#'.repeat(44));
	});
});

describe('computeEventSaid', () => {
	test('produces a SAID whose embedded version-string size matches the bytes', () => {
		const partial = {
			t: 'icp' as const,
			s: '0',
			kt: '1',
		};
		const { said, versionString, digestedBytes } = computeEventSaid(
			partial,
			['d', 'i']
		);

		// The size encoded in v must equal the byte length of the digested bytes.
		const sizeHex = versionString.slice(
			'KERI10JSON'.length,
			'KERI10JSON'.length + 6
		);
		expect(parseInt(sizeHex, 16)).toBe(digestedBytes.length);

		// The SAID is a SHA-256 digest of those exact bytes.
		const expected = sha256(digestedBytes);
		expect(Array.from(decodeDigestSha256(said))).toEqual(Array.from(expected));
	});

	test('is deterministic for equal inputs', () => {
		const partial = {
			t: 'icp' as const,
			s: '0',
			kt: '1',
			extra: { z: 1, a: 2 },
		};
		const a = computeEventSaid(partial, ['d', 'i']);
		const b = computeEventSaid(partial, ['d', 'i']);
		expect(a.said).toBe(b.said);
		expect(a.versionString).toBe(b.versionString);
		expect(Array.from(a.digestedBytes)).toEqual(Array.from(b.digestedBytes));
	});

	test('digested bytes contain placeholder, not the SAID itself', () => {
		const partial = { t: 'ixn' as const, s: '1' };
		const { said, digestedBytes } = computeEventSaid(partial, ['d']);
		const json = utf8Decode(digestedBytes);
		expect(json).toContain('"d":"' + SAID_PLACEHOLDER + '"');
		expect(json).not.toContain(said);
	});

	test('rejects empty saidFields', () => {
		expect(() => computeEventSaid({ t: 'ixn' }, [])).toThrow(
			InvalidArgumentError
		);
	});

	test('rejects partial event containing v or a SAID field', () => {
		expect(() =>
			computeEventSaid({ v: 'KERI10JSON000000_' }, ['d'])
		).toThrow(InvalidArgumentError);
		expect(() =>
			computeEventSaid({ d: SAID_PLACEHOLDER }, ['d'])
		).toThrow(InvalidArgumentError);
		expect(() =>
			computeEventSaid({ t: 'icp', i: 'placeholder' }, ['d', 'i'])
		).toThrow(InvalidArgumentError);
	});

	test('rejects "v" listed as a SAID field', () => {
		expect(() => computeEventSaid({ t: 'icp' }, ['v'])).toThrow(
			InvalidArgumentError
		);
	});

	test('different inputs produce different SAIDs', () => {
		const a = computeEventSaid({ t: 'ixn', s: '1' }, ['d']);
		const b = computeEventSaid({ t: 'ixn', s: '2' }, ['d']);
		expect(a.said).not.toBe(b.said);
	});

	test('digested bytes round-trip through canonicalizeJson', () => {
		// Verifying that the function emits exactly canonicalizeJson output:
		// reconstructing the same object and canonicalizing should reproduce
		// the same bytes the SAID was computed over.
		const partial = { t: 'ixn' as const, i: 'I' + 'A'.repeat(43), s: '1' };
		const { versionString, digestedBytes } = computeEventSaid(partial, ['d']);
		const reconstructed = canonicalizeJson({
			...partial,
			d: SAID_PLACEHOLDER,
			v: versionString,
		});
		expect(Array.from(reconstructed)).toEqual(Array.from(digestedBytes));
	});
});

describe('deriveNextKeyCommitment', () => {
	test('hashes the qb64 form of the public key', () => {
		const kp = keyPairFromSeed(fillSeed(0x07));
		const qb64 = encodePublicKeyEd25519(kp.publicKey.raw);
		const expected = sha256(utf8Encode(qb64));

		const commitment = deriveNextKeyCommitment(kp.publicKey);
		expect(Array.from(decodeDigestSha256(commitment))).toEqual(
			Array.from(expected)
		);
	});

	test('is deterministic for the same key', () => {
		const kp = keyPairFromSeed(fillSeed(0x09));
		expect(deriveNextKeyCommitment(kp.publicKey)).toBe(
			deriveNextKeyCommitment(kp.publicKey)
		);
	});

	test('different keys produce different commitments', () => {
		const a = keyPairFromSeed(fillSeed(0x10));
		const b = keyPairFromSeed(fillSeed(0x11));
		expect(deriveNextKeyCommitment(a.publicKey)).not.toBe(
			deriveNextKeyCommitment(b.publicKey)
		);
	});

	test('rejects non-public-key inputs', () => {
		expect(() =>
			deriveNextKeyCommitment({} as never)
		).toThrow(InvalidArgumentError);
	});
});
