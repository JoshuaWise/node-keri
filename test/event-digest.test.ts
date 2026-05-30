import { utf8Decode, utf8Encode } from '../src/bytes/utf8';
import { canonicalizeJson } from '../src/event/canonical-json';
import {
	KERI_VERSION_STRING_LENGTH,
	SAID_PLACEHOLDER,
	computeEventSaid,
	deriveNextKeyCommitment,
	formatKeriVersionString,
} from '../src/event/digest';
import { toCanonicalEvent } from '../src/event/field-order';
import { decodeDigestSha256 } from '../src/cesr/decode';
import { keyPairFromSeed, publicKeyToCesr } from '../src/crypto/keypair';
import { CanonicalJsonError, InvalidArgumentError } from '../src/profile/errors';
import { sha256, fillSeed } from './helpers/util';

describe('formatKeriVersionString', () => {
	test('produces a fixed 17-character string with size in 6 hex chars', () => {
		expect(formatKeriVersionString(0)).toBe('KERI10JSON000000_');
		expect(formatKeriVersionString(255)).toBe('KERI10JSON0000ff_');
		expect(formatKeriVersionString(0xffffff)).toBe('KERI10JSONffffff_');
		// Length is constant regardless of size value.
		expect(formatKeriVersionString(1).length).toBe(KERI_VERSION_STRING_LENGTH);
		expect(formatKeriVersionString(0xfffff).length).toBe(KERI_VERSION_STRING_LENGTH);
	});

	test('rejects non-integer or negative sizes', () => {
		expect(() => formatKeriVersionString(-1)).toThrow(InvalidArgumentError);
		expect(() => formatKeriVersionString(1.5)).toThrow(InvalidArgumentError);
		expect(() => formatKeriVersionString(NaN)).toThrow(InvalidArgumentError);
	});

	test('rejects sizes that overflow the 6-char hex field', () => {
		expect(() => formatKeriVersionString(0x1000000)).toThrow(CanonicalJsonError);
	});
});

describe('SAID_PLACEHOLDER', () => {
	test('is 44 `#` characters', () => {
		expect(SAID_PLACEHOLDER).toBe('#'.repeat(44));
	});
});

describe('computeEventSaid', () => {
	test('produces a SAID whose embedded version-string size matches the bytes', () => {
		// SAID-bearing fields are passed already holding the placeholder.
		const fields = {
			t: 'icp' as const,
			d: SAID_PLACEHOLDER,
			i: SAID_PLACEHOLDER,
			s: '0',
			kt: '1',
		};
		const { said, versionString, digestedBytes } = computeEventSaid(fields);

		// The size encoded in v must equal the byte length of the digested bytes.
		const sizeHex = versionString.slice('KERI10JSON'.length, 'KERI10JSON'.length + 6);
		expect(parseInt(sizeHex, 16)).toBe(digestedBytes.length);

		// The SAID is a SHA-256 digest of those exact bytes.
		const expected = sha256(digestedBytes);
		expect(Array.from(decodeDigestSha256(said))).toEqual(Array.from(expected));
	});

	test('is deterministic for equal inputs', () => {
		const fields = {
			t: 'icp' as const,
			d: SAID_PLACEHOLDER,
			i: SAID_PLACEHOLDER,
			s: '0',
			kt: '1',
		};
		const a = computeEventSaid(fields);
		const b = computeEventSaid(fields);
		expect(a.said).toBe(b.said);
		expect(a.versionString).toBe(b.versionString);
		expect(Array.from(a.digestedBytes)).toEqual(Array.from(b.digestedBytes));
	});

	test('serializes fields in canonical order regardless of input order', () => {
		// Same fields, scrambled construction order, must yield the same SAID.
		const ordered = computeEventSaid({
			t: 'ixn' as const,
			d: SAID_PLACEHOLDER,
			i: 'I' + 'A'.repeat(43),
			s: '1',
			p: 'E' + 'B'.repeat(43),
			a: [],
		});
		const scrambled = computeEventSaid({
			a: [],
			p: 'E' + 'B'.repeat(43),
			s: '1',
			i: 'I' + 'A'.repeat(43),
			d: SAID_PLACEHOLDER,
			t: 'ixn' as const,
		});
		expect(scrambled.said).toBe(ordered.said);
		expect(Array.from(scrambled.digestedBytes)).toEqual(
			Array.from(ordered.digestedBytes)
		);
	});

	test('digested bytes contain placeholder, not the SAID itself', () => {
		const fields = { t: 'ixn' as const, d: SAID_PLACEHOLDER, s: '1' };
		const { said, digestedBytes } = computeEventSaid(fields);
		const json = utf8Decode(digestedBytes);
		expect(json).toContain('"d":"' + SAID_PLACEHOLDER + '"');
		expect(json).not.toContain(said);
	});

	test('rejects an event of unknown type', () => {
		expect(() => computeEventSaid({ t: 'xyz' })).toThrow(InvalidArgumentError);
		expect(() => computeEventSaid({ s: '0' })).toThrow(InvalidArgumentError);
	});

	test('different inputs produce different SAIDs', () => {
		const a = computeEventSaid({ t: 'ixn', d: SAID_PLACEHOLDER, s: '1' });
		const b = computeEventSaid({ t: 'ixn', d: SAID_PLACEHOLDER, s: '2' });
		expect(a.said).not.toBe(b.said);
	});

	test('digested bytes round-trip through the canonical serialization', () => {
		// Verifying that the function emits exactly canonicalizeJson output
		// over the canonically-ordered event: reconstructing the same event
		// should reproduce the bytes the SAID was computed over.
		const fields = {
			t: 'ixn' as const,
			d: SAID_PLACEHOLDER,
			i: 'I' + 'A'.repeat(43),
			s: '1',
			p: 'E' + 'B'.repeat(43),
			a: [],
		};
		const { versionString, digestedBytes } = computeEventSaid(fields);
		const reconstructed = canonicalizeJson(
			toCanonicalEvent({ ...fields, v: versionString })
		);
		expect(Array.from(reconstructed)).toEqual(Array.from(digestedBytes));
	});
});

describe('deriveNextKeyCommitment', () => {
	test('hashes the qb64 form of the public key', () => {
		const kp = keyPairFromSeed(fillSeed(0x07));
		const qb64 = publicKeyToCesr(kp.publicKey);
		const expected = sha256(utf8Encode(qb64));

		const commitment = deriveNextKeyCommitment(kp.publicKey);
		expect(Array.from(decodeDigestSha256(commitment))).toEqual(Array.from(expected));
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
		expect(() => deriveNextKeyCommitment({} as never)).toThrow(InvalidArgumentError);
	});
});
