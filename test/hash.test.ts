import { utf8Encode } from '../src/bytes/utf8';
import { sha256 } from '../src/crypto/hash';

function hex(bytes: Uint8Array): string {
	let s = '';
	for (const b of bytes) s += b.toString(16).padStart(2, '0');
	return s;
}

describe('sha256', () => {
	test('matches NIST/RFC vectors', () => {
		// Empty string
		expect(hex(sha256(new Uint8Array(0)))).toBe(
			'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
		);
		// "abc"
		expect(hex(sha256(utf8Encode('abc')))).toBe(
			'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
		);
		// "The quick brown fox jumps over the lazy dog"
		expect(
			hex(sha256(utf8Encode('The quick brown fox jumps over the lazy dog')))
		).toBe('d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592');
	});

	test('always returns 32 bytes', () => {
		expect(sha256(new Uint8Array(0)).length).toBe(32);
		expect(sha256(new Uint8Array(1024)).length).toBe(32);
	});

	test('is deterministic', () => {
		const input = utf8Encode('keri');
		expect(Array.from(sha256(input))).toEqual(Array.from(sha256(input)));
	});
});
