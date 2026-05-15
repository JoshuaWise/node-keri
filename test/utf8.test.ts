import { utf8Decode, utf8Encode } from '../src/bytes/utf8';
import { MalformedInputError } from '../src/profile/errors';

describe('utf8', () => {
	test('encodes ASCII', () => {
		expect(Array.from(utf8Encode('abc'))).toEqual([0x61, 0x62, 0x63]);
	});

	test('encodes multi-byte codepoints', () => {
		// U+00E9 (é) → 0xC3 0xA9; U+1F600 (😀) → 0xF0 0x9F 0x98 0x80
		expect(Array.from(utf8Encode('é'))).toEqual([0xc3, 0xa9]);
		expect(Array.from(utf8Encode('😀'))).toEqual([0xf0, 0x9f, 0x98, 0x80]);
	});

	test('round-trips Unicode strings', () => {
		const samples = ['', 'hello', 'café', '日本語', '🔑🛡️'];
		for (const s of samples) {
			expect(utf8Decode(utf8Encode(s))).toBe(s);
		}
	});

	test('rejects invalid UTF-8 bytes', () => {
		// 0xC3 starts a 2-byte sequence but is followed by an invalid byte.
		expect(() => utf8Decode(new Uint8Array([0xc3, 0x28]))).toThrow(
			MalformedInputError
		);
	});

	test('rejects lone surrogates', () => {
		expect(() => utf8Decode(new Uint8Array([0xed, 0xa0, 0x80]))).toThrow(
			MalformedInputError
		);
	});
});
