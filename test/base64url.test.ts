import { base64urlDecode, base64urlEncode } from '../src/bytes/base64url';
import { MalformedInputError } from '../src/profile/errors';

describe('base64url', () => {
	test('encodes RFC 4648 vectors without padding', () => {
		// Test vectors derived from RFC 4648 §10, converted to URL-safe alphabet.
		expect(base64urlEncode(new Uint8Array([]))).toBe('');
		expect(base64urlEncode(new Uint8Array([0x66]))).toBe('Zg');
		expect(base64urlEncode(new Uint8Array([0x66, 0x6f]))).toBe('Zm8');
		expect(base64urlEncode(new Uint8Array([0x66, 0x6f, 0x6f]))).toBe('Zm9v');
		expect(base64urlEncode(new Uint8Array([0x66, 0x6f, 0x6f, 0x62]))).toBe(
			'Zm9vYg'
		);
		expect(base64urlEncode(new Uint8Array([0xff, 0xff, 0xff]))).toBe('____');
		expect(base64urlEncode(new Uint8Array([0xfb, 0xff, 0xbf]))).toBe('-_-_');
	});

	test('round-trips arbitrary bytes', () => {
		for (let len = 0; len < 200; len++) {
			const bytes = new Uint8Array(len);
			for (let i = 0; i < len; i++) bytes[i] = (i * 37 + 11) & 0xff;
			const encoded = base64urlEncode(bytes);
			expect(/^[A-Za-z0-9_-]*$/.test(encoded)).toBe(true);
			const decoded = base64urlDecode(encoded);
			expect(Array.from(decoded)).toEqual(Array.from(bytes));
		}
	});

	test('rejects padding', () => {
		expect(() => base64urlDecode('Zg==')).toThrow(MalformedInputError);
		expect(() => base64urlDecode('Zm8=')).toThrow(MalformedInputError);
	});

	test('rejects standard-base64 characters', () => {
		expect(() => base64urlDecode('a+b/')).toThrow(MalformedInputError);
	});

	test('rejects whitespace and control chars', () => {
		expect(() => base64urlDecode('Zm 8')).toThrow(MalformedInputError);
		expect(() => base64urlDecode('Zm\n8')).toThrow(MalformedInputError);
	});

	test('rejects length === 1 mod 4', () => {
		expect(() => base64urlDecode('A')).toThrow(MalformedInputError);
		expect(() => base64urlDecode('AAAAA')).toThrow(MalformedInputError);
	});

	test('rejects non-canonical encodings (trailing bits set)', () => {
		// 'Zh' decodes to 0x66 with the lowest 2 bits of 'h' (0x21) being
		// nonzero — Buffer would silently accept this.
		expect(() => base64urlDecode('Zh')).toThrow(MalformedInputError);
	});

	test('rejects non-string input', () => {
		expect(() => base64urlDecode(123 as unknown as string)).toThrow(
			MalformedInputError
		);
	});

	test('handles a Uint8Array view into a larger buffer', () => {
		const buf = new Uint8Array([0x00, 0x66, 0x6f, 0x6f, 0x00]);
		const view = new Uint8Array(buf.buffer, 1, 3);
		expect(base64urlEncode(view)).toBe('Zm9v');
	});
});
