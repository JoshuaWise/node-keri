import { utf8Decode } from '../src/bytes/utf8';
import { canonicalizeJson } from '../src/event/canonical-json';
import { CanonicalJsonError } from '../src/profile/errors';

function canon(value: unknown): string {
	return utf8Decode(canonicalizeJson(value));
}

describe('canonicalizeJson', () => {
	test('serializes primitives', () => {
		expect(canon(null)).toBe('null');
		expect(canon(true)).toBe('true');
		expect(canon(false)).toBe('false');
		expect(canon('hello')).toBe('"hello"');
		expect(canon(0)).toBe('0');
		expect(canon(42)).toBe('42');
		expect(canon(-7)).toBe('-7');
	});

	test('escapes strings via JSON.stringify rules', () => {
		expect(canon('a"b')).toBe('"a\\"b"');
		expect(canon('a\nb')).toBe('"a\\nb"');
		expect(canon('日本語')).toBe('"日本語"');
	});

	test('serializes arrays preserving order', () => {
		expect(canon([])).toBe('[]');
		expect(canon([3, 1, 2])).toBe('[3,1,2]');
		expect(canon([null, true, 'x'])).toBe('[null,true,"x"]');
	});

	test('preserves object key insertion order', () => {
		// Keys are emitted in property order, never sorted — KERI uses a
		// fixed canonical field order, applied by toCanonicalEvent upstream.
		expect(canon({ b: 1, a: 2, c: 3 })).toBe('{"b":1,"a":2,"c":3}');
		expect(canon({ c: 3, a: 2, b: 1 })).toBe('{"c":3,"a":2,"b":1}');
	});

	test('produces no whitespace', () => {
		const out = canon({ a: [1, 2], b: { c: 'd' } });
		expect(out).toBe('{"a":[1,2],"b":{"c":"d"}}');
		expect(/\s/.test(out)).toBe(false);
	});

	test('is deterministic for equal inputs', () => {
		const a = canonicalizeJson({ x: 1, y: [2, 3], z: { q: 'r', p: null } });
		const b = canonicalizeJson({ x: 1, y: [2, 3], z: { q: 'r', p: null } });
		expect(Array.from(a)).toEqual(Array.from(b));
	});

	test('rejects non-finite numbers', () => {
		expect(() => canon(NaN)).toThrow(CanonicalJsonError);
		expect(() => canon(Infinity)).toThrow(CanonicalJsonError);
		expect(() => canon(-Infinity)).toThrow(CanonicalJsonError);
	});

	test('rejects negative zero', () => {
		expect(() => canon(-0)).toThrow(CanonicalJsonError);
	});

	test('rejects bigint', () => {
		expect(() => canon(BigInt(1))).toThrow(CanonicalJsonError);
	});

	test('rejects undefined at every position', () => {
		expect(() => canon(undefined)).toThrow(CanonicalJsonError);
		expect(() => canon([undefined])).toThrow(CanonicalJsonError);
		expect(() => canon({ a: undefined })).toThrow(CanonicalJsonError);
	});

	test('rejects functions and symbols', () => {
		expect(() => canon(() => 1)).toThrow(CanonicalJsonError);
		expect(() => canon(Symbol('x'))).toThrow(CanonicalJsonError);
		expect(() => canon({ a: () => 1 })).toThrow(CanonicalJsonError);
		expect(() => canon([Symbol('x')])).toThrow(CanonicalJsonError);
	});

	test('rejects non-plain objects', () => {
		class Foo {
			x = 1;
		}
		expect(() => canon(new Foo())).toThrow(CanonicalJsonError);
		expect(() => canon(new Map())).toThrow(CanonicalJsonError);
		expect(() => canon(new Date(0))).toThrow(CanonicalJsonError);
	});

	test('emits UTF-8 bytes', () => {
		const bytes = canonicalizeJson({ k: 'é' });
		// {"k":"é"} → {"k":" 0xc3 0xa9 "}
		expect(Array.from(bytes)).toEqual([
			0x7b, 0x22, 0x6b, 0x22, 0x3a, 0x22, 0xc3, 0xa9, 0x22, 0x7d,
		]);
	});
});
