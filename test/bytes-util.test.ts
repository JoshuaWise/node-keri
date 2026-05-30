import { bytesEqual, concatBytes } from '../src/bytes/util';

describe('bytes/util', () => {
	test('bytesEqual returns true for equal arrays', () => {
		const a = new Uint8Array([1, 2, 3, 4]);
		const b = new Uint8Array([1, 2, 3, 4]);
		expect(bytesEqual(a, b)).toBe(true);
	});

	test('bytesEqual returns false for differing arrays of equal length', () => {
		expect(bytesEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(
			false
		);
	});

	test('bytesEqual returns false for differing lengths', () => {
		expect(bytesEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2]))).toBe(false);
	});

	test('bytesEqual rejects mismatches and length differences', () => {
		expect(bytesEqual(new Uint8Array([7, 8, 9]), new Uint8Array([7, 0, 9]))).toBe(
			false
		);
		expect(bytesEqual(new Uint8Array([7, 8]), new Uint8Array([7, 8, 9]))).toBe(false);
	});

	test('concatBytes joins zero, one, and many arrays', () => {
		expect(Array.from(concatBytes())).toEqual([]);
		expect(Array.from(concatBytes(new Uint8Array([1, 2, 3])))).toEqual([1, 2, 3]);
		expect(
			Array.from(
				concatBytes(
					new Uint8Array([1]),
					new Uint8Array([2, 3]),
					new Uint8Array([4, 5, 6])
				)
			)
		).toEqual([1, 2, 3, 4, 5, 6]);
	});

	test('concatBytes returns a fresh buffer', () => {
		const a = new Uint8Array([1, 2]);
		const out = concatBytes(a);
		out[0] = 99;
		expect(a[0]).toBe(1);
	});
});
