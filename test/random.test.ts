import { randomBytes } from '../src/crypto/random';
import { InvalidArgumentError } from '../src/profile/errors';

describe('randomBytes', () => {
	test('returns a Uint8Array of the requested length', () => {
		const out = randomBytes(32);
		expect(out).toBeInstanceOf(Uint8Array);
		expect(out.length).toBe(32);
	});

	test('returns an empty array for length 0', () => {
		expect(randomBytes(0).length).toBe(0);
	});

	test('successive calls differ', () => {
		const a = randomBytes(32);
		const b = randomBytes(32);
		expect(Array.from(a)).not.toEqual(Array.from(b));
	});

	test('rejects negative or non-integer sizes', () => {
		expect(() => randomBytes(-1)).toThrow(InvalidArgumentError);
		expect(() => randomBytes(1.5)).toThrow(InvalidArgumentError);
		expect(() => randomBytes(NaN)).toThrow(InvalidArgumentError);
	});
});
