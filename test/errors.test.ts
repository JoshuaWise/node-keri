import {
	CanonicalJsonError,
	InvalidArgumentError,
	KeriError,
	MalformedInputError,
	UnsupportedAlgorithmError,
} from '../src/profile/errors';

describe('error hierarchy', () => {
	test('all typed errors extend KeriError and Error', () => {
		const errs = [
			new InvalidArgumentError('x'),
			new UnsupportedAlgorithmError('x'),
			new MalformedInputError('x'),
			new CanonicalJsonError('x'),
		];
		for (const e of errs) {
			expect(e).toBeInstanceOf(Error);
			expect(e).toBeInstanceOf(KeriError);
		}
	});

	test('error name reflects the subclass', () => {
		expect(new InvalidArgumentError('x').name).toBe('InvalidArgumentError');
		expect(new UnsupportedAlgorithmError('x').name).toBe(
			'UnsupportedAlgorithmError'
		);
		expect(new MalformedInputError('x').name).toBe('MalformedInputError');
		expect(new CanonicalJsonError('x').name).toBe('CanonicalJsonError');
	});

	test('messages are preserved', () => {
		expect(new InvalidArgumentError('boom').message).toBe('boom');
	});
});
