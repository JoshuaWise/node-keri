import { createIdentifier } from '../src/api/create-identifier';
import { rotateIdentifier } from '../src/api/rotate-identifier';
import { verifyKel } from '../src/api/verify-kel';
import { keyPairFromSeed } from '../src/crypto/keypair';
import { InvalidArgumentError } from '../src/profile/errors';

function fillSeed(byte: number): Uint8Array {
	return new Uint8Array(32).fill(byte);
}

const K0 = () => keyPairFromSeed(fillSeed(0x20));
const K1 = () => keyPairFromSeed(fillSeed(0x21));
const K2 = () => keyPairFromSeed(fillSeed(0x22));
const K3 = () => keyPairFromSeed(fillSeed(0x23));

function freshIdentifier() {
	return createIdentifier({ currentKeyPair: K0(), nextKeyPair: K1() });
}

describe('rotateIdentifier', () => {
	test('produces a rotation event that extends the KEL', () => {
		const id = freshIdentifier();
		const rotation = rotateIdentifier({
			state: id.state,
			currentPrivateKey: id.nextKeyPair.privateKey,
			nextKeyPair: K2(),
		});

		expect(rotation.rotationEvent.event.t).toBe('rot');
		expect(rotation.rotationEvent.event.s).toBe('1');
		expect(rotation.state.sequenceNumber).toBe(1);
		expect(rotation.state.aid).toBe(id.aid);
	});

	test('the rotated KEL verifies end to end', () => {
		const id = freshIdentifier();
		const rotation = rotateIdentifier({
			state: id.state,
			currentPrivateKey: id.nextKeyPair.privateKey,
			nextKeyPair: K2(),
		});
		const verified = verifyKel({
			aid: id.aid,
			events: [id.inceptionEvent, rotation.rotationEvent],
		});
		expect(verified.ok).toBe(true);
		if (!verified.ok) throw new Error('unreachable');
		expect(verified.state).toEqual(rotation.state);
	});

	test('supports chained rotations', () => {
		const id = freshIdentifier();
		const rot1 = rotateIdentifier({
			state: id.state,
			currentPrivateKey: id.nextKeyPair.privateKey,
			nextKeyPair: K2(),
		});
		const rot2 = rotateIdentifier({
			state: rot1.state,
			currentPrivateKey: K2().privateKey,
			nextKeyPair: K3(),
		});
		expect(rot2.rotationEvent.event.s).toBe('2');
		const verified = verifyKel({
			aid: id.aid,
			events: [id.inceptionEvent, rot1.rotationEvent, rot2.rotationEvent],
		});
		expect(verified.ok).toBe(true);
	});
});

describe('rotateIdentifier — rejects bad input', () => {
	test('throws when the private key does not match the prior commitment', () => {
		const id = freshIdentifier();
		expect(() =>
			rotateIdentifier({
				state: id.state,
				// K2, not the pre-rotated K1 — does not match `n[0]`.
				currentPrivateKey: K2().privateKey,
				nextKeyPair: K3(),
			})
		).toThrow(InvalidArgumentError);
	});

	test('throws when the rotated-to key equals nextKeyPair', () => {
		const id = freshIdentifier();
		expect(() =>
			rotateIdentifier({
				state: id.state,
				currentPrivateKey: id.nextKeyPair.privateKey,
				nextKeyPair: K1(),
			})
		).toThrow(/distinct keys/);
	});

	test('throws on a non-object input', () => {
		expect(() => rotateIdentifier(null as never)).toThrow(InvalidArgumentError);
	});

	test('throws when nextKeyPair is missing', () => {
		const id = freshIdentifier();
		expect(() =>
			rotateIdentifier({
				state: id.state,
				currentPrivateKey: id.nextKeyPair.privateKey,
			} as never)
		).toThrow(InvalidArgumentError);
	});

	test('throws when currentPrivateKey is not a private key', () => {
		const id = freshIdentifier();
		expect(() =>
			rotateIdentifier({
				state: id.state,
				currentPrivateKey: id.nextKeyPair.publicKey as never,
				nextKeyPair: K2(),
			})
		).toThrow(InvalidArgumentError);
	});
});
