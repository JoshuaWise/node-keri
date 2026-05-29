import { createIdentifier } from '../src/api/create-identifier';
import { rotateIdentifier } from '../src/api/rotate-identifier';
import { verifyIdentifier } from '../src/api/verify-identifier';
import { keyPairFromSeed } from '../src/crypto/keypair';
import { parseSignedEvent } from '../src/event/stream';
import { InvalidArgumentError } from '../src/profile/errors';

function fillSeed(byte: number): Uint8Array {
	return new Uint8Array(32).fill(byte);
}

const K0 = () => keyPairFromSeed(fillSeed(0x20));
const K1 = () => keyPairFromSeed(fillSeed(0x21));
const K2 = () => keyPairFromSeed(fillSeed(0x22));
const K3 = () => keyPairFromSeed(fillSeed(0x23));

function freshIdentifier() {
	const currentKeyPair = K0();
	const nextKeyPair = K1();
	const result = createIdentifier({
		currentPrivateKey: currentKeyPair.privateKey,
		nextPublicKey: nextKeyPair.publicKey,
	});
	// Thread the keypairs through so callers can rotate to the pre-rotated key.
	return { ...result, currentKeyPair, nextKeyPair };
}

describe('rotateIdentifier', () => {
	test('produces a rotation event that extends the KEL', () => {
		const id = freshIdentifier();
		const rotation = rotateIdentifier({
			state: id.state,
			currentPrivateKey: id.nextKeyPair.privateKey,
			nextPublicKey: K2().publicKey,
		});

		const rotEvent = parseSignedEvent(rotation.event).event;
		expect(rotEvent.t).toBe('rot');
		expect(rotEvent.s).toBe('1');
		expect(rotation.state.lastSequenceNumber).toBe(1);
		expect(rotation.state.aid).toBe(id.aid);
	});

	test('the rotated KEL verifies end to end', () => {
		const id = freshIdentifier();
		const rotation = rotateIdentifier({
			state: id.state,
			currentPrivateKey: id.nextKeyPair.privateKey,
			nextPublicKey: K2().publicKey,
		});
		const verified = verifyIdentifier({
			aid: id.aid,
			kel: id.event + rotation.event,
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
			nextPublicKey: K2().publicKey,
		});
		const rot2 = rotateIdentifier({
			state: rot1.state,
			currentPrivateKey: K2().privateKey,
			nextPublicKey: K3().publicKey,
		});
		expect(parseSignedEvent(rot2.event).event.s).toBe('2');
		const verified = verifyIdentifier({
			aid: id.aid,
			kel: id.event + rot1.event + rot2.event,
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
				nextPublicKey: K3().publicKey,
			})
		).toThrow(InvalidArgumentError);
	});

	test('throws when the rotated-to key equals nextPublicKey', () => {
		const id = freshIdentifier();
		expect(() =>
			rotateIdentifier({
				state: id.state,
				currentPrivateKey: id.nextKeyPair.privateKey,
				nextPublicKey: K1().publicKey,
			})
		).toThrow(/distinct keys/);
	});

	test('throws on a non-object input', () => {
		expect(() => rotateIdentifier(null as never)).toThrow(InvalidArgumentError);
	});

	test('throws when nextPublicKey is missing', () => {
		const id = freshIdentifier();
		expect(() =>
			rotateIdentifier({
				state: id.state,
				currentPrivateKey: id.nextKeyPair.privateKey,
			} as never)
		).toThrow(InvalidArgumentError);
	});

	test('throws when nextPublicKey is not a public key', () => {
		const id = freshIdentifier();
		expect(() =>
			rotateIdentifier({
				state: id.state,
				currentPrivateKey: id.nextKeyPair.privateKey,
				nextPublicKey: {} as never,
			})
		).toThrow(InvalidArgumentError);
	});

	test('throws when currentPrivateKey is not a private key', () => {
		const id = freshIdentifier();
		expect(() =>
			rotateIdentifier({
				state: id.state,
				currentPrivateKey: id.nextKeyPair.publicKey as never,
				nextPublicKey: K2().publicKey,
			})
		).toThrow(InvalidArgumentError);
	});
});
