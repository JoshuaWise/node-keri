import { createIdentifier } from '../src/api/create-identifier';
import { interactIdentifier } from '../src/api/interact-identifier';
import { rotateIdentifier } from '../src/api/rotate-identifier';
import { verifyKel } from '../src/api/verify-kel';
import { keyPairFromSeed } from '../src/crypto/keypair';
import { parseSignedEvent } from '../src/event/stream';
import { InvalidArgumentError } from '../src/profile/errors';

function fillSeed(byte: number): Uint8Array {
	return new Uint8Array(32).fill(byte);
}

const K0 = () => keyPairFromSeed(fillSeed(0x40));
const K1 = () => keyPairFromSeed(fillSeed(0x41));
const K2 = () => keyPairFromSeed(fillSeed(0x42));

function freshIdentifier() {
	return createIdentifier({ currentKeyPair: K0(), nextKeyPair: K1() });
}

describe('interactIdentifier', () => {
	test('produces an interaction event that extends the KEL', () => {
		const id = freshIdentifier();
		const ixn = interactIdentifier({
			state: id.state,
			currentPrivateKey: id.currentKeyPair.privateKey,
			data: [{ capabilityHash: 'abc' }],
		});

		const ixnEvent = parseSignedEvent(ixn.interactionEvent).event;
		expect(ixnEvent.t).toBe('ixn');
		expect(ixnEvent.s).toBe('1');
		expect(ixn.state.sequenceNumber).toBe(1);
		expect(ixn.state.aid).toBe(id.aid);
		// An interaction does not rotate keys.
		expect(ixn.state.currentPublicKey).toBe(id.state.currentPublicKey);
		expect(ixn.state.nextKeyCommitment).toBe(id.state.nextKeyCommitment);
	});

	test('omitting data yields an empty anchor list', () => {
		const id = freshIdentifier();
		const ixn = interactIdentifier({
			state: id.state,
			currentPrivateKey: id.currentKeyPair.privateKey,
		});
		expect(
			(parseSignedEvent(ixn.interactionEvent).event as { a: readonly unknown[] }).a
		).toEqual([]);
	});

	test('the KEL with an interaction verifies end to end', () => {
		const id = freshIdentifier();
		const ixn = interactIdentifier({
			state: id.state,
			currentPrivateKey: id.currentKeyPair.privateKey,
			data: [{ step: 1 }],
		});
		const verified = verifyKel({
			aid: id.aid,
			kel: id.inceptionEvent + ixn.interactionEvent,
		});
		expect(verified.ok).toBe(true);
		if (!verified.ok) throw new Error('unreachable');
		expect(verified.state).toEqual(ixn.state);
	});

	test('interacts under the post-rotation key', () => {
		const id = freshIdentifier();
		const rot = rotateIdentifier({
			state: id.state,
			currentPrivateKey: id.nextKeyPair.privateKey,
			nextKeyPair: K2(),
		});
		// After rotation the authoritative key is the revealed K1.
		const ixn = interactIdentifier({
			state: rot.state,
			currentPrivateKey: id.nextKeyPair.privateKey,
			data: [{ step: 2 }],
		});
		expect(parseSignedEvent(ixn.interactionEvent).event.s).toBe('2');
		const verified = verifyKel({
			aid: id.aid,
			kel: id.inceptionEvent + rot.rotationEvent + ixn.interactionEvent,
		});
		expect(verified.ok).toBe(true);
	});
});

describe('interactIdentifier — rejects bad input', () => {
	test('throws on a non-object input', () => {
		expect(() => interactIdentifier(null as never)).toThrow(InvalidArgumentError);
	});

	test('throws when currentPrivateKey is not a private key', () => {
		const id = freshIdentifier();
		expect(() =>
			interactIdentifier({
				state: id.state,
				currentPrivateKey: id.currentKeyPair.publicKey as never,
			})
		).toThrow(InvalidArgumentError);
	});

	test('throws when the private key does not match the current key', () => {
		const id = freshIdentifier();
		expect(() =>
			interactIdentifier({
				state: id.state,
				// K1, not the current K0 — does not match `state.currentPublicKey`.
				currentPrivateKey: id.nextKeyPair.privateKey,
			})
		).toThrow(InvalidArgumentError);
	});

	test('throws when data is not canonical-JSON-serializable', () => {
		const id = freshIdentifier();
		expect(() =>
			interactIdentifier({
				state: id.state,
				currentPrivateKey: id.currentKeyPair.privateKey,
				data: [{ bad: NaN }],
			})
		).toThrow(InvalidArgumentError);
	});
});
