import { createIdentifier } from '../src/api/create-identifier';
import { interactOnIdentifier } from '../src/api/interact-on-identifier';
import { rotateIdentifier } from '../src/api/rotate-identifier';
import { verifyIdentifier } from '../src/api/verify-identifier';
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
	const currentKeyPair = K0();
	const nextKeyPair = K1();
	const result = createIdentifier({
		currentPrivateKey: currentKeyPair.privateKey,
		nextPublicKey: nextKeyPair.publicKey,
	});
	// Thread the keypairs through so callers can sign with / rotate to them.
	return { ...result, currentKeyPair, nextKeyPair };
}

describe('interactOnIdentifier', () => {
	test('produces an interaction event that extends the KEL', () => {
		const id = freshIdentifier();
		const ixn = interactOnIdentifier({
			state: id.state,
			currentPrivateKey: id.currentKeyPair.privateKey,
			data: [{ capabilityHash: 'abc' }],
		});

		const ixnEvent = parseSignedEvent(ixn.event).event;
		expect(ixnEvent.t).toBe('ixn');
		expect(ixnEvent.s).toBe('1');
		expect(ixn.state.lastSequenceNumber).toBe(1);
		expect(ixn.state.aid).toBe(id.aid);
		// An interaction does not rotate keys.
		expect(ixn.state.currentPublicKey).toBe(id.state.currentPublicKey);
		expect(ixn.state.nextKeyCommitment).toBe(id.state.nextKeyCommitment);
	});

	test('allows an empty anchor list', () => {
		const id = freshIdentifier();
		const ixn = interactOnIdentifier({
			state: id.state,
			currentPrivateKey: id.currentKeyPair.privateKey,
			data: [],
		});
		expect(
			(parseSignedEvent(ixn.event).event as { a: readonly unknown[] }).a
		).toEqual([]);
	});

	test('the KEL with an interaction verifies end to end', () => {
		const id = freshIdentifier();
		const ixn = interactOnIdentifier({
			state: id.state,
			currentPrivateKey: id.currentKeyPair.privateKey,
			data: [{ step: 1 }],
		});
		const verified = verifyIdentifier({
			aid: id.aid,
			kel: id.event + ixn.event,
		});
		expect(verified.ok).toBe(true);
		if (!verified.ok) throw new Error('unreachable');
		expect(verified.state).toEqual(ixn.state);
	});

	test('interacts under the post-rotation key', () => {
		const id = freshIdentifier();
		const rot = rotateIdentifier({
			state: id.state,
			newPrivateKey: id.nextKeyPair.privateKey,
			nextPublicKey: K2().publicKey,
		});
		// After rotation the authoritative key is the revealed K1.
		const ixn = interactOnIdentifier({
			state: rot.state,
			currentPrivateKey: id.nextKeyPair.privateKey,
			data: [{ step: 2 }],
		});
		expect(parseSignedEvent(ixn.event).event.s).toBe('2');
		const verified = verifyIdentifier({
			aid: id.aid,
			kel: id.event + rot.event + ixn.event,
		});
		expect(verified.ok).toBe(true);
	});
});

describe('interactOnIdentifier — rejects bad input', () => {
	test('throws on a non-object input', () => {
		expect(() => interactOnIdentifier(null as never)).toThrow(InvalidArgumentError);
	});

	test('throws when currentPrivateKey is not a private key', () => {
		const id = freshIdentifier();
		expect(() =>
			interactOnIdentifier({
				state: id.state,
				currentPrivateKey: id.currentKeyPair.publicKey as never,
				data: [],
			})
		).toThrow(InvalidArgumentError);
	});

	test('throws when the private key does not match the current key', () => {
		const id = freshIdentifier();
		expect(() =>
			interactOnIdentifier({
				state: id.state,
				// K1, not the current K0 — does not match `state.currentPublicKey`.
				currentPrivateKey: id.nextKeyPair.privateKey,
				data: [],
			})
		).toThrow(InvalidArgumentError);
	});

	test('throws when data is not canonical-JSON-serializable', () => {
		const id = freshIdentifier();
		expect(() =>
			interactOnIdentifier({
				state: id.state,
				currentPrivateKey: id.currentKeyPair.privateKey,
				data: [{ bad: NaN }],
			})
		).toThrow(InvalidArgumentError);
	});
});
