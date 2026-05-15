import { encodePublicKeyEd25519 } from '../src/cesr/encode';
import { keyPairFromSeed } from '../src/crypto/keypair';
import { createInceptionEvent } from '../src/event/inception';
import { createInteractionEvent } from '../src/event/interaction';
import { serializeEvent } from '../src/event/sign';
import { verifyEventSignature } from '../src/event/verify-signature';
import { InvalidArgumentError } from '../src/profile/errors';

function fillSeed(byte: number): Uint8Array {
	return new Uint8Array(32).fill(byte);
}

const SEED_K0 = fillSeed(0x60);
const SEED_K1 = fillSeed(0x61);

function freshIdentity() {
	const k0 = keyPairFromSeed(SEED_K0);
	const k1 = keyPairFromSeed(SEED_K1);
	const inception = createInceptionEvent({
		currentKeyPair: k0,
		nextPublicKey: k1.publicKey,
	});
	return { k0, k1, inception };
}

describe('createInteractionEvent', () => {
	test('produces an event with the expected shape', () => {
		const { k0, inception } = freshIdentity();

		const { signedEvent, state } = createInteractionEvent({
			state: inception.state,
			currentKeyPair: k0,
		});

		const event = signedEvent.event;
		expect(event.t).toBe('ixn');
		expect(event.s).toBe('1');
		expect(event.i).toBe(inception.state.aid);
		expect(event.v).toMatch(/^KERI10JSON[0-9a-f]{6}_$/);
		if (event.t !== 'ixn') throw new Error('discriminant');
		expect(event.p).toBe(inception.state.lastEventDigest);
		expect(event.a).toEqual([]);

		// Key material is unchanged (no rotation).
		expect(state.currentPublicKey).toBe(inception.state.currentPublicKey);
		expect(state.nextKeyCommitment).toBe(inception.state.nextKeyCommitment);
		expect(state.aid).toBe(inception.state.aid);
		expect(state.did).toBe(inception.state.did);
		expect(state.sequenceNumber).toBe(1);
		expect(state.lastEventDigest).toBe(event.d);
		expect(state.eventType).toBe('ixn');
	});

	test('preserves anchored data verbatim', () => {
		const { k0, inception } = freshIdentity();
		const anchors = [
			{ d: 'capability-doc-hash', i: 'agent-1' },
			'free-form-string',
			42,
		];

		const { signedEvent } = createInteractionEvent({
			state: inception.state,
			currentKeyPair: k0,
			data: anchors,
		});

		if (signedEvent.event.t !== 'ixn') throw new Error('discriminant');
		expect(signedEvent.event.a).toEqual(anchors);
	});

	test('signature verifies under the unchanged current key', () => {
		const { k0, inception } = freshIdentity();
		const { signedEvent } = createInteractionEvent({
			state: inception.state,
			currentKeyPair: k0,
			data: [{ note: 'hello' }],
		});

		expect(
			verifyEventSignature(
				signedEvent.event,
				encodePublicKeyEd25519(k0.publicKey.raw),
				signedEvent.signatures[0]
			)
		).toBe(true);
	});

	test('throws when the signing key does not match the current public key', () => {
		const { inception } = freshIdentity();
		const stranger = keyPairFromSeed(fillSeed(0x99));

		expect(() =>
			createInteractionEvent({
				state: inception.state,
				currentKeyPair: stranger,
			})
		).toThrow(/current public key/);
	});

	test('rejects non-canonical-JSON anchors with a clear error', () => {
		const { k0, inception } = freshIdentity();
		expect(() =>
			createInteractionEvent({
				state: inception.state,
				currentKeyPair: k0,
				data: [Number.NaN],
			})
		).toThrow(/canonical-JSON/);

		expect(() =>
			createInteractionEvent({
				state: inception.state,
				currentKeyPair: k0,
				data: [() => 1],
			})
		).toThrow(InvalidArgumentError);
	});

	test("v field encodes the event's serialized byte length", () => {
		const { k0, inception } = freshIdentity();
		const { signedEvent } = createInteractionEvent({
			state: inception.state,
			currentKeyPair: k0,
			data: [{ note: 'sized' }, 'and-more', 7],
		});
		const sizeHex = signedEvent.event.v.slice(10, 16);
		expect(serializeEvent(signedEvent.event).length).toBe(
			parseInt(sizeHex, 16)
		);
	});

	test('signed interaction is frozen and resists post-construction mutation', () => {
		const { k0, inception } = freshIdentity();
		const { signedEvent } = createInteractionEvent({
			state: inception.state,
			currentKeyPair: k0,
		});
		expect(Object.isFrozen(signedEvent)).toBe(true);
		expect(Object.isFrozen(signedEvent.event)).toBe(true);
		expect(Object.isFrozen(signedEvent.signatures)).toBe(true);
		expect(() => {
			(signedEvent.event as { s: string }).s = '2';
		}).toThrow(TypeError);
	});

	test('successive interactions chain by previous-event digest', () => {
		const { k0, inception } = freshIdentity();
		const i1 = createInteractionEvent({
			state: inception.state,
			currentKeyPair: k0,
		});
		const i2 = createInteractionEvent({
			state: i1.state,
			currentKeyPair: k0,
			data: [{ tick: 2 }],
		});

		expect(i2.signedEvent.event.s).toBe('2');
		if (i2.signedEvent.event.t !== 'ixn') throw new Error('discriminant');
		expect(i2.signedEvent.event.p).toBe(i1.signedEvent.event.d);
		// Current key is still k0.
		expect(i2.state.currentPublicKey).toBe(inception.state.currentPublicKey);
	});
});
