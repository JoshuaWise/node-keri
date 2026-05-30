import { publicKeyToCesr } from '../src/crypto/keypair';
import { createInceptionEvent } from '../src/event/inception';
import { createInteractionEvent, CreateInteractionInput } from '../src/event/interaction';
import { serializeEvent, signEvent } from '../src/event/sign';
import { verifyEventSignature } from '../src/event/verify-signature';
import { InvalidArgumentError } from '../src/profile/errors';
import { parseSignedEvent, fillSeed, keyPairFromSeed } from './helpers/util';

/**
 * `createInteractionEvent` returns the event in CESR stream wire form; parse
 * the frame back so these tests can inspect the in-memory `SignedKeriEvent`.
 */
function interactSigned(input: CreateInteractionInput) {
	const { event, state } = createInteractionEvent(input);
	return { signedEvent: parseSignedEvent(event), state };
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

		const { signedEvent, state } = interactSigned({
			state: inception.state,
			currentKeyPair: k0,
			data: [],
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
		expect(state.lastSequenceNumber).toBe(1);
		expect(state.lastEventDigest).toBe(event.d);
		expect(state.lastEventType).toBe('ixn');
	});

	test('preserves anchored data verbatim', () => {
		const { k0, inception } = freshIdentity();
		const anchors = [
			{ d: 'capability-doc-hash', i: 'agent-1' },
			'free-form-string',
			42,
		];

		const { signedEvent } = interactSigned({
			state: inception.state,
			currentKeyPair: k0,
			data: anchors,
		});

		if (signedEvent.event.t !== 'ixn') throw new Error('discriminant');
		expect(signedEvent.event.a).toEqual(anchors);
	});

	test('signature verifies under the unchanged current key', () => {
		const { k0, inception } = freshIdentity();
		const { signedEvent } = interactSigned({
			state: inception.state,
			currentKeyPair: k0,
			data: [{ note: 'hello' }],
		});

		expect(
			verifyEventSignature(
				signedEvent.event,
				publicKeyToCesr(k0.publicKey),
				signedEvent.signatures[0]
			)
		).toBe(true);
	});

	test('throws when the signing key does not match the current public key', () => {
		const { inception } = freshIdentity();
		const stranger = keyPairFromSeed(fillSeed(0x99));

		expect(() =>
			interactSigned({
				state: inception.state,
				currentKeyPair: stranger,
				data: [],
			})
		).toThrow(/current public key/);
	});

	test('rejects non-canonical-JSON anchors with a clear error', () => {
		const { k0, inception } = freshIdentity();
		expect(() =>
			interactSigned({
				state: inception.state,
				currentKeyPair: k0,
				data: [Number.NaN],
			})
		).toThrow(/canonical-JSON/);

		expect(() =>
			interactSigned({
				state: inception.state,
				currentKeyPair: k0,
				data: [() => 1],
			})
		).toThrow(InvalidArgumentError);
	});

	test("v field encodes the event's serialized byte length", () => {
		const { k0, inception } = freshIdentity();
		const { signedEvent } = interactSigned({
			state: inception.state,
			currentKeyPair: k0,
			data: [{ note: 'sized' }, 'and-more', 7],
		});
		const sizeHex = signedEvent.event.v.slice(10, 16);
		expect(serializeEvent(signedEvent.event).length).toBe(parseInt(sizeHex, 16));
	});

	test('signEvent freezes the signed interaction against post-construction mutation', () => {
		const { k0, inception } = freshIdentity();
		const { signedEvent } = interactSigned({
			state: inception.state,
			currentKeyPair: k0,
			data: [],
		});
		const reSigned = signEvent(signedEvent.event, k0.privateKey);
		expect(Object.isFrozen(reSigned)).toBe(true);
		expect(Object.isFrozen(reSigned.event)).toBe(true);
		expect(Object.isFrozen(reSigned.signatures)).toBe(true);
		expect(() => {
			(reSigned.event as { s: string }).s = '2';
		}).toThrow(TypeError);
	});

	test('successive interactions chain by previous-event digest', () => {
		const { k0, inception } = freshIdentity();
		const i1 = interactSigned({
			state: inception.state,
			currentKeyPair: k0,
			data: [],
		});
		const i2 = interactSigned({
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
