import { publicKeyToCesr } from '../src/crypto/keypair';
import { deriveNextKeyCommitment } from '../src/event/digest';
import { createInceptionEvent } from '../src/event/inception';
import { createRotationEvent, CreateRotationInput } from '../src/event/rotation';
import { serializeEvent, signEvent } from '../src/event/sign';
import { verifyEventSignature } from '../src/event/verify-signature';
import { InvalidArgumentError } from '../src/profile/errors';
import { parseSignedEvent, fillSeed, keyPairFromSeed } from './helpers/util';

/**
 * `createRotationEvent` returns the event in CESR stream wire form; parse the
 * frame back so these tests can inspect the in-memory `SignedKeriEvent`.
 */
function rotateSigned(input: CreateRotationInput) {
	const { event, state } = createRotationEvent(input);
	return { signedEvent: parseSignedEvent(event), state };
}

const SEED_K0 = fillSeed(0x40);
const SEED_K1 = fillSeed(0x41);
const SEED_K2 = fillSeed(0x42);
const SEED_K3 = fillSeed(0x43);

function freshIdentity() {
	const k0 = keyPairFromSeed(SEED_K0);
	const k1 = keyPairFromSeed(SEED_K1);
	const inception = createInceptionEvent({
		currentKeyPair: k0,
		nextPublicKey: k1.publicKey,
	});
	return { k0, k1, inception };
}

describe('createRotationEvent', () => {
	test('produces an event with the expected shape', () => {
		const { k1, inception } = freshIdentity();
		const k2 = keyPairFromSeed(SEED_K2);

		const { signedEvent, state } = rotateSigned({
			state: inception.state,
			newCurrentKeyPair: k1,
			nextPublicKey: k2.publicKey,
		});

		const event = signedEvent.event;
		expect(event.t).toBe('rot');
		expect(event.s).toBe('1');
		expect(event.i).toBe(inception.state.aid);
		expect(event.v).toMatch(/^KERI10JSON[0-9a-f]{6}_$/);
		if (event.t !== 'rot') throw new Error('discriminant');
		expect(event.p).toBe(inception.state.lastEventDigest);
		expect(event.kt).toBe('1');
		expect(event.k).toEqual([publicKeyToCesr(k1.publicKey)]);
		expect(event.nt).toBe('1');
		expect(event.n).toEqual([deriveNextKeyCommitment(k2.publicKey)]);
		expect(event.bt).toBe('0');
		expect(event.br).toEqual([]);
		expect(event.ba).toEqual([]);
		expect(event.a).toEqual([]);

		// State advances by one and tracks the new key material.
		expect(state.lastSequenceNumber).toBe(1);
		expect(state.lastEventDigest).toBe(event.d);
		expect(state.aid).toBe(inception.state.aid);
		expect(state.did).toBe(inception.state.did);
		expect(state.currentPublicKey).toBe(publicKeyToCesr(k1.publicKey));
		expect(state.nextKeyCommitment).toBe(deriveNextKeyCommitment(k2.publicKey));
		expect(state.lastEventType).toBe('rot');
	});

	test('signature is by the new current (revealed) key', () => {
		const { k1, inception } = freshIdentity();
		const k2 = keyPairFromSeed(SEED_K2);

		const { signedEvent } = rotateSigned({
			state: inception.state,
			newCurrentKeyPair: k1,
			nextPublicKey: k2.publicKey,
		});

		expect(
			verifyEventSignature(
				signedEvent.event,
				publicKeyToCesr(k1.publicKey),
				signedEvent.signatures[0]
			)
		).toBe(true);

		// The OLD current key (k0) must NOT verify the rotation.
		const k0 = keyPairFromSeed(SEED_K0);
		expect(
			verifyEventSignature(
				signedEvent.event,
				publicKeyToCesr(k0.publicKey),
				signedEvent.signatures[0]
			)
		).toBe(false);
	});

	test('throws when the disclosed key does not match the prior commitment', () => {
		const { inception } = freshIdentity();
		// k1 was committed to as next; using k_other (a different seed) as
		// the disclosed rotation key must be rejected.
		const kOther = keyPairFromSeed(fillSeed(0x55));
		const k2 = keyPairFromSeed(SEED_K2);

		expect(() =>
			rotateSigned({
				state: inception.state,
				newCurrentKeyPair: kOther,
				nextPublicKey: k2.publicKey,
			})
		).toThrow(/prior next-key commitment/);
	});

	test('throws on malformed key arguments', () => {
		const { inception } = freshIdentity();
		const k2 = keyPairFromSeed(SEED_K2);

		expect(() =>
			rotateSigned({
				state: inception.state,
				newCurrentKeyPair: { publicKey: {} as never, privateKey: {} as never },
				nextPublicKey: k2.publicKey,
			})
		).toThrow(InvalidArgumentError);

		const k1 = keyPairFromSeed(SEED_K1);
		expect(() =>
			rotateSigned({
				state: inception.state,
				newCurrentKeyPair: k1,
				nextPublicKey: {} as never,
			})
		).toThrow(InvalidArgumentError);
	});

	test('chained rotations advance sequence and commitments correctly', () => {
		const { k1, inception } = freshIdentity();
		const k2 = keyPairFromSeed(SEED_K2);
		const k3 = keyPairFromSeed(SEED_K3);

		const r1 = rotateSigned({
			state: inception.state,
			newCurrentKeyPair: k1,
			nextPublicKey: k2.publicKey,
		});
		const r2 = rotateSigned({
			state: r1.state,
			newCurrentKeyPair: k2,
			nextPublicKey: k3.publicKey,
		});

		expect(r2.signedEvent.event.s).toBe('2');
		if (r2.signedEvent.event.t !== 'rot') throw new Error('discriminant');
		expect(r2.signedEvent.event.p).toBe(r1.signedEvent.event.d);
		expect(r2.state.currentPublicKey).toBe(publicKeyToCesr(k2.publicKey));
		expect(r2.state.nextKeyCommitment).toBe(deriveNextKeyCommitment(k3.publicKey));

		expect(
			verifyEventSignature(
				r2.signedEvent.event,
				publicKeyToCesr(k2.publicKey),
				r2.signedEvent.signatures[0]
			)
		).toBe(true);
	});

	test("v field encodes the event's serialized byte length", () => {
		const { k1, inception } = freshIdentity();
		const k2 = keyPairFromSeed(SEED_K2);
		const { signedEvent } = rotateSigned({
			state: inception.state,
			newCurrentKeyPair: k1,
			nextPublicKey: k2.publicKey,
		});
		const sizeHex = signedEvent.event.v.slice(10, 16);
		expect(serializeEvent(signedEvent.event).length).toBe(parseInt(sizeHex, 16));
	});

	test('signEvent freezes the signed rotation against post-construction mutation', () => {
		const { k1, inception } = freshIdentity();
		const k2 = keyPairFromSeed(SEED_K2);
		const { signedEvent } = rotateSigned({
			state: inception.state,
			newCurrentKeyPair: k1,
			nextPublicKey: k2.publicKey,
		});
		const reSigned = signEvent(signedEvent.event, k1.privateKey);
		expect(Object.isFrozen(reSigned)).toBe(true);
		expect(Object.isFrozen(reSigned.event)).toBe(true);
		expect(Object.isFrozen(reSigned.signatures)).toBe(true);
		expect(() => {
			(reSigned.event as { s: string }).s = '2';
		}).toThrow(TypeError);
	});

	test('sequence number switches to multi-character hex past 15', () => {
		// Walk sequence up to 0x10 to confirm hex formatting handles >1 digit.
		const k0 = keyPairFromSeed(SEED_K0);
		const k1 = keyPairFromSeed(SEED_K1);
		let state = createInceptionEvent({
			currentKeyPair: k0,
			nextPublicKey: k1.publicKey,
		}).state;

		let nextSeed = SEED_K1; // seed of the key currently committed as next

		for (let i = 1; i <= 16; i++) {
			const newCurrentSeed = nextSeed;
			const freshNextSeed = fillSeed(0x80 + i);
			const newCurrent = keyPairFromSeed(newCurrentSeed);
			const fresh = keyPairFromSeed(freshNextSeed);
			const r = rotateSigned({
				state,
				newCurrentKeyPair: newCurrent,
				nextPublicKey: fresh.publicKey,
			});
			expect(r.signedEvent.event.s).toBe(i.toString(16));
			expect(r.state.lastSequenceNumber).toBe(i);
			state = r.state;
			nextSeed = freshNextSeed;
		}
		expect(state.lastSequenceNumber).toBe(16);
	});
});
