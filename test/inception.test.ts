import { decodeDigestSha256, decodePublicKeyEd25519 } from '../src/cesr/decode';
import { encodePublicKeyEd25519 } from '../src/cesr/encode';
import { keyPairFromSeed } from '../src/crypto/keypair';
import { DID_KERI_PREFIX } from '../src/did/did-keri';
import { canonicalizeJson } from '../src/event/canonical-json';
import { deriveNextKeyCommitment } from '../src/event/digest';
import { createInceptionEvent } from '../src/event/inception';
import { serializeEvent, signEvent } from '../src/event/sign';
import { verifyEventSignature } from '../src/event/verify-signature';
import { InvalidArgumentError } from '../src/profile/errors';

function fillSeed(byte: number): Uint8Array {
	return new Uint8Array(32).fill(byte);
}

const SEED_CURRENT = fillSeed(0x21);
const SEED_NEXT = fillSeed(0x22);

describe('createInceptionEvent', () => {
	test('produces an event with the expected shape', () => {
		const current = keyPairFromSeed(SEED_CURRENT);
		const next = keyPairFromSeed(SEED_NEXT);

		const { signedEvent } = createInceptionEvent({
			currentKeyPair: current,
			nextPublicKey: next.publicKey,
		});

		const event = signedEvent.event;
		expect(event.t).toBe('icp');
		expect(event.s).toBe('0');
		// In an inception event the AID equals the SAID.
		expect(event.i).toBe(event.d);
		expect(event.v).toMatch(/^KERI10JSON[0-9a-f]{6}_$/);
		expect(event.v.length).toBe(17);

		// Inception-specific fields fixed by the profile.
		if (event.t !== 'icp') throw new Error('discriminant');
		expect(event.kt).toBe('1');
		expect(event.k).toEqual([encodePublicKeyEd25519(current.publicKey.raw)]);
		expect(event.nt).toBe('1');
		expect(event.n).toEqual([deriveNextKeyCommitment(next.publicKey)]);
		expect(event.bt).toBe('0');
		expect(event.b).toEqual([]);
		expect(event.c).toEqual([]);
		expect(event.a).toEqual([]);

		expect(signedEvent.signatures).toHaveLength(1);
		expect(signedEvent.signatures[0]).toMatch(/^0B[A-Za-z0-9_-]{86}$/);
	});

	test('SAID is deterministic for the same inputs', () => {
		const current = keyPairFromSeed(SEED_CURRENT);
		const next = keyPairFromSeed(SEED_NEXT);

		const a = createInceptionEvent({
			currentKeyPair: current,
			nextPublicKey: next.publicKey,
		});
		const b = createInceptionEvent({
			currentKeyPair: current,
			nextPublicKey: next.publicKey,
		});
		expect(a.signedEvent.event.d).toBe(b.signedEvent.event.d);
		expect(a.signedEvent.event.v).toBe(b.signedEvent.event.v);
		// Ed25519 is deterministic, so signatures match too.
		expect(a.signedEvent.signatures[0]).toBe(b.signedEvent.signatures[0]);
		expect(a.state.aid).toBe(b.state.aid);
	});

	test('different next keys produce different SAIDs', () => {
		const current = keyPairFromSeed(SEED_CURRENT);
		const next1 = keyPairFromSeed(fillSeed(0x30));
		const next2 = keyPairFromSeed(fillSeed(0x31));

		const a = createInceptionEvent({
			currentKeyPair: current,
			nextPublicKey: next1.publicKey,
		});
		const b = createInceptionEvent({
			currentKeyPair: current,
			nextPublicKey: next2.publicKey,
		});
		expect(a.signedEvent.event.d).not.toBe(b.signedEvent.event.d);
	});

	test('returns a state matching the inception event', () => {
		const current = keyPairFromSeed(SEED_CURRENT);
		const next = keyPairFromSeed(SEED_NEXT);

		const { signedEvent, state } = createInceptionEvent({
			currentKeyPair: current,
			nextPublicKey: next.publicKey,
		});

		expect(state.sequenceNumber).toBe(0);
		expect(state.lastEventDigest).toBe(signedEvent.event.d);
		expect(state.aid).toBe(signedEvent.event.i);
		expect(state.did).toBe(DID_KERI_PREFIX + state.aid);
		expect(state.currentPublicKey).toBe(
			encodePublicKeyEd25519(current.publicKey.raw)
		);
		expect(state.nextKeyCommitment).toBe(
			deriveNextKeyCommitment(next.publicKey)
		);
		expect(state.transferable).toBe(true);
		expect(state.eventType).toBe('icp');
	});

	test('signature verifies under the disclosed key', () => {
		const current = keyPairFromSeed(SEED_CURRENT);
		const next = keyPairFromSeed(SEED_NEXT);

		const { signedEvent } = createInceptionEvent({
			currentKeyPair: current,
			nextPublicKey: next.publicKey,
		});

		expect(
			verifyEventSignature(
				signedEvent.event,
				encodePublicKeyEd25519(current.publicKey.raw),
				signedEvent.signatures[0]
			)
		).toBe(true);
	});

	test('signature does not verify under a different key', () => {
		const current = keyPairFromSeed(SEED_CURRENT);
		const next = keyPairFromSeed(SEED_NEXT);
		const stranger = keyPairFromSeed(fillSeed(0x99));

		const { signedEvent } = createInceptionEvent({
			currentKeyPair: current,
			nextPublicKey: next.publicKey,
		});

		expect(
			verifyEventSignature(
				signedEvent.event,
				encodePublicKeyEd25519(stranger.publicKey.raw),
				signedEvent.signatures[0]
			)
		).toBe(false);
	});

	test('signature does not verify if the event is tampered', () => {
		const current = keyPairFromSeed(SEED_CURRENT);
		const next = keyPairFromSeed(SEED_NEXT);

		const { signedEvent } = createInceptionEvent({
			currentKeyPair: current,
			nextPublicKey: next.publicKey,
		});

		// Mutate the canonical bytes of the event by swapping the sequence
		// number; this changes the signed payload without changing the SAID
		// fields, so verification must reject it.
		const tampered = { ...signedEvent.event, s: '1' };
		expect(
			verifyEventSignature(
				tampered as typeof signedEvent.event,
				encodePublicKeyEd25519(current.publicKey.raw),
				signedEvent.signatures[0]
			)
		).toBe(false);
	});

	test('AID round-trips as a SHA-256 digest', () => {
		const current = keyPairFromSeed(SEED_CURRENT);
		const next = keyPairFromSeed(SEED_NEXT);
		const { state } = createInceptionEvent({
			currentKeyPair: current,
			nextPublicKey: next.publicKey,
		});
		// AID === SAID, decodable as a digest with code I.
		expect(decodeDigestSha256(state.aid).length).toBe(32);
	});

	test('disclosed public key in `k` decodes to the correct raw bytes', () => {
		const current = keyPairFromSeed(SEED_CURRENT);
		const next = keyPairFromSeed(SEED_NEXT);
		const { signedEvent } = createInceptionEvent({
			currentKeyPair: current,
			nextPublicKey: next.publicKey,
		});
		if (signedEvent.event.t !== 'icp') throw new Error('discriminant');
		const raw = decodePublicKeyEd25519(signedEvent.event.k[0]);
		expect(Array.from(raw)).toEqual(Array.from(current.publicKey.raw));
	});

	test('rejects malformed key arguments', () => {
		const next = keyPairFromSeed(SEED_NEXT);
		expect(() =>
			createInceptionEvent({
				currentKeyPair: { publicKey: {} as never, privateKey: {} as never },
				nextPublicKey: next.publicKey,
			})
		).toThrow(InvalidArgumentError);

		const current = keyPairFromSeed(SEED_CURRENT);
		expect(() =>
			createInceptionEvent({
				currentKeyPair: current,
				nextPublicKey: {} as never,
			})
		).toThrow(InvalidArgumentError);
	});

	test("v field encodes the event's serialized byte length", () => {
		const current = keyPairFromSeed(SEED_CURRENT);
		const next = keyPairFromSeed(SEED_NEXT);
		const { signedEvent } = createInceptionEvent({
			currentKeyPair: current,
			nextPublicKey: next.publicKey,
		});
		const sizeHex = signedEvent.event.v.slice(10, 16);
		expect(serializeEvent(signedEvent.event).length).toBe(
			parseInt(sizeHex, 16)
		);
	});

	test('signed event is frozen and resists post-construction mutation', () => {
		const current = keyPairFromSeed(SEED_CURRENT);
		const next = keyPairFromSeed(SEED_NEXT);
		const { signedEvent } = createInceptionEvent({
			currentKeyPair: current,
			nextPublicKey: next.publicKey,
		});
		expect(Object.isFrozen(signedEvent)).toBe(true);
		expect(Object.isFrozen(signedEvent.event)).toBe(true);
		expect(Object.isFrozen(signedEvent.signatures)).toBe(true);
		expect(() => {
			(signedEvent.event as { s: string }).s = '1';
		}).toThrow(TypeError);
	});

	test('signature is over canonical bytes of the FINAL event (with SAID in d/i)', () => {
		const current = keyPairFromSeed(SEED_CURRENT);
		const next = keyPairFromSeed(SEED_NEXT);
		const { signedEvent } = createInceptionEvent({
			currentKeyPair: current,
			nextPublicKey: next.publicKey,
		});

		// Reconstruct the event verbatim and re-sign with the same key; we
		// should get back the same signature, demonstrating the bytes the
		// signature was made over are exactly canonicalize(event).
		const resigned = signEvent(signedEvent.event, current.privateKey);
		expect(resigned.signatures[0]).toBe(signedEvent.signatures[0]);
		// And canonicalize must match.
		expect(Array.from(canonicalizeJson(signedEvent.event))).toEqual(
			Array.from(canonicalizeJson(resigned.event))
		);
	});
});
