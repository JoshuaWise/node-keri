import {
	decodeIndexedSignatureEd25519,
	decodePublicKeyEd25519,
} from '../src/cesr/decode';
import { sign } from '../src/crypto/ed25519';
import { publicKeyToCesr, rawPublicKey } from '../src/crypto/keypair';
import { DID_KERI_PREFIX } from '../src/did/did-keri';
import { deriveNextKeyCommitment } from '../src/event/digest';
import { createInceptionEvent, CreateInceptionInput } from '../src/event/inception';
import { serializeEvent, signEvent } from '../src/event/sign';
import { verifyEventSignature } from '../src/event/verify-signature';
import { InvalidArgumentError } from '../src/profile/errors';
import {
	parseSignedEvent,
	fillSeed,
	decodeDigestSha256,
	keyPairFromSeed,
} from './helpers/util';

const SEED_CURRENT = fillSeed(0x21);
const SEED_NEXT = fillSeed(0x22);

/**
 * `createInceptionEvent` returns the event in CESR stream wire form. These
 * tests inspect the in-memory shape, so parse the frame back into a
 * `SignedKeriEvent` and keep the replay-derived `state` alongside.
 */
function inceptSigned(input: CreateInceptionInput) {
	const { event, state } = createInceptionEvent(input);
	return { signedEvent: parseSignedEvent(event), state };
}

describe('createInceptionEvent', () => {
	test('produces an event with the expected shape', () => {
		const current = keyPairFromSeed(SEED_CURRENT);
		const next = keyPairFromSeed(SEED_NEXT);

		const { signedEvent } = inceptSigned({
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
		expect(event.k).toEqual([publicKeyToCesr(current.publicKey)]);
		expect(event.nt).toBe('1');
		expect(event.n).toEqual([deriveNextKeyCommitment(next.publicKey)]);
		expect(event.bt).toBe('0');
		expect(event.b).toEqual([]);
		expect(event.c).toEqual([]);
		expect(event.a).toEqual([]);

		expect(signedEvent.signatures).toHaveLength(1);
		// An indexed Ed25519 signature (Siger): code `A`, then the 1-char index
		// (`A` = 0 in this single-key profile), then 86 base64 payload chars.
		expect(signedEvent.signatures[0]).toMatch(/^AA[A-Za-z0-9_-]{86}$/);
	});

	test('SAID is deterministic for the same inputs', () => {
		const current = keyPairFromSeed(SEED_CURRENT);
		const next = keyPairFromSeed(SEED_NEXT);

		const a = inceptSigned({
			currentKeyPair: current,
			nextPublicKey: next.publicKey,
		});
		const b = inceptSigned({
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

		const a = inceptSigned({
			currentKeyPair: current,
			nextPublicKey: next1.publicKey,
		});
		const b = inceptSigned({
			currentKeyPair: current,
			nextPublicKey: next2.publicKey,
		});
		expect(a.signedEvent.event.d).not.toBe(b.signedEvent.event.d);
	});

	test('returns a state matching the inception event', () => {
		const current = keyPairFromSeed(SEED_CURRENT);
		const next = keyPairFromSeed(SEED_NEXT);

		const { signedEvent, state } = inceptSigned({
			currentKeyPair: current,
			nextPublicKey: next.publicKey,
		});

		expect(state.lastSequenceNumber).toBe(0);
		expect(state.lastEventDigest).toBe(signedEvent.event.d);
		expect(state.aid).toBe(signedEvent.event.i);
		expect(state.did).toBe(DID_KERI_PREFIX + state.aid);
		expect(state.currentPublicKey).toBe(publicKeyToCesr(current.publicKey));
		expect(state.nextKeyCommitment).toBe(deriveNextKeyCommitment(next.publicKey));
		expect(state.transferable).toBe(true);
		expect(state.lastEventType).toBe('icp');
	});

	test('signature verifies under the disclosed key', () => {
		const current = keyPairFromSeed(SEED_CURRENT);
		const next = keyPairFromSeed(SEED_NEXT);

		const { signedEvent } = inceptSigned({
			currentKeyPair: current,
			nextPublicKey: next.publicKey,
		});

		expect(
			verifyEventSignature(
				signedEvent.event,
				publicKeyToCesr(current.publicKey),
				signedEvent.signatures[0]
			)
		).toBe(true);
	});

	test('signature does not verify under a different key', () => {
		const current = keyPairFromSeed(SEED_CURRENT);
		const next = keyPairFromSeed(SEED_NEXT);
		const stranger = keyPairFromSeed(fillSeed(0x99));

		const { signedEvent } = inceptSigned({
			currentKeyPair: current,
			nextPublicKey: next.publicKey,
		});

		expect(
			verifyEventSignature(
				signedEvent.event,
				publicKeyToCesr(stranger.publicKey),
				signedEvent.signatures[0]
			)
		).toBe(false);
	});

	test('signature does not verify if the event is tampered', () => {
		const current = keyPairFromSeed(SEED_CURRENT);
		const next = keyPairFromSeed(SEED_NEXT);

		const { signedEvent } = inceptSigned({
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
				publicKeyToCesr(current.publicKey),
				signedEvent.signatures[0]
			)
		).toBe(false);
	});

	test('AID round-trips as a SHA-256 digest', () => {
		const current = keyPairFromSeed(SEED_CURRENT);
		const next = keyPairFromSeed(SEED_NEXT);
		const { state } = inceptSigned({
			currentKeyPair: current,
			nextPublicKey: next.publicKey,
		});
		// AID === SAID, decodable as a digest with code I.
		expect(decodeDigestSha256(state.aid).length).toBe(32);
	});

	test('disclosed public key in `k` decodes to the correct raw bytes', () => {
		const current = keyPairFromSeed(SEED_CURRENT);
		const next = keyPairFromSeed(SEED_NEXT);
		const { signedEvent } = inceptSigned({
			currentKeyPair: current,
			nextPublicKey: next.publicKey,
		});
		if (signedEvent.event.t !== 'icp') throw new Error('discriminant');
		const raw = decodePublicKeyEd25519(signedEvent.event.k[0]);
		expect(Array.from(raw)).toEqual(Array.from(rawPublicKey(current.publicKey)));
	});

	test('rejects malformed key arguments', () => {
		const next = keyPairFromSeed(SEED_NEXT);
		expect(() =>
			inceptSigned({
				currentKeyPair: { publicKey: {} as never, privateKey: {} as never },
				nextPublicKey: next.publicKey,
			})
		).toThrow(InvalidArgumentError);

		const current = keyPairFromSeed(SEED_CURRENT);
		expect(() =>
			inceptSigned({
				currentKeyPair: current,
				nextPublicKey: {} as never,
			})
		).toThrow(InvalidArgumentError);
	});

	test("v field encodes the event's serialized byte length", () => {
		const current = keyPairFromSeed(SEED_CURRENT);
		const next = keyPairFromSeed(SEED_NEXT);
		const { signedEvent } = inceptSigned({
			currentKeyPair: current,
			nextPublicKey: next.publicKey,
		});
		const sizeHex = signedEvent.event.v.slice(10, 16);
		expect(serializeEvent(signedEvent.event).length).toBe(parseInt(sizeHex, 16));
	});

	test('signEvent freezes the signed event against post-construction mutation', () => {
		const current = keyPairFromSeed(SEED_CURRENT);
		const next = keyPairFromSeed(SEED_NEXT);
		// The wire form is an immutable string; the in-memory `signEvent`
		// output is frozen so a casual mutation that would invalidate the
		// signature is rejected at runtime.
		const { signedEvent } = inceptSigned({
			currentKeyPair: current,
			nextPublicKey: next.publicKey,
		});
		const reSigned = signEvent(signedEvent.event, current.privateKey);
		expect(Object.isFrozen(reSigned)).toBe(true);
		expect(Object.isFrozen(reSigned.event)).toBe(true);
		expect(Object.isFrozen(reSigned.signatures)).toBe(true);
		expect(() => {
			(reSigned.event as { s: string }).s = '1';
		}).toThrow(TypeError);
	});

	test('signature is the Ed25519 signature over the canonical bytes of the final event', () => {
		const current = keyPairFromSeed(SEED_CURRENT);
		const next = keyPairFromSeed(SEED_NEXT);
		const { signedEvent } = inceptSigned({
			currentKeyPair: current,
			nextPublicKey: next.publicKey,
		});

		// Independently sign `serializeEvent(event)` — the canonical JSON of the
		// final event, SAID and version string in place — with the raw Ed25519
		// primitive. Those 64 bytes must equal the raw signature carried by the
		// event's indexed Siger (at key index 0), pinning down exactly which
		// bytes the attached signature was made over.
		const expected = sign(current.privateKey, serializeEvent(signedEvent.event));
		const carried = decodeIndexedSignatureEd25519(signedEvent.signatures[0]);
		expect(carried.index).toBe(0);
		expect(Array.from(carried.raw)).toEqual(Array.from(expected));
	});
});
