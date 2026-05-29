/**
 * Test suite for identifier deactivation.
 *
 * Deactivation is the `did:keri` abandonment operation: a rotation to zero
 * next keys (`nt: "0"`, empty `n`). These tests cover the constructor, the
 * `deactivateIdentifier` API, replay verification of a deactivated KEL, the
 * refusal to extend it, and the DID-surface consequences (resolution metadata,
 * an authority-free document, and signature verification failing closed).
 */

import { createIdentifier } from '../src/api/create-identifier';
import { rotateIdentifier } from '../src/api/rotate-identifier';
import { interactIdentifier } from '../src/api/interact-identifier';
import { deactivateIdentifier } from '../src/api/deactivate-identifier';
import { verifyKel } from '../src/api/verify-kel';
import { verifySignatureWithDid } from '../src/api/verify-signature-with-did';
import { utf8Encode } from '../src/bytes/utf8';
import { encodeSignatureEd25519 } from '../src/cesr/encode';
import { sign } from '../src/crypto/ed25519';
import { keyPairFromSeed } from '../src/crypto/keypair';
import { createDeactivationEvent } from '../src/event/deactivation';
import { createInteractionEvent } from '../src/event/interaction';
import { deriveNextKeyCommitment } from '../src/event/digest';
import { parseSignedEvent } from '../src/event/stream';
import { createDidDocument } from '../src/did/document';
import { resolveDid } from '../src/did/resolver';
import { KeriState, TransferableKeriState } from '../src/kel/state';
import { InvalidArgumentError } from '../src/profile/errors';
import { reframe } from './kel-stream';

function fillSeed(byte: number): Uint8Array {
	return new Uint8Array(32).fill(byte);
}

const K0 = () => keyPairFromSeed(fillSeed(0x50));
const K1 = () => keyPairFromSeed(fillSeed(0x51));
const K2 = () => keyPairFromSeed(fillSeed(0x52));
const K3 = () => keyPairFromSeed(fillSeed(0x53));

/** A fresh transferable identifier whose current/next keys are K0/K1. */
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

describe('deactivateIdentifier — constructs the deactivation event', () => {
	test('produces a rot event with empty nt/n that closes the KEL', () => {
		const id = freshIdentifier();
		const deact = deactivateIdentifier({
			state: id.state,
			currentPrivateKey: id.nextKeyPair.privateKey,
		});

		const event = parseSignedEvent(deact.deactivationEvent)
			.event as unknown as Record<string, unknown>;
		expect(event.t).toBe('rot');
		expect(event.s).toBe('1');
		expect(event.nt).toBe('0');
		expect(event.n).toEqual([]);
		// The revealed key still appears in `k` — it both reproduces the prior
		// commitment and signs the event.
		expect(event.k).toHaveLength(1);
		expect(event.p).toBe(id.state.lastEventDigest);
	});

	test('returns a deactivated, non-transferable terminal state', () => {
		const id = freshIdentifier();
		const deact = deactivateIdentifier({
			state: id.state,
			currentPrivateKey: id.nextKeyPair.privateKey,
		});

		expect(deact.state.deactivated).toBe(true);
		expect(deact.state.transferable).toBe(false);
		expect(deact.state.eventType).toBe('rot');
		expect(deact.state.sequenceNumber).toBe(1);
		expect(deact.state.aid).toBe(id.aid);
		// No `nextKeyCommitment` — the identifier committed to nothing.
		expect('nextKeyCommitment' in deact.state).toBe(false);
	});

	test('rejects a key that does not match the prior next-key commitment', () => {
		const id = freshIdentifier();
		expect(() =>
			deactivateIdentifier({
				state: id.state,
				// K2 was never pre-rotated to; K1 is the committed next key.
				currentPrivateKey: K2().privateKey,
			})
		).toThrow(InvalidArgumentError);
	});

	test('a non-transferable identifier cannot be deactivated', () => {
		const id = freshIdentifier();
		const nonTransferable: KeriState = {
			aid: id.aid,
			did: id.did,
			sequenceNumber: 0,
			currentPublicKey: id.state.currentPublicKey,
			transferable: false,
		};
		expect(() =>
			createDeactivationEvent({
				state: nonTransferable,
				revealedKeyPair: K1(),
			})
		).toThrow(/non-transferable identifier cannot be deactivated/);
	});

	test('an already-deactivated identifier cannot be deactivated again', () => {
		const id = freshIdentifier();
		const deact = deactivateIdentifier({
			state: id.state,
			currentPrivateKey: id.nextKeyPair.privateKey,
		});
		expect(() =>
			deactivateIdentifier({
				state: deact.state,
				currentPrivateKey: id.nextKeyPair.privateKey,
			})
		).toThrow(/already deactivated/);
	});
});

describe('deactivateIdentifier — extends a longer KEL', () => {
	test('deactivates after a rotation', () => {
		const id = freshIdentifier();
		const rot = rotateIdentifier({
			state: id.state,
			currentPrivateKey: id.nextKeyPair.privateKey,
			nextPublicKey: K2().publicKey,
		});
		const deact = deactivateIdentifier({
			state: rot.state,
			currentPrivateKey: K2().privateKey,
		});

		const kel = id.inceptionEvent + rot.rotationEvent + deact.deactivationEvent;
		const result = verifyKel({ aid: id.aid, kel });
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.state.deactivated).toBe(true);
		expect(result.state.sequenceNumber).toBe(2);
	});

	test('deactivates after an interaction event', () => {
		const id = freshIdentifier();
		const ixn = interactIdentifier({
			state: id.state,
			currentPrivateKey: id.currentKeyPair.privateKey,
			data: [{ note: 'last words' }],
		});
		const deact = deactivateIdentifier({
			state: ixn.state,
			currentPrivateKey: id.nextKeyPair.privateKey,
		});

		const kel = id.inceptionEvent + ixn.interactionEvent + deact.deactivationEvent;
		const result = verifyKel({ aid: id.aid, kel });
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.state.deactivated).toBe(true);
		expect(result.state.sequenceNumber).toBe(2);
	});
});

describe('verifyKel — replays a deactivated KEL', () => {
	test('verifies a KEL ending in a deactivation event', () => {
		const id = freshIdentifier();
		const deact = deactivateIdentifier({
			state: id.state,
			currentPrivateKey: id.nextKeyPair.privateKey,
		});
		const kel = id.inceptionEvent + deact.deactivationEvent;

		const result = verifyKel({ aid: id.aid, kel });
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.state.transferable).toBe(false);
		expect(result.state.deactivated).toBe(true);
		expect(result.state.eventType).toBe('rot');
		expect(result.state.sequenceNumber).toBe(1);
	});

	test('rejects any event appended after deactivation', () => {
		const id = freshIdentifier();
		const deact = deactivateIdentifier({
			state: id.state,
			currentPrivateKey: id.nextKeyPair.privateKey,
		});

		// Forge a syntactically valid interaction event that chains onto the
		// deactivation event, by feeding `createInteractionEvent` a state that
		// looks transferable. Replay must still reject it: the prior event was
		// a deactivation.
		const pretendState: TransferableKeriState = {
			aid: deact.state.aid,
			did: deact.state.did,
			sequenceNumber: deact.state.sequenceNumber,
			lastEventDigest: deact.state.lastEventDigest,
			currentPublicKey: deact.state.currentPublicKey,
			nextKeyCommitment: deriveNextKeyCommitment(K2().publicKey),
			transferable: true,
			eventType: 'rot',
		};
		const appended = createInteractionEvent({
			state: pretendState,
			// The deactivation revealed K1, so K1 is its `currentPublicKey`.
			currentKeyPair: K1(),
			data: [],
		});

		const kel = id.inceptionEvent + deact.deactivationEvent + appended.event;
		const result = verifyKel({ aid: id.aid, kel });
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe('DEACTIVATED_NOT_EXTENSIBLE');
	});

	test('rejects a deactivation event that still commits to a next key', () => {
		const id = freshIdentifier();
		const deact = deactivateIdentifier({
			state: id.state,
			currentPrivateKey: id.nextKeyPair.privateKey,
		});
		const signed = parseSignedEvent(deact.deactivationEvent);
		// `nt: "0"` but a non-empty `n` is a contradiction the shape pass
		// rejects: a deactivation commits to no next key.
		const tampered = {
			...(signed.event as unknown as Record<string, unknown>),
			n: [deriveNextKeyCommitment(K2().publicKey)],
		};
		const kel = id.inceptionEvent + reframe(tampered, signed.signatures);

		const result = verifyKel({ aid: id.aid, kel });
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe('UNSUPPORTED_FEATURE');
	});

	test('rejects a tampered deactivation event', () => {
		const id = freshIdentifier();
		const deact = deactivateIdentifier({
			state: id.state,
			currentPrivateKey: id.nextKeyPair.privateKey,
		});
		const signed = parseSignedEvent(deact.deactivationEvent);
		// Mutate the sequence number, leaving the SAID/signature stale.
		const tampered = {
			...(signed.event as unknown as Record<string, unknown>),
			s: '2',
		};
		const kel = id.inceptionEvent + reframe(tampered, signed.signatures);

		const result = verifyKel({ aid: id.aid, kel });
		expect(result.ok).toBe(false);
	});
});

describe('deactivation closes the lifecycle API', () => {
	test('a deactivated state cannot be rotated', () => {
		const id = freshIdentifier();
		const deact = deactivateIdentifier({
			state: id.state,
			currentPrivateKey: id.nextKeyPair.privateKey,
		});
		expect(() =>
			rotateIdentifier({
				state: deact.state,
				currentPrivateKey: K2().privateKey,
				nextPublicKey: K3().publicKey,
			})
		).toThrow(/deactivated identifier cannot be rotated/);
	});

	test('a deactivated state cannot anchor interaction events', () => {
		const id = freshIdentifier();
		const deact = deactivateIdentifier({
			state: id.state,
			currentPrivateKey: id.nextKeyPair.privateKey,
		});
		expect(() =>
			interactIdentifier({
				state: deact.state,
				currentPrivateKey: K1().privateKey,
				data: [],
			})
		).toThrow(/deactivated identifier cannot anchor/);
	});
});

describe('DID surface — a deactivated DID', () => {
	test('resolveDid reports deactivation and an authority-free document', () => {
		const id = freshIdentifier();
		const deact = deactivateIdentifier({
			state: id.state,
			currentPrivateKey: id.nextKeyPair.privateKey,
		});
		const kel = id.inceptionEvent + deact.deactivationEvent;

		const result = resolveDid({ did: id.did, kel });
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.metadata.deactivated).toBe(true);
		expect(result.metadata.eventCount).toBe(2);
		expect(result.didDocument.verificationMethod).toEqual([]);
		expect(result.didDocument.authentication).toEqual([]);
		expect(result.didDocument.assertionMethod).toEqual([]);
		expect(result.didDocument.id).toBe(id.did);
	});

	test('createDidDocument projects a deactivated state with no key', () => {
		const id = freshIdentifier();
		const deact = deactivateIdentifier({
			state: id.state,
			currentPrivateKey: id.nextKeyPair.privateKey,
		});
		const doc = createDidDocument({ state: deact.state });
		expect(doc.verificationMethod).toEqual([]);
		expect(doc.authentication).toEqual([]);
		expect(doc.assertionMethod).toEqual([]);
		expect(doc.service).toBeUndefined();
	});

	test('verifySignatureWithDid fails closed against a deactivated DID', () => {
		const id = freshIdentifier();
		const deact = deactivateIdentifier({
			state: id.state,
			currentPrivateKey: id.nextKeyPair.privateKey,
		});
		const kel = id.inceptionEvent + deact.deactivationEvent;

		const payload = utf8Encode('message from an abandoned identity');
		// Sign with the key the deactivation event reveals — the only key in
		// the deactivated state. It must still not verify: the DID is abandoned.
		const signature = encodeSignatureEd25519(sign(K1().privateKey, payload));

		expect(verifySignatureWithDid({ did: id.did, kel, payload, signature })).toBe(
			false
		);
	});
});
