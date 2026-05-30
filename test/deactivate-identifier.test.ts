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
import { interactOnIdentifier } from '../src/api/interact-on-identifier';
import { deactivateIdentifier } from '../src/api/deactivate-identifier';
import { verifyIdentifier } from '../src/api/verify-identifier';
import { verifySignatureWithDid } from '../src/did/verify-signature-with-did';
import { utf8Encode } from '../src/bytes/utf8';
import { encodeSignatureEd25519 } from '../src/cesr/encode';
import { sign } from '../src/crypto/ed25519';
import { createDeactivationEvent } from '../src/event/deactivation';
import { createInteractionEvent } from '../src/event/interaction';
import { deriveNextKeyCommitment } from '../src/event/digest';
import { createDidDocument } from '../src/did/document';
import { verifyDid } from '../src/did/verify-did';
import { KeriState, TransferableKeriState } from '../src/kel/state';
import { InvalidArgumentError } from '../src/profile/errors';
import { reframe } from './kel-stream';
import { parseSignedEvent, fillSeed, keyPairFromSeed } from './helpers/util';

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
			newPrivateKey: id.nextKeyPair.privateKey,
		});

		const event = parseSignedEvent(deact.event).event as unknown as Record<
			string,
			unknown
		>;
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
			newPrivateKey: id.nextKeyPair.privateKey,
		});

		expect(deact.state.deactivated).toBe(true);
		expect(deact.state.transferable).toBe(false);
		expect(deact.state.lastEventType).toBe('rot');
		expect(deact.state.lastSequenceNumber).toBe(1);
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
				newPrivateKey: K2().privateKey,
			})
		).toThrow(InvalidArgumentError);
	});

	test('a non-transferable identifier cannot be deactivated', () => {
		const id = freshIdentifier();
		const nonTransferable: KeriState = {
			aid: id.aid,
			did: id.did,
			lastSequenceNumber: 0,
			currentPublicKey: id.state.currentPublicKey,
			transferable: false,
			deactivated: false,
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
			newPrivateKey: id.nextKeyPair.privateKey,
		});
		expect(() =>
			deactivateIdentifier({
				state: deact.state,
				newPrivateKey: id.nextKeyPair.privateKey,
			})
		).toThrow(/already deactivated/);
	});
});

describe('deactivateIdentifier — extends a longer KEL', () => {
	test('deactivates after a rotation', () => {
		const id = freshIdentifier();
		const rot = rotateIdentifier({
			state: id.state,
			newPrivateKey: id.nextKeyPair.privateKey,
			nextPublicKey: K2().publicKey,
		});
		const deact = deactivateIdentifier({
			state: rot.state,
			newPrivateKey: K2().privateKey,
		});

		const kel = id.event + rot.event + deact.event;
		const result = verifyIdentifier({ aid: id.aid, kel });
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.state.deactivated).toBe(true);
		expect(result.state.lastSequenceNumber).toBe(2);
	});

	test('deactivates after an interaction event', () => {
		const id = freshIdentifier();
		const ixn = interactOnIdentifier({
			state: id.state,
			currentPrivateKey: id.currentKeyPair.privateKey,
			data: [{ note: 'last words' }],
		});
		const deact = deactivateIdentifier({
			state: ixn.state,
			newPrivateKey: id.nextKeyPair.privateKey,
		});

		const kel = id.event + ixn.event + deact.event;
		const result = verifyIdentifier({ aid: id.aid, kel });
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.state.deactivated).toBe(true);
		expect(result.state.lastSequenceNumber).toBe(2);
	});
});

describe('verifyIdentifier — replays a deactivated KEL', () => {
	test('verifies a KEL ending in a deactivation event', () => {
		const id = freshIdentifier();
		const deact = deactivateIdentifier({
			state: id.state,
			newPrivateKey: id.nextKeyPair.privateKey,
		});
		const kel = id.event + deact.event;

		const result = verifyIdentifier({ aid: id.aid, kel });
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.state.transferable).toBe(false);
		expect(result.state.deactivated).toBe(true);
		expect(result.state.lastEventType).toBe('rot');
		expect(result.state.lastSequenceNumber).toBe(1);
	});

	test('rejects any event appended after deactivation', () => {
		const id = freshIdentifier();
		const deact = deactivateIdentifier({
			state: id.state,
			newPrivateKey: id.nextKeyPair.privateKey,
		});

		// Forge a syntactically valid interaction event that chains onto the
		// deactivation event, by feeding `createInteractionEvent` a state that
		// looks transferable. Replay must still reject it: the prior event was
		// a deactivation.
		const pretendState: TransferableKeriState = {
			aid: deact.state.aid,
			did: deact.state.did,
			lastSequenceNumber: deact.state.lastSequenceNumber,
			lastEventType: 'rot',
			lastEventDigest: deact.state.lastEventDigest,
			currentPublicKey: id.state.currentPublicKey,
			nextKeyCommitment: deriveNextKeyCommitment(K2().publicKey),
			transferable: true,
			deactivated: false,
			establishmentOnly: false,
		};
		const appended = createInteractionEvent({
			state: pretendState,
			currentKeyPair: K0(),
			data: [],
		});

		const kel = id.event + deact.event + appended.event;
		const result = verifyIdentifier({ aid: id.aid, kel });
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe('DEACTIVATED_NOT_EXTENSIBLE');
	});

	test('rejects a deactivation event that still commits to a next key', () => {
		const id = freshIdentifier();
		const deact = deactivateIdentifier({
			state: id.state,
			newPrivateKey: id.nextKeyPair.privateKey,
		});
		const signed = parseSignedEvent(deact.event);
		// `nt: "0"` but a non-empty `n` is a contradiction the shape pass
		// rejects: a deactivation commits to no next key.
		const tampered = {
			...(signed.event as unknown as Record<string, unknown>),
			n: [deriveNextKeyCommitment(K2().publicKey)],
		};
		const kel = id.event + reframe(tampered, signed.signatures);

		const result = verifyIdentifier({ aid: id.aid, kel });
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe('UNSUPPORTED_FEATURE');
	});

	test('rejects a tampered deactivation event', () => {
		const id = freshIdentifier();
		const deact = deactivateIdentifier({
			state: id.state,
			newPrivateKey: id.nextKeyPair.privateKey,
		});
		const signed = parseSignedEvent(deact.event);
		// Mutate the sequence number, leaving the SAID/signature stale.
		const tampered = {
			...(signed.event as unknown as Record<string, unknown>),
			s: '2',
		};
		const kel = id.event + reframe(tampered, signed.signatures);

		const result = verifyIdentifier({ aid: id.aid, kel });
		expect(result.ok).toBe(false);
	});
});

describe('deactivation closes the lifecycle API', () => {
	test('a deactivated state cannot be rotated', () => {
		const id = freshIdentifier();
		const deact = deactivateIdentifier({
			state: id.state,
			newPrivateKey: id.nextKeyPair.privateKey,
		});
		expect(() =>
			rotateIdentifier({
				state: deact.state,
				newPrivateKey: K2().privateKey,
				nextPublicKey: K3().publicKey,
			})
		).toThrow(/deactivated identifier cannot be rotated/);
	});

	test('a deactivated state cannot anchor interaction events', () => {
		const id = freshIdentifier();
		const deact = deactivateIdentifier({
			state: id.state,
			newPrivateKey: id.nextKeyPair.privateKey,
		});
		expect(() =>
			interactOnIdentifier({
				state: deact.state,
				currentPrivateKey: K1().privateKey,
				data: [],
			})
		).toThrow(/deactivated identifier cannot anchor/);
	});
});

describe('DID surface — a deactivated DID', () => {
	test('verifyDid reports deactivation and an authority-free document', () => {
		const id = freshIdentifier();
		const deact = deactivateIdentifier({
			state: id.state,
			newPrivateKey: id.nextKeyPair.privateKey,
		});
		const kel = id.event + deact.event;

		const result = verifyDid({ did: id.did, kel });
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.state.deactivated).toBe(true);
		// Two events (icp + deactivating rot) ⇒ the last is at sequence number 1.
		expect(result.state.lastSequenceNumber).toBe(1);
		// The verified deactivated state projects to an authority-free document.
		const doc = createDidDocument({ state: result.state });
		expect(doc.verificationMethod).toEqual([]);
		expect(doc.authentication).toEqual([]);
		expect(doc.assertionMethod).toEqual([]);
		expect(doc.id).toBe(id.did);
	});

	test('createDidDocument projects a deactivated state with no key', () => {
		const id = freshIdentifier();
		const deact = deactivateIdentifier({
			state: id.state,
			newPrivateKey: id.nextKeyPair.privateKey,
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
			newPrivateKey: id.nextKeyPair.privateKey,
		});
		const kel = id.event + deact.event;

		const payload = utf8Encode('message from an abandoned identity');
		// Sign with the key the deactivation event reveals — the only key in
		// the deactivated state. It must still not verify: the DID is abandoned.
		const signature = encodeSignatureEd25519(sign(K1().privateKey, payload));

		expect(verifySignatureWithDid({ did: id.did, kel, payload, signature })).toBe(
			false
		);
	});
});
