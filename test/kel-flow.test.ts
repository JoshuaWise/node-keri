import { keyPairFromSeed, publicKeyToCesr } from '../src/crypto/keypair';
import { createInceptionEvent } from '../src/event/inception';
import { createInteractionEvent } from '../src/event/interaction';
import { createRotationEvent } from '../src/event/rotation';
import { parseSignedEvent } from '../src/event/stream';
import { verifyEventSignature } from '../src/event/verify-signature';
import { SignedKeriEvent } from '../src/event/types';
import { CesrPublicKey } from '../src/cesr/qualified';

function fillSeed(byte: number): Uint8Array {
	return new Uint8Array(32).fill(byte);
}

/**
 * End-to-end exercise of the Milestone 3 surface: build a full local KEL
 * containing inception, interaction, rotation, interaction, rotation, and
 * verify each event under the key that was authoritative when it was issued.
 *
 * This is the closest Milestone 3 gets to a "verifyIdentifier" check — a real
 * replay verifier (Milestone 4) will walk the same chain but additionally
 * cross-check sequence numbers, digest links, and rotation-commitment
 * matches. Here we just confirm that the *constructors* produce a chain
 * that hangs together end-to-end.
 */
describe('local KEL flow (inception + ixn + rot + ixn + rot)', () => {
	test('builds and verifies a 5-event chain', () => {
		const k0 = keyPairFromSeed(fillSeed(0xa0));
		const k1 = keyPairFromSeed(fillSeed(0xa1));
		const k2 = keyPairFromSeed(fillSeed(0xa2));
		const k3 = keyPairFromSeed(fillSeed(0xa3));

		// Track which key was authoritative for each event so we can verify.
		const expectedSigner: CesrPublicKey[] = [];
		const events: SignedKeriEvent[] = [];

		// 1. Inception, signed by k0; commits to k1 next.
		const icp = createInceptionEvent({
			currentKeyPair: k0,
			nextPublicKey: k1.publicKey,
		});
		events.push(parseSignedEvent(icp.event));
		expectedSigner.push(publicKeyToCesr(k0.publicKey));

		// 2. Interaction signed by k0 (no rotation yet).
		const ixn1 = createInteractionEvent({
			state: icp.state,
			currentKeyPair: k0,
			data: [{ kind: 'announce', payload: 'agent online' }],
		});
		events.push(parseSignedEvent(ixn1.event));
		expectedSigner.push(publicKeyToCesr(k0.publicKey));

		// 3. Rotate to k1; commits to k2 next.
		const rot1 = createRotationEvent({
			state: ixn1.state,
			newCurrentKeyPair: k1,
			nextPublicKey: k2.publicKey,
		});
		events.push(parseSignedEvent(rot1.event));
		expectedSigner.push(publicKeyToCesr(k1.publicKey));

		// 4. Interaction signed by k1.
		const ixn2 = createInteractionEvent({
			state: rot1.state,
			currentKeyPair: k1,
			data: [{ kind: 'attest', hash: 'I' + 'A'.repeat(43) }],
		});
		events.push(parseSignedEvent(ixn2.event));
		expectedSigner.push(publicKeyToCesr(k1.publicKey));

		// 5. Rotate to k2; commits to k3 next.
		const rot2 = createRotationEvent({
			state: ixn2.state,
			newCurrentKeyPair: k2,
			nextPublicKey: k3.publicKey,
		});
		events.push(parseSignedEvent(rot2.event));
		expectedSigner.push(publicKeyToCesr(k2.publicKey));

		// Sequence numbers are dense and monotonic, AID is stable.
		const aid = icp.state.aid;
		for (let i = 0; i < events.length; i++) {
			const e = events[i]!.event;
			expect(e.i).toBe(aid);
			expect(e.s).toBe(i.toString(16));
		}

		// Each event's `p` (where it has one) chains to the previous SAID.
		for (let i = 1; i < events.length; i++) {
			const e = events[i]!.event;
			if (e.t === 'icp') throw new Error('only the first event may be icp');
			expect(e.p).toBe(events[i - 1]!.event.d);
		}

		// Every signature verifies under the key that was authoritative at
		// the time the event was issued.
		for (let i = 0; i < events.length; i++) {
			expect(
				verifyEventSignature(
					events[i]!.event,
					expectedSigner[i]!,
					events[i]!.signatures[0]
				)
			).toBe(true);
		}

		// Final state reflects the latest rotation.
		expect(rot2.state.lastSequenceNumber).toBe(4);
		expect(rot2.state.currentPublicKey).toBe(
			publicKeyToCesr(k2.publicKey)
		);
		expect(rot2.state.lastEventType).toBe('rot');
		expect(rot2.state.aid).toBe(aid);
	});

	test('many consecutive rotations build a long chain', () => {
		const seeds = Array.from({ length: 20 }, (_, i) => fillSeed(0xc0 + i));
		const keys = seeds.map((s) => keyPairFromSeed(s));

		const icp = createInceptionEvent({
			currentKeyPair: keys[0]!,
			nextPublicKey: keys[1]!.publicKey,
		});
		let state = icp.state;

		for (let i = 1; i < keys.length - 1; i++) {
			const r = createRotationEvent({
				state,
				newCurrentKeyPair: keys[i]!,
				nextPublicKey: keys[i + 1]!.publicKey,
			});
			expect(r.state.lastSequenceNumber).toBe(i);
			expect(r.state.currentPublicKey).toBe(
				publicKeyToCesr(keys[i]!.publicKey)
			);
			const signed = parseSignedEvent(r.event);
			expect(
				verifyEventSignature(
					signed.event,
					publicKeyToCesr(keys[i]!.publicKey),
					signed.signatures[0]
				)
			).toBe(true);
			state = r.state;
		}

		expect(state.lastSequenceNumber).toBe(keys.length - 2);
	});
});
