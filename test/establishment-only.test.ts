/**
 * Test suite for establishment-only (EO) identifiers.
 *
 * The `EO` configuration trait restricts a KEL to establishment events only:
 * `icp` and `rot`, never `ixn`. The trait is declared at inception and
 * inherited by every later event through the replay-derived state. These
 * tests cover:
 *   - constructing an EO inception via `createIdentifier` and the lower-level
 *     `createInceptionEvent`;
 *   - `establishmentOnly` survives rotation and deactivation in the state;
 *   - constructor-side rejection of interaction events on an EO identifier;
 *   - replay-side rejection of an `ixn` appended out of band;
 *   - replay accepts a multi-event KEL with rotations on an EO identifier;
 *   - `EO` on a non-transferable inception is rejected.
 */

import { createIdentifier } from '../src/api/create-identifier';
import { deactivateIdentifier } from '../src/api/deactivate-identifier';
import { interactOnIdentifier } from '../src/api/interact-on-identifier';
import { rotateIdentifier } from '../src/api/rotate-identifier';
import { verifyIdentifier } from '../src/api/verify-identifier';
import { keyPairFromSeed } from '../src/crypto/keypair';
import { createInceptionEvent } from '../src/event/inception';
import { createInteractionEvent } from '../src/event/interaction';
import { parseSignedEvent } from '../src/event/stream';
import { InvalidArgumentError } from '../src/profile/errors';
import { reframe } from './kel-stream';

function fillSeed(byte: number): Uint8Array {
	return new Uint8Array(32).fill(byte);
}

const K0 = () => keyPairFromSeed(fillSeed(0x60));
const K1 = () => keyPairFromSeed(fillSeed(0x61));
const K2 = () => keyPairFromSeed(fillSeed(0x62));
const K3 = () => keyPairFromSeed(fillSeed(0x63));

/** A fresh establishment-only identifier whose current/next keys are K0/K1. */
function freshEoIdentifier() {
	const currentKeyPair = K0();
	const nextKeyPair = K1();
	const result = createIdentifier({
		currentPrivateKey: currentKeyPair.privateKey,
		nextPublicKey: nextKeyPair.publicKey,
		establishmentOnly: true,
	});
	// Thread the keypairs through so callers can sign with / rotate to them.
	return { ...result, currentKeyPair, nextKeyPair };
}

describe('createIdentifier — establishment-only', () => {
	test('emits an inception event whose `c` field is `["EO"]`', () => {
		const id = freshEoIdentifier();
		const event = parseSignedEvent(id.event).event as unknown as {
			t: string;
			c: readonly unknown[];
		};
		expect(event.t).toBe('icp');
		expect(event.c).toEqual(['EO']);
	});

	test('records the establishmentOnly flag on the returned state', () => {
		const id = freshEoIdentifier();
		expect(id.state.establishmentOnly).toBe(true);
		expect(id.state.transferable).toBe(true);
	});

	test('a non-EO identifier has a false `establishmentOnly` flag and an empty `c`', () => {
		const id = createIdentifier({
			currentPrivateKey: K0().privateKey,
			nextPublicKey: K1().publicKey,
		});
		expect(id.state.establishmentOnly).toBe(false);
		const event = parseSignedEvent(id.event).event as unknown as {
			c: readonly unknown[];
		};
		expect(event.c).toEqual([]);
	});

	test('verifyIdentifier replays an EO inception and surfaces the flag in the state', () => {
		const id = freshEoIdentifier();
		const verified = verifyIdentifier({ aid: id.aid, kel: id.event });
		expect(verified.ok).toBe(true);
		if (!verified.ok) throw new Error('unreachable');
		expect(verified.state.transferable).toBe(true);
		if (!verified.state.transferable) throw new Error('unreachable');
		expect(verified.state.establishmentOnly).toBe(true);
		// The replayed state matches the constructor's state exactly — the
		// trait is in both, in the same shape.
		expect(verified.state).toEqual(id.state);
	});
});

describe('createInceptionEvent — establishment-only', () => {
	test('omitting establishmentOnly defaults to a non-EO identifier', () => {
		const result = createInceptionEvent({
			currentKeyPair: K0(),
			nextPublicKey: K1().publicKey,
		});
		expect(result.state.establishmentOnly).toBe(false);
	});

	test('explicit `false` is equivalent to omitting the flag', () => {
		const result = createInceptionEvent({
			currentKeyPair: K0(),
			nextPublicKey: K1().publicKey,
			establishmentOnly: false,
		});
		expect(result.state.establishmentOnly).toBe(false);
		const event = parseSignedEvent(result.event).event as unknown as {
			c: readonly unknown[];
		};
		expect(event.c).toEqual([]);
	});
});

describe('interactOnIdentifier — refuses an EO state', () => {
	test('throws InvalidArgumentError when the state is establishment-only', () => {
		const id = freshEoIdentifier();
		expect(() =>
			interactOnIdentifier({
				state: id.state,
				currentPrivateKey: id.currentKeyPair.privateKey,
				data: [{ blocked: true }],
			})
		).toThrow(InvalidArgumentError);
		expect(() =>
			interactOnIdentifier({
				state: id.state,
				currentPrivateKey: id.currentKeyPair.privateKey,
				data: [],
			})
		).toThrow(/establishment-only/);
	});

	test('the constructor-level call is refused too', () => {
		const id = freshEoIdentifier();
		expect(() =>
			createInteractionEvent({
				state: id.state,
				currentKeyPair: K0(),
				data: [{ blocked: true }],
			})
		).toThrow(InvalidArgumentError);
	});

	test('rotation does not clear the EO flag — interaction is still refused after one', () => {
		const id = freshEoIdentifier();
		const rot = rotateIdentifier({
			state: id.state,
			newPrivateKey: id.nextKeyPair.privateKey,
			nextPublicKey: K2().publicKey,
		});
		expect(rot.state.establishmentOnly).toBe(true);
		expect(() =>
			interactOnIdentifier({
				state: rot.state,
				currentPrivateKey: id.nextKeyPair.privateKey,
				data: [{ still: 'blocked' }],
			})
		).toThrow(InvalidArgumentError);
	});
});

describe('rotateIdentifier — propagates establishmentOnly through the KEL', () => {
	test('the post-rotation state still carries the flag', () => {
		const id = freshEoIdentifier();
		const rot = rotateIdentifier({
			state: id.state,
			newPrivateKey: id.nextKeyPair.privateKey,
			nextPublicKey: K2().publicKey,
		});
		expect(rot.state.establishmentOnly).toBe(true);
	});

	test('verifyIdentifier accepts an EO KEL with multiple rotations', () => {
		const id = freshEoIdentifier();
		const k2 = K2();
		const k3 = K3();
		const rot1 = rotateIdentifier({
			state: id.state,
			newPrivateKey: id.nextKeyPair.privateKey,
			nextPublicKey: k2.publicKey,
		});
		const rot2 = rotateIdentifier({
			state: rot1.state,
			newPrivateKey: k2.privateKey,
			nextPublicKey: k3.publicKey,
		});

		const verified = verifyIdentifier({
			aid: id.aid,
			kel: id.event + rot1.event + rot2.event,
		});
		expect(verified.ok).toBe(true);
		if (!verified.ok) throw new Error('unreachable');
		expect(verified.state.lastSequenceNumber).toBe(2);
		expect(verified.state.transferable).toBe(true);
		if (!verified.state.transferable) throw new Error('unreachable');
		expect(verified.state.establishmentOnly).toBe(true);
		expect(verified.state).toEqual(rot2.state);
	});
});

describe('deactivateIdentifier — works on an EO identifier and preserves the trait', () => {
	test('deactivation is permitted (it is an establishment event) and carries the flag', () => {
		const id = freshEoIdentifier();
		const deact = deactivateIdentifier({
			state: id.state,
			newPrivateKey: id.nextKeyPair.privateKey,
		});
		expect(deact.state.deactivated).toBe(true);
		expect(deact.state.transferable).toBe(false);
		expect(deact.state.establishmentOnly).toBe(true);

		const verified = verifyIdentifier({
			aid: id.aid,
			kel: id.event + deact.event,
		});
		expect(verified.ok).toBe(true);
		if (!verified.ok) throw new Error('unreachable');
		expect(verified.state).toEqual(deact.state);
	});
});

describe('verifyIdentifier — rejects out-of-band ixn appended to an EO KEL', () => {
	test('ESTABLISHMENT_ONLY_NO_INTERACTION fires when an `ixn` follows an EO inception', () => {
		const id = freshEoIdentifier();
		// Mint a non-EO identifier with the *same* current/next keys, so its
		// `ixn` is byte-compatible — apart from its `i`, which we rewrite — and
		// the only reason replay rejects it is the EO trait on the prior state.
		const nonEo = createIdentifier({
			currentPrivateKey: K0().privateKey,
			nextPublicKey: K1().publicKey,
		});
		const ixn = createInteractionEvent({
			state: nonEo.state,
			currentKeyPair: K0(),
			data: [{ smuggled: true }],
		});

		// Re-frame the smuggled ixn so its `i`/`p` line up with the EO
		// identifier, then re-sign it under K0 against the EO KEL.
		const parsedIxn = parseSignedEvent(ixn.event);
		const tampered = reframe(
			{
				...(parsedIxn.event as unknown as Record<string, unknown>),
				i: id.aid,
				p: id.state.lastEventDigest,
			},
			parsedIxn.signatures
		);
		const verified = verifyIdentifier({
			aid: id.aid,
			kel: id.event + tampered,
		});
		// The exact diagnosis we want: replay refuses an `ixn` on an EO KEL
		// before bothering with shape, digest, or signature checks.
		expect(verified.ok).toBe(false);
		if (verified.ok) throw new Error('unreachable');
		expect(verified.error.code).toBe('ESTABLISHMENT_ONLY_NO_INTERACTION');
		if (verified.error.code !== 'ESTABLISHMENT_ONLY_NO_INTERACTION') {
			throw new Error('unreachable');
		}
		expect(verified.error.eventType).toBe('ixn');
	});
});

describe('verifyIdentifier — configuration traits boundary', () => {
	test('rejects an inception whose `c` carries an unknown trait', () => {
		const id = createIdentifier({
			currentPrivateKey: K0().privateKey,
			nextPublicKey: K1().publicKey,
		});
		const parsed = parseSignedEvent(id.event);
		// Splice in `c: ['DND']` — a real KERI trait, but one outside this profile.
		const tampered = reframe(
			{ ...(parsed.event as unknown as Record<string, unknown>), c: ['DND'] },
			parsed.signatures
		);
		const verified = verifyIdentifier({ aid: id.aid, kel: tampered });
		expect(verified.ok).toBe(false);
		if (verified.ok) throw new Error('unreachable');
		expect(verified.error.code).toBe('UNSUPPORTED_FEATURE');
	});

	test('rejects an inception whose `c` carries `EO` plus another trait', () => {
		const id = createIdentifier({
			currentPrivateKey: K0().privateKey,
			nextPublicKey: K1().publicKey,
		});
		const parsed = parseSignedEvent(id.event);
		const tampered = reframe(
			{
				...(parsed.event as unknown as Record<string, unknown>),
				c: ['EO', 'DND'],
			},
			parsed.signatures
		);
		const verified = verifyIdentifier({ aid: id.aid, kel: tampered });
		expect(verified.ok).toBe(false);
		if (verified.ok) throw new Error('unreachable');
		expect(verified.error.code).toBe('UNSUPPORTED_FEATURE');
	});

	test('rejects an inception whose `c` is not an array', () => {
		const id = createIdentifier({
			currentPrivateKey: K0().privateKey,
			nextPublicKey: K1().publicKey,
		});
		const parsed = parseSignedEvent(id.event);
		const tampered = reframe(
			{ ...(parsed.event as unknown as Record<string, unknown>), c: 'EO' },
			parsed.signatures
		);
		const verified = verifyIdentifier({ aid: id.aid, kel: tampered });
		expect(verified.ok).toBe(false);
		if (verified.ok) throw new Error('unreachable');
		expect(verified.error.code).toBe('UNSUPPORTED_FEATURE');
	});
});
