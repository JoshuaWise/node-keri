/**
 * Mutation-style tamper tests.
 *
 * A single valid five-event KEL (icp, ixn, rot, ixn, rot) is built once, then
 * systematically mutated one field — or one structural property — at a time.
 * Every mutation must make `verifyKel` return `{ ok: false }`. `verifyKel`
 * must never *throw* for a tampered KEL: hostile input is expected input.
 */

import { createIdentifier } from '../src/api/create-identifier';
import { rotateIdentifier } from '../src/api/rotate-identifier';
import { verifyKel } from '../src/api/verify-kel';
import { createInteractionEvent } from '../src/event/interaction';
import { keyPairFromSeed } from '../src/crypto/keypair';
import { SignedKeriEvent } from '../src/event/types';
import { Aid } from '../src/did/did-keri';

function fillSeed(byte: number): Uint8Array {
	return new Uint8Array(32).fill(byte);
}

/** Build the canonical exercise KEL using only the public high-level API. */
function buildKel() {
	const k0 = keyPairFromSeed(fillSeed(0x60));
	const k1 = keyPairFromSeed(fillSeed(0x61));
	const k2 = keyPairFromSeed(fillSeed(0x62));
	const k3 = keyPairFromSeed(fillSeed(0x63));

	const id = createIdentifier({ currentKeyPair: k0, nextKeyPair: k1 });
	const ixn1 = createInteractionEvent({
		state: id.state,
		currentKeyPair: k0,
		data: [{ step: 1 }],
	});
	const rot1 = rotateIdentifier({
		state: ixn1.state,
		currentPrivateKey: k1.privateKey,
		nextKeyPair: k2,
	});
	// After rot1 the authoritative key is k1 (the key it revealed), so the
	// interaction that follows must be signed by k1, not the next key.
	const ixn2 = createInteractionEvent({
		state: rot1.state,
		currentKeyPair: k1,
		data: [{ step: 2 }],
	});
	const rot2 = rotateIdentifier({
		state: ixn2.state,
		currentPrivateKey: k2.privateKey,
		nextKeyPair: k3,
	});

	const events: SignedKeriEvent[] = [
		id.inceptionEvent,
		ixn1.signedEvent,
		rot1.rotationEvent,
		ixn2.signedEvent,
		rot2.rotationEvent,
	];
	return { aid: id.aid, events };
}

/** Flip one interior character of a string to a different base64url char. */
function mutateChar(s: string): string {
	const i = Math.floor(s.length / 2);
	const replacement = s[i] === 'A' ? 'B' : 'A';
	return s.slice(0, i) + replacement + s.slice(i + 1);
}

/** Clone a signed event, replacing fields of the inner event object. */
function patchEvent(
	signed: SignedKeriEvent,
	patch: Record<string, unknown>
): SignedKeriEvent {
	return {
		event: { ...signed.event, ...patch } as SignedKeriEvent['event'],
		signatures: signed.signatures,
	};
}

/** Replace event `index` of a fresh KEL copy with `replacement`. */
function withReplaced(index: number, replacement: SignedKeriEvent) {
	const { aid, events } = buildKel();
	const tampered = events.slice();
	tampered[index] = replacement;
	return { aid, events: tampered };
}

/** Assert that verifyKel rejects `events` as belonging to `aid`. */
function expectRejected(aid: Aid, events: readonly SignedKeriEvent[]): void {
	let result: ReturnType<typeof verifyKel>;
	expect(() => {
		result = verifyKel({ aid, events });
	}).not.toThrow();
	expect(result!.ok).toBe(false);
}

const indices = [0, 1, 2, 3, 4];

describe('tamper — the untampered KEL verifies', () => {
	test('baseline: a clean five-event KEL is accepted', () => {
		const { aid, events } = buildKel();
		const result = verifyKel({ aid, events });
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error('unreachable');
		expect(result.state.sequenceNumber).toBe(4);
	});
});

describe('tamper — single-field mutation of each event', () => {
	test.each(indices)('event %d: mutated self-addressing digest `d`', (i) => {
		const { aid, events } = buildKel();
		expectRejected(
			aid,
			withReplaced(i, patchEvent(events[i], { d: mutateChar(events[i].event.d) }))
				.events
		);
	});

	test.each(indices)('event %d: mutated identifier `i`', (i) => {
		const { aid, events } = buildKel();
		expectRejected(
			aid,
			withReplaced(i, patchEvent(events[i], { i: mutateChar(events[i].event.i) }))
				.events
		);
	});

	test.each(indices)('event %d: mutated version string `v`', (i) => {
		const { aid, events } = buildKel();
		expectRejected(
			aid,
			withReplaced(i, patchEvent(events[i], { v: mutateChar(events[i].event.v) }))
				.events
		);
	});

	test.each(indices)('event %d: wrong sequence number `s`', (i) => {
		const { aid, events } = buildKel();
		expectRejected(aid, withReplaced(i, patchEvent(events[i], { s: 'ff' })).events);
	});

	test.each(indices)('event %d: mutated event type `t`', (i) => {
		const { aid, events } = buildKel();
		expectRejected(
			aid,
			withReplaced(i, patchEvent(events[i], { t: mutateChar(events[i].event.t) }))
				.events
		);
	});

	// `p` (previous-event digest) exists on every non-inception event.
	test.each([1, 2, 3, 4])('event %d: mutated previous-event digest `p`', (i) => {
		const { aid, events } = buildKel();
		const event = events[i].event as { p: string };
		expectRejected(
			aid,
			withReplaced(i, patchEvent(events[i], { p: mutateChar(event.p) })).events
		);
	});

	test.each(indices)('event %d: mutated signature', (i) => {
		const { aid, events } = buildKel();
		const tampered = patchEvent(events[i], {});
		tampered.signatures = [mutateChar(events[i].signatures[0]) as never];
		expectRejected(aid, withReplaced(i, tampered).events);
	});
});

describe('tamper — mutation of key material', () => {
	// Events 0, 2, 4 are icp/rot/rot — each carries a `k` and an `n` list.
	test.each([0, 2, 4])('event %d: mutated current key `k[0]`', (i) => {
		const { aid, events } = buildKel();
		const event = events[i].event as { k: readonly string[] };
		expectRejected(
			aid,
			withReplaced(i, patchEvent(events[i], { k: [mutateChar(event.k[0])] })).events
		);
	});

	test.each([0, 2, 4])('event %d: mutated next-key commitment `n[0]`', (i) => {
		const { aid, events } = buildKel();
		const event = events[i].event as { n: readonly string[] };
		expectRejected(
			aid,
			withReplaced(i, patchEvent(events[i], { n: [mutateChar(event.n[0])] })).events
		);
	});

	test('a rotation revealing the wrong key fails the commitment check', () => {
		const { aid, events } = buildKel();
		// Lift event 4's key list onto event 2 — a structurally valid key,
		// but not the one event 1 pre-committed to.
		const foreignKey = (events[4].event as { k: readonly string[] }).k;
		expectRejected(
			aid,
			withReplaced(2, patchEvent(events[2], { k: foreignKey })).events
		);
	});
});

describe('tamper — mutation of anchored interaction data', () => {
	test.each([1, 3])('event %d: altered `a` payload', (i) => {
		const { aid, events } = buildKel();
		expectRejected(
			aid,
			withReplaced(i, patchEvent(events[i], { a: [{ step: 999 }] })).events
		);
	});
});

describe('tamper — structural mutation of the log', () => {
	test('reordering two events fails', () => {
		const { aid, events } = buildKel();
		const reordered = events.slice();
		[reordered[1], reordered[2]] = [reordered[2], reordered[1]];
		expectRejected(aid, reordered);
	});

	test('dropping an interior event fails', () => {
		const { aid, events } = buildKel();
		const dropped = [...events.slice(0, 2), ...events.slice(3)];
		expectRejected(aid, dropped);
	});

	test('duplicating an event fails', () => {
		const { aid, events } = buildKel();
		const duplicated = [...events.slice(0, 3), events[2], ...events.slice(3)];
		expectRejected(aid, duplicated);
	});

	test('a KEL that does not start with inception fails', () => {
		const { aid, events } = buildKel();
		expectRejected(aid, events.slice(1));
	});

	test("appending another identifier's event fails", () => {
		const { aid, events } = buildKel();
		const intruder = createIdentifier({
			currentKeyPair: keyPairFromSeed(fillSeed(0x70)),
			nextKeyPair: keyPairFromSeed(fillSeed(0x71)),
		});
		expectRejected(aid, [...events, intruder.inceptionEvent]);
	});

	test('verifying the KEL against the wrong AID fails', () => {
		const { events } = buildKel();
		const other = createIdentifier({
			currentKeyPair: keyPairFromSeed(fillSeed(0x72)),
			nextKeyPair: keyPairFromSeed(fillSeed(0x73)),
		});
		expectRejected(other.aid, events);
	});

	test('a truncated KEL still verifies as an earlier state', () => {
		// Truncation is not tampering: a prefix of a valid KEL is itself a
		// valid KEL describing an earlier point in the identifier's history.
		const { aid, events } = buildKel();
		const result = verifyKel({ aid, events: events.slice(0, 3) });
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error('unreachable');
		expect(result.state.sequenceNumber).toBe(2);
	});
});

describe('tamper — wrapper-level mutation', () => {
	test.each(indices)('event %d: zero signatures rejected', (i) => {
		const { aid, events } = buildKel();
		const stripped = { event: events[i].event, signatures: [] as never };
		expectRejected(aid, withReplaced(i, stripped).events);
	});

	test.each(indices)('event %d: two signatures rejected (multisig)', (i) => {
		const { aid, events } = buildKel();
		const doubled = {
			event: events[i].event,
			signatures: [events[i].signatures[0], events[i].signatures[0]] as never,
		};
		expectRejected(aid, withReplaced(i, doubled).events);
	});
});
