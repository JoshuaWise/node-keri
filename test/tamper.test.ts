/**
 * Mutation-style tamper tests.
 *
 * A single valid five-event KEL (icp, ixn, rot, ixn, rot) is built once, then
 * systematically mutated one field — or one structural property — at a time.
 * Every mutation must make `verifyKel` return `{ ok: false }`, and never
 * *throw*: a tampered KEL is hostile but expected input.
 *
 * What each mutation actually exercises
 * -------------------------------------
 * Most event fields (`d`, `i`, `s`, `t`, `p`, `k`, `n`, `a`) are inputs to the
 * event's self-addressing digest. Mutating any of them changes the bytes the
 * SAID is computed over, so replay recomputes a digest that no longer matches
 * the event's `d` and rejects with `INVALID_EVENT_DIGEST` — the digest check
 * is the single mechanism that catches every content tamper, which is the
 * whole point of a self-addressing identifier. These tests therefore assert
 * that *specific* code: a content tamper that started being caught for some
 * other reason (or stopped being caught at all) is itself a regression.
 *
 * A few mutations are caught earlier or elsewhere: the event-type `t` is read
 * before the digest is recomputed; the version string `v` is part of the
 * frame's framing; the controller signature and its count are checked against
 * the attachment, not the event body. Those have their own expected codes.
 *
 * This suite proves *tamper detection breadth* — that no single-field change to
 * any event survives. It deliberately does NOT reach the per-stage semantic
 * checks (sequence chaining, previous-digest linkage, next-key commitment),
 * because the digest check intercepts a raw mutation first. Those checks are
 * exercised against well-formed, self-consistent events in `verify-kel.test.ts`.
 *
 * The KEL is exchanged as a CESR stream, so a mutation is applied to the
 * in-memory `SignedKeriEvent`s and then re-framed (`frameKel`) into the wire
 * form `verifyKel` consumes.
 */

import { createIdentifier } from '../src/api/create-identifier';
import { rotateIdentifier } from '../src/api/rotate-identifier';
import { verifyKel } from '../src/api/verify-kel';
import { createInteractionEvent } from '../src/event/interaction';
import { parseSignedEvent } from '../src/event/stream';
import { keyPairFromSeed } from '../src/crypto/keypair';
import { SignedKeriEvent } from '../src/event/types';
import { Aid } from '../src/did/did-keri';
import { KeriVerificationError } from '../src/profile/errors';
import { frameKel, reframe } from './kel-stream';

function fillSeed(byte: number): Uint8Array {
	return new Uint8Array(32).fill(byte);
}

/** Build the canonical exercise KEL using only the public high-level API. */
function buildKel() {
	const k0 = keyPairFromSeed(fillSeed(0x60));
	const k1 = keyPairFromSeed(fillSeed(0x61));
	const k2 = keyPairFromSeed(fillSeed(0x62));
	const k3 = keyPairFromSeed(fillSeed(0x63));

	const id = createIdentifier({
		currentPrivateKey: k0.privateKey,
		nextPublicKey: k1.publicKey,
	});
	const ixn1 = createInteractionEvent({
		state: id.state,
		currentKeyPair: k0,
		data: [{ step: 1 }],
	});
	const rot1 = rotateIdentifier({
		state: ixn1.state,
		currentPrivateKey: k1.privateKey,
		nextPublicKey: k2.publicKey,
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
		nextPublicKey: k3.publicKey,
	});

	// The constructors return wire-form frames; parse them back so each event
	// can be mutated as a structured `SignedKeriEvent` before re-framing.
	const events: SignedKeriEvent[] = [
		parseSignedEvent(id.inceptionEvent),
		parseSignedEvent(ixn1.event),
		parseSignedEvent(rot1.rotationEvent),
		parseSignedEvent(ixn2.event),
		parseSignedEvent(rot2.rotationEvent),
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

/**
 * Assert that verifyKel rejects the CESR stream `kel` for `aid`, without
 * throwing, and with the exact discriminated error `code` expected. Asserting
 * the code — not merely `ok === false` — is what keeps each test honest about
 * which check is doing the rejecting.
 */
function expectRejected(
	aid: Aid,
	kel: string,
	expectedCode: KeriVerificationError['code']
): void {
	let result: ReturnType<typeof verifyKel>;
	expect(() => {
		result = verifyKel({ aid, kel });
	}).not.toThrow();
	expect(result!.ok).toBe(false);
	if (result!.ok) throw new Error('unreachable');
	expect(result!.error.code).toBe(expectedCode);
}

const indices = [0, 1, 2, 3, 4];

describe('tamper — the untampered KEL verifies', () => {
	test('baseline: a clean five-event KEL is accepted', () => {
		const { aid, events } = buildKel();
		const result = verifyKel({ aid, kel: frameKel(events) });
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error('unreachable');
		expect(result.state.lastSequenceNumber).toBe(4);
	});
});

describe('tamper — single-field mutation of each event', () => {
	test.each(indices)('event %d: mutated self-addressing digest `d`', (i) => {
		const { aid, events } = buildKel();
		expectRejected(
			aid,
			frameKel(
				withReplaced(
					i,
					patchEvent(events[i]!, { d: mutateChar(events[i]!.event.d) })
				).events
			),
			'INVALID_EVENT_DIGEST'
		);
	});

	test.each(indices)('event %d: mutated identifier `i`', (i) => {
		const { aid, events } = buildKel();
		// `i` is the only content field NOT folded into a transferable
		// inception's SAID (there the AID *is* the SAID, so `i` is digested as a
		// placeholder). Mutating it on the inception therefore survives the
		// digest check and is caught by the `i === SAID` identity check
		// instead; on every later event `i` is a normal digested field.
		const code = i === 0 ? 'INVALID_DID' : 'INVALID_EVENT_DIGEST';
		expectRejected(
			aid,
			frameKel(
				withReplaced(
					i,
					patchEvent(events[i]!, { i: mutateChar(events[i]!.event.i) })
				).events
			),
			code
		);
	});

	test.each(indices)('event %d: mutated version string `v`', (i) => {
		const { aid, events } = buildKel();
		// The version string is part of the frame's *framing*, so mutate it on
		// the wire form directly: char 10 falls inside the `KERI10JSON` prefix,
		// so the parser can no longer recognize the frame.
		const frames = events.map((e) =>
			reframe(e.event as unknown as Record<string, unknown>, e.signatures)
		);
		const f = frames[i]!;
		frames[i] = f.slice(0, 10) + (f[10] === 'A' ? 'B' : 'A') + f.slice(11);
		expectRejected(aid, frames.join(''), 'MALFORMED_STREAM');
	});

	test.each(indices)('event %d: mutated sequence number `s`', (i) => {
		const { aid, events } = buildKel();
		// `s` is digested, so a raw mutation is caught as a digest mismatch
		// before the sequence check ever runs; the sequence check itself is
		// exercised by the structural-reorder tests below and in verify-kel.
		expectRejected(
			aid,
			frameKel(withReplaced(i, patchEvent(events[i]!, { s: 'ff' })).events),
			'INVALID_EVENT_DIGEST'
		);
	});

	test.each(indices)('event %d: mutated event type `t`', (i) => {
		const { aid, events } = buildKel();
		// `t` is read and validated before the digest is recomputed, so a
		// mangled type is diagnosed as an invalid event type directly.
		expectRejected(
			aid,
			frameKel(
				withReplaced(
					i,
					patchEvent(events[i]!, { t: mutateChar(events[i]!.event.t) })
				).events
			),
			'INVALID_EVENT_TYPE'
		);
	});

	// `p` (previous-event digest) exists on every non-inception event.
	test.each([1, 2, 3, 4])('event %d: mutated previous-event digest `p`', (i) => {
		const { aid, events } = buildKel();
		const event = events[i]!.event as { p: string };
		// `p` is digested: a raw mutation is a digest mismatch, caught before
		// the previous-digest chain check. That chain check is exercised
		// against self-consistent events in verify-kel.test.ts.
		expectRejected(
			aid,
			frameKel(
				withReplaced(i, patchEvent(events[i]!, { p: mutateChar(event.p) })).events
			),
			'INVALID_EVENT_DIGEST'
		);
	});

	test.each(indices)('event %d: mutated signature', (i) => {
		const { aid, events } = buildKel();
		// The signature is an attachment, not a digested field: the event still
		// hashes correctly, so this is the one mutation that reaches — and is
		// caught by — the signature check.
		const tampered = patchEvent(events[i]!, {});
		tampered.signatures = [mutateChar(events[i]!.signatures[0]) as never];
		expectRejected(
			aid,
			frameKel(withReplaced(i, tampered).events),
			'INVALID_SIGNATURE'
		);
	});
});

describe('tamper — mutation of key material', () => {
	// Events 0, 2, 4 are icp/rot/rot — each carries a `k` and an `n` list.
	test.each([0, 2, 4])('event %d: mutated current key `k[0]`', (i) => {
		const { aid, events } = buildKel();
		const event = events[i]!.event as { k: readonly string[] };
		expectRejected(
			aid,
			frameKel(
				withReplaced(i, patchEvent(events[i]!, { k: [mutateChar(event.k[0]!)] }))
					.events
			),
			'INVALID_EVENT_DIGEST'
		);
	});

	test.each([0, 2, 4])('event %d: mutated next-key commitment `n[0]`', (i) => {
		const { aid, events } = buildKel();
		const event = events[i]!.event as { n: readonly string[] };
		expectRejected(
			aid,
			frameKel(
				withReplaced(i, patchEvent(events[i]!, { n: [mutateChar(event.n[0]!)] }))
					.events
			),
			'INVALID_EVENT_DIGEST'
		);
	});

	test('lifting a foreign key onto a rotation is caught as a digest mismatch', () => {
		const { aid, events } = buildKel();
		// Lift event 4's key list onto event 2. `k` is a digested field, so the
		// swap changes event 2's recomputed SAID and is rejected as a digest
		// mismatch — before the next-key commitment check is even reached. The
		// commitment check proper (a rotation that reveals an uncommitted key
		// but whose SAID *is* self-consistent) is exercised in verify-kel.test.ts.
		const foreignKey = (events[4]!.event as { k: readonly string[] }).k;
		expectRejected(
			aid,
			frameKel(withReplaced(2, patchEvent(events[2]!, { k: foreignKey })).events),
			'INVALID_EVENT_DIGEST'
		);
	});
});

describe('tamper — mutation of anchored interaction data', () => {
	test.each([1, 3])('event %d: altered `a` payload', (i) => {
		const { aid, events } = buildKel();
		expectRejected(
			aid,
			frameKel(
				withReplaced(i, patchEvent(events[i]!, { a: [{ step: 999 }] })).events
			),
			'INVALID_EVENT_DIGEST'
		);
	});
});

describe('tamper — structural mutation of the log', () => {
	test('reordering two events fails the sequence check', () => {
		const { aid, events } = buildKel();
		const reordered = events.slice();
		[reordered[1], reordered[2]] = [reordered[2]!, reordered[1]!];
		expectRejected(aid, frameKel(reordered), 'INVALID_SEQUENCE');
	});

	test('dropping an interior event fails the sequence check', () => {
		const { aid, events } = buildKel();
		const dropped = [...events.slice(0, 2), ...events.slice(3)];
		expectRejected(aid, frameKel(dropped), 'INVALID_SEQUENCE');
	});

	test('duplicating an event fails the sequence check', () => {
		const { aid, events } = buildKel();
		const duplicated = [...events.slice(0, 3), events[2]!, ...events.slice(3)];
		expectRejected(aid, frameKel(duplicated), 'INVALID_SEQUENCE');
	});

	test('a KEL that does not start with inception fails', () => {
		const { aid, events } = buildKel();
		expectRejected(aid, frameKel(events.slice(1)), 'INVALID_EVENT_TYPE');
	});

	test("appending another identifier's inception event fails", () => {
		const { aid, events } = buildKel();
		const intruder = createIdentifier({
			currentPrivateKey: keyPairFromSeed(fillSeed(0x70)).privateKey,
			nextPublicKey: keyPairFromSeed(fillSeed(0x71)).publicKey,
		});
		// A second `icp` past sequence 0 is not a valid continuation event.
		expectRejected(
			aid,
			frameKel(events) + intruder.inceptionEvent,
			'INVALID_EVENT_TYPE'
		);
	});

	test('verifying the KEL against the wrong AID fails', () => {
		const { events } = buildKel();
		const other = createIdentifier({
			currentPrivateKey: keyPairFromSeed(fillSeed(0x72)).privateKey,
			nextPublicKey: keyPairFromSeed(fillSeed(0x73)).publicKey,
		});
		expectRejected(other.aid, frameKel(events), 'INVALID_DID');
	});

	test('a truncated KEL still verifies as an earlier state', () => {
		// Truncation is not tampering: a prefix of a valid KEL is itself a
		// valid KEL describing an earlier point in the identifier's history.
		const { aid, events } = buildKel();
		const result = verifyKel({ aid, kel: frameKel(events.slice(0, 3)) });
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error('unreachable');
		expect(result.state.lastSequenceNumber).toBe(2);
	});
});

describe('tamper — attachment-level mutation', () => {
	test.each(indices)('event %d: zero signatures rejected', (i) => {
		const { aid, events } = buildKel();
		const stripped: SignedKeriEvent = {
			event: events[i]!.event,
			signatures: [] as never,
		};
		expectRejected(
			aid,
			frameKel(withReplaced(i, stripped).events),
			'UNSUPPORTED_FEATURE'
		);
	});

	test.each(indices)('event %d: two signatures rejected (multisig)', (i) => {
		const { aid, events } = buildKel();
		const doubled: SignedKeriEvent = {
			event: events[i]!.event,
			signatures: [events[i]!.signatures[0], events[i]!.signatures[0]] as never,
		};
		expectRejected(
			aid,
			frameKel(withReplaced(i, doubled).events),
			'UNSUPPORTED_FEATURE'
		);
	});
});

describe('tamper — non-canonical serialization', () => {
	// KERI fixes a type-specific field order; the event SAID and signature are
	// computed over those ordered bytes. The replay verifier re-canonicalizes
	// an event before recomputing, so a frame whose JSON merely reorders fields
	// is byte-for-byte equivalent in content and would pass the digest and
	// signature checks — yet a strict verifier (which digests the bytes as
	// received) rejects it. `verifyKel` must reject it too, as
	// `NON_CANONICAL_EVENT`, so the KEL has one canonical wire form.
	test.each(indices)('event %d: non-canonical field order rejected', (i) => {
		const { aid, events } = buildKel();
		const stream = events
			.map((e, idx) => {
				const ev = e.event as unknown as Record<string, unknown>;
				if (idx !== i) return reframe(ev, e.signatures);
				// Same fields, same values — only the order differs from canonical.
				const reordered: Record<string, unknown> = { v: ev.v };
				for (const k of Object.keys(ev)
					.filter((k) => k !== 'v')
					.reverse()) {
					reordered[k] = ev[k];
				}
				return reframe(reordered, e.signatures);
			})
			.join('');
		expectRejected(aid, stream, 'NON_CANONICAL_EVENT');
	});
});
