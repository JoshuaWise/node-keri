import { encodePublicKeyEd25519 } from '../src/cesr/encode';
import { keyPairFromSeed } from '../src/crypto/keypair';
import { computeEventSaid, deriveNextKeyCommitment } from '../src/event/digest';
import { createInceptionEvent } from '../src/event/inception';
import { createInteractionEvent } from '../src/event/interaction';
import { createRotationEvent } from '../src/event/rotation';
import { signEvent } from '../src/event/sign';
import {
	InceptionEvent,
	InteractionEvent,
	RotationEvent,
	SignedKeriEvent,
} from '../src/event/types';
import { aidFromSaid } from '../src/did/did-keri';
import { InvalidArgumentError } from '../src/profile/errors';
import { verifyKel } from '../src/api/verify-kel';

function fillSeed(byte: number): Uint8Array {
	return new Uint8Array(32).fill(byte);
}

/** Build the canonical exercise KEL: icp, ixn, rot, ixn, rot (seq 0..4). */
function buildKel() {
	const k0 = keyPairFromSeed(fillSeed(0xa0));
	const k1 = keyPairFromSeed(fillSeed(0xa1));
	const k2 = keyPairFromSeed(fillSeed(0xa2));
	const k3 = keyPairFromSeed(fillSeed(0xa3));

	const icp = createInceptionEvent({
		currentKeyPair: k0,
		nextPublicKey: k1.publicKey,
	});
	const ixn1 = createInteractionEvent({
		state: icp.state,
		currentKeyPair: k0,
		data: [{ kind: 'announce' }],
	});
	const rot1 = createRotationEvent({
		state: ixn1.state,
		newCurrentKeyPair: k1,
		nextPublicKey: k2.publicKey,
	});
	const ixn2 = createInteractionEvent({
		state: rot1.state,
		currentKeyPair: k1,
		data: [{ kind: 'attest' }],
	});
	const rot2 = createRotationEvent({
		state: ixn2.state,
		newCurrentKeyPair: k2,
		nextPublicKey: k3.publicKey,
	});

	const events: SignedKeriEvent[] = [
		icp.signedEvent,
		ixn1.signedEvent,
		rot1.signedEvent,
		ixn2.signedEvent,
		rot2.signedEvent,
	];
	return { aid: icp.state.aid, events, icp, ixn1, rot1, ixn2, rot2, keys: { k0, k1, k2, k3 } };
}

/** Clone a signed event, patching fields of the inner event object. */
function patchEvent(
	signed: SignedKeriEvent,
	patch: Record<string, unknown>
): SignedKeriEvent {
	return {
		event: { ...signed.event, ...patch } as SignedKeriEvent['event'],
		signatures: signed.signatures,
	};
}

describe('verifyKel — successful replay', () => {
	test('verifies a valid 5-event KEL and reconstructs the latest state', () => {
		const { aid, events, rot2, keys } = buildKel();
		const result = verifyKel({ aid, events });

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.state.aid).toBe(aid);
		expect(result.state.sequenceNumber).toBe(4);
		expect(result.state.eventType).toBe('rot');
		expect(result.state.currentPublicKey).toBe(
			encodePublicKeyEd25519(keys.k2.publicKey.raw)
		);
		expect(result.state.lastEventDigest).toBe(rot2.signedEvent.event.d);
		expect(result.state.nextKeyCommitment).toBe(rot2.state.nextKeyCommitment);
	});

	test('verifies an inception-only KEL', () => {
		const { aid, icp } = buildKel();
		const result = verifyKel({ aid, events: [icp.signedEvent] });
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.state.sequenceNumber).toBe(0);
		expect(result.state.eventType).toBe('icp');
	});

	test('is deterministic — repeated verification yields an identical state', () => {
		const { aid, events } = buildKel();
		const first = verifyKel({ aid, events });
		const second = verifyKel({ aid, events });
		expect(first.ok && second.ok).toBe(true);
		if (!first.ok || !second.ok) return;
		expect(second.state).toEqual(first.state);
	});
});

describe('verifyKel — structural rejection', () => {
	test('rejects an empty KEL', () => {
		const { aid } = buildKel();
		const result = verifyKel({ aid, events: [] });
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error).toEqual({ code: 'EMPTY_KEL' });
	});

	test('rejects an event with a mis-declared version string', () => {
		const { aid, events, icp } = buildKel();
		const tampered = [...events];
		// Content is untouched, so the SAID still matches; only `v` is wrong.
		tampered[0] = patchEvent(icp.signedEvent, { v: 'KERI10JSON000000_' });
		const result = verifyKel({ aid, events: tampered });
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error).toEqual({ code: 'NON_CANONICAL_EVENT' });
	});

	test('rejects an event with a non-canonical sequence number', () => {
		const { aid, events, ixn1 } = buildKel();
		const tampered = [...events];
		// `01` has a leading zero — not the canonical hex form of seq 1.
		tampered[1] = patchEvent(ixn1.signedEvent, { s: '01' });
		const result = verifyKel({ aid, events: tampered });
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error).toEqual({ code: 'NON_CANONICAL_EVENT' });
	});

	test('rejects a KEL whose first event is not an inception', () => {
		const { aid, rot1 } = buildKel();
		const result = verifyKel({ aid, events: [rot1.signedEvent] });
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error).toEqual({
			code: 'INVALID_EVENT_TYPE',
			eventType: 'rot',
		});
	});

	test('rejects a duplicate inception event', () => {
		const { aid, icp } = buildKel();
		const result = verifyKel({
			aid,
			events: [icp.signedEvent, icp.signedEvent],
		});
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error).toEqual({
			code: 'INVALID_EVENT_TYPE',
			eventType: 'icp',
		});
	});

	test('rejects an event carrying witnesses', () => {
		const { aid, events, icp } = buildKel();
		const tampered = [...events];
		tampered[0] = patchEvent(icp.signedEvent, { b: ['Dwitnesskey'] });
		const result = verifyKel({ aid, events: tampered });
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe('UNSUPPORTED_FEATURE');
	});

	test('rejects a multisig signing threshold', () => {
		const { aid, events, icp } = buildKel();
		const tampered = [...events];
		tampered[0] = patchEvent(icp.signedEvent, { kt: '2' });
		const result = verifyKel({ aid, events: tampered });
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe('UNSUPPORTED_FEATURE');
	});

	test('rejects an unknown event field', () => {
		const { aid, events, icp } = buildKel();
		const tampered = [...events];
		tampered[0] = patchEvent(icp.signedEvent, { surprise: 1 });
		const result = verifyKel({ aid, events: tampered });
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error).toEqual({
			code: 'UNSUPPORTED_FEATURE',
			feature: "unknown field 'surprise'",
		});
	});

	test('rejects a malformed CESR primitive', () => {
		const { aid, events, icp } = buildKel();
		const tampered = [...events];
		tampered[0] = patchEvent(icp.signedEvent, { d: 'Z'.repeat(44) });
		const result = verifyKel({ aid, events: tampered });
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe('INVALID_CESR_CODE');
	});
});

describe('verifyKel — cryptographic and chain rejection', () => {
	test('rejects a KEL whose inception does not derive the requested AID', () => {
		const { events } = buildKel();
		const other = createInceptionEvent({
			currentKeyPair: keyPairFromSeed(fillSeed(0x11)),
			nextPublicKey: keyPairFromSeed(fillSeed(0x22)).publicKey,
		});
		const result = verifyKel({ aid: other.state.aid, events });
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe('INVALID_DID');
	});

	test('rejects a tampered event (digest mismatch)', () => {
		const { aid, events, ixn1 } = buildKel();
		const tampered = [...events];
		tampered[1] = patchEvent(ixn1.signedEvent, { a: [{ kind: 'forged' }] });
		const result = verifyKel({ aid, events: tampered });
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe('INVALID_EVENT_DIGEST');
	});

	test('rejects a tampered signature', () => {
		const { aid, events, icp, ixn1 } = buildKel();
		const tampered = [...events];
		// Swap in the inception's signature: well-formed CESR, wrong key.
		tampered[1] = {
			event: ixn1.signedEvent.event,
			signatures: [icp.signedEvent.signatures[0]],
		};
		const result = verifyKel({ aid, events: tampered });
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe('INVALID_SIGNATURE');
	});

	test('rejects reordered events', () => {
		const { aid, events } = buildKel();
		const reordered = [...events];
		[reordered[1], reordered[2]] = [reordered[2], reordered[1]];
		const result = verifyKel({ aid, events: reordered });
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error).toEqual({
			code: 'INVALID_SEQUENCE',
			expected: 1,
			actual: 2,
		});
	});

	test('rejects a sequence gap (a dropped event)', () => {
		const { aid, events } = buildKel();
		// Drop the seq-1 interaction; the seq-2 rotation now follows inception.
		const withGap = [events[0], events[2], events[3], events[4]];
		const result = verifyKel({ aid, events: withGap });
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error).toEqual({
			code: 'INVALID_SEQUENCE',
			expected: 1,
			actual: 2,
		});
	});

	test('rejects a previous-digest mismatch', () => {
		const k0 = keyPairFromSeed(fillSeed(0xb0));
		const k1 = keyPairFromSeed(fillSeed(0xb1));
		const icp = createInceptionEvent({
			currentKeyPair: k0,
			nextPublicKey: k1.publicKey,
		});
		// Two distinct seq-1 interactions off the same state: same seq and
		// `p`, but different anchored data and therefore different SAIDs.
		const ixn1 = createInteractionEvent({
			state: icp.state,
			currentKeyPair: k0,
			data: [{ v: 1 }],
		});
		const ixn1alt = createInteractionEvent({
			state: icp.state,
			currentKeyPair: k0,
			data: [{ v: 2 }],
		});
		// ixn2 chains onto ixn1, but we splice in ixn1alt instead.
		const ixn2 = createInteractionEvent({
			state: ixn1.state,
			currentKeyPair: k0,
			data: [{ v: 3 }],
		});
		const result = verifyKel({
			aid: icp.state.aid,
			events: [icp.signedEvent, ixn1alt.signedEvent, ixn2.signedEvent],
		});
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe('INVALID_PREVIOUS_DIGEST');
	});

	test('rejects a rotation revealing a key outside the prior commitment', () => {
		const k0 = keyPairFromSeed(fillSeed(0xc0));
		const k1 = keyPairFromSeed(fillSeed(0xc1));
		const icp = createInceptionEvent({
			currentKeyPair: k0,
			nextPublicKey: k1.publicKey,
		});

		// Hand-build a rotation that discloses k9 — never committed by icp.
		const k9 = keyPairFromSeed(fillSeed(0xc9));
		const k3 = keyPairFromSeed(fillSeed(0xc3));
		const partial = {
			t: 'rot' as const,
			i: icp.state.aid,
			s: '1',
			p: icp.state.lastEventDigest,
			kt: '1' as const,
			k: [encodePublicKeyEd25519(k9.publicKey.raw)] as const,
			nt: '1' as const,
			n: [deriveNextKeyCommitment(k3.publicKey)] as const,
			bt: '0' as const,
			br: [] as const,
			ba: [] as const,
			a: [] as const,
		};
		const { said, versionString } = computeEventSaid(partial, ['d']);
		const rotEvent = {
			v: versionString,
			t: 'rot',
			d: said,
			i: icp.state.aid,
			s: '1',
			p: icp.state.lastEventDigest,
			kt: '1',
			k: partial.k,
			nt: '1',
			n: partial.n,
			bt: '0',
			br: [],
			ba: [],
			a: [],
		} as unknown as RotationEvent;
		const forgedRotation = signEvent(rotEvent, k9.privateKey);

		const result = verifyKel({
			aid: icp.state.aid,
			events: [icp.signedEvent, forgedRotation],
		});
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe('INVALID_NEXT_KEY_COMMITMENT');
	});

	test('rejects a tampered inception event (digest mismatch)', () => {
		const { aid, events, icp } = buildKel();
		const other = keyPairFromSeed(fillSeed(0x5e));
		const tampered = [...events];
		// A well-formed but different signing key — passes shape validation,
		// fails the recomputed SAID.
		tampered[0] = patchEvent(icp.signedEvent, {
			k: [encodePublicKeyEd25519(other.publicKey.raw)],
		});
		const result = verifyKel({ aid, events: tampered });
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe('INVALID_EVENT_DIGEST');
	});

	test('rejects a tampered rotation event (digest mismatch)', () => {
		const { aid, events, rot1 } = buildKel();
		const other = keyPairFromSeed(fillSeed(0x5f));
		const tampered = [...events];
		tampered[2] = patchEvent(rot1.signedEvent, {
			n: [deriveNextKeyCommitment(other.publicKey)],
		});
		const result = verifyKel({ aid, events: tampered });
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe('INVALID_EVENT_DIGEST');
	});

	test('rejects an inception event with a non-zero sequence number', () => {
		const k0 = keyPairFromSeed(fillSeed(0xe0));
		const k1 = keyPairFromSeed(fillSeed(0xe1));
		// Hand-build an inception whose `s` is 1: a self-consistent SAID, so
		// the digest check passes and the sequence check is what rejects it.
		const partial = {
			t: 'icp' as const,
			s: '1',
			kt: '1' as const,
			k: [encodePublicKeyEd25519(k0.publicKey.raw)] as const,
			nt: '1' as const,
			n: [deriveNextKeyCommitment(k1.publicKey)] as const,
			bt: '0' as const,
			b: [] as const,
			c: [] as const,
			a: [] as const,
		};
		const { said, versionString } = computeEventSaid(partial, ['d', 'i']);
		const icpEvent = {
			v: versionString,
			t: 'icp',
			d: said,
			i: said,
			s: '1',
			kt: '1',
			k: partial.k,
			nt: '1',
			n: partial.n,
			bt: '0',
			b: [],
			c: [],
			a: [],
		} as unknown as InceptionEvent;
		const signed = signEvent(icpEvent, k0.privateKey);

		const result = verifyKel({ aid: aidFromSaid(said), events: [signed] });
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error).toEqual({
			code: 'INVALID_SEQUENCE',
			expected: 0,
			actual: 1,
		});
	});

	test('rejects a rotation revealing the committed key but signed by another', () => {
		const k0 = keyPairFromSeed(fillSeed(0xf0));
		const k1 = keyPairFromSeed(fillSeed(0xf1));
		const k2 = keyPairFromSeed(fillSeed(0xf2));
		const kWrong = keyPairFromSeed(fillSeed(0xfe));
		const icp = createInceptionEvent({
			currentKeyPair: k0,
			nextPublicKey: k1.publicKey,
		});

		// The rotation discloses k1 — exactly the key icp committed to — so the
		// next-key commitment check passes; only the signature is wrong.
		const partial = {
			t: 'rot' as const,
			i: icp.state.aid,
			s: '1',
			p: icp.state.lastEventDigest,
			kt: '1' as const,
			k: [encodePublicKeyEd25519(k1.publicKey.raw)] as const,
			nt: '1' as const,
			n: [deriveNextKeyCommitment(k2.publicKey)] as const,
			bt: '0' as const,
			br: [] as const,
			ba: [] as const,
			a: [] as const,
		};
		const { said, versionString } = computeEventSaid(partial, ['d']);
		const rotEvent = {
			v: versionString,
			t: 'rot',
			d: said,
			i: icp.state.aid,
			s: '1',
			p: icp.state.lastEventDigest,
			kt: '1',
			k: partial.k,
			nt: '1',
			n: partial.n,
			bt: '0',
			br: [],
			ba: [],
			a: [],
		} as unknown as RotationEvent;
		const signed = signEvent(rotEvent, kWrong.privateKey);

		const result = verifyKel({
			aid: icp.state.aid,
			events: [icp.signedEvent, signed],
		});
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe('INVALID_SIGNATURE');
	});

	test('rejects an interaction signed by a superseded key', () => {
		const { aid, events, rot1, keys } = buildKel();
		// After rot1 the authoritative key is k1; build a seq-3 interaction
		// off rot1's state but sign it with the now-retired k0.
		const partial = {
			t: 'ixn' as const,
			i: aid,
			s: '3',
			p: rot1.state.lastEventDigest,
			a: [{ kind: 'stale' }] as const,
		};
		const { said, versionString } = computeEventSaid(partial, ['d']);
		const ixnEvent = {
			v: versionString,
			t: 'ixn',
			d: said,
			i: aid,
			s: '3',
			p: rot1.state.lastEventDigest,
			a: partial.a,
		} as unknown as InteractionEvent;
		const staleIxn = signEvent(ixnEvent, keys.k0.privateKey);

		const result = verifyKel({
			aid,
			events: [events[0], events[1], events[2], staleIxn],
		});
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe('INVALID_SIGNATURE');
	});

	test('rejects a rotation whose `i` does not match the KEL AID', () => {
		const k0 = keyPairFromSeed(fillSeed(0xd0));
		const k1 = keyPairFromSeed(fillSeed(0xd1));
		const k2 = keyPairFromSeed(fillSeed(0xd2));
		const icp = createInceptionEvent({
			currentKeyPair: k0,
			nextPublicKey: k1.publicKey,
		});
		// A foreign AID — a valid CESR digest, but not this KEL's identifier.
		const foreign = createInceptionEvent({
			currentKeyPair: keyPairFromSeed(fillSeed(0xde)),
			nextPublicKey: keyPairFromSeed(fillSeed(0xdf)).publicKey,
		});

		const partial = {
			t: 'rot' as const,
			i: foreign.state.aid,
			s: '1',
			p: icp.state.lastEventDigest,
			kt: '1' as const,
			k: [encodePublicKeyEd25519(k1.publicKey.raw)] as const,
			nt: '1' as const,
			n: [deriveNextKeyCommitment(k2.publicKey)] as const,
			bt: '0' as const,
			br: [] as const,
			ba: [] as const,
			a: [] as const,
		};
		const { said, versionString } = computeEventSaid(partial, ['d']);
		const rotEvent = {
			v: versionString,
			t: 'rot',
			d: said,
			i: foreign.state.aid,
			s: '1',
			p: icp.state.lastEventDigest,
			kt: '1',
			k: partial.k,
			nt: '1',
			n: partial.n,
			bt: '0',
			br: [],
			ba: [],
			a: [],
		} as unknown as RotationEvent;
		const signed = signEvent(rotEvent, k1.privateKey);

		const result = verifyKel({
			aid: icp.state.aid,
			events: [icp.signedEvent, signed],
		});
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe('INVALID_DID');
	});

	test('rejects an interaction whose `i` does not match the KEL AID', () => {
		const k0 = keyPairFromSeed(fillSeed(0xd5));
		const k1 = keyPairFromSeed(fillSeed(0xd6));
		const icp = createInceptionEvent({
			currentKeyPair: k0,
			nextPublicKey: k1.publicKey,
		});
		const foreign = createInceptionEvent({
			currentKeyPair: keyPairFromSeed(fillSeed(0xea)),
			nextPublicKey: keyPairFromSeed(fillSeed(0xeb)).publicKey,
		});

		const partial = {
			t: 'ixn' as const,
			i: foreign.state.aid,
			s: '1',
			p: icp.state.lastEventDigest,
			a: [] as const,
		};
		const { said, versionString } = computeEventSaid(partial, ['d']);
		const ixnEvent = {
			v: versionString,
			t: 'ixn',
			d: said,
			i: foreign.state.aid,
			s: '1',
			p: icp.state.lastEventDigest,
			a: [],
		} as unknown as InteractionEvent;
		const signed = signEvent(ixnEvent, k0.privateKey);

		const result = verifyKel({
			aid: icp.state.aid,
			events: [icp.signedEvent, signed],
		});
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe('INVALID_DID');
	});
});

describe('verifyKel — argument contract', () => {
	test('throws on a non-array events argument', () => {
		const { aid } = buildKel();
		expect(() =>
			verifyKel({ aid, events: 'not an array' as never })
		).toThrow(InvalidArgumentError);
	});

	test('throws on a missing aid', () => {
		const { events } = buildKel();
		expect(() =>
			verifyKel({ aid: '' as never, events })
		).toThrow(InvalidArgumentError);
	});
});
