/**
 * Negative test suite for the public API.
 *
 * This consolidates the failure-mode contract of every exported entry point
 * not already covered by its own dedicated suite, plus the profile-boundary
 * checks: an event carrying any feature the KERI Direct JSON Profile excludes
 * must be rejected by `verifyKel` with `UNSUPPORTED_FEATURE` — the library
 * fails closed, never silently accepting an out-of-profile event.
 */

import { createIdentifier } from '../src/api/create-identifier';
import { verifyKel } from '../src/api/verify-kel';
import { decodeDigestSha256 } from '../src/cesr/decode';
import { canonicalizeJson } from '../src/event/canonical-json';
import {
	exportPublicKey,
	exportPublicKeyRaw,
	keyPairFromPrivateKey,
	keyPairFromSeed,
} from '../src/crypto/keypair';
import { createDidDocument } from '../src/did/document';
import { formatDidKeri, parseDidKeri } from '../src/did/did-keri';
import { resolveDid } from '../src/did/resolver';
import { SignedKeriEvent } from '../src/event/types';
import {
	CanonicalJsonError,
	InvalidArgumentError,
	MalformedInputError,
} from '../src/profile/errors';

function fillSeed(byte: number): Uint8Array {
	return new Uint8Array(32).fill(byte);
}

/** A valid identifier reused across cases that need real material. */
function sample() {
	return createIdentifier({
		currentKeyPair: keyPairFromSeed(fillSeed(0x80)),
		nextKeyPair: keyPairFromSeed(fillSeed(0x81)),
	});
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

describe('negative — parseDidKeri', () => {
	test('rejects a non-string', () => {
		expect(() => parseDidKeri(42 as never)).toThrow(InvalidArgumentError);
	});

	test('rejects a non-keri method', () => {
		expect(() => parseDidKeri('did:web:example.com')).toThrow(InvalidArgumentError);
	});

	test('rejects an empty method-specific id', () => {
		expect(() => parseDidKeri('did:keri:')).toThrow(InvalidArgumentError);
	});

	test('rejects DID-URL path, query and fragment components', () => {
		const aid = sample().aid;
		expect(() => parseDidKeri(`did:keri:${aid}/path`)).toThrow(InvalidArgumentError);
		expect(() => parseDidKeri(`did:keri:${aid}?q=1`)).toThrow(InvalidArgumentError);
		expect(() => parseDidKeri(`did:keri:${aid}#frag`)).toThrow(InvalidArgumentError);
	});

	test('rejects an id that is not a valid AID', () => {
		expect(() => parseDidKeri('did:keri:not-a-valid-aid')).toThrow(
			InvalidArgumentError
		);
	});
});

describe('negative — formatDidKeri', () => {
	test('rejects an empty or non-string aid', () => {
		expect(() => formatDidKeri('' as never)).toThrow(InvalidArgumentError);
		expect(() => formatDidKeri(null as never)).toThrow(InvalidArgumentError);
	});
});

describe('negative — verifyKel argument contract', () => {
	test('throws on a non-object input', () => {
		expect(() => verifyKel(null as never)).toThrow(InvalidArgumentError);
	});

	test('throws when aid is missing', () => {
		expect(() => verifyKel({ events: [] } as never)).toThrow(InvalidArgumentError);
	});

	test('throws when events is not an array', () => {
		expect(() => verifyKel({ aid: sample().aid, events: {} as never })).toThrow(
			InvalidArgumentError
		);
	});

	test('returns EMPTY_KEL (not a throw) for an empty log', () => {
		const result = verifyKel({ aid: sample().aid, events: [] });
		expect(result.ok).toBe(false);
		if (result.ok) throw new Error('unreachable');
		expect(result.error.code).toBe('EMPTY_KEL');
	});
});

describe('negative — resolveDid', () => {
	test('throws on a non-object input', () => {
		expect(() => resolveDid(null as never)).toThrow(InvalidArgumentError);
	});

	test('throws when kel is not an array', () => {
		expect(() => resolveDid({ did: sample().did, kel: 'nope' as never })).toThrow(
			InvalidArgumentError
		);
	});

	test('returns INVALID_DID (not a throw) for a malformed DID', () => {
		const result = resolveDid({ did: 'did:web:x' as never, kel: [] });
		expect(result.ok).toBe(false);
		if (result.ok) throw new Error('unreachable');
		expect(result.error.code).toBe('INVALID_DID');
	});
});

describe('negative — createDidDocument', () => {
	test('throws on a non-object input', () => {
		expect(() => createDidDocument(null as never)).toThrow(InvalidArgumentError);
	});

	test('throws when state is not a verified KeriState', () => {
		expect(() => createDidDocument({ state: {} as never })).toThrow(
			InvalidArgumentError
		);
	});

	test('throws when the supplied did contradicts state.did', () => {
		const id = sample();
		expect(() =>
			createDidDocument({
				state: id.state,
				did: 'did:keri:mismatch' as never,
			})
		).toThrow(InvalidArgumentError);
	});

	test('throws when services is not an array', () => {
		const id = sample();
		expect(() =>
			createDidDocument({ state: id.state, services: {} as never })
		).toThrow(InvalidArgumentError);
	});
});

describe('negative — key export and import', () => {
	test('exportPublicKey rejects a non-public-key', () => {
		expect(() => exportPublicKey({} as never)).toThrow(InvalidArgumentError);
	});

	test('exportPublicKeyRaw rejects a non-public-key', () => {
		expect(() => exportPublicKeyRaw('nope' as never)).toThrow(InvalidArgumentError);
	});

	test('keyPairFromSeed rejects a wrong-length seed', () => {
		expect(() => keyPairFromSeed(new Uint8Array(31))).toThrow(InvalidArgumentError);
	});

	test('keyPairFromPrivateKey rejects a non-private-key', () => {
		const pub = sample().currentKeyPair.publicKey;
		expect(() => keyPairFromPrivateKey(pub as never)).toThrow(InvalidArgumentError);
	});
});

describe('negative — CESR decoding', () => {
	test('rejects an unknown derivation code', () => {
		// Right length for a digest, but the leading code is not `I`.
		expect(() => decodeDigestSha256('Z'.repeat(44))).toThrow(MalformedInputError);
	});

	test('rejects a wrong-length primitive', () => {
		expect(() => decodeDigestSha256('I' + 'A'.repeat(10))).toThrow(
			MalformedInputError
		);
	});
});

describe('negative — canonical JSON', () => {
	test('rejects NaN, Infinity, undefined and functions', () => {
		expect(() => canonicalizeJson(NaN)).toThrow(CanonicalJsonError);
		expect(() => canonicalizeJson(Infinity)).toThrow(CanonicalJsonError);
		expect(() => canonicalizeJson(undefined)).toThrow(CanonicalJsonError);
		expect(() => canonicalizeJson(() => 0)).toThrow(CanonicalJsonError);
	});
});

describe('negative — profile boundary fails closed', () => {
	// Each case patches a single field of an otherwise-valid inception event
	// to an out-of-profile value, then asserts verifyKel rejects it as an
	// unsupported feature. The shape pass runs before digest recomputation,
	// so the diagnosis is the specific UNSUPPORTED_FEATURE — not a generic
	// digest mismatch.
	function expectUnsupported(event: SignedKeriEvent, aid = sample().aid) {
		const result = verifyKel({ aid, events: [event] });
		expect(result.ok).toBe(false);
		if (result.ok) throw new Error('unreachable');
		expect(result.error.code).toBe('UNSUPPORTED_FEATURE');
	}

	test('rejects a non-empty witness list', () => {
		const id = sample();
		expectUnsupported(patchEvent(id.inceptionEvent, { b: ['DwitnessAID'] }), id.aid);
	});

	test('rejects a signing threshold other than 1', () => {
		const id = sample();
		expectUnsupported(patchEvent(id.inceptionEvent, { kt: '2' }), id.aid);
	});

	test('rejects a non-empty configuration trait list', () => {
		const id = sample();
		expectUnsupported(patchEvent(id.inceptionEvent, { c: ['EO'] }), id.aid);
	});

	test('rejects a multisig (two-key) signing list', () => {
		const id = sample();
		const key = (id.inceptionEvent.event as { k: readonly string[] }).k[0];
		expectUnsupported(patchEvent(id.inceptionEvent, { k: [key, key] }), id.aid);
	});

	test('rejects an unknown event field', () => {
		const id = sample();
		expectUnsupported(patchEvent(id.inceptionEvent, { extra: 'x' }), id.aid);
	});

	test('rejects an event with zero signatures', () => {
		const id = sample();
		const event: SignedKeriEvent = {
			event: id.inceptionEvent.event,
			signatures: [] as never,
		};
		expectUnsupported(event, id.aid);
	});

	test('rejects an event with two signatures', () => {
		const id = sample();
		const sig = id.inceptionEvent.signatures[0];
		const event: SignedKeriEvent = {
			event: id.inceptionEvent.event,
			signatures: [sig, sig] as never,
		};
		expectUnsupported(event, id.aid);
	});
});
