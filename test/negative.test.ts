/**
 * Negative test suite for the public API.
 *
 * This consolidates the failure-mode contract of every exported entry point
 * not already covered by its own dedicated suite, plus the profile-boundary
 * checks: an event carrying any feature the KERI Direct JSON Profile excludes
 * must be rejected by `verifyIdentifier` with `UNSUPPORTED_FEATURE` — the library
 * fails closed, never silently accepting an out-of-profile event.
 */

import { createIdentifier } from '../src/api/create-identifier';
import { verifyIdentifier } from '../src/api/verify-identifier';
import { canonicalizeJson } from '../src/event/canonical-json';
import { keyPairFromPrivateKey } from '../src/crypto/keypair';
import { createDidDocument } from '../src/did/document';
import { formatDidKeri, parseDidKeri } from '../src/did/did-keri';
import { verifyDid } from '../src/did/verify-did';
import { SignedKeriEvent } from '../src/event/types';
import {
	CanonicalJsonError,
	InvalidArgumentError,
	MalformedInputError,
} from '../src/profile/errors';
import { frameKel } from './kel-stream';
import {
	parseSignedEvent,
	fillSeed,
	decodeDigestSha256,
	keyPairFromSeed,
} from './helpers/util';

/** A valid identifier reused across cases that need real material. */
function sample() {
	const currentKeyPair = keyPairFromSeed(fillSeed(0x80));
	const nextKeyPair = keyPairFromSeed(fillSeed(0x81));
	const result = createIdentifier({
		currentPrivateKey: currentKeyPair.privateKey,
		nextPublicKey: nextKeyPair.publicKey,
	});
	return { ...result, currentKeyPair, nextKeyPair };
}

/** The parsed (in-memory) inception event of a `sample()`-style identifier. */
function inceptionOf(id: ReturnType<typeof sample>): SignedKeriEvent {
	return parseSignedEvent(id.event);
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

describe('negative — verifyIdentifier argument contract', () => {
	test('throws on a non-object input', () => {
		expect(() => verifyIdentifier(null as never)).toThrow(InvalidArgumentError);
	});

	test('throws when aid is missing', () => {
		expect(() => verifyIdentifier({ kel: '' } as never)).toThrow(
			InvalidArgumentError
		);
	});

	test('throws when kel is not a string', () => {
		expect(() => verifyIdentifier({ aid: sample().aid, kel: {} as never })).toThrow(
			InvalidArgumentError
		);
	});

	test('returns EMPTY_KEL (not a throw) for an empty log', () => {
		const result = verifyIdentifier({ aid: sample().aid, kel: '' });
		expect(result.ok).toBe(false);
		if (result.ok) throw new Error('unreachable');
		expect(result.error.code).toBe('EMPTY_KEL');
	});
});

describe('negative — verifyDid', () => {
	test('throws on a non-object input', () => {
		expect(() => verifyDid(null as never)).toThrow(InvalidArgumentError);
	});

	test('throws when kel is not a string', () => {
		expect(() => verifyDid({ did: sample().did, kel: 123 as never })).toThrow(
			InvalidArgumentError
		);
	});

	test('returns INVALID_DID (not a throw) for a malformed DID', () => {
		const result = verifyDid({ did: 'did:web:x' as never, kel: '' });
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

	test('throws when services is not an array', () => {
		const id = sample();
		expect(() =>
			createDidDocument({ state: id.state, services: {} as never })
		).toThrow(InvalidArgumentError);
	});
});

describe('negative — key import', () => {
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
	// to an out-of-profile value, then asserts verifyIdentifier rejects it as an
	// unsupported feature. The shape pass runs before digest recomputation,
	// so the diagnosis is the specific UNSUPPORTED_FEATURE — not a generic
	// digest mismatch.
	function expectUnsupported(event: SignedKeriEvent, aid = sample().aid) {
		const result = verifyIdentifier({ aid, kel: frameKel([event]) });
		expect(result.ok).toBe(false);
		if (result.ok) throw new Error('unreachable');
		expect(result.error.code).toBe('UNSUPPORTED_FEATURE');
	}

	test('rejects a non-empty witness list', () => {
		const id = sample();
		expectUnsupported(patchEvent(inceptionOf(id), { b: ['DwitnessAID'] }), id.aid);
	});

	test('rejects a signing threshold other than 1', () => {
		const id = sample();
		expectUnsupported(patchEvent(inceptionOf(id), { kt: '2' }), id.aid);
	});

	test('rejects an unsupported configuration trait', () => {
		// `EO` is permitted; every other KERI trait — `DND`, `RB`, `NB`,
		// `NRB`, `DID` — is outside this profile and rejected.
		const id = sample();
		expectUnsupported(patchEvent(inceptionOf(id), { c: ['DND'] }), id.aid);
	});

	test('rejects a multisig (two-key) signing list', () => {
		const id = sample();
		const inception = inceptionOf(id);
		const key = (inception.event as { k: readonly string[] }).k[0];
		expectUnsupported(patchEvent(inception, { k: [key, key] }), id.aid);
	});

	test('rejects an unknown event field', () => {
		const id = sample();
		expectUnsupported(patchEvent(inceptionOf(id), { extra: 'x' }), id.aid);
	});

	test('rejects an event with zero signatures', () => {
		const id = sample();
		const event: SignedKeriEvent = {
			event: inceptionOf(id).event,
			signatures: [] as never,
		};
		expectUnsupported(event, id.aid);
	});

	test('rejects an event with two signatures', () => {
		const id = sample();
		const inception = inceptionOf(id);
		const event: SignedKeriEvent = {
			event: inception.event,
			signatures: [inception.signatures[0], inception.signatures[0]] as never,
		};
		expectUnsupported(event, id.aid);
	});
});
