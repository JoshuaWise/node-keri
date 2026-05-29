import { base64urlEncode } from '../src/bytes/base64url';
import { keyPairFromSeed } from '../src/crypto/keypair';
import { createInceptionEvent } from '../src/event/inception';
import { createInteractionEvent } from '../src/event/interaction';
import { createRotationEvent } from '../src/event/rotation';
import { parseSignedEvent } from '../src/event/stream';
import { SignedKeriEvent } from '../src/event/types';
import { DID_KERI_PREFIX, formatDidKeri, parseDidKeri } from '../src/did/did-keri';
import { createDidDocument } from '../src/did/document';
import { resolveDid } from '../src/did/resolver';
import { verifyKel } from '../src/api/verify-kel';
import { InvalidArgumentError } from '../src/profile/errors';
import { frameKel } from './kel-stream';

function fillSeed(byte: number): Uint8Array {
	return new Uint8Array(32).fill(byte);
}

/** Build an icp, ixn, rot KEL (seq 0..2). Latest signing key is k1. */
function buildKel() {
	const k0 = keyPairFromSeed(fillSeed(0x10));
	const k1 = keyPairFromSeed(fillSeed(0x11));
	const k2 = keyPairFromSeed(fillSeed(0x12));

	const icp = createInceptionEvent({
		currentKeyPair: k0,
		nextPublicKey: k1.publicKey,
	});
	const ixn = createInteractionEvent({
		state: icp.state,
		currentKeyPair: k0,
		data: [{ kind: 'announce' }],
	});
	const rot = createRotationEvent({
		state: ixn.state,
		newCurrentKeyPair: k1,
		nextPublicKey: k2.publicKey,
	});

	// The constructors return wire-form frames; a KEL is those concatenated.
	const frames = [icp.event, ixn.event, rot.event];
	const events: SignedKeriEvent[] = frames.map(parseSignedEvent);
	return {
		aid: icp.state.aid,
		did: icp.state.did,
		events,
		kel: frames.join(''),
		keys: { k0, k1, k2 },
	};
}

describe('parseDidKeri', () => {
	test('parses a well-formed did:keri DID into its components', () => {
		const { did, aid } = buildKel();
		const parsed = parseDidKeri(did);
		expect(parsed.did).toBe(did);
		expect(parsed.method).toBe('keri');
		expect(parsed.aid).toBe(aid);
	});

	test('round-trips with formatDidKeri', () => {
		const { aid } = buildKel();
		expect(parseDidKeri(formatDidKeri(aid)).aid).toBe(aid);
	});

	test('reports transferable for a digest AID, non-transferable for a B-key AID', () => {
		const { did } = buildKel();
		// node-keri mints transferable, self-addressing AIDs: a digest.
		expect(parseDidKeri(did).transferable).toBe(true);

		// A non-transferable AID is a `B`-coded Ed25519 key (44 chars). The
		// all-zero key is a valid one; node-keri verifies these but the parser
		// is what first recognizes the kind.
		const ntAid = 'B' + 'A'.repeat(43);
		const parsed = parseDidKeri(`${DID_KERI_PREFIX}${ntAid}`);
		expect(parsed.transferable).toBe(false);
		expect(parsed.aid).toBe(ntAid);
	});

	test('rejects a non-string argument', () => {
		expect(() => parseDidKeri(undefined as never)).toThrow(InvalidArgumentError);
	});

	test('rejects a DID without the did:keri prefix', () => {
		const { aid } = buildKel();
		expect(() => parseDidKeri(`did:web:${aid}`)).toThrow(InvalidArgumentError);
	});

	test('rejects a DID missing its method-specific identifier', () => {
		expect(() => parseDidKeri(DID_KERI_PREFIX)).toThrow(InvalidArgumentError);
	});

	test('rejects DID-URL path, query, and fragment components', () => {
		const { did } = buildKel();
		expect(() => parseDidKeri(`${did}/path`)).toThrow(InvalidArgumentError);
		expect(() => parseDidKeri(`${did}?q=1`)).toThrow(InvalidArgumentError);
		expect(() => parseDidKeri(`${did}#key-0`)).toThrow(InvalidArgumentError);
	});

	test('rejects an identifier that is not a valid CESR AID', () => {
		expect(() => parseDidKeri(`${DID_KERI_PREFIX}not-a-real-aid`)).toThrow(
			InvalidArgumentError
		);
		// Right length, wrong derivation code.
		expect(() => parseDidKeri(`${DID_KERI_PREFIX}${'Z'.repeat(44)}`)).toThrow(
			InvalidArgumentError
		);
	});
});

describe('createDidDocument', () => {
	test('projects a verified state into a minimal DID document', () => {
		const { aid, did, kel, keys } = buildKel();
		const result = verifyKel({ aid, kel });
		expect(result.ok).toBe(true);
		if (!result.ok) return;

		const doc = createDidDocument({ state: result.state });
		const keyId = `${did}#key-0`;
		expect(doc).toEqual({
			'@context': [
				'https://www.w3.org/ns/did/v1',
				'https://w3id.org/security/suites/jws-2020/v1',
			],
			id: did,
			verificationMethod: [
				{
					id: keyId,
					type: 'JsonWebKey2020',
					controller: did,
					publicKeyJwk: {
						kty: 'OKP',
						crv: 'Ed25519',
						// After icp, ixn, rot the authoritative key is k1; the JWK
						// `x` is its raw public key, base64url-encoded.
						x: base64urlEncode(keys.k1.publicKey.raw),
					},
				},
			],
			authentication: [keyId],
			assertionMethod: [keyId],
		});
		expect(doc.service).toBeUndefined();
	});

	test('reflects the latest signing key after rotation', () => {
		const { aid, kel, keys } = buildKel();
		const result = verifyKel({ aid, kel });
		if (!result.ok) throw new Error('expected a valid KEL');

		const doc = createDidDocument({ state: result.state });
		// After the rotation the authoritative key is k1, not the inception k0.
		expect(doc.verificationMethod[0]!.publicKeyJwk.x).toBe(
			base64urlEncode(keys.k1.publicKey.raw)
		);
		expect(doc.verificationMethod[0]!.publicKeyJwk.x).not.toBe(
			base64urlEncode(keys.k0.publicKey.raw)
		);
	});

	test('includes and normalizes caller-supplied services', () => {
		const { aid, did, kel } = buildKel();
		const result = verifyKel({ aid, kel });
		if (!result.ok) throw new Error('expected a valid KEL');

		const doc = createDidDocument({
			state: result.state,
			services: [
				{
					id: '#agent',
					type: 'AgentService',
					serviceEndpoint: 'https://agent.example/keri',
				},
			],
		});
		expect(doc.service).toEqual([
			{
				id: `${did}#agent`,
				type: 'AgentService',
				serviceEndpoint: 'https://agent.example/keri',
			},
		]);
	});

	test('accepts a matching `did` and rejects a mismatched one', () => {
		const { aid, did, kel } = buildKel();
		const result = verifyKel({ aid, kel });
		if (!result.ok) throw new Error('expected a valid KEL');

		expect(() => createDidDocument({ state: result.state, did })).not.toThrow();
		expect(() =>
			createDidDocument({
				state: result.state,
				did: 'did:keri:other' as never,
			})
		).toThrow(InvalidArgumentError);
	});

	test('rejects a malformed service entry', () => {
		const { aid, kel } = buildKel();
		const result = verifyKel({ aid, kel });
		if (!result.ok) throw new Error('expected a valid KEL');

		expect(() =>
			createDidDocument({
				state: result.state,
				services: [{ id: '', type: 'X', serviceEndpoint: 'x' } as never],
			})
		).toThrow(InvalidArgumentError);
	});

	test('rejects an input that is not a verified state', () => {
		expect(() => createDidDocument({ state: {} as never })).toThrow(
			InvalidArgumentError
		);
	});
});

describe('resolveDid', () => {
	test('resolves a valid DID + KEL to a DID document and verified state', () => {
		const { did, kel } = buildKel();
		const result = resolveDid({ did, kel });
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.didDocument.id).toBe(did);
		// Three events (icp + 2 more) ⇒ the last is at sequence number 2.
		expect(result.state.lastSequenceNumber).toBe(2);
	});

	test('returns INVALID_DID for a malformed DID rather than throwing', () => {
		const { kel } = buildKel();
		const result = resolveDid({
			did: 'did:keri:not-a-real-aid' as never,
			kel,
		});
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe('INVALID_DID');
	});

	test('propagates a verification error for a tampered KEL', () => {
		const { did, events } = buildKel();
		const tampered: SignedKeriEvent[] = [...events];
		tampered[1] = {
			event: {
				...events[1]!.event,
				a: [{ kind: 'forged' }],
			} as SignedKeriEvent['event'],
			signatures: events[1]!.signatures,
		};
		const result = resolveDid({ did, kel: frameKel(tampered) });
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe('INVALID_EVENT_DIGEST');
	});

	test('returns a verification error when the KEL is for another identifier', () => {
		const { kel } = buildKel();
		const other = createInceptionEvent({
			currentKeyPair: keyPairFromSeed(fillSeed(0x90)),
			nextPublicKey: keyPairFromSeed(fillSeed(0x91)).publicKey,
		});
		const result = resolveDid({ did: other.state.did, kel });
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe('INVALID_DID');
	});

	test('rejects an empty KEL for a transferable DID', () => {
		const { did } = buildKel();
		const result = resolveDid({ did, kel: '' });
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error).toEqual({ code: 'EMPTY_KEL' });
	});

	test('resolves a bare non-transferable DID with the empty-string "no KEL" value', () => {
		// A non-transferable AID is a `B`-coded Ed25519 key — self-certifying,
		// so it resolves with no KEL. The all-zero key is a valid one.
		const ntAid = 'B' + 'A'.repeat(43);
		const ntDid = `${DID_KERI_PREFIX}${ntAid}`;
		const result = resolveDid({
			did: ntDid as never,
			kel: '',
		});
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.didDocument.id).toBe(ntDid);
		expect(result.didDocument.verificationMethod).toHaveLength(1);
		expect(result.state.transferable).toBe(false);
		expect(result.state.aid).toBe(ntAid);
		expect(result.state.deactivated).toBe(false);
		if (!result.state.deactivated) {
			// A non-transferable AID *is* its own signing key.
			expect(result.state.currentPublicKey).toBe(ntAid);
		}
		// Resolved bare from the prefix, with no KEL: there are no event-derived
		// fields, which is what tells a bare AID apart from one verified from a
		// single-event KEL (both report sequenceNumber 0).
		expect(result.state.lastEventDigest).toBeUndefined();
		expect(result.state.lastEventType).toBeUndefined();
	});

	test('throws on an argument-contract violation', () => {
		const { did } = buildKel();
		expect(() => resolveDid({ did, kel: 123 as never })).toThrow(
			InvalidArgumentError
		);
	});
});
