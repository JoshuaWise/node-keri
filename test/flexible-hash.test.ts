/**
 * Integration tests for algorithm-flexible digesting.
 *
 * Exercises the whole chain: CESR encode/decode of 256- and 512-bit digest
 * codes, generating identifiers and events under a chosen algorithm, replaying
 * KELs that mix algorithms across events, `did:keri` parsing of non-SHA-256
 * AIDs, and the monkey-patch path that adds an algorithm node-keri does not
 * ship (standing in for Blake3-256).
 */

import { createIdentifier } from '../src/api/create-identifier';
import { rotateIdentifier } from '../src/api/rotate-identifier';
import { interactIdentifier } from '../src/api/interact-identifier';
import { verifyKel } from '../src/api/verify-kel';
import { verifySignatureWithDid } from '../src/api/verify-signature-with-did';
import { createDidDocument } from '../src/did/document';
import { resolveDid } from '../src/did/resolver';
import { decodeDigest, decodeDigestSha256 } from '../src/cesr/decode';
import {
	encodeDigest,
	encodePublicKeyEd25519,
	encodeSignatureEd25519,
} from '../src/cesr/encode';
import {
	DIGEST_CODES,
	DigestAlgorithm,
	digestAlgorithms,
	isRegisteredDigestCode,
} from '../src/crypto/digests';
import { sha256 } from '../src/crypto/hash';
import { sign } from '../src/crypto/ed25519';
import { keyPairFromSeed } from '../src/crypto/keypair';
import { parseDidKeri } from '../src/did/did-keri';
import type { Aid } from '../src/did/did-keri';
import { parseSignedEvent } from '../src/event/stream';
import { utf8Encode } from '../src/bytes/utf8';
import type { SignedKeriEvent } from '../src/event/types';
import type { CesrSignature } from '../src/cesr/qualified';
import {
	InvalidArgumentError,
	MalformedInputError,
	UnsupportedAlgorithmError,
} from '../src/profile/errors';
import { frameKel } from './kel-stream';

function fillSeed(byte: number): Uint8Array {
	return new Uint8Array(32).fill(byte);
}

/** Restore the digest registry after any test that monkey-patches it. */
let snapshot: Record<string, DigestAlgorithm | undefined>;
beforeEach(() => {
	snapshot = {};
	for (const c of Object.keys(digestAlgorithms)) snapshot[c] = digestAlgorithms[c];
});
afterEach(() => {
	// `digestAlgorithms` is sealed: clear entries by reassigning `undefined`
	// (not `delete`), then restore them from the snapshot.
	for (const c of Object.keys(digestAlgorithms)) digestAlgorithms[c] = undefined;
	for (const c of Object.keys(snapshot)) digestAlgorithms[c] = snapshot[c];
});

/** Native codes that are registered in this runtime, with their qb64 length. */
const AVAILABLE: ReadonlyArray<{ code: string; qb64Length: number }> = [
	{ code: DIGEST_CODES.SHA2_256, qb64Length: 44 },
	{ code: DIGEST_CODES.SHA2_512, qb64Length: 88 },
	{ code: DIGEST_CODES.SHA3_256, qb64Length: 44 },
	{ code: DIGEST_CODES.SHA3_512, qb64Length: 88 },
	{ code: DIGEST_CODES.BLAKE2S_256, qb64Length: 44 },
	{ code: DIGEST_CODES.BLAKE2B_512, qb64Length: 88 },
].filter((d) => isRegisteredDigestCode(d.code));

describe('CESR — encode/decode of flexible digest codes', () => {
	test('round-trips raw bytes through every registered digest code', () => {
		for (const { code, qb64Length } of AVAILABLE) {
			const rawSize = qb64Length === 44 ? 32 : 64;
			const raw = new Uint8Array(rawSize);
			for (let i = 0; i < rawSize; i++) raw[i] = (i * 7 + 3) & 0xff;

			const qb64 = encodeDigest(code, raw);
			expect(qb64.length).toBe(qb64Length);
			expect(qb64.startsWith(code)).toBe(true);

			const decoded = decodeDigest(qb64);
			expect(decoded.code).toBe(code);
			expect(Array.from(decoded.raw)).toEqual(Array.from(raw));
		}
	});

	test('encodeDigest rejects a raw payload of the wrong length', () => {
		// `I` is 256-bit: 64 raw bytes is invalid; `0G` is 512-bit: 32 is invalid.
		expect(() => encodeDigest('I', new Uint8Array(64))).toThrow(InvalidArgumentError);
		expect(() => encodeDigest('0G', new Uint8Array(32))).toThrow(
			InvalidArgumentError
		);
	});

	test('encodeDigest rejects a structurally invalid code', () => {
		expect(() => encodeDigest('XYZ', new Uint8Array(32))).toThrow(
			UnsupportedAlgorithmError
		);
	});

	test('decodeDigest rejects an unregistered (but well-formed) code', () => {
		// `E` is the conventional Blake3-256 code — no native implementation.
		expect(() => decodeDigest('E' + 'A'.repeat(43))).toThrow(MalformedInputError);
	});

	test('decodeDigest rejects an unknown code and a wrong length', () => {
		expect(() => decodeDigest('Z' + 'A'.repeat(43))).toThrow(MalformedInputError);
		expect(() => decodeDigest('I' + 'A'.repeat(10))).toThrow(MalformedInputError);
	});

	test('decodeDigestSha256 stays strict — only code `I`', () => {
		const sha3 = encodeDigest('H', new Uint8Array(32));
		expect(() => decodeDigestSha256(sha3)).toThrow(MalformedInputError);
	});
});

describe('generation under a chosen digest algorithm', () => {
	test('a SHA3-256 identifier is 44 chars and verifies', () => {
		const id = createIdentifier({
			currentPrivateKey: keyPairFromSeed(fillSeed(0x10)).privateKey,
			nextPublicKey: keyPairFromSeed(fillSeed(0x11)).publicKey,
			digestCode: DIGEST_CODES.SHA3_256,
		});
		expect(id.aid.startsWith('H')).toBe(true);
		expect(id.aid.length).toBe(44);
		// For inception the AID *is* the SAID.
		const inception = parseSignedEvent(id.inceptionEvent);
		expect(inception.event.d).toBe(id.aid);
		expect(decodeDigest(inception.event.d).code).toBe('H');

		const result = verifyKel({ aid: id.aid, kel: id.inceptionEvent });
		expect(result.ok).toBe(true);
		if (result.ok) expect(result.state.aid).toBe(id.aid);
	});

	test('a SHA2-512 identifier produces an 88-char AID that parses and verifies', () => {
		const id = createIdentifier({
			currentPrivateKey: keyPairFromSeed(fillSeed(0x12)).privateKey,
			nextPublicKey: keyPairFromSeed(fillSeed(0x13)).publicKey,
			digestCode: DIGEST_CODES.SHA2_512,
		});
		expect(id.aid.startsWith('0G')).toBe(true);
		expect(id.aid.length).toBe(88);

		// The 88-char AID parses under the strict offline did:keri grammar.
		const parsed = parseDidKeri(id.did);
		expect(parsed.aid).toBe(id.aid);

		const result = verifyKel({ aid: id.aid, kel: id.inceptionEvent });
		expect(result.ok).toBe(true);
	});

	test('requesting an unavailable algorithm throws', () => {
		expect(() =>
			createIdentifier({
				currentPrivateKey: keyPairFromSeed(fillSeed(0x14)).privateKey,
				nextPublicKey: keyPairFromSeed(fillSeed(0x15)).publicKey,
				digestCode: DIGEST_CODES.BLAKE3_256, // `E` — not registered
			})
		).toThrow(UnsupportedAlgorithmError);
	});

	test('the default (no digestCode) stays SHA-256', () => {
		const id = createIdentifier({
			currentPrivateKey: keyPairFromSeed(fillSeed(0x16)).privateKey,
			nextPublicKey: keyPairFromSeed(fillSeed(0x17)).publicKey,
		});
		expect(id.aid.startsWith('I')).toBe(true);
		expect(decodeDigest(id.aid).code).toBe('I');
	});
});

describe('a KEL that mixes digest algorithms across events', () => {
	/** icp(SHA-256) → ixn(SHA3-256) → rot(SHA2-512) → ixn(BLAKE2b-512) → rot(SHA3-512). */
	function buildMixedKel() {
		const k0 = keyPairFromSeed(fillSeed(0x30));
		const k1 = keyPairFromSeed(fillSeed(0x31));
		const k2 = keyPairFromSeed(fillSeed(0x32));
		const k3 = keyPairFromSeed(fillSeed(0x33));

		const icp = createIdentifier({
			currentPrivateKey: k0.privateKey,
			nextPublicKey: k1.publicKey,
		});
		const ixn1 = interactIdentifier({
			state: icp.state,
			currentPrivateKey: k0.privateKey,
			data: [{ step: 1 }],
			digestCode: DIGEST_CODES.SHA3_256,
		});
		const rot1 = rotateIdentifier({
			state: ixn1.state,
			currentPrivateKey: k1.privateKey,
			nextPublicKey: k2.publicKey,
			digestCode: DIGEST_CODES.SHA2_512,
		});
		const ixn2 = interactIdentifier({
			state: rot1.state,
			currentPrivateKey: k1.privateKey,
			data: [{ step: 2 }],
			digestCode: DIGEST_CODES.BLAKE2B_512,
		});
		const rot2 = rotateIdentifier({
			state: ixn2.state,
			currentPrivateKey: k2.privateKey,
			nextPublicKey: k3.publicKey,
			digestCode: DIGEST_CODES.SHA3_512,
		});

		// The constructors return wire-form frames; the KEL is them concatenated.
		const frames = [
			icp.inceptionEvent,
			ixn1.interactionEvent,
			rot1.rotationEvent,
			ixn2.interactionEvent,
			rot2.rotationEvent,
		];
		const events: SignedKeriEvent[] = frames.map(parseSignedEvent);
		return {
			aid: icp.aid,
			did: icp.did,
			events,
			kel: frames.join(''),
			keys: { k0, k1, k2 },
		};
	}

	test('each event carries the digest code it was generated with', () => {
		const { events } = buildMixedKel();
		expect(events.map((e) => decodeDigest(e.event.d).code)).toEqual([
			'I',
			'H',
			'0G',
			'0F',
			'0E',
		]);
	});

	test('verifyKel replays the mixed-algorithm KEL and reconstructs state', () => {
		const { aid, events, kel, keys } = buildMixedKel();
		const result = verifyKel({ aid, kel });
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.state.sequenceNumber).toBe(4);
		expect(result.state.lastEventDigest).toBe(events[4]!.event.d);
		// The final rotation revealed k2, so it is the current key.
		expect(result.state.currentPublicKey).toBe(
			encodePublicKeyEd25519(keys.k2.publicKey.raw)
		);
	});

	test('tampering one event of the mixed KEL is still rejected', () => {
		const { aid, events } = buildMixedKel();
		const tampered = events.slice();
		// Forge the SHA3-256 interaction's anchored data.
		tampered[1] = {
			event: {
				...events[1]!.event,
				a: [{ step: 999 }],
			} as SignedKeriEvent['event'],
			signatures: events[1]!.signatures,
		};
		const result = verifyKel({ aid, kel: frameKel(tampered) });
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.error.code).toBe('INVALID_EVENT_DIGEST');
	});

	test('a message verifies under a mixed-algorithm identifier', () => {
		const { did, kel, keys } = buildMixedKel();
		const payload = utf8Encode('signed by the post-rotation key');
		// After the KEL the authoritative key is k2.
		const signature = encodeSignatureEd25519(sign(keys.k2.privateKey, payload));
		const ok = verifySignatureWithDid({
			did,
			kel,
			payload,
			signature: signature as CesrSignature,
		});
		expect(ok).toBe(true);
	});
});

describe('did:keri parsing across algorithms', () => {
	test('rejects an AID under an unregistered digest code', () => {
		// A well-formed 44-char `E` (Blake3) digest — but no implementation.
		expect(() => parseDidKeri('did:keri:E' + 'A'.repeat(43))).toThrow(
			InvalidArgumentError
		);
	});
});

describe('monkey-patching a non-native algorithm end to end', () => {
	// A deterministic 32-byte stand-in for Blake3-256, registered under `E`.
	const blake3Stub = (input: Uint8Array): Uint8Array => sha256(sha256(input));

	test('a registered custom algorithm works for generation and verification', () => {
		digestAlgorithms['E'] = { name: 'Blake3-256 (stub)', hash: blake3Stub };

		const id = createIdentifier({
			currentPrivateKey: keyPairFromSeed(fillSeed(0x40)).privateKey,
			nextPublicKey: keyPairFromSeed(fillSeed(0x41)).publicKey,
			digestCode: 'E',
		});
		expect(id.aid.startsWith('E')).toBe(true);
		expect(decodeDigest(id.aid).code).toBe('E');

		const result = verifyKel({ aid: id.aid, kel: id.inceptionEvent });
		expect(result.ok).toBe(true);

		// The custom-algorithm DID now parses too.
		expect(parseDidKeri(id.did).aid).toBe(id.aid);
	});

	test('a KEL using a now-unregistered algorithm fails closed', () => {
		// Build the KEL while `E` is registered...
		digestAlgorithms['E'] = { name: 'Blake3-256 (stub)', hash: blake3Stub };
		const id = createIdentifier({
			currentPrivateKey: keyPairFromSeed(fillSeed(0x42)).privateKey,
			nextPublicKey: keyPairFromSeed(fillSeed(0x43)).publicKey,
			digestCode: 'E',
		});
		const aid = id.aid as Aid;
		const kel = id.inceptionEvent;

		// ...then drop the implementation. The KEL can no longer be verified.
		// The registry is sealed, so the entry is cleared by reassignment.
		digestAlgorithms['E'] = undefined;

		const result = verifyKel({ aid, kel });
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.error.code).toBe('INVALID_CESR_CODE');
	});

	test('a throwing registered algorithm makes verifyKel throw', () => {
		// Mint a KEL while `E` works...
		digestAlgorithms['E'] = { name: 'Blake3-256 (stub)', hash: blake3Stub };
		const id = createIdentifier({
			currentPrivateKey: keyPairFromSeed(fillSeed(0x44)).privateKey,
			nextPublicKey: keyPairFromSeed(fillSeed(0x45)).publicKey,
			digestCode: 'E',
		});
		const aid = id.aid as Aid;
		const kel = id.inceptionEvent;

		// ...then swap in an implementation that throws. The digest is still a
		// structurally valid, registered `E` digest, so shape validation passes
		// and the throw surfaces from `runDigest` during SAID recomputation. A
		// faulty registered algorithm is a programmer error, not hostile input,
		// so verifyKel does not convert it to an { ok: false } result — the
		// exception propagates unchanged.
		digestAlgorithms['E'] = {
			name: 'Blake3-256 (broken)',
			hash: () => {
				throw new Error('blake3 unavailable');
			},
		};
		expect(() => verifyKel({ aid, kel })).toThrow('blake3 unavailable');
	});
});

describe('the DID surface under a 512-bit AID', () => {
	test('createDidDocument and resolveDid handle an 88-char AID', () => {
		const id = createIdentifier({
			currentPrivateKey: keyPairFromSeed(fillSeed(0x50)).privateKey,
			nextPublicKey: keyPairFromSeed(fillSeed(0x51)).publicKey,
			digestCode: DIGEST_CODES.SHA2_512,
		});
		expect(id.aid.length).toBe(88);

		const verified = verifyKel({ aid: id.aid, kel: id.inceptionEvent });
		expect(verified.ok).toBe(true);
		if (!verified.ok) return;

		// The document projects the verified state and is algorithm-agnostic:
		// the 88-char AID flows through `id` and the verification-method ids.
		const doc = createDidDocument({ state: verified.state });
		expect(doc.id).toBe(id.did);
		expect(doc.verificationMethod[0]!.id).toBe(`${id.did}#key-0`);
		expect(doc.verificationMethod[0]!.controller).toBe(id.did);

		// Local resolution of the same DID reproduces that document.
		const resolution = resolveDid({ did: id.did, kel: id.inceptionEvent });
		expect(resolution.ok).toBe(true);
		if (resolution.ok) expect(resolution.didDocument.id).toBe(id.did);
	});
});

describe('a SAID re-encoded under a different algorithm', () => {
	test('verifyKel rejects an event whose `d` digest code was swapped', () => {
		// Build a plain SHA-256 KEL, then re-qualify the rotation's SAID bytes
		// under the SHA3-256 code without recomputing them. `digestCodeOf` now
		// reports `H`, so replay recomputes the SAID with SHA3-256 — which
		// cannot match a SHA-256 digest — and the event is rejected.
		const k0 = keyPairFromSeed(fillSeed(0x60));
		const k1 = keyPairFromSeed(fillSeed(0x61));
		const k2 = keyPairFromSeed(fillSeed(0x62));
		const icp = createIdentifier({
			currentPrivateKey: k0.privateKey,
			nextPublicKey: k1.publicKey,
		});
		const rot = rotateIdentifier({
			state: icp.state,
			currentPrivateKey: k1.privateKey,
			nextPublicKey: k2.publicKey,
		});

		const signedRot = parseSignedEvent(rot.rotationEvent);
		const { raw, code } = decodeDigest(signedRot.event.d);
		expect(code).toBe('I');
		const swapped = encodeDigest(DIGEST_CODES.SHA3_256, raw);
		const tamperedRot: SignedKeriEvent = {
			event: { ...signedRot.event, d: swapped } as SignedKeriEvent['event'],
			signatures: signedRot.signatures,
		};

		const result = verifyKel({
			aid: icp.aid,
			kel: icp.inceptionEvent + frameKel([tamperedRot]),
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.error.code).toBe('INVALID_EVENT_DIGEST');
	});
});
