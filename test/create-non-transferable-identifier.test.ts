import { createNonTransferableIdentifier } from '../src/api/create-non-transferable-identifier';
import { createSignature } from '../src/api/create-signature';
import { verifyIdentifier } from '../src/api/verify-identifier';
import { verifySignature } from '../src/api/verify-signature';
import { encodeNonTransferablePublicKeyEd25519 } from '../src/cesr/encode';
import { keyPairFromSeed, publicKeyToCesr, rawPublicKey } from '../src/crypto/keypair';
import { createDidDocument } from '../src/did/document';
import { DID_KERI_PREFIX, parseDidKeri } from '../src/did/did-keri';
import { verifyDid } from '../src/did/verify-did';
import { base64urlEncode } from '../src/bytes/base64url';
import { utf8Encode } from '../src/bytes/utf8';
import { InvalidArgumentError } from '../src/profile/errors';

function fillSeed(byte: number): Uint8Array {
	return new Uint8Array(32).fill(byte);
}

const PAYLOAD = utf8Encode('a message from a non-transferable controller');

describe('createNonTransferableIdentifier', () => {
	test('mints a B-coded basic-prefix AID and matching DID, with no KEL', () => {
		const kp = keyPairFromSeed(fillSeed(0x40));
		const id = createNonTransferableIdentifier({ publicKey: kp.publicKey });

		// The AID is the `B`-coded basic prefix of the key — 44 chars, no SAID.
		expect(id.aid.startsWith('B')).toBe(true);
		expect(id.aid.length).toBe(44);
		expect(id.aid).toBe(encodeNonTransferablePublicKeyEd25519(rawPublicKey(kp.publicKey)));
		expect(id.did).toBe(`${DID_KERI_PREFIX}${id.aid}`);

		// The result has no `event` field — there is no inception event / KEL.
		expect('event' in id).toBe(false);

		// State: non-transferable, live, self-certifying, no event-derived fields.
		expect(id.state.transferable).toBe(false);
		expect(id.state.deactivated).toBe(false);
		expect(id.state.lastSequenceNumber).toBe(0);
		expect(id.state.currentPublicKey).toBe(id.aid); // the AID *is* the key
		expect(id.state.lastEventDigest).toBeUndefined();
		expect(id.state.lastEventType).toBeUndefined();
	});

	test('the AID equals the qb64 produced by swapping a `D` key to `B`', () => {
		// The historical hand-rolled form (no `B` encoder) was a `D` key with its
		// code char swapped; the real encoder must agree byte-for-byte.
		const kp = keyPairFromSeed(fillSeed(0x41));
		const id = createNonTransferableIdentifier({ publicKey: kp.publicKey });
		expect(id.aid).toBe('B' + publicKeyToCesr(kp.publicKey).slice(1));
	});

	test('the minted DID parses as non-transferable', () => {
		const kp = keyPairFromSeed(fillSeed(0x42));
		const id = createNonTransferableIdentifier({ publicKey: kp.publicKey });
		const parsed = parseDidKeri(id.did);
		expect(parsed.transferable).toBe(false);
		expect(parsed.aid).toBe(id.aid);
	});

	test('verifyIdentifier and verifyDid reproduce its state from the empty-string "no KEL"', () => {
		const kp = keyPairFromSeed(fillSeed(0x43));
		const id = createNonTransferableIdentifier({ publicKey: kp.publicKey });

		const byAid = verifyIdentifier({ aid: id.aid, kel: '' });
		expect(byAid.ok).toBe(true);
		if (byAid.ok) expect(byAid.state).toEqual(id.state);

		const byDid = verifyDid({ did: id.did, kel: '' });
		expect(byDid.ok).toBe(true);
		if (byDid.ok) expect(byDid.state).toEqual(id.state);
	});

	test('composes with createSignature / verifySignature using no KEL', () => {
		const kp = keyPairFromSeed(fillSeed(0x44));
		const id = createNonTransferableIdentifier({ publicKey: kp.publicKey });

		// Sign with the controller's private key; verify straight from the AID.
		const signature = createSignature(kp.privateKey, PAYLOAD);
		expect(
			verifySignature({ aid: id.aid, kel: '', payload: PAYLOAD, signature })
		).toBe(true);

		// A signature by a different key does not verify.
		const other = keyPairFromSeed(fillSeed(0x45));
		const wrong = createSignature(other.privateKey, PAYLOAD);
		expect(
			verifySignature({ aid: id.aid, kel: '', payload: PAYLOAD, signature: wrong })
		).toBe(false);
	});

	test('projects into a DID document advertising the controlling key', () => {
		const kp = keyPairFromSeed(fillSeed(0x46));
		const id = createNonTransferableIdentifier({ publicKey: kp.publicKey });

		const doc = createDidDocument({ state: id.state });
		expect(doc.id).toBe(id.did);
		expect(doc.verificationMethod).toHaveLength(1);
		expect(doc.verificationMethod[0]!.id).toBe(`${id.did}#key-0`);
		// The advertised JWK is the controlling key itself.
		expect(doc.verificationMethod[0]!.publicKeyJwk.x).toBe(
			base64urlEncode(rawPublicKey(kp.publicKey))
		);
	});

	test('is deterministic for a fixed key', () => {
		const seed = fillSeed(0x47);
		const a = createNonTransferableIdentifier({ publicKey: keyPairFromSeed(seed).publicKey });
		const b = createNonTransferableIdentifier({ publicKey: keyPairFromSeed(seed).publicKey });
		expect(b.did).toBe(a.did);
		expect(b.state).toEqual(a.state);
	});

	describe('argument contract', () => {
		test('throws on a non-object input', () => {
			expect(() => createNonTransferableIdentifier(null as never)).toThrow(
				InvalidArgumentError
			);
		});

		test('throws when given a private key instead of a public key', () => {
			const kp = keyPairFromSeed(fillSeed(0x48));
			expect(() =>
				createNonTransferableIdentifier({ publicKey: kp.privateKey as never })
			).toThrow(InvalidArgumentError);
		});

		test('throws when publicKey is not a key at all', () => {
			expect(() =>
				createNonTransferableIdentifier({ publicKey: {} as never })
			).toThrow(InvalidArgumentError);
		});
	});
});
