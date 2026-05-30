import { createIdentifier } from '../src/api/create-identifier';
import { rotateIdentifier } from '../src/api/rotate-identifier';
import { verifySignatureWithDid } from '../src/did/verify-signature-with-did';
import { decodeSignatureEd25519 } from '../src/cesr/decode';
import { encodeSignatureEd25519 } from '../src/cesr/encode';
import { sign } from '../src/crypto/ed25519';
import { publicKeyToCesr } from '../src/crypto/keypair';
import type { DidKeri } from '../src/did/did-keri';
import { utf8Encode } from '../src/bytes/utf8';
import { InvalidArgumentError } from '../src/profile/errors';
import { fillSeed, keyPairFromSeed } from './helpers/util';

const K0 = () => keyPairFromSeed(fillSeed(0x30));
const K1 = () => keyPairFromSeed(fillSeed(0x31));
const K2 = () => keyPairFromSeed(fillSeed(0x32));

const PAYLOAD = utf8Encode('agent-to-agent message body');

function newIdentifier() {
	const currentKeyPair = K0();
	const nextKeyPair = K1();
	const result = createIdentifier({
		currentPrivateKey: currentKeyPair.privateKey,
		nextPublicKey: nextKeyPair.publicKey,
	});
	// Thread the keypairs through so callers can sign with / rotate to them.
	return { ...result, currentKeyPair, nextKeyPair };
}

describe('verifySignatureWithDid — accepts a valid signature', () => {
	test('verifies a payload signed by the current key', () => {
		const id = newIdentifier();
		const signature = encodeSignatureEd25519(
			sign(id.currentKeyPair.privateKey, PAYLOAD)
		);
		expect(
			verifySignatureWithDid({
				did: id.did,
				kel: id.event,
				payload: PAYLOAD,
				signature,
			})
		).toBe(true);
	});

	test('tracks key rotation: the new key verifies, the old one does not', () => {
		const id = newIdentifier();
		const rotation = rotateIdentifier({
			state: id.state,
			newPrivateKey: id.nextKeyPair.privateKey,
			nextPublicKey: K2().publicKey,
		});
		const kel = id.event + rotation.event;

		const byNewKey = encodeSignatureEd25519(sign(id.nextKeyPair.privateKey, PAYLOAD));
		expect(
			verifySignatureWithDid({
				did: id.did,
				kel,
				payload: PAYLOAD,
				signature: byNewKey,
			})
		).toBe(true);

		const byOldKey = encodeSignatureEd25519(
			sign(id.currentKeyPair.privateKey, PAYLOAD)
		);
		expect(
			verifySignatureWithDid({
				did: id.did,
				kel,
				payload: PAYLOAD,
				signature: byOldKey,
			})
		).toBe(false);
	});
});

describe('verifySignatureWithDid — rejects invalid signatures', () => {
	test('false for a tampered payload', () => {
		const id = newIdentifier();
		const signature = encodeSignatureEd25519(
			sign(id.currentKeyPair.privateKey, PAYLOAD)
		);
		expect(
			verifySignatureWithDid({
				did: id.did,
				kel: id.event,
				payload: utf8Encode('a different message'),
				signature,
			})
		).toBe(false);
	});

	test('false for a tampered (but well-formed) signature', () => {
		const id = newIdentifier();
		const raw = decodeSignatureEd25519(
			encodeSignatureEd25519(sign(id.currentKeyPair.privateKey, PAYLOAD))
		);
		raw[0] = raw[0]! ^ 0xff;
		expect(
			verifySignatureWithDid({
				did: id.did,
				kel: id.event,
				payload: PAYLOAD,
				signature: encodeSignatureEd25519(raw),
			})
		).toBe(false);
	});

	test('false for a structurally malformed signature string', () => {
		const id = newIdentifier();
		expect(
			verifySignatureWithDid({
				did: id.did,
				kel: id.event,
				payload: PAYLOAD,
				signature: 'not-a-cesr-signature' as never,
			})
		).toBe(false);
	});

	test('false when the KEL belongs to a different identifier', () => {
		const idA = newIdentifier();
		const idB = createIdentifier({
			currentPrivateKey: K1().privateKey,
			nextPublicKey: K2().publicKey,
		});
		const signature = encodeSignatureEd25519(
			sign(idA.currentKeyPair.privateKey, PAYLOAD)
		);
		expect(
			verifySignatureWithDid({
				did: idB.did,
				kel: idA.event,
				payload: PAYLOAD,
				signature,
			})
		).toBe(false);
	});

	test('false for a malformed DID', () => {
		const id = newIdentifier();
		const signature = encodeSignatureEd25519(
			sign(id.currentKeyPair.privateKey, PAYLOAD)
		);
		expect(
			verifySignatureWithDid({
				did: 'did:web:example.com' as never,
				kel: id.event,
				payload: PAYLOAD,
				signature,
			})
		).toBe(false);
	});

	test('false for a KEL that does not verify', () => {
		const id = newIdentifier();
		const signature = encodeSignatureEd25519(
			sign(id.currentKeyPair.privateKey, PAYLOAD)
		);
		expect(
			verifySignatureWithDid({
				did: id.did,
				kel: '',
				payload: PAYLOAD,
				signature,
			})
		).toBe(false);
	});

	test('false for a transferable DID given the empty-string "no KEL" value', () => {
		const id = newIdentifier();
		const signature = encodeSignatureEd25519(
			sign(id.currentKeyPair.privateKey, PAYLOAD)
		);
		// A transferable identifier's key state lives in its KEL; the
		// empty-string "no KEL" value leaves nothing to establish the key from.
		expect(
			verifySignatureWithDid({ did: id.did, kel: '', payload: PAYLOAD, signature })
		).toBe(false);
	});
});

describe('verifySignatureWithDid — non-transferable DID', () => {
	// A non-transferable AID *is* the signing key — a `B`-coded basic prefix,
	// self-certifying, so it verifies with the empty-string "no KEL" value.
	// Build one by swapping the code char of a `D` key (equivalently
	// `encodeNonTransferablePublicKeyEd25519`): same raw bytes, the `B` code.
	const kp = keyPairFromSeed(fillSeed(0x44));
	const ntDid = ('did:keri:B' + publicKeyToCesr(kp.publicKey).slice(1)) as DidKeri;

	test('verifies a signature with the empty-string "no KEL" value', () => {
		const signature = encodeSignatureEd25519(sign(kp.privateKey, PAYLOAD));
		expect(
			verifySignatureWithDid({ did: ntDid, kel: '', payload: PAYLOAD, signature })
		).toBe(true);
	});

	test('false for a tampered payload', () => {
		const signature = encodeSignatureEd25519(sign(kp.privateKey, PAYLOAD));
		expect(
			verifySignatureWithDid({
				did: ntDid,
				kel: '',
				payload: utf8Encode('a different message'),
				signature,
			})
		).toBe(false);
	});

	test('false for a signature by a different key', () => {
		const other = keyPairFromSeed(fillSeed(0x45));
		const signature = encodeSignatureEd25519(sign(other.privateKey, PAYLOAD));
		expect(
			verifySignatureWithDid({ did: ntDid, kel: '', payload: PAYLOAD, signature })
		).toBe(false);
	});

	test('false when given a malformed KEL instead of the empty string', () => {
		// A non-empty `kel` is always replayed — even for a non-transferable
		// DID — so a bogus one fails rather than being silently ignored.
		const signature = encodeSignatureEd25519(sign(kp.privateKey, PAYLOAD));
		expect(
			verifySignatureWithDid({
				did: ntDid,
				kel: 'not-a-real-kel',
				payload: PAYLOAD,
				signature,
			})
		).toBe(false);
	});
});

describe('verifySignatureWithDid — argument contract', () => {
	const id = newIdentifier();
	const signature = encodeSignatureEd25519(sign(id.currentKeyPair.privateKey, PAYLOAD));
	const base = {
		did: id.did,
		kel: id.event,
		payload: PAYLOAD,
		signature,
	};

	test('throws on a non-object input', () => {
		expect(() => verifySignatureWithDid(null as never)).toThrow(InvalidArgumentError);
	});

	test('throws when did is not a string', () => {
		expect(() => verifySignatureWithDid({ ...base, did: 42 as never })).toThrow(
			InvalidArgumentError
		);
	});

	test('throws when kel is not a string', () => {
		expect(() => verifySignatureWithDid({ ...base, kel: {} as never })).toThrow(
			InvalidArgumentError
		);
	});

	test('throws when payload is not a Uint8Array', () => {
		expect(() =>
			verifySignatureWithDid({ ...base, payload: 'text' as never })
		).toThrow(InvalidArgumentError);
	});

	test('throws when signature is not a string', () => {
		expect(() =>
			verifySignatureWithDid({ ...base, signature: 123 as never })
		).toThrow(InvalidArgumentError);
	});
});
