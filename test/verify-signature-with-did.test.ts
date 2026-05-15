import { createIdentifier } from '../src/api/create-identifier';
import { rotateIdentifier } from '../src/api/rotate-identifier';
import { verifySignatureWithDid } from '../src/api/verify-signature-with-did';
import { decodeSignatureEd25519 } from '../src/cesr/decode';
import { encodeSignatureEd25519 } from '../src/cesr/encode';
import { sign } from '../src/crypto/ed25519';
import { keyPairFromSeed } from '../src/crypto/keypair';
import { utf8Encode } from '../src/bytes/utf8';
import { InvalidArgumentError } from '../src/profile/errors';

function fillSeed(byte: number): Uint8Array {
	return new Uint8Array(32).fill(byte);
}

const K0 = () => keyPairFromSeed(fillSeed(0x30));
const K1 = () => keyPairFromSeed(fillSeed(0x31));
const K2 = () => keyPairFromSeed(fillSeed(0x32));

const PAYLOAD = utf8Encode('agent-to-agent message body');

function newIdentifier() {
	return createIdentifier({ currentKeyPair: K0(), nextKeyPair: K1() });
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
				kel: [id.inceptionEvent],
				payload: PAYLOAD,
				signature,
			})
		).toBe(true);
	});

	test('tracks key rotation: the new key verifies, the old one does not', () => {
		const id = newIdentifier();
		const rotation = rotateIdentifier({
			state: id.state,
			currentPrivateKey: id.nextKeyPair.privateKey,
			nextKeyPair: K2(),
		});
		const kel = [id.inceptionEvent, rotation.rotationEvent];

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
				kel: [id.inceptionEvent],
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
		raw[0] ^= 0xff;
		expect(
			verifySignatureWithDid({
				did: id.did,
				kel: [id.inceptionEvent],
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
				kel: [id.inceptionEvent],
				payload: PAYLOAD,
				signature: 'not-a-cesr-signature' as never,
			})
		).toBe(false);
	});

	test('false when the KEL belongs to a different identifier', () => {
		const idA = newIdentifier();
		const idB = createIdentifier({
			currentKeyPair: K1(),
			nextKeyPair: K2(),
		});
		const signature = encodeSignatureEd25519(
			sign(idA.currentKeyPair.privateKey, PAYLOAD)
		);
		expect(
			verifySignatureWithDid({
				did: idB.did,
				kel: [idA.inceptionEvent],
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
				kel: [id.inceptionEvent],
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
				kel: [],
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
		kel: [id.inceptionEvent],
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

	test('throws when kel is not an array', () => {
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
