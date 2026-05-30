import { createIdentifier } from '../src/api/create-identifier';
import { createSignature } from '../src/api/create-signature';
import { verifySignature } from '../src/api/verify-signature';
import { decodeSignatureEd25519 } from '../src/cesr/decode';
import { encodeSignatureEd25519 } from '../src/cesr/encode';
import { sign } from '../src/crypto/ed25519';
import { keyPairFromSeed } from '../src/crypto/keypair';
import { utf8Encode } from '../src/bytes/utf8';
import { ED25519_SIGNATURE_BYTES } from '../src/profile/constants';
import { InvalidArgumentError } from '../src/profile/errors';
import { fillSeed } from './helpers/util';

const PAYLOAD = utf8Encode('a message from the DID controller');

describe('createSignature', () => {
	test('returns the CESR-qualified form of the raw signature', () => {
		const kp = keyPairFromSeed(fillSeed(0x10));
		// Ed25519 is deterministic, so the convenience function must equal the
		// explicit sign + encode it stands in for.
		expect(createSignature(kp.privateKey, PAYLOAD)).toBe(
			encodeSignatureEd25519(sign(kp.privateKey, PAYLOAD))
		);
	});

	test('produces a non-indexed Cigar that decodes to 64 raw bytes', () => {
		const kp = keyPairFromSeed(fillSeed(0x11));
		const signature = createSignature(kp.privateKey, PAYLOAD);
		// A "Cigar" (non-indexed Ed25519 signature) is code `0B`.
		expect(signature.startsWith('0B')).toBe(true);
		expect(decodeSignatureEd25519(signature).length).toBe(ED25519_SIGNATURE_BYTES);
	});

	test('composes with verifySignature: the signature it makes verifies', () => {
		const currentKeyPair = keyPairFromSeed(fillSeed(0x20));
		const id = createIdentifier({
			currentPrivateKey: currentKeyPair.privateKey,
			nextPublicKey: keyPairFromSeed(fillSeed(0x21)).publicKey,
		});

		const signature = createSignature(currentKeyPair.privateKey, PAYLOAD);
		expect(
			verifySignature({ aid: id.aid, kel: id.event, payload: PAYLOAD, signature })
		).toBe(true);

		// A signature over a different payload does not verify.
		const wrong = createSignature(currentKeyPair.privateKey, utf8Encode('other'));
		expect(
			verifySignature({
				aid: id.aid,
				kel: id.event,
				payload: PAYLOAD,
				signature: wrong,
			})
		).toBe(false);
	});

	test('throws on a non-private key', () => {
		const kp = keyPairFromSeed(fillSeed(0x30));
		// A public key is not a signing key.
		expect(() => createSignature(kp.publicKey as never, PAYLOAD)).toThrow(
			InvalidArgumentError
		);
		expect(() => createSignature({} as never, PAYLOAD)).toThrow(InvalidArgumentError);
	});
});
