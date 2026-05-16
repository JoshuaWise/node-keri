import { utf8Encode } from '../src/bytes/utf8';
import { sign, verify } from '../src/crypto/ed25519';
import {
	exportPublicKeyRaw,
	generateKeyPair,
	keyPairFromSeed,
	publicKeyFromRaw,
} from '../src/crypto/keypair';
import {
	ED25519_PUBLIC_KEY_BYTES,
	ED25519_SIGNATURE_BYTES,
} from '../src/profile/constants';
import {
	InvalidArgumentError,
	UnsupportedAlgorithmError,
} from '../src/profile/errors';

function hex(bytes: Uint8Array): string {
	let s = '';
	for (const b of bytes) s += b.toString(16).padStart(2, '0');
	return s;
}

function fromHex(s: string): Uint8Array {
	const out = new Uint8Array(s.length / 2);
	for (let i = 0; i < out.length; i++) {
		out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
	}
	return out;
}

describe('ed25519', () => {
	test('generateKeyPair produces a 32-byte public key and a usable private key', () => {
		const kp = generateKeyPair();
		expect(kp.publicKey.algorithm).toBe('Ed25519');
		expect(kp.privateKey.algorithm).toBe('Ed25519');
		expect(kp.publicKey.raw.length).toBe(ED25519_PUBLIC_KEY_BYTES);

		const msg = utf8Encode('hello');
		const sig = sign(kp.privateKey, msg);
		expect(sig.length).toBe(ED25519_SIGNATURE_BYTES);
		expect(verify(kp.publicKey, msg, sig)).toBe(true);
	});

	test('keyPairFromSeed is deterministic and matches RFC 8032 test vector 1', () => {
		// RFC 8032 §7.1, Test 1.
		const seed = fromHex(
			'9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
		);
		const expectedPublic =
			'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
		const message = new Uint8Array(0);
		const expectedSignature =
			'e5564300c360ac729086e2cc806e828a'
			+ '84877f1eb8e5d974d873e06522490155'
			+ '5fb8821590a33bacc61e39701cf9b46b'
			+ 'd25bf5f0595bbe24655141438e7a100b';

		const kp = keyPairFromSeed(seed);
		expect(hex(kp.publicKey.raw)).toBe(expectedPublic);

		const sig = sign(kp.privateKey, message);
		expect(hex(sig)).toBe(expectedSignature);

		expect(verify(kp.publicKey, message, sig)).toBe(true);
	});

	test('keyPairFromSeed rejects wrong-length seeds', () => {
		expect(() => keyPairFromSeed(new Uint8Array(31))).toThrow(
			InvalidArgumentError
		);
		expect(() => keyPairFromSeed(new Uint8Array(33))).toThrow(
			InvalidArgumentError
		);
	});

	test('verify rejects a tampered message', () => {
		const kp = generateKeyPair();
		const msg = utf8Encode('hello');
		const sig = sign(kp.privateKey, msg);
		const tampered = utf8Encode('hellp');
		expect(verify(kp.publicKey, tampered, sig)).toBe(false);
	});

	test('verify rejects a tampered signature', () => {
		const kp = generateKeyPair();
		const msg = utf8Encode('hello');
		const sig = sign(kp.privateKey, msg);
		sig[0] = sig[0]! ^ 0x01;
		expect(verify(kp.publicKey, msg, sig)).toBe(false);
	});

	test('verify rejects a wrong-length signature without throwing', () => {
		const kp = generateKeyPair();
		expect(verify(kp.publicKey, utf8Encode('m'), new Uint8Array(63))).toBe(
			false
		);
		expect(verify(kp.publicKey, utf8Encode('m'), new Uint8Array(65))).toBe(
			false
		);
	});

	test('verify rejects under a different keypair', () => {
		const a = generateKeyPair();
		const b = generateKeyPair();
		const msg = utf8Encode('hello');
		const sig = sign(a.privateKey, msg);
		expect(verify(b.publicKey, msg, sig)).toBe(false);
	});

	test('publicKeyFromRaw round-trips through exportPublicKeyRaw', () => {
		const kp = generateKeyPair();
		const raw = exportPublicKeyRaw(kp.publicKey);
		const restored = publicKeyFromRaw(raw);
		expect(Array.from(exportPublicKeyRaw(restored))).toEqual(Array.from(raw));

		// And the reconstructed key should still verify the original signature.
		const msg = utf8Encode('roundtrip');
		const sig = sign(kp.privateKey, msg);
		expect(verify(restored, msg, sig)).toBe(true);
	});

	test('publicKeyFromRaw rejects wrong-length input', () => {
		expect(() => publicKeyFromRaw(new Uint8Array(31))).toThrow(
			InvalidArgumentError
		);
		expect(() => publicKeyFromRaw(new Uint8Array(33))).toThrow(
			InvalidArgumentError
		);
	});

	test('sign and verify reject foreign key objects', () => {
		const kp = generateKeyPair();
		expect(() => sign({} as never, utf8Encode('x'))).toThrow(
			InvalidArgumentError
		);
		expect(() =>
			verify({} as never, utf8Encode('x'), new Uint8Array(64))
		).toThrow(InvalidArgumentError);
		// Swapping public and private should also fail.
		expect(() => sign(kp.publicKey as never, utf8Encode('x'))).toThrow(
			InvalidArgumentError
		);
		expect(() =>
			verify(kp.privateKey as never, utf8Encode('x'), new Uint8Array(64))
		).toThrow(InvalidArgumentError);
	});

	// Reference to UnsupportedAlgorithmError exists so that future RSA/X25519
	// regression tests can extend this file without re-importing.
	void UnsupportedAlgorithmError;
});
