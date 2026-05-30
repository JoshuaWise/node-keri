import {
	decodeDigestSha256,
	decodeNonTransferablePublicKeyEd25519,
	decodePublicKeyEd25519,
	decodeSignatureEd25519,
	decodeVerificationKeyEd25519,
} from '../src/cesr/decode';
import {
	encodeDigestSha256,
	encodeNonTransferablePublicKeyEd25519,
	encodePublicKeyEd25519,
	encodeSignatureEd25519,
} from '../src/cesr/encode';
import { sha256 } from '../src/crypto/hash';
import { sign } from '../src/crypto/ed25519';
import { keyPairFromSeed, publicKeyToCesr, rawPublicKey } from '../src/crypto/keypair';
import { utf8Encode } from '../src/bytes/utf8';
import {
	InvalidArgumentError,
	MalformedInputError,
} from '../src/profile/errors';

function fromHex(s: string): Uint8Array {
	const out = new Uint8Array(s.length / 2);
	for (let i = 0; i < out.length; i++) {
		out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
	}
	return out;
}

function toArray(bytes: Uint8Array): number[] {
	return Array.from(bytes);
}

const RFC8032_SEED = fromHex(
	'9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
);
const RFC8032_PUBLIC_KEY = fromHex(
	'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
);

describe('cesr encode/decode', () => {
	describe('public keys (code D)', () => {
		test('encoding the all-zero key produces D + 43 A', () => {
			const qb64 = encodePublicKeyEd25519(new Uint8Array(32));
			expect(qb64).toBe('D' + 'A'.repeat(43));
			expect(qb64.length).toBe(44);
		});

		test('encode is deterministic and uses URL-safe alphabet', () => {
			const qb64 = encodePublicKeyEd25519(RFC8032_PUBLIC_KEY);
			expect(qb64.length).toBe(44);
			expect(qb64.startsWith('D')).toBe(true);
			expect(/^[A-Za-z0-9_-]+$/.test(qb64)).toBe(true);
			// Re-encoding the same bytes yields exactly the same string.
			expect(encodePublicKeyEd25519(RFC8032_PUBLIC_KEY)).toBe(qb64);
		});

		test('round-trips a generated keypair public key', () => {
			const kp = keyPairFromSeed(RFC8032_SEED);
			const qb64 = publicKeyToCesr(kp.publicKey);
			expect(toArray(decodePublicKeyEd25519(qb64))).toEqual(
				toArray(RFC8032_PUBLIC_KEY)
			);
		});

		test('round-trips arbitrary 32-byte payloads', () => {
			for (let trial = 0; trial < 32; trial++) {
				const raw = new Uint8Array(32);
				for (let i = 0; i < 32; i++) raw[i] = (i * 37 + trial * 11) & 0xff;
				expect(toArray(decodePublicKeyEd25519(encodePublicKeyEd25519(raw))))
					.toEqual(toArray(raw));
			}
		});

		test('encode rejects wrong-length raw input', () => {
			expect(() => encodePublicKeyEd25519(new Uint8Array(31))).toThrow(
				InvalidArgumentError
			);
			expect(() => encodePublicKeyEd25519(new Uint8Array(33))).toThrow(
				InvalidArgumentError
			);
			expect(() => encodePublicKeyEd25519(new Uint8Array(0))).toThrow(
				InvalidArgumentError
			);
		});

		test('decode rejects wrong-length qb64', () => {
			expect(() => decodePublicKeyEd25519('D' + 'A'.repeat(42))).toThrow(
				MalformedInputError
			);
			expect(() => decodePublicKeyEd25519('D' + 'A'.repeat(44))).toThrow(
				MalformedInputError
			);
			expect(() => decodePublicKeyEd25519('')).toThrow(MalformedInputError);
		});

		test('decode rejects a different known code with a helpful message', () => {
			// A valid SHA-256 digest qb64 is the same length (44) but starts
			// with 'I'. It must not be silently accepted as a public key.
			const digestQb64 = encodeDigestSha256(new Uint8Array(32));
			expect(() => decodePublicKeyEd25519(digestQb64)).toThrow(
				/SHA-256 digest/
			);
		});

		test('decode rejects the wrong known code, and unknown codes', () => {
			// 'B' is the non-transferable Ed25519 code — a recognized code, but
			// `decodePublicKeyEd25519` decodes only the transferable `D` form,
			// so a `B` key is the wrong code here (same length, 44).
			const bad = 'B' + 'A'.repeat(43);
			expect(() => decodePublicKeyEd25519(bad)).toThrow(MalformedInputError);
			// A completely unrecognized prefix.
			expect(() => decodePublicKeyEd25519('Z' + 'A'.repeat(43))).toThrow(
				MalformedInputError
			);
		});

		test('decode rejects non-base64url characters', () => {
			const bad = 'D' + 'A'.repeat(42) + '+';
			expect(() => decodePublicKeyEd25519(bad)).toThrow(MalformedInputError);
			const padded = 'D' + 'A'.repeat(42) + '=';
			expect(() => decodePublicKeyEd25519(padded)).toThrow(MalformedInputError);
		});

		test('decode rejects non-canonical encodings (leading pad bits non-zero)', () => {
			// After substituting 'D' with 'A', the first decoded byte equals
			// (b64[1] >> 4). 'Q' has base64 value 16, so its top 2 bits are 01
			// and the resulting first byte is 1 — non-zero, hence non-canonical.
			const bad = 'DQ' + 'A'.repeat(42);
			expect(() => decodePublicKeyEd25519(bad)).toThrow(
				/non-canonical/
			);
		});

		test('decode rejects non-string input', () => {
			expect(() =>
				decodePublicKeyEd25519(123 as unknown as string)
			).toThrow(MalformedInputError);
		});
	});

	describe('signatures (code 0B)', () => {
		test('encoding the all-zero signature produces 0B + 86 A', () => {
			const qb64 = encodeSignatureEd25519(new Uint8Array(64));
			expect(qb64).toBe('0B' + 'A'.repeat(86));
			expect(qb64.length).toBe(88);
		});

		test('round-trips an RFC 8032 signature', () => {
			const kp = keyPairFromSeed(RFC8032_SEED);
			const sig = sign(kp.privateKey, new Uint8Array(0));
			const qb64 = encodeSignatureEd25519(sig);
			expect(qb64.length).toBe(88);
			expect(qb64.startsWith('0B')).toBe(true);
			expect(toArray(decodeSignatureEd25519(qb64))).toEqual(toArray(sig));
		});

		test('round-trips arbitrary 64-byte payloads', () => {
			for (let trial = 0; trial < 16; trial++) {
				const raw = new Uint8Array(64);
				for (let i = 0; i < 64; i++) raw[i] = (i * 53 + trial * 7) & 0xff;
				expect(
					toArray(decodeSignatureEd25519(encodeSignatureEd25519(raw)))
				).toEqual(toArray(raw));
			}
		});

		test('encode rejects wrong-length raw input', () => {
			expect(() => encodeSignatureEd25519(new Uint8Array(63))).toThrow(
				InvalidArgumentError
			);
			expect(() => encodeSignatureEd25519(new Uint8Array(65))).toThrow(
				InvalidArgumentError
			);
		});

		test('decode rejects wrong-length qb64', () => {
			expect(() => decodeSignatureEd25519('0B' + 'A'.repeat(85))).toThrow(
				MalformedInputError
			);
			expect(() => decodeSignatureEd25519('0B' + 'A'.repeat(87))).toThrow(
				MalformedInputError
			);
		});

		test('decode rejects wrong derivation code', () => {
			// '0C' is reserved for X25519 ECDH signatures; not in this profile.
			expect(() => decodeSignatureEd25519('0C' + 'A'.repeat(86))).toThrow(
				MalformedInputError
			);
			// A 1-char code can't begin a signature qb64 either.
			expect(() => decodeSignatureEd25519('D' + 'A'.repeat(87))).toThrow(
				MalformedInputError
			);
		});

		test('decode rejects non-canonical encodings (leading pad bits non-zero)', () => {
			// For 0B (ps=2), the first 12 bits after the code must be zero. Set
			// the third character (first content character) to 'Q' (b64 value
			// 16, high 2 bits non-zero), producing decoded byte[0] != 0.
			const bad = '0BQ' + 'A'.repeat(85);
			expect(() => decodeSignatureEd25519(bad)).toThrow(/non-canonical/);
		});
	});

	describe('digests (code I)', () => {
		test('encoding the all-zero digest produces I + 43 A', () => {
			const qb64 = encodeDigestSha256(new Uint8Array(32));
			expect(qb64).toBe('I' + 'A'.repeat(43));
		});

		test('round-trips sha256("")', () => {
			// Well-known: SHA-256 of the empty string.
			const digest = sha256(new Uint8Array(0));
			const expected = fromHex(
				'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
			);
			expect(toArray(digest)).toEqual(toArray(expected));

			const qb64 = encodeDigestSha256(digest);
			expect(qb64.length).toBe(44);
			expect(qb64.startsWith('I')).toBe(true);
			expect(toArray(decodeDigestSha256(qb64))).toEqual(toArray(digest));
		});

		test('round-trips sha256 of a known message', () => {
			const digest = sha256(utf8Encode('hello'));
			const qb64 = encodeDigestSha256(digest);
			expect(toArray(decodeDigestSha256(qb64))).toEqual(toArray(digest));
		});

		test('encode rejects wrong-length raw input', () => {
			expect(() => encodeDigestSha256(new Uint8Array(31))).toThrow(
				InvalidArgumentError
			);
			expect(() => encodeDigestSha256(new Uint8Array(33))).toThrow(
				InvalidArgumentError
			);
		});

		test('decode distinguishes digests from public keys', () => {
			// Same length, different code; must not cross.
			const pkQb64 = encodePublicKeyEd25519(new Uint8Array(32));
			expect(() => decodeDigestSha256(pkQb64)).toThrow(
				/Ed25519 public key/
			);
		});

		test('decode rejects non-canonical encodings', () => {
			const bad = 'IQ' + 'A'.repeat(42);
			expect(() => decodeDigestSha256(bad)).toThrow(/non-canonical/);
		});
	});

	describe('non-transferable public keys (code B)', () => {
		// `encodeNonTransferablePublicKeyEd25519` mints the `B` basic-prefix form.
		// Equivalently it is the `D` key qb64 with its code char swapped — same
		// raw bytes, different derivation code — which lets us cross-check it.
		const RAW = rawPublicKey(keyPairFromSeed(RFC8032_SEED).publicKey);
		const dKey = encodePublicKeyEd25519(RAW);
		const bKey = encodeNonTransferablePublicKeyEd25519(RAW);

		test('encodeNonTransferablePublicKeyEd25519 produces a `B` key (the swapped `D` key)', () => {
			expect(bKey.startsWith('B')).toBe(true);
			expect(bKey).toBe('B' + dKey.slice(1));
		});

		test('decodeNonTransferablePublicKeyEd25519 decodes a `B` key', () => {
			expect(toArray(decodeNonTransferablePublicKeyEd25519(bKey))).toEqual(
				toArray(RAW)
			);
		});

		test('decodeNonTransferablePublicKeyEd25519 rejects a transferable `D` key', () => {
			expect(() => decodeNonTransferablePublicKeyEd25519(dKey)).toThrow(
				MalformedInputError
			);
		});

		test('decodeVerificationKeyEd25519 accepts both `B` and `D` keys', () => {
			expect(toArray(decodeVerificationKeyEd25519(bKey))).toEqual(toArray(RAW));
			expect(toArray(decodeVerificationKeyEd25519(dKey))).toEqual(toArray(RAW));
		});

		test('decodeVerificationKeyEd25519 rejects an unrelated code', () => {
			// A SHA-256 digest qb64 is the same length but neither `B` nor `D`.
			const digestQb64 = encodeDigestSha256(new Uint8Array(32));
			expect(() => decodeVerificationKeyEd25519(digestQb64)).toThrow(
				MalformedInputError
			);
		});
	});

	test('encoders never share a code prefix', () => {
		// The qb64 forms must be self-typing: the first hs characters uniquely
		// identify which primitive a string represents. This test fails fast
		// if a future code addition violates that invariant.
		const pk = encodePublicKeyEd25519(new Uint8Array(32));
		const sig = encodeSignatureEd25519(new Uint8Array(64));
		const dig = encodeDigestSha256(new Uint8Array(32));
		expect(pk[0]).not.toBe(dig[0]);
		expect(pk[0]).not.toBe(sig[0]);
		expect(dig[0]).not.toBe(sig[0]);
	});
});
