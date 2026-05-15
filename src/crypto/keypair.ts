import { Buffer } from 'node:buffer';
import {
	KeyObject,
	createPrivateKey,
	createPublicKey,
	generateKeyPairSync,
} from 'node:crypto';
import { base64urlDecode, base64urlEncode } from '../bytes/base64url';
import { concatBytes } from '../bytes/compare';
import {
	ED25519_PRIVATE_SEED_BYTES,
	ED25519_PUBLIC_KEY_BYTES,
	SUPPORTED_KEY_ALGORITHM,
	SupportedKeyAlgorithm,
} from '../profile/constants';
import {
	InvalidArgumentError,
	UnsupportedAlgorithmError,
} from '../profile/errors';

/**
 * Opaque wrapper around a Node KeyObject for an Ed25519 public key.
 * The raw 32-byte public key is exposed because it is required for AID
 * derivation, CESR encoding, and DID document generation.
 */
export interface KeriPublicKey {
	readonly type: 'KeriPublicKey';
	readonly algorithm: SupportedKeyAlgorithm;
	readonly raw: Uint8Array;
	readonly keyObject: KeyObject;
}

/**
 * Opaque wrapper around a Node KeyObject for an Ed25519 private key.
 * The raw seed is intentionally NOT exposed: callers should not be in the
 * habit of touching key material directly. Use `sign()` for the only
 * supported operation on private keys.
 */
export interface KeriPrivateKey {
	readonly type: 'KeriPrivateKey';
	readonly algorithm: SupportedKeyAlgorithm;
	readonly keyObject: KeyObject;
}

export interface KeriKeyPair {
	readonly publicKey: KeriPublicKey;
	readonly privateKey: KeriPrivateKey;
}

// PKCS#8 ASN.1 DER prefix for an Ed25519 private key (RFC 8410). The
// 32-byte seed follows immediately after this prefix.
const ED25519_PKCS8_PREFIX = new Uint8Array([
	0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04,
	0x22, 0x04, 0x20,
]);

/** Generate a fresh Ed25519 keypair using the platform CSPRNG. */
export function generateKeyPair(): KeriKeyPair {
	const { publicKey, privateKey } = generateKeyPairSync('ed25519');
	return wrapKeyPair(publicKey, privateKey);
}

/**
 * Construct a KeriKeyPair from a 32-byte Ed25519 seed. Intended for test
 * vectors and any caller that already holds raw key material. The public
 * half is derived from the seed by Node.
 */
export function keyPairFromSeed(seed: Uint8Array): KeriKeyPair {
	if (seed.length !== ED25519_PRIVATE_SEED_BYTES) {
		throw new InvalidArgumentError(
			`Ed25519 seed must be ${ED25519_PRIVATE_SEED_BYTES} bytes`
		);
	}
	const der = concatBytes(ED25519_PKCS8_PREFIX, seed);
	const privateKey = createPrivateKey({
		key: Buffer.from(der),
		format: 'der',
		type: 'pkcs8',
	});
	const publicKey = createPublicKey(privateKey);
	return wrapKeyPair(publicKey, privateKey);
}

/** Wrap a raw 32-byte Ed25519 public key as a KeriPublicKey. */
export function publicKeyFromRaw(raw: Uint8Array): KeriPublicKey {
	if (raw.length !== ED25519_PUBLIC_KEY_BYTES) {
		throw new InvalidArgumentError(
			`Ed25519 public key must be ${ED25519_PUBLIC_KEY_BYTES} bytes`
		);
	}
	const keyObject = createPublicKey({
		key: { kty: 'OKP', crv: 'Ed25519', x: base64urlEncode(raw) },
		format: 'jwk',
	});
	return Object.freeze({
		type: 'KeriPublicKey' as const,
		algorithm: SUPPORTED_KEY_ALGORITHM,
		raw: new Uint8Array(raw),
		keyObject,
	});
}

/** Export the raw 32-byte public key bytes from a KeriPublicKey. */
export function exportPublicKeyRaw(publicKey: KeriPublicKey): Uint8Array {
	assertPublicKey(publicKey);
	return new Uint8Array(publicKey.raw);
}

function wrapKeyPair(
	publicKey: KeyObject,
	privateKey: KeyObject
): KeriKeyPair {
	const raw = rawPublicKeyBytes(publicKey);
	const wrappedPublic: KeriPublicKey = Object.freeze({
		type: 'KeriPublicKey',
		algorithm: SUPPORTED_KEY_ALGORITHM,
		raw,
		keyObject: publicKey,
	});
	const wrappedPrivate: KeriPrivateKey = Object.freeze({
		type: 'KeriPrivateKey',
		algorithm: SUPPORTED_KEY_ALGORITHM,
		keyObject: privateKey,
	});
	return Object.freeze({ publicKey: wrappedPublic, privateKey: wrappedPrivate });
}

function rawPublicKeyBytes(publicKey: KeyObject): Uint8Array {
	const jwk = publicKey.export({ format: 'jwk' }) as {
		kty?: string;
		crv?: string;
		x?: string;
	};
	if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
		throw new UnsupportedAlgorithmError(
			'expected Ed25519 (OKP) public key'
		);
	}
	const raw = base64urlDecode(jwk.x);
	if (raw.length !== ED25519_PUBLIC_KEY_BYTES) {
		throw new UnsupportedAlgorithmError('Ed25519 public key length mismatch');
	}
	return raw;
}

export function assertPublicKey(
	value: unknown
): asserts value is KeriPublicKey {
	if (
		!value
		|| (value as KeriPublicKey).type !== 'KeriPublicKey'
		|| (value as KeriPublicKey).algorithm !== SUPPORTED_KEY_ALGORITHM
	) {
		throw new InvalidArgumentError('expected an Ed25519 KeriPublicKey');
	}
}

export function assertPrivateKey(
	value: unknown
): asserts value is KeriPrivateKey {
	if (
		!value
		|| (value as KeriPrivateKey).type !== 'KeriPrivateKey'
		|| (value as KeriPrivateKey).algorithm !== SUPPORTED_KEY_ALGORITHM
	) {
		throw new InvalidArgumentError('expected an Ed25519 KeriPrivateKey');
	}
}
