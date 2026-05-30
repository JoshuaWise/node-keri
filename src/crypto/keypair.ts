import { KeyObject, createPublicKey, generateKeyPairSync } from 'node:crypto';
import { base64urlDecode, base64urlEncode } from '../bytes/base64url';
import { encodePublicKeyEd25519 } from '../cesr/encode';
import { decodeVerificationKeyEd25519 } from '../cesr/decode';
import { CesrPublicKey } from '../cesr/qualified';
import {
	SupportedKeyAlgorithm,
	SUPPORTED_KEY_ALGORITHM,
	ED25519_PUBLIC_KEY_BYTES,
} from '../profile/constants';
import { InvalidArgumentError, UnsupportedAlgorithmError } from '../profile/errors';

/**
 * An Ed25519 *public* key, as a Node `KeyObject` refined to the one algorithm
 * and half this profile supports. It is a plain `KeyObject` — interoperate with
 * the rest of the Node ecosystem directly: import any standard format with
 * `createPublicKey(...)` then `asPublicKey(...)`, and export with
 * `key.export({ format, type })`.
 *
 * The branding is two `KeyObject` fields narrowed to literals, so a `PublicKey`
 * and a `PrivateKey` are not interchangeable at compile time (passing the wrong
 * half is a type error, not a runtime surprise), and a bare `KeyObject` must be
 * narrowed through `asPublicKey` before it can be used here.
 */
export type PublicKey = KeyObject & {
	readonly asymmetricKeyType: SupportedKeyAlgorithm;
	readonly type: 'public';
};

/**
 * An Ed25519 *private* key, as a Node `KeyObject` refined as above. The raw
 * seed is never exposed by this library; `sign()` is the supported operation.
 * Deliberate serialization for secure storage is still possible through the
 * underlying `KeyObject` — `key.export({ format: 'der', type: 'pkcs8' })` and
 * so on — see SECURITY.md.
 */
export type PrivateKey = KeyObject & {
	readonly asymmetricKeyType: SupportedKeyAlgorithm;
	readonly type: 'private';
};

export interface KeyPair {
	readonly publicKey: PublicKey;
	readonly privateKey: PrivateKey;
}

/** Generate a fresh Ed25519 keypair using the platform CSPRNG. */
export function generateKeyPair(): KeyPair {
	const { publicKey, privateKey } = generateKeyPairSync(SUPPORTED_KEY_ALGORITHM);
	return { publicKey: asPublicKey(publicKey), privateKey: asPrivateKey(privateKey) };
}

/**
 * Reconstruct a full KeyPair from just its private half.
 *
 * Ed25519 private keys carry their public point, so Node can derive the
 * public KeyObject deterministically — no key material is generated. This is
 * what lets `rotateIdentifier` accept the bare private key of the key being
 * rotated *to* and still build the disclosed-public-key event.
 */
export function keyPairFromPrivateKey(privateKey: PrivateKey): KeyPair {
	assertPrivateKey(privateKey);
	return { publicKey: asPublicKey(createPublicKey(privateKey)), privateKey };
}

/** Wrap a raw 32-byte Ed25519 public key as a PublicKey. */
export function publicKeyFromRaw(raw: Readonly<Uint8Array>): PublicKey {
	if (raw.length !== ED25519_PUBLIC_KEY_BYTES) {
		throw new InvalidArgumentError(
			`Ed25519 public key must be ${ED25519_PUBLIC_KEY_BYTES} bytes`
		);
	}
	return asPublicKey(
		createPublicKey({
			key: { kty: 'OKP', crv: 'Ed25519', x: base64urlEncode(raw) },
			format: 'jwk',
		})
	);
}

/** The raw 32 public-key bytes of `key` — its AID-derivation/CESR input. */
export function rawPublicKey(key: PublicKey): Uint8Array {
	const jwk = key.export({ format: 'jwk' }) as {
		kty?: string;
		crv?: string;
		x?: string;
	};
	if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
		throw new UnsupportedAlgorithmError('expected Ed25519 (OKP) public key');
	}
	const raw = base64urlDecode(jwk.x);
	if (raw.length !== ED25519_PUBLIC_KEY_BYTES) {
		throw new UnsupportedAlgorithmError('Ed25519 public key length mismatch');
	}
	return raw;
}

/** CESR-qualify a public key (the transferable `D` form). */
export function publicKeyToCesr(key: PublicKey): CesrPublicKey {
	assertPublicKey(key);
	return encodePublicKeyEd25519(rawPublicKey(key));
}

/**
 * Reconstruct a `PublicKey` from its CESR-qualified form — the inverse of
 * `publicKeyToCesr`, and the bridge from a `KeriState.currentPublicKey` back to
 * a usable key. Accepts either the transferable (`D`) or non-transferable (`B`)
 * encoding.
 */
export function publicKeyFromCesr(cesr: CesrPublicKey): PublicKey {
	return publicKeyFromRaw(decodeVerificationKeyEd25519(cesr));
}

/**
 * Narrow a `KeyObject` to a `PublicKey`, throwing if it is not an Ed25519
 * public key. This is the validating import boundary: parse any standard
 * format to a `KeyObject` with Node's `createPublicKey(...)`, then narrow here.
 */
export function asPublicKey(value: unknown): PublicKey {
	assertPublicKey(value);
	return value;
}

/** Narrow a `KeyObject` to a `PrivateKey`, throwing if it is not an Ed25519 private key. */
export function asPrivateKey(value: unknown): PrivateKey {
	assertPrivateKey(value);
	return value;
}

export function assertPublicKey(value: unknown): asserts value is PublicKey {
	if (
		!(value instanceof KeyObject)
		|| value.type !== 'public'
		|| value.asymmetricKeyType !== SUPPORTED_KEY_ALGORITHM
	) {
		throw new InvalidArgumentError('expected an Ed25519 public KeyObject');
	}
}

export function assertPrivateKey(value: unknown): asserts value is PrivateKey {
	if (
		!(value instanceof KeyObject)
		|| value.type !== 'private'
		|| value.asymmetricKeyType !== SUPPORTED_KEY_ALGORITHM
	) {
		throw new InvalidArgumentError('expected an Ed25519 private KeyObject');
	}
}
