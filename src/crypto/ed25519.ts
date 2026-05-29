import { sign as nodeSign, verify as nodeVerify } from 'node:crypto';
import { ED25519_SIGNATURE_BYTES } from '../profile/constants';
import {
	KeriPrivateKey,
	KeriPublicKey,
	assertPrivateKey,
	assertPublicKey,
} from './keypair';

/** Produce an Ed25519 signature over `message`. Always 64 bytes. */
export function sign(
	privateKey: KeriPrivateKey,
	message: Readonly<Uint8Array>
): Uint8Array {
	assertPrivateKey(privateKey);
	const sig = new Uint8Array(nodeSign(null, message, privateKey.keyObject));
	if (sig.length !== ED25519_SIGNATURE_BYTES) {
		throw new Error('ed25519 signature length mismatch');
	}
	return sig;
}

/**
 * Verify an Ed25519 signature. Returns false (not throws) for any
 * verification failure, including malformed signature length, so callers
 * can treat this as a pure boolean.
 */
export function verify(
	publicKey: KeriPublicKey,
	message: Readonly<Uint8Array>,
	signature: Readonly<Uint8Array>
): boolean {
	assertPublicKey(publicKey);
	if (signature.length !== ED25519_SIGNATURE_BYTES) return false;
	return nodeVerify(null, message, publicKey.keyObject, signature);
}
