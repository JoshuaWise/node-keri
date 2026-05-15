/**
 * Event signing.
 *
 * The signature is taken over the canonical JSON serialization of the *final*
 * event — i.e. with the SAID and version string already in place. Verifiers
 * recompute the same canonical bytes from the event object, so the signature
 * binds the entire event including its SAID.
 */

import { encodeSignatureEd25519 } from '../cesr/encode';
import { sign } from '../crypto/ed25519';
import { KeriPrivateKey } from '../crypto/keypair';
import { canonicalizeJson } from './canonical-json';
import { KeriEvent, SignedKeriEvent } from './types';

/** Canonical bytes of `event`, suitable for digesting or signing. */
export function serializeEvent(event: KeriEvent): Uint8Array {
	return canonicalizeJson(event);
}

/**
 * Sign `event` with `privateKey` and return a SignedKeriEvent.
 *
 * The returned wrapper, its inner event, and its signatures array are all
 * frozen so that casual post-construction mutation (which would silently
 * invalidate the signature) is rejected at runtime. The readonly types
 * already prevent this at compile time; the freeze is belt-and-suspenders
 * for callers reaching in through `as any` or untyped JSON paths.
 */
export function signEvent(
	event: KeriEvent,
	privateKey: KeriPrivateKey
): SignedKeriEvent {
	const sig = sign(privateKey, serializeEvent(event));
	Object.freeze(event);
	return Object.freeze({
		event,
		signatures: Object.freeze([encodeSignatureEd25519(sig)] as const),
	});
}
