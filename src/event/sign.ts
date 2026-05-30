/**
 * Event signing.
 *
 * The signature is taken over the canonical JSON serialization of the *final*
 * event — i.e. with the SAID and version string already in place. Verifiers
 * recompute the same canonical bytes from the event object, so the signature
 * binds the entire event including its SAID.
 */

import { encodeIndexedSignatureEd25519 } from '../cesr/encode';
import { sign } from '../crypto/ed25519';
import { PrivateKey } from '../crypto/keypair';
import { canonicalizeJson } from './canonical-json';
import { toCanonicalEvent } from './field-order';
import { KeriEvent, SignedKeriEvent } from './types';

/**
 * Canonical bytes of `event`, suitable for digesting or signing.
 *
 * The event's fields are reordered into KERI canonical field order first, so
 * the bytes are independent of the order in which `event` was constructed or
 * parsed — a signer and a verifier reach the same serialization either way.
 */
export function serializeEvent(event: KeriEvent): Uint8Array {
	return canonicalizeJson(toCanonicalEvent(event));
}

/**
 * Sign `event` with `privateKey` and return a SignedKeriEvent.
 *
 * The signature is an *indexed* signature (a "Siger") at index 0 — KERI
 * attaches controller signatures on KEL events in indexed form, and this
 * single-key profile has exactly one key, at position 0 of the event's `k`
 * list.
 *
 * The returned wrapper, its inner event, and its signatures array are all
 * frozen so that casual post-construction mutation (which would silently
 * invalidate the signature) is rejected at runtime. The readonly types
 * already prevent this at compile time; the freeze is belt-and-suspenders
 * for callers reaching in through `as any` or untyped JSON paths.
 */
export function signEvent(event: KeriEvent, privateKey: PrivateKey): SignedKeriEvent {
	const sig = sign(privateKey, serializeEvent(event));
	Object.freeze(event);
	return Object.freeze({
		event,
		signatures: Object.freeze([encodeIndexedSignatureEd25519(sig, 0)] as const),
	});
}
