/**
 * Structural validation of an inception (`icp`) event.
 *
 * An inception event establishes one of two kinds of AID, and the form of its
 * `i` field selects which:
 *   - a *transferable* AID, whose `i` is the event's own self-addressing
 *     digest (so `d === i`) and which pre-rotates — `nt` is `"1"` and `n`
 *     carries exactly one next-key digest; or
 *   - a *non-transferable* AID, whose `i` is the controller's `B`-coded
 *     Ed25519 key itself and which commits to no next key — `nt` is `"0"` and
 *     `n` is empty, so the identifier can never rotate.
 *
 * This pass is purely about *shape*: it confirms the event carries exactly the
 * fields the profile permits, with the excluded-feature fields pinned to their
 * sentinel values and every CESR primitive well-formed. The semantic checks —
 * recomputing the SAID, deriving the AID, verifying the signature — are the
 * job of the replay verifier, which only runs once the shape is known good.
 */

import { decodeDigest, decodeNonTransferablePublicKeyEd25519 } from '../cesr/decode';
import { InceptionEvent, NonTransferableInceptionEvent } from '../event/types';
import {
	KeriVerificationError,
	MalformedInputError,
	UnsupportedAlgorithmError,
} from '../profile/errors';
import {
	ShapeResult,
	checkDigest,
	checkEmptyArray,
	checkExactKeys,
	checkSentinel,
	checkSequenceString,
	checkSingleton,
	checkVersionString,
	describe,
	firstError,
} from './shape';

/** Every field an inception event may carry — nothing else is permitted. */
const INCEPTION_KEYS: readonly string[] = [
	'v',
	't',
	'd',
	'i',
	's',
	'kt',
	'k',
	'nt',
	'n',
	'bt',
	'b',
	'c',
	'a',
];

/**
 * A validated inception event, tagged with the kind of AID it establishes so
 * the replay verifier can apply the matching derivation rule. Discriminated on
 * `transferable`.
 */
export type ValidatedInception =
	| { readonly transferable: true; readonly event: InceptionEvent }
	| { readonly transferable: false; readonly event: NonTransferableInceptionEvent };

/**
 * Decide whether an inception `i` field names a transferable AID (a
 * self-addressing digest) or a non-transferable one (a `B`-coded Ed25519 key),
 * or is neither — a malformed prefix.
 */
function classifyPrefix(
	value: unknown
): { transferable: boolean } | { error: KeriVerificationError } {
	if (typeof value !== 'string') {
		return { error: { code: 'INVALID_CESR_CODE', value: describe(value) } };
	}
	// A transferable AID is a self-addressing digest under a recognized
	// algorithm; a non-transferable one is the controller's `B`-coded key.
	try {
		decodeDigest(value);
		return { transferable: true };
	} catch (err) {
		if (
			!(err instanceof MalformedInputError)
			&& !(err instanceof UnsupportedAlgorithmError)
		) {
			throw err;
		}
	}
	try {
		decodeNonTransferablePublicKeyEd25519(value);
		return { transferable: false };
	} catch (err) {
		if (err instanceof MalformedInputError) {
			return { error: { code: 'INVALID_CESR_CODE', value } };
		}
		throw err;
	}
}

/**
 * Validate the shape of an inception event. The caller has already confirmed
 * `event` is an object and `event.t === 'icp'`.
 */
export function validateInceptionShape(
	event: Record<string, unknown>
): ShapeResult<ValidatedInception> {
	// Fields whose rules do not depend on the transferable/non-transferable
	// distinction.
	const common = firstError([
		checkVersionString(event.v),
		checkDigest(event.d),
		checkSequenceString(event.s),
		checkSentinel(event.kt, '1', 'signing threshold'),
		checkSentinel(event.bt, '0', 'witness threshold'),
		checkEmptyArray(event.b, 'witnesses are not supported'),
		checkEmptyArray(event.c, 'configuration traits are not supported'),
		checkEmptyArray(event.a, 'inception seals are not supported'),
		checkExactKeys(event, INCEPTION_KEYS),
	]);
	if (common) return { ok: false, error: common };

	const prefix = classifyPrefix(event.i);
	if ('error' in prefix) return { ok: false, error: prefix.error };

	if (prefix.transferable) {
		// Transferable: a single `D`-coded signing key and a single next-key
		// digest committed for the future rotation.
		const error = firstError([
			checkSingleton(event.k, 'key'),
			checkSentinel(event.nt, '1', 'next-key threshold'),
			checkSingleton(event.n, 'digest'),
		]);
		if (error) return { ok: false, error };
		return {
			ok: true,
			value: { transferable: true, event: event as unknown as InceptionEvent },
		};
	}

	// Non-transferable: a single `B`-coded signing key and no next-key
	// commitment at all — the identifier can never rotate.
	const error = firstError([
		checkSingleton(event.k, 'ntkey'),
		checkSentinel(event.nt, '0', 'next-key threshold'),
		checkEmptyArray(event.n, 'a non-transferable identifier commits to no next key'),
	]);
	if (error) return { ok: false, error };
	return {
		ok: true,
		value: {
			transferable: false,
			event: event as unknown as NonTransferableInceptionEvent,
		},
	};
}
