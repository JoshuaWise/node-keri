/**
 * Structural validation of an inception (`icp`) event.
 *
 * This pass is purely about *shape*: it confirms the event carries exactly the
 * fields the profile permits, with the excluded-feature fields pinned to their
 * sentinel values and every CESR primitive well-formed. The semantic checks —
 * recomputing the SAID, deriving the AID, verifying the signature — are the
 * job of the replay verifier, which only runs once the shape is known good.
 */

import { InceptionEvent } from '../event/types';
import {
	ShapeResult,
	checkDigest,
	checkEmptyArray,
	checkExactKeys,
	checkSentinel,
	checkSequenceString,
	checkSingleton,
	checkVersionString,
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
 * Validate the shape of an inception event. The caller has already confirmed
 * `event` is an object and `event.t === 'icp'`.
 */
export function validateInceptionShape(
	event: Record<string, unknown>
): ShapeResult<InceptionEvent> {
	const error = firstError([
		checkVersionString(event.v),
		checkDigest(event.d),
		checkDigest(event.i),
		checkSequenceString(event.s),
		checkSentinel(event.kt, '1', 'signing threshold'),
		checkSingleton(event.k, 'key'),
		checkSentinel(event.nt, '1', 'next-key threshold'),
		checkSingleton(event.n, 'digest'),
		checkSentinel(event.bt, '0', 'witness threshold'),
		checkEmptyArray(event.b, 'witnesses are not supported'),
		checkEmptyArray(event.c, 'configuration traits are not supported'),
		checkEmptyArray(event.a, 'inception seals are not supported'),
		checkExactKeys(event, INCEPTION_KEYS),
	]);
	if (error) return { ok: false, error };
	return { ok: true, value: event as unknown as InceptionEvent };
}
