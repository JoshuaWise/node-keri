/**
 * Structural validation of a rotation (`rot`) event.
 *
 * A rotation looks like an inception with a back-pointer `p` and the witness
 * fields split into add/remove lists — all of which the profile pins empty.
 * As with inception, this pass only checks shape; the replay verifier
 * recomputes the SAID, checks the digest chain, confirms the revealed key
 * matches the prior next-key commitment, and verifies the signature.
 */

import { RotationEvent } from '../event/types';
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

/** Every field a rotation event may carry — nothing else is permitted. */
const ROTATION_KEYS: readonly string[] = [
	'v',
	't',
	'd',
	'i',
	's',
	'p',
	'kt',
	'k',
	'nt',
	'n',
	'bt',
	'br',
	'ba',
	'a',
];

/**
 * Validate the shape of a rotation event. The caller has already confirmed
 * `event` is an object and `event.t === 'rot'`.
 */
export function validateRotationShape(
	event: Record<string, unknown>
): ShapeResult<RotationEvent> {
	const error = firstError([
		checkVersionString(event.v),
		checkDigest(event.d),
		checkDigest(event.i),
		checkSequenceString(event.s),
		checkDigest(event.p),
		checkSentinel(event.kt, '1', 'signing threshold'),
		checkSingleton(event.k, 'key'),
		checkSentinel(event.nt, '1', 'next-key threshold'),
		checkSingleton(event.n, 'digest'),
		checkSentinel(event.bt, '0', 'witness threshold'),
		checkEmptyArray(event.br, 'witness removal is not supported'),
		checkEmptyArray(event.ba, 'witness addition is not supported'),
		checkEmptyArray(event.a, 'rotation seals are not supported'),
		checkExactKeys(event, ROTATION_KEYS),
	]);
	if (error) return { ok: false, error };
	return { ok: true, value: event as unknown as RotationEvent };
}
