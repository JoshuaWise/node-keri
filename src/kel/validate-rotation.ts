/**
 * Structural validation of a rotation (`rot`) event.
 *
 * A `rot` event comes in two forms, and `nt`/`n` select which:
 *   - an ordinary *rotation*, which rolls the signing key forward — `nt` is
 *     `"1"` and `n` carries exactly one fresh next-key digest; or
 *   - a *deactivation*, which abandons the identifier — `nt` is `"0"` and `n`
 *     is empty, committing to no next key, so the KEL can never be extended.
 *
 * Both look like an inception with a back-pointer `p` and the witness fields
 * split into add/remove lists — all of which the profile pins empty. As with
 * inception, this pass only checks shape; the replay verifier recomputes the
 * SAID, checks the digest chain, confirms the revealed key matches the prior
 * next-key commitment, and verifies the signature.
 */

import { DeactivationEvent, RotationEvent } from '../event/types';
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
 * A validated `rot` event, tagged with whether it is a deactivation so the
 * replay verifier can apply the matching rule. Discriminated on `deactivation`.
 */
export type ValidatedRotation =
	| { readonly deactivation: false; readonly event: RotationEvent }
	| { readonly deactivation: true; readonly event: DeactivationEvent };

/**
 * Validate the shape of a rotation event. The caller has already confirmed
 * `event` is an object and `event.t === 'rot'`.
 */
export function validateRotationShape(
	event: Record<string, unknown>
): ShapeResult<ValidatedRotation> {
	// Fields shared by an ordinary rotation and a deactivation.
	const common = firstError([
		checkVersionString(event.v),
		checkDigest(event.d),
		checkDigest(event.i),
		checkSequenceString(event.s),
		checkDigest(event.p),
		checkSentinel(event.kt, '1', 'signing threshold'),
		checkSingleton(event.k, 'key'),
		checkSentinel(event.bt, '0', 'witness threshold'),
		checkEmptyArray(event.br, 'witness removal is not supported'),
		checkEmptyArray(event.ba, 'witness addition is not supported'),
		checkEmptyArray(event.a, 'rotation seals are not supported'),
		checkExactKeys(event, ROTATION_KEYS),
	]);
	if (common) return { ok: false, error: common };

	// `nt` distinguishes a deactivation (`"0"`, empty `n`) from an ordinary
	// rotation (`"1"`, a single next-key digest).
	if (event.nt === '0') {
		const error = checkEmptyArray(event.n, 'a deactivation commits to no next key');
		if (error) return { ok: false, error };
		return {
			ok: true,
			value: {
				deactivation: true,
				event: event as unknown as DeactivationEvent,
			},
		};
	}

	const error = firstError([
		checkSentinel(event.nt, '1', 'next-key threshold'),
		checkSingleton(event.n, 'digest'),
	]);
	if (error) return { ok: false, error };
	return {
		ok: true,
		value: { deactivation: false, event: event as unknown as RotationEvent },
	};
}
