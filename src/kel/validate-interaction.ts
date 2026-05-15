/**
 * Structural validation of an interaction (`ixn`) event.
 *
 * Interaction events are the simplest in the profile: a back-pointer `p` and
 * an anchor list `a` whose contents are unconstrained here. The replay
 * verifier still canonicalizes `a` when recomputing the SAID, so a non-JSON-
 * safe anchor is caught there as a `NON_CANONICAL_EVENT`.
 */

import { InteractionEvent } from '../event/types';
import {
	ShapeResult,
	checkArray,
	checkDigest,
	checkExactKeys,
	checkSequenceString,
	checkVersionString,
	firstError,
} from './shape';

/** Every field an interaction event may carry — nothing else is permitted. */
const INTERACTION_KEYS: readonly string[] = ['v', 't', 'd', 'i', 's', 'p', 'a'];

/**
 * Validate the shape of an interaction event. The caller has already
 * confirmed `event` is an object and `event.t === 'ixn'`.
 */
export function validateInteractionShape(
	event: Record<string, unknown>
): ShapeResult<InteractionEvent> {
	const error = firstError([
		checkVersionString(event.v),
		checkDigest(event.d),
		checkDigest(event.i),
		checkSequenceString(event.s),
		checkDigest(event.p),
		checkArray(event.a, 'interaction anchors must be an array'),
		checkExactKeys(event, INTERACTION_KEYS),
	]);
	if (error) return { ok: false, error };
	return { ok: true, value: event as unknown as InteractionEvent };
}
