/**
 * Shared test helpers for building CESR stream KELs.
 *
 * The library's own `encodeEventFrame` serializes through `toCanonicalEvent`,
 * which drops fields the profile does not name. Tamper tests need the opposite:
 * a frame that carries a hand-built event *verbatim* — forbidden fields, bad
 * values and all — so replay is the thing that rejects it, not serialization.
 *
 * `reframe` does that. It re-sizes the version string so the frame is still
 * well-formed (the parser can locate the event) but otherwise preserves the
 * event object as given, and attaches an arbitrary number of signatures behind
 * a `-A` counter (including 0 or 2, which the profile forbids but which the
 * tamper suite deliberately constructs).
 *
 * This is not a `*.test.ts` file, so jest does not run it as a suite.
 */

import { intToB64 } from '../src/bytes/base64url';
import { utf8Decode } from '../src/bytes/utf8';
import { CONTROLLER_IDX_SIGS_CODE } from '../src/cesr/counter';
import { canonicalizeJson } from '../src/event/canonical-json';
import { formatKeriVersionString } from '../src/event/digest';
import { SignedKeriEvent } from '../src/event/types';

/** Re-frame an event object verbatim, with a correctly-sized version string. */
export function reframe(
	event: Record<string, unknown>,
	signatures: readonly string[]
): string {
	const { v: _v, ...rest } = event;
	const sized = (versionString: string) =>
		canonicalizeJson({ v: versionString, ...rest });
	const draftLength = sized(formatKeriVersionString(0)).length;
	const eventJson = utf8Decode(sized(formatKeriVersionString(draftLength)));
	const counter = CONTROLLER_IDX_SIGS_CODE + intToB64(signatures.length, 2);
	return eventJson + counter + signatures.join('');
}

/** Concatenate signed events into a single KEL CESR stream. */
export function frameKel(events: readonly SignedKeriEvent[]): string {
	return events
		.map((e) => reframe(e.event as unknown as Record<string, unknown>, e.signatures))
		.join('');
}
